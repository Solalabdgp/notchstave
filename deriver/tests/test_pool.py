"""Address issuance: pool first, new index only when the pool is empty.

TZ 5.1 p. 3 and TZ 5.8/T5.3. Two properties are being pinned down:

* **Ordering.** A reused address must be preferred over a freshly derived one.
  This is what makes consumed index space a function of peak concurrency rather
  than of total ``/buy`` presses, which is the difference between "the gap-limit
  attack is expensive" and "the gap-limit attack is impossible".
* **The race.** Concurrent reservations must not collide on an index, and must
  not queue behind each other either — hence ``FOR UPDATE SKIP LOCKED``.

The unit tests below drive the real functions against a scripted fake
connection, so they run in CI without Postgres. They can prove control flow
(what was executed, in what order, with which parameters) but not locking
semantics — no fake can. The ``FOR UPDATE SKIP LOCKED`` behaviour and the
genuinely concurrent case belong to the integration tests at the bottom, which
skip unless ``NOTCHSTAVE_TEST_DSN`` points at a throwaway database. Marking
that gap explicitly is the point: a green unit suite here does not yet mean the
race is closed.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import pytest

from deriver import pool
from deriver.derivation import derive_address
from deriver.pool import (
    SQL_BIND_ADDRESS,
    SQL_BUMP_NEXT_INDEX,
    SQL_INSERT_ADDRESS,
    SQL_LOCK_ACCOUNT,
    SQL_MARK_FUNDED,
    SQL_PEEK_FREE_FROM_POOL,
    SQL_RELEASE_DUE,
    SQL_TAKE_FREE_FROM_POOL,
    AddressNotBindable,
    AddressPoolExhausted,
    InactiveHDAccount,
    allocate_free_address,
    bind_address_to_invoice,
    reserve_address_for_invoice,
)
from deriver.service import Deriver
from deriver.tests.test_account_addresses import EXPECTED_FIRST_FIVE, TEST_ACCOUNT_XPUB

HD_ACCOUNT_ID = 1
INVOICE_ID = uuid.UUID("018f4c2a-0000-7000-8000-000000000001")
HEAD_BLOCK = 21_000_000


# --------------------------------------------------------------------------
# Scripted fake connection
# --------------------------------------------------------------------------


class FakeCursor:
    def __init__(self, script: dict[str, list[list[dict[str, Any]]]], log: list[tuple[str, dict]]):
        self._script = script
        self._log = log
        self._pending: list[dict[str, Any]] = []

    def execute(self, sql: str, params: dict[str, Any] | None = None) -> None:
        self._log.append((sql, dict(params or {})))
        queued = self._script.get(sql)
        if queued is None:
            raise AssertionError(f"unscripted statement executed:\n{sql}")
        self._pending = queued.pop(0) if queued else []

    def fetchone(self) -> dict[str, Any] | None:
        return self._pending[0] if self._pending else None

    def fetchall(self) -> list[dict[str, Any]]:
        return list(self._pending)

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class FakeConnection:
    """Returns scripted rows per SQL statement and records what ran."""

    def __init__(self, script: dict[str, list[list[dict[str, Any]]]]):
        self.script = script
        self.log: list[tuple[str, dict]] = []

    def cursor(self, **_: Any) -> FakeCursor:
        return FakeCursor(self.script, self.log)

    def statements(self) -> list[str]:
        return [sql for sql, _ in self.log]

    def params_for(self, sql: str) -> dict[str, Any]:
        for executed_sql, params in self.log:
            if executed_sql == sql:
                return params
        raise AssertionError("statement was never executed")


@pytest.fixture()
def deriver() -> Deriver:
    return Deriver({HD_ACCOUNT_ID: TEST_ACCOUNT_XPUB})


def account_row(*, next_index: int = 5, active: int = 2, ceiling: int = 500) -> dict[str, Any]:
    return {
        "id": HD_ACCOUNT_ID,
        "next_index": next_index,
        "max_active_addresses": ceiling,
        "path_prefix": "m/44'/60'/0'",
        "xpub_fingerprint": "60b68b69",
        "active_addresses": active,
    }


# --------------------------------------------------------------------------
# Allocation order
# --------------------------------------------------------------------------


def test_a_free_pool_address_is_reused_and_the_index_is_not_bumped(deriver: Deriver) -> None:
    """The load-bearing behaviour of TZ 5.8/T5.3."""
    conn = FakeConnection(
        {
            SQL_TAKE_FREE_FROM_POOL: [
                [
                    {
                        "id": 42,
                        "hd_account_id": HD_ACCOUNT_ID,
                        "derivation_index": 2,
                        "address": EXPECTED_FIRST_FIVE[2],
                    }
                ]
            ]
        }
    )

    result = reserve_address_for_invoice(conn, deriver, HD_ACCOUNT_ID, INVOICE_ID, HEAD_BLOCK)

    assert result.derivation_index == 2
    assert result.address == EXPECTED_FIRST_FIVE[2]
    assert result.newly_derived is False
    assert SQL_BUMP_NEXT_INDEX not in conn.statements()
    assert SQL_LOCK_ACCOUNT not in conn.statements()


def test_an_empty_pool_bumps_the_index_and_derives(deriver: Deriver) -> None:
    conn = FakeConnection(
        {
            SQL_TAKE_FREE_FROM_POOL: [[]],
            SQL_LOCK_ACCOUNT: [[account_row(next_index=3)]],
            SQL_BUMP_NEXT_INDEX: [[{"derivation_index": 3}]],
            SQL_INSERT_ADDRESS: [
                [
                    {
                        "id": 77,
                        "hd_account_id": HD_ACCOUNT_ID,
                        "derivation_index": 3,
                        "address": EXPECTED_FIRST_FIVE[3],
                    }
                ]
            ],
        }
    )

    result = reserve_address_for_invoice(conn, deriver, HD_ACCOUNT_ID, INVOICE_ID, HEAD_BLOCK)

    assert result.newly_derived is True
    assert result.derivation_index == 3
    assert conn.statements().index(SQL_TAKE_FREE_FROM_POOL) < conn.statements().index(
        SQL_BUMP_NEXT_INDEX
    )


def test_the_inserted_address_is_the_derived_one(deriver: Deriver) -> None:
    """The address written to the pool comes from the xpub, never from a caller.

    An address that entered ``receive_addresses`` any other way is precisely
    what TZ 5.8/T1.2 restricts the deriver role to prevent.
    """
    conn = FakeConnection(
        {
            SQL_TAKE_FREE_FROM_POOL: [[]],
            SQL_LOCK_ACCOUNT: [[account_row(next_index=4)]],
            SQL_BUMP_NEXT_INDEX: [[{"derivation_index": 4}]],
            SQL_INSERT_ADDRESS: [
                [
                    {
                        "id": 78,
                        "hd_account_id": HD_ACCOUNT_ID,
                        "derivation_index": 4,
                        "address": EXPECTED_FIRST_FIVE[4],
                    }
                ]
            ],
        }
    )

    reserve_address_for_invoice(conn, deriver, HD_ACCOUNT_ID, INVOICE_ID, HEAD_BLOCK)

    params = conn.params_for(SQL_INSERT_ADDRESS)
    assert params["address"] == derive_address(TEST_ACCOUNT_XPUB, 4)
    assert params["address"] == EXPECTED_FIRST_FIVE[4]
    assert params["status"] == "reserved"
    assert params["reserved_from_block"] == HEAD_BLOCK


def test_reservation_records_the_head_block(deriver: Deriver) -> None:
    """Condition 3 of the reuse rules (TZ 5.1 p. 2, 5.8/T3.3).

    Without ``reserved_from_block`` a late payment from the address's previous
    tenant would be credited to whoever holds it now.
    """
    conn = FakeConnection(
        {
            SQL_TAKE_FREE_FROM_POOL: [
                [
                    {
                        "id": 42,
                        "hd_account_id": HD_ACCOUNT_ID,
                        "derivation_index": 0,
                        "address": EXPECTED_FIRST_FIVE[0],
                    }
                ]
            ]
        }
    )

    reserve_address_for_invoice(conn, deriver, HD_ACCOUNT_ID, INVOICE_ID, HEAD_BLOCK)

    params = conn.params_for(SQL_TAKE_FREE_FROM_POOL)
    assert params["reserved_from_block"] == HEAD_BLOCK
    assert params["invoice_id"] == INVOICE_ID


def test_a_negative_head_block_is_refused(deriver: Deriver) -> None:
    with pytest.raises(ValueError):
        reserve_address_for_invoice(FakeConnection({}), deriver, HD_ACCOUNT_ID, INVOICE_ID, -1)


# --------------------------------------------------------------------------
# Ceilings and inactive accounts
# --------------------------------------------------------------------------


def test_the_active_address_ceiling_stops_derivation(deriver: Deriver) -> None:
    """TZ 5.8/T5.2. The ceiling bounds the watcher's `eth_getLogs` filter.

    Crucially the index must NOT be bumped when the ceiling is hit — otherwise
    a rejected `/buy` would still push the gap forward, which is the damage the
    ceiling exists to prevent.
    """
    conn = FakeConnection(
        {
            SQL_TAKE_FREE_FROM_POOL: [[]],
            SQL_LOCK_ACCOUNT: [[account_row(active=500, ceiling=500)]],
        }
    )

    with pytest.raises(AddressPoolExhausted):
        reserve_address_for_invoice(conn, deriver, HD_ACCOUNT_ID, INVOICE_ID, HEAD_BLOCK)

    assert SQL_BUMP_NEXT_INDEX not in conn.statements()
    assert SQL_INSERT_ADDRESS not in conn.statements()


def test_an_inactive_account_cannot_issue_addresses(deriver: Deriver) -> None:
    """After rotation the old account is watch-only until the final sweep."""
    conn = FakeConnection({SQL_TAKE_FREE_FROM_POOL: [[]], SQL_LOCK_ACCOUNT: [[]]})

    with pytest.raises(InactiveHDAccount):
        reserve_address_for_invoice(conn, deriver, HD_ACCOUNT_ID, INVOICE_ID, HEAD_BLOCK)


# --------------------------------------------------------------------------
# Two-phase protocol
# --------------------------------------------------------------------------


def test_allocate_leaves_the_address_free(deriver: Deriver) -> None:
    conn = FakeConnection(
        {
            SQL_PEEK_FREE_FROM_POOL: [
                [
                    {
                        "id": 9,
                        "hd_account_id": HD_ACCOUNT_ID,
                        "derivation_index": 1,
                        "address": EXPECTED_FIRST_FIVE[1],
                    }
                ]
            ]
        }
    )

    result = allocate_free_address(conn, deriver, HD_ACCOUNT_ID)

    assert result.address == EXPECTED_FIRST_FIVE[1]
    assert result.newly_derived is False


def test_allocate_derives_when_the_pool_is_empty(deriver: Deriver) -> None:
    conn = FakeConnection(
        {
            SQL_PEEK_FREE_FROM_POOL: [[]],
            SQL_LOCK_ACCOUNT: [[account_row(next_index=0)]],
            SQL_BUMP_NEXT_INDEX: [[{"derivation_index": 0}]],
            SQL_INSERT_ADDRESS: [
                [
                    {
                        "id": 1,
                        "hd_account_id": HD_ACCOUNT_ID,
                        "derivation_index": 0,
                        "address": EXPECTED_FIRST_FIVE[0],
                    }
                ]
            ],
        }
    )

    result = allocate_free_address(conn, deriver, HD_ACCOUNT_ID)

    assert result.newly_derived is True
    assert conn.params_for(SQL_INSERT_ADDRESS)["status"] == "free"
    assert conn.params_for(SQL_INSERT_ADDRESS)["invoice_id"] is None


def test_binding_a_taken_address_raises(deriver: Deriver) -> None:
    """A lost race after the invoice already points at the address.

    Returning False here would let a caller shrug and continue with an invoice
    whose address belongs to someone else.
    """
    conn = FakeConnection({SQL_BIND_ADDRESS: [[]]})

    with pytest.raises(AddressNotBindable):
        bind_address_to_invoice(conn, 42, INVOICE_ID, HEAD_BLOCK)


def test_binding_succeeds_on_a_free_address() -> None:
    conn = FakeConnection(
        {
            SQL_BIND_ADDRESS: [
                [
                    {
                        "id": 42,
                        "hd_account_id": HD_ACCOUNT_ID,
                        "derivation_index": 2,
                        "address": EXPECTED_FIRST_FIVE[2],
                    }
                ]
            ]
        }
    )

    result = bind_address_to_invoice(conn, 42, INVOICE_ID, HEAD_BLOCK)

    assert result.address == EXPECTED_FIRST_FIVE[2]
    assert conn.params_for(SQL_BIND_ADDRESS)["reserved_from_block"] == HEAD_BLOCK


# --------------------------------------------------------------------------
# The SQL itself. These read like pedantry until someone "simplifies" a query.
# --------------------------------------------------------------------------


def test_pool_pickup_uses_skip_locked_and_lowest_index_first() -> None:
    for statement in (SQL_TAKE_FREE_FROM_POOL, SQL_PEEK_FREE_FROM_POOL):
        collapsed = " ".join(statement.split())
        assert "FOR UPDATE SKIP LOCKED" in collapsed
        assert "ORDER BY" in collapsed
        assert "derivation_index" in collapsed
        assert "status = 'free'" in collapsed
        assert "LIMIT 1" in collapsed


def test_index_bump_is_a_single_statement() -> None:
    """No read-then-write window: the claim and the increment are one UPDATE."""
    collapsed = " ".join(SQL_BUMP_NEXT_INDEX.split())

    assert "next_index = next_index + 1" in collapsed
    assert "RETURNING next_index - 1" in collapsed


def test_release_enforces_all_three_reuse_conditions() -> None:
    """All three live in the WHERE clause, not in Python (TZ 5.1 p. 2)."""
    collapsed = " ".join(SQL_RELEASE_DUE.split())

    assert "NOT ra.ever_funded" in collapsed  # condition 1
    assert "ra.cooldown_until <= now()" in collapsed  # condition 2
    assert "'awaiting', 'seen', 'partially_paid'" in collapsed  # invoice no longer live


def test_ever_funded_is_a_one_way_latch() -> None:
    """Nothing anywhere in the package sets `ever_funded` back to false.

    Condition 1 of the reuse rules is absolute: a funded address never returns
    to the pool "ни при каких обстоятельствах" (TZ 5.1 p. 2).
    """
    assert "ever_funded = true" in SQL_MARK_FUNDED

    source = (pytest.importorskip("pathlib").Path(pool.__file__)).read_text(encoding="utf-8")
    assert "ever_funded = false" not in source
    assert "ever_funded=false" not in source


def test_pool_pickup_never_hands_out_a_previously_funded_address() -> None:
    """Belt and braces on top of the CHECK constraint in migration 0001."""
    for statement in (SQL_TAKE_FREE_FROM_POOL, SQL_PEEK_FREE_FROM_POOL, SQL_BIND_ADDRESS):
        assert "ever_funded" in statement


def test_bind_is_compare_and_set() -> None:
    """TZ 5.8/T2.2: expected state in the WHERE clause, never read-then-write."""
    collapsed = " ".join(SQL_BIND_ADDRESS.split())

    assert "status = 'free'" in collapsed
    assert "current_invoice_id IS NULL" in collapsed


# --------------------------------------------------------------------------
# Integration — needs a real database, skipped otherwise.
# --------------------------------------------------------------------------

TEST_DSN = os.environ.get("NOTCHSTAVE_TEST_DSN")

integration = pytest.mark.skipif(
    not TEST_DSN,
    reason=(
        "set NOTCHSTAVE_TEST_DSN to a throwaway Postgres with migrations applied "
        "to exercise real FOR UPDATE SKIP LOCKED behaviour"
    ),
)


@integration
def test_concurrent_reservations_never_share_an_index() -> None:
    """The test TZ 5.1 p. 3 calls mandatory ("тест на параллельную выдачу").

    Deliberately left unimplemented rather than faked: it needs real
    connections, real transactions and a real chain of migrations, and a
    version that mocks the database would assert nothing about locking while
    looking like coverage.
    """
    pytest.skip("Week 2: implement against the migrated schema (TZ 5.1 p. 3)")
