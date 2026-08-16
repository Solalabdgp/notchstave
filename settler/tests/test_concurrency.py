"""TZ 5.8/T2 — двадцать корутин на одном инвойсе, ровно одна выдача.

The tests here are the reason the settler is written the way it is, so it is
worth being precise about what each one actually proves.

``test_twenty_workers_grant_exactly_once`` runs the same scenario under four
lock configurations. Three of them (no lock at all, a lock that has failed open
because Redis is unreachable, and a lock deliberately handing the same invoice
to everybody) put twenty real workers on twenty real connections into the money
path simultaneously. If correctness lived in Redis rather than in PostgreSQL,
those three would produce twenty entitlements and the fourth would hide it. That
is exactly the failure TZ 5.8/T2.4 asks to be ruled out by a test:

    Если убрать Redis целиком, система обязана остаться корректной —
    это отдельный тест.

``test_the_partial_index_alone_stops_a_second_grant`` then removes the second
line of defence too. The twenty-worker test is serialised by ``SELECT FOR
UPDATE``, so it never actually reaches ``entitlements_active_uniq`` — a passing
run there says nothing about whether the index works or whether the code handles
its violation correctly. So that test calls the grant directly, with no invoice
lock anywhere, and checks both that exactly one row appears and that the losers
return quietly instead of raising.

No mocks: a mocked connection cannot deadlock, cannot block on a row lock, and
cannot violate a unique index, which is to say it cannot fail any of these.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from core.db import enums as E
from settler import repository as repo
from settler.locks import BrokenLock, InvoiceLock, NullLock, RedisAdvisoryLock
from settler.policy import Outcome
from settler.service import LIVE_INVOICE_STATUSES, Settler
from settler.tests.conftest import Scenario, World, count

USDC = 1_000_000
WORKERS = 20


# ---------------------------------------------------------------------------
# Redis doubles
# ---------------------------------------------------------------------------


class FakeRedis:
    """A Redis that works. Enough of ``SET NX PX`` and ``EVAL`` for the lock."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def set(
        self, name: str, value: str, *, nx: bool = False, px: int | None = None
    ) -> Any:
        if nx and name in self._store:
            return None
        self._store[name] = value
        return True

    async def eval(self, script: str, numkeys: int, *args: Any) -> Any:
        key, token = args[0], args[1]
        if self._store.get(key) == token:
            del self._store[key]
            return 1
        return 0


class DownRedis:
    """A Redis that is not there. Every call raises, as a real outage would.

    The lock must fail *open* — do the work — because failing closed would make
    Redis a correctness dependency through the back door, which is the exact
    thing TZ 5.8/T2.4 forbids.
    """

    async def set(self, *args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("redis is down")

    async def eval(self, *args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("redis is down")


LOCKS: dict[str, tuple[InvoiceLock, bool]] = {
    # name -> (lock, does every worker reach the database?)
    "no-redis-at-all": (NullLock(), True),
    "redis-working": (RedisAdvisoryLock(FakeRedis()), False),
    "redis-down": (RedisAdvisoryLock(DownRedis()), True),
    "redis-lying": (BrokenLock(), True),
}


# ---------------------------------------------------------------------------
# Committed setup
# ---------------------------------------------------------------------------


async def a_fully_paid_invoice(engine: AsyncEngine) -> Scenario:
    """Set the scene in its own committed transaction.

    The ``conn`` fixture used elsewhere holds one open transaction for the whole
    test, which is fine when a test is the only actor. Here twenty other
    connections have to *see* the invoice, so the setup must be committed before
    they start — an uncommitted fixture would produce twenty ``InvoiceNotFound``
    errors and a very confusing green run if the assertions were weaker.
    """
    async with engine.begin() as conn:
        world = World(conn)
        scenario = await world.scenario(amount_due_raw=10 * USDC)
        await world.payment(
            chain_id=scenario.chain_id,
            asset_id=scenario.asset_id,
            address_id=scenario.address_id,
            invoice_id=scenario.invoice_id,
            amount_raw=10 * USDC,
            block_number=90,
            status=E.PaymentStatus.CONFIRMED,
        )
    return scenario


# ---------------------------------------------------------------------------
# T2 — the headline test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("lock_name", list(LOCKS))
async def test_twenty_workers_grant_exactly_once(
    engine: AsyncEngine, lock_name: str
) -> None:
    """"двадцать корутин одновременно обрабатывают один confirmed-инвойс —
    ровно одна запись в entitlements, ровно одно сообщение" (TZ 5.8/T2).
    """
    lock, everyone_works = LOCKS[lock_name]
    scenario = await a_fully_paid_invoice(engine)
    settler = Settler(engine, lock=lock)

    results = await asyncio.gather(
        *(settler.settle(scenario.invoice_id) for _ in range(WORKERS))
    )

    granted = [r for r in results if r.granted]
    assert len(granted) == 1, f"{len(granted)} workers granted access under {lock_name}"

    async with engine.connect() as conn:
        assert await count(conn, "entitlements") == 1
        assert await count(conn, "entitlements", "revoked_at IS NULL") == 1
        assert await count(conn, "notifications", "kind = 'invoice_settled'") == 1
        assert await count(conn, "payments", "status = 'credited'") == 1
        assert await count(conn, "invoices", "status = 'paid'") == 1
        # One decision, one audit row. Nineteen no-ops are not decisions.
        assert await count(conn, "audit_log", "action = 'settle.paid'") == 1

    losers = [r for r in results if not r.granted]
    if everyone_works:
        # Every worker went to the database and every loser found the invoice
        # already settled — that is PostgreSQL doing the work, not the lock.
        assert all(r.outcome is Outcome.ALREADY_SETTLED for r in losers)
        assert not any(r.outcome is Outcome.SKIPPED_BUSY for r in losers)
    else:
        # With a working lock most workers never open a transaction at all. That
        # is the entire value of the lock: saved work, not correctness.
        assert any(r.outcome is Outcome.SKIPPED_BUSY for r in losers)


async def test_a_worker_that_skipped_on_the_lock_claims_nothing(
    engine: AsyncEngine,
) -> None:
    """``SKIPPED_BUSY`` is not ``ALREADY_SETTLED`` and the difference matters.

    A worker that failed to take the advisory lock knows nothing about the
    invoice — not that it is settled, not that it is unpaid. Collapsing the two
    outcomes would let a lock held by a crashed worker read as "this invoice is
    done", which is how an advisory lock quietly becomes a source of truth.
    """
    scenario = await a_fully_paid_invoice(engine)
    redis = FakeRedis()
    await redis.set(f"invoice:{scenario.invoice_id}", "someone-else", nx=True, px=30_000)

    settler = Settler(engine, lock=RedisAdvisoryLock(redis))
    result = await settler.settle(scenario.invoice_id)

    assert result.outcome is Outcome.SKIPPED_BUSY
    assert not result.granted
    assert result.decision is None

    async with engine.connect() as conn:
        assert await count(conn, "entitlements") == 0
        assert await count(conn, "invoices", "status = 'awaiting'") == 1


# ---------------------------------------------------------------------------
# T2.1 — the index on its own
# ---------------------------------------------------------------------------


async def test_the_partial_index_alone_stops_a_second_grant(
    engine: AsyncEngine,
) -> None:
    """Remove the row lock and the CAS; the index must still hold (TZ 5.8/T2.1).

    Twenty transactions call the grant directly, with nothing serialising them
    beforehand. ``entitlements_active_uniq`` blocks each newcomer until the
    current inserter commits and then rejects it, and
    :func:`settler.repository.insert_entitlement` turns that rejection into
    ``None`` — "не «падает с ошибкой», а именно тихо признаёт, что проиграл
    гонку".
    """
    scenario = await a_fully_paid_invoice(engine)

    async def try_grant() -> int | None:
        async with engine.begin() as conn:
            return await repo.insert_entitlement(
                conn,
                user_id=scenario.user_id,
                product_id=scenario.product_id,
                invoice_id=scenario.invoice_id,
                subscription_days=None,
            )

    outcomes = await asyncio.gather(*(try_grant() for _ in range(WORKERS)))

    winners = [o for o in outcomes if o is not None]
    assert len(winners) == 1, f"{len(winners)} inserts succeeded"
    assert outcomes.count(None) == WORKERS - 1

    async with engine.connect() as conn:
        assert await count(conn, "entitlements") == 1


async def test_a_genuine_constraint_failure_is_not_swallowed(
    engine: AsyncEngine,
) -> None:
    """Only ``entitlements_active_uniq`` means "lost the race".

    A broken foreign key is a bug, and returning ``None`` for it would report a
    lost race that never happened — the caller would then finish quietly having
    granted nothing, which is worse than crashing.
    """
    scenario = await a_fully_paid_invoice(engine)

    with pytest.raises(sa.exc.IntegrityError):
        async with engine.begin() as conn:
            await repo.insert_entitlement(
                conn,
                user_id=999_999_999,  # no such user
                product_id=scenario.product_id,
                invoice_id=scenario.invoice_id,
                subscription_days=None,
            )

    async with engine.connect() as conn:
        assert await count(conn, "entitlements") == 0


async def test_a_revoked_grant_frees_the_invoice_for_a_new_one(
    engine: AsyncEngine,
) -> None:
    """The index is partial precisely so that TZ 5.4 can re-grant after a reorg.

    A plain unique index would make the revocation permanent, which would mean a
    reorg that later resolves in the buyer's favour could never be honoured.
    """
    scenario = await a_fully_paid_invoice(engine)

    async with engine.begin() as conn:
        first = await repo.insert_entitlement(
            conn,
            user_id=scenario.user_id,
            product_id=scenario.product_id,
            invoice_id=scenario.invoice_id,
            subscription_days=None,
        )
        assert first is not None
        blocked = await repo.insert_entitlement(
            conn,
            user_id=scenario.user_id,
            product_id=scenario.product_id,
            invoice_id=scenario.invoice_id,
            subscription_days=None,
        )
        assert blocked is None

        await repo.revoke_entitlements_for_invoices(
            conn, [scenario.invoice_id], reason="test"
        )
        second = await repo.insert_entitlement(
            conn,
            user_id=scenario.user_id,
            product_id=scenario.product_id,
            invoice_id=scenario.invoice_id,
            subscription_days=None,
        )
        assert second is not None and second != first

        assert await count(conn, "entitlements") == 2
        assert await count(conn, "entitlements", "revoked_at IS NULL") == 1


# ---------------------------------------------------------------------------
# T2.2 — compare-and-set
# ---------------------------------------------------------------------------


async def test_cas_reports_the_loss_instead_of_overwriting(engine: AsyncEngine) -> None:
    """"Ноль затронутых строк означает, что состояние уже изменил кто-то другой."

    The expected state is in the WHERE clause, so a transition from a state the
    caller did not expect writes nothing at all — as opposed to a read-check-write
    in Python, which would happily stamp `paid` over `cancelled`.
    """
    scenario = await a_fully_paid_invoice(engine)

    async with engine.begin() as conn:
        won = await repo.cas_invoice_status(
            conn,
            scenario.invoice_id,
            new_status=str(E.InvoiceStatus.PAID),
            expected=LIVE_INVOICE_STATUSES,
            mark_settled=True,
        )
        assert won is True

        again = await repo.cas_invoice_status(
            conn,
            scenario.invoice_id,
            new_status=str(E.InvoiceStatus.PAID),
            expected=LIVE_INVOICE_STATUSES,
            mark_settled=True,
        )
        assert again is False, "a second transition from a live status must not happen"

        status = (
            await conn.execute(
                sa.text("SELECT status::text, settled_at FROM invoices WHERE id = :id"),
                {"id": scenario.invoice_id},
            )
        ).one()
        assert status[0] == "paid"
        assert status[1] is not None


async def test_cas_against_an_unknown_invoice_writes_nothing(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        won = await repo.cas_invoice_status(
            conn,
            uuid.uuid4(),
            new_status=str(E.InvoiceStatus.PAID),
            expected=LIVE_INVOICE_STATUSES,
        )
        assert won is False


# ---------------------------------------------------------------------------
# T2.5 — the outbox is in the same transaction
# ---------------------------------------------------------------------------


async def test_a_failed_settlement_leaves_no_half_issued_access(
    engine: AsyncEngine,
) -> None:
    """"Убийство воркера в середине транзакции не оставляет полувыданного доступа."

    A worker killed mid-settlement is a transaction that never commits. It is
    simulated here by raising after the grant and before the transaction ends —
    the same effect on the database, without needing to kill a process. The
    entitlement, the outbox row and the invoice status either all exist or none
    of them do, because they are one transaction (TZ 5.8/T2.5).
    """
    scenario = await a_fully_paid_invoice(engine)

    class Boom(Exception):
        pass

    with contextlib.suppress(Boom):
        async with engine.begin() as conn:
            from settler.service import settle_invoice

            result = await settle_invoice(conn, scenario.invoice_id)
            assert result.granted
            assert await count(conn, "entitlements") == 1
            raise Boom

    async with engine.connect() as conn:
        assert await count(conn, "entitlements") == 0
        assert await count(conn, "notifications") == 0
        assert await count(conn, "invoices", "status = 'awaiting'") == 1
        assert await count(conn, "payments", "status = 'credited'") == 0

    # And the work is simply redone on the next pass. Nothing needs repairing.
    settler = Settler(engine)
    redo = await settler.settle(scenario.invoice_id)
    assert redo.outcome is Outcome.PAID
    assert redo.granted
