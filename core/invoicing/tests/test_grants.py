"""Invoice issuance under the PostgreSQL role that will actually run it.

Every other test in this directory runs as the database owner, which is fine for
testing what the service *does* and useless for testing what it *may* do.
Migration 0006 moved a capability between roles — invoice issuance from
``notchstave_api``/``notchstave_bot`` to ``notchstave_deriver`` — and a grant
change is exactly the kind of thing that is right on the day it is written and
quietly wrong six weeks later.

So this file does the two halves that matter, the same way
``settler/tests/test_grants.py`` does:

* **sufficient** — one complete ``/buy`` as ``notchstave_deriver``, proving the
  new matrix does not break the process it constrains, which is the failure mode
  nobody notices until deploy;
* **necessary** — the writes the other roles must no longer have, proving the
  REVOKEs did something. TZ 5.8/T1.2 is the reason ``receive_addresses`` is
  closed to everyone but the deriver, and 0006's own argument is the reason
  minting an invoice is now in the same place.

``SET ROLE`` rather than six logins: the roles are created ``NOLOGIN`` on
purpose, and a test that needed passwords for six roles would be a test nobody
runs.
"""

from __future__ import annotations

from typing import Any

import psycopg
import pytest

from core.invoicing.integrity import IntegrityKey
from core.invoicing.tests.conftest import FakeDeriver, World, buy, scalar

DERIVER_ROLE = "notchstave_deriver"
API_ROLE = "notchstave_api"
BOT_ROLE = "notchstave_bot"


@pytest.fixture(autouse=True)
def _require_roles(conn: psycopg.Connection[Any]) -> None:
    """Skip where migration 0002 could not create the roles.

    Creating roles is a cluster-level operation and 0002 degrades to a NOTICE on
    a managed database whose migrating user has no CREATEROLE. A red suite there
    would be reporting the wrong problem.
    """
    if scalar(conn, "SELECT 1 FROM pg_roles WHERE rolname = %(r)s", r=DERIVER_ROLE) is None:
        pytest.skip(f"{DERIVER_ROLE} does not exist; migration 0002 had no CREATEROLE")


def test_a_complete_buy_succeeds_with_only_the_derivers_privileges(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """The sufficiency half — and the one that would have caught a missing GRANT.

    Issuance touches seven tables (``products``, ``assets``, ``chains``,
    ``users`` implicitly through the FK, ``receive_addresses``, ``hd_accounts``,
    ``invoices``, ``rate_limits``, ``audit_log``). Migration 0006 had to widen
    the deriver's matrix for four of them; this is what says the list was
    complete.
    """
    shop = world.shop()
    with conn.cursor() as cur:
        cur.execute(f"SET ROLE {DERIVER_ROLE}")

    view = buy(conn, deriver, key, shop)

    with conn.cursor() as cur:
        cur.execute("RESET ROLE")

    assert view.address_id > 0
    assert scalar(conn, "SELECT count(*) FROM invoices") == 1
    assert scalar(conn, "SELECT count(*) FROM rate_limits") == 1
    assert scalar(conn, "SELECT count(*) FROM audit_log WHERE action = 'invoice_created'") == 1
    # The deferred foreign key resolved at the end of the statement batch under
    # a restricted role exactly as it does under the owner.
    assert (
        scalar(
            conn,
            "SELECT current_invoice_id FROM receive_addresses WHERE id = %(id)s",
            id=view.address_id,
        )
        == view.invoice_id
    )


@pytest.mark.parametrize("role", [API_ROLE, BOT_ROLE])
def test_api_and_bot_can_no_longer_mint_an_invoice(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey, role: str
) -> None:
    """The necessity half of 0006.

    An invoice is a promise that an address derives from our xpub. A component
    that cannot derive can only copy an address from somewhere and assert it, so
    letting it mint invoices duplicates the capability rather than dividing it.
    After 0006 a compromised api or bot can read and cancel invoices and cannot
    put a new address in front of a buyer.
    """
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    view = buy(conn, deriver, key, shop)
    conn.commit()

    with conn.cursor() as cur:
        cur.execute(f"SET ROLE {role}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute(
                """
                INSERT INTO invoices (id, user_id, product_id, chain_id, asset_id, address_id,
                                      amount_due_raw, amount_due_usd, rate_snapshot,
                                      rate_locked_until, expires_at, topup_window_until,
                                      integrity_mac, public_token, policy_version)
                SELECT gen_random_uuid(), user_id, product_id, chain_id, asset_id, address_id,
                       amount_due_raw, amount_due_usd, rate_snapshot, rate_locked_until,
                       expires_at, topup_window_until, integrity_mac, 'stolen', policy_version
                  FROM invoices WHERE id = %(id)s
                """,
                {"id": view.invoice_id},
            )
    conn.rollback()

    # ...but the two things they still legitimately do are untouched.
    with conn.cursor() as cur:
        cur.execute(f"SET ROLE {role}")
        cur.execute(
            "UPDATE invoices SET status = 'cancelled' WHERE id = %(id)s", {"id": view.invoice_id}
        )
        cur.execute("SELECT count(*) FROM invoices")
        cur.execute("RESET ROLE")
    conn.rollback()


@pytest.mark.parametrize("role", [API_ROLE, BOT_ROLE])
def test_nobody_but_the_deriver_may_still_write_receive_addresses(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey, role: str
) -> None:
    """TZ 5.8/T1.2, re-asserted because 0006 touched the neighbouring grants.

    The whole point of moving issuance was to *narrow* who can put an address in
    front of a buyer. If widening the deriver's matrix had come with a stray
    widening elsewhere, this is where it shows.
    """
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    view = buy(conn, deriver, key, shop)
    conn.commit()

    with conn.cursor() as cur:
        cur.execute(f"SET ROLE {role}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute(
                "UPDATE receive_addresses SET address = %(a)s WHERE id = %(id)s",
                {"a": "0x" + "ba" * 20, "id": view.address_id},
            )
    conn.rollback()


def test_the_deriver_cannot_rewrite_an_invoice_it_issued(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """0006 granted INSERT and deliberately not UPDATE.

    Issuing an invoice and re-pricing one are different powers. Settlement,
    expiry and cancellation stay with the settler and the bot; the deriver can
    create a row and never touch it again, which keeps ``integrity_mac`` a
    statement about the moment of issuance rather than about the last write.
    """
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    view = buy(conn, deriver, key, shop)
    conn.commit()

    with conn.cursor() as cur:
        cur.execute(f"SET ROLE {DERIVER_ROLE}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute(
                "UPDATE invoices SET amount_due_raw = 1 WHERE id = %(id)s", {"id": view.invoice_id}
            )
    conn.rollback()


@pytest.mark.parametrize("role", [API_ROLE, BOT_ROLE])
def test_bot_and_api_may_ask_for_an_invoice_and_may_not_answer(
    conn: psycopg.Connection[Any], world: World, role: str
) -> None:
    """Migration 0007's asymmetry, which is where its security lives.

    A ``bot`` that could UPDATE ``invoice_requests`` could write its own reply —
    ``status='done'`` with a ``result_json`` naming any address it liked — and
    the buyer would be shown it. That is precisely the capability 0006 took away
    by moving INSERT on ``invoices`` to the deriver, so leaving it available one
    table over would have undone the whole revision. The MAC check in
    ``core.invoicing.client`` is the second line here; this is the first.
    """
    shop = world.shop()

    with conn.cursor() as cur:
        cur.execute(f"SET ROLE {role}")
        cur.execute(
            """
            INSERT INTO invoice_requests (id, user_id, product_id, chain_id, asset_id,
                                          hd_account_id)
            VALUES (gen_random_uuid(), %(u)s, %(p)s, %(c)s, %(a)s, %(h)s)
            RETURNING id
            """,
            {
                "u": shop.user_id,
                "p": shop.product_id,
                "c": shop.chain_id,
                "a": shop.asset_id,
                "h": shop.hd_account_id,
            },
        )
        row = cur.fetchone()
        assert row is not None

        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("UPDATE invoice_requests SET status = 'done'")
    conn.rollback()

    with conn.cursor() as cur:
        cur.execute(f"SET ROLE {role}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("DELETE FROM invoice_requests")
    conn.rollback()


def test_the_deriver_may_answer_a_request_and_may_not_create_one(
    conn: psycopg.Connection[Any], world: World
) -> None:
    """The other half of the asymmetry, and it is a T5 measure rather than a T1 one.

    Every quota in TZ 5.8/T5 sits on the way *in* — the one-open-per-user index
    at INSERT, the hourly and active-invoice counts inside ``create_invoice``.
    A process that could enqueue its own work would be on the wrong side of all
    of them. The deriver answers questions; it does not get to ask any.
    """
    shop = world.shop()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO invoice_requests (id, user_id, product_id, chain_id, asset_id,
                                          hd_account_id)
            VALUES (gen_random_uuid(), %(u)s, %(p)s, %(c)s, %(a)s, %(h)s)
            """,
            {
                "u": shop.user_id,
                "p": shop.product_id,
                "c": shop.chain_id,
                "a": shop.asset_id,
                "h": shop.hd_account_id,
            },
        )
    conn.commit()

    with conn.cursor() as cur:
        cur.execute(f"SET ROLE {DERIVER_ROLE}")
        # Claiming and answering: the two writes the loop actually performs.
        cur.execute("UPDATE invoice_requests SET status = 'processing', claimed_at = now()")
        cur.execute("DELETE FROM invoice_requests WHERE status = 'done'")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute(
                """
                INSERT INTO invoice_requests (id, user_id, product_id, chain_id, asset_id,
                                              hd_account_id)
                VALUES (gen_random_uuid(), %(u)s, %(p)s, %(c)s, %(a)s, %(h)s)
                """,
                {
                    "u": shop.user_id,
                    "p": shop.product_id,
                    "c": shop.chain_id,
                    "a": shop.asset_id,
                    "h": shop.hd_account_id,
                },
            )
    conn.rollback()


def test_no_role_can_erase_the_issuance_from_the_audit_log(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 5.8/T7, T8 — append-only, and now with one more thing appended to it."""
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    buy(conn, deriver, key, shop)
    conn.commit()

    for role in (DERIVER_ROLE, API_ROLE, BOT_ROLE):
        with conn.cursor() as cur:
            cur.execute(f"SET ROLE {role}")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute("DELETE FROM audit_log WHERE action = 'invoice_created'")
        conn.rollback()
