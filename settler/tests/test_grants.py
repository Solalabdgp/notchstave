"""The settler under its own PostgreSQL role (migration 0002, TZ 5.8/T1.2, T7).

Every other test in this directory runs as the database owner, which is fine for
testing what the settler *does* and useless for testing what it *may* do. The
process separation of TZ section 4 is decorative unless the grants back it, and
grants are the kind of thing that is written once and quietly drifts.

So this file does two things:

* runs one complete settlement as ``notchstave_settler`` — proving the grant
  matrix is *sufficient*, i.e. that the privilege separation does not break the
  process it constrains, which is the failure mode nobody notices until deploy;
* tries the writes the settler must never have — proving the matrix is
  *necessary*. Both REVOKEs at the end of migration 0002 exist because of
  specific holes (the settler used to hold UPDATE on ``receive_addresses``), and
  a test is what stops them being reopened by a future edit to the GRANTS dict.

``SET ROLE`` on the owner's connection, which is a deliberate choice and a
limited one. It proves what ``notchstave_settler`` is *allowed* to do; it cannot
prove that the settler process ever assumes it, and for weeks 1-5 it did not —
every process connected as the table owner, so none of these REVOKEs was ever
evaluated in production. That half is now covered by
``settler/tests/test_login_roles.py``, which connects as
``notchstave_settler_login`` with a password and never calls ``SET ROLE``.

This file stays because the two are complementary, not redundant: ``SET ROLE``
needs no credentials, so it runs on any developer's database, and the sufficiency
half below (a whole settlement, a whole admin resolution, under the role) is far
more thorough than anything a connection-level test would be worth writing twice.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

from settler import repository as repo
from settler.admin import repository as admin_repo
from settler.policy import Outcome
from settler.service import handle_reorg, settle_invoice
from settler.tests.conftest import World, count, invoice_status

USDC = 1_000_000
SETTLER_ROLE = "notchstave_settler"


@pytest.fixture(autouse=True)
async def _require_roles(conn: AsyncConnection) -> None:
    """Skip rather than fail where migration 0002 could not create the roles.

    Creating roles is a cluster-level operation; 0002 degrades to a NOTICE on a
    managed database where the migrating user has no CREATEROLE. A red suite
    there would be reporting the wrong problem.
    """
    exists = (
        await conn.execute(
            sa.text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": SETTLER_ROLE}
        )
    ).scalar_one_or_none()
    if not exists:
        pytest.skip(f"{SETTLER_ROLE} does not exist; migration 0002 had no CREATEROLE")


async def test_a_full_settlement_succeeds_with_only_the_settlers_privileges(
    conn: AsyncConnection, world: World
) -> None:
    """The grant matrix is sufficient: nothing the money path needs is missing.

    This covers, in one pass, INSERT on ``entitlements`` / ``notifications`` /
    ``audit_log``, UPDATE on ``invoices`` / ``payments``, SELECT on
    ``receive_addresses`` / ``assets`` / ``chains`` / ``products`` / ``blocks``,
    and USAGE on the sequences behind all of them.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    await conn.execute(sa.text(f"SET LOCAL ROLE {SETTLER_ROLE}"))
    try:
        result = await settle_invoice(conn, scenario.invoice_id)
    finally:
        await conn.execute(sa.text("RESET ROLE"))

    assert result.outcome is Outcome.PAID
    assert result.granted
    assert await invoice_status(conn, scenario.invoice_id) == "paid"
    assert await count(conn, "entitlements") == 1
    assert await count(conn, "notifications") == 1
    assert await count(conn, "audit_log") == 1


async def test_the_reorg_path_also_fits_inside_the_grant_matrix(
    conn: AsyncConnection, world: World
) -> None:
    """Revocation touches a different set of tables and is easy to forget."""
    from core.db import enums as E

    scenario = await world.scenario(amount_due_raw=10 * USDC)
    await world.block(scenario.chain_id, 90, status=E.BlockStatus.CONFIRMED)
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )
    assert (await settle_invoice(conn, scenario.invoice_id)).granted
    await world.orphan_block(scenario.chain_id, 90)

    await conn.execute(sa.text(f"SET LOCAL ROLE {SETTLER_ROLE}"))
    try:
        reorg = await handle_reorg(conn, scenario.chain_id)
    finally:
        await conn.execute(sa.text("RESET ROLE"))

    assert len(reorg.revoked_entitlement_ids) == 1
    assert await count(conn, "entitlements", "revoked_at IS NOT NULL") == 1


@pytest.mark.parametrize(
    ("statement", "why"),
    [
        (
            "UPDATE receive_addresses SET status = 'funded'",
            "TZ 5.8/T1.2 — only the deriver writes the address pool",
        ),
        (
            "INSERT INTO receive_addresses (hd_account_id, derivation_index, address) "
            "VALUES (1, 999, '0x1111111111111111111111111111111111111111')",
            "an address can only be derived, never declared",
        ),
        (
            "UPDATE audit_log SET action = 'nothing happened'",
            "TZ 5.8/T7, T8 — decisions cannot be edited after the fact",
        ),
        ("DELETE FROM audit_log", "append-only means append-only"),
        (
            "DELETE FROM entitlements",
            "TZ 5.4 — a grant is revoked, never deleted; the role cannot delete at all",
        ),
        ("UPDATE products SET price_usd = 1", "the settler does not set prices"),
        # Migration 0003 grants UPDATE on exactly one column of `users`. These
        # three are the proof that "exactly one" is enforced by PostgreSQL and
        # not merely intended: `tg_id` in particular decides which human owns a
        # purchase, and a settler able to rewrite it could move a product to a
        # different person without touching `entitlements` at all.
        ("UPDATE users SET lang = 'ru'", "migration 0003 grants one column, not the table"),
        ("UPDATE users SET tg_id = 1", "a settler must never be able to reassign an account"),
        (
            "UPDATE users SET settings_json = '{}'::jsonb",
            "column-level grants are per column, and this is not the column",
        ),
        (
            "UPDATE sweep_exports SET total_raw = 0",
            "0003 grants SELECT+INSERT: a record of what to sweep must not be revisable",
        ),
        (
            "DELETE FROM sweep_exports",
            "same reason as audit_log — the history of exports is the audit of the sweep",
        ),
    ],
)
async def test_the_settler_role_is_refused_the_writes_it_must_not_have(
    conn: AsyncConnection, world: World, statement: str, why: str
) -> None:
    await world.scenario(amount_due_raw=10 * USDC)

    await conn.execute(sa.text(f"SET LOCAL ROLE {SETTLER_ROLE}"))
    try:
        with pytest.raises(sa.exc.ProgrammingError) as caught:
            async with conn.begin_nested():
                await conn.execute(sa.text(statement))
        assert "permission denied" in str(caught.value).lower(), why
    finally:
        await conn.execute(sa.text("RESET ROLE"))


async def test_the_settler_may_credit_an_internal_balance_and_nothing_else_on_users(
    conn: AsyncConnection, world: World
) -> None:
    """Migration 0003, both halves: the grant is sufficient *and* one column wide.

    The Week 2 settler recorded a tolerated overpayment in the outbox and left
    ``users.internal_balance_usd`` untouched, because migration 0002 gave it only
    SELECT — a gap the settler agent flagged rather than closed by widening a
    privilege. 0003 closes it with ``GRANT UPDATE (internal_balance_usd)``, and
    this test is the reason that phrasing was chosen over the table-level grant:
    the narrowing is checked, not asserted in a comment.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)

    await conn.execute(sa.text(f"SET LOCAL ROLE {SETTLER_ROLE}"))
    try:
        await repo.credit_internal_balance(
            conn, user_id=scenario.user_id, delta_usd=Decimal("2.50")
        )
        with pytest.raises(sa.exc.ProgrammingError) as caught:
            async with conn.begin_nested():
                await conn.execute(
                    sa.text("UPDATE users SET lang = 'ru' WHERE id = :id"),
                    {"id": scenario.user_id},
                )
    finally:
        await conn.execute(sa.text("RESET ROLE"))

    assert "permission denied" in str(caught.value).lower()
    balance = (
        await conn.execute(
            sa.text("SELECT internal_balance_usd FROM users WHERE id = :id"),
            {"id": scenario.user_id},
        )
    ).scalar_one()
    assert Decimal(balance) == Decimal("2.50")


async def test_the_settler_may_record_a_sweep_export(
    conn: AsyncConnection, world: World
) -> None:
    """0003's second grant. `/sweeplist` runs under this role, so it needs INSERT.

    Migration 0002 gave ``sweep_exports`` to the bot on the assumption that the
    bot builds the file. It does not: the bot is the surface of the admin
    commands and the settler executes them, so that `/resolve credit` never
    requires giving the bot process the power to grant an entitlement (TZ
    5.8/T2, T7).
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)

    await conn.execute(sa.text(f"SET LOCAL ROLE {SETTLER_ROLE}"))
    try:
        export_id, _generated_at = await admin_repo.record_sweep_export(
            conn,
            address_count=1,
            total_raw=Decimal(10 * USDC),
            asset_id=scenario.asset_id,
            file_ref="grants.csv",
            operator_id=770_001,
        )
    finally:
        await conn.execute(sa.text("RESET ROLE"))

    assert export_id > 0


async def test_the_admin_path_fits_inside_the_settlers_privileges(
    conn: AsyncConnection, world: World
) -> None:
    """`/resolve credit` under the settler role, end to end.

    The sufficiency half of the matrix for the Week 3 additions, in the same
    spirit as the settlement test at the top of this file: it covers UPDATE on
    ``manual_reviews``, INSERT on ``entitlements`` / ``notifications`` /
    ``audit_log``, UPDATE on ``invoices`` / ``payments``, and SELECT everywhere
    the resolution reads. The failure mode it protects against — a privilege the
    admin path needs and does not have — is invisible until a real owner runs a
    real command in production.
    """
    import datetime as dt

    from settler.admin.reviews import ResolutionOutcome, resolve_manual_review
    from settler.policy import Outcome
    from settler.service import settle_invoice

    scenario = await world.scenario(
        amount_due_raw=10 * USDC,
        age=dt.timedelta(minutes=30),
        expires_in=dt.timedelta(minutes=15),
        topup_window=dt.timedelta(0),
    )
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=4 * USDC,
        block_number=90,
    )
    opened = await settle_invoice(conn, scenario.invoice_id)
    assert opened.outcome is Outcome.UNDERPAID_MANUAL_REVIEW
    review_id = opened.manual_review_ids[0]

    await conn.execute(sa.text(f"SET LOCAL ROLE {SETTLER_ROLE}"))
    try:
        result = await resolve_manual_review(
            conn, review_id, "credit", 770_001, "granted under the settler role"
        )
    finally:
        await conn.execute(sa.text("RESET ROLE"))

    assert result.outcome is ResolutionOutcome.CREDITED
    assert await invoice_status(conn, scenario.invoice_id) == "paid"
