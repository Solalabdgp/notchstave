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

``SET ROLE`` rather than a second connection with its own login: the roles are
created ``NOLOGIN`` on purpose, and a test that needed passwords for six roles
would be a test nobody runs.
"""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

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
        ("UPDATE users SET internal_balance_usd = 999", "see the Week 3 TODO on overpayment"),
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
