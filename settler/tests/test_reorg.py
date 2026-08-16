"""TZ 5.4 — реорг после выдачи доступа. "Самый ценный тест в проекте."

The tracker version of a reorg costs a wrong notification. This one costs a
product handed over for money that no longer exists, and the recovery is not a
rollback of a row — it is a business decision with a user-visible consequence.

The properties asserted below, and why each is a separate assertion rather than
one "it worked":

* the entitlement is **revoked, not deleted**. "Why did this user have access
  last Tuesday" has to stay answerable, and a DELETE makes it unanswerable;
* the invoice goes back to a state where the buyer can still pay — but only
  while there is still time to, otherwise it lands in ``reverted``;
* the user is told, through the same outbox as every other message;
* ``notchstave_reverted_credits_total`` moves, because TZ section 7 puts it in
  the block of metrics whose normal value is zero and whose every increment is
  an incident;
* and the invoice becomes grantable again, which is the only reason
  ``entitlements_active_uniq`` is a partial index in the first place.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

from core.db import enums as E
from settler import metrics
from settler.policy import Outcome
from settler.service import SettlementResult, handle_reorg, settle_invoice
from settler.tests.conftest import (
    Scenario,
    World,
    count,
    counter_value,
    invoice_status,
    payment_status,
)

USDC = 1_000_000
PAYING_BLOCK = 90


async def a_delivered_invoice(
    world: World, conn: AsyncConnection, **kwargs: Any
) -> tuple[Scenario, int, SettlementResult]:
    """Settle an invoice for real, then hand back everything needed to break it."""
    scenario = await world.scenario(amount_due_raw=10 * USDC, **kwargs)
    await world.block(scenario.chain_id, PAYING_BLOCK, status=E.BlockStatus.CONFIRMED)
    payment_id = await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=PAYING_BLOCK,
    )
    result = await settle_invoice(conn, scenario.invoice_id)
    assert result.outcome is Outcome.PAID
    assert result.granted
    return scenario, payment_id, result


# ---------------------------------------------------------------------------
# The headline
# ---------------------------------------------------------------------------


async def test_a_reorg_after_delivery_revokes_access_without_deleting_it(
    conn: AsyncConnection, world: World
) -> None:
    """"Если по откаченному платежу доступ уже выдан — доступ отзывается." (TZ 5.4)"""
    scenario, payment_id, settled = await a_delivered_invoice(world, conn)
    before = counter_value(metrics.REVERTED_CREDITS)

    await world.orphan_block(scenario.chain_id, PAYING_BLOCK)
    reorg = await handle_reorg(conn, scenario.chain_id)

    assert reorg.reverted_payment_ids == (payment_id,)
    assert reorg.revoked_entitlement_ids == (settled.entitlement_id,)

    # The money is gone from the ledger's point of view.
    assert await payment_status(conn, payment_id) == "reverted"

    # The grant is revoked. The row is still there — that is the point.
    row = (
        await conn.execute(
            sa.text(
                """
                SELECT id, revoked_at, revoke_reason, granted_at
                  FROM entitlements WHERE invoice_id = :id
                """
            ),
            {"id": scenario.invoice_id},
        )
    ).mappings().one()
    assert row["id"] == settled.entitlement_id
    assert row["revoked_at"] is not None
    assert "reorg" in row["revoke_reason"]
    assert row["revoked_at"] >= row["granted_at"]

    assert await count(conn, "entitlements") == 1, "revoked, never deleted"
    assert await count(conn, "entitlements", "revoked_at IS NULL") == 0

    # The invoice can be paid again — the buyer's window is still open.
    assert await invoice_status(conn, scenario.invoice_id) == "awaiting"
    assert reorg.unsettled_invoices[scenario.invoice_id] == "awaiting"

    settled_at = (
        await conn.execute(
            sa.text("SELECT settled_at FROM invoices WHERE id = :id"),
            {"id": scenario.invoice_id},
        )
    ).scalar_one()
    assert settled_at is None

    # TZ section 7: normal value zero, every increment is an incident.
    assert counter_value(metrics.REVERTED_CREDITS) == before + 1


async def test_the_user_is_told_through_the_same_outbox(
    conn: AsyncConnection, world: World
) -> None:
    """"Пользователю уходит сообщение-поправка." (TZ 5.4)

    Queued in the same transaction as the revocation, like every other side
    effect in this package — there is no code path that revokes access and then
    tries to send a message.
    """
    scenario, _, settled = await a_delivered_invoice(world, conn)
    await world.orphan_block(scenario.chain_id, PAYING_BLOCK)

    reorg = await handle_reorg(conn, scenario.chain_id)

    assert len(reorg.notification_ids) == 1
    row = (
        await conn.execute(
            sa.text(
                """
                SELECT user_id, status::text AS status, payload_json
                  FROM notifications WHERE kind = 'entitlement_revoked'
                """
            )
        )
    ).mappings().one()
    assert row["user_id"] == scenario.user_id
    assert row["status"] == "queued"
    assert row["payload_json"]["reason"] == "chain_reorg"
    assert row["payload_json"]["entitlement_id"] == settled.entitlement_id
    assert row["payload_json"]["new_invoice_status"] == "awaiting"


async def test_the_decision_is_written_to_the_audit_log(
    conn: AsyncConnection, world: World
) -> None:
    scenario, payment_id, _ = await a_delivered_invoice(world, conn)
    await world.orphan_block(scenario.chain_id, PAYING_BLOCK)

    await handle_reorg(conn, scenario.chain_id)

    row = (
        await conn.execute(
            sa.text(
                "SELECT args_json, after_state FROM audit_log WHERE action = 'reorg.revoke'"
            )
        )
    ).mappings().one()
    assert row["args_json"]["chain_id"] == scenario.chain_id
    assert row["args_json"]["reverted_payment_ids"] == [payment_id]
    assert row["after_state"]["status"] == "awaiting"


# ---------------------------------------------------------------------------
# Where the invoice lands
# ---------------------------------------------------------------------------


async def test_an_invoice_past_its_window_lands_in_reverted_not_awaiting(
    conn: AsyncConnection, world: World
) -> None:
    """"Возвращается в состояние ожидания" only means something while there is time.

    Past the top-up window there is nothing to wait for, so the row goes to the
    terminal state that says "this was settled and then the money disappeared"
    rather than pretending the buyer can still fix it.
    """
    scenario, _, _ = await a_delivered_invoice(
        world,
        conn,
        age=dt.timedelta(hours=30),
        expires_in=dt.timedelta(minutes=15),
        topup_window=dt.timedelta(hours=24),
    )
    await world.orphan_block(scenario.chain_id, PAYING_BLOCK)

    reorg = await handle_reorg(conn, scenario.chain_id)

    assert reorg.unsettled_invoices[scenario.invoice_id] == "reverted"
    assert await invoice_status(conn, scenario.invoice_id) == "reverted"
    assert await count(conn, "entitlements", "revoked_at IS NOT NULL") == 1


async def test_the_invoice_can_be_paid_and_delivered_again(
    conn: AsyncConnection, world: World
) -> None:
    """The reason ``entitlements_active_uniq`` is partial (TZ 5.8/T2.1).

    After the revocation the invoice is live again and a fresh payment settles
    it normally — producing a *second* entitlement row, not a resurrection of
    the first. The history of what was granted and taken away survives intact.
    """
    scenario, _, first = await a_delivered_invoice(world, conn)
    await world.orphan_block(scenario.chain_id, PAYING_BLOCK)
    await handle_reorg(conn, scenario.chain_id)

    # The buyer sends again; the watcher records it in a block that survives.
    await world.block(scenario.chain_id, 93, status=E.BlockStatus.CONFIRMED)
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=93,
    )

    second = await settle_invoice(conn, scenario.invoice_id)

    assert second.outcome is Outcome.PAID
    assert second.granted
    assert second.entitlement_id != first.entitlement_id
    assert await count(conn, "entitlements") == 2
    assert await count(conn, "entitlements", "revoked_at IS NULL") == 1
    assert await invoice_status(conn, scenario.invoice_id) == "paid"


# ---------------------------------------------------------------------------
# When a reorg must NOT fire
# ---------------------------------------------------------------------------


async def test_a_reorg_on_a_quiet_chain_does_nothing(
    conn: AsyncConnection, world: World
) -> None:
    """The rollback runs every pass; it must be free when there is nothing to do."""
    scenario, _, _ = await a_delivered_invoice(world, conn)

    reorg = await handle_reorg(conn, scenario.chain_id)

    assert reorg.reverted_payment_ids == ()
    assert reorg.revoked_entitlement_ids == ()
    assert await count(conn, "entitlements", "revoked_at IS NULL") == 1
    assert await invoice_status(conn, scenario.invoice_id) == "paid"


async def test_a_transaction_re_included_at_the_same_height_is_left_alone(
    conn: AsyncConnection, world: World
) -> None:
    """The ``NOT EXISTS`` guard: an orphaned height that has been rebuilt is not empty.

    A reorg orphans a block and the watcher writes the replacement. If the
    rollback fired on "an orphaned block exists at this height" alone, it would
    revert payments that are still perfectly valid on the new chain.

    LIMITATION, and it is a real one: ``payments`` records ``block_number`` but
    not ``block_hash``, so this height-level guard is as precise as the schema
    allows. A payment that was in the orphaned block and *not* re-included is
    left credited here, and a payment re-included at a different height is
    reverted. Both need `/reconcile`. The fix is a column — see the Week 3 TODO
    in the docstring of :mod:`settler.service`.
    """
    scenario, payment_id, _ = await a_delivered_invoice(world, conn)

    await world.orphan_block(scenario.chain_id, PAYING_BLOCK)
    await world.block(
        scenario.chain_id, PAYING_BLOCK, status=E.BlockStatus.CONFIRMED, variant="-replacement"
    )

    reorg = await handle_reorg(conn, scenario.chain_id)

    assert reorg.reverted_payment_ids == ()
    assert await payment_status(conn, payment_id) == "credited"
    assert await count(conn, "entitlements", "revoked_at IS NULL") == 1


async def test_a_reorg_below_an_undelivered_invoice_reverts_money_but_revokes_nothing(
    conn: AsyncConnection, world: World
) -> None:
    """Not every rollback has a grant behind it, and that path must stay quiet.

    A payment reverted before it ever bought anything is bookkeeping. Emitting a
    "your access was revoked" message here would be telling the buyer about
    something that never happened.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    await world.block(scenario.chain_id, PAYING_BLOCK, status=E.BlockStatus.CONFIRMED)
    payment_id = await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=3 * USDC,  # short of the price: nothing was ever granted
        block_number=PAYING_BLOCK,
    )
    assert (await settle_invoice(conn, scenario.invoice_id)).outcome is Outcome.PARTIALLY_PAID
    before = counter_value(metrics.REVERTED_CREDITS)

    await world.orphan_block(scenario.chain_id, PAYING_BLOCK)
    reorg = await handle_reorg(conn, scenario.chain_id)

    assert reorg.reverted_payment_ids == (payment_id,)
    assert reorg.revoked_entitlement_ids == ()
    assert reorg.notification_ids == ()
    assert await payment_status(conn, payment_id) == "reverted"
    assert counter_value(metrics.REVERTED_CREDITS) == before, "no credit was reverted"


async def test_reverted_money_is_no_longer_in_the_total(
    conn: AsyncConnection, world: World
) -> None:
    """The aggregate is the single source of truth, so the rollback is enough.

    Nothing subtracts anything anywhere. ``reverted`` is simply not one of the
    statuses ``SUM(amount_raw)`` looks at, which is why a reorg needs no
    compensating arithmetic — the same property that makes TZ 5.3 idempotent.
    """
    scenario, _, _ = await a_delivered_invoice(world, conn)
    await world.orphan_block(scenario.chain_id, PAYING_BLOCK)
    await handle_reorg(conn, scenario.chain_id)

    again = await settle_invoice(conn, scenario.invoice_id)

    assert again.outcome is Outcome.NO_FUNDS
    assert await count(conn, "entitlements", "revoked_at IS NULL") == 0
