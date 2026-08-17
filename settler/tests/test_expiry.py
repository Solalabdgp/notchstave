"""Rate-lock expiry (TZ 5.5, "Курс уехал между выставлением и оплатой").

The row of the TZ 5.5 anomaly table this file covers reads: "Курс фиксируется в
момент создания инвойса (``rate_snapshot``) и действует ``rate_locked_until`` (по
умолчанию 15 минут). После — инвойс истекает."

Every test here is really about the same question — *which* of the two deadlines
on an invoice applies to *which* invoice — because getting that wrong is silent
in both directions. Expire too eagerly and a buyer whose money is already
in-flight is told their invoice is dead. Expire too lazily and someone pays an
hour-old ETH quote at leisure.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

from core.db import enums as E
from settler.service import expire_stale_invoices, sweep_expired_invoices
from settler.tests.conftest import World, count, invoice_status

USDC = 1_000_000

#: A quote that went stale fifteen minutes ago on an invoice created half an
#: hour ago. The default `World.scenario` shape, spelled out because most tests
#: below vary exactly one of these two numbers.
STALE: dict[str, Any] = {
    "age": dt.timedelta(minutes=30),
    "expires_in": dt.timedelta(minutes=15),
}

#: Created a minute ago, quote good for another fourteen.
FRESH: dict[str, Any] = {
    "age": dt.timedelta(minutes=1),
    "expires_in": dt.timedelta(minutes=15),
}


async def test_an_unpaid_invoice_expires_once_its_quote_is_stale(
    conn: AsyncConnection, world: World
) -> None:
    scenario = await world.scenario(amount_due_raw=10 * USDC, **STALE)

    expired = await expire_stale_invoices(conn)

    assert expired == (scenario.invoice_id,)
    assert await invoice_status(conn, scenario.invoice_id) == str(E.InvoiceStatus.EXPIRED)
    # The decision is recorded with its reason, not just its result (TZ 5.8/T8).
    assert await count(
        conn, "audit_log", "action = 'sweep.rate_lock_expired' AND target_id = :t",
        t=str(scenario.invoice_id),
    ) == 1
    assert await count(conn, "notifications", "kind = 'invoice_expired'") == 1


async def test_an_invoice_inside_its_rate_lock_is_left_alone(
    conn: AsyncConnection, world: World
) -> None:
    scenario = await world.scenario(amount_due_raw=10 * USDC, **FRESH)

    assert await expire_stale_invoices(conn) == ()
    assert await invoice_status(conn, scenario.invoice_id) == str(E.InvoiceStatus.AWAITING)


async def test_an_invoice_with_an_open_topup_window_survives_a_stale_quote(
    conn: AsyncConnection, world: World
) -> None:
    """The requirement in one test: money in, window open, quote stale -> untouched.

    This is the case where the two deadlines actively disagree, and TZ 5.5
    settles it in the buyer's favour — "окно доплаты живёт дольше самого
    инвойса, потому что человек, который уже отправил деньги, находится в другом
    положении, чем человек, который просто не заплатил". The quote is stale by
    fifteen minutes; the top-up window has twenty-four hours left; the invoice
    stays open at its snapshot rate so the buyer can top up to the amount they
    were originally quoted.
    """
    scenario = await world.scenario(
        amount_due_raw=10 * USDC, topup_window=dt.timedelta(hours=24), **STALE
    )
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=4 * USDC,
        block_number=90,
    )

    assert await expire_stale_invoices(conn) == ()
    assert await invoice_status(conn, scenario.invoice_id) == str(E.InvoiceStatus.AWAITING)
    assert await count(conn, "notifications", "kind = 'invoice_expired'") == 0


async def test_money_on_a_closed_window_goes_to_a_human_not_to_expired(
    conn: AsyncConnection, world: World
) -> None:
    """Both deadlines passed, and the money decides the destination.

    ``expire_stale_invoices`` must not claim this invoice even though its quote
    is long dead, because the answer for an invoice holding money is
    ``manual_review`` (TZ 5.5.3, "автоматически не зачитывается никогда"), and
    ``expired`` would be an automatic write-off by timer of money that actually
    arrived.
    """
    scenario = await world.scenario(
        amount_due_raw=10 * USDC, topup_window=dt.timedelta(0), **STALE
    )
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=4 * USDC,
        block_number=90,
    )

    assert await expire_stale_invoices(conn) == ()

    moved = await sweep_expired_invoices(conn)
    assert moved == {scenario.invoice_id: str(E.InvoiceStatus.MANUAL_REVIEW)}


async def test_an_empty_invoice_past_both_deadlines_is_expired_by_the_rate_pass(
    conn: AsyncConnection, world: World
) -> None:
    """No money anywhere: both passes agree, and the first one wins the CAS.

    Asserted because the two sweeps run back to back in
    :func:`settler.main.run_once` and overlap on exactly this shape of invoice.
    The point is not which one claims it — it is that the second finds nothing
    left to do rather than writing a second audit row about the same event.
    """
    scenario = await world.scenario(
        amount_due_raw=10 * USDC, topup_window=dt.timedelta(0), **STALE
    )

    assert await expire_stale_invoices(conn) == (scenario.invoice_id,)
    assert await sweep_expired_invoices(conn) == {}
    assert await invoice_status(conn, scenario.invoice_id) == str(E.InvoiceStatus.EXPIRED)
    assert await count(conn, "audit_log", "target_id = :t", t=str(scenario.invoice_id)) == 1


async def test_running_the_pass_twice_expires_once(
    conn: AsyncConnection, world: World
) -> None:
    """Idempotence, held by the CAS rather than by remembering what ran.

    The second pass does not even see the invoice — ``expired`` is not in the
    live set — but the assertion is on the side effects rather than on the return
    value, because a duplicate notification would be the visible symptom for a
    user and is what TZ 3.5 forbids ("ни одного дубликата при перезапуске любого
    компонента").
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC, **STALE)

    assert await expire_stale_invoices(conn) == (scenario.invoice_id,)
    assert await expire_stale_invoices(conn) == ()
    assert await count(conn, "notifications", "kind = 'invoice_expired'") == 1


async def test_a_late_payment_between_select_and_update_is_not_expired_over(
    conn: AsyncConnection, world: World
) -> None:
    """The ``NOT EXISTS`` in the UPDATE, not the one in the SELECT.

    Simulated by inserting the payment after the candidate list is read, which is
    exactly the window the watcher's own transaction occupies in production. If
    the emptiness test lived only in the SELECT this would expire an invoice that
    had just been paid — and the buyer would be told their invoice is dead while
    their money sits on our address.
    """
    from settler import repository as repo
    from settler.service import LIVE_INVOICE_STATUSES

    scenario = await world.scenario(amount_due_raw=10 * USDC, **STALE)

    candidates = await repo.invoices_past_rate_lock(conn, live_statuses=LIVE_INVOICE_STATUSES)
    assert [row["id"] for row in candidates] == [scenario.invoice_id]

    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    assert not await repo.expire_invoice_past_rate_lock(
        conn, scenario.invoice_id, expected=LIVE_INVOICE_STATUSES
    )
    assert await invoice_status(conn, scenario.invoice_id) == str(E.InvoiceStatus.AWAITING)


async def test_the_rate_lock_is_read_and_not_confused_with_the_expiry(
    conn: AsyncConnection, world: World
) -> None:
    """A quote that outlives the invoice is respected as written.

    ``rate_locked_until`` and ``expires_at`` are separate columns and this pass
    reads the first one. An invoice whose invoice-level expiry has passed but
    whose quote is still good must not be expired *by this pass* — that is the
    top-up sweep's decision to make on the top-up deadline, and a pass that
    silently keyed off the wrong column would look correct in every test where
    the two coincide, which is every other test in this file.
    """
    scenario = await world.scenario(
        amount_due_raw=10 * USDC,
        rate_lock=dt.timedelta(hours=2),
        **STALE,
    )

    row = (
        await conn.execute(
            sa.text("SELECT rate_locked_until > now() AS live FROM invoices WHERE id = :id"),
            {"id": scenario.invoice_id},
        )
    ).scalar_one()
    assert row is True

    assert await expire_stale_invoices(conn) == ()
    assert await invoice_status(conn, scenario.invoice_id) == str(E.InvoiceStatus.AWAITING)
