"""The tolerated overpayment actually reaches the user's balance (TZ 5.5).

> "В пределах ``overpay_tolerance`` ... инвойс закрывается, излишек фиксируется
> как ``overpaid_credited`` и уходит на внутренний баланс пользователя в счёт
> следующих покупок. Пользователю сообщается прямым текстом, сколько именно и
> куда зачтено. **Тихо оставлять себе чужие деньги нельзя.**"

Week 2 implemented every part of that sentence except the last clause of the
first half: the outcome was classified, the message was queued, and the balance
column was never written, because migration 0002 gave the settler only SELECT on
``users``. Migration 0003 closes it with a column-level grant; this file is what
says the money now arrives.

The interesting test here is not the happy path. It is
:func:`test_re_running_the_settler_credits_the_balance_once`: a balance is the
one figure in this package that cannot be recomputed from the ledger, so it is
the one place TZ 5.3's "SUM, never a counter" rule cannot be applied, and the
protection has to come from somewhere else.
"""

from __future__ import annotations

from decimal import Decimal

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

from settler.policy import Outcome
from settler.service import settle_invoice
from settler.tests.conftest import World, count

USDC = 1_000_000


async def _balance(conn: AsyncConnection, user_id: int) -> Decimal:
    value = (
        await conn.execute(
            sa.text("SELECT internal_balance_usd FROM users WHERE id = :id"), {"id": user_id}
        )
    ).scalar_one()
    return Decimal(value)


async def test_a_tolerated_overpayment_lands_on_the_internal_balance(
    conn: AsyncConnection, world: World
) -> None:
    """Ten dollars billed, thirteen paid: three go to the balance.

    Inside ``overpay_tolerance``, which TZ 5.5 sets at the *larger* of 5% and 5
    USD — the asymmetry with the underpayment tolerance being deliberate, so
    that dust does not open a refund case.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=13 * USDC,
        block_number=90,
    )

    result = await settle_invoice(conn, scenario.invoice_id)

    assert result.outcome is Outcome.OVERPAID_CREDITED
    assert result.granted, "TZ 5.5 — the product is still delivered"
    assert await _balance(conn, scenario.user_id) == Decimal("3.000000")
    # And the user is told in plain words, with the figure in the payload.
    assert await count(conn, "notifications", "kind = 'overpaid_credited'") == 1
    row = (
        await conn.execute(
            sa.text(
                "SELECT payload_json FROM notifications WHERE kind = 'overpaid_credited'"
            )
        )
    ).scalar_one()
    assert row["credited_excess_usd"] == "3.000000"


async def test_the_credit_is_on_the_record_with_its_policy(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 5.8/T8 — a money movement nobody can explain later is not acceptable."""
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=12 * USDC,
        block_number=90,
    )

    await settle_invoice(conn, scenario.invoice_id)

    row = (
        await conn.execute(
            sa.text(
                """
                SELECT target_kind, target_id, after_state, args_json, policy_version
                  FROM audit_log
                 WHERE action = 'settle.internal_balance_credited'
                """
            )
        )
    ).mappings().one()
    assert row["target_kind"] == "user"
    assert row["target_id"] == str(scenario.user_id)
    assert row["after_state"]["internal_balance_usd"] == "2.000000"
    assert row["args_json"]["excess_raw"] == str(2 * USDC)
    assert row["policy_version"]


async def test_re_running_the_settler_credits_the_balance_once(
    conn: AsyncConnection, world: World
) -> None:
    """The one increment in the package, and what stops it running twice.

    TZ 5.3 forbids a running counter for the settled total precisely because a
    redelivered event would add twice; a balance has no ledger to re-sum, so the
    increment is unavoidable and the guard moves up a level. The
    ``overpaid_credited`` outbox row is inserted first, and ``UNIQUE (kind,
    ref_id, dedup_key)`` makes that insert happen exactly once per grant — so the
    second settlement attempt finds the row already there and does not credit.

    Two settlement passes are run here rather than one, because a settler that
    crashes and restarts is the ordinary case, not the exotic one.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=13 * USDC,
        block_number=90,
    )

    first = await settle_invoice(conn, scenario.invoice_id)
    second = await settle_invoice(conn, scenario.invoice_id)

    assert first.outcome is Outcome.OVERPAID_CREDITED
    assert second.outcome is Outcome.ALREADY_SETTLED
    assert await _balance(conn, scenario.user_id) == Decimal("3.000000")
    assert await count(conn, "notifications", "kind = 'overpaid_credited'") == 1
    assert await count(conn, "audit_log", "action = 'settle.internal_balance_credited'") == 1


async def test_an_overpayment_above_tolerance_opens_a_refund_and_credits_nothing(
    conn: AsyncConnection, world: World
) -> None:
    """The other branch of TZ 5.5: beyond tolerance the excess is *owed*, not kept.

    Crediting it to an internal balance would be the system deciding, on the
    buyer's behalf, that they would rather have store credit than their money
    back. The obligation goes to ``refunds`` and a human executes it offline.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=40 * USDC,
        block_number=90,
    )

    result = await settle_invoice(conn, scenario.invoice_id)

    assert result.outcome is Outcome.OVERPAID_REFUND_PENDING
    assert result.refund_id is not None
    assert await _balance(conn, scenario.user_id) == Decimal(0)


async def test_an_exact_payment_moves_no_balance(
    conn: AsyncConnection, world: World
) -> None:
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    assert (await settle_invoice(conn, scenario.invoice_id)).outcome is Outcome.PAID
    assert await _balance(conn, scenario.user_id) == Decimal(0)
    assert await count(conn, "audit_log", "action = 'settle.internal_balance_credited'") == 0


async def test_an_excess_too_small_to_represent_credits_nothing_and_says_so(
    conn: AsyncConnection, world: World
) -> None:
    """A few wei of an expensive token round below ``NUMERIC(18, 6)``.

    Rounding *down* is the deliberate direction: rounding up would credit a
    fraction of a cent nobody sent, and `/reconcile` would then report a drift
    that is really an artefact of our own arithmetic. The raw excess is still in
    the audit trail, so nothing is lost — only unrepresentable.
    """
    scenario = await world.scenario(
        amount_due_raw=10**18,
        amount_due_usd="3000",
        rate_snapshot="3000",
        decimals=18,
        credit_threshold_usd=100_000,
    )
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10**18 + 100,
        block_number=90,
    )

    result = await settle_invoice(conn, scenario.invoice_id)

    assert result.outcome is Outcome.OVERPAID_CREDITED
    assert await _balance(conn, scenario.user_id) == Decimal(0)
    row = (
        await conn.execute(
            sa.text(
                "SELECT args_json FROM audit_log "
                " WHERE action = 'settle.internal_balance_credited'"
            )
        )
    ).scalar_one()
    assert row["excess_raw"] == "100"
    assert row["excess_usd"] == "0.000000"
