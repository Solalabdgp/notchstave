"""TZ 5.3 and 5.5 through the database — the policy table as it is actually applied.

``test_policy_table.py`` proves the decision is right. This file proves the
right decision is *carried out*: the invoice ends in the correct status, exactly
one entitlement exists, the outbox has a message in the same transaction, the
refund obligation is recorded, and the anomalous money is excluded from the
total rather than quietly folded into it.

Every test here runs against a real Postgres schema built by the real
migrations. The aggregate under test is a ``SUM`` executed by the database, so
testing it anywhere else would test a reimplementation of it.
"""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

from core.db import enums as E
from settler import metrics
from settler.errors import InvoiceNotFound
from settler.policy import Outcome
from settler.service import (
    review_anomalous_payments,
    settle_invoice,
    sweep_expired_invoices,
)
from settler.tests.conftest import (
    Scenario,
    World,
    count,
    invoice_status,
    payment_status,
    sample_value,
)

USDC = 1_000_000  # one whole token in base units, 6 decimals


# ---------------------------------------------------------------------------
# TZ 5.3 — the total is an aggregate over the ledger
# ---------------------------------------------------------------------------


async def test_two_transfers_to_one_address_sum_into_one_credit(
    conn: AsyncConnection, world: World
) -> None:
    """"Пользователь может отправить двумя переводами" (TZ 5.3).

    The invoice is settled by the sum of the transfers, not by any one of them
    reaching the price — which is also why neither transfer alone triggers
    anything.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=6 * USDC,
        block_number=90,
    )
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=4 * USDC,
        block_number=91,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.PAID
    assert result.granted
    assert result.decision is not None
    assert result.decision.total_raw == Decimal(10 * USDC)
    assert len(result.credited_payment_ids) == 2
    assert await invoice_status(conn, s.invoice_id) == "paid"
    assert await count(conn, "entitlements") == 1


async def test_running_the_settler_again_changes_nothing(
    conn: AsyncConnection, world: World
) -> None:
    """Idempotent by construction, because the total is recomputed not accumulated.

    This is the property that makes the whole design safe under redelivery: a
    settler that added to a counter would double the balance here.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    first = await settle_invoice(conn, s.invoice_id)
    assert first.outcome is Outcome.PAID

    for _ in range(5):
        again = await settle_invoice(conn, s.invoice_id)
        assert again.outcome is Outcome.ALREADY_SETTLED
        assert not again.granted

    assert await count(conn, "entitlements") == 1
    assert await count(conn, "notifications", "kind = 'invoice_settled'") == 1


async def test_a_payment_that_is_not_deep_enough_is_not_in_the_total(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 5.4: the confirmation gate lives inside the aggregate, not beside it."""
    s = await world.scenario(amount_due_raw=10 * USDC, head_block=100, min_confirmations=3)
    # head 100, 3 confirmations -> 98 is the deepest creditable height. 99 is not.
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=99,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.AWAITING_CONFIRMATIONS
    assert not result.granted
    assert await count(conn, "entitlements") == 0
    # And the invoice is untouched — "waiting" is not a state transition.
    assert await invoice_status(conn, s.invoice_id) == "awaiting"


# ---------------------------------------------------------------------------
# TZ 5.5 — underpayment, three outcomes
# ---------------------------------------------------------------------------


async def test_underpayment_inside_tolerance_settles(
    conn: AsyncConnection, world: World
) -> None:
    """5.5.1 — an exchange withdrawal fee. "Гонять человека из-за трёх центов" is not a plan."""
    s = await world.scenario(amount_due_raw=10 * USDC)
    # tolerance = min(0.5% of 10 USDC, 1 USD) = 50_000 base units
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC - 50_000,
        block_number=90,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.UNDERPAID_TOLERATED
    assert result.granted
    assert await invoice_status(conn, s.invoice_id) == "paid"
    assert await count(conn, "entitlements", "revoked_at IS NULL") == 1
    # Settled, so no case for a human.
    assert await count(conn, "manual_reviews") == 0


async def test_underpayment_outside_tolerance_with_the_window_open_is_partially_paid(
    conn: AsyncConnection, world: World
) -> None:
    """5.5.2 — the buyer is told the exact shortfall and given the same address.

    A new address here would be the one thing guaranteed to lose the money, so
    the test asserts on the address in the outbox payload, not just on the status.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=3 * USDC,
        block_number=90,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.PARTIALLY_PAID
    assert not result.granted
    assert result.decision is not None
    assert result.decision.shortfall_raw == Decimal(7 * USDC)
    assert await invoice_status(conn, s.invoice_id) == "partially_paid"
    assert await count(conn, "entitlements") == 0
    # Not a human's problem yet — the buyer can still fix it themselves.
    assert await count(conn, "manual_reviews") == 0

    row = (
        await conn.execute(
            sa.text(
                "SELECT payload_json FROM notifications WHERE kind = 'invoice_underpaid'"
            )
        )
    ).scalar_one()
    assert row["address"] == s.address
    assert row["missing_raw"] == str(7 * USDC)


async def test_a_second_transfer_completes_a_partially_paid_invoice(
    conn: AsyncConnection, world: World
) -> None:
    """5.5.2 — "Доплата приходит вторым переводом на тот же адрес и суммируется".

    The invoice is in ``partially_paid``, which is a live status, so the next
    settler pass picks it up and the TZ 5.3 aggregate does the rest. No new
    invoice, no new address, no special "top-up" code path.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=3 * USDC,
        block_number=90,
    )
    assert (await settle_invoice(conn, s.invoice_id)).outcome is Outcome.PARTIALLY_PAID

    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=7 * USDC,
        block_number=92,
    )
    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.PAID
    assert result.granted
    assert await invoice_status(conn, s.invoice_id) == "paid"
    assert await count(conn, "entitlements") == 1
    assert await count(conn, "payments", "status = 'credited'") == 2


async def test_underpayment_after_the_window_closes_goes_to_a_human(
    conn: AsyncConnection, world: World
) -> None:
    """5.5.3 — "Автоматически не зачитывается никогда."

    The money stays where it is, the invoice leaves the live set, and a case is
    opened for `/resolve`. Nothing here has a threshold at which it becomes
    automatic, and nothing writes off the money on a timer.
    """
    s = await world.scenario(
        amount_due_raw=10 * USDC,
        age=dt.timedelta(hours=30),
        expires_in=dt.timedelta(minutes=15),
        topup_window=dt.timedelta(hours=24),
    )
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=3 * USDC,
        block_number=90,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.UNDERPAID_MANUAL_REVIEW
    assert not result.granted
    assert await invoice_status(conn, s.invoice_id) == "manual_review"
    assert await count(conn, "entitlements") == 0
    assert await count(conn, "manual_reviews", "kind = 'underpaid' AND resolved_at IS NULL") == 1
    # Re-running must not stack up a second identical case for the owner.
    await settle_invoice(conn, s.invoice_id)
    assert await count(conn, "manual_reviews", "kind = 'underpaid'") == 1


# ---------------------------------------------------------------------------
# TZ 5.5 — overpayment, two outcomes
# ---------------------------------------------------------------------------


async def test_overpayment_inside_tolerance_settles_and_says_so(
    conn: AsyncConnection, world: World
) -> None:
    """"Тихо оставлять себе чужие деньги нельзя." (TZ 5.5)

    The excess is credited and the buyer is told, in a message of its own so it
    cannot be lost inside the delivery message.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    # tolerance = max(5% of 10 USDC, 5 USD) = 5 USDC; 2 USDC over is inside it.
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=12 * USDC,
        block_number=90,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.OVERPAID_CREDITED
    assert result.granted
    assert result.decision is not None
    assert result.decision.excess_raw == Decimal(2 * USDC)
    assert await invoice_status(conn, s.invoice_id) == "overpaid"
    assert await count(conn, "entitlements") == 1
    assert await count(conn, "notifications", "kind = 'overpaid_credited'") == 1
    # No refund case: this is below the threshold at which a human gets involved.
    assert await count(conn, "refunds") == 0


async def test_overpayment_above_threshold_delivers_and_opens_a_refund(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 5.5 — "товар выдаётся ... а излишек порождает запись в refunds".

    Both halves matter. The buyer paid for the product and gets it; the excess
    becomes an obligation with a human attached. And ``to_address`` stays NULL:
    "адрес отправителя — не надёжный адрес для возврата".
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=16 * USDC,
        block_number=90,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.OVERPAID_REFUND_PENDING
    assert result.granted, "the product is owed regardless of the refund"
    assert result.refund_id is not None
    assert await invoice_status(conn, s.invoice_id) == "overpaid"
    assert await count(conn, "entitlements") == 1

    refund = (
        await conn.execute(
            sa.text(
                "SELECT amount_raw, status::text AS status, to_address FROM refunds"
            )
        )
    ).mappings().one()
    assert refund["amount_raw"] == Decimal(6 * USDC)
    assert refund["status"] == "pending"
    assert refund["to_address"] is None, "the sender address is never a refund destination"
    assert await count(conn, "manual_reviews", "kind = 'overpaid'") == 1


async def test_reprocessing_an_overpayment_does_not_stack_refund_requests(
    conn: AsyncConnection, world: World
) -> None:
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=16 * USDC,
        block_number=90,
    )

    await settle_invoice(conn, s.invoice_id)
    for _ in range(3):
        await settle_invoice(conn, s.invoice_id)

    assert await count(conn, "refunds") == 1
    assert await count(conn, "entitlements") == 1


# ---------------------------------------------------------------------------
# TZ 5.5 — the anomaly table
# ---------------------------------------------------------------------------


async def test_the_wrong_token_is_not_summed_and_reaches_a_human(
    conn: AsyncConnection, world: World
) -> None:
    """"Прислали не тот токен (USDT вместо USDC)" — `wrong_asset` -> `manual_review`.

    The asset predicate lives in the aggregate itself, so this is not a matter
    of the service remembering to filter: a USDT transfer is not in the SUM at
    the SQL level.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    usdt = await world.asset(s.chain_id, symbol="USDT", decimals=6)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=usdt,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
        anomaly=E.PaymentAnomaly.WRONG_ASSET,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.NO_FUNDS
    assert await count(conn, "entitlements") == 0
    assert await count(conn, "manual_reviews", "kind = 'wrong_asset'") == 1
    assert await invoice_status(conn, s.invoice_id) == "awaiting"


async def test_the_right_token_on_the_wrong_chain_is_not_summed(
    conn: AsyncConnection, world: World
) -> None:
    """"Прислали в другой EVM-сети на тот же адрес" (TZ 5.5).

    The same key derives the same address on every EVM network, so this money
    is physically on one of our addresses — and still belongs to no invoice on
    this chain. The chain predicate in the aggregate is what keeps it out, which
    is why the payment below is deliberately bound to the invoice: even a
    mis-bound row cannot be summed across chains.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    other_chain = await world.chain(chain_id=1, last_indexed_block=100)
    other_asset = await world.asset(other_chain, symbol="USDC", decimals=6)
    await world.payment(
        chain_id=other_chain,
        asset_id=other_asset,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
        anomaly=E.PaymentAnomaly.WRONG_CHAIN,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.NO_FUNDS
    assert await count(conn, "entitlements") == 0
    assert await count(conn, "manual_reviews", "kind = 'wrong_chain'") == 1


async def test_a_previous_tenants_payment_never_credits_the_new_invoice(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 5.8/T3.3 — the one genuine replay vector in the design.

    An address returns to the pool and is handed to somebody else. The previous
    buyer pays late, and the money lands on an address that now belongs to a
    stranger's invoice. Crediting it would be giving away a product for someone
    else's money.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    await conn.execute(
        sa.text(
            "UPDATE receive_addresses SET reserved_from_block = 50 WHERE id = :id"
        ),
        {"id": s.address_id},
    )
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=40,  # below reserved_from_block
        anomaly=E.PaymentAnomaly.ORPHAN_PAYMENT,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.NO_FUNDS
    assert await count(conn, "entitlements") == 0
    assert await count(conn, "manual_reviews", "kind = 'orphan_payment'") == 1


async def test_money_on_an_address_with_no_invoice_still_reaches_a_human(
    conn: AsyncConnection, world: World
) -> None:
    """"Платёж пришёл на адрес, у которого нет активного инвойса" (TZ 5.5).

    This anomaly has no invoice, so no amount of settling invoices will ever
    surface it — it needs its own sweep, or the money sits on a real address
    with nobody looking at it.
    """
    chain_id = await world.chain()
    asset_id = await world.asset(chain_id)
    hd = await world.hd_account()
    address_id, _ = await world.address(hd, index=7)
    await world.payment(
        chain_id=chain_id,
        asset_id=asset_id,
        address_id=address_id,
        invoice_id=None,
        amount_raw=10 * USDC,
        block_number=90,
        anomaly=E.PaymentAnomaly.UNASSIGNED_PAYMENT,
    )

    opened = await review_anomalous_payments(conn)

    assert len(opened) == 1
    assert await count(conn, "manual_reviews", "kind = 'unassigned_payment'") == 1
    # Idempotent: the sweep runs every pass and must not spam `/pending`.
    assert await review_anomalous_payments(conn) == ()
    assert await count(conn, "manual_reviews") == 1


async def test_dust_is_ignored_without_bothering_anyone(
    conn: AsyncConnection, world: World
) -> None:
    """"Ниже dust_threshold игнорируется ... в /pending не попадает" (TZ 5.5).

    Dust is the one anomaly that is deliberately not escalated: a dust-attack
    that generates a support case per transfer is a denial of service against
    the owner's attention.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=1,
        block_number=90,
        status=E.PaymentStatus.IGNORED_DUST,
        anomaly=E.PaymentAnomaly.DUST,
    )
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.PAID
    assert result.decision is not None
    assert result.decision.total_raw == Decimal(10 * USDC), "dust must not move the total"
    assert await count(conn, "manual_reviews") == 0


async def test_an_anomalous_transfer_does_not_block_a_correct_one(
    conn: AsyncConnection, world: World
) -> None:
    """A stray USDT transfer is a payment-level problem, not an invoice-level one.

    The correct USDC payment settles the invoice; the USDT gets its own case.
    Blocking the sale because a second token arrived would punish the buyer for
    something they may not even have done.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    usdt = await world.asset(s.chain_id, symbol="USDT", decimals=6)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=usdt,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=99 * USDC,
        block_number=90,
        anomaly=E.PaymentAnomaly.WRONG_ASSET,
    )
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.PAID
    assert result.decision is not None
    assert result.decision.total_raw == Decimal(10 * USDC)
    assert await count(conn, "entitlements") == 1
    assert await count(conn, "manual_reviews", "kind = 'wrong_asset'") == 1


# ---------------------------------------------------------------------------
# TZ 5.4 — a large payment waits for finality
# ---------------------------------------------------------------------------


async def test_a_large_payment_is_not_credited_on_confirmation_count_alone(
    conn: AsyncConnection, world: World
) -> None:
    """"Выше — только по финализированному блоку." (TZ 5.4)

    Block 96 is five confirmations deep at head 100, which clears the chain's
    ``min_confirmations`` of 3 — and is still not credited, because 200 USD is
    above ``credit_threshold_usd`` and 96 is above the finalized head.
    """
    s = await world.scenario(
        amount_due_raw=200 * USDC,
        amount_due_usd="200",
        head_block=100,
        finalized_block=95,
        min_confirmations=3,
    )
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=200 * USDC,
        block_number=96,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.AWAITING_CONFIRMATIONS
    assert result.confirmation_rule is not None
    assert result.confirmation_rule.needs_finality
    assert result.confirmation_rule.label == "finalized"
    assert await count(conn, "entitlements") == 0

    # The same amount one block lower — inside the finalized range — settles.
    await world.finalize(s.chain_id, 96)
    after = await settle_invoice(conn, s.invoice_id)
    assert after.outcome is Outcome.PAID
    assert await count(conn, "entitlements") == 1


async def test_a_small_payment_at_the_same_depth_settles_immediately(
    conn: AsyncConnection, world: World
) -> None:
    """The control for the test above: same block, same chain, smaller amount.

    Without this pair, "the large payment waited" could just as well mean the
    confirmation gate is broken for everything.
    """
    s = await world.scenario(
        amount_due_raw=10 * USDC, head_block=100, finalized_block=95, min_confirmations=3
    )
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=96,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.PAID
    assert result.confirmation_rule is not None
    assert not result.confirmation_rule.needs_finality


async def test_a_large_payment_waits_forever_on_a_chain_that_finalizes_nothing(
    conn: AsyncConnection, world: World
) -> None:
    """Fail closed. A missing finality signal must not read as "go ahead"."""
    s = await world.scenario(
        amount_due_raw=200 * USDC,
        amount_due_usd="200",
        head_block=100,
        finalized_block=None,
        min_confirmations=3,
    )
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=200 * USDC,
        block_number=10,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.AWAITING_CONFIRMATIONS
    assert await count(conn, "entitlements") == 0


# ---------------------------------------------------------------------------
# Outbox and audit
# ---------------------------------------------------------------------------


async def test_the_grant_and_its_message_are_written_together(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 5.8/T2.5 — transactional outbox.

    There is no window in which access exists without a queued notification,
    because there is no second transaction in which one of them could fail. The
    notifier drains ``notifications``; the settler never sends anything itself.
    """
    s = await world.scenario(amount_due_raw=10 * USDC, subscription_days=30)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.granted
    assert len(result.notification_ids) == 1
    row = (
        await conn.execute(
            sa.text(
                """
                SELECT n.status::text AS status, n.payload_json, n.dedup_key,
                       e.expires_at IS NOT NULL AS subscription_expires
                  FROM notifications n
                  JOIN entitlements e ON e.id = :entitlement_id
                 WHERE n.kind = 'invoice_settled'
                """
            ),
            {"entitlement_id": result.entitlement_id},
        )
    ).mappings().one()
    assert row["status"] == "queued"
    assert row["dedup_key"] == str(result.entitlement_id)
    assert row["payload_json"]["entitlement_id"] == result.entitlement_id
    assert row["subscription_expires"], "a subscription product must expire (TZ 3.3)"


async def test_payment_credit_seconds_is_observed_on_grant(
    conn: AsyncConnection, world: World
) -> None:
    """TZ section 7 — ``notchstave_payment_credit_seconds``: "от первого
    обнаружения до выдачи доступа".

    The collector existed in ``settler/metrics.py`` before this test but was
    never ``.observe()``-d anywhere (grep the codebase pre-fix: zero hits
    outside the declaration and ``__all__``). Backdating ``payments.created_at``
    by a known amount and asserting the histogram's sum moved by roughly that
    amount is what tells the two apart — asserting only that the metric object
    exists would still pass against the dead collector.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    payment_id = await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )
    await conn.execute(
        sa.text(
            "UPDATE payments SET created_at = now() - interval '90 seconds' WHERE id = :id"
        ),
        {"id": payment_id},
    )

    before_count = sample_value(metrics.PAYMENT_CREDIT_SECONDS, "_count")
    before_sum = sample_value(metrics.PAYMENT_CREDIT_SECONDS, "_sum")

    result = await settle_invoice(conn, s.invoice_id)

    assert result.granted
    after_count = sample_value(metrics.PAYMENT_CREDIT_SECONDS, "_count")
    after_sum = sample_value(metrics.PAYMENT_CREDIT_SECONDS, "_sum")
    assert after_count == before_count + 1
    # ~90s backdate plus whatever the test itself took to reach this line.
    assert 85 <= (after_sum - before_sum) <= 150


async def test_payment_credit_seconds_uses_the_credited_payment_not_an_anomaly(
    conn: AsyncConnection, world: World
) -> None:
    """The histogram must read detection time off the payment that actually
    paid the bill, not off an older anomalous payment sitting on the same
    invoice (TZ 5.5 lets an anomaly and a good payment coexist on one invoice —
    see ``test_an_anomalous_transfer_does_not_block_a_correct_one`` above).
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    old_anomalous = await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=5 * USDC,
        block_number=80,
        status=E.PaymentStatus.IGNORED_DUST,
        anomaly=E.PaymentAnomaly.DUST,
    )
    await conn.execute(
        sa.text(
            "UPDATE payments SET created_at = now() - interval '1 hour' WHERE id = :id"
        ),
        {"id": old_anomalous},
    )
    good_payment = await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )
    await conn.execute(
        sa.text(
            "UPDATE payments SET created_at = now() - interval '20 seconds' WHERE id = :id"
        ),
        {"id": good_payment},
    )

    before_sum = sample_value(metrics.PAYMENT_CREDIT_SECONDS, "_sum")
    result = await settle_invoice(conn, s.invoice_id)
    assert result.granted
    observed = sample_value(metrics.PAYMENT_CREDIT_SECONDS, "_sum") - before_sum

    # Would be ~3600s if the hour-old dust payment leaked into the calculation.
    assert 15 <= observed <= 60


async def test_every_money_decision_records_the_policy_that_made_it(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 5.5 — "все решения логируются с указанием применённой политики".

    Re-deriving the reasoning later from thresholds that have since changed is
    not the same thing as having recorded it, so the numbers go in the row.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC - 50_000,
        block_number=90,
    )

    await settle_invoice(conn, s.invoice_id)

    row = (
        await conn.execute(
            sa.text(
                """
                SELECT actor_kind::text AS actor_kind, actor_id, action,
                       args_json, policy_version, before_state, after_state
                  FROM audit_log
                 WHERE target_id = :invoice_id
                """
            ),
            {"invoice_id": str(s.invoice_id)},
        )
    ).mappings().one()
    assert row["actor_kind"] == "system"
    assert row["actor_id"] == "settler"
    assert row["action"] == "settle.underpaid_tolerated"
    assert row["policy_version"]
    assert row["args_json"]["tolerance_raw"] == "50000"
    assert row["args_json"]["total_raw"] == str(10 * USDC - 50_000)
    assert row["before_state"]["status"] == "awaiting"
    assert row["after_state"]["status"] == "paid"


# ---------------------------------------------------------------------------
# Sweeps
# ---------------------------------------------------------------------------


async def test_an_unpaid_invoice_expires_but_one_holding_money_does_not(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 5.5 — money is never written off by a timer.

    Two invoices past their top-up window: the one nobody paid simply expires,
    the one holding a partial payment goes to a human. Collapsing these into one
    UPDATE is how money quietly disappears.
    """
    # Created 30 hours ago, expired 15 minutes later, top-up window 24 hours:
    # both are well past the point where anything can still arrive.
    async def past_its_window() -> Scenario:
        return await world.scenario(
            amount_due_raw=10 * USDC,
            age=dt.timedelta(hours=30),
            expires_in=dt.timedelta(minutes=15),
            topup_window=dt.timedelta(hours=24),
        )

    empty = await past_its_window()
    funded = await past_its_window()
    await world.payment(
        chain_id=funded.chain_id,
        asset_id=funded.asset_id,
        address_id=funded.address_id,
        invoice_id=funded.invoice_id,
        amount_raw=3 * USDC,
        block_number=90,
    )

    moved = await sweep_expired_invoices(conn)

    assert moved[empty.invoice_id] == "expired"
    assert moved[funded.invoice_id] == "manual_review"
    assert await invoice_status(conn, empty.invoice_id) == "expired"
    assert await invoice_status(conn, funded.invoice_id) == "manual_review"
    assert await count(conn, "manual_reviews", "invoice_id = :id", id=funded.invoice_id) == 1
    assert await count(conn, "manual_reviews", "invoice_id = :id", id=empty.invoice_id) == 0


async def test_a_live_invoice_inside_its_window_is_not_swept(
    conn: AsyncConnection, world: World
) -> None:
    s = await world.scenario(amount_due_raw=10 * USDC)
    assert await sweep_expired_invoices(conn) == {}
    assert await invoice_status(conn, s.invoice_id) == "awaiting"


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


async def test_settling_an_invoice_that_does_not_exist_is_an_error(
    conn: AsyncConnection, world: World
) -> None:
    """Not "nothing to do": the caller is working from a stale or forged id."""
    with pytest.raises(InvoiceNotFound):
        await settle_invoice(conn, uuid.uuid4())


async def test_a_cancelled_invoice_takes_no_money_decision(
    conn: AsyncConnection, world: World
) -> None:
    s = await world.scenario(amount_due_raw=10 * USDC)
    await conn.execute(
        sa.text(
            "UPDATE invoices SET status = 'cancelled' WHERE id = :id"
        ),
        {"id": s.invoice_id},
    )
    payment_id = await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.NOT_LIVE
    assert await count(conn, "entitlements") == 0
    assert await payment_status(conn, payment_id) == "seen"
