"""The settler proper: match, confirm, decide, grant, revoke.

This module owns every money decision in Notchstave (TZ section 4) and it makes
them from one input only — what the watcher has already written to PostgreSQL.
There is no RPC client here, no HTTP client, and no import that could add one.

----

**The four things this file is really about.**

1. **The settled total is a SUM, never a counter** (TZ 5.3). Nothing anywhere
   adds to a running "amount paid" field, because a re-delivered event would
   add twice. :func:`settle_invoice` recomputes from the ledger every time,
   which makes the whole function naturally idempotent: running it a hundred
   times on the same invoice produces the same single grant.

2. **Every state transition is compare-and-set** (TZ 5.8/T2.2). Read-check-write
   does not appear in this file. The expected state is in the WHERE clause, and
   a zero rowcount means another worker already handled it, so this one exits
   without side effects.

3. **Correctness lives in the schema, not here.** ``FOR UPDATE`` on the invoice
   row serialises workers; ``entitlements_active_uniq`` refuses a second grant
   even if the serialisation were broken; ``UNIQUE (chain_id, tx_hash,
   log_index)`` makes a replayed log a no-op before the settler ever sees it.
   The Redis lock in :mod:`settler.locks` adds none of this and is optional.

4. **A revoked grant is revoked, not deleted** (TZ 5.4). A reorg sets
   ``revoked_at``. The row stays, because "why did this user have access last
   Tuesday" must remain answerable.

----

**Where the claims above are checked.** ``settler/tests/`` runs against a real
Postgres built by the real migrations — ``docker compose -f
docker-compose.test.yml run --rm tests``. In particular ``test_concurrency.py``
puts twenty workers on one invoice under four lock configurations including a
Redis that is down and a lock that lies, and ``test_reorg.py`` is the "реорг
после выдачи доступа" test TZ 5.4 calls the most valuable one in the project.

----

**TODO / known gaps, deliberately visible rather than buried.**

* ``TODO(week3, schema)``: ``payments`` has ``block_number`` but no
  ``block_hash`` (TZ 6). Reorg rollback therefore reverts by height and cannot
  tell whether a transaction was re-included in the replacement block. A
  surviving payment is reverted and needs `/reconcile` plus a manual review to
  come back. The fix is a column, i.e. a migration on a table this package does
  not own — see :data:`settler.repository.SQL_REVERT_PAYMENTS_IN_ORPHANED_BLOCKS`.
* ``RESOLVED(week3, grants)``: the Week 2 note here said a tolerated
  overpayment was never actually credited to ``users.internal_balance_usd``,
  because migration 0002 gave the settler only SELECT on ``users``. Migration
  0003 closes it with a **column-level** ``GRANT UPDATE (internal_balance_usd)``
  — the privilege is exactly one column wide, PostgreSQL enforces it, and
  ``settler/tests/test_grants.py`` asserts that every other column of ``users``
  is still refused to this role. See the head of 0003 for why a table-level
  grant and a ``SECURITY DEFINER`` function were both rejected.
* ``TODO(week3, watcher contract)``: "finalized" is read as
  ``blocks.status = 'confirmed'`` — see :mod:`settler.confirmations` for the
  full reasoning and the cleaner alternative.
* ``TODO(bot)``: TZ 5.8/T2.6 (dedup of ``callback_query.id`` so a double tap on
  "I paid" does not start two settlements) belongs to the aiogram handler in
  ``bot/``. It is not implemented here because it cannot be: the settler never
  sees a callback query. It is also not *needed* for correctness — a second
  settlement attempt is a no-op by point 1 above — it only saves work, exactly
  like the Redis lock.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from decimal import ROUND_FLOOR, Decimal
from typing import Any

from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from core.db import enums as E
from settler import metrics
from settler import repository as repo
from settler.amounts import raw_to_usd, sum_raw
from settler.confirmations import ConfirmationRule, creditable_cutoff_height, required_rule
from settler.errors import InconsistentInvoice, InvoiceNotFound
from settler.locks import InvoiceLock, NullLock
from settler.policy import (
    DEFAULT_POLICY,
    GRANTING_OUTCOMES,
    AmountDecision,
    MoneyPolicy,
    Outcome,
    classify,
)

__all__ = [
    "SettlementResult",
    "ReorgResult",
    "Settler",
    "settle_invoice",
    "handle_reorg",
    "sweep_expired_invoices",
    "expire_stale_invoices",
    "review_anomalous_payments",
    "LIVE_INVOICE_STATUSES",
    "SETTLED_INVOICE_STATUSES",
    "CREDITABLE_PAYMENT_STATUSES",
    "BLOCKING_ANOMALIES",
    "CREDITABLE_ANOMALIES",
]

#: Statuses in which an invoice can still receive a money decision. Mirrors the
#: predicate of ``uq_invoices_active_address`` — the schema and this tuple are
#: two halves of one rule and must be changed together.
LIVE_INVOICE_STATUSES: tuple[str, ...] = tuple(str(s) for s in E.LIVE_INVOICE_STATUSES)

#: Terminal "the buyer paid" states.
SETTLED_INVOICE_STATUSES: tuple[str, ...] = (
    str(E.InvoiceStatus.PAID),
    str(E.InvoiceStatus.OVERPAID),
)

#: TZ 5.3 — the settled total sums payments in exactly these statuses.
CREDITABLE_PAYMENT_STATUSES: tuple[str, ...] = tuple(E.CREDITABLE_PAYMENT_STATUSES)

#: Statuses a reorg can pull the rug from under.
REVERTIBLE_PAYMENT_STATUSES: tuple[str, ...] = (
    str(E.PaymentStatus.SEEN),
    str(E.PaymentStatus.CONFIRMED),
    str(E.PaymentStatus.CREDITED),
)

#: An anomaly that still counts towards the bill. Only one: a payment that
#: arrived after the invoice expired is creditable while the top-up window is
#: open (TZ 5.5, "Платёж пришёл после истечения инвойса").
CREDITABLE_ANOMALIES: tuple[str, ...] = (str(E.PaymentAnomaly.LATE),)

#: Anomalies that never count towards a bill and always end up in front of a
#: human (TZ 5.5, anomaly table). Each is excluded from the SUM by the
#: predicates in :data:`settler.repository.SQL_SETTLED_TOTAL`.
BLOCKING_ANOMALIES: tuple[str, ...] = (
    str(E.PaymentAnomaly.WRONG_ASSET),
    str(E.PaymentAnomaly.WRONG_CHAIN),
    str(E.PaymentAnomaly.ORPHAN_PAYMENT),
    str(E.PaymentAnomaly.UNASSIGNED_PAYMENT),
)

#: Which manual-review kind a payment anomaly opens.
_ANOMALY_REVIEW_KIND: dict[str, str] = {
    str(E.PaymentAnomaly.WRONG_ASSET): str(E.ManualReviewKind.WRONG_ASSET),
    str(E.PaymentAnomaly.WRONG_CHAIN): str(E.ManualReviewKind.WRONG_CHAIN),
    str(E.PaymentAnomaly.ORPHAN_PAYMENT): str(E.ManualReviewKind.ORPHAN_PAYMENT),
    str(E.PaymentAnomaly.UNASSIGNED_PAYMENT): str(E.ManualReviewKind.UNASSIGNED_PAYMENT),
    str(E.PaymentAnomaly.LATE): str(E.ManualReviewKind.LATE_PAYMENT),
}

_ACTOR_ID = "settler"

#: Scale of ``users.internal_balance_usd`` — ``NUMERIC(18, 6)`` from migration
#: 0001. Named here because the rounding direction below is a money decision, not
#: a formatting detail.
_USD_QUANTUM = Decimal("0.000001")


def _creditable_usd(raw: Decimal, decimals: int, rate: Decimal) -> Decimal:
    """Excess in base units -> the USD figure actually written to a balance.

    Rounded **down** to the scale of the column. Two reasons, and the second is
    the one that matters:

    * rounding up would credit a buyer a fraction of a cent nobody sent, which
      makes ``/reconcile`` — the check that the ledger matches the chain —
      report a drift that is really an artefact of our own arithmetic;
    * the column is ``NUMERIC(18, 6)``, so PostgreSQL rounds *half-up* on insert
      if the application does not round first. Leaving it to the database means
      the credited figure and the figure in the notification and the audit row
      can differ in the last digit, and "the message said one thing and the
      ledger says another" is the single worst sentence in a payment system.

    A one-wei excess on an expensive token can round to zero here. That is the
    correct answer — there is no representable amount to credit — and the caller
    records the raw excess in the audit trail either way, so nothing is lost.
    """
    return raw_to_usd(raw, decimals, rate).quantize(_USD_QUANTUM, rounding=ROUND_FLOOR)


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SettlementResult:
    """Everything one settlement attempt did, and why.

    Returned rather than logged-and-forgotten because the caller (worker loop,
    admin command, test) needs to distinguish "granted", "granted by somebody
    else", and "deliberately did nothing" — three situations that look
    identical from the outside if the function returns ``None``.
    """

    invoice_id: uuid.UUID
    outcome: Outcome
    decision: AmountDecision | None = None
    entitlement_id: int | None = None
    notification_ids: tuple[int, ...] = ()
    manual_review_ids: tuple[int, ...] = ()
    refund_id: int | None = None
    credited_payment_ids: tuple[int, ...] = ()
    confirmation_rule: ConfirmationRule | None = None
    pending_reason: str | None = None
    #: True when the partial unique index stopped a second grant (TZ 5.8/T2.1).
    lost_grant_race: bool = False

    @property
    def granted(self) -> bool:
        return self.entitlement_id is not None


@dataclass(frozen=True, slots=True)
class ReorgResult:
    """Outcome of rolling back one chain's orphaned blocks (TZ 5.4)."""

    chain_id: int
    reverted_payment_ids: tuple[int, ...] = ()
    revoked_entitlement_ids: tuple[int, ...] = ()
    unsettled_invoices: dict[uuid.UUID, str] = field(default_factory=dict)
    notification_ids: tuple[int, ...] = ()


# ---------------------------------------------------------------------------
# Settlement
# ---------------------------------------------------------------------------


async def settle_invoice(
    conn: AsyncConnection,
    invoice_id: uuid.UUID,
    *,
    policy: MoneyPolicy = DEFAULT_POLICY,
    actor_id: str = _ACTOR_ID,
) -> SettlementResult:
    """Decide and apply the state of one invoice. Idempotent by construction.

    Runs inside the caller's transaction and never commits — the caller owns the
    boundary, which is what lets the entitlement, the outbox row and the audit
    entry be one atomic act (TZ 5.8/T2.5).

    The sequence, and why it is in this order:

    1. ``SELECT ... FOR UPDATE`` the invoice. Everything after this point is
       serialised per invoice (T2.3). The row also carries the chain's
       confirmation policy and the asset's decimals, read in the same snapshot.
    2. Open a manual review for every anomalous payment on the invoice. These
       are *payment-level* problems: a stray USDT transfer does not stop a
       correct USDC payment from settling, it just needs its own human. The
       anomalous amounts are not in the SUM either way.
    3. Work out the confirmation regime from the money at stake (TZ 5.4) and
       turn it into a single creditable height.
    4. Recompute the settled total as a ``SUM`` (TZ 5.3) and classify it against
       the TZ 5.5 table.
    5. Apply — with CAS, and with the grant guarded by the partial unique index.
    """
    ctx = await repo.lock_invoice(conn, invoice_id)
    if ctx is None:
        raise InvoiceNotFound(str(invoice_id))
    if ctx.asset_chain_id != ctx.chain_id:
        raise InconsistentInvoice(
            f"invoice {invoice_id}: asset {ctx.asset_id} belongs to chain "
            f"{ctx.asset_chain_id}, invoice claims {ctx.chain_id}"
        )

    if ctx.status in SETTLED_INVOICE_STATUSES:
        # Already settled — by an earlier run or by a worker that won the race a
        # microsecond ago. Both mean the same thing: nothing to do, no message.
        return SettlementResult(invoice_id, Outcome.ALREADY_SETTLED)
    if ctx.status not in LIVE_INVOICE_STATUSES:
        return SettlementResult(invoice_id, Outcome.NOT_LIVE)

    payments = await repo.invoice_payments(conn, invoice_id)

    review_ids = await _open_reviews_for_anomalies(
        conn, ctx.invoice_id, payments, policy_version=policy.version
    )

    candidates = [
        p
        for p in payments
        if p.status in (str(E.PaymentStatus.SEEN), *CREDITABLE_PAYMENT_STATUSES)
        and p.asset_id == ctx.asset_id
        and p.chain_id == ctx.chain_id
        and (p.anomaly is None or p.anomaly in CREDITABLE_ANOMALIES)
    ]
    candidate_total = sum_raw(p.amount_raw for p in candidates)

    if candidate_total <= 0:
        return SettlementResult(
            invoice_id,
            Outcome.NO_FUNDS,
            manual_review_ids=review_ids,
            pending_reason="no creditable payment on this invoice",
        )

    # --- confirmation regime (TZ 5.4) -------------------------------------
    #
    # The regime is chosen from the *total at stake*, not from the size of an
    # individual transfer. Choosing per transfer would let anyone split a
    # $300 payment into twenty $15 ones and be credited on the fast path,
    # which defeats the economic argument the threshold is built on.
    rule = required_rule(
        amount_raw=candidate_total,
        decimals=ctx.asset_decimals,
        rate=ctx.rate_snapshot,
        min_confirmations=ctx.min_confirmations,
        credit_threshold_usd=ctx.credit_threshold_usd,
    )
    finalized = await repo.finalized_head(conn, ctx.chain_id) if rule.needs_finality else None
    cutoff = creditable_cutoff_height(
        head_block=ctx.last_indexed_block, rule=rule, finalized_head=finalized
    )

    # Promote everything that now qualifies. `seen -> confirmed` is itself a
    # CAS, so a concurrent promotion is harmless.
    for payment in candidates:
        if payment.status == str(E.PaymentStatus.SEEN) and payment.block_number <= cutoff:
            await repo.promote_payment_to_confirmed(conn, payment.id)

    total_raw = await repo.settled_total_raw(
        conn,
        invoice_id,
        asset_id=ctx.asset_id,
        chain_id=ctx.chain_id,
        statuses=CREDITABLE_PAYMENT_STATUSES,
        creditable_anomalies=CREDITABLE_ANOMALIES,
        max_creditable_block=cutoff,
    )

    decision = classify(
        due_raw=ctx.amount_due_raw,
        total_raw=total_raw,
        decimals=ctx.asset_decimals,
        rate=ctx.rate_snapshot,
        now=ctx.db_now,
        topup_window_until=ctx.topup_window_until,
        policy=policy,
    )

    # Do not nag a buyer whose money is on-chain but not yet deep enough. If
    # the pending amount would settle the bill, the honest state is "waiting",
    # not "you underpaid".
    if decision.outcome not in GRANTING_OUTCOMES and candidate_total > total_raw:
        potential = classify(
            due_raw=ctx.amount_due_raw,
            total_raw=candidate_total,
            decimals=ctx.asset_decimals,
            rate=ctx.rate_snapshot,
            now=ctx.db_now,
            topup_window_until=ctx.topup_window_until,
            policy=policy,
        )
        if potential.outcome in GRANTING_OUTCOMES:
            gated = [p for p in candidates if p.block_number > cutoff]
            reason = (
                f"{len(gated)} payment(s) below the {rule.label} threshold "
                f"(creditable up to block {cutoff}, head {ctx.last_indexed_block})"
            )
            return SettlementResult(
                invoice_id,
                Outcome.AWAITING_CONFIRMATIONS,
                decision=decision,
                manual_review_ids=review_ids,
                confirmation_rule=rule,
                pending_reason=reason,
            )

    if decision.outcome in GRANTING_OUTCOMES:
        return await _apply_settlement(
            conn,
            ctx=ctx,
            decision=decision,
            rule=rule,
            candidates=candidates,
            cutoff=cutoff,
            review_ids=review_ids,
            policy=policy,
            actor_id=actor_id,
        )

    if decision.outcome is Outcome.PARTIALLY_PAID:
        return await _apply_partially_paid(
            conn, ctx=ctx, decision=decision, review_ids=review_ids,
            policy=policy, actor_id=actor_id,
        )

    if decision.outcome is Outcome.UNDERPAID_MANUAL_REVIEW:
        return await _apply_underpaid_manual_review(
            conn, ctx=ctx, decision=decision, review_ids=review_ids,
            policy=policy, actor_id=actor_id,
        )

    return SettlementResult(
        invoice_id,
        decision.outcome,
        decision=decision,
        manual_review_ids=review_ids,
        confirmation_rule=rule,
    )


async def _open_reviews_for_anomalies(
    conn: AsyncConnection,
    invoice_id: uuid.UUID,
    payments: Sequence[repo.PaymentRow],
    *,
    policy_version: str,
) -> tuple[int, ...]:
    """One human case per anomalous payment, opened at most once.

    The anomalies handled here are the rows of the TZ 5.5 table that arrive
    attached to an invoice: ``wrong_asset``, ``wrong_chain``, ``orphan_payment``,
    ``unassigned_payment``. None of them are credited — they are excluded from
    the SUM by the predicates in the aggregate — and none of them are ever
    auto-resolved.
    """
    opened: list[int] = []
    for payment in payments:
        if payment.anomaly is None or payment.anomaly not in BLOCKING_ANOMALIES:
            continue
        kind = _ANOMALY_REVIEW_KIND[payment.anomaly]
        review_id = await repo.open_manual_review(
            conn,
            kind=kind,
            invoice_id=invoice_id,
            payment_id=payment.id,
            note=(
                f"payment {payment.tx_hash}:{payment.log_index} on chain "
                f"{payment.chain_id} flagged {payment.anomaly}; amount_raw="
                f"{payment.amount_raw}; not credited"
            ),
            policy_version=policy_version,
        )
        if review_id is not None:
            opened.append(review_id)
            if payment.anomaly == str(E.PaymentAnomaly.ORPHAN_PAYMENT):
                metrics.ORPHAN_PAYMENTS.labels(chain=str(payment.chain_id)).inc()
            elif payment.anomaly == str(E.PaymentAnomaly.UNASSIGNED_PAYMENT):
                metrics.UNASSIGNED_PAYMENTS.labels(chain=str(payment.chain_id)).inc()
    return tuple(opened)


async def _apply_settlement(
    conn: AsyncConnection,
    *,
    ctx: repo.InvoiceContext,
    decision: AmountDecision,
    rule: ConfirmationRule,
    candidates: Sequence[repo.PaymentRow],
    cutoff: int,
    review_ids: tuple[int, ...],
    policy: MoneyPolicy,
    actor_id: str,
) -> SettlementResult:
    """Close the invoice, credit the payments, grant access, queue the message.

    Order matters and is not arbitrary:

    * the CAS on ``invoices.status`` comes **first**, so that a worker that
      loses it stops before writing anything at all (T2.2);
    * the entitlement INSERT comes before the notification, so the message can
      carry the grant id — and so a lost grant race skips the message too;
    * everything is one transaction, so there is no window in which access
      exists without a queued notification or the other way round (T2.5).
    """
    new_status = (
        str(E.InvoiceStatus.OVERPAID)
        if decision.outcome
        in (Outcome.OVERPAID_CREDITED, Outcome.OVERPAID_REFUND_PENDING)
        else str(E.InvoiceStatus.PAID)
    )

    won = await repo.cas_invoice_status(
        conn,
        ctx.invoice_id,
        new_status=new_status,
        expected=LIVE_INVOICE_STATUSES,
        mark_settled=True,
    )
    if not won:
        # Zero affected rows. TZ 5.8/T2.2: "обработчик обязан выйти".
        return SettlementResult(
            ctx.invoice_id, Outcome.ALREADY_SETTLED, decision=decision, confirmation_rule=rule
        )

    credited: list[int] = []
    for payment in candidates:
        if payment.block_number > cutoff:
            continue
        confirmations = max(0, ctx.last_indexed_block - payment.block_number + 1)
        if await repo.credit_payment(conn, payment.id, confirmations):
            credited.append(payment.id)

    entitlement_id = await repo.insert_entitlement(
        conn,
        user_id=ctx.user_id,
        product_id=ctx.product_id,
        invoice_id=ctx.invoice_id,
        subscription_days=ctx.subscription_days,
    )

    notifications: list[int] = []
    refund_id: int | None = None
    reviews = list(review_ids)

    if entitlement_id is None:
        # The index of T2.1 spoke. Not an error: an active grant for this
        # invoice already exists, so the buyer already has what they paid for.
        metrics.DOUBLE_GRANT_BLOCKED.inc()
        await repo.write_audit(
            conn,
            actor_id=actor_id,
            action="settle.grant_blocked",
            target_kind="invoice",
            target_id=str(ctx.invoice_id),
            before_state={"status": ctx.status},
            after_state={"status": new_status},
            args=_audit_args(decision, rule, credited),
            policy_version=policy.version,
        )
        return SettlementResult(
            ctx.invoice_id,
            Outcome.ALREADY_SETTLED,
            decision=decision,
            credited_payment_ids=tuple(credited),
            manual_review_ids=tuple(reviews),
            confirmation_rule=rule,
            lost_grant_race=True,
        )

    payload: dict[str, Any] = {
        "invoice_id": str(ctx.invoice_id),
        "outcome": str(decision.outcome),
        "asset": ctx.asset_symbol,
        "decimals": ctx.asset_decimals,
        "amount_due_raw": str(decision.due_raw),
        "amount_paid_raw": str(decision.total_raw),
        "delta_raw": str(decision.delta_raw),
        "entitlement_id": entitlement_id,
        "policy_version": policy.version,
    }

    notification_id = await repo.enqueue_notification(
        conn,
        user_id=ctx.user_id,
        kind="invoice_settled",
        ref_id=str(ctx.invoice_id),
        # The grant id, so a re-grant after a reorg produces a new message
        # instead of being swallowed by the dedup index.
        dedup_key=str(entitlement_id),
        payload=payload,
    )
    if notification_id is not None:
        notifications.append(notification_id)

    if decision.outcome is Outcome.OVERPAID_CREDITED:
        # TZ 5.5: the excess goes to the user's internal balance and the user is
        # told in plain words. "Тихо оставлять себе чужие деньги нельзя."
        #
        # The outbox insert is deliberately *first* and is the idempotency gate
        # for the credit that follows. A balance is the one figure in this
        # package that cannot be recomputed from the ledger — there is no ledger
        # of balances to re-sum — so the increment has to be protected by
        # something, and ``UNIQUE (kind, ref_id, dedup_key)`` on ``notifications``
        # is a guarantee that already exists and is already tested. A `None` here
        # means this exact (invoice, grant) pair was credited before, and the
        # balance is left alone.
        #
        # Both statements are in the settler's transaction, so a rollback takes
        # the outbox row and the balance together: there is no window in which
        # the guard exists without the credit it guards.
        excess_usd = _creditable_usd(decision.excess_raw, ctx.asset_decimals, ctx.rate_snapshot)
        extra = await repo.enqueue_notification(
            conn,
            user_id=ctx.user_id,
            kind="overpaid_credited",
            ref_id=str(ctx.invoice_id),
            dedup_key=str(entitlement_id),
            payload={
                **payload,
                "credited_excess_raw": str(decision.excess_raw),
                "credited_excess_usd": str(excess_usd),
            },
        )
        if extra is not None:
            notifications.append(extra)
            new_balance = (
                await repo.credit_internal_balance(
                    conn, user_id=ctx.user_id, delta_usd=excess_usd
                )
                if excess_usd > 0
                else None
            )
            await repo.write_audit(
                conn,
                actor_id=actor_id,
                action="settle.internal_balance_credited",
                target_kind="user",
                target_id=str(ctx.user_id),
                before_state={"invoice_id": str(ctx.invoice_id)},
                after_state={"internal_balance_usd": str(new_balance)},
                args={
                    "excess_raw": str(decision.excess_raw),
                    "excess_usd": str(excess_usd),
                    "rate_snapshot": str(ctx.rate_snapshot),
                    "notification_id": extra,
                },
                policy_version=policy.version,
            )

    if decision.outcome is Outcome.OVERPAID_REFUND_PENDING:
        sender = next((p.sender for p in candidates if p.sender), None)
        refund_id = await repo.create_refund_request(
            conn,
            invoice_id=ctx.invoice_id,
            amount_raw=decision.excess_raw,
            asset_id=ctx.asset_id,
            note=(
                "overpayment above tolerance; destination must be asked from the user "
                f"(TZ 5.5). First sender seen, reference only, NOT a refund address: {sender}"
            ),
        )
        review_id = await repo.open_manual_review(
            conn,
            kind=str(E.ManualReviewKind.OVERPAID),
            invoice_id=ctx.invoice_id,
            payment_id=None,
            note=f"refund obligation {refund_id}: excess_raw={decision.excess_raw}",
            policy_version=policy.version,
        )
        if review_id is not None:
            reviews.append(review_id)
        extra = await repo.enqueue_notification(
            conn,
            user_id=ctx.user_id,
            kind="refund_pending",
            ref_id=str(ctx.invoice_id),
            dedup_key=str(entitlement_id),
            payload={**payload, "refund_id": refund_id, "excess_raw": str(decision.excess_raw)},
        )
        if extra is not None:
            notifications.append(extra)

    await repo.write_audit(
        conn,
        actor_id=actor_id,
        action=f"settle.{decision.outcome}",
        target_kind="invoice",
        target_id=str(ctx.invoice_id),
        before_state={"status": ctx.status},
        after_state={"status": new_status, "entitlement_id": entitlement_id},
        args=_audit_args(decision, rule, credited),
        policy_version=policy.version,
    )

    metrics.INVOICES_SETTLED.labels(outcome=str(decision.outcome)).inc()

    return SettlementResult(
        ctx.invoice_id,
        decision.outcome,
        decision=decision,
        entitlement_id=entitlement_id,
        notification_ids=tuple(notifications),
        manual_review_ids=tuple(reviews),
        refund_id=refund_id,
        credited_payment_ids=tuple(credited),
        confirmation_rule=rule,
    )


async def _apply_partially_paid(
    conn: AsyncConnection,
    *,
    ctx: repo.InvoiceContext,
    decision: AmountDecision,
    review_ids: tuple[int, ...],
    policy: MoneyPolicy,
    actor_id: str,
) -> SettlementResult:
    """TZ 5.5.2 — short by more than tolerance, window still open.

    The message carries the exact shortfall **and the same address**: the buyer
    tops up with a second transfer to the address they already have, and TZ 5.3
    sums the two. No new invoice, no new address — a new address here would be
    the one thing guaranteed to lose the money.
    """
    won = await repo.cas_invoice_status(
        conn,
        ctx.invoice_id,
        new_status=str(E.InvoiceStatus.PARTIALLY_PAID),
        expected=LIVE_INVOICE_STATUSES,
    )
    if not won:
        return SettlementResult(ctx.invoice_id, Outcome.ALREADY_SETTLED, decision=decision)

    notification_id = await repo.enqueue_notification(
        conn,
        user_id=ctx.user_id,
        kind="invoice_underpaid",
        ref_id=str(ctx.invoice_id),
        # Keyed on the amount received so far: every further partial transfer
        # produces exactly one new message, and re-running the settler produces
        # none.
        dedup_key=str(decision.total_raw),
        payload={
            "invoice_id": str(ctx.invoice_id),
            "outcome": str(decision.outcome),
            "address": ctx.address,
            "asset": ctx.asset_symbol,
            "decimals": ctx.asset_decimals,
            "amount_due_raw": str(decision.due_raw),
            "amount_paid_raw": str(decision.total_raw),
            "missing_raw": str(decision.shortfall_raw),
            "topup_window_until": ctx.topup_window_until,
            "policy_version": policy.version,
        },
    )

    await repo.write_audit(
        conn,
        actor_id=actor_id,
        action=f"settle.{decision.outcome}",
        target_kind="invoice",
        target_id=str(ctx.invoice_id),
        before_state={"status": ctx.status},
        after_state={"status": str(E.InvoiceStatus.PARTIALLY_PAID)},
        args=_audit_args(decision, None, []),
        policy_version=policy.version,
    )

    return SettlementResult(
        ctx.invoice_id,
        decision.outcome,
        decision=decision,
        notification_ids=() if notification_id is None else (notification_id,),
        manual_review_ids=review_ids,
    )


async def _apply_underpaid_manual_review(
    conn: AsyncConnection,
    *,
    ctx: repo.InvoiceContext,
    decision: AmountDecision,
    review_ids: tuple[int, ...],
    policy: MoneyPolicy,
    actor_id: str,
) -> SettlementResult:
    """TZ 5.5.3 — short, and the top-up window has closed.

    "Автоматически не зачитывается никогда." The invoice stops being live, a
    case is opened, and the owner decides with `/resolve`. There is deliberately
    no threshold at which this becomes automatic.
    """
    won = await repo.cas_invoice_status(
        conn,
        ctx.invoice_id,
        new_status=str(E.InvoiceStatus.MANUAL_REVIEW),
        expected=LIVE_INVOICE_STATUSES,
    )
    if not won:
        return SettlementResult(ctx.invoice_id, Outcome.ALREADY_SETTLED, decision=decision)

    reviews = list(review_ids)
    review_id = await repo.open_manual_review(
        conn,
        kind=str(E.ManualReviewKind.UNDERPAID),
        invoice_id=ctx.invoice_id,
        payment_id=None,
        note=(
            f"underpaid by {decision.shortfall_raw} raw after the top-up window closed "
            f"({ctx.topup_window_until.isoformat()}); tolerance was {decision.tolerance_raw} raw"
        ),
        policy_version=policy.version,
    )
    if review_id is not None:
        reviews.append(review_id)

    notification_id = await repo.enqueue_notification(
        conn,
        user_id=ctx.user_id,
        kind="invoice_manual_review",
        ref_id=str(ctx.invoice_id),
        dedup_key=str(decision.total_raw),
        payload={
            "invoice_id": str(ctx.invoice_id),
            "outcome": str(decision.outcome),
            "amount_due_raw": str(decision.due_raw),
            "amount_paid_raw": str(decision.total_raw),
            "missing_raw": str(decision.shortfall_raw),
            "policy_version": policy.version,
        },
    )

    await repo.write_audit(
        conn,
        actor_id=actor_id,
        action=f"settle.{decision.outcome}",
        target_kind="invoice",
        target_id=str(ctx.invoice_id),
        before_state={"status": ctx.status},
        after_state={"status": str(E.InvoiceStatus.MANUAL_REVIEW)},
        args=_audit_args(decision, None, []),
        policy_version=policy.version,
    )

    metrics.INVOICES_SETTLED.labels(outcome=str(decision.outcome)).inc()

    return SettlementResult(
        ctx.invoice_id,
        decision.outcome,
        decision=decision,
        notification_ids=() if notification_id is None else (notification_id,),
        manual_review_ids=tuple(reviews),
    )


def _audit_args(
    decision: AmountDecision, rule: ConfirmationRule | None, credited: Sequence[int]
) -> dict[str, Any]:
    """The numbers that made the decision, frozen into the audit row.

    TZ 5.5: "все решения логируются с указанием применённой политики, ни одно
    состояние не остаётся немым". Re-deriving the reasoning later from
    thresholds that have since changed is not the same thing as recording it.
    """
    args: dict[str, Any] = {
        "due_raw": str(decision.due_raw),
        "total_raw": str(decision.total_raw),
        "delta_raw": str(decision.delta_raw),
        "tolerance_raw": str(decision.tolerance_raw),
        "credited_payment_ids": list(credited),
    }
    if rule is not None:
        args["confirmation_rule"] = rule.label
        args["amount_usd"] = str(rule.amount_usd)
        args["credit_threshold_usd"] = str(rule.credit_threshold_usd)
    return args


# ---------------------------------------------------------------------------
# Reorg (TZ 5.4)
# ---------------------------------------------------------------------------


async def handle_reorg(
    conn: AsyncConnection,
    chain_id: int,
    *,
    policy: MoneyPolicy = DEFAULT_POLICY,
    actor_id: str = _ACTOR_ID,
) -> ReorgResult:
    """Roll back payments whose block was orphaned, and take back what they bought.

    The watcher detects the reorg and marks blocks ``orphaned``; this function
    is the money half. TZ 5.4: "если по откаченному платежу доступ уже выдан —
    доступ отзывается, инвойс возвращается в состояние ожидания, пользователю
    уходит сообщение-поправка".

    ``revoked_at`` is set. Nothing is deleted — see point 4 of the module
    docstring. The partial unique index only constrains rows with
    ``revoked_at IS NULL``, so revoking is also what makes a later re-grant of
    the same invoice possible if the payment comes back on the new chain.

    This is the test TZ 5.4 calls "самый ценный тест в проекте".
    """
    reverted = await repo.revert_payments_in_orphaned_blocks(
        conn, chain_id, live_statuses=REVERTIBLE_PAYMENT_STATUSES
    )
    if not reverted:
        return ReorgResult(chain_id=chain_id)

    payment_ids = tuple(int(r["id"]) for r in reverted)
    invoice_ids = list({r["invoice_id"] for r in reverted if r["invoice_id"] is not None})

    revoked = await repo.revoke_entitlements_for_invoices(
        conn, invoice_ids, reason=f"reorg on chain {chain_id}: paying block orphaned"
    )
    unsettled = await repo.unsettle_invoices(
        conn, invoice_ids, expected=SETTLED_INVOICE_STATUSES
    )

    notifications: list[int] = []
    for row in revoked:
        notification_id = await repo.enqueue_notification(
            conn,
            user_id=int(row["user_id"]),
            kind="entitlement_revoked",
            ref_id=str(row["invoice_id"]),
            dedup_key=str(row["id"]),
            payload={
                "invoice_id": str(row["invoice_id"]),
                "entitlement_id": int(row["id"]),
                "reason": "chain_reorg",
                "chain_id": chain_id,
                "new_invoice_status": unsettled.get(row["invoice_id"]),
                "policy_version": policy.version,
            },
        )
        if notification_id is not None:
            notifications.append(notification_id)

    for invoice_id in invoice_ids:
        await repo.write_audit(
            conn,
            actor_id=actor_id,
            action="reorg.revoke",
            target_kind="invoice",
            target_id=str(invoice_id),
            before_state={"status": "settled"},
            after_state={"status": unsettled.get(invoice_id)},
            args={
                "chain_id": chain_id,
                "reverted_payment_ids": [
                    int(r["id"]) for r in reverted if r["invoice_id"] == invoice_id
                ],
            },
            policy_version=policy.version,
        )

    if revoked:
        # Normal value zero; any increase is an incident (TZ section 7).
        metrics.REVERTED_CREDITS.inc(len(revoked))

    return ReorgResult(
        chain_id=chain_id,
        reverted_payment_ids=payment_ids,
        revoked_entitlement_ids=tuple(int(r["id"]) for r in revoked),
        unsettled_invoices=unsettled,
        notification_ids=tuple(notifications),
    )


# ---------------------------------------------------------------------------
# Sweeps
# ---------------------------------------------------------------------------


async def sweep_expired_invoices(
    conn: AsyncConnection,
    *,
    policy: MoneyPolicy = DEFAULT_POLICY,
    actor_id: str = _ACTOR_ID,
    limit: int = 500,
) -> dict[uuid.UUID, str]:
    """Close invoices whose top-up window has passed (TZ 5.5).

    Two destinations, and the difference is the whole reason this is not one
    UPDATE: an invoice that never received a coin simply expires, while one
    holding money that never reached the price goes to ``manual_review``. Money
    is never quietly written off by a timer.
    """
    rows = await repo.invoices_past_topup_window(
        conn,
        live_statuses=LIVE_INVOICE_STATUSES,
        money_statuses=(
            str(E.PaymentStatus.SEEN),
            *CREDITABLE_PAYMENT_STATUSES,
        ),
        limit=limit,
    )

    moved: dict[uuid.UUID, str] = {}
    for row in rows:
        invoice_id = row["id"]
        target = (
            str(E.InvoiceStatus.MANUAL_REVIEW) if row["has_money"] else str(E.InvoiceStatus.EXPIRED)
        )
        if not await repo.expire_invoice(
            conn, invoice_id, new_status=target, expected=LIVE_INVOICE_STATUSES
        ):
            continue
        moved[invoice_id] = target

        if row["has_money"]:
            await repo.open_manual_review(
                conn,
                kind=str(E.ManualReviewKind.UNDERPAID),
                invoice_id=invoice_id,
                payment_id=None,
                note="top-up window closed with money on the invoice; /resolve decides",
                policy_version=policy.version,
            )
        await repo.write_audit(
            conn,
            actor_id=actor_id,
            action=f"sweep.{target}",
            target_kind="invoice",
            target_id=str(invoice_id),
            before_state={"status": row["status"]},
            after_state={"status": target},
            args={"has_money": bool(row["has_money"])},
            policy_version=policy.version,
        )
        metrics.INVOICES_SETTLED.labels(outcome=target).inc()

    return moved


async def expire_stale_invoices(
    conn: AsyncConnection,
    *,
    policy: MoneyPolicy = DEFAULT_POLICY,
    actor_id: str = _ACTOR_ID,
    limit: int = 500,
) -> tuple[uuid.UUID, ...]:
    """Expire invoices whose quoted rate has gone stale (TZ 5.5, rate table).

    "Курс фиксируется в момент создания инвойса (``rate_snapshot``) и действует
    ``rate_locked_until`` (по умолчанию 15 минут). После — инвойс истекает. Для
    USDC вопрос вырожденный, для ETH — основной."

    That last sentence is why this exists as its own pass rather than as a line
    in :func:`sweep_expired_invoices`. The two deadlines are different
    quantities protecting different parties:

    * ``rate_locked_until`` (minutes) protects **us**. Its job is to stop
      somebody quoting an ETH price, waiting for the market to move, and paying
      the stale number. Without this pass a live invoice would keep its quote
      indefinitely, because ``sweep_expired_invoices`` only looks at
      ``topup_window_until`` — a deadline a full day later.
    * ``topup_window_until`` (a day past expiry) protects **the buyer** who has
      already sent money and is mid-payment.

    So this function deliberately touches **only invoices with no payment rows at
    all**. An invoice holding money keeps its quote until the top-up window
    closes, and is then routed by :func:`sweep_expired_invoices` to
    ``manual_review`` rather than to ``expired``, because money is never written
    off by a timer. The emptiness test is re-checked inside the UPDATE — see
    :data:`settler.repository.SQL_EXPIRE_INVOICE_PAST_RATE_LOCK` for why the gap
    between the SELECT and the UPDATE is long enough to matter.

    Scheduling: this is the same shape as the other sweeps — a pass over
    database state, driven by :func:`settler.main.run_once` on the settler's own
    poll loop. Not Celery beat, and that is the project's existing decision
    rather than a new one: ``settler/main.py`` runs a poll loop precisely
    because every settler action is a function of database state, so a missed
    tick costs latency and nothing else. A beat scheduler would add a broker, a
    second deployment unit and a lost-schedule failure mode to a job whose worst
    case is "an unpaid invoice expires thirty seconds late".
    """
    rows = await repo.invoices_past_rate_lock(
        conn, live_statuses=LIVE_INVOICE_STATUSES, limit=limit
    )

    expired: list[uuid.UUID] = []
    for row in rows:
        invoice_id = row["id"]
        if not await repo.expire_invoice_past_rate_lock(
            conn, invoice_id, expected=LIVE_INVOICE_STATUSES
        ):
            # Lost the CAS, or money landed between the two statements. Either
            # way this invoice is somebody else's problem now.
            continue
        expired.append(invoice_id)

        await repo.enqueue_notification(
            conn,
            user_id=int(row["user_id"]),
            kind="invoice_expired",
            ref_id=str(invoice_id),
            # Keyed on the reason: a later expiry of the same invoice is
            # impossible (``expired`` is terminal), so one message per invoice is
            # the whole requirement.
            dedup_key="rate_lock",
            payload={
                "invoice_id": str(invoice_id),
                "reason": "rate_lock_expired",
                "rate_locked_until": row["rate_locked_until"],
                "policy_version": policy.version,
            },
        )
        await repo.write_audit(
            conn,
            actor_id=actor_id,
            action="sweep.rate_lock_expired",
            target_kind="invoice",
            target_id=str(invoice_id),
            before_state={"status": row["status"]},
            after_state={"status": str(E.InvoiceStatus.EXPIRED)},
            args={
                "rate_locked_until": str(row["rate_locked_until"]),
                "topup_window_until": str(row["topup_window_until"]),
                "had_payments": False,
            },
            policy_version=policy.version,
        )
        metrics.INVOICES_SETTLED.labels(outcome=str(E.InvoiceStatus.EXPIRED)).inc()

    return tuple(expired)


async def review_anomalous_payments(
    conn: AsyncConnection,
    *,
    policy: MoneyPolicy = DEFAULT_POLICY,
    limit: int = 500,
) -> tuple[int, ...]:
    """Put every unreviewed anomalous payment in front of a human (TZ 5.5).

    Covers the anomalies that arrive without an invoice attached —
    ``unassigned_payment`` above all, which by definition has no invoice for
    :func:`settle_invoice` to be called with, and would otherwise sit in the
    database unnoticed while the money sits on a real address.
    """
    rows = await repo.unreviewed_anomalous_payments(conn, anomalies=BLOCKING_ANOMALIES, limit=limit)
    opened: list[int] = []
    for row in rows:
        kind = _ANOMALY_REVIEW_KIND[row["anomaly"]]
        review_id = await repo.open_manual_review(
            conn,
            kind=kind,
            invoice_id=row["invoice_id"],
            payment_id=int(row["id"]),
            note=(
                f"anomaly={row['anomaly']} chain={row['chain_id']} "
                f"block={row['block_number']} amount_raw={row['amount_raw']} "
                f"sender={row['sender']}"
            ),
            policy_version=policy.version,
        )
        if review_id is not None:
            opened.append(review_id)
            chain = str(row["chain_id"])
            if row["anomaly"] == str(E.PaymentAnomaly.ORPHAN_PAYMENT):
                metrics.ORPHAN_PAYMENTS.labels(chain=chain).inc()
            elif row["anomaly"] == str(E.PaymentAnomaly.UNASSIGNED_PAYMENT):
                metrics.UNASSIGNED_PAYMENTS.labels(chain=chain).inc()
    return tuple(opened)


# ---------------------------------------------------------------------------
# Worker-facing facade
# ---------------------------------------------------------------------------


class Settler:
    """Transaction and lock management around the functions above.

    The split is deliberate: :func:`settle_invoice` takes a connection and does
    the money work, this class decides where transactions begin and end. Tests
    drive the function directly with their own connection, production drives the
    class — and neither can accidentally change the other's transaction shape.
    """

    def __init__(
        self,
        engine: AsyncEngine,
        *,
        policy: MoneyPolicy = DEFAULT_POLICY,
        lock: InvoiceLock | None = None,
        actor_id: str = _ACTOR_ID,
    ) -> None:
        self._engine = engine
        self._policy = policy
        #: Default is no lock at all. Redis is an optimisation and the system
        #: must be correct without it (TZ 5.8/T2.4).
        self._lock: InvoiceLock = lock or NullLock()
        self._actor_id = actor_id

    @property
    def policy(self) -> MoneyPolicy:
        return self._policy

    async def settle(self, invoice_id: uuid.UUID) -> SettlementResult:
        async with self._lock.acquire(invoice_id) as acquired:
            if not acquired:
                # Someone else is on it. Nothing is known about the invoice, and
                # nothing is assumed: the next scan will look again.
                return SettlementResult(invoice_id, Outcome.SKIPPED_BUSY)
            async with self._engine.begin() as conn:
                return await settle_invoice(
                    conn, invoice_id, policy=self._policy, actor_id=self._actor_id
                )

    async def handle_reorg(self, chain_id: int) -> ReorgResult:
        async with self._engine.begin() as conn:
            return await handle_reorg(
                conn, chain_id, policy=self._policy, actor_id=self._actor_id
            )

    async def sweep_expired(self) -> dict[uuid.UUID, str]:
        async with self._engine.begin() as conn:
            return await sweep_expired_invoices(
                conn, policy=self._policy, actor_id=self._actor_id
            )

    async def expire_stale(self) -> tuple[uuid.UUID, ...]:
        async with self._engine.begin() as conn:
            return await expire_stale_invoices(
                conn, policy=self._policy, actor_id=self._actor_id
            )

    async def review_anomalies(self) -> tuple[int, ...]:
        async with self._engine.begin() as conn:
            return await review_anomalous_payments(conn, policy=self._policy)
