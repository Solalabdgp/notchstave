"""`/pending` and `/resolve` — the human end of the TZ 5.5 table.

TZ 5.5 leaves three doors open that no automatic rule may ever walk through:
an underpayment past the top-up window, an overpayment above tolerance, and
every anomaly in the table at the bottom of the section. All of them park in
``manual_reviews`` and wait. This module is what happens when the owner
finally looks.

    /pending
    /resolve <invoice_id> <credit|refund|reject> [комментарий]

**Three resolutions, and what each one actually does.**

``credit`` — hand over the product despite the anomaly. "Щедрость", in the TZ's
word. Grants the entitlement through the same
:func:`settler.repository.insert_entitlement` the automatic path uses, so the
partial unique index of TZ 5.8/T2.1 guards a manual credit exactly as it guards
an automatic one. Above ``manual_credit_limit_usd`` it needs the two-step
confirmation of TZ 5.8/T7 before it will do anything at all.

``refund`` — record an obligation to give the money back. Writes a ``refunds``
row with status ``pending`` and ``to_address`` left NULL, and **sends nothing**.
TZ 12 and TZ 5.5 both spell out why: "автоматический возврат означает, что на
сервере есть ключ, которым можно отправлять деньги. Как только он там
появляется, всё остальное ТЗ теряет смысл." The destination is deliberately
absent because the sender address is not a refund address — money arriving from
an exchange hot wallet returns to nobody — so the owner asks the buyer for one.

``reject`` — close the case with nothing handed over and nothing owed.

**Every one of them writes ``audit_log``** with the actor, the state before, the
state after and the arguments (TZ 5.8/T7), and stamps the admin policy version
in force at the moment of the decision (T8). A resolution that leaves no trace
of who made it and under which thresholds is, for a system about money, the same
as no resolution at all.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import Any

from sqlalchemy.ext.asyncio import AsyncConnection

from core.db import enums as E
from settler import metrics
from settler import repository as repo
from settler.admin import repository as admin_repo
from settler.admin.errors import (
    ResolutionNotApplicable,
    ReviewAlreadyResolved,
    ReviewNotFound,
)
from settler.admin.policy import DEFAULT_ADMIN_POLICY, AdminPolicy
from settler.admin.twostep import ConfirmationKey, issue_code, verify_code
from settler.service import (
    CREDITABLE_ANOMALIES,
    CREDITABLE_PAYMENT_STATUSES,
    LIVE_INVOICE_STATUSES,
)

__all__ = [
    "PendingCase",
    "ResolutionOutcome",
    "ResolutionResult",
    "list_pending",
    "resolve_manual_review",
    "ADMIN_ACTOR_KIND",
    "RESOLVABLE_INVOICE_STATUSES",
]

#: TZ 3.4 restricts these commands to the owner by a fixed ``tg_id``; the schema
#: enum from migration 0001 calls that principal ``owner``. See the note in
#: :func:`settler.repository.write_audit` on the ``admin``/``owner`` synonymy.
ADMIN_ACTOR_KIND = str(E.ActorKind.OWNER)

#: Invoice statuses a resolution may move. ``manual_review`` plus the live set —
#: an anomaly can open a case without ever moving the invoice out of
#: ``awaiting``, and that invoice still has to be closable by hand.
#:
#: Terminal money states (``paid`` / ``overpaid`` / ``expired`` / ``cancelled`` /
#: ``reverted``) are **not** here, and their absence is a feature rather than an
#: omission: resolving the ``overpaid`` case that the settler opened alongside a
#: refund obligation must not reopen or cancel an invoice whose product was
#: already delivered. The status CAS failing in that situation is the expected
#: outcome, not a lost race.
RESOLVABLE_INVOICE_STATUSES: tuple[str, ...] = (
    *LIVE_INVOICE_STATUSES,
    str(E.InvoiceStatus.MANUAL_REVIEW),
)

#: What a manual credit marks as credited: money on the invoice's own asset and
#: chain. A stray transfer of a different token keeps its own status and its own
#: open case — crediting an invoice is a decision about *that invoice*, and
#: sweeping an unrelated anomaly into it under the same command is how a case
#: quietly disappears without anybody deciding about it.
_MANUALLY_CREDITABLE_STATUSES: tuple[str, ...] = (
    str(E.PaymentStatus.SEEN),
    *CREDITABLE_PAYMENT_STATUSES,
)


class ResolutionOutcome(StrEnum):
    """What the resolution actually achieved.

    Distinct from the resolution *word* the owner typed, because ``credit`` can
    end in two different places: a new entitlement, or the discovery that one
    already exists. Collapsing those would make the audit trail claim a grant
    that did not happen.
    """

    CREDITED = "credited"
    ALREADY_GRANTED = "already_granted"
    REFUND_REQUESTED = "refund_requested"
    REFUND_ALREADY_PENDING = "refund_already_pending"
    REJECTED = "rejected"
    #: TZ 5.8/T7, first half: a large credit was asked for and a code issued.
    #: Nothing was decided; the case is still open.
    CONFIRMATION_REQUIRED = "confirmation_required"


@dataclass(frozen=True, slots=True)
class PendingCase:
    """One row of `/pending` (TZ 3.4)."""

    review_id: int
    kind: str
    invoice_id: uuid.UUID | None
    payment_id: int | None
    opened_at: dt.datetime
    note: str | None
    policy_version: str | None
    invoice_status: str | None
    user_id: int | None
    asset_symbol: str | None
    asset_decimals: int | None
    amount_due_raw: Decimal | None
    amount_due_usd: Decimal | None
    received_raw: Decimal

    @property
    def shortfall_raw(self) -> Decimal | None:
        """How much is still missing, or ``None`` when there is no bill."""
        if self.amount_due_raw is None:
            return None
        gap = self.amount_due_raw - self.received_raw
        return gap if gap > 0 else Decimal(0)


@dataclass(frozen=True, slots=True)
class ResolutionResult:
    """Everything one `/resolve` did, for the message and for the tests."""

    review_id: int
    resolution: str
    outcome: ResolutionOutcome
    invoice_id: uuid.UUID | None
    operator_id: int
    amount_usd: Decimal
    policy_version: str
    audit_id: int
    entitlement_id: int | None = None
    refund_id: int | None = None
    credited_payment_ids: tuple[int, ...] = ()
    notification_ids: tuple[int, ...] = ()
    invoice_status_after: str | None = None
    #: True when ``entitlements_active_uniq`` refused a second grant — the buyer
    #: already had what the owner was about to hand them (TZ 5.8/T2.1).
    lost_grant_race: bool = False
    #: Set only with :attr:`ResolutionOutcome.CONFIRMATION_REQUIRED`. The code the
    #: owner must send back; never written to ``audit_log``.
    confirmation_code: str | None = None

    @property
    def needs_confirmation(self) -> bool:
        return self.outcome is ResolutionOutcome.CONFIRMATION_REQUIRED


async def list_pending(
    conn: AsyncConnection, *, limit: int = 200
) -> tuple[PendingCase, ...]:
    """`/pending` — "счета, зависшие в неоднозначных состояниях" (TZ 3.4).

    Also refreshes ``notchstave_manual_review_open``, the gauge TZ section 7
    puts behind the "ручные разборы копятся, продукт требует внимания" alert.
    Updating it here rather than on a timer is deliberate: the number is only
    interesting next to the list it summarises, and a gauge maintained by a
    second query on a second schedule is a gauge that eventually disagrees with
    the screen.
    """
    rows = await admin_repo.pending_cases(
        conn, creditable_statuses=CREDITABLE_PAYMENT_STATUSES, limit=limit
    )
    metrics.MANUAL_REVIEW_OPEN.set(await admin_repo.open_review_count(conn))
    return tuple(
        PendingCase(
            review_id=int(r["id"]),
            kind=r["kind"],
            invoice_id=r["invoice_id"],
            payment_id=None if r["payment_id"] is None else int(r["payment_id"]),
            opened_at=r["opened_at"],
            note=r["note"],
            policy_version=r["policy_version"],
            invoice_status=r["invoice_status"],
            user_id=None if r["user_id"] is None else int(r["user_id"]),
            asset_symbol=r["asset_symbol"],
            asset_decimals=None if r["asset_decimals"] is None else int(r["asset_decimals"]),
            amount_due_raw=None if r["amount_due_raw"] is None else Decimal(r["amount_due_raw"]),
            amount_due_usd=None if r["amount_due_usd"] is None else Decimal(r["amount_due_usd"]),
            received_raw=Decimal(r["received_raw"]),
        )
        for r in rows
    )


async def resolve_manual_review(
    conn: AsyncConnection,
    review_id: int,
    resolution: str | E.ManualReviewResolution,
    operator_id: int,
    comment: str | None = None,
    *,
    confirmation_code: str | None = None,
    confirmation_key: ConfirmationKey | None = None,
    admin_policy: AdminPolicy = DEFAULT_ADMIN_POLICY,
    owner_user_id: int | None = None,
    now: float | None = None,
) -> ResolutionResult:
    """`/resolve <invoice_id> <credit|refund|reject> [комментарий]` (TZ 3.4).

    Runs inside the caller's transaction and never commits, exactly like
    :func:`settler.service.settle_invoice`: the entitlement, the refund row, the
    outbox message, the resolution and the audit entry are one atomic act, and a
    partially applied owner decision is worse than a rejected one.

    Order of operations, and why it is this order:

    1. Lock the case (``FOR UPDATE``) and refuse a second resolution. A case
       resolved twice with two different words is a question nobody can answer
       afterwards.
    2. Lock the invoice, if there is one, and price the decision. The threshold
       of TZ 5.8/T7 is checked against ``amount_due_usd`` — the value of what is
       being handed over, not the size of the shortfall being forgiven. Waiving
       forty dollars on a two-hundred-dollar product is a two-hundred-dollar
       decision.
    3. **Confirm before acting.** The threshold check happens before a single
       write, so an unconfirmed large credit leaves the database exactly as it
       found it. Checking afterwards would mean rolling back, and a control that
       depends on a rollback is one bug away from not existing.
    4. Apply the resolution, close the case with a CAS, write the audit row.

    Args:
        review_id: ``manual_reviews.id``. The bot resolves the invoice id from
            TZ 3.4's command syntax into this; a single invoice can carry more
            than one open case (an underpayment *and* a stray token), and only
            the case id is unambiguous.
        resolution: ``credit`` / ``refund`` / ``reject``.
        operator_id: the owner's Telegram id. Stored on the case and in the
            audit row — TZ 5.8/T8, "``manual_reviews`` хранит ``operator_id``".
        comment: free text from the command, kept verbatim.
        confirmation_code: the code from the first attempt, for a credit above
            the limit.
        owner_user_id: ``users.id`` of the owner, when they have one. Present →
            an ``admin_action`` message is queued into their chat, which is the
            third measure of TZ 5.8/T7 ("захвативший аккаунт не сможет
            действовать незаметно"). Absent → the action is still in
            ``audit_log`` and in ``notchstave_admin_actions_total``, and the
            chat notification waits for the bot in Week 5.

    Returns:
        A :class:`ResolutionResult`. An outcome of
        :attr:`ResolutionOutcome.CONFIRMATION_REQUIRED` means **nothing was
        decided**: the case is still open and the result carries the code for the
        second call. Callers that own their own transaction must check
        :attr:`ResolutionResult.needs_confirmation`;
        :meth:`settler.admin.ops.AdminOps.resolve` does it for them by raising
        :class:`~settler.admin.errors.ConfirmationRequired` after the commit.

    Raises:
        ReviewNotFound: no such case.
        ReviewAlreadyResolved: somebody decided it first.
        ResolutionNotApplicable: ``credit`` or ``refund`` on a case with no
            invoice behind it, or ``refund`` on an invoice that received nothing.
        InvalidConfirmationCode: a code for a different decision, or expired.
        ConfirmationUnavailable: no key configured — fails closed.
    """
    verb = E.ManualReviewResolution(str(resolution))

    review = await admin_repo.lock_review(conn, review_id)
    if review is None:
        raise ReviewNotFound(f"manual review {review_id} does not exist")
    if review.resolved_at is not None:
        raise ReviewAlreadyResolved(
            f"manual review {review_id} was resolved at {review.resolved_at.isoformat()} "
            f"by operator {review.operator_id} as {review.resolution}"
        )

    if review.invoice_id is None and verb is not E.ManualReviewResolution.REJECT:
        raise ResolutionNotApplicable(
            f"manual review {review_id} ({review.kind}) has no invoice behind it, so "
            f"'{verb}' is meaningless; only 'reject' applies. The money is on a known "
            "address and is swept and accounted for by hand (TZ 5.5)."
        )

    ctx = (
        await repo.lock_invoice(conn, review.invoice_id)
        if review.invoice_id is not None
        else None
    )
    amount_usd = ctx.amount_due_usd if ctx is not None else Decimal(0)

    # --- TZ 5.8/T7: threshold before any write ----------------------------
    if verb is E.ManualReviewResolution.CREDIT and admin_policy.needs_confirmation(amount_usd):
        challenge_args: dict[str, Any] = {
            "review_id": review.id,
            "resolution": str(verb),
            "invoice_id": None if review.invoice_id is None else str(review.invoice_id),
            "amount_usd": amount_usd,
            "operator_id": operator_id,
            "ttl_seconds": admin_policy.confirmation_ttl_seconds,
            "length": admin_policy.confirmation_code_length,
            "now": now,
        }
        if not confirmation_code:
            code = issue_code(confirmation_key, **challenge_args)
            audit_id = await repo.write_audit(
                conn,
                actor_kind=ADMIN_ACTOR_KIND,
                actor_id=str(operator_id),
                action="admin.credit_confirmation_requested",
                target_kind="manual_review",
                target_id=str(review.id),
                before_state={"resolved_at": None, "kind": review.kind},
                after_state={"resolved_at": None},
                # The code itself is never recorded: `audit_log` is SELECT-able
                # by every application role, and a stored code is a stored bypass.
                args={
                    "amount_usd": str(amount_usd),
                    "manual_credit_limit_usd": str(admin_policy.manual_credit_limit_usd),
                    "invoice_id": None if review.invoice_id is None else str(review.invoice_id),
                },
                policy_version=admin_policy.version,
            )
            metrics.ADMIN_ACTIONS.labels(action="credit_confirmation_requested").inc()
            # Returned rather than raised, and the reason is transactional. This
            # function runs inside the caller's transaction, and
            # ``AsyncEngine.begin()`` rolls back on an exception — so raising
            # here would discard the audit row that was just written to record
            # that a large credit was attempted. That row is the whole point of
            # TZ 5.8/T7: the attempt is exactly what a compromised owner account
            # would produce, and losing it because the request was refused would
            # mean the control leaves no trace of having fired.
            #
            # The safety property that made an exception attractive — a caller
            # cannot quietly proceed as if nothing happened — is kept, one level
            # up: :meth:`settler.admin.ops.AdminOps.resolve` commits this
            # transaction and *then* raises
            # :class:`~settler.admin.errors.ConfirmationRequired`.
            return ResolutionResult(
                review_id=review.id,
                resolution=str(verb),
                outcome=ResolutionOutcome.CONFIRMATION_REQUIRED,
                invoice_id=review.invoice_id,
                operator_id=operator_id,
                amount_usd=amount_usd,
                policy_version=admin_policy.version,
                audit_id=audit_id,
                confirmation_code=code,
            )
        verify_code(confirmation_key, confirmation_code, **challenge_args)

    notifications: list[int] = []
    entitlement_id: int | None = None
    refund_id: int | None = None
    credited: tuple[int, ...] = ()
    status_after: str | None = None
    lost_race = False

    if verb is E.ManualReviewResolution.CREDIT:
        assert ctx is not None  # guaranteed above: no invoice -> only reject
        outcome, entitlement_id, credited, status_after, lost_race, notified = await _apply_credit(
            conn, ctx=ctx, review_id=review.id, operator_id=operator_id, comment=comment,
            admin_policy=admin_policy,
        )
        notifications.extend(notified)
    elif verb is E.ManualReviewResolution.REFUND:
        assert ctx is not None
        outcome, refund_id, status_after, notified = await _apply_refund(
            conn, ctx=ctx, review_id=review.id, operator_id=operator_id, comment=comment,
            admin_policy=admin_policy,
        )
        notifications.extend(notified)
    else:
        outcome, status_after, notified = await _apply_reject(
            conn, ctx=ctx, review_id=review.id, operator_id=operator_id, comment=comment,
            admin_policy=admin_policy,
        )
        notifications.extend(notified)

    # Close the case last, and with a CAS. Last, so that a failure in the work
    # above leaves the case open for somebody to look at again rather than
    # closed over nothing.
    closed = await admin_repo.resolve_review(
        conn,
        review.id,
        resolution=str(verb),
        operator_id=operator_id,
        note=_resolution_note(review.note, verb, comment),
        policy_version=admin_policy.version,
    )
    if not closed:
        # Somebody resolved it between our FOR UPDATE and here. Not reachable
        # while the lock is held — kept as a loud failure rather than a silent
        # pass because if it ever *is* reachable, the lock is not doing its job
        # and that is a fact worth an exception rather than a log line.
        raise ReviewAlreadyResolved(
            f"manual review {review.id} was closed concurrently despite the row lock"
        )

    audit_id = await repo.write_audit(
        conn,
        actor_kind=ADMIN_ACTOR_KIND,
        actor_id=str(operator_id),
        action=f"admin.resolve.{verb}",
        target_kind="manual_review",
        target_id=str(review.id),
        before_state={
            "resolved_at": None,
            "kind": review.kind,
            "invoice_status": None if ctx is None else ctx.status,
            # The version the case was *opened* under. TZ 5.8/T8 wants both:
            # `manual_reviews.policy_version` now holds the resolving version,
            # and the opening one survives here, in the table nothing can edit.
            "opened_policy_version": review.policy_version,
        },
        after_state={
            "resolved_at": "now()",
            "resolution": str(verb),
            "operator_id": operator_id,
            "invoice_status": status_after,
            "entitlement_id": entitlement_id,
            "refund_id": refund_id,
        },
        args={
            "outcome": str(outcome),
            "comment": comment,
            "amount_usd": str(amount_usd),
            "manual_credit_limit_usd": str(admin_policy.manual_credit_limit_usd),
            "confirmation_required": bool(
                verb is E.ManualReviewResolution.CREDIT
                and admin_policy.needs_confirmation(amount_usd)
            ),
            "credited_payment_ids": list(credited),
            "invoice_id": None if review.invoice_id is None else str(review.invoice_id),
        },
        policy_version=admin_policy.version,
    )

    # TZ 5.8/T7, third measure: the owner's own chat gets a copy of every admin
    # action, so a captured account cannot act invisibly to whoever reads the
    # history.
    if owner_user_id is not None:
        echo = await repo.enqueue_notification(
            conn,
            user_id=owner_user_id,
            kind="admin_action",
            ref_id=str(review.id),
            dedup_key=f"resolve:{verb}",
            payload={
                "action": f"admin.resolve.{verb}",
                "review_id": review.id,
                "invoice_id": None if review.invoice_id is None else str(review.invoice_id),
                "operator_id": operator_id,
                "outcome": str(outcome),
                "amount_usd": str(amount_usd),
                "audit_id": audit_id,
                "policy_version": admin_policy.version,
            },
        )
        if echo is not None:
            notifications.append(echo)

    metrics.ADMIN_ACTIONS.labels(action=f"resolve.{verb}").inc()
    metrics.MANUAL_REVIEW_OPEN.set(await admin_repo.open_review_count(conn))

    return ResolutionResult(
        review_id=review.id,
        resolution=str(verb),
        outcome=outcome,
        invoice_id=review.invoice_id,
        operator_id=operator_id,
        amount_usd=amount_usd,
        policy_version=admin_policy.version,
        audit_id=audit_id,
        entitlement_id=entitlement_id,
        refund_id=refund_id,
        credited_payment_ids=credited,
        notification_ids=tuple(notifications),
        invoice_status_after=status_after,
        lost_grant_race=lost_race,
    )


# ---------------------------------------------------------------------------
# The three resolutions
# ---------------------------------------------------------------------------


async def _apply_credit(
    conn: AsyncConnection,
    *,
    ctx: repo.InvoiceContext,
    review_id: int,
    operator_id: int,
    comment: str | None,
    admin_policy: AdminPolicy,
) -> tuple[ResolutionOutcome, int | None, tuple[int, ...], str | None, bool, tuple[int, ...]]:
    """Hand over the product despite the anomaly (TZ 5.5, "щедрость").

    Reuses :func:`settler.repository.insert_entitlement` rather than writing its
    own INSERT, and that is the load-bearing detail of this function. The
    savepoint, the ``entitlements_active_uniq`` violation being read as "lost the
    race" rather than as an error, and the guarantee that a buyer cannot end up
    with two active grants for one invoice — all of TZ 5.8/T2.1 — come along for
    free. A second INSERT statement here would be a second place for the double
    grant bug to live, in the path a compromised owner account can reach.
    """
    status_after: str | None = None
    if await repo.cas_invoice_status(
        conn,
        ctx.invoice_id,
        new_status=str(E.InvoiceStatus.PAID),
        expected=RESOLVABLE_INVOICE_STATUSES,
        mark_settled=True,
    ):
        status_after = str(E.InvoiceStatus.PAID)
    else:
        # Already terminal — typically the `overpaid` case the settler opened
        # next to a refund obligation, where the product was delivered long ago.
        # Not a race loss and not an error: the case still needs closing.
        status_after = ctx.status

    payments = await repo.invoice_payments(conn, ctx.invoice_id)
    credited: list[int] = []
    for payment in payments:
        if payment.asset_id != ctx.asset_id or payment.chain_id != ctx.chain_id:
            continue
        if payment.anomaly is not None and payment.anomaly not in CREDITABLE_ANOMALIES:
            continue
        if payment.status not in _MANUALLY_CREDITABLE_STATUSES:
            continue
        if payment.status == str(E.PaymentStatus.SEEN):
            await repo.promote_payment_to_confirmed(conn, payment.id)
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
    if entitlement_id is None:
        metrics.DOUBLE_GRANT_BLOCKED.inc()
        return (
            ResolutionOutcome.ALREADY_GRANTED,
            None,
            tuple(credited),
            status_after,
            True,
            (),
        )

    notification_id = await repo.enqueue_notification(
        conn,
        user_id=ctx.user_id,
        kind="invoice_manual_credit",
        ref_id=str(ctx.invoice_id),
        dedup_key=str(entitlement_id),
        payload={
            "invoice_id": str(ctx.invoice_id),
            "review_id": review_id,
            "outcome": str(ResolutionOutcome.CREDITED),
            "entitlement_id": entitlement_id,
            "operator_comment": comment,
            "asset": ctx.asset_symbol,
            "amount_due_raw": str(ctx.amount_due_raw),
            "policy_version": admin_policy.version,
        },
    )
    return (
        ResolutionOutcome.CREDITED,
        entitlement_id,
        tuple(credited),
        status_after,
        False,
        () if notification_id is None else (notification_id,),
    )


async def _apply_refund(
    conn: AsyncConnection,
    *,
    ctx: repo.InvoiceContext,
    review_id: int,
    operator_id: int,
    comment: str | None,
    admin_policy: AdminPolicy,
) -> tuple[ResolutionOutcome, int | None, str | None, tuple[int, ...]]:
    """Record an obligation to return the money. Sends nothing (TZ 12).

    The amount is what actually arrived on the invoice — read without a
    confirmation gate, because a human deciding to return money a day later is
    not waiting on three more blocks (see
    :data:`settler.admin.repository.SQL_INVOICE_RECEIVED_TOTAL`).

    ``to_address`` stays NULL. TZ 5.5: "адрес отправителя — не надёжный адрес
    для возврата ... при возврате свыше порога бот запрашивает у пользователя
    адрес для возврата явно". The owner fills it in when the buyer supplies one,
    and the ``executed_requires_details`` CHECK from migration 0001 makes it
    impossible to mark a refund executed without it.
    """
    received_raw, _count = await admin_repo.invoice_received_total(
        conn,
        ctx.invoice_id,
        asset_id=ctx.asset_id,
        chain_id=ctx.chain_id,
        statuses=CREDITABLE_PAYMENT_STATUSES,
        creditable_anomalies=CREDITABLE_ANOMALIES,
    )

    status_after = ctx.status
    if received_raw <= 0:
        # Nothing arrived, so there is nothing to give back. Refusing here rather
        # than writing a zero-amount refund row: `amount_raw > 0` is a CHECK in
        # migration 0001, and an owner who typed `refund` on an empty invoice
        # meant `reject`.
        raise ResolutionNotApplicable(
            f"invoice {ctx.invoice_id} has received nothing in {ctx.asset_symbol}; "
            "there is no money to refund — use 'reject' to close the case"
        )

    refund_id = await repo.create_refund_request(
        conn,
        invoice_id=ctx.invoice_id,
        amount_raw=received_raw,
        asset_id=ctx.asset_id,
        note=(
            f"/resolve refund by operator {operator_id} on review {review_id}. "
            f"to_address intentionally NULL — ask the buyer for a destination "
            f"(TZ 5.5). Operator comment: {comment or '-'}"
        ),
    )
    if refund_id is None:
        # `uq_refunds_pending_per_invoice` — a pending obligation for this
        # invoice already exists, typically the one the settler opened for an
        # overpayment. One obligation per invoice is the correct number.
        return ResolutionOutcome.REFUND_ALREADY_PENDING, None, status_after, ()

    if await repo.cas_invoice_status(
        conn,
        ctx.invoice_id,
        new_status=str(E.InvoiceStatus.CANCELLED),
        expected=RESOLVABLE_INVOICE_STATUSES,
    ):
        # `cancelled` and not a new `refunded` status: the invoice state machine
        # of TZ 6 is closed, adding a tenth value would be an enum migration on
        # a shipped schema, and what `cancelled` means here — "this invoice will
        # not deliver a product" — is exactly right. The obligation lives in
        # `refunds`, which is the table that exists to hold it.
        status_after = str(E.InvoiceStatus.CANCELLED)

    notification_id = await repo.enqueue_notification(
        conn,
        user_id=ctx.user_id,
        kind="refund_requested",
        ref_id=str(ctx.invoice_id),
        dedup_key=str(refund_id),
        payload={
            "invoice_id": str(ctx.invoice_id),
            "review_id": review_id,
            "refund_id": refund_id,
            "amount_raw": str(received_raw),
            "asset": ctx.asset_symbol,
            "decimals": ctx.asset_decimals,
            # The buyer has to supply a destination; the bot's message is where
            # that is asked for.
            "needs_destination_address": True,
            "operator_comment": comment,
            "policy_version": admin_policy.version,
        },
    )
    return (
        ResolutionOutcome.REFUND_REQUESTED,
        refund_id,
        status_after,
        () if notification_id is None else (notification_id,),
    )


async def _apply_reject(
    conn: AsyncConnection,
    *,
    ctx: repo.InvoiceContext | None,
    review_id: int,
    operator_id: int,
    comment: str | None,
    admin_policy: AdminPolicy,
) -> tuple[ResolutionOutcome, str | None, tuple[int, ...]]:
    """Close the case with nothing granted and nothing owed.

    Deliberately does **not** touch ``payments``. A rejected case leaves the
    money exactly where it is, in whatever status the watcher gave it, and the
    funds are swept offline like any other balance on a receive address. Marking
    them anything else would be the application editing the ledger to match a
    decision, which is the inverse of how this system is meant to work.
    """
    if ctx is None:
        return ResolutionOutcome.REJECTED, None, ()

    status_after = ctx.status
    if await repo.cas_invoice_status(
        conn,
        ctx.invoice_id,
        new_status=str(E.InvoiceStatus.CANCELLED),
        expected=RESOLVABLE_INVOICE_STATUSES,
    ):
        status_after = str(E.InvoiceStatus.CANCELLED)

    notification_id = await repo.enqueue_notification(
        conn,
        user_id=ctx.user_id,
        kind="invoice_rejected",
        ref_id=str(ctx.invoice_id),
        dedup_key=str(review_id),
        payload={
            "invoice_id": str(ctx.invoice_id),
            "review_id": review_id,
            "outcome": str(ResolutionOutcome.REJECTED),
            "operator_comment": comment,
            "policy_version": admin_policy.version,
        },
    )
    return (
        ResolutionOutcome.REJECTED,
        status_after,
        () if notification_id is None else (notification_id,),
    )


def _resolution_note(
    opening_note: str | None, verb: E.ManualReviewResolution, comment: str | None
) -> str:
    """Keep the machine's reason and the human's reason in one field.

    ``manual_reviews.note`` is a single column and the resolution overwrites it,
    so the opening note — which is where the settler recorded *why* the case
    exists, with the amounts — is carried forward rather than replaced. Losing it
    would leave a resolved case saying only "credit: ok", which answers nothing
    a month later.
    """
    head = opening_note or ""
    tail = f"[{verb}] {comment}" if comment else f"[{verb}]"
    return f"{head}\n{tail}".strip()
