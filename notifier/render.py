"""Outbox row -> message text. Payload only, no joins, no invention.

**Week 5 owns the wording.** TZ section 11 puts "тексты сообщений" in Week 5
alongside the invoice page and the help section, and rightly — copy for a
product that takes money is a piece of work, not a side effect of a delivery
loop. What Week 4 needs from this module is the *shape*: a total function from
``(kind, payload)`` to a message, with a registry that fails loudly on an
unknown kind instead of guessing. The strings below are placeholders in English;
replacing them, adding ``users.lang`` branching, and formatting raw amounts into
human units is Week 5's job and touches nothing else in this package.

Two constraints that are not stylistic and must survive that rewrite:

**Everything comes from ``payload_json``.** The notifier has no grant on
``products`` (migration 0002) and cannot read a title or a price. That is the
privilege boundary of TZ section 4 showing up as an API: the process that talks
to the internet does not get to read the catalogue. It is also why the settler
writes symbols and amounts into the payload rather than ids alone.

**A missing key is a failure, not a blank.** ``payload["address"]`` and not
``payload.get("address", "")`` — a "send the rest to:" message with an empty
address is worse than no message at all, and TZ 3.5 asks the underpayment
notice to carry "точную недостающую сумму и тот же адрес для доплаты". A
``KeyError`` here is caught by :mod:`notifier.service` and lands the row in the
DLQ, where somebody sees it.

The one deliberate hole: raw amounts are printed as raw base units. Converting
``12500000`` into ``12.5 USDC`` needs the asset's ``decimals``, which the
settler does put in the payload for the underpayment case and not for others.
Formatting is Week 5's; printing the honest raw number in the meantime is
better than a plausible wrong one.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from notifier.errors import UnrenderableNotificationError

__all__ = ["Rendered", "render", "RENDERERS", "KINDS_WITH_RENDERERS"]


@dataclass(frozen=True, slots=True)
class Rendered:
    """What to say, and whether it replaces something already on screen."""

    text: str
    #: When set, the notifier looks for an earlier delivered message with this
    #: ``kind`` and the same ``ref_id`` and edits it instead of sending a new
    #: one (TZ 5.5). If none is found the message is sent normally — an edit
    #: whose target was never delivered is still information the user needs.
    edits_kind: str | None = None


Renderer = Callable[[Mapping[str, Any]], Rendered]


def _payment_seen(payload: Mapping[str, Any]) -> Rendered:
    """TZ 3.5 — "увидели ваш перевод", before confirmations."""
    return Rendered(
        "We can see your transfer on-chain and are waiting for it to confirm.\n"
        f"Invoice: {payload['invoice_id']}"
    )


def _invoice_settled(payload: Mapping[str, Any]) -> Rendered:
    """TZ 3.5 — "оплачено, доступ выдан".

    Sent *after* the entitlement row exists, never instead of it (TZ 5.7). That
    ordering is not enforced here — it is enforced by this row only existing
    because the settler wrote it in the same transaction as the grant.
    """
    return Rendered(
        "Payment confirmed — your access is active.\n"
        f"Invoice: {payload['invoice_id']}\n"
        f"Outcome: {payload['outcome']}"
    )


def _invoice_underpaid(payload: Mapping[str, Any]) -> Rendered:
    """TZ 3.5 — the exact shortfall and the same address to top up."""
    return Rendered(
        "We received less than the invoice total.\n"
        f"Still missing: {payload['missing_raw']} (raw units of {payload['asset']})\n"
        f"Send the remainder to the same address: {payload['address']}\n"
        f"Invoice: {payload['invoice_id']}"
    )


def _entitlement_revoked(payload: Mapping[str, Any]) -> Rendered:
    """TZ 3.5 — "платёж откатился" after a reorg.

    The one renderer that asks for an edit. The user is looking at "your access
    is active" from :func:`_invoice_settled`; leaving that message intact under
    a correction is how somebody keeps believing they still have access.
    """
    return Rendered(
        "Your payment was rolled back by a chain reorganisation, so the access "
        "granted for it has been revoked.\n"
        f"Invoice: {payload['invoice_id']}\n"
        f"Reason: {payload['reason']}",
        edits_kind="invoice_settled",
    )


def _overpaid_credited(payload: Mapping[str, Any]) -> Rendered:
    return Rendered(
        "You sent more than the invoice total. The excess has been credited to "
        "your balance for future purchases.\n"
        f"Credited: {payload['credited_excess_usd']} USD\n"
        f"Invoice: {payload['invoice_id']}"
    )


def _refund_pending(payload: Mapping[str, Any]) -> Rendered:
    return Rendered(
        "You sent more than the invoice total. Your access is active, and we "
        "have opened a refund for the difference — we will ask you where to "
        "send it.\n"
        f"Invoice: {payload['invoice_id']}"
    )


def _invoice_expired(payload: Mapping[str, Any]) -> Rendered:
    return Rendered(
        "This invoice has expired and its rate quote is no longer valid. "
        "Nothing was charged; start a new order to get a fresh quote.\n"
        f"Invoice: {payload['invoice_id']}"
    )


def _invoice_manual_review(payload: Mapping[str, Any]) -> Rendered:
    return Rendered(
        "Your payment needs a manual check before we can release access. "
        "Nothing is lost — we will come back to you.\n"
        f"Invoice: {payload['invoice_id']}"
    )


def _invoice_manual_credit(payload: Mapping[str, Any]) -> Rendered:
    return Rendered(
        "Your payment has been reviewed and credited — your access is active.\n"
        f"Invoice: {payload['invoice_id']}"
    )


def _refund_requested(payload: Mapping[str, Any]) -> Rendered:
    return Rendered(
        "A refund has been approved for this invoice. Reply with the address it "
        "should be sent to — we never reuse the sending address for refunds.\n"
        f"Invoice: {payload['invoice_id']}"
    )


#: ``kind`` -> renderer. The keys are exactly the kinds
#: :mod:`settler.service` and :mod:`settler.admin` enqueue today.
#:
#: Two kinds the settler writes are deliberately absent — ``admin_action`` and
#: ``reconcile_drift``. Both are addressed to the owner, not to a buyer, and
#: both carry operational detail (drift amounts, admin arguments) that has no
#: business being formatted by the same code path that talks to customers. They
#: belong to the bot's owner channel in Week 5. Until that exists they land in
#: the DLQ by the rule below, which is visible and reversible; inventing a
#: customer-facing rendering for them would be neither.
RENDERERS: dict[str, Renderer] = {
    "payment_seen": _payment_seen,
    "invoice_settled": _invoice_settled,
    "invoice_underpaid": _invoice_underpaid,
    "entitlement_revoked": _entitlement_revoked,
    "overpaid_credited": _overpaid_credited,
    "refund_pending": _refund_pending,
    "invoice_expired": _invoice_expired,
    "invoice_manual_review": _invoice_manual_review,
    "invoice_manual_credit": _invoice_manual_credit,
    "refund_requested": _refund_requested,
}

KINDS_WITH_RENDERERS = frozenset(RENDERERS)


def render(kind: str, payload: Mapping[str, Any]) -> Rendered:
    """Text for one outbox row, or refuse.

    Both failure modes raise :class:`~notifier.errors
    .UnrenderableNotificationError`, which is permanent — no renderer and a
    payload missing the field the renderer needs are equally unfixable by
    retrying, and both are fixed by a code change plus a re-queue.
    """
    renderer = RENDERERS.get(kind)
    if renderer is None:
        raise UnrenderableNotificationError(f"no renderer for kind {kind!r}")
    try:
        return renderer(payload)
    except KeyError as exc:
        raise UnrenderableNotificationError(
            f"payload for kind {kind!r} is missing {exc.args[0]!r}"
        ) from exc
