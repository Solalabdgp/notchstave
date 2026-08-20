"""The four rungs of TZ 3.2's ladder, and the branches off it.

    ожидает оплаты -> увидели транзакцию, N/M подтверждений -> оплачено ->
    доступ выдан

A pure function over an :class:`api.repository.InvoiceProgress`, in its own
module so it can be tested without a database — the ladder has more edges than
it looks like it has, and every one of them is a sentence a buyer reads while
deciding whether they have been robbed.

**Why the stage is derived and not stored.** There is no column that means "the
buyer should be told N/M". ``invoices.status`` is the settler's state machine
and stops at ``paid``; the fourth rung lives in ``entitlements``; the
confirmation count lives in ``payments`` against ``chains.last_indexed_block``.
Deriving one label from those three is either done here, once, or spread across
the page script and the bot's message templates in two dialects that drift.

**Why ``expired`` is not the end of the story.** TZ 5.5 keeps the top-up window
open past ``expires_at``, so an expired invoice with money against it is
``underpaid`` and still payable, not dead. Telling that buyer "expired" when the
system will still credit them is how a support conversation starts.
"""

from __future__ import annotations

import enum

from api.repository import InvoiceProgress
from core.db import enums as E

__all__ = ["Stage", "stage_of"]


class Stage(enum.StrEnum):
    """What the page says, in one word the script can switch on.

    Values are the API contract — the browser compares against these strings —
    so they are lowercase ASCII and never localized. The human sentence is the
    page's job, not this enum's.
    """

    #: Nothing on chain yet.
    AWAITING = "awaiting"
    #: At least one transfer seen, still short of the confirmation threshold.
    CONFIRMING = "confirming"
    #: Money arrived and was credited, but less than the invoice asks for
    #: (TZ 5.5 underpayment — the same address stays open for a top-up).
    UNDERPAID = "underpaid"
    #: The settler credited the full amount.
    PAID = "paid"
    #: ...and the entitlement row exists. The last rung.
    GRANTED = "granted"
    #: Deadline passed with nothing credited and no top-up window left.
    EXPIRED = "expired"
    #: A human is looking at it (over/underpay past the window, wrong asset,
    #: wrong chain). The page must not guess an outcome here.
    MANUAL_REVIEW = "manual_review"
    #: A confirmed payment was undone by a reorg (TZ 5.4).
    REVERTED = "reverted"
    CANCELLED = "cancelled"


_TERMINAL = {
    str(E.InvoiceStatus.MANUAL_REVIEW): Stage.MANUAL_REVIEW,
    str(E.InvoiceStatus.REVERTED): Stage.REVERTED,
    str(E.InvoiceStatus.CANCELLED): Stage.CANCELLED,
}


def stage_of(progress: InvoiceProgress) -> Stage:
    """Collapse three tables into the one word the buyer sees.

    Order of the checks is the whole content of this function:

    1. **Granted first.** The entitlement is the outcome the buyer actually
       wants, and it outranks everything — including a later reorg that flipped
       ``invoices.status``, because a revoked grant clears ``access_granted``
       and a live one means the product was delivered.
    2. **Explicit terminal statuses next**, before any arithmetic. An invoice in
       ``manual_review`` must never be shown a confirmation count, because the
       count implies an automatic outcome that is no longer coming.
    3. **Paid/overpaid**, which is the settler's verdict and not ours to
       recompute from the sums.
    4. **Money present but not enough** — underpaid, whether or not the nominal
       deadline has passed, as long as the top-up window has not (TZ 5.5).
    5. **Something on chain, nothing credited** — the N/M rung.
    6. **Expired**, only once none of the above applied.
    """
    if progress.access_granted:
        return Stage.GRANTED

    terminal = _TERMINAL.get(progress.status)
    if terminal is not None:
        return terminal

    if progress.status in (str(E.InvoiceStatus.PAID), str(E.InvoiceStatus.OVERPAID)):
        return Stage.PAID

    if progress.amount_paid_raw > 0 and progress.amount_outstanding_raw > 0:
        return Stage.UNDERPAID

    if progress.payments:
        return Stage.CONFIRMING

    if progress.status == str(E.InvoiceStatus.EXPIRED):
        return Stage.EXPIRED

    return Stage.AWAITING
