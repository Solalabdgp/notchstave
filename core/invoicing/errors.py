"""Every way invoice creation and invoice display can refuse.

Two rules shape this hierarchy, and both come out of the TZ rather than out of
taste.

**A refusal is an answer, not a crash.** TZ 5.8/T5.2 is explicit that hitting
the address ceiling must produce *"честное «сейчас нельзя, попробуйте позже»"*
and not a 500. So every exception here carries :attr:`InvoicingError.user_message`
— a sentence that can be sent to a buyer as-is — separately from its ``str()``,
which is for the operator and may name limits, counts and ids. The bot renders
one, the log records the other, and neither has to guess.

**Integrity failures are a different species and must not be catchable by
accident.** :class:`AddressMismatch` and :class:`MacMismatch` do not mean "try
again later", they mean the database no longer agrees with the xpub or with the
HMAC key (TZ 5.8/T1.1, T1.3: *"событие классифицируется как подозрение на
компрометацию"*). They deliberately do **not** inherit from
:class:`InvoiceUnavailable`, so a handler written to be friendly about quotas
and outages cannot swallow them, and a caller that catches
:class:`InvoicingError` broadly still gets a distinguishable type on the way
past.
"""

from __future__ import annotations

import datetime as dt

__all__ = [
    "InvoicingError",
    "InvoiceUnavailable",
    "CatalogError",
    "UnknownProduct",
    "UnknownAsset",
    "RateUnavailable",
    "QuotaExceeded",
    "TooManyActiveInvoices",
    "HourlyQuotaExceeded",
    "BehaviouralCooldown",
    "AddressCapacityExhausted",
    "InvoiceRequestInFlight",
    "InvoiceRequestTimeout",
    "InvoiceRequestAbandoned",
    "InvoiceNotFound",
    "IntegrityFailure",
    "AddressMismatch",
    "MacMismatch",
]


class InvoicingError(Exception):
    """Base class. Carries a buyer-safe sentence alongside the operator detail."""

    #: Default text shown to the buyer. Subclasses override or replace per instance.
    user_message = "Something went wrong creating this invoice. Please try again."

    def __init__(self, detail: str, *, user_message: str | None = None) -> None:
        super().__init__(detail)
        if user_message is not None:
            self.user_message = user_message


class InvoiceUnavailable(InvoicingError):
    """Cannot issue an invoice right now — a business answer, never a 500.

    The scenarios underneath are unrelated (quota, cooldown, address ceiling,
    disabled asset), and grouping them is not laziness: from the caller's side
    they share the only property that matters, which is that the correct
    response is a polite refusal with, where possible, a time to come back.
    """

    #: When the caller may retry, if that is knowable. ``None`` means "unknown"
    #: and must be rendered as "later", not as "now".
    retry_at: dt.datetime | None = None


# ---------------------------------------------------------------------------
# Catalog and pricing
# ---------------------------------------------------------------------------


class CatalogError(InvoiceUnavailable):
    """The product/asset/chain combination cannot be billed."""


class UnknownProduct(CatalogError):
    user_message = "That item is not on sale right now."


class UnknownAsset(CatalogError):
    """Asset missing, disabled, or not on the requested chain.

    TZ 12 — the accepted assets are an explicit allow-list, so "not found" and
    "not enabled" get the same answer on purpose. Telling a caller which of the
    two it was is free reconnaissance on the allow-list.
    """

    user_message = "That network or token is not accepted right now."


class RateUnavailable(CatalogError):
    """No usable price snapshot for the asset (TZ 5.7).

    Fails closed. An invoice priced from a missing or stale rate is an invoice
    whose amount is wrong in one direction or the other, and TZ 5.5 makes the
    quote binding for ``rate_locked_until`` — there is no safe fallback number.
    """

    user_message = "Pricing for this token is temporarily unavailable. Please try again shortly."


# ---------------------------------------------------------------------------
# T5 — DoS through address generation
# ---------------------------------------------------------------------------


class QuotaExceeded(InvoiceUnavailable):
    """A TZ 5.8/T5 quota stopped this ``/buy``.

    ``scope`` is the label value of ``notchstave_invoice_ratelimit_hits_total``
    (TZ section 7), so the metric and the exception cannot drift into using
    different vocabularies for the same event.
    """

    scope = "unknown"

    def __init__(
        self,
        detail: str,
        *,
        limit: int,
        observed: int,
        retry_at: dt.datetime | None = None,
        user_message: str | None = None,
    ) -> None:
        super().__init__(detail, user_message=user_message)
        self.limit = limit
        self.observed = observed
        self.retry_at = retry_at


class TooManyActiveInvoices(QuotaExceeded):
    """``max_active_invoices_per_user`` (default 3) reached — TZ 5.8/T5.1."""

    scope = "active_invoices"
    user_message = (
        "You already have the maximum number of open invoices. "
        "Pay or cancel one of them before creating another."
    )


class HourlyQuotaExceeded(QuotaExceeded):
    """``max_invoices_per_hour`` (default 10) reached — TZ 5.8/T5.1."""

    scope = "hourly"
    user_message = "You have created too many invoices in the last hour. Please try again later."


class BehaviouralCooldown(QuotaExceeded):
    """N consecutive expired unpaid invoices — TZ 5.8/T5.5.

    "Мера мягкая и обратимая — обычный покупатель в неё не упирается, скрипт
    упирается сразу." Nothing is banned and nothing needs an operator to undo:
    the cooldown lapses on its own, and one payment resets the streak.
    """

    scope = "cooldown"
    user_message = (
        "Several of your recent invoices expired without payment, "
        "so new invoices are paused for a while. Please try again later."
    )


class AddressCapacityExhausted(InvoiceUnavailable):
    """``max_active_addresses`` reached on the derivation account — TZ 5.8/T5.2.

    This is a system-wide condition, not this buyer's fault, and it is the one
    the TZ writes a sentence for: the answer is "сейчас нельзя, попробуйте
    позже", the metric moves, and an alert fires at 80% of the ceiling long
    before anyone sees this.
    """

    user_message = (
        "We cannot open a new payment address at the moment. Please try again in a few minutes."
    )


# ---------------------------------------------------------------------------
# The ask-the-deriver round trip (migration 0007)
# ---------------------------------------------------------------------------
#
# Issuance happens in the deriver process, so a `/buy` can now fail in ways that
# have nothing to do with the invoice: the request never got picked up, or the
# caller stopped waiting. Those live here rather than in the client module,
# because a bot that catches `InvoiceUnavailable` should not have to import a
# second exception hierarchy to catch the whole set.


class InvoiceRequestInFlight(InvoiceUnavailable):
    """This user already has an unanswered request (0007's unique index).

    The cheapest of the T5.1 quotas and the first one a double-tapped button
    meets: one open request per user, enforced by
    ``uq_invoice_requests_one_open_per_user`` at INSERT time, before an advisory
    lock has been taken or a count has been read. Normal use never sees it —
    the window it guards is the few milliseconds a request is in flight.
    """

    user_message = "We are already creating an invoice for you. One moment."


class InvoiceRequestTimeout(InvoiceUnavailable):
    """The caller stopped waiting. **Not** proof that nothing was issued.

    The request row stays where it is and the deriver may still answer it, so
    the honest message is "we do not know yet", never "that failed". A buyer who
    is told it failed will press ``/buy`` again; a buyer who is told to check is
    pointed at ``/status``, where a successfully issued invoice is waiting.

    In practice this means the deriver is down or the database is unreachable:
    the expected round trip is one ``NOTIFY`` hop, three orders of magnitude
    inside the default deadline.
    """

    user_message = (
        "This is taking longer than usual. Your invoice may still be on its way — "
        "check /status in a moment before trying again."
    )


class InvoiceRequestAbandoned(InvoiceUnavailable):
    """The deriver tried, failed repeatedly, and said so.

    Distinct from a timeout because it is a *finished* request: nothing was
    issued, nothing is pending, and retrying is the right advice. The class name
    is also the ``error_code`` the deriver writes (``deriver.requests
    .ABANDONED_ERROR_CODE``), which is what lets the client map it back without
    a translation table.
    """

    user_message = (
        "We could not create this invoice. Nothing was charged — please try again."
    )


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


class InvoiceNotFound(InvoicingError):
    """No such invoice — or not this user's, or the public token has expired.

    One exception for all three, because TZ 5.8/T1.7 wants ``/status`` on
    somebody else's invoice to answer 404 and not 403: a 403 confirms the id
    exists, which is exactly the fact an enumeration attempt is fishing for.
    """

    user_message = "No such invoice."


# ---------------------------------------------------------------------------
# T1 — address substitution
# ---------------------------------------------------------------------------


class IntegrityFailure(InvoicingError):
    """The stored invoice disagrees with the key material. Suspected compromise.

    Deliberately not an :class:`InvoiceUnavailable`: "try again later" is the
    wrong shape of answer, because trying again will produce the same result and
    because the correct operator response is to stop taking payments and look at
    the database (TZ section 7 alert table, ``address_mismatch_total > 0``).
    """

    user_message = (
        "This invoice failed a security check and cannot be displayed. "
        "Do not send any funds. Please contact support."
    )

    def __init__(self, detail: str, *, invoice_id: object, user_message: str | None = None) -> None:
        super().__init__(detail, user_message=user_message)
        self.invoice_id = invoice_id


class AddressMismatch(IntegrityFailure):
    """``deriver.verify`` said no — TZ 5.8/T1.1.

    The address in the row does not come out of the xpub at the index the row
    claims. Either the database was written to outside the deriver, or the
    derivation is broken; both are handled the same way and neither is a
    display glitch to retry.
    """


class MacMismatch(IntegrityFailure):
    """``integrity_mac`` did not verify — TZ 5.8/T1.3.

    The address may still derive correctly: this is the counterpart check that
    covers the *rest* of the significant tuple — chain, asset, amount, deadline.
    An attacker who edits ``amount_due_raw`` in a stolen replica does not touch
    the address at all.
    """
