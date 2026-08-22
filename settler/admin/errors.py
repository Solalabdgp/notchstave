"""Failure modes of the admin commands.

Same discipline as :mod:`settler.errors`: an unusual *outcome* is a value, an
unusual *situation* is an exception. ``/resolve reject`` is an outcome and
returns a :class:`~settler.admin.reviews.ResolutionResult`; ``/resolve`` against
a review id that does not exist is a situation and raises, because swallowing it
would hide that the owner — or something wearing the owner's session — is
working from a reference nobody issued.

:class:`ConfirmationRequired` sits deliberately on the exception side of that
line even though it is a perfectly normal thing to happen. The reason is TZ
5.8/T7: the whole point of the threshold is that a scripted caller must not be
able to treat "credit" and "credit, pending confirmation" as interchangeable.
An exception cannot be ignored by a caller that forgot to check a field.
"""

from __future__ import annotations

from decimal import Decimal

__all__ = [
    "AdminError",
    "ReviewNotFound",
    "ReviewAlreadyResolved",
    "ResolutionNotApplicable",
    "ConfirmationRequired",
    "InvalidConfirmationCode",
    "ConfirmationUnavailable",
    "BalancesUnavailable",
    "AdminActionFailed",
    "AdminUnavailable",
]


class AdminError(Exception):
    """Base class for the admin commands of TZ 3.4."""


class ReviewNotFound(AdminError):
    """No ``manual_reviews`` row with this id."""


class ReviewAlreadyResolved(AdminError):
    """Somebody already decided this case.

    Raised rather than silently returning the previous decision: two owners (or
    one owner and one replayed message) resolving the same case differently is
    exactly the situation ``resolved_at IS NULL`` in the CAS exists to catch, and
    the second caller must be told their decision did **not** take effect.
    """


class ResolutionNotApplicable(AdminError):
    """This resolution cannot be applied to this case.

    The realistic instance: a payment-level review with no invoice behind it —
    ``unassigned_payment`` on an address nobody was billing. There is no invoice
    to credit and ``refunds.invoice_id`` is ``NOT NULL``, so ``credit`` and
    ``refund`` are both meaningless; only ``reject`` (close the case, the money
    is swept and accounted for by hand) applies.
    """


class ConfirmationRequired(AdminError):
    """TZ 5.8/T7 — a manual credit above ``manual_credit_limit_usd``.

    Carries the code the owner must send back in the second call. The code is
    the *only* new information in this exception: everything else in it was
    already in the request, and is repeated so that the message the bot renders
    ("confirm crediting $240 on invoice X with code ABCD-1234") can be built
    without a second query.
    """

    def __init__(
        self,
        *,
        review_id: int,
        code: str,
        amount_usd: Decimal,
        limit_usd: Decimal,
        ttl_seconds: int,
    ) -> None:
        super().__init__(
            f"manual credit of {amount_usd} USD on review {review_id} exceeds the "
            f"{limit_usd} USD limit; re-send with confirmation_code={code} "
            f"within {ttl_seconds}s"
        )
        self.review_id = review_id
        self.code = code
        self.amount_usd = amount_usd
        self.limit_usd = limit_usd
        self.ttl_seconds = ttl_seconds


class InvalidConfirmationCode(AdminError):
    """The presented code does not belong to this decision, or has expired.

    "Does not belong to" is the important half. The code is derived from the
    exact arguments of the decision, so a code legitimately issued for one
    invoice fails here when replayed against another — which is the attack a
    captured session would actually try.
    """


class ConfirmationUnavailable(AdminError):
    """No confirmation key is configured, so a large credit cannot be confirmed.

    Fails **closed**, and that choice is the whole security value of this class.
    A missing ``NOTCHSTAVE_ADMIN_CONFIRMATION_KEY`` must mean "large manual
    credits are impossible until an operator sets it", never "large manual
    credits proceed without confirmation" — a misconfiguration silently
    disabling a control is how controls stop existing. TZ section 9 puts this key
    with the settler under ``LoadCredential=``, alongside
    ``INVOICE_INTEGRITY_KEY``.
    """


# ---------------------------------------------------------------------------
# Raised across the queue of migration 0012
# ---------------------------------------------------------------------------
#
# The three below exist because the admin commands stopped being function calls
# in the bot process and became requests to the settler (migration 0012). Two of
# them describe a settler that could not answer; the third describes one that
# answered with something this vocabulary has no word for. All three are
# `AdminError` so that a handler written against the in-process call — `except
# AdminError` — keeps catching everything it used to.


class BalancesUnavailable(AdminError):
    """`/reconcile` and `/sweeplist` need on-chain balances and there are none.

    The settler builds one :class:`~settler.admin.balances.RpcBalanceSource` per
    chain from ``chains.rpc_urls`` and a fresh checkout has none, so this is the
    ordinary answer on a half-configured deployment rather than a fault.

    Fails **closed**, and that is the point: reconciling against an unreachable
    chain would read every balance as zero and report that the entire float is
    missing — the single most alarming wrong answer this system can produce.
    """


class AdminActionFailed(AdminError):
    """The settler raised something that is not an :class:`AdminError`.

    ``/reconcile`` reaches RPC and pricing, either of which can fail in ways
    :mod:`settler.admin` has no vocabulary for (``UnknownRate``, a circuit
    breaker that is open, a provider returning nonsense). Those used to surface
    in the bot as themselves, because the call was in-process; across a queue
    only the class *name* survives, so they arrive as this and carry the
    settler's message.

    The message is passed through rather than replaced. The audience for these
    four commands is one operator who owns the deployment and is the only person
    who can act on "all three providers are rate-limiting" — sanitising that into
    "something went wrong" would be protecting them from their own logs.
    """


class AdminUnavailable(AdminError):
    """The request was never answered: no settler, or not in time.

    Distinct from :class:`AdminActionFailed`, and the distinction is the one the
    owner needs: this means **nothing happened**. The row is not withdrawn and
    may still be served — which is why the message says so rather than inviting
    an immediate retry of a credit that might already be in flight.
    """
