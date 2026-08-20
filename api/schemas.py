"""The JSON contract. Amounts are strings, and that is not a style choice.

``amount_due_raw`` is ``NUMERIC(78,0)`` — up to 78 digits, far past the 2^53
where a JSON number stops surviving a round trip through a parser that treats it
as a double. The wire format of :mod:`core.invoicing.wire` already made this
call for the deriver round trip and gives the full argument; this module makes
the same one at the HTTP boundary, for the same reason and with the same
consequence: a browser reading ``amount_due_raw`` gets a string it can display
character for character, and never a float that rounds the last two digits of a
payment amount.

**Decimal-as-string also protects the comparison the buyer is asked to make.**
TZ 5.8/T1.4 says the check available to a buyer without an xpub is that the
address and amount are identical across the bot message, the page, and the
EIP-681 string. That check is only meaningful if all three render the number the
same way; a float in one of them makes "identical" ambiguous.

**What is deliberately absent.** No ``user_id``, no ``product_id``, no
``derivation_index``, no ``hd_account_id``, no ``integrity_mac``. The public
page is reachable by anyone holding the token (TZ 5.8/T1.7), so its payload is
scoped to what the payer needs in order to pay: where, how much, how it is
going, how long is left. ``derivation_index`` in particular would leak issuance
volume — the revenue disclosure of T1 vector 5 — from a page with no login.
"""

from __future__ import annotations

import datetime as dt
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from api.repository import InvoiceProgress
from api.stages import Stage, stage_of

__all__ = [
    "PaymentOut",
    "StatusOut",
    "InvoiceOut",
    "HealthOut",
    "ErrorOut",
]


def _raw(amount: Decimal) -> str:
    """Base units as a plain integer string — never ``1E+7``.

    Same hazard :func:`core.invoicing.eip681._amount_literal` guards against:
    psycopg hands back a ``Decimal`` whose ``str()`` may carry an exponent, and
    a page showing ``1E+7`` next to a QR containing ``10000000`` has broken the
    one comparison the buyer can actually perform.
    """
    return format(int(amount), "d")


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PaymentOut(_Model):
    """One incoming transfer. ``tx_hash`` is here so the buyer can go and look."""

    tx_hash: str
    amount_raw: str
    status: str
    confirmations: int
    anomaly: str | None = None


class StatusOut(_Model):
    """The polled half: everything that changes while the page is open.

    Split from :class:`InvoiceOut` because the halves have different lifetimes.
    The address, the amount and the EIP-681 string are fixed for the life of the
    invoice and are verified reads (a MAC check each time); the status changes
    every block and is polled every couple of seconds. Serving them together
    would mean re-verifying an unchanging address hundreds of times per page
    view, and — worse — shipping the address down a frequently-polled channel
    that the script then has to decide whether to re-render from.

    The address is **not** in this payload for that second reason. It is
    rendered once, from :class:`InvoiceOut`, and the page script never rewrites
    it. That is the browser-side counterpart of TZ 5.8/T1.5, where the bot never
    edits a message containing an address.
    """

    stage: Stage
    #: ``invoices.status`` as the settler wrote it, alongside the derived
    #: :attr:`stage`. Both, because the stage is a lossy summary and an operator
    #: reading a support screenshot needs the real one.
    invoice_status: str
    amount_due_raw: str
    amount_paid_raw: str
    amount_outstanding_raw: str
    #: ``None`` when nothing is pending confirmation. The page shows the N/M
    #: line only when this is set (TZ 3.2's second rung).
    confirmations: int | None = None
    required_confirmations: int
    expires_at: dt.datetime
    topup_window_until: dt.datetime
    #: Whole seconds until :attr:`expires_at`, floored at zero. Sent as well as
    #: the timestamp so the countdown does not depend on the buyer's device
    #: clock being right — a phone an hour fast would otherwise show an invoice
    #: as expired while it is still payable.
    seconds_until_expiry: int
    access_granted: bool
    payments: tuple[PaymentOut, ...] = ()

    @classmethod
    def of(cls, progress: InvoiceProgress, *, now: dt.datetime) -> StatusOut:
        remaining = int((progress.expires_at - now).total_seconds())
        return cls(
            stage=stage_of(progress),
            invoice_status=progress.status,
            amount_due_raw=_raw(progress.amount_due_raw),
            amount_paid_raw=_raw(progress.amount_paid_raw),
            amount_outstanding_raw=_raw(progress.amount_outstanding_raw),
            confirmations=progress.confirmations,
            required_confirmations=progress.required_confirmations,
            expires_at=progress.expires_at,
            topup_window_until=progress.topup_window_until,
            seconds_until_expiry=max(0, remaining),
            access_granted=progress.access_granted,
            payments=tuple(
                PaymentOut(
                    tx_hash=p.tx_hash,
                    amount_raw=_raw(p.amount_raw),
                    status=p.status,
                    confirmations=p.confirmations,
                    anomaly=p.anomaly,
                )
                for p in progress.payments
            ),
        )


class InvoiceOut(_Model):
    """The fixed half: what to pay, where, and the one string the QR is built from."""

    #: Present so a buyer can quote it to support. It is a UUIDv7 and therefore
    #: not enumerable (TZ 5.8/T1.7), and knowing it grants nothing on its own —
    #: every authenticated read filters by ``user_id`` as well.
    invoice_id: str
    chain_id: int
    asset_symbol: str
    asset_decimals: int
    address: str
    amount_due_raw: str
    #: Human-readable amount, derived from ``amount_due_raw`` and ``decimals``
    #: on the server so the page never does decimal arithmetic in JavaScript,
    #: where it would be floating point.
    amount_due_display: str
    amount_due_usd: str
    #: **The** EIP-681 string (TZ 3.2, 5.8/T1.4). The QR is drawn from this in
    #: the browser and this same text is shown beside it. One point of truth —
    #: which is why the server sends a string and never an image.
    eip681: str
    status: StatusOut

    @classmethod
    def of(
        cls,
        view: object,
        progress: InvoiceProgress,
        *,
        now: dt.datetime,
    ) -> InvoiceOut:
        """Built from a verified :class:`~core.invoicing.service.InvoiceView`.

        Typed ``object`` rather than ``InvoiceView`` only to keep this module
        free of an import cycle through :mod:`api.repository`; the caller in
        :mod:`api.routes` has the real type and mypy checks it there.
        """
        from core.invoicing.service import InvoiceView

        assert isinstance(view, InvoiceView)
        return cls(
            invoice_id=str(view.invoice_id),
            chain_id=view.chain_id,
            asset_symbol=view.asset_symbol,
            asset_decimals=view.asset_decimals,
            address=view.address,
            amount_due_raw=_raw(view.amount_due_raw),
            amount_due_display=_display(view.amount_due_raw, view.asset_decimals),
            amount_due_usd=format(view.amount_due_usd, "f"),
            # Never stored, always recomputed from the verified view — see
            # InvoiceView.eip681 for why that is the point.
            eip681=view.eip681(),
            status=StatusOut.of(progress, now=now),
        )


def _display(amount_raw: Decimal, decimals: int) -> str:
    """Base units -> a human amount, exactly, with trailing zeros trimmed.

    Exact because it is ``Decimal`` scaling and not division by a float, and
    trimmed because ``10.000000 USDC`` reads like a placeholder while
    ``10 USDC`` reads like a price. The untrimmed base-unit figure is still in
    the payload beside it for anyone reconciling against the chain.
    """
    scaled = Decimal(amount_raw).scaleb(-decimals)
    text = format(scaled, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


class HealthOut(_Model):
    """``/healthz``. Reports posture, never configuration (TZ 5.1)."""

    status: str
    database: str
    #: ``"derivation"`` or ``"mac-only"`` — which T1 checks this process can
    #: run. A deploy that expected a verifying deriver and got neither can be
    #: caught by a probe instead of by a buyer.
    address_verification: str
    #: Whether ``initData`` endpoints are available. Not *what* the secret is.
    telegram_auth: str


class ErrorOut(_Model):
    """The only error shape. ``detail`` is buyer-safe text, never ``str(exc)``.

    :mod:`core.invoicing.errors` draws exactly this line and explains it: the
    operator detail names limits, ids and counts and belongs in the log, while
    ``user_message`` is a sentence that can be rendered as-is. Handlers in
    :mod:`api.routes` are the enforcement point.
    """

    detail: str = Field(description="Safe to show to the person who made the request.")
