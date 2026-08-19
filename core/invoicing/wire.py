"""The on-the-wire form of an :class:`~core.invoicing.service.InvoiceView`.

An invoice is issued in the deriver process (migration 0006) and rendered in
``bot``/``api``, so it has to cross a process boundary as JSON in
``invoice_requests.result_json``. This module is the only place that encoding
exists, in both directions, which is the point: an encoder and a decoder written
in two files drift, and the field they drift on will be an amount or an address.

**Every number is a string.** ``amount_due_raw`` is ``NUMERIC(78,0)`` — up to
78 digits, which is roughly 2^259, well past the 2^53 where JSON numbers stop
being exact in every parser that treats them as doubles. ``rate_snapshot`` and
``amount_due_usd`` are exact decimals whose scale is part of their meaning, and
``json.dumps(Decimal('10.00'))`` is not even legal without a custom encoder that
would have to make the same choice. So: decimals go as their canonical string
and come back through :class:`~decimal.Decimal`, and the round trip is exact
rather than nearly exact.

**Timestamps are ISO-8601 with an offset**, which ``datetime.fromisoformat``
parses back to the same aware instant including microseconds. That precision is
not cosmetic: ``expires_at`` is one of the six fields under ``integrity_mac``,
and the MAC is computed over microseconds since the epoch
(:mod:`core.invoicing.integrity`). A representation that rounded to the second
would produce a view whose MAC cannot verify — which the client would correctly
report as tampering.

**``integrity_mac`` travels as hex, and it is what makes this transport safe.**
The reply carries the address the buyer will be shown, through a table, into a
process that has no xpub and therefore cannot re-derive it (TZ 5.3 wants a check
before any address reaches a human). :func:`from_wire` is not that check — it is
a decoder — but it is the input to it: ``core.invoicing.client`` recomputes the
MAC over the decoded view before returning it, so an attacker holding UPDATE on
``invoice_requests`` and not ``INVOICE_INTEGRITY_KEY`` can break a reply and
cannot rewrite one (TZ 5.8/T1.3).
"""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal
from typing import Any

from core.invoicing.service import InvoiceView

__all__ = ["WIRE_VERSION", "to_wire", "from_wire", "WireFormatError"]

#: Bumped whenever a field is added, removed or re-encoded. Checked on the way
#: in, so a deriver and a bot on different deploys refuse to misread each other
#: instead of silently reading a missing field as ``None``. Rolling deploys make
#: that a real state, not a hypothetical one.
WIRE_VERSION = 1


class WireFormatError(ValueError):
    """A reply that is not this format. Never a partial decode."""


def to_wire(view: InvoiceView) -> dict[str, Any]:
    """Encode a verified view. Never called on an unverified one — there are none."""
    return {
        "v": WIRE_VERSION,
        "invoice_id": str(view.invoice_id),
        "public_token": view.public_token,
        "user_id": view.user_id,
        "product_id": view.product_id,
        "chain_id": view.chain_id,
        "asset_id": view.asset_id,
        "address_id": view.address_id,
        "address": view.address,
        "hd_account_id": view.hd_account_id,
        "derivation_index": view.derivation_index,
        "amount_due_raw": str(view.amount_due_raw),
        "amount_due_usd": str(view.amount_due_usd),
        "rate_snapshot": str(view.rate_snapshot),
        "rate_locked_until": view.rate_locked_until.isoformat(),
        "status": view.status,
        "expires_at": view.expires_at.isoformat(),
        "topup_window_until": view.topup_window_until.isoformat(),
        "created_at": view.created_at.isoformat(),
        "integrity_mac": view.integrity_mac.hex(),
        "policy_version": view.policy_version,
        "asset_symbol": view.asset_symbol,
        "asset_decimals": view.asset_decimals,
        "asset_contract": view.asset_contract,
        "asset_is_native": view.asset_is_native,
        "newly_derived": view.newly_derived,
    }


def _moment(payload: dict[str, Any], field: str) -> dt.datetime:
    value = dt.datetime.fromisoformat(str(payload[field]))
    if value.tzinfo is None:
        # Everything in this schema is `timestamptz` and psycopg hands back aware
        # datetimes, so a naive one means the value did not come from the
        # database. Guessing UTC here is how an invoice acquires a MAC over an
        # instant an hour away from its own `expires_at`.
        raise WireFormatError(f"{field} must carry a UTC offset")
    return value


def from_wire(payload: dict[str, Any]) -> InvoiceView:
    """Decode a reply. Raises :class:`WireFormatError` rather than guessing.

    A missing or unreadable field is an error and not a default. The alternative
    — a view with a zero amount or a ``None`` address because a key was spelled
    differently on the other side of a rolling deploy — is a bug that reaches a
    buyer looking like a product.
    """
    try:
        version = int(payload["v"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WireFormatError("reply carries no wire version") from exc
    if version != WIRE_VERSION:
        raise WireFormatError(f"reply is wire v{version}, this build speaks v{WIRE_VERSION}")

    try:
        return InvoiceView(
            invoice_id=uuid.UUID(str(payload["invoice_id"])),
            public_token=str(payload["public_token"]),
            user_id=int(payload["user_id"]),
            product_id=int(payload["product_id"]),
            chain_id=int(payload["chain_id"]),
            asset_id=int(payload["asset_id"]),
            address_id=int(payload["address_id"]),
            address=str(payload["address"]),
            hd_account_id=int(payload["hd_account_id"]),
            derivation_index=int(payload["derivation_index"]),
            amount_due_raw=Decimal(str(payload["amount_due_raw"])),
            amount_due_usd=Decimal(str(payload["amount_due_usd"])),
            rate_snapshot=Decimal(str(payload["rate_snapshot"])),
            rate_locked_until=_moment(payload, "rate_locked_until"),
            status=str(payload["status"]),
            expires_at=_moment(payload, "expires_at"),
            topup_window_until=_moment(payload, "topup_window_until"),
            created_at=_moment(payload, "created_at"),
            integrity_mac=bytes.fromhex(str(payload["integrity_mac"])),
            policy_version=str(payload["policy_version"]),
            asset_symbol=str(payload["asset_symbol"]),
            asset_decimals=int(payload["asset_decimals"]),
            asset_contract=None
            if payload["asset_contract"] is None
            else str(payload["asset_contract"]),
            asset_is_native=bool(payload["asset_is_native"]),
            newly_derived=bool(payload["newly_derived"]),
        )
    except WireFormatError:
        raise
    except (KeyError, TypeError, ValueError, ArithmeticError) as exc:
        raise WireFormatError(f"malformed invoice reply: {exc}") from exc
