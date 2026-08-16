"""Conversions between raw base units and USD.

Two rules hold everywhere in this package.

**Raw is the source of truth.** On-chain amounts live in base units
(``NUMERIC(78, 0)``, see ``core.db.base.AMOUNT_RAW``) and every comparison that
decides whether a bill is settled happens in raw units. USD only ever enters as
a *threshold* — "one dollar of slack", "twenty dollars above which we wait for
finality" — and is converted into raw before the comparison. Comparing in USD
would make the outcome depend on rounding of a price quote.

**The rate is the invoice's own snapshot, never a live quote.** ``invoices
.rate_snapshot`` is frozen at creation (TZ 5.5, rate table). Re-pricing a
tolerance against today's rate would mean the same payment is settled or not
depending on when the settler happened to run.

Rounding is stated explicitly at every call site rather than left to the
default context: a tolerance that rounds *up* hands out product for free, and a
shortfall that rounds *down* nags a customer over a rounding error.
"""

from __future__ import annotations

from decimal import ROUND_FLOOR, Decimal

__all__ = ["raw_to_usd", "usd_to_raw", "whole_units"]


def whole_units(raw: Decimal, decimals: int) -> Decimal:
    """Base units -> whole tokens (1_500_000 with 6 decimals -> ``1.5``)."""
    return Decimal(raw) / (Decimal(10) ** decimals)


def raw_to_usd(raw: Decimal, decimals: int, rate: Decimal) -> Decimal:
    """Base units -> USD at ``rate`` (USD per one whole token).

    Used for *reporting* and for the threshold comparisons of TZ 5.4
    (``credit_threshold_usd``). Not used to decide whether an invoice is
    covered — that comparison stays in raw units.
    """
    return whole_units(raw, decimals) * rate


def usd_to_raw(usd: Decimal, decimals: int, rate: Decimal) -> Decimal:
    """USD -> base units, rounded **down** to a whole base unit.

    Rounding down is the safe direction for every current caller, because every
    current caller converts a *tolerance*: a smaller tolerance can only make the
    system stricter with itself, never more generous with the buyer's money.

    ``rate`` of zero would mean an asset without a price; the caller must have
    rejected that at invoice creation (``ck_invoices_rate_snapshot_positive``),
    so this raises rather than silently returning an infinite tolerance.
    """
    if rate <= 0:
        raise ValueError(f"rate must be positive, got {rate!r}")
    return ((usd / rate) * (Decimal(10) ** decimals)).to_integral_value(rounding=ROUND_FLOOR)
