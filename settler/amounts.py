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

from collections.abc import Iterable
from decimal import ROUND_FLOOR, Decimal, localcontext

__all__ = ["raw_to_usd", "usd_to_raw", "whole_units", "sum_raw", "RAW_PRECISION"]

#: Digits of precision needed to add base-unit amounts without silent rounding.
#:
#: This is not a tuning knob, it is a correctness requirement, and it was found
#: by a test rather than by reading the docs. Python's default decimal context
#: carries **28** significant digits; ``2**256 - 1`` has **78**, and the schema
#: stores amounts as ``NUMERIC(78, 0)`` for exactly that reason. Adding two large
#: ``Decimal`` values under the default context therefore returns a *rounded*
#: result — silently, with no exception — so a sweep total over addresses holding
#: a token with 18 decimals loses its low digits, and the CSV the owner signs
#: from is wrong in a way nothing downstream can detect.
#:
#: Eighty leaves headroom over the 78-digit maximum without pretending arbitrary
#: precision is free.
RAW_PRECISION = 80


def sum_raw(values: Iterable[Decimal]) -> Decimal:
    """Add base-unit amounts exactly, whatever the ambient decimal context.

    Use this and not the builtin ``sum`` anywhere the addends are ``amount_raw``
    values. ``sum`` is not wrong in itself — it is wrong because it inherits
    whichever context happens to be installed, and the default one truncates a
    uint256 to its first 28 digits.

    The context is entered locally rather than set process-wide: a global
    ``setcontext`` would change the behaviour of every ``Decimal`` in whatever
    process imports this module, including the USD arithmetic that deliberately
    rounds, and a money module that reaches out and changes arithmetic for
    everyone else is worse than the bug it fixes.
    """
    with localcontext() as ctx:
        ctx.prec = RAW_PRECISION
        total = Decimal(0)
        for value in values:
            total += value
        return total


def whole_units(raw: Decimal, decimals: int) -> Decimal:
    """Base units -> whole tokens (1_500_000 with 6 decimals -> ``1.5``).

    Evaluated under :data:`RAW_PRECISION` for the same reason :func:`sum_raw`
    is. Dividing by a power of ten is an exact operation given enough digits and
    a silently truncating one without them: under the default 28-digit context a
    balance of ``2**200`` base units on an 18-decimal token comes back with its
    tail replaced by zeros, which is the number that would then be printed in the
    human-readable column of a `/sweeplist` CSV.
    """
    with localcontext() as ctx:
        ctx.prec = RAW_PRECISION
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
