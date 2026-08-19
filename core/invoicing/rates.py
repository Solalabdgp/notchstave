"""The rate snapshot, and the one rounding decision in invoice pricing.

TZ 5.5, rate table: *"Курс фиксируется в момент создания инвойса
(``rate_snapshot``) и действует ``rate_locked_until``... Для USDC вопрос
вырожденный, для ETH — основной."* TZ 5.7 names the source: a public price API
inside its free tier, cached in Redis for 60 seconds, and *"Токен без цены не
ломает обработку: инвойс в USDC выставляется вообще без обращения к API
курсов."*

So this module deliberately contains **no HTTP client**. It defines the seam
(:class:`RateSource`) and ships the one implementation that needs no network —
:class:`PeggedRates`, which prices a dollar-pegged stablecoin at exactly 1.00
and refuses everything else. A CoinGecko-backed source is a small class the
api/bot process injects; keeping it out of ``core`` means the invoicing path can
be tested end to end with no network at all (TZ section 8: *"Никаких сетевых
вызовов в CI"*), and means a price-API outage cannot take USDC checkout down.

**Refusing is the only safe fallback.** There is no "use the last known rate"
branch, because ``rate_snapshot`` is binding for ``rate_locked_until`` — a
stale number does not produce a slightly wrong invoice, it produces an invoice
the buyer can pay at yesterday's price. :class:`~core.invoicing.errors
.RateUnavailable` is the whole error handling strategy.
"""

from __future__ import annotations

from decimal import ROUND_CEILING, Decimal, localcontext
from typing import Protocol

from core.invoicing.errors import RateUnavailable

__all__ = [
    "RateSource",
    "PeggedRates",
    "StaticRates",
    "PEGGED_SYMBOLS",
    "price_to_raw",
    "RATE_PRECISION",
]

#: Digits used for the price arithmetic. Not :data:`settler.amounts.RAW_PRECISION`
#: (80) because that one exists to add uint256 values exactly; here the inputs are
#: a 12,2 catalog price and a 38,18 rate, and 60 digits carries their product
#: past the 78-digit ``NUMERIC(78,0)`` ceiling without pretending precision is
#: free. What matters is only that the default 28-digit context is not silently
#: in charge — an 18-decimal token at a four-figure price overruns it.
RATE_PRECISION = 60

#: Symbols this project treats as exactly one US dollar. Deliberately a short,
#: explicit list rather than a "stablecoin" heuristic: TZ 12 makes accepted
#: assets an allow-list, and "the symbol ends in USD" is how a token called
#: ``USDX`` gets priced at a dollar.
PEGGED_SYMBOLS = frozenset({"USDC", "USDT", "DAI", "PYUSD"})


class RateSource(Protocol):
    """USD per one whole token, at the moment of invoice creation.

    ``chain_id`` is part of the question and not decoration: the same symbol on
    two networks is two different contracts, and a bridged asset that has
    depegged on one of them is exactly the case where answering from the symbol
    alone is wrong.
    """

    def quote(self, *, symbol: str, chain_id: int) -> Decimal: ...


class PeggedRates:
    """Dollar-pegged assets at 1.00, everything else refused. The default source.

    This is the honest v1 behaviour rather than a stub. TZ 2 makes USDC the
    primary asset and TZ 5.7 says a USDC invoice is issued without touching a
    price API at all; treating the peg as 1.00 is what that sentence means. An
    ETH invoice under this source fails loudly at creation, before an address is
    spent, which is the correct outcome when no price feed is wired.
    """

    def __init__(self, symbols: frozenset[str] = PEGGED_SYMBOLS) -> None:
        self._symbols = symbols

    def quote(self, *, symbol: str, chain_id: int) -> Decimal:
        if symbol.upper() in self._symbols:
            return Decimal(1)
        raise RateUnavailable(
            f"no price source configured for {symbol} on chain {chain_id}; "
            "only dollar-pegged assets are priced without a rate API (TZ 5.7)"
        )


class StaticRates:
    """A fixed table. For tests and for a deliberately pinned deployment."""

    def __init__(self, rates: dict[str, Decimal]) -> None:
        self._rates = {k.upper(): Decimal(v) for k, v in rates.items()}

    def quote(self, *, symbol: str, chain_id: int) -> Decimal:
        try:
            rate = self._rates[symbol.upper()]
        except KeyError:
            raise RateUnavailable(
                f"no static rate for {symbol} on chain {chain_id}"
            ) from None
        if rate <= 0:
            raise RateUnavailable(f"static rate for {symbol} is not positive: {rate!r}")
        return rate


def price_to_raw(price_usd: Decimal, *, decimals: int, rate: Decimal) -> Decimal:
    """Catalog price in USD -> base units of the payment asset, rounded **up**.

    The rounding direction is the interesting part, and it is the opposite of
    :func:`settler.amounts.usd_to_raw`. That function converts *tolerances*, and
    rounding a tolerance down can only make the system stricter with itself.
    This one converts the *bill*, where rounding down has two distinct costs:

    * the product is sold below its catalog price, by up to one base unit — a
      rounding error on USDC, real money on a token with few decimals;
    * worse, an invoice for a price that does not land on a whole base unit
      would be *overpaid* by anyone paying the true price, which routes a
      perfectly normal payment through the overpayment branch of TZ 5.5.

    One base unit up is invisible to the buyer (a millionth of a cent on USDC)
    and keeps the bill exactly payable. ``ROUND_CEILING`` and not ``ROUND_UP``
    because the amount is always positive here and ceiling says what is meant.
    """
    if rate <= 0:
        raise ValueError(f"rate must be positive, got {rate!r}")
    if price_usd <= 0:
        raise ValueError(f"price_usd must be positive, got {price_usd!r}")
    if decimals < 0:
        raise ValueError(f"decimals must not be negative, got {decimals!r}")

    with localcontext() as ctx:
        ctx.prec = RATE_PRECISION
        raw = (price_usd / rate) * (Decimal(10) ** decimals)
        return raw.to_integral_value(rounding=ROUND_CEILING)
