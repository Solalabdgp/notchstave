"""Turning exact values into strings a human reads and a wallet can accept.

Three rules, all of them from the TZ rather than from taste.

**Amounts are formatted from base units and never from a float.** Every amount
in this system is ``NUMERIC(78,0)`` base units — 12500000 rather than 12.5 —
and the conversion needs the asset's ``decimals``. Doing it with
:class:`~decimal.Decimal` and a scale shift keeps it exact; doing it with a
float would put a rounded number in front of somebody who is about to type it
into a wallet. :mod:`notifier.render` prints raw units today precisely because
it has no ``decimals`` in its payload; here the bot does, so here is where the
honest human form appears (TZ 3.1).

**The address and the amount go out in a monospaced block.** TZ 3.1: *"сумма и
адрес выводятся в сообщении в машинно-копируемом виде (моноширинный блок), адрес
— в EIP-55 checksum-регистре"*. ``<code>`` is what makes a Telegram client offer
tap-to-copy, and copy-paste is the difference between an address typed correctly
and a payment nobody can find.

**Everything that came from outside is escaped.** A product title, a sku typed
into a chat, an error message: all of it lands in HTML. ``&`` in a title is not
an attack, it is a Tuesday, and an unescaped one silently truncates the message
at the client. The escaping is applied at the formatting boundary rather than at
the data boundary so that there is one place to look for it.
"""

from __future__ import annotations

import datetime as dt
import html
from decimal import Decimal

__all__ = [
    "esc",
    "code",
    "whole_units",
    "format_amount",
    "format_usd",
    "format_deadline",
    "humanise_duration",
]


def esc(value: object) -> str:
    """HTML-escape anything on its way into a message."""
    return html.escape(str(value), quote=False)


def code(value: object) -> str:
    """A monospaced, tap-to-copy block (TZ 3.1)."""
    return f"<code>{esc(value)}</code>"


def whole_units(raw: Decimal, decimals: int) -> Decimal:
    """Base units to whole tokens, exactly and at any magnitude.

    Rebuilt from the digit tuple rather than computed, and the reason is that
    both obvious computations are wrong in the same quiet way. Dividing by
    ``10 ** decimals`` rounds to the active :class:`~decimal.Context`'s
    precision — 28 significant digits by default. So does ``scaleb``, despite
    reading like a pure exponent shift: it is an arithmetic operation and
    ``Decimal(10**30 + 1).scaleb(-18)`` comes back as
    ``1000000000000.00000000000000000`` with the low digit gone.

    ``amount_due_raw`` is ``NUMERIC(78,0)``. A token with 18 decimals therefore
    reaches 28 significant digits at around ten billion whole units, which is
    inside the range of a cheap token, and the failure is silent: the number
    still looks like a number. Moving the exponent on the tuple touches no
    context at all, so there is no precision to get wrong and no
    ``localcontext`` for a future caller to forget.
    """
    sign, digits, exponent = Decimal(raw).as_tuple()
    if not isinstance(exponent, int):  # pragma: no cover - NaN/Infinity
        raise ValueError(f"not a finite amount: {raw!r}")
    return Decimal((sign, digits, exponent - decimals))


def format_amount(raw: Decimal, decimals: int, symbol: str) -> str:
    """``12500000, 6, "USDC"`` -> ``"12.5 USDC"``.

    Trailing zeros are trimmed but a whole number keeps no decimal point, so the
    string reads like a price rather than like a database column. The value is
    never rounded — trimming zeros cannot change a number, and anything that
    could is left long on purpose: a buyer comparing this against their wallet
    needs the digits to match.
    """
    value = whole_units(raw, decimals)
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return f"{text or '0'} {symbol}"


def format_usd(amount: Decimal) -> str:
    """Two decimal places, because that is what a price is."""
    return f"${amount:.2f}"


def humanise_duration(delta: dt.timedelta) -> str:
    """``"12 minutes"``, ``"1 hour 5 minutes"``, ``"less than a minute"``.

    Minute resolution and no seconds. An invoice lives fifteen minutes (TZ
    5.8/T5.4) and a countdown ticking in seconds inside a message that is never
    edited (T1.5) would be wrong the moment it was read; minutes are honest at
    the resolution the reader can act on.
    """
    seconds = int(delta.total_seconds())
    if seconds <= 0:
        return "expired"
    if seconds < 60:
        return "less than a minute"
    minutes, hours = (seconds // 60) % 60, seconds // 3600
    hour_part = f"{hours} hour{'s' if hours != 1 else ''}"
    minute_part = f"{minutes} minute{'s' if minutes != 1 else ''}"
    if hours and minutes:
        return f"{hour_part} {minute_part}"
    if hours:
        return hour_part
    return minute_part


def format_deadline(moment: dt.datetime, *, now: dt.datetime | None = None) -> str:
    """``"14:32 UTC (in 12 minutes)"``.

    Both halves, and neither is redundant. The absolute time survives the
    message being read an hour later — which is the normal case for a message
    that is never edited — and the relative one is what a person acts on right
    now. UTC is named rather than converted to the reader's zone: this process
    does not know the reader's zone, and quietly rendering a server's local time
    as though it were theirs is how a deadline is missed by an hour.
    """
    instant = dt.datetime.now(dt.UTC) if now is None else now
    absolute = moment.astimezone(dt.UTC).strftime("%H:%M UTC")
    return f"{absolute} (in {humanise_duration(moment - instant)})"
