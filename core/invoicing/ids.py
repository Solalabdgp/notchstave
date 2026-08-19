"""UUIDv7 invoice ids and the unguessable public token.

TZ 6 and 5.8/T1.7: ``id`` is a UUIDv7, *not* a serial, "защита от перебора".

**Why the standard library is not used.** ``uuid.uuid7()`` landed in CPython
3.14; this project targets 3.12 (``requires-python = ">=3.12"``), so it is
implemented here from RFC 9562 §5.7 rather than pulled in as a dependency for
sixteen bytes of bit-twiddling. The layout, most significant bit first:

    48 bits   unix_ts_ms       big-endian milliseconds since the epoch
     4 bits   version          0b0111
    12 bits   rand_a           random
     2 bits   variant          0b10
    62 bits   rand_b           random

**What a UUIDv7 does and does not buy.** It stops enumeration — the thing TZ
5.8/T1.7 asks for — because 74 random bits sit between any two ids. It does not
make an id *secret*: the timestamp is right there in the first six bytes, so a
leaked id reveals when the invoice was created. That is why the public invoice
page is keyed by :func:`public_token` and not by the id, and why every status
lookup is additionally filtered by the authenticated ``user_id`` rather than
trusting the id to be unguessable on its own. The two mechanisms answer two
different questions and neither replaces the other.

Ordering: because the high 48 bits are time, ids from the same millisecond sort
together and ids from different milliseconds sort correctly. That keeps B-tree
inserts local instead of scattering them the way UUIDv4 does — a real cost on
the primary key of the busiest money table, and the reason RFC 9562 defines v7
at all.
"""

from __future__ import annotations

import datetime as dt
import secrets
import uuid

__all__ = ["uuid7", "public_token"]

_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.UTC)


def uuid7(now: dt.datetime | None = None) -> uuid.UUID:
    """A fresh RFC 9562 UUIDv7.

    ``now`` is injectable so a test can pin the timestamp half and still get
    fresh randomness — the property worth testing is that two calls in the same
    millisecond differ, which cannot be shown if the clock is the only source of
    variation.
    """
    moment = dt.datetime.now(dt.UTC) if now is None else now
    if moment.tzinfo is None:
        raise ValueError("uuid7 needs a timezone-aware datetime")
    delta = moment.astimezone(dt.UTC) - _EPOCH
    unix_ts_ms = delta.days * 86_400_000 + delta.seconds * 1_000 + delta.microseconds // 1_000
    if not 0 <= unix_ts_ms < 1 << 48:
        raise ValueError(f"timestamp out of UUIDv7 range: {moment!r}")

    raw = bytearray(unix_ts_ms.to_bytes(6, "big") + secrets.token_bytes(10))
    # Version 7 in the high nibble of octet 6, keeping the 12 random bits below.
    raw[6] = 0x70 | (raw[6] & 0x0F)
    # RFC 4122/9562 variant 0b10 in the top two bits of octet 8.
    raw[8] = 0x80 | (raw[8] & 0x3F)
    return uuid.UUID(bytes=bytes(raw))


def public_token(nbytes: int) -> str:
    """URL-safe token for the public invoice page (TZ 5.8/T1.7).

    ``secrets.token_urlsafe`` and not ``uuid4().hex``: the token's only job is to
    be unguessable, and this is the standard library's CSPRNG-backed answer for
    exactly that. 32 bytes renders as 43 characters, which fits ``String(64)``.

    There is no TTL *in the token*. It is a bearer string with no structure to
    verify, so the expiry has to be a lookup against ``topup_window_until`` at
    read time — see :func:`core.invoicing.service.load_invoice_by_public_token`.
    Encoding a deadline into the token itself would need a second MAC and would
    still require the lookup, since a token for a cancelled invoice must stop
    working before its nominal deadline.
    """
    if nbytes < 16:
        raise ValueError("public_token needs at least 16 bytes of entropy")
    return secrets.token_urlsafe(nbytes)
