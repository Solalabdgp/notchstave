"""``integrity_mac``: the HMAC that makes a database-only compromise loud.

TZ 5.8/T1.3, verbatim::

    integrity_mac = HMAC-SHA256(INVOICE_INTEGRITY_KEY,
                                invoice_id || chain_id || asset_id ||
                                address || amount_due_raw || expires_at)

Key from systemd credentials, **never** stored in the database. The boundary of
the measure is stated in the TZ and is repeated here rather than softened: this
does not protect against full host compromise, where the attacker gets the key
too. It protects against the most likely and cheapest-to-close class — a leaked
replica, a stolen backup with write access, a forgotten port forward, a
contractor's SQL session. In that world an attacker can rewrite
``invoices.address`` or ``amount_due_raw`` and cannot produce a matching MAC.

----

**Why ``||`` is not string concatenation here.**

Written naively, ``str(chain_id) + str(asset_id) + address + ...`` is ambiguous:
``chain_id=1, asset_id=23`` and ``chain_id=12, asset_id=3`` serialise to the
same bytes. A MAC over an ambiguous encoding authenticates the *bytes*, not the
*tuple*, so an attacker who can move a digit across a field boundary keeps a
valid MAC. That is a canonicalisation bug and it has sunk real signature
schemes; the fix costs four bytes per field.

So every field is length-prefixed (4-byte big-endian) into
:func:`canonical_payload`, and the whole thing is prefixed with a domain-
separation tag. The tag carries a version number: changing the encoding later
means bumping ``v1`` to ``v2``, which invalidates every stored MAC at once and
visibly — rather than silently making old and new invoices verify under subtly
different rules.

**Normalisation, and why each choice is the one that survives a round trip.**

* ``invoice_id`` — the 16 raw UUID bytes, not its hyphenated text. One
  representation, no case question.
* ``chain_id`` / ``asset_id`` — decimal, no padding.
* ``address`` — the exact string stored in ``receive_addresses.address``, in
  EIP-55 mixed case. Not lowercased: this is the string the buyer is shown, and
  the MAC's job is to authenticate what is shown. A lowercased copy of the same
  address is a *different* value that ``deriver.verify`` would still accept
  (comparison there is case-insensitive by design) — so leaving the case out of
  the MAC would leave a gap exactly where the two checks overlap.
* ``amount_due_raw`` — the integer, formatted with no exponent. ``NUMERIC(78,0)``
  comes back as a ``Decimal`` which may render as ``1E+7`` after arithmetic;
  ``Decimal('1E+7')`` and ``Decimal('10000000')`` are equal numbers and
  different strings, and only one of them can be the MAC input.
* ``expires_at`` — integer microseconds since the Unix epoch, UTC. Not ISO-8601:
  ``timestamptz`` renders in the session's ``TimeZone`` setting, so an ISO string
  computed on a server set to ``Europe/Moscow`` and re-checked on one set to
  ``UTC`` would differ while naming the same instant. Microseconds is also
  exactly the resolution PostgreSQL stores, so nothing is truncated on the way
  back in.
"""

from __future__ import annotations

import datetime as dt
import hmac
import os
import uuid
from decimal import Decimal
from pathlib import Path

__all__ = [
    "IntegrityKey",
    "CREDENTIAL_NAME",
    "DOMAIN_TAG",
    "canonical_payload",
    "compute_mac",
    "verify_mac",
    "load_integrity_key",
]

#: ``LoadCredential=notchstave-invoice-integrity-key:...`` on the units that
#: issue or display invoices. Deliberately *not* on notchstave-deriver in the
#: original Week 1 layout — see the note in :func:`load_integrity_key`.
CREDENTIAL_NAME = "notchstave-invoice-integrity-key"

#: Domain separation + encoding version. Present so that this MAC can never be
#: confused with the admin confirmation MAC of :mod:`settler.admin.twostep`,
#: which is computed with a different key over a different tuple but with the
#: same primitive.
DOMAIN_TAG = b"notchstave/invoice-integrity/v1"

_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.UTC)


class IntegrityKey:
    """Key material with a ``__repr__`` that cannot leak it.

    Same discipline as :class:`deriver.service.Deriver` and
    :class:`settler.admin.twostep.ConfirmationKey`, and for the same reason
    (TZ 5.8/T4): the concrete failure this prevents is a key appearing in a
    pytest assertion diff, a ``repr(settings)`` dump at startup, or a Sentry
    breadcrumb. The bytes live in one name-mangled slot and every accessor that
    could print them is overridden.
    """

    __slots__ = ("__key",)

    def __init__(self, key: bytes | str) -> None:
        raw = key.encode("utf-8") if isinstance(key, str) else key
        if len(raw) < 16:
            # HMAC accepts any length; a 4-byte key is still a valid HMAC and a
            # worthless one. Refuse at construction rather than let a
            # placeholder from a half-filled .env become production config.
            raise ValueError(
                "INVOICE_INTEGRITY_KEY must be at least 16 bytes; "
                f"got {len(raw)} (TZ 5.8/T1.3)"
            )
        self.__key = raw

    def __repr__(self) -> str:
        return f"<IntegrityKey {len(self.__key)} bytes, redacted>"

    __str__ = __repr__

    def mac(self, payload: bytes) -> bytes:
        """32 raw bytes, matching ``octet_length(integrity_mac) = 32`` in 0001."""
        return hmac.new(self.__key, payload, "sha256").digest()

    def verify(self, payload: bytes, expected: bytes) -> bool:
        """Constant-time comparison.

        ``hmac.compare_digest`` and not ``==``: the timing signal from a
        short-circuiting byte comparison is small but the cost of removing it is
        zero, and this function is reachable by anyone who can request an
        invoice page.
        """
        return hmac.compare_digest(self.mac(payload), expected)


def load_integrity_key(
    credentials_dir: str | os.PathLike[str] | None = None,
    *,
    env: dict[str, str] | None = None,
) -> IntegrityKey:
    """Read the key from systemd credentials, falling back to the env for dev.

    Order, and why it is this way round: the credentials directory wins whenever
    it is present, so a correctly configured production unit cannot be
    downgraded by a stray ``INVOICE_INTEGRITY_KEY`` in the environment. The
    environment path exists because ``.env.example`` documents it for local dev
    and because refusing to start without systemd would make the whole repo
    un-runnable on a laptop — but it is second, and the docstring of
    ``.env.example`` says the same thing.

    Raises rather than generating a random key when neither source is present.
    A generated key would make every previously issued invoice fail its MAC
    check on the next restart, which reads as a mass compromise event.
    """
    src = os.environ if env is None else env
    raw_dir = credentials_dir or src.get("CREDENTIALS_DIRECTORY")

    if raw_dir:
        candidate = Path(raw_dir) / CREDENTIAL_NAME
        if candidate.is_file():
            # `.rstrip` and not `.strip`: leading whitespace in a credential file
            # is content, trailing newline is an editor artefact.
            return IntegrityKey(candidate.read_bytes().rstrip(b"\r\n"))

    from_env = src.get("INVOICE_INTEGRITY_KEY")
    if from_env:
        return IntegrityKey(from_env)

    raise RuntimeError(
        f"no invoice integrity key: expected {CREDENTIAL_NAME} in "
        "$CREDENTIALS_DIRECTORY (production) or INVOICE_INTEGRITY_KEY in the "
        "environment (local dev only). Refusing to invent one — a fresh key "
        "would fail the MAC on every invoice already issued (TZ 5.8/T1.3)."
    )


def _framed(*fields: bytes) -> bytes:
    """Length-prefix each field so no two tuples share an encoding."""
    out = bytearray(DOMAIN_TAG)
    for field in fields:
        out += len(field).to_bytes(4, "big")
        out += field
    return bytes(out)


def _amount_bytes(amount_due_raw: Decimal | int) -> bytes:
    """Canonical decimal integer, exponent notation removed."""
    value = Decimal(amount_due_raw)
    if value != value.to_integral_value():
        raise ValueError(f"amount_due_raw must be a whole number of base units, got {value!r}")
    # `int()` normalises 1E+7 and 10000000 to the same object; `format(..., 'd')`
    # then renders it without a sign for positives and without separators.
    return format(int(value), "d").encode("ascii")


def _instant_bytes(moment: dt.datetime) -> bytes:
    """Microseconds since the epoch, UTC.

    A naive datetime is rejected rather than assumed to be UTC. Everything in
    this schema is ``timestamptz`` and psycopg returns aware datetimes; a naive
    one here means the value came from somewhere else, and guessing its zone is
    how an invoice ends up with a MAC over an instant an hour away from its
    ``expires_at``.
    """
    if moment.tzinfo is None:
        raise ValueError("expires_at must be timezone-aware")
    delta = moment.astimezone(dt.UTC) - _EPOCH
    micros = delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds
    return format(micros, "d").encode("ascii")


def canonical_payload(
    *,
    invoice_id: uuid.UUID,
    chain_id: int,
    asset_id: int,
    address: str,
    amount_due_raw: Decimal | int,
    expires_at: dt.datetime,
) -> bytes:
    """The exact bytes the MAC is taken over. TZ 5.8/T1.3's tuple, unambiguously.

    Keyword-only on purpose. The tuple is six values of which four are integers
    or integer-like, and a positional call site that transposes ``chain_id`` and
    ``asset_id`` would produce MACs that verify perfectly against each other and
    authenticate the wrong invoice.
    """
    return _framed(
        invoice_id.bytes,
        format(int(chain_id), "d").encode("ascii"),
        format(int(asset_id), "d").encode("ascii"),
        address.encode("utf-8"),
        _amount_bytes(amount_due_raw),
        _instant_bytes(expires_at),
    )


def compute_mac(
    key: IntegrityKey,
    *,
    invoice_id: uuid.UUID,
    chain_id: int,
    asset_id: int,
    address: str,
    amount_due_raw: Decimal | int,
    expires_at: dt.datetime,
) -> bytes:
    """Convenience wrapper: canonicalise, then MAC."""
    return key.mac(
        canonical_payload(
            invoice_id=invoice_id,
            chain_id=chain_id,
            asset_id=asset_id,
            address=address,
            amount_due_raw=amount_due_raw,
            expires_at=expires_at,
        )
    )


def verify_mac(
    key: IntegrityKey,
    expected: bytes,
    *,
    invoice_id: uuid.UUID,
    chain_id: int,
    asset_id: int,
    address: str,
    amount_due_raw: Decimal | int,
    expires_at: dt.datetime,
) -> bool:
    """Recompute and compare in constant time. Never raises on a mismatch.

    Returning ``False`` rather than raising mirrors
    :meth:`deriver.service.Deriver.verify` and exists for the same reason: a
    caller must not be able to conflate "the MAC did not match" with "the
    question was malformed". Malformed input still raises, out of
    :func:`canonical_payload`.
    """
    return key.verify(
        canonical_payload(
            invoice_id=invoice_id,
            chain_id=chain_id,
            asset_id=asset_id,
            address=address,
            amount_due_raw=amount_due_raw,
            expires_at=expires_at,
        ),
        expected,
    )
