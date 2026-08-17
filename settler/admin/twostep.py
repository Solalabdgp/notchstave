"""Two-step confirmation for a large manual credit (TZ 5.8/T7).

> "Порог на ручной зачёт. ``/resolve credit`` выше ``manual_credit_limit_usd``
> требует подтверждения вторым сообщением с кодом из первого. Дёшево, а
> автоматический перебор командой из угнанной сессии ломает."

The threat is narrow and so is the control. An attacker holding the owner's
Telegram session can send commands; what they cannot cheaply do is *read the
replies and act on them faster than the real owner notices*, because every admin
action also fires a notification into the same chat. Requiring a value that only
appears in the reply turns "fire ``/resolve credit`` at every open case" from one
scripted burst into an interactive session leaving a visible trail.

----

**The code is a keyed hash of the decision, not a stored nonce.**

Two designs were possible. A stored challenge (a row, or a Redis key) is the
obvious one and was rejected for three reasons: it needs a table this schema does
not have (TZ 6 is the contract) or a Redis that TZ 5.8/T2.4 insists the system
must be correct without; it introduces a cleanup job; and a challenge row is
itself a thing an attacker with database access can read.

So the code is ``HMAC-SHA256(key, canonical form of the decision ‖ time bucket)``
rendered in Base32. The properties that buys, in order of how much they matter:

* **It is bound to the exact decision.** ``review_id``, ``resolution``,
  ``invoice_id``, the amount and the operator all go into the MAC. A code the
  owner was legitimately given for one case cannot confirm a different case, a
  different amount, or a different operator. A stored nonce keyed only by
  ``review_id`` would not have this property, and "replay the confirmation
  against a bigger invoice" is precisely what a captured session would try.
* **It expires without a scheduler**, through a coarse time bucket. Both the
  current and the previous bucket verify, so the usable lifetime is between one
  and two TTLs — a code issued one second before a boundary is still good for
  five minutes, rather than being dead on arrival.
* **It is stateless**, so it survives a settler restart between the two messages
  and works identically across however many workers exist.

**The key is mandatory.** With no key there is no code, and
:class:`~settler.admin.errors.ConfirmationUnavailable` is raised — a large manual
credit becomes impossible rather than unconfirmed. A control that switches itself
off when its secret is missing is not a control.

**Comparison is constant-time** (:func:`hmac.compare_digest`). The attacker here
is remote and rate-limited by Telegram rather than by us, so a timing oracle is
not the likely path — but this is a six-character change and the alternative is
explaining, in a project about money, why the one string comparison that guards a
payout used ``==``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from decimal import Decimal

from settler.admin.errors import ConfirmationUnavailable, InvalidConfirmationCode

__all__ = [
    "ConfirmationKey",
    "CONFIRMATION_KEY_ENV",
    "confirmation_key_from_env",
    "issue_code",
    "verify_code",
]

CONFIRMATION_KEY_ENV = "NOTCHSTAVE_ADMIN_CONFIRMATION_KEY"

#: Crockford-ish Base32 minus the characters a human retypes wrongly. No 0/O, no
#: 1/I/L, no U (which turns short random strings into words nobody wants to read
#: aloud to their own bot).
_ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ"


@dataclass(frozen=True, slots=True, repr=False)
class ConfirmationKey:
    """The HMAC key, with a repr that cannot leak it.

    The same discipline :mod:`deriver.redaction` applies to extended keys, for
    the same reason: config objects end up in exception messages, in
    ``logging.exception`` tracebacks and in debug dumps, and a dataclass with a
    default repr is the standard way a secret escapes a process.
    """

    material: bytes

    #: ``repr=False`` on the decorator, not just an override below: a generated
    #: dataclass ``__repr__`` prints every field, and this one's only field is
    #: the key. Belt and braces, because the failure mode is a secret in a log.
    def __repr__(self) -> str:
        return "<ConfirmationKey redacted>"

    def __str__(self) -> str:
        return "<ConfirmationKey redacted>"


def confirmation_key_from_env(env: dict[str, str] | None = None) -> ConfirmationKey | None:
    """Read the key, or ``None`` when it is not configured.

    ``None`` rather than a generated random key: a per-process random key would
    "work" in a single-process deployment and then fail mysteriously the moment a
    second settler is started, with the failure looking like an expired code. An
    absent key must look absent.

    TZ section 9 — secrets go to the units that need them ("``LoadCredential=``
    ... ``INVOICE_INTEGRITY_KEY`` — только ``settler``, ``api``, ``bot``"). This
    one belongs to the settler alone, because the settler is what executes
    ``/resolve``; the bot only relays the code the owner typed.
    """
    src = os.environ if env is None else env
    raw = src.get(CONFIRMATION_KEY_ENV, "")
    if not raw:
        return None
    return ConfirmationKey(raw.encode("utf-8"))


def _canonical(
    *,
    review_id: int,
    resolution: str,
    invoice_id: str | None,
    amount_usd: Decimal,
    operator_id: int,
    bucket: int,
) -> bytes:
    """The exact bytes that get MAC'd.

    Field separator is ``\\x1f`` (unit separator) rather than a comma or a colon:
    every field here can in principle contain punctuation, and two different
    decisions rendering to the same joined string is the one way a bound code
    stops being bound. A control character cannot appear in a uuid, a decimal or
    a decision word, so the encoding is unambiguous by construction.
    """
    parts = (
        "notchstave-admin-confirm-v1",
        str(review_id),
        resolution,
        invoice_id or "-",
        # Normalised so that ``240`` and ``240.00`` — the same money, two
        # spellings out of Decimal — produce the same code.
        format(amount_usd.normalize(), "f"),
        str(operator_id),
        str(bucket),
    )
    return "\x1f".join(parts).encode("utf-8")


def _bucket(ttl_seconds: int, now: float | None = None) -> int:
    stamp = time.time() if now is None else now
    return int(stamp // max(ttl_seconds, 1))


def _render(digest: bytes, length: int) -> str:
    """Digest -> a short human-typable string over :data:`_ALPHABET`."""
    raw = base64.b32encode(digest).decode("ascii")
    mapped = "".join(_ALPHABET[b % len(_ALPHABET)] for b in raw.encode("ascii")[:length])
    return mapped


def _code_for_bucket(key: ConfirmationKey, payload: bytes, length: int) -> str:
    digest = hmac.new(key.material, payload, hashlib.sha256).digest()
    return _render(digest, length)


def issue_code(
    key: ConfirmationKey | None,
    *,
    review_id: int,
    resolution: str,
    invoice_id: str | None,
    amount_usd: Decimal,
    operator_id: int,
    ttl_seconds: int,
    length: int,
    now: float | None = None,
) -> str:
    """The code the owner must send back. Raises when no key is configured."""
    if key is None:
        raise ConfirmationUnavailable(
            f"{CONFIRMATION_KEY_ENV} is not set; a manual credit above the limit "
            "cannot be confirmed and is therefore refused (TZ 5.8/T7)"
        )
    payload = _canonical(
        review_id=review_id,
        resolution=resolution,
        invoice_id=invoice_id,
        amount_usd=amount_usd,
        operator_id=operator_id,
        bucket=_bucket(ttl_seconds, now),
    )
    return _code_for_bucket(key, payload, length)


def verify_code(
    key: ConfirmationKey | None,
    presented: str,
    *,
    review_id: int,
    resolution: str,
    invoice_id: str | None,
    amount_usd: Decimal,
    operator_id: int,
    ttl_seconds: int,
    length: int,
    now: float | None = None,
) -> None:
    """Accept, or raise. No boolean return, on purpose.

    A boolean is a value a caller can forget to check; this function either
    returns normally or stops the decision. The same reasoning as
    :class:`~settler.admin.errors.ConfirmationRequired` being an exception.
    """
    if key is None:
        raise ConfirmationUnavailable(
            f"{CONFIRMATION_KEY_ENV} is not set; no confirmation code can be verified"
        )
    candidate = (presented or "").strip().upper().replace("-", "").replace(" ", "")
    current = _bucket(ttl_seconds, now)
    # The previous bucket too: without it a code issued a second before a
    # boundary would be rejected instantly, and an owner who typed the code they
    # were just given would be told it had expired.
    for bucket in (current, current - 1):
        payload = _canonical(
            review_id=review_id,
            resolution=resolution,
            invoice_id=invoice_id,
            amount_usd=amount_usd,
            operator_id=operator_id,
            bucket=bucket,
        )
        expected = _code_for_bucket(key, payload, length)
        if hmac.compare_digest(expected, candidate):
            return
    raise InvalidConfirmationCode(
        f"confirmation code does not match this decision on review {review_id}, "
        "or has expired"
    )


# NOTE: the code is deliberately never written to ``audit_log``. Migration 0002
# grants ``SELECT`` on that table to every application role, so a stored code
# would be a stored bypass for anyone who reaches the database. What the audit
# trail records is that a confirmation was demanded and later satisfied — the
# two ``admin.*`` actions in :mod:`settler.admin.reviews` say exactly that.
