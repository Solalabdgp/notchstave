"""Telegram Mini App ``initData``: parse it, prove it, or refuse it.

TZ 3.2 asks for *"авторизация через initData с **обязательной проверкой подписи
на бэкенде**"*. This module is that check and nothing else — it decides whether
a string came from Telegram, and hands back the ``user_id`` inside it. What that
``user_id`` is then allowed to see is TZ 5.8/T1.7's problem and lives in
:mod:`api.routes`.

The algorithm is Telegram's, not ours (core.telegram.org/bots/webapps,
"Validating data received via the Mini App"), and is quoted here because every
step of it is load-bearing:

1. the fields arrive as a URL-encoded query string; **decode first**, then work
   with decoded values;
2. take out ``hash``; sort the remaining pairs by key; join them as
   ``key=value`` with ``\\n`` between — this is the *data-check-string*;
3. ``secret_key = HMAC_SHA256(data=<bot token>, key="WebAppData")`` — the
   constant is the *key* and the bot token is the *message*, which is the way
   round that is easy to get backwards and produces a validator that rejects
   everything;
4. the expected hash is ``HMAC_SHA256(data=data_check_string, key=secret_key)``
   compared, in hex, against the ``hash`` field.

----

**Why this process holds a derived secret and not the bot token.** Step 3 is a
pure function of the token, so a verifier needs its *output*, never its input.
That difference is worth a class (:class:`WebAppSecret`): TZ section 9 hands out
secrets "кому нужно", and TZ 5.8/T1 vector 3 is specifically *"компрометация
токена бота... старое сообщение с адресом тихо переписывается на новый адрес"*.
An ``api`` holding the real token could do exactly that. An ``api`` holding only
``HMAC_SHA256(token, "WebAppData")`` can verify every Mini App session and
cannot call ``editMessageText``, because the derivation is one-way. So the
production credential for this unit is the derived key, and
:func:`derive_webapp_secret` exists for local dev and for the operator command
that produces the credential in the first place.

**Why ``auth_date`` is checked and not merely parsed.** Telegram calls the
freshness check optional ("you can additionally check"). It is not optional
here: ``initData`` is a bearer string that stays valid forever without it, so
one copy out of a browser console, a proxy log or a shared screenshot is a
permanent key to that user's invoices. :data:`DEFAULT_MAX_AGE_SECONDS` is a day,
which is long enough for a Mini App left open on a phone overnight and short
enough that a leaked string is not a standing credential.

**Why a duplicate key is a refusal.** ``a=1&a=2`` has no single reading, and the
two readings differ: whichever one this module folds into the check string, a
proxy or a client library may fold the other. Rejecting is the only answer that
cannot be gamed into a signature that verifies over text the server never saw.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

__all__ = [
    "CREDENTIAL_NAME",
    "DEFAULT_MAX_AGE_SECONDS",
    "WEBAPP_CONSTANT",
    "InitData",
    "InitDataError",
    "InitDataMalformed",
    "InitDataExpired",
    "InitDataSignatureInvalid",
    "WebAppSecret",
    "derive_webapp_secret",
    "load_webapp_secret",
    "verify_init_data",
]

#: The constant from Telegram's spec. Used as the HMAC *key* over the token.
WEBAPP_CONSTANT = b"WebAppData"

#: systemd credential holding the *derived* key (hex or raw 32 bytes), never the
#: bot token. Produced offline with :func:`derive_webapp_secret`.
CREDENTIAL_NAME = "notchstave-telegram-webapp-secret"

#: How old an ``initData`` may be. See the module docstring — not optional.
DEFAULT_MAX_AGE_SECONDS = 86_400


class InitDataError(Exception):
    """Base class. Every subclass means "this request is not authorized".

    Carries a ``user_message`` for the same reason
    :mod:`core.invoicing.errors` does: the detail names what failed and is for
    the log, and a Mini App that renders ``str(exc)`` would tell a prober which
    of the four checks it tripped.
    """

    user_message = "This Mini App session could not be verified. Please reopen it from the bot."

    def __init__(self, detail: str) -> None:
        super().__init__(detail)


class InitDataMalformed(InitDataError):
    """Not a readable ``initData`` at all — bad encoding, no ``hash``, duplicate key."""


class InitDataSignatureInvalid(InitDataError):
    """The HMAC did not match. Forged, corrupted, or signed by a different bot."""


class InitDataExpired(InitDataError):
    """Genuine, but older than the freshness window."""

    user_message = "This Mini App session has expired. Please reopen it from the bot."


@dataclass(frozen=True, slots=True)
class WebAppSecret:
    """``HMAC_SHA256(bot_token, "WebAppData")`` — the only Telegram secret ``api`` gets.

    ``repr`` is overridden for the reason TZ 5.8/T4 gives about the xpub: a
    config object that prints its own key material puts it in a pytest diff, a
    debugger dump and a crash report. The ``field(repr=False)`` is belt and
    braces on top of the explicit ``__repr__``.
    """

    raw: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if len(self.raw) != hashlib.sha256().digest_size:
            raise ValueError(
                f"a WebAppData secret is {hashlib.sha256().digest_size} bytes "
                f"(HMAC-SHA256 output), got {len(self.raw)}"
            )

    def __repr__(self) -> str:
        return "WebAppSecret(<redacted>)"

    __str__ = __repr__


def derive_webapp_secret(bot_token: str) -> WebAppSecret:
    """Step 3 of the spec: the constant is the key, the token is the message.

    Run this once, offline, to produce the credential this process is given —
    or at startup in local dev, where the token is already in ``.env`` and a
    second variable would be ceremony.
    """
    if not bot_token or not bot_token.strip():
        raise ValueError("bot token is empty")
    digest = hmac.new(WEBAPP_CONSTANT, bot_token.encode("utf-8"), hashlib.sha256).digest()
    return WebAppSecret(digest)


def load_webapp_secret(
    env: Mapping[str, str] | None = None,
    *,
    credentials_dir: str | os.PathLike[str] | None = None,
) -> WebAppSecret | None:
    """Credential first, bot token second, ``None`` last.

    The precedence matters and mirrors
    :func:`core.invoicing.integrity.load_integrity_key`: a correctly configured
    unit cannot be downgraded by a stray environment variable, because the
    credential is consulted first and wins whenever it is present.

    Returns ``None`` rather than raising when nothing is configured. Refusing to
    start would take the *public* invoice page — which needs no Telegram
    identity at all (TZ 5.8/T1.7) — down with the authenticated one, and those
    two have genuinely different requirements. :mod:`api.routes` turns a
    ``None`` into a 503 on the endpoints that need it, and ``/healthz`` reports
    it, so it is loud without being fatal.
    """
    src = os.environ if env is None else env

    raw_dir = credentials_dir if credentials_dir is not None else src.get("CREDENTIALS_DIRECTORY")
    if raw_dir:
        candidate = Path(raw_dir) / CREDENTIAL_NAME
        if candidate.exists():
            return _secret_from_credential(candidate.read_bytes())

    token = src.get("TELEGRAM_BOT_TOKEN")
    if token and token.strip():
        return derive_webapp_secret(token.strip())

    return None


def _secret_from_credential(blob: bytes) -> WebAppSecret:
    """Accept the credential as hex or as 32 raw bytes; guess neither silently."""
    text = blob.strip()
    if len(text) == 2 * hashlib.sha256().digest_size:
        try:
            return WebAppSecret(bytes.fromhex(text.decode("ascii")))
        except (UnicodeDecodeError, ValueError):
            pass
    return WebAppSecret(bytes(text))


@dataclass(frozen=True, slots=True)
class InitData:
    """A verified session. Nothing here is trusted until this type exists.

    There is no ``valid: bool`` field, for the reason
    :class:`core.invoicing.service.InvoiceView` gives about itself: an
    unverified :class:`InitData` is not constructed, so a caller cannot forget
    to look at a flag.
    """

    user_id: int
    auth_date: dt.datetime
    #: Every decoded field except ``hash``, kept so a caller can read
    #: ``query_id`` or ``start_param`` without re-parsing the raw string.
    fields: Mapping[str, str]

    @property
    def query_id(self) -> str | None:
        return self.fields.get("query_id")

    @property
    def start_param(self) -> str | None:
        return self.fields.get("start_param")


def _pairs(raw: str) -> dict[str, str]:
    try:
        decoded = parse_qsl(raw, strict_parsing=True, keep_blank_values=True)
    except ValueError as exc:
        raise InitDataMalformed(f"initData is not a valid query string: {exc}") from exc

    out: dict[str, str] = {}
    for key, value in decoded:
        # An unnamed field is not something Telegram emits, and it would put a
        # line beginning with "=" into the data-check-string. Refused for the
        # same reason a duplicate key is: this module must not be the place that
        # decides what a malformed string was supposed to mean.
        if not key:
            raise InitDataMalformed("initData carries a field with no name")
        if key in out:
            raise InitDataMalformed(f"initData repeats the field {key!r}; refusing to guess")
        out[key] = value
    if not out:
        raise InitDataMalformed("initData is empty")
    return out


def _data_check_string(fields: Mapping[str, str]) -> str:
    return "\n".join(f"{key}={fields[key]}" for key in sorted(fields))


def _user_id(fields: Mapping[str, str]) -> int:
    """``user`` is a JSON object; the id inside it is what authorization uses.

    A missing or unreadable ``user`` is malformed rather than anonymous. Every
    endpoint that asks for ``initData`` asks in order to filter by user, so a
    session without one is useless in a way that must not be discovered three
    layers down as a ``None``.
    """
    raw = fields.get("user")
    if raw is None:
        raise InitDataMalformed("initData carries no user field")
    try:
        parsed: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InitDataMalformed(f"initData user field is not JSON: {exc}") from exc
    if not isinstance(parsed, dict) or "id" not in parsed:
        raise InitDataMalformed("initData user object has no id")
    try:
        return int(parsed["id"])
    except (TypeError, ValueError) as exc:
        raise InitDataMalformed(f"initData user id is not an integer: {exc}") from exc


def _auth_date(fields: Mapping[str, str]) -> dt.datetime:
    raw = fields.get("auth_date")
    if raw is None:
        raise InitDataMalformed("initData carries no auth_date")
    try:
        return dt.datetime.fromtimestamp(int(raw), tz=dt.UTC)
    except (TypeError, ValueError, OSError, OverflowError) as exc:
        raise InitDataMalformed(f"initData auth_date is not a unix timestamp: {exc}") from exc


def verify_init_data(
    raw: str,
    secret: WebAppSecret,
    *,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    now: dt.datetime | None = None,
) -> InitData:
    """Prove one ``initData`` string, or raise :class:`InitDataError`.

    Order is deliberate: shape, then signature, then freshness. Checking
    freshness before the signature would let an unauthenticated caller learn
    whether a timestamp it made up is inside the window — a small oracle, but a
    free one to close by ordering.
    """
    fields = _pairs(raw)

    received = fields.pop("hash", None)
    if received is None:
        raise InitDataMalformed("initData carries no hash field")

    expected = hmac.new(
        secret.raw, _data_check_string(fields).encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # Constant time, and case-insensitive on the received side only: Telegram
    # sends lowercase hex, but a client library that upper-cased it would
    # otherwise fail a check it should pass.
    if not hmac.compare_digest(expected, received.lower()):
        raise InitDataSignatureInvalid("initData hash does not verify against the WebApp secret")

    auth_date = _auth_date(fields)
    moment = dt.datetime.now(dt.UTC) if now is None else now
    age = (moment - auth_date).total_seconds()
    if age > max_age_seconds:
        raise InitDataExpired(
            f"initData is {int(age)}s old, over the {max_age_seconds}s window"
        )

    return InitData(user_id=_user_id(fields), auth_date=auth_date, fields=fields)
