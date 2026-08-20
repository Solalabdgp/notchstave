"""Everything the api process reads from the environment, in one frozen object.

Same shape and the same rule as :class:`notifier.config.NotifierConfig` and
:class:`settler.policy.MoneyPolicy`: read once at startup, passed down
explicitly, and nothing below :meth:`ApiConfig.from_env` touches
``os.environ``. A test builds the configuration it wants instead of mutating
process state.

Secrets are deliberately **not** in here. ``INVOICE_INTEGRITY_KEY`` and the
Telegram WebApp secret are loaded by their own modules
(:func:`core.invoicing.integrity.load_integrity_key`,
:func:`api.telegram.load_webapp_secret`), both of which prefer a systemd
credential over an environment variable. Putting them in this dataclass would
mean one object that prints half the process's secrets whenever a config dump
is logged, which is the failure TZ 5.8/T4 asks to design against.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

__all__ = ["ApiConfig"]

DEFAULT_DATABASE_URL = "postgresql+psycopg://notchstave:change-me-local-dev-only@localhost:5432/notchstave"
#: How often the invoice page re-asks for status. Two seconds is well inside the
#: block time of every chain in TZ 2, so the page never shows a confirmation
#: count that the watcher has already moved past for longer than one tick.
DEFAULT_STATUS_POLL_SECONDS = 2.0
#: Freshness window for ``initData``. See :mod:`api.telegram` for why this is
#: enforced rather than merely parsed.
DEFAULT_INITDATA_MAX_AGE_SECONDS = 86_400
#: Cap on the ``public_token`` length this process will even look up. The tokens
#: are 32 bytes of urlsafe base64 by default (``core.invoicing.config``) and the
#: column is ``String(64)``; anything longer is a probe, and bouncing it before
#: it reaches the database keeps a scan from turning into query load.
DEFAULT_MAX_TOKEN_LENGTH = 64


def _float(src: Mapping[str, str], name: str, default: float) -> float:
    raw = src.get(name)
    return default if raw is None or not raw.strip() else float(raw)


def _int(src: Mapping[str, str], name: str, default: int) -> int:
    raw = src.get(name)
    return default if raw is None or not raw.strip() else int(raw)


@dataclass(frozen=True, slots=True)
class ApiConfig:
    """Non-secret knobs for the invoice page and its status endpoint."""

    #: SQLAlchemy-form URL, as everywhere else in this repo. Converted to a
    #: libpq DSN at the point of connection, not here — one variable for the
    #: whole project rather than a second that can drift out of sync.
    database_url: str = DEFAULT_DATABASE_URL

    #: Seconds between the page's status polls. Sent to the browser rather than
    #: hard-coded in the script, so an operator can slow it down under load
    #: without shipping new static assets.
    status_poll_seconds: float = DEFAULT_STATUS_POLL_SECONDS

    initdata_max_age_seconds: int = DEFAULT_INITDATA_MAX_AGE_SECONDS

    max_token_length: int = DEFAULT_MAX_TOKEN_LENGTH

    @property
    def psycopg_dsn(self) -> str:
        """``postgresql+psycopg://`` -> ``postgresql://``.

        psycopg does not understand SQLAlchemy's ``+driver`` suffix, and this
        process talks to Postgres through psycopg directly — the invoicing
        module it calls is synchronous psycopg for the reasons its own docstring
        gives.
        """
        return self.database_url.replace("postgresql+psycopg://", "postgresql://", 1)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ApiConfig:
        src = os.environ if env is None else env
        return cls(
            database_url=src.get("DATABASE_URL", DEFAULT_DATABASE_URL),
            status_poll_seconds=_float(
                src, "API_STATUS_POLL_SECONDS", DEFAULT_STATUS_POLL_SECONDS
            ),
            initdata_max_age_seconds=_int(
                src, "API_INITDATA_MAX_AGE_SECONDS", DEFAULT_INITDATA_MAX_AGE_SECONDS
            ),
            max_token_length=_int(src, "API_MAX_TOKEN_LENGTH", DEFAULT_MAX_TOKEN_LENGTH),
        )

    def __post_init__(self) -> None:
        if self.status_poll_seconds <= 0:
            raise ValueError("status_poll_seconds must be positive")
        if self.initdata_max_age_seconds < 1:
            raise ValueError("initdata_max_age_seconds must be at least 1")
        if self.max_token_length < 16:
            raise ValueError("max_token_length must be at least 16")
