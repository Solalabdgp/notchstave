"""Thresholds and deadlines for invoice issuance (TZ 5.5, 5.8/T5).

Same shape and same rules as :mod:`settler.policy`: a frozen dataclass, an
explicit ``version`` that travels into ``invoices.policy_version`` and into the
``audit_log`` row of every issuance, and module-level constants for the defaults
rather than only dataclass field defaults.

That last point is not style. ``slots=True`` makes the class attribute the slot
*descriptor*, so reading ``InvoicingPolicy.invoice_ttl`` off the class inside
:meth:`InvoicingPolicy.from_env` yields ``<member 'invoice_ttl' of ...>`` and not
a timedelta — which either raises on the first arithmetic or writes a repr into
a money row. :mod:`settler.policy` found this the hard way; naming the defaults
once is what stops the dataclass and the environment reader from diverging.

**Why the two fifteen-minute deadlines are separate fields.** TZ 5.8/T5.4 wants
a short invoice life so addresses cycle back into the pool quickly, and TZ 5.5
wants the quoted rate to stop being honoured after ``rate_locked_until``. The TZ
says the two are "согласован" — aligned, defaulting to the same fifteen minutes
— not that they are the same number. They protect different parties and the
settler already treats them as two quantities (``settler.service
.expire_stale_invoices`` vs ``sweep_expired_invoices``), so collapsing them into
one knob here would make a test for one of them impossible to write.
"""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass

__all__ = [
    "InvoicingPolicy",
    "DEFAULT_POLICY",
    "DEFAULT_POLICY_VERSION",
]

#: Bump this in the same edit as any number below (TZ 5.8/T8). A threshold that
#: moved without the version moving turns every earlier ``policy_version`` in
#: ``invoices`` and ``audit_log`` into a lie about what it meant.
DEFAULT_POLICY_VERSION = "2026-08-19.invoicing-1"

#: TZ 5.8/T5.1 — "не более 3 одновременно активных неоплаченных инвойсов".
DEFAULT_MAX_ACTIVE_INVOICES_PER_USER = 3

#: TZ 5.8/T5.1 — "не более 10 за час".
DEFAULT_MAX_INVOICES_PER_HOUR = 10

#: TZ 5.8/T5.4 — "Дефолт 15 минут, согласован с rate_locked_until".
DEFAULT_INVOICE_TTL = dt.timedelta(minutes=15)

#: TZ 5.5 rate table — "действует rate_locked_until (по умолчанию 15 минут)".
DEFAULT_RATE_LOCK_TTL = dt.timedelta(minutes=15)

#: TZ 5.5 underpayment — "Окно доплаты живёт дольше самого инвойса (по умолчанию
#: 24 часа после истечения)". Measured from ``expires_at``, not from creation.
DEFAULT_TOPUP_WINDOW = dt.timedelta(hours=24)

#: TZ 5.8/T5.5 — "После N подряд истёкших неоплаченных инвойсов (по умолчанию 5)".
DEFAULT_EXPIRED_STREAK_LIMIT = 5

#: TZ 5.8/T5.5 — "пользователь уходит в cooldown на час".
DEFAULT_COOLDOWN = dt.timedelta(hours=1)

#: The rolling window the hourly quota counts over.
DEFAULT_QUOTA_WINDOW = dt.timedelta(hours=1)

#: Bytes of entropy behind ``invoices.public_token`` (TZ 5.8/T1.7 — "по
#: отдельному неугадываемому токену"). 32 bytes is 256 bits, which
#: ``secrets.token_urlsafe`` renders as 43 characters — comfortably inside the
#: ``String(64)`` column and far past any online guessing budget.
DEFAULT_PUBLIC_TOKEN_BYTES = 32


@dataclass(frozen=True, slots=True)
class InvoicingPolicy:
    """Everything about issuance that an operator is allowed to tune."""

    version: str = DEFAULT_POLICY_VERSION

    max_active_invoices_per_user: int = DEFAULT_MAX_ACTIVE_INVOICES_PER_USER
    max_invoices_per_hour: int = DEFAULT_MAX_INVOICES_PER_HOUR
    quota_window: dt.timedelta = DEFAULT_QUOTA_WINDOW

    invoice_ttl: dt.timedelta = DEFAULT_INVOICE_TTL
    rate_lock_ttl: dt.timedelta = DEFAULT_RATE_LOCK_TTL
    topup_window: dt.timedelta = DEFAULT_TOPUP_WINDOW

    expired_streak_limit: int = DEFAULT_EXPIRED_STREAK_LIMIT
    cooldown: dt.timedelta = DEFAULT_COOLDOWN

    public_token_bytes: int = DEFAULT_PUBLIC_TOKEN_BYTES

    def __post_init__(self) -> None:
        # Validated at construction because every one of these lands in a money
        # row or a CHECK constraint, and a zero TTL fails `expiry_after_creation`
        # at INSERT time — inside the issuance transaction, after an address has
        # already been taken out of the pool.
        if self.max_active_invoices_per_user < 1:
            raise ValueError("max_active_invoices_per_user must be at least 1")
        if self.max_invoices_per_hour < 1:
            raise ValueError("max_invoices_per_hour must be at least 1")
        if self.expired_streak_limit < 1:
            raise ValueError("expired_streak_limit must be at least 1")
        if self.invoice_ttl <= dt.timedelta(0):
            raise ValueError("invoice_ttl must be positive")
        if self.rate_lock_ttl <= dt.timedelta(0):
            raise ValueError("rate_lock_ttl must be positive")
        if self.topup_window < dt.timedelta(0):
            raise ValueError("topup_window must not be negative")
        if self.quota_window <= dt.timedelta(0):
            raise ValueError("quota_window must be positive")
        if self.public_token_bytes < 16:
            # 128 bits is the floor at which "unguessable" stops being an
            # argument and starts being an assumption.
            raise ValueError("public_token_bytes must be at least 16")

    @property
    def public_token_ttl(self) -> dt.timedelta:
        """TZ 6 — "TTL = срок жизни инвойса + окно доплаты".

        Derived rather than configured, because the token's job is to stay
        usable exactly as long as the page it opens is meaningful. A token that
        outlives the top-up window is a link that shows an address nobody should
        send to any more; one that dies earlier locks a paying buyer out of the
        status page mid-payment.
        """
        return self.invoice_ttl + self.topup_window

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> InvoicingPolicy:
        """Read the knobs from the environment, keeping the defaults above.

        Not pydantic-Settings and not a module-level singleton, matching
        :meth:`settler.policy.MoneyPolicy.from_env`: the policy is passed
        explicitly into every call so a test can hand in a different table, and
        a global would quietly make that impossible.
        """
        src = os.environ if env is None else env

        def _int(key: str, default: int) -> int:
            raw = src.get(key)
            return default if raw is None or raw == "" else int(raw)

        def _seconds(key: str, default: dt.timedelta) -> dt.timedelta:
            raw = src.get(key)
            return default if raw is None or raw == "" else dt.timedelta(seconds=int(raw))

        return cls(
            version=src.get("INVOICING_POLICY_VERSION", DEFAULT_POLICY_VERSION),
            max_active_invoices_per_user=_int(
                "INVOICING_MAX_ACTIVE_INVOICES_PER_USER",
                DEFAULT_MAX_ACTIVE_INVOICES_PER_USER,
            ),
            max_invoices_per_hour=_int(
                "INVOICING_MAX_INVOICES_PER_HOUR", DEFAULT_MAX_INVOICES_PER_HOUR
            ),
            quota_window=_seconds("INVOICING_QUOTA_WINDOW_SECONDS", DEFAULT_QUOTA_WINDOW),
            invoice_ttl=_seconds("INVOICING_INVOICE_TTL_SECONDS", DEFAULT_INVOICE_TTL),
            rate_lock_ttl=_seconds("INVOICING_RATE_LOCK_TTL_SECONDS", DEFAULT_RATE_LOCK_TTL),
            topup_window=_seconds("INVOICING_TOPUP_WINDOW_SECONDS", DEFAULT_TOPUP_WINDOW),
            expired_streak_limit=_int(
                "INVOICING_EXPIRED_STREAK_LIMIT", DEFAULT_EXPIRED_STREAK_LIMIT
            ),
            cooldown=_seconds("INVOICING_COOLDOWN_SECONDS", DEFAULT_COOLDOWN),
            public_token_bytes=_int(
                "INVOICING_PUBLIC_TOKEN_BYTES", DEFAULT_PUBLIC_TOKEN_BYTES
            ),
        )


DEFAULT_POLICY = InvoicingPolicy()
