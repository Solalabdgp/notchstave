"""Thresholds governing owner decisions, versioned (TZ 5.8/T8).

The sibling of :class:`settler.policy.MoneyPolicy`, and separate from it on
purpose. They answer different questions and change for different reasons: the
money policy says what the *system* does automatically with an underpayment, and
this one says what the *owner* may do by hand and above which number they have to
prove they meant it. Merging them would mean bumping the version stamped on
thousands of automatic settlements every time an operational limit is adjusted,
which makes ``policy_version`` useless as an answer to "which rules were in
force when this invoice was closed".

Both versions end up in ``audit_log.policy_version``, and which one appears is
itself the record of who decided: a ``settle.*`` row carries the money policy,
an ``admin.*`` row carries this one.

**The secret is not in here.** ``NOTCHSTAVE_ADMIN_CONFIRMATION_KEY`` is loaded
separately by :func:`settler.admin.twostep.confirmation_key_from_env` and wrapped
in a type with a redacted ``repr``. A policy object is exactly the kind of thing
that gets logged whole during debugging or dumped into an audit payload, and TZ
5.8/T4 is a standing reminder in this repository of what happens when a secret
rides along in a config object.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from decimal import Decimal

__all__ = [
    "AdminPolicy",
    "DEFAULT_ADMIN_POLICY",
    "DEFAULT_ADMIN_POLICY_VERSION",
    "DEFAULT_MANUAL_CREDIT_LIMIT_USD",
    "DEFAULT_RECONCILE_DRIFT_THRESHOLD_USD",
    "DEFAULT_CONFIRMATION_TTL_SECONDS",
]

#: Bump this whenever any number below changes. The two are one edit — a
#: threshold change without a version change makes every audit row written after
#: it a lie about what the row before it meant.
DEFAULT_ADMIN_POLICY_VERSION = "2026-08-17.admin-1"

#: TZ 5.8/T7 gives the control ("порог на ручной зачёт") and not a number. Fifty
#: dollars is chosen against the catalogue rather than out of the air: products
#: in this project are priced in the tens of dollars, so the limit sits above a
#: routine goodwill credit on one purchase and below anything that would be worth
#: a captured session's while. It is configuration; an operator running a
#: different price list should move it.
DEFAULT_MANUAL_CREDIT_LIMIT_USD = Decimal("50")

#: Above this, `/reconcile` stops being a report and becomes an incident (TZ
#: section 7: "БД и цепь разошлись ... самое серьёзное, что может случиться").
#: One dollar, not zero: dust arriving on a receive address is a drift by the
#: arithmetic and not by the accounting, and an alert that fires on every
#: unsolicited transfer is an alert nobody reads.
DEFAULT_RECONCILE_DRIFT_THRESHOLD_USD = Decimal("1")

#: How long a confirmation code stays valid. Five minutes: long enough for a
#: human reading a chat, short enough that a code lifted from a notification an
#: hour later is worthless.
DEFAULT_CONFIRMATION_TTL_SECONDS = 300

#: Characters of the code the owner types back. Eight from a 32-symbol alphabet
#: is forty bits — irrelevant as a brute-force target (the code is bound to one
#: decision and one time window) and short enough to retype without a copy-paste.
DEFAULT_CONFIRMATION_CODE_LENGTH = 8


@dataclass(frozen=True, slots=True)
class AdminPolicy:
    """Owner-side thresholds, versioned for TZ 5.8/T8."""

    version: str = DEFAULT_ADMIN_POLICY_VERSION
    manual_credit_limit_usd: Decimal = DEFAULT_MANUAL_CREDIT_LIMIT_USD
    reconcile_drift_threshold_usd: Decimal = DEFAULT_RECONCILE_DRIFT_THRESHOLD_USD
    confirmation_ttl_seconds: int = DEFAULT_CONFIRMATION_TTL_SECONDS
    confirmation_code_length: int = DEFAULT_CONFIRMATION_CODE_LENGTH

    def needs_confirmation(self, amount_usd: Decimal) -> bool:
        """TZ 5.8/T7 — "выше ``manual_credit_limit_usd`` требует подтверждения".

        Strictly greater, matching :func:`settler.confirmations.required_rule`:
        a decision sitting exactly on a configured limit takes the cheaper path
        in both places, and two thresholds in one codebase disagreeing about
        their own boundary is a bug waiting for the one invoice priced at
        exactly the limit.
        """
        return amount_usd > self.manual_credit_limit_usd

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> AdminPolicy:
        """Read thresholds from the environment, keeping the defaults above.

        Explicitly passed into every admin call rather than read from a global,
        for the reason :class:`settler.policy.MoneyPolicy` gives: a test must be
        able to hand in a different table, and a settings singleton quietly makes
        that impossible.
        """
        src = os.environ if env is None else env

        def _dec(key: str, default: Decimal) -> Decimal:
            raw = src.get(key)
            return default if raw is None or raw == "" else Decimal(raw)

        def _int(key: str, default: int) -> int:
            raw = src.get(key)
            return default if raw is None or raw == "" else int(raw)

        return cls(
            version=src.get("ADMIN_POLICY_VERSION", DEFAULT_ADMIN_POLICY_VERSION),
            manual_credit_limit_usd=_dec(
                "ADMIN_MANUAL_CREDIT_LIMIT_USD", DEFAULT_MANUAL_CREDIT_LIMIT_USD
            ),
            reconcile_drift_threshold_usd=_dec(
                "ADMIN_RECONCILE_DRIFT_THRESHOLD_USD", DEFAULT_RECONCILE_DRIFT_THRESHOLD_USD
            ),
            confirmation_ttl_seconds=_int(
                "ADMIN_CONFIRMATION_TTL_SECONDS", DEFAULT_CONFIRMATION_TTL_SECONDS
            ),
            confirmation_code_length=_int(
                "ADMIN_CONFIRMATION_CODE_LENGTH", DEFAULT_CONFIRMATION_CODE_LENGTH
            ),
        )


DEFAULT_ADMIN_POLICY = AdminPolicy()
