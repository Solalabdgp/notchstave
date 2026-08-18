"""Everything tunable about delivery, in one frozen dataclass.

Read from the environment once at startup and then passed down explicitly, the
same shape :class:`settler.policy.MoneyPolicy` uses. Nothing in this package
reads ``os.environ`` below :func:`NotifierConfig.from_env`, so a test constructs
the configuration it wants instead of mutating process state — which matters
here more than usual, because half of these knobs are *durations* and a test
that had to wait real backoff intervals would not be run.

The two rate limits are not tunable in the sense that a number is tunable: TZ
5.5 quotes them from Telegram's own documented limits ("не более 30 сообщений в
секунду суммарно, 1 в секунду на чат"). They are fields rather than constants
so that a test can run the token bucket at a speed a test can observe, and so
that an operator can lower them — never so they can be raised past what the API
allows.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = ["NotifierConfig"]


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return default if raw is None or not raw.strip() else float(raw)


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return default if raw is None or not raw.strip() else int(raw)


# The defaults live here as module constants and not only as field defaults, for
# the same reason :mod:`settler.policy` states: this dataclass is ``slots=True``,
# and on a slotted dataclass the class attribute is the slot *descriptor* rather
# than the default value. ``NotifierConfig.batch`` inside :meth:`from_env` would
# evaluate to ``<member 'batch' of 'NotifierConfig'>``, not to ``50`` — which
# mypy catches and a reader would not.
DEFAULT_BATCH = 50
DEFAULT_POLL_INTERVAL_SECONDS = 1.0
DEFAULT_MAX_ATTEMPTS = 6
DEFAULT_LEASE_SECONDS = 120.0
DEFAULT_BACKOFF_BASE_SECONDS = 5.0
DEFAULT_BACKOFF_MAX_SECONDS = 1800.0
DEFAULT_BACKOFF_JITTER = 0.25
#: TZ 5.5, quoted from Telegram's documented limits. Not a tuning knob upwards.
DEFAULT_GLOBAL_RATE_PER_SECOND = 30.0
DEFAULT_GLOBAL_BURST = 30.0
DEFAULT_CHAT_RATE_PER_SECOND = 1.0
DEFAULT_CHAT_BURST = 1.0
DEFAULT_MAX_RATE_LIMIT_WAIT_SECONDS = 30.0
DEFAULT_REDIS_PREFIX = "notchstave:notify:"


@dataclass(frozen=True, slots=True)
class NotifierConfig:
    """One pass's worth of policy, plus the Telegram limits of TZ 5.5."""

    #: Rows claimed per pass. Not a throughput knob — the token bucket decides
    #: throughput. It bounds how many rows one process holds a lease on, which
    #: is what a crash costs in delayed re-delivery.
    batch: int = DEFAULT_BATCH

    #: Seconds between passes when the last pass found nothing. A pass that
    #: filled its batch loops again immediately; see `notifier.main`.
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS

    #: "после N неудач — DLQ" (TZ 5.5). Six attempts across the backoff curve
    #: below spans roughly half an hour, which covers a Telegram incident
    #: without keeping a stale "payment received" message alive for a day.
    max_attempts: int = DEFAULT_MAX_ATTEMPTS

    #: How long a claimed row stays invisible to other claimants. Must exceed
    #: the worst realistic single send (HTTP timeout + rate-limit wait), or a
    #: slow send races its own retry.
    lease_seconds: float = DEFAULT_LEASE_SECONDS

    #: Backoff is ``base * 2 ** (attempts - 1)``, capped, then jittered.
    backoff_base_seconds: float = DEFAULT_BACKOFF_BASE_SECONDS
    backoff_max_seconds: float = DEFAULT_BACKOFF_MAX_SECONDS
    #: Fraction of the delay to spread randomly. Every notification for one
    #: Telegram outage is queued within seconds of every other, so an unjittered
    #: curve retries all of them at the same instants, forever.
    backoff_jitter: float = DEFAULT_BACKOFF_JITTER

    #: TZ 5.5 — Telegram's global ceiling. Burst equals rate: the bucket may
    #: hand out a second's worth at once, never a minute's worth saved up.
    global_rate_per_second: float = DEFAULT_GLOBAL_RATE_PER_SECOND
    global_burst: float = DEFAULT_GLOBAL_BURST

    #: TZ 5.5 — per-chat ceiling. Burst of one, because a burst of two on one
    #: chat is exactly the pattern the limit exists to stop.
    chat_rate_per_second: float = DEFAULT_CHAT_RATE_PER_SECOND
    chat_burst: float = DEFAULT_CHAT_BURST

    #: Upper bound on a single wait inside the limiter, so a clock jump or a
    #: misconfigured rate cannot park a worker forever without a log line.
    max_rate_limit_wait_seconds: float = DEFAULT_MAX_RATE_LIMIT_WAIT_SECONDS

    #: Namespace for the Redis buckets. Shared by every notifier instance —
    #: that sharing is the entire reason Redis is involved (TZ 5.5).
    redis_prefix: str = DEFAULT_REDIS_PREFIX

    @classmethod
    def from_env(cls) -> NotifierConfig:
        return cls(
            batch=_int("NOTIFIER_BATCH", DEFAULT_BATCH),
            poll_interval_seconds=_float(
                "NOTIFIER_POLL_INTERVAL_SECONDS", DEFAULT_POLL_INTERVAL_SECONDS
            ),
            max_attempts=_int("NOTIFIER_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS),
            lease_seconds=_float("NOTIFIER_LEASE_SECONDS", DEFAULT_LEASE_SECONDS),
            backoff_base_seconds=_float(
                "NOTIFIER_BACKOFF_BASE_SECONDS", DEFAULT_BACKOFF_BASE_SECONDS
            ),
            backoff_max_seconds=_float(
                "NOTIFIER_BACKOFF_MAX_SECONDS", DEFAULT_BACKOFF_MAX_SECONDS
            ),
            backoff_jitter=_float("NOTIFIER_BACKOFF_JITTER", DEFAULT_BACKOFF_JITTER),
            global_rate_per_second=_float(
                "NOTIFIER_GLOBAL_RATE", DEFAULT_GLOBAL_RATE_PER_SECOND
            ),
            global_burst=_float("NOTIFIER_GLOBAL_BURST", DEFAULT_GLOBAL_BURST),
            chat_rate_per_second=_float("NOTIFIER_CHAT_RATE", DEFAULT_CHAT_RATE_PER_SECOND),
            chat_burst=_float("NOTIFIER_CHAT_BURST", DEFAULT_CHAT_BURST),
            max_rate_limit_wait_seconds=_float(
                "NOTIFIER_MAX_RATE_LIMIT_WAIT_SECONDS", DEFAULT_MAX_RATE_LIMIT_WAIT_SECONDS
            ),
            redis_prefix=os.environ.get("NOTIFIER_REDIS_PREFIX", DEFAULT_REDIS_PREFIX),
        )

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.batch < 1:
            raise ValueError("batch must be at least 1")
        if self.global_rate_per_second <= 0 or self.chat_rate_per_second <= 0:
            raise ValueError("rates must be positive")
        if not 0.0 <= self.backoff_jitter < 1.0:
            raise ValueError("backoff_jitter must be in [0, 1)")
