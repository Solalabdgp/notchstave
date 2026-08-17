"""Per-provider circuit breaker and request budget (TZ 5.6).

State machine, identical to the one in `scraping-platform/app/core/breaker.py`:

    closed    --(N consecutive failures)--> open
    open      --(cooldown elapsed)-------->  half_open   (one trial call)
    half_open --(trial succeeds)---------->  closed
    half_open --(trial fails)------------->  open  (longer cooldown)

**Why this one is in-process while the scraping-platform one is in Redis.**
There, the breaker was consulted by many Celery prefork children that had to
agree about one shared source, so the state had to live outside any single
process. Here the unit being protected is "this watcher's connection to this
provider", and TZ section 4 puts exactly one watcher process on a chain. A
second process would have its own connection pool, its own budget and its own
opinion about latency, so sharing breaker state between them would be sharing
the wrong thing.

The rule from TZ 5.8/T2.4 also applies by analogy: Redis saves work, it never
holds correctness. A breaker that forgets everything on restart re-probes a
dead provider once and re-opens — annoying, not incorrect.

Both classes take a `clock` so the tests can move time forward without
sleeping. Everything here is synchronous and allocation-free on the hot path:
`allow()` is called before every single RPC request.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

__all__ = [
    "BreakerState",
    "BreakerPolicy",
    "CircuitBreaker",
    "RequestBudget",
    "STATE_TO_METRIC",
]

Clock = Callable[[], float]


class BreakerState:
    """Plain strings — they are Prometheus label values and log fields."""

    CLOSED: Final = "closed"
    OPEN: Final = "open"
    HALF_OPEN: Final = "half_open"


#: Grafana cannot chart a string (same trick as scraping-platform).
STATE_TO_METRIC: Final[dict[str, float]] = {
    BreakerState.CLOSED: 0.0,
    BreakerState.HALF_OPEN: 1.0,
    BreakerState.OPEN: 2.0,
}


@dataclass(frozen=True, slots=True)
class BreakerPolicy:
    """Tuning knobs. Defaults are deliberately impatient.

    A payment watcher that keeps hammering a degraded provider is not being
    resilient, it is burning the free-tier budget that the *working* provider
    will need in ten minutes. Three strikes and thirty seconds out is cheap when
    there are two more providers in the rotation.
    """

    failure_threshold: int = 3
    cooldown_seconds: float = 30.0
    #: Each consecutive trip multiplies the cooldown, capped. A provider that is
    #: down for an hour should not be probed 120 times during that hour.
    cooldown_backoff_factor: float = 2.0
    max_cooldown_seconds: float = 300.0

    def __post_init__(self) -> None:
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if self.cooldown_seconds <= 0:
            raise ValueError("cooldown_seconds must be > 0")
        if self.cooldown_backoff_factor < 1:
            raise ValueError("cooldown_backoff_factor must be >= 1")


class CircuitBreaker:
    """One provider's health, as a state machine.

    Usage is always the same three lines, and the pool is the only caller::

        if not breaker.allow():
            ...  # skip to the next provider
        try:
            result = await client.call()
        except RpcError:
            breaker.record_failure()
        else:
            breaker.record_success()

    `allow()` never raises and never blocks: a breaker that can fail is a
    breaker that takes the system down with it.
    """

    __slots__ = (
        "name",
        "policy",
        "_clock",
        "_state",
        "_failures",
        "_trips",
        "_cooldown_until",
        "_trial_in_flight",
    )

    def __init__(
        self,
        name: str,
        policy: BreakerPolicy | None = None,
        *,
        clock: Clock = time.monotonic,
    ) -> None:
        self.name = name
        self.policy = policy or BreakerPolicy()
        self._clock = clock
        self._state = BreakerState.CLOSED
        self._failures = 0
        self._trips = 0
        self._cooldown_until = 0.0
        self._trial_in_flight = False

    # ------------------------------------------------------------- readable --
    @property
    def state(self) -> str:
        """Current state, promoting `open -> half_open` if the cooldown expired.

        Reading the state is allowed to move it: `open` with an elapsed cooldown
        *is* `half_open`, and forcing callers to poke the breaker first would
        make `snapshot()`-style code report a stale value.
        """
        if self._state == BreakerState.OPEN and self._clock() >= self._cooldown_until:
            self._state = BreakerState.HALF_OPEN
            self._trial_in_flight = False
        return self._state

    @property
    def consecutive_failures(self) -> int:
        return self._failures

    @property
    def cooldown_remaining(self) -> float:
        return max(self._cooldown_until - self._clock(), 0.0)

    # ------------------------------------------------------------ decisions --
    def allow(self) -> bool:
        """May the pool send a request to this provider right now?"""
        state = self.state
        if state == BreakerState.CLOSED:
            return True
        if state == BreakerState.OPEN:
            return False
        # half_open: exactly one trial call is allowed through. The watcher is a
        # single-threaded asyncio process, so a plain flag is a sufficient latch;
        # a threaded caller would need a lock here and this comment is the
        # warning that would matter then.
        if self._trial_in_flight:
            return False
        self._trial_in_flight = True
        return True

    # -------------------------------------------------------------- results --
    def record_success(self) -> None:
        """Any success fully closes the breaker and forgets the trip history."""
        self._state = BreakerState.CLOSED
        self._failures = 0
        self._trips = 0
        self._cooldown_until = 0.0
        self._trial_in_flight = False

    def record_failure(self) -> None:
        """Count a failure; trip (or re-trip) when warranted."""
        was_half_open = self.state == BreakerState.HALF_OPEN
        self._failures += 1
        self._trial_in_flight = False

        # A failed trial re-opens immediately: half-open exists to ask one
        # question, and the answer was "still broken".
        if not was_half_open and self._failures < self.policy.failure_threshold:
            self._state = BreakerState.CLOSED
            return

        self._trips += 1
        cooldown = min(
            self.policy.cooldown_seconds
            * (self.policy.cooldown_backoff_factor ** (self._trips - 1)),
            self.policy.max_cooldown_seconds,
        )
        self._state = BreakerState.OPEN
        self._cooldown_until = self._clock() + cooldown

    def reset(self) -> None:
        """Manual override — used by `/healthz` recovery paths and by tests."""
        self.record_success()


class RequestBudget:
    """A coarse per-window cap on requests to one provider (TZ 5.6).

    Fixed window rather than sliding, and that is a deliberate simplification:
    provider free tiers are quoted per month or per day in "compute units",
    which this cannot model faithfully anyway. The purpose here is narrower —
    stop one runaway loop (a reorg storm, a filter that keeps splitting) from
    eating a whole day's quota in five minutes. The honest accounting of spend
    is the `notchstave_rpc_requests_total{provider,method}` counter, which is
    what the dashboard reads.

    `limit=None` means unmetered, which is the right setting for a local node.
    """

    __slots__ = ("name", "limit", "window_seconds", "_clock", "_window_start", "_spent", "_total")

    def __init__(
        self,
        name: str,
        limit: int | None,
        window_seconds: float = 60.0,
        *,
        clock: Clock = time.monotonic,
    ) -> None:
        if limit is not None and limit < 1:
            raise ValueError("budget limit must be >= 1 or None for unmetered")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self.name = name
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock
        self._window_start = clock()
        self._spent = 0
        self._total = 0

    @property
    def spent(self) -> int:
        """Requests used in the current window."""
        self._roll()
        return self._spent

    @property
    def total(self) -> int:
        """Requests ever made through this budget (a monotone counter)."""
        return self._total

    @property
    def remaining(self) -> int | None:
        if self.limit is None:
            return None
        return max(self.limit - self.spent, 0)

    def _roll(self) -> None:
        now = self._clock()
        if now - self._window_start >= self.window_seconds:
            self._window_start = now
            self._spent = 0

    def try_spend(self, cost: int = 1) -> bool:
        """Reserve `cost` requests. False means the window is exhausted."""
        self._roll()
        if self.limit is not None and self._spent + cost > self.limit:
            return False
        self._spent += cost
        self._total += cost
        return True
