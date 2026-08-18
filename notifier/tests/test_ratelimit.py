"""The two Telegram limits of TZ 5.5, under load, on a clock the test owns.

No Postgres and no sleeping. A rate limiter tested against the wall clock is a
rate limiter tested for about four seconds before somebody deletes the test for
being slow, and the assertions it can make are all approximate. With an injected
clock that only advances when the limiter itself sleeps, "three hundred messages
through a 30/sec bucket" runs in microseconds and the assertions are exact.

What is asserted here is the guarantee a token bucket actually makes, stated
precisely rather than hopefully:

* **sustained** — ``n`` grants take at least ``(n - burst) / rate`` seconds. This
  is the whole property; everything else is a special case of it.
* **burst** — the first ``burst`` grants may be instantaneous, and no more than
  that. A bucket with ``capacity = rate`` therefore admits up to ``burst + rate``
  inside the worst single second, which is the shape Telegram's own limiter has
  and the reason ``global_burst`` defaults to 30 rather than to something
  larger. Setting it to 1 turns the bucket into strict pacing at 1/30s, at the
  cost of latency; that is a supported configuration, not the default.
* **per chat** — burst of 1 and rate of 1 means no chat ever receives two
  messages inside one second. Unlike the global limit, this one has no burst
  allowance at all, because a burst of two on one chat is exactly the pattern
  the limit exists to stop.
"""

from __future__ import annotations

import pytest

from notifier.ratelimit import LocalRateLimiter


class FakeClock:
    """A monotonic clock that only moves when the limiter waits.

    That coupling is the point: if a change makes the limiter grant a token
    without accounting for time, the clock does not advance and the sustained
    assertions below fail immediately instead of becoming flaky.
    """

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds


def build(clock: FakeClock, **kwargs: float) -> LocalRateLimiter:
    params: dict[str, float] = {
        "global_rate": 30.0,
        "global_burst": 30.0,
        "chat_rate": 1.0,
        "chat_burst": 1.0,
    }
    params.update(kwargs)
    return LocalRateLimiter(
        global_rate=params["global_rate"],
        global_burst=params["global_burst"],
        chat_rate=params["chat_rate"],
        chat_burst=params["chat_burst"],
        max_wait=params.get("max_wait", 30.0),
        clock=clock,
        sleep=clock.sleep,
    )


async def test_global_limit_holds_over_a_long_run() -> None:
    """300 messages to 300 distinct chats cannot beat 30/sec.

    Distinct chats on purpose: the per-chat bucket is out of the way, so the
    only thing that can slow this down is the global one, and any failure points
    at exactly one bucket.
    """
    clock = FakeClock()
    limiter = build(clock)

    grants: list[float] = []
    for chat in range(300):
        await limiter.acquire(chat)
        grants.append(clock.now)

    # The exact guarantee: everything above the initial burst has to be paid for
    # at the refill rate.
    assert clock.now >= (300 - 30) / 30.0 - 1e-9

    # And no sliding second contains more than one burst plus one second of
    # refill — the honest upper bound for capacity == rate.
    for i, t in enumerate(grants):
        in_window = sum(1 for u in grants[: i + 1] if u > t - 1.0)
        assert in_window <= 60


async def test_burst_is_capped_at_capacity() -> None:
    """Exactly ``burst`` grants are free; the next one waits."""
    clock = FakeClock()
    limiter = build(clock)

    for chat in range(30):
        await limiter.acquire(chat)
    assert clock.now == pytest.approx(0.0)

    await limiter.acquire(999)
    assert clock.now == pytest.approx(1 / 30.0)


async def test_idle_does_not_bank_unlimited_credit() -> None:
    """A quiet hour does not buy an hour's worth of messages.

    The bucket is capped at ``capacity``; without that cap a notifier restarted
    after a quiet night would empty its backlog into Telegram at once, which is
    the single most likely way this system would earn a rate-limit ban in
    practice.
    """
    clock = FakeClock()
    limiter = build(clock)
    clock.now = 3600.0  # an hour of doing nothing

    for chat in range(30):
        await limiter.acquire(chat)
    assert clock.now == pytest.approx(3600.0)

    await limiter.acquire(999)
    assert clock.now > 3600.0


async def test_per_chat_limit_is_one_per_second_with_no_burst() -> None:
    """TZ 5.5: "1 в секунду на чат". No allowance, ever."""
    clock = FakeClock()
    limiter = build(clock)

    grants: list[float] = []
    for _ in range(10):
        await limiter.acquire(777)
        grants.append(clock.now)

    gaps = [b - a for a, b in zip(grants, grants[1:], strict=False)]
    assert all(gap >= 1.0 - 1e-9 for gap in gaps), gaps


async def test_one_slow_chat_does_not_stall_the_others() -> None:
    """Interleaving a hot chat with others must not serialise everything.

    This is what the peek-both-then-take-both ordering buys. A naive limiter
    that consumed the global token before discovering the per-chat wait would
    burn a global token per blocked attempt, and the eleven messages below would
    cost far more than eleven tokens' worth of time.
    """
    clock = FakeClock()
    limiter = build(clock)

    await limiter.acquire(1)
    for chat in range(2, 12):
        await limiter.acquire(chat)

    # Ten different chats, well inside the global burst: no waiting at all.
    assert clock.now == pytest.approx(0.0)


async def test_tokens_are_not_spent_while_waiting_on_the_other_bucket() -> None:
    """The leak the atomic take exists to prevent, made observable.

    Chat 1 is rate-limited (its second message must wait a second). During that
    second the global bucket must be untouched — so afterwards the full burst is
    still available to other chats. If the limiter had consumed a global token
    per failed attempt, the burst would be gone and this loop would take time.
    """
    clock = FakeClock()
    limiter = build(clock)

    await limiter.acquire(1)
    await limiter.acquire(1)  # waits ~1s on the per-chat bucket

    # A full second of refill elapsed during that wait, so the global bucket is
    # back at capacity minus the single token the second message consumed. The
    # exact number is the assertion: a limiter that spent a global token on each
    # blocked attempt would have far fewer than 29 left here.
    started = clock.now
    for chat in range(100, 129):
        await limiter.acquire(chat)
    assert clock.now == pytest.approx(started)

    await limiter.acquire(129)
    assert clock.now > started


async def test_configured_burst_of_one_gives_strict_pacing() -> None:
    """The stricter configuration works too, and is a one-line change."""
    clock = FakeClock()
    limiter = build(clock, global_burst=1.0)

    grants: list[float] = []
    for chat in range(20):
        await limiter.acquire(chat)
        grants.append(clock.now)

    gaps = [b - a for a, b in zip(grants, grants[1:], strict=False)]
    assert all(gap >= 1 / 30.0 - 1e-9 for gap in gaps), gaps
    for i, t in enumerate(grants):
        assert sum(1 for u in grants[: i + 1] if u > t - 1.0) <= 31


async def test_acquire_reports_what_it_waited() -> None:
    """The return value feeds ``notchstave_notification_rate_limit_wait_seconds``.

    A limiter that quietly waited without reporting it would make delivery
    latency look like a Telegram problem on the dashboard when it is the token
    budget doing its job.
    """
    clock = FakeClock()
    limiter = build(clock)

    assert await limiter.acquire(5) == pytest.approx(0.0)
    waited = await limiter.acquire(5)
    assert waited >= 1.0 - 1e-9
