"""Redis removed entirely — delivery still works, limits still hold.

This file is the notifier's counterpart to the settler's "broken lock" case, and
it exists for the same reason: the repo makes a standing claim that PostgreSQL
carries correctness and Redis is an optimisation (TZ 5.8/T2.4), and a claim of
that kind is worth exactly as much as the test that enforces it.

The notifier's version of the claim is narrower and has to be stated carefully,
because the two components use Redis for different things and a copy-pasted
"fails open" here would be a bug:

* the **settler** uses Redis for an advisory lock, so an unreachable Redis means
  do the work anyway — the worst outcome is wasted CPU;
* the **notifier** uses Redis for a rate limiter, so failing open would mean
  ignoring a Telegram limit, and the worst outcome is a throttled or banned bot
  token.

So the notifier's guarantee is not "works without Redis" but "works without
Redis *and still enforces both limits*, losing only the coordination between
instances". Both halves are asserted below.
"""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from notifier.config import NotifierConfig
from notifier.main import build_rate_limiter
from notifier.ratelimit import LocalRateLimiter, RedisRateLimiter
from notifier.sender import RecordingSender
from notifier.service import Notifier
from notifier.tests.conftest import Outbox
from notifier.tests.test_ratelimit import FakeClock


class DeadRedis:
    """Every call raises. What an unreachable server looks like from here.

    Raises synchronously rather than returning a failing awaitable, because that
    is the harder case for the caller: an exception thrown before any ``await``
    skips a ``try`` block placed around the wrong expression.
    """

    def eval(self, script: str, numkeys: int, *args: Any) -> Awaitable[Any]:
        raise ConnectionError("redis is gone")


async def test_delivery_works_with_no_redis_configured(
    engine: AsyncEngine, outbox: Outbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole outbox drains with ``REDIS_URL`` unset.

    Nothing in the delivery path touches Redis — the claim, the lease, the retry
    schedule and the DLQ are all Postgres — so this is a statement about the one
    place that could have crept in.
    """
    monkeypatch.delenv("REDIS_URL", raising=False)
    limiter = build_rate_limiter(
        NotifierConfig(global_rate_per_second=1000.0, chat_rate_per_second=1000.0)
    )
    assert isinstance(limiter, LocalRateLimiter)

    user_id = await outbox.user()
    for i in range(5):
        await outbox.enqueue(user_id=user_id, dedup_key=str(i))

    sender = RecordingSender()
    result = await Notifier(engine, sender=sender, limiter=limiter).run_once()

    assert (result.claimed, result.sent, result.dead) == (5, 5, 0)


async def test_no_redis_still_enforces_both_limits() -> None:
    """The half that makes this different from the settler's lock.

    A "graceful degradation" that dropped the limits would look identical in the
    delivery test above and would get the bot token throttled in production.
    """
    monkey_clock = FakeClock()
    limiter = LocalRateLimiter(
        global_rate=30.0,
        global_burst=30.0,
        chat_rate=1.0,
        chat_burst=1.0,
        clock=monkey_clock,
        sleep=monkey_clock.sleep,
    )

    for chat in range(120):
        await limiter.acquire(chat)
    assert monkey_clock.now >= (120 - 30) / 30.0 - 1e-9

    before = monkey_clock.now
    await limiter.acquire(0)  # already served above, so the per-chat bucket bites
    assert monkey_clock.now - before > 0.0


async def test_redis_going_away_mid_flight_degrades_to_local_limits() -> None:
    """A limiter that loses its server keeps limiting, it does not stop.

    Falling back to the in-process buckets is a real degradation — the limits
    become per-instance rather than per-token — and it is the strictly better of
    the two available failure modes. The alternative, failing open, is the one
    that costs a bot token.
    """
    clock = FakeClock()
    limiter = RedisRateLimiter(
        DeadRedis(),
        global_rate=30.0,
        global_burst=30.0,
        chat_rate=1.0,
        chat_burst=1.0,
        clock=clock,
        sleep=clock.sleep,
    )

    for chat in range(60):
        await limiter.acquire(chat)

    assert clock.now >= (60 - 30) / 30.0 - 1e-9


async def test_unreachable_redis_does_not_break_delivery(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """The end-to-end version: messages still go out."""
    clock = FakeClock()
    limiter = RedisRateLimiter(
        DeadRedis(),
        global_rate=1000.0,
        global_burst=1000.0,
        chat_rate=1000.0,
        chat_burst=1000.0,
        clock=clock,
        sleep=clock.sleep,
    )

    user_id = await outbox.user()
    for i in range(3):
        await outbox.enqueue(user_id=user_id, dedup_key=str(i))

    sender = RecordingSender()
    result = await Notifier(engine, sender=sender, limiter=limiter).run_once()

    assert (result.claimed, result.sent) == (3, 3)
