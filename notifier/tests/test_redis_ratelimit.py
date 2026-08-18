"""The Lua half of the rate limiter, against a real Redis.

Skipped when ``REDIS_URL`` is unset so a developer without a server still gets
the whole delivery suite; ``docker-compose.test.yml`` sets it, so CI does not
skip. The reason this file exists at all, when ``test_ratelimit.py`` already
covers the algorithm exhaustively against the in-process implementation, is that
:data:`notifier.ratelimit.TAKE_LUA` is the one piece of this package that cannot
be verified by reading it — Lua inside a string, executed by another process,
against a data model (a hash of two string fields) that Python never sees.

These tests use the wall clock and therefore make coarse assertions. That is the
right trade: the fine-grained properties are already pinned down on a fake clock
next door, and what is being checked here is that the script is syntactically
valid, atomic, and refills the way the Python version does.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncGenerator

import pytest

from notifier.ratelimit import RedisRateLimiter
from notifier.tests.conftest import redis_url

REDIS_URL = redis_url()

# asyncio_mode is `auto` (root pyproject), so only the skip needs declaring.
pytestmark = pytest.mark.skipif(REDIS_URL is None, reason="REDIS_URL not set")


@pytest.fixture
async def limiter() -> AsyncGenerator[RedisRateLimiter, None]:
    from redis.asyncio import Redis

    client = Redis.from_url(str(REDIS_URL), decode_responses=True)
    # A per-test prefix instead of FLUSHDB: the tests must be safe to point at a
    # shared Redis, and a suite that flushes somebody's database to get a clean
    # slate is a suite that eventually flushes the wrong one.
    prefix = f"notchstave:test:{uuid.uuid4().hex}:"
    try:
        yield RedisRateLimiter(
            client,
            global_rate=50.0,
            global_burst=5.0,
            chat_rate=5.0,
            chat_burst=1.0,
            prefix=prefix,
        )
    finally:
        await client.aclose()


async def test_script_runs_and_grants_the_burst(limiter: RedisRateLimiter) -> None:
    """Syntax, argument order, and the empty-key branch, in one assertion."""
    started = time.monotonic()
    for chat in range(5):
        assert await limiter.acquire(chat) == pytest.approx(0.0, abs=0.05)
    assert time.monotonic() - started < 0.2


async def test_beyond_the_burst_the_caller_waits(limiter: RedisRateLimiter) -> None:
    """Refill arithmetic survives the round trip through two hash fields."""
    for chat in range(5):
        await limiter.acquire(chat)

    started = time.monotonic()
    await limiter.acquire(99)
    elapsed = time.monotonic() - started
    # 50/sec global, one token short: ~20ms. Generous upper bound because this
    # one is on the wall clock and shares a machine with a Postgres container.
    assert 0.005 < elapsed < 1.0


async def test_per_chat_bucket_is_independent_of_the_global_one(
    limiter: RedisRateLimiter,
) -> None:
    """Two keys, two refill rates, one atomic take."""
    await limiter.acquire(7)

    started = time.monotonic()
    await limiter.acquire(7)  # 5/sec per chat -> ~200ms
    same_chat = time.monotonic() - started

    started = time.monotonic()
    await limiter.acquire(8)  # a fresh chat, global has refilled by now
    other_chat = time.monotonic() - started

    assert same_chat > other_chat
    assert same_chat > 0.05


async def test_a_blocked_take_consumes_nothing(limiter: RedisRateLimiter) -> None:
    """The leak the script exists to prevent, checked against the real thing.

    Chat 7 is over its per-chat limit. While that wait plays out, the global
    bucket must be untouched — so a different chat is served immediately
    afterwards. If the script consumed the global token before discovering the
    per-chat shortfall, that second call would have to wait too.
    """
    await limiter.acquire(7)
    await limiter.acquire(7)

    started = time.monotonic()
    await limiter.acquire(1234)
    assert time.monotonic() - started < 0.1
