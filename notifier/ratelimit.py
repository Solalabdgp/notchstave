"""Token buckets for Telegram's two limits, over Redis or in this process.

TZ 5.5 states both limits: **не более 30 сообщений в секунду суммарно, 1 в
секунду на чат.** Two buckets, and every message has to pass both.

**Why both are taken in one operation.** The naive shape — take from the chat
bucket, then take from the global bucket — leaks: when the second take says
"wait", the first bucket has already spent a token on a message that is not
going out yet. Under load that turns a 1/sec chat limit into something slower
and unpredictable, and the direction of the error is not the safe one to reason
about. So both buckets are *peeked*, the caller sleeps for the longer of the two
waits, and only then is a single atomic take attempted against both. Either both
tokens are consumed or neither is. In Redis that atomicity is one Lua script and
one round trip; locally it is the same function without the network.

**Why Redis at all, when there is one notifier process.** TZ section 4 gives the
notifier no per-network sharding, so today one process is the whole fleet and
the local bucket is exactly correct. The Redis path exists because the limit
being enforced belongs to *the bot token*, not to a process: the moment a second
instance starts — a rolling deploy overlapping by ten seconds is enough — two
local buckets each politely send 30/sec and the token gets limited. Coordinating
through Redis costs one round trip per message and removes a failure that only
appears in production.

**How this differs from :mod:`settler.locks`, deliberately.** That module fails
*open*: an unreachable Redis means do the work anyway, because the worst outcome
is wasted CPU and correctness lives in Postgres. Here, failing open means
ignoring a rate limit, and the cost is the bot token getting throttled or banned
— so an unreachable Redis falls back to *local enforcement*, never to *no
enforcement*. The limit still holds for this process; what is lost is only the
coordination between processes. That is a real degradation and it is logged as
one, but it is the strictly better of the two available failure modes.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "RateLimiter",
    "LocalRateLimiter",
    "RedisRateLimiter",
    "NullRateLimiter",
    "RedisLike",
    "TAKE_LUA",
]

log = logging.getLogger("notchstave.notifier.ratelimit")

#: Injected in tests so a "does the bucket hold under load" assertion does not
#: take real seconds. Signature matches :func:`time.monotonic`.
Clock = Callable[[], float]


class RateLimiter(Protocol):
    """Block until this chat is allowed one message under both limits."""

    async def acquire(self, chat_id: int) -> float:
        """Return how long the call waited, in seconds. Zero means no wait."""
        ...


@runtime_checkable
class RedisLike(Protocol):
    """The one call this module needs from ``redis.asyncio.Redis``.

    Structural, for the same two reasons :class:`settler.locks.RedisLike` is:
    the notifier must not import redis when it is not configured, and a test
    must be able to pass a fake without running a server. Declared as returning
    :class:`~collections.abc.Awaitable` rather than with ``async def``, because
    ``async def`` in a Protocol demands a ``Coroutine`` and the real client
    annotates ``eval`` as returning ``Awaitable`` — a Protocol that the actual
    library fails to satisfy describes an idealised client, not this one.
    """

    def eval(self, script: str, numkeys: int, *args: Any) -> Awaitable[Any]: ...


@dataclass(slots=True)
class _Bucket:
    """A classic token bucket, refilled continuously rather than on a tick.

    Continuous refill matters at these numbers: a 1/sec bucket refilled once per
    second delivers a message at t=0.999 and then makes the next one wait a full
    second, while continuous refill makes it wait 0.001.
    """

    capacity: float
    rate: float
    tokens: float
    updated_at: float

    def _refill(self, now: float) -> None:
        # max(0, ...) rather than a bare subtraction: a monotonic clock cannot
        # go backwards, but `updated_at` can be ahead of `now` by a hair when
        # two coroutines interleave between the read and the write.
        elapsed = max(0.0, now - self.updated_at)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated_at = now

    def wait_for(self, now: float) -> float:
        """Seconds until one token exists. Does not consume anything."""
        self._refill(now)
        if self.tokens >= 1.0:
            return 0.0
        return (1.0 - self.tokens) / self.rate

    def take(self, now: float) -> bool:
        self._refill(now)
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


class LocalRateLimiter:
    """Both buckets in this process. Correct for a single-instance notifier.

    Per-chat buckets are evicted once they are full and idle, which is what
    keeps this from being an unbounded map keyed by user id: a full bucket is
    indistinguishable from a bucket that never existed, so forgetting it loses
    nothing. Eviction is amortised over calls rather than run on a timer —
    a background task for a dictionary is a lifecycle to get wrong.
    """

    def __init__(
        self,
        *,
        global_rate: float,
        global_burst: float,
        chat_rate: float,
        chat_burst: float,
        max_wait: float = 30.0,
        clock: Clock | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._clock = clock or time.monotonic
        self._sleep = sleep or asyncio.sleep
        self._chat_rate = chat_rate
        self._chat_burst = chat_burst
        self._max_wait = max_wait
        now = self._clock()
        self._global = _Bucket(
            capacity=global_burst, rate=global_rate, tokens=global_burst, updated_at=now
        )
        self._chats: dict[int, _Bucket] = {}
        # One lock over both buckets. The critical section is arithmetic with no
        # await in it, so this never blocks on I/O — it exists because "peek both,
        # then take both" is only atomic if nothing runs between the two halves.
        self._lock = asyncio.Lock()

    def _chat_bucket(self, chat_id: int, now: float) -> _Bucket:
        bucket = self._chats.get(chat_id)
        if bucket is None:
            bucket = _Bucket(
                capacity=self._chat_burst,
                rate=self._chat_rate,
                tokens=self._chat_burst,
                updated_at=now,
            )
            self._chats[chat_id] = bucket
        return bucket

    def _evict_idle(self, now: float, keep: int) -> None:
        if len(self._chats) <= 1024:
            return
        stale = [
            cid
            for cid, b in self._chats.items()
            if cid != keep and b.tokens + (now - b.updated_at) * b.rate >= b.capacity
        ]
        for cid in stale:
            del self._chats[cid]

    async def acquire(self, chat_id: int) -> float:
        started = self._clock()
        while True:
            async with self._lock:
                now = self._clock()
                chat = self._chat_bucket(chat_id, now)
                wait = max(self._global.wait_for(now), chat.wait_for(now))
                if wait <= 0.0 and self._global.take(now) and chat.take(now):
                    self._evict_idle(now, keep=chat_id)
                    return max(0.0, now - started)
            # Both waits were computed under the lock; sleeping outside it is
            # the whole point, and re-looping afterwards is required rather than
            # optional — another coroutine may have taken the token we waited
            # for. This is a retry loop, not a sleep-then-assume.
            await self._sleep(min(max(wait, 0.001), self._max_wait))


#: Peek both, take both, or take neither. Returns milliseconds to wait; 0 means
#: two tokens were consumed and the caller may send.
#:
#: State is a two-field hash per bucket rather than Redis's own INCR/EXPIRE
#: counter idiom, because a fixed window lets 2x the limit through across a
#: window boundary — at 30/sec that is 60 messages inside one second, which is
#: exactly the burst the limit exists to prevent.
#:
#: TTL is set on every write so an idle chat's key disappears on its own; a full
#: bucket and an absent key mean the same thing, which is what makes expiry safe
#: here rather than a subtle reset of somebody's quota.
TAKE_LUA = """
-- KEYS[1] global bucket, KEYS[2] per-chat bucket
-- ARGV[1] now_ms
-- ARGV[2] global capacity, ARGV[3] global rate/sec
-- ARGV[4] chat capacity,   ARGV[5] chat rate/sec
local now_ms = tonumber(ARGV[1])
local tokens = {}
local wait_ms = 0

for i = 1, 2 do
    local capacity = tonumber(ARGV[i * 2])
    local rate = tonumber(ARGV[i * 2 + 1])
    local state = redis.call('HMGET', KEYS[i], 'tokens', 'ts')
    local have = tonumber(state[1])
    local ts = tonumber(state[2])
    if have == nil or ts == nil then
        have = capacity
        ts = now_ms
    end
    have = math.min(capacity, have + (math.max(0, now_ms - ts) / 1000.0) * rate)
    tokens[i] = have
    if have < 1.0 then
        wait_ms = math.max(wait_ms, math.ceil(((1.0 - have) / rate) * 1000))
    end
end

-- Peek said no: touch nothing. A partial take here is the leak this whole
-- script exists to avoid.
if wait_ms > 0 then
    return wait_ms
end

for i = 1, 2 do
    local capacity = tonumber(ARGV[i * 2])
    local rate = tonumber(ARGV[i * 2 + 1])
    redis.call('HSET', KEYS[i], 'tokens', tokens[i] - 1.0, 'ts', now_ms)
    -- Outlive a full refill by a second: once full, an absent key and a present
    -- one behave identically, so expiry cannot reset anybody's quota.
    redis.call('PEXPIRE', KEYS[i], math.ceil((capacity / rate) * 1000) + 1000)
end
return 0
"""


class RedisRateLimiter:
    """Both buckets in Redis, shared by every notifier instance.

    Falls back to a local limiter — not to nothing — when Redis is unreachable;
    see the module docstring for why that asymmetry with
    :mod:`settler.locks` is deliberate.
    """

    def __init__(
        self,
        redis: RedisLike,
        *,
        global_rate: float,
        global_burst: float,
        chat_rate: float,
        chat_burst: float,
        max_wait: float = 30.0,
        prefix: str = "notchstave:notify:",
        clock: Clock | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._redis = redis
        self._prefix = prefix
        self._global_rate = global_rate
        self._global_burst = global_burst
        self._chat_rate = chat_rate
        self._chat_burst = chat_burst
        self._max_wait = max_wait
        self._clock = clock or time.monotonic
        self._sleep = sleep or asyncio.sleep
        self._degraded = False
        self._fallback = LocalRateLimiter(
            global_rate=global_rate,
            global_burst=global_burst,
            chat_rate=chat_rate,
            chat_burst=chat_burst,
            max_wait=max_wait,
            clock=self._clock,
            sleep=self._sleep,
        )

    async def acquire(self, chat_id: int) -> float:
        started = self._clock()
        global_key = f"{self._prefix}global"
        chat_key = f"{self._prefix}chat:{chat_id}"
        while True:
            try:
                # Redis's own clock, not ours: the buckets are shared, and two
                # instances with a second of drift between them would refill the
                # same bucket at two different rates.
                wait_ms = int(
                    await self._redis.eval(
                        TAKE_LUA,
                        2,
                        global_key,
                        chat_key,
                        str(int(time.time() * 1000)),
                        str(self._global_burst),
                        str(self._global_rate),
                        str(self._chat_burst),
                        str(self._chat_rate),
                    )
                )
            except Exception:  # noqa: BLE001 — degrade to local, never to unlimited
                if not self._degraded:
                    self._degraded = True
                    log.warning(
                        "notifier rate limiter lost Redis; enforcing Telegram limits "
                        "locally only. Correct for one instance, unsafe for several.",
                        exc_info=True,
                    )
                waited = await self._fallback.acquire(chat_id)
                return max(waited, self._clock() - started)

            if self._degraded:
                self._degraded = False
                log.info("notifier rate limiter reconnected to Redis")
            if wait_ms <= 0:
                return max(0.0, self._clock() - started)
            await self._sleep(min(max(wait_ms / 1000.0, 0.001), self._max_wait))


class NullRateLimiter:
    """No limiting at all. Tests only — never selectable from configuration.

    Deliberately not wired into :func:`notifier.main.build_rate_limiter`: the
    Redis-off production path is :class:`LocalRateLimiter`, which still enforces
    both limits. There is no supported way to run this process with the Telegram
    limits switched off, and this class exists so that a test about backoff does
    not have to spend real seconds proving a point about rate limiting.
    """

    async def acquire(self, chat_id: int) -> float:
        del chat_id
        return 0.0


_LOCAL_IS_A_LIMITER: RateLimiter = LocalRateLimiter(
    global_rate=1.0, global_burst=1.0, chat_rate=1.0, chat_burst=1.0
)
_NULL_IS_A_LIMITER: RateLimiter = NullRateLimiter()
