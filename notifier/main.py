"""Notifier process entrypoint — outbox drain, retries, DLQ, Telegram limits.

Reads the transactional outbox (``core.db.models.Notification``) that the
settler writes in the same transaction as the money decision, and delivers it.
Makes no decisions about money itself (TZ sections 4, 5.7) — the grants of
migrations 0002/0004 make that structural rather than a promise: this process
cannot insert an outbox row, cannot write ``entitlements``, and can write
exactly one column of ``users``.

A poll loop, like :mod:`settler.main`, and for a related reason: the work is a
function of database state, so a missed tick costs latency and nothing else.
TZ 5.7 asks for "очередь на Redis отдельно от очереди индексации" — and the
separation the sentence is really about is that delivery must not share fate
with block indexing, which is satisfied here by the two being different
processes against different tables. Redis carries the part that genuinely needs
to be shared between instances, which is the rate limiter (:mod:`notifier
.ratelimit`), not the work items; a Redis queue in front of an outbox that is
already durable, ordered and idempotent would add a second place for a message
to be lost. If throughput ever demands one, the claim query is where it goes.

**Adaptive pacing.** A pass that filled its batch loops again immediately — a
backlog is drained at whatever rate the token bucket allows, not at one batch
per poll interval. A pass that found nothing sleeps. The rate limiter, not the
loop, is what protects Telegram, and conflating the two is how a queue that is
already behind falls further behind.

Not wired here, with owners named:

* ``/metrics`` — TZ section 7 puts the endpoint on the api process. This
  package declares the collectors (:mod:`notifier.metrics`) and nothing else.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from contextlib import suppress

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from core.db.roles import process_database_url
from notifier.config import NotifierConfig
from notifier.ratelimit import LocalRateLimiter, RateLimiter, RedisRateLimiter
from notifier.sender import DryRunSender, MessageSender
from notifier.service import Notifier

log = logging.getLogger("notchstave.notifier")

__all__ = ["build_engine", "build_rate_limiter", "build_sender", "main"]


def _database_url() -> str:
    """``NOTIFIER_DATABASE_URL`` — this process's own login, not the owner's.

    The notifier connects as ``notchstave_notifier_login`` (a member of
    ``notchstave_notifier``), whose grants are: UPDATE on ``notifications``,
    SELECT on what a message renders from, INSERT on ``audit_log``, and no write
    anywhere near money. Under the previous shared ``DATABASE_URL`` — the schema
    owner — none of that was enforced, because an owner is never denied anything
    on its own tables. See :mod:`core.db.roles`.
    """
    return process_database_url("notifier")


def build_engine(url: str | None = None) -> AsyncEngine:
    return create_async_engine(url or _database_url(), pool_pre_ping=True)


def build_rate_limiter(config: NotifierConfig) -> RateLimiter:
    """Redis if configured, this process's own buckets if not.

    Both enforce the TZ 5.5 limits. The difference is only whose limits they
    are: with Redis, every notifier instance shares one budget; without it,
    each instance has its own, which is correct while there is one instance and
    wrong the moment a deploy overlaps two. There is deliberately no third
    option that turns limiting off — see :class:`notifier.ratelimit
    .NullRateLimiter`.
    """
    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        log.warning(
            "REDIS_URL is not set: enforcing Telegram limits per process. Correct "
            "for a single notifier instance, unsafe for several (TZ 5.5)."
        )
        return LocalRateLimiter(
            global_rate=config.global_rate_per_second,
            global_burst=config.global_burst,
            chat_rate=config.chat_rate_per_second,
            chat_burst=config.chat_burst,
            max_wait=config.max_rate_limit_wait_seconds,
        )

    from redis.asyncio import Redis  # imported lazily: optional dependency

    return RedisRateLimiter(
        Redis.from_url(redis_url, decode_responses=True),
        global_rate=config.global_rate_per_second,
        global_burst=config.global_burst,
        chat_rate=config.chat_rate_per_second,
        chat_burst=config.chat_burst,
        max_wait=config.max_rate_limit_wait_seconds,
        prefix=config.redis_prefix,
    )


def build_sender() -> MessageSender:
    """The real Telegram transport, or the dry run if explicitly asked for.

    The dry run stays selectable and stays *not the default*, because a sender
    that always succeeds without sending marks every outbox row ``sent`` — and
    the outbox is the one structure whose entire value is that an undelivered
    message about somebody's money is still there tomorrow. Defaulting to a
    no-op would drain the queue into nothing on the first accidental start
    against a production database.

    The order is dry-run first, then the token, so that ``NOTIFIER_DRY_RUN=1``
    works on a machine with no credential installed. A missing token with the
    flag unset is a startup failure rather than a silent downgrade: the two
    states this function must never confuse are "delivering" and "pretending
    to".

    **The bot and the notifier hold separate sessions of the same token, on
    purpose.** They are separate systemd units (TZ section 4) and a shared
    ``Bot`` object would mean a shared process. Telegram's limits are per bot,
    not per connection, and that is what :mod:`notifier.ratelimit` is for —
    with Redis configured the two processes share one budget, which is the
    arrangement TZ 5.5 describes.
    """
    if os.environ.get("NOTIFIER_DRY_RUN") == "1":
        log.warning("NOTIFIER_DRY_RUN=1: messages are logged, not sent, and marked delivered")
        return DryRunSender()

    # Imported here, not at module scope: `notifier.sender` defines the protocol
    # and the tests exercise the whole delivery loop through it without a
    # Telegram client installed at all (notifier/tests/requirements.txt). A
    # top-level import would make that impossible, the same way it would for the
    # optional Redis client above.
    from aiogram import Bot

    from core.telegram import load_bot_token
    from notifier.telegram import AiogramSender

    return AiogramSender(Bot(token=load_bot_token()))


async def run_forever(notifier: Notifier, *, stopping: asyncio.Event) -> None:
    config = notifier.config
    while not stopping.is_set():
        try:
            result = await notifier.run_once()
        except Exception:  # noqa: BLE001 — a bad pass must not kill the loop
            log.exception("notifier pass failed")
            with suppress(TimeoutError):
                await asyncio.wait_for(stopping.wait(), timeout=config.poll_interval_seconds)
            continue

        if result.claimed:
            log.info(
                "pass: claimed=%d sent=%d retried=%d dead=%d stale=%d dlq=%d",
                result.claimed,
                result.sent,
                result.retried,
                result.dead,
                result.stale,
                result.dlq_size,
            )
        if result.claimed >= config.batch:
            # Full batch: there is more waiting. Loop without sleeping and let
            # the token bucket set the pace.
            continue
        with suppress(TimeoutError):
            await asyncio.wait_for(stopping.wait(), timeout=config.poll_interval_seconds)


async def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    config = NotifierConfig.from_env()

    engine = build_engine()
    notifier = Notifier(
        engine,
        sender=build_sender(),
        limiter=build_rate_limiter(config),
        config=config,
    )

    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):  # Windows has no SIGTERM handler
            loop.add_signal_handler(sig, stopping.set)

    log.info(
        "notifier started: batch=%d max_attempts=%d limits=%.0f/s global, %.0f/s per chat",
        config.batch,
        config.max_attempts,
        config.global_rate_per_second,
        config.chat_rate_per_second,
    )
    try:
        await run_forever(notifier, stopping=stopping)
    finally:
        await engine.dispose()
        log.info("notifier stopped")


if __name__ == "__main__":
    asyncio.run(main())
