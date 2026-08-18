"""Retries with backoff (TZ 5.5), and the line between transient and permanent."""

from __future__ import annotations

import datetime as dt
import random

from sqlalchemy.ext.asyncio import AsyncEngine

from notifier.backoff import is_exhausted, next_delay_seconds
from notifier.config import NotifierConfig
from notifier.errors import (
    PermanentDeliveryError,
    RateLimitedError,
    TransientDeliveryError,
)
from notifier.ratelimit import NullRateLimiter
from notifier.sender import RecordingSender
from notifier.service import Notifier
from notifier.tests.conftest import Outbox

CONFIG = NotifierConfig(max_attempts=4, backoff_base_seconds=10.0, backoff_jitter=0.0)


def build(engine: AsyncEngine, sender: RecordingSender) -> Notifier:
    return Notifier(engine, sender=sender, limiter=NullRateLimiter(), config=CONFIG)


# --------------------------------------------------------------------------
# The curve, as arithmetic
# --------------------------------------------------------------------------


def test_backoff_doubles_and_is_capped() -> None:
    config = NotifierConfig(backoff_base_seconds=5.0, backoff_max_seconds=100.0, backoff_jitter=0.0)
    delays = [next_delay_seconds(n, config) for n in range(1, 8)]
    assert delays == [5.0, 10.0, 20.0, 40.0, 80.0, 100.0, 100.0]


def test_jitter_spreads_but_stays_near_the_curve() -> None:
    """Every retry of one outage is scheduled within seconds of every other.

    Without jitter the whole backlog retries at the same instants for as long as
    the outage lasts, which turns a Telegram wobble into a self-inflicted
    thundering herd against it.
    """
    config = NotifierConfig(backoff_base_seconds=10.0, backoff_jitter=0.25)
    rng = random.Random(20260819)
    samples = [next_delay_seconds(3, config, rng=rng) for _ in range(500)]

    assert all(30.0 <= s <= 50.0 for s in samples)
    assert len(set(samples)) > 400  # actually spread, not a constant
    assert 38.0 < sum(samples) / len(samples) < 42.0


def test_telegram_retry_after_overrides_the_curve() -> None:
    """429 carries the real answer; our exponent is a guess about a server we
    cannot see (TZ 5.5 rate limits)."""
    config = NotifierConfig(backoff_base_seconds=10.0, backoff_jitter=0.0)
    assert next_delay_seconds(5, config, retry_after=3.0) == 3.0
    assert next_delay_seconds(1, config, retry_after=900.0) == 900.0


def test_huge_attempt_counts_do_not_explode() -> None:
    """``attempts`` is a column a human with a re-queue command can set."""
    config = NotifierConfig(backoff_max_seconds=1800.0, backoff_jitter=0.0)
    assert next_delay_seconds(4000, config) == 1800.0


def test_exhaustion_counts_the_attempt_in_hand() -> None:
    """``attempts`` is incremented at claim time, so the sixth failure is the last."""
    config = NotifierConfig(max_attempts=6)
    assert not is_exhausted(5, config)
    assert is_exhausted(6, config)
    assert is_exhausted(7, config)


# --------------------------------------------------------------------------
# The curve, applied to a real row
# --------------------------------------------------------------------------


async def test_transient_failure_schedules_a_retry(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id)

    sender = RecordingSender(script=[TransientDeliveryError("telegram 502")])
    result = await build(engine, sender).run_once()

    assert (result.sent, result.retried, result.dead) == (0, 1, 0)
    row = await outbox.row(notification_id)
    assert row["status"] == "failed"
    assert row["attempts"] == 1
    assert "telegram 502" in row["last_error"]
    assert row["sent_at"] is None
    assert row["message_id"] is None

    # Backoff for attempt 2 is 10s with jitter off, so the row is not eligible
    # again on the very next pass — which is the whole point of scheduling it.
    assert row["next_attempt_at"] > dt.datetime.now(dt.UTC)
    assert (await build(engine, sender).run_once()).claimed == 0


async def test_retry_eventually_succeeds_and_sends_once(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """"Fail twice, then work" — and the user gets exactly one message."""
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id)

    sender = RecordingSender(
        script=[TransientDeliveryError("boom"), TransientDeliveryError("boom again")]
    )
    notifier = build(engine, sender)

    assert (await notifier.run_once()).retried == 1
    await outbox.expire_lease(notification_id)
    assert (await notifier.run_once()).retried == 1
    await outbox.expire_lease(notification_id)
    assert (await notifier.run_once()).sent == 1

    assert len(sender.sent) == 1
    row = await outbox.row(notification_id)
    assert row["status"] == "sent"
    assert row["attempts"] == 3
    # The error from the last failed attempt is cleared on success: a `sent` row
    # carrying a `last_error` reads as a delivery that half-worked.
    assert row["last_error"] is None


async def test_rate_limited_uses_telegrams_own_delay(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id)

    sender = RecordingSender(script=[RateLimitedError(retry_after=45.0)])
    await build(engine, sender).run_once()

    row = await outbox.row(notification_id)
    scheduled = row["next_attempt_at"] - dt.datetime.now(dt.UTC)
    # 45s from Telegram, not the 10s this config's curve would have chosen.
    assert dt.timedelta(seconds=35) < scheduled < dt.timedelta(seconds=55)


async def test_permanent_failure_skips_the_retry_budget(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """A message Telegram will never accept must not consume four attempts.

    Attempts spent on a hopeless row are attempts not spent on rows that could
    still land, and they are exactly the traffic that gets a bot throttled.
    """
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id)

    sender = RecordingSender(script=[PermanentDeliveryError("chat not found")])
    result = await build(engine, sender).run_once()

    assert (result.dead, result.retried) == (1, 0)
    row = await outbox.row(notification_id)
    assert row["status"] == "dead"
    assert row["attempts"] == 1  # one, not max_attempts
    assert "permanent" in row["last_error"]


async def test_unknown_exception_is_treated_as_transient(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """The cheap mistake, on purpose (see ``notifier.errors``).

    An unclassified error retried is a few wasted calls; an unclassified error
    dropped is a silent loss of a message about somebody's money.
    """
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id)

    sender = RecordingSender(script=[RuntimeError("something nobody mapped")])
    result = await build(engine, sender).run_once()

    assert (result.retried, result.dead) == (1, 0)
    assert await outbox.status(notification_id) == "failed"
