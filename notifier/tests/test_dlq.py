"""The dead-letter queue after N attempts, and the gauge TZ section 7 names."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from notifier import metrics
from notifier.config import NotifierConfig
from notifier.errors import TransientDeliveryError
from notifier.ratelimit import NullRateLimiter
from notifier.sender import RecordingSender
from notifier.service import Notifier
from notifier.tests.conftest import Outbox, sample_value

CONFIG = NotifierConfig(max_attempts=3, backoff_jitter=0.0)


def build(engine: AsyncEngine, sender: RecordingSender) -> Notifier:
    return Notifier(engine, sender=sender, limiter=NullRateLimiter(), config=CONFIG)


async def drain(notifier: Notifier, outbox: Outbox, notification_id: int, passes: int) -> None:
    """Run ``passes`` attempts back to back, skipping the real backoff wait.

    A test that honoured a ten-second backoff three times over is a test nobody
    runs. What is under test here is the attempt *count*, not the clock — the
    schedule itself has its own assertions in ``test_retry_backoff.py``.
    """
    for _ in range(passes):
        await notifier.run_once()
        await outbox.expire_lease(notification_id)


async def test_row_dies_after_max_attempts(engine: AsyncEngine, outbox: Outbox) -> None:
    """TZ 5.5: "после N неудач — DLQ с ручным разбором"."""
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id)

    sender = RecordingSender(script=[TransientDeliveryError("down")] * 10)
    notifier = build(engine, sender)

    await drain(notifier, outbox, notification_id, passes=2)
    assert await outbox.status(notification_id) == "failed"  # still retrying

    result = await notifier.run_once()
    assert (result.dead, result.retried) == (1, 0)

    row = await outbox.row(notification_id)
    assert row["status"] == "dead"
    assert row["attempts"] == 3
    assert "retries_exhausted" in row["last_error"]
    # No schedule on a dead row: nothing in this package will pick it up again.
    assert row["next_attempt_at"] is None


async def test_dead_rows_are_never_reclaimed(engine: AsyncEngine, outbox: Outbox) -> None:
    """"Ручной разбор" means a human, not a loop that keeps trying quietly."""
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id)

    sender = RecordingSender(script=[TransientDeliveryError("down")] * 10)
    notifier = build(engine, sender)
    await drain(notifier, outbox, notification_id, passes=3)

    assert await outbox.status(notification_id) == "dead"
    for _ in range(3):
        assert (await notifier.run_once()).claimed == 0
    assert sender.sent == []


async def test_dead_row_keeps_everything_a_human_needs(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """The row is the triage record — nothing about it is thrown away.

    Week 5's `/dlq` command re-queues by setting ``status = 'queued', attempts =
    0``, which is only safe because the payload, the kind, the ref and the
    ``UNIQUE (kind, ref_id, dedup_key)`` are all still intact. A "cleanup" that
    nulled ``payload_json`` on death would make the DLQ unresolvable.
    """
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(
        user_id=user_id, kind="invoice_settled", ref_id="inv-1", dedup_key="ent-9"
    )

    sender = RecordingSender(script=[TransientDeliveryError("down")] * 10)
    notifier = build(engine, sender)
    await drain(notifier, outbox, notification_id, passes=3)

    row = await outbox.row(notification_id)
    assert row["status"] == "dead"
    assert (row["kind"], row["ref_id"], row["dedup_key"]) == ("invoice_settled", "inv-1", "ent-9")
    assert row["payload_json"]["invoice_id"] == "inv-1"
    assert row["last_error"]


async def test_dlq_entry_is_audited(engine: AsyncEngine, outbox: Outbox) -> None:
    """Append-only trail for the two terminal events (TZ 5.8/T8).

    Not every delivery — thousands of routine rows would bury the `/resolve` and
    `/reconcile` decisions this table exists for.
    """
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id)

    sender = RecordingSender(script=[TransientDeliveryError("down")] * 10)
    notifier = build(engine, sender)
    await drain(notifier, outbox, notification_id, passes=3)

    assert await outbox.audit_count("notifier_dlq") == 1


async def test_dlq_size_gauge_tracks_the_table(engine: AsyncEngine, outbox: Outbox) -> None:
    """``notchstave_dlq_size`` (TZ section 7), set from a count on every pass.

    Including the passes that find nothing: an explicit zero is what separates
    "nothing is stuck" from "the notifier has not run since the last restart",
    which look identical on a gauge only touched when something is wrong.
    """
    user_id = await outbox.user()
    first = await outbox.enqueue(user_id=user_id, dedup_key="a")
    second = await outbox.enqueue(user_id=user_id, dedup_key="b")

    sender = RecordingSender(script=[TransientDeliveryError("down")] * 30)
    notifier = build(engine, sender)
    for _ in range(3):
        await notifier.run_once()
        await outbox.expire_lease(first)
        await outbox.expire_lease(second)

    result = await notifier.run_once()
    assert result.dlq_size == 2
    assert sample_value(metrics.DLQ_SIZE) == 2.0

    # A human resolves them; the gauge follows the table down rather than
    # staying red because it once was.
    async with engine.begin() as conn:
        await conn.execute(sa.text("UPDATE notifications SET status = 'queued', attempts = 0"))

    sender.script = []
    after = await notifier.run_once()
    assert after.sent == 2
    assert after.dlq_size == 0
    assert sample_value(metrics.DLQ_SIZE) == 0.0


async def test_unrenderable_kind_lands_in_the_dlq(engine: AsyncEngine, outbox: Outbox) -> None:
    """A kind nobody wrote a renderer for is visible, not invented.

    The alternative — a generic "something happened with your invoice" fallback
    — keeps the queue draining and sends a user a message about their money that
    nobody wrote. This way the omission shows up on ``notchstave_dlq_size`` and
    the message is recoverable once the renderer exists.
    """
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id, kind="something_new_in_week_7")

    sender = RecordingSender()
    result = await build(engine, sender).run_once()

    assert (result.dead, result.sent) == (1, 0)
    assert sender.sent == []
    row = await outbox.row(notification_id)
    assert row["status"] == "dead"
    assert "no_renderer" in row["last_error"]
    # No token spent, no attempt wasted beyond the claim.
    assert row["attempts"] == 1


async def test_payload_missing_a_required_field_lands_in_the_dlq(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """TZ 3.5 wants "точную недостающую сумму и тот же адрес для доплаты".

    A top-up message with a blank address is worse than no message: it is an
    instruction the user can follow into losing money. A missing field is a bug
    to be seen, not a hole to be papered over with ``.get(..., "")``.
    """
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(
        user_id=user_id,
        kind="invoice_underpaid",
        payload={"invoice_id": "inv-1", "missing_raw": "5", "asset": "USDC"},  # no address
    )

    sender = RecordingSender()
    result = await build(engine, sender).run_once()

    assert result.dead == 1
    assert sender.sent == []
    assert "address" in (await outbox.row(notification_id))["last_error"]
