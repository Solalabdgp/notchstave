"""TZ 5.5: "Пользователь заблокировал бота — помечаем и прекращаем слать."

Two obligations in one sentence, and they are tested as two things because they
fail independently: marking without stopping is a flag nobody acts on, and
stopping without marking is a queue that silently stalls.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine

from notifier import metrics, repository
from notifier.config import NotifierConfig
from notifier.ratelimit import NullRateLimiter
from notifier.sender import RecordingSender
from notifier.service import Notifier
from notifier.tests.conftest import Outbox, sample_value


def build(engine: AsyncEngine, sender: RecordingSender) -> Notifier:
    return Notifier(
        engine,
        sender=sender,
        limiter=NullRateLimiter(),
        config=NotifierConfig(max_attempts=6, backoff_jitter=0.0),
    )


async def test_403_marks_the_user_and_does_not_retry(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    user_id = await outbox.user(tg_id=555)
    notification_id = await outbox.enqueue(user_id=user_id)

    sender = RecordingSender(blocked_chats={555})
    notifier = build(engine, sender)
    result = await notifier.run_once()

    assert (result.dead, result.retried, result.sent) == (1, 0, 0)
    assert await outbox.blocked_at(user_id) is not None

    row = await outbox.row(notification_id)
    assert row["status"] == "dead"
    # One attempt, not six: a blocked chat is permanent, and the retry budget is
    # for messages that might still land.
    assert row["attempts"] == 1
    assert "bot_blocked" in row["last_error"]


async def test_everything_else_queued_for_that_user_is_retired(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """The "прекращаем слать" half, and the reason it is not simply skipping.

    Rows for a blocked user are invisible to the claim query, so leaving them
    ``queued`` would be quieter and wrong twice over: they accumulate forever,
    and an operator reading the outbox cannot tell "never delivered because
    blocked" from "not delivered yet".
    """
    user_id = await outbox.user(tg_id=555)
    for i in range(5):
        await outbox.enqueue(user_id=user_id, dedup_key=str(i))

    sender = RecordingSender(blocked_chats={555})
    result = await build(engine, sender).run_once()

    # One send attempt discovered the block; the rest never reached Telegram.
    assert len(sender.sent) == 0
    assert await outbox.count("status = 'dead'") == 5
    assert await outbox.count("status IN ('queued', 'failed')") == 0
    assert result.claimed >= 1


async def test_a_blocked_user_is_never_claimed_again(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """Rows written *after* the block are not attempted either.

    The settler goes on writing outbox rows — it does not know or care that a
    buyer blocked the bot — so the claim query carries ``bot_blocked_at IS
    NULL`` rather than relying on the retirement sweep having already run.
    """
    blocked = await outbox.user(tg_id=555, blocked=True)
    ok = await outbox.user(tg_id=556)
    await outbox.enqueue(user_id=blocked)
    await outbox.enqueue(user_id=ok)

    sender = RecordingSender(blocked_chats={555})
    result = await build(engine, sender).run_once()

    assert result.claimed == 1
    assert [m.chat_id for m in sender.sent] == [556]


async def test_other_users_are_untouched(engine: AsyncEngine, outbox: Outbox) -> None:
    """One buyer blocking the bot must not retire another buyer's receipt."""
    blocked = await outbox.user(tg_id=555)
    other = await outbox.user(tg_id=666)
    await outbox.enqueue(user_id=blocked)
    other_row = await outbox.enqueue(user_id=other)

    sender = RecordingSender(blocked_chats={555})
    await build(engine, sender).run_once()

    assert await outbox.status(other_row) == "sent"
    assert await outbox.blocked_at(other) is None
    assert [m.chat_id for m in sender.sent] == [666]


async def test_blocking_is_recorded_once_and_audited(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """``bot_blocked_at`` answers "when did they block us", not "when did we last try".

    Re-stamping it on every later attempt would overwrite the only piece of
    information the column carries; ``notifications.next_attempt_at`` is where
    "when did we last try" lives.
    """
    user_id = await outbox.user(tg_id=555)
    await outbox.enqueue(user_id=user_id, dedup_key="a")

    sender = RecordingSender(blocked_chats={555})
    notifier = build(engine, sender)
    before = sample_value(metrics.USERS_BLOCKED, "_total")
    await notifier.run_once()

    first_seen = await outbox.blocked_at(user_id)
    assert first_seen is not None
    assert sample_value(metrics.USERS_BLOCKED, "_total") - before == 1.0
    assert await outbox.audit_count("notifier_bot_blocked") == 1

    # A second row for the same user cannot even be claimed now, so the mark
    # cannot be re-stamped by the normal path. Force the situation anyway.
    async with engine.begin() as conn:
        assert await repository.block_user(conn, user_id=user_id) is False
    assert await outbox.blocked_at(user_id) == first_seen
