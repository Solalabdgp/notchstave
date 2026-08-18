"""One decision, one row, one message — and where each of those is enforced.

TZ 3.5 asks for "ни одного дубликата при перезапуске любого компонента". The
guarantee is layered, and the layers are tested separately because they protect
against different failures:

1. ``UNIQUE (kind, ref_id, dedup_key)`` — the settler cannot enqueue the same
   decision twice, however many times settlement is re-run. This is where
   idempotency actually lives, and it lives in the database rather than in
   Python on purpose. The notifier deliberately adds no second dedup cache: a
   Python-side "have I sent this" set can disagree with the table, and a
   constraint cannot.
2. the claim lease — two notifier instances, or one instance restarting, cannot
   both hold the same row.
3. the ``attempts`` compare-and-set — a send that finishes after its lease
   expired cannot stamp its result over the newer attempt's.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from notifier import repository
from notifier.ratelimit import NullRateLimiter
from notifier.sender import OutgoingMessage, RecordingSender, SentMessage
from notifier.service import Notifier
from notifier.tests.conftest import Outbox

SQL_ENQUEUE = sa.text(
    """
    INSERT INTO notifications (user_id, kind, ref_id, dedup_key, payload_json, status)
    VALUES (:user_id, :kind, :ref_id, :dedup_key, '{}'::jsonb, 'queued')
    ON CONFLICT (kind, ref_id, dedup_key) DO NOTHING
    RETURNING id
    """
)


async def test_constraint_absorbs_a_repeated_enqueue(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """Re-running settlement produces no second row, so no second message.

    This is :func:`settler.repository.enqueue_notification`'s statement,
    verbatim, run twice. The notifier's idempotency is a consequence of this
    returning ``None`` the second time — not of anything the notifier does.
    """
    user_id = await outbox.user()
    ref = str(uuid.uuid4())
    params = {"user_id": user_id, "kind": "invoice_settled", "ref_id": ref, "dedup_key": "ent-1"}

    async with engine.begin() as conn:
        first = (await conn.execute(SQL_ENQUEUE, params)).first()
    async with engine.begin() as conn:
        second = (await conn.execute(SQL_ENQUEUE, params)).first()

    assert first is not None
    assert second is None
    assert await outbox.count() == 1


async def test_the_constraint_is_real_without_on_conflict(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """Without ``ON CONFLICT`` the database refuses outright.

    Worth its own assertion: ``ON CONFLICT DO NOTHING`` would silently do
    nothing at all if the unique index were ever dropped, and the suite above
    would still be green.
    """
    user_id = await outbox.user()
    ref = str(uuid.uuid4())
    await outbox.enqueue(user_id=user_id, ref_id=ref, dedup_key="ent-1")

    with pytest.raises(IntegrityError):
        await outbox.enqueue(user_id=user_id, ref_id=ref, dedup_key="ent-1")


async def test_reprocessing_one_row_is_a_no_op(engine: AsyncEngine, outbox: Outbox) -> None:
    """Delivering, then running the loop again, sends nothing more."""
    user_id = await outbox.user()
    await outbox.enqueue(user_id=user_id)

    sender = RecordingSender()
    notifier = Notifier(engine, sender=sender, limiter=NullRateLimiter())

    for _ in range(5):
        await notifier.run_once()

    assert len(sender.sent) == 1


async def test_two_claimants_split_the_queue(engine: AsyncEngine, outbox: Outbox) -> None:
    """``SKIP LOCKED``: every row goes to exactly one claimant, none to both.

    Two real connections, concurrently — the reason this rig uses ``NullPool``.
    A pool would turn this into one connection taking turns, which passes
    against an implementation with no locking at all.
    """
    user_id = await outbox.user()
    for i in range(20):
        await outbox.enqueue(user_id=user_id, dedup_key=str(i))

    async def claim() -> list[int]:
        async with engine.begin() as conn:
            rows = await repository.claim_batch(conn, limit=20, lease_seconds=300)
            return [r.id for r in rows]

    left, right = await asyncio.gather(claim(), claim())

    assert set(left) & set(right) == set()
    assert len(left) + len(right) == 20


async def test_a_stale_winner_cannot_overwrite_a_newer_attempt(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """The ``attempts`` compare-and-set, which status alone would not give.

    Scenario: instance A claims the row (attempts -> 1) and its send hangs past
    the lease. Instance B re-claims it (attempts -> 2) and delivers. A finally
    returns and tries to record success against attempts=1. It must lose — and
    ``status`` cannot tell it so, because B's re-claim left the status at
    ``failed``, which is exactly the value A would have matched.
    """
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id)

    async with engine.begin() as conn:
        first = await repository.claim_batch(conn, limit=1, lease_seconds=-1)
    async with engine.begin() as conn:
        second = await repository.claim_batch(conn, limit=1, lease_seconds=300)

    assert first[0].attempts == 1
    assert second[0].attempts == 2

    async with engine.begin() as conn:
        assert (
            await repository.mark_sent(
                conn, notification_id=notification_id, attempts=second[0].attempts, message_id=77
            )
            is True
        )
    async with engine.begin() as conn:
        assert (
            await repository.mark_sent(
                conn, notification_id=notification_id, attempts=first[0].attempts, message_id=11
            )
            is False
        )

    row = await outbox.row(notification_id)
    assert row["message_id"] == 77
    assert row["status"] == "sent"


class StealingSender(RecordingSender):
    """Sends, and lets somebody else re-claim the row while it does.

    Stands in for the only way this race happens in production: a send that
    outlives its lease, after which a second instance picks the row up. Both
    halves are forced here — the lease is expired and then the row is
    re-claimed — because doing it deterministically is the difference between a
    test of the compare-and-set and a test that passes because the timing
    happened to work out.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        super().__init__()
        self._engine = engine

    async def send(self, message: OutgoingMessage) -> SentMessage:
        async with self._engine.begin() as conn:
            await conn.execute(
                sa.text("UPDATE notifications SET next_attempt_at = now() - interval '1 minute'")
            )
            await repository.claim_batch(conn, limit=10, lease_seconds=300)
        return await super().send(message)


async def test_a_stale_winner_is_counted_not_hidden(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """``PassResult.stale`` exists so a too-short lease is visible.

    Losing the compare-and-set is neither an error nor a success, and reporting
    it as either would hide a configuration problem that only appears under
    load — exactly the class of thing nobody finds without a counter. The
    message itself is not lost: the row still belongs to the newer generation
    and is delivered again, which is the duplicate-over-loss direction TZ 5.7
    chooses.
    """
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id)

    sender = StealingSender(engine)
    notifier = Notifier(engine, sender=sender, limiter=NullRateLimiter())
    result = await notifier.run_once()

    assert (result.claimed, result.sent, result.stale) == (1, 0, 1)
    assert len(sender.sent) == 1
    row = await outbox.row(notification_id)
    assert row["status"] == "failed"  # still owned by the newer claim
    assert row["attempts"] == 2
