"""Draining the outbox: the happy path, ordering, leases, and TZ 5.5's edits."""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncEngine

from notifier import repository
from notifier.config import NotifierConfig
from notifier.ratelimit import NullRateLimiter
from notifier.sender import RecordingSender
from notifier.service import Notifier
from notifier.tests.conftest import Outbox


def build(
    engine: AsyncEngine, sender: RecordingSender, config: NotifierConfig | None = None
) -> Notifier:
    """A notifier with the rate limiter switched off.

    Deliberate: these tests are about the outbox, and the limits get their own
    file where a fake clock makes them free. Leaving a real limiter in here
    would add a second per message to a suite that asserts nothing about it.
    """
    return Notifier(engine, sender=sender, limiter=NullRateLimiter(), config=config)


async def test_queued_row_is_delivered_and_stamped(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    user_id = await outbox.user(tg_id=4242)
    notification_id = await outbox.enqueue(user_id=user_id)

    sender = RecordingSender()
    result = await build(engine, sender).run_once()

    assert (result.claimed, result.sent, result.dead) == (1, 1, 0)
    assert [m.chat_id for m in sender.sent] == [4242]

    row = await outbox.row(notification_id)
    assert row["status"] == "sent"
    assert row["sent_at"] is not None
    assert row["message_id"] == sender.next_message_id
    assert row["attempts"] == 1
    assert row["next_attempt_at"] is None
    assert row["last_error"] is None


async def test_message_goes_to_tg_id_not_user_id(engine: AsyncEngine, outbox: Outbox) -> None:
    """The one confusion in this schema that would leak a receipt to a stranger.

    ``users.id`` and ``users.tg_id`` are both bigints, and a message addressed
    to the wrong one lands in whichever Telegram account owns that number. The
    claim query joins ``users`` precisely so the sender is never handed a value
    it could get wrong.
    """
    user_id = await outbox.user(tg_id=987_654_321)
    assert user_id != 987_654_321
    await outbox.enqueue(user_id=user_id)

    sender = RecordingSender()
    await build(engine, sender).run_once()

    assert [m.chat_id for m in sender.sent] == [987_654_321]


async def test_sent_rows_are_not_reclaimed(engine: AsyncEngine, outbox: Outbox) -> None:
    """A second pass over a drained outbox sends nothing.

    The simplest form of TZ 3.5's "ни одного дубликата при перезапуске любого
    компонента": a notifier restarting is exactly a second pass.
    """
    user_id = await outbox.user()
    await outbox.enqueue(user_id=user_id)

    sender = RecordingSender()
    notifier = build(engine, sender)
    assert (await notifier.run_once()).sent == 1
    second = await notifier.run_once()

    assert (second.claimed, second.sent) == (0, 0)
    assert len(sender.sent) == 1


async def test_batch_bounds_one_pass(engine: AsyncEngine, outbox: Outbox) -> None:
    user_id = await outbox.user()
    for i in range(7):
        await outbox.enqueue(user_id=user_id, dedup_key=str(i))

    sender = RecordingSender()
    notifier = build(engine, sender, NotifierConfig(batch=3))

    assert (await notifier.run_once()).claimed == 3
    assert (await notifier.run_once()).claimed == 3
    assert (await notifier.run_once()).claimed == 1
    assert (await notifier.run_once()).claimed == 0
    assert len(sender.sent) == 7


async def test_claim_order_is_created_at(engine: AsyncEngine, outbox: Outbox) -> None:
    """TZ 5.5: corrections share the queue and the priority of everything else.

    There is no priority column, and this test is why one is not needed: the
    queue is ordered by the moment the money decision committed, so a correction
    written after a notice is delivered after it. The ordering has to be
    restored explicitly after ``UPDATE ... RETURNING``, which does not preserve
    it — remove that sort and this test fails.
    """
    user_id = await outbox.user()
    ref = str(uuid.uuid4())
    await outbox.enqueue(user_id=user_id, kind="invoice_settled", ref_id=ref)
    await outbox.enqueue(
        user_id=user_id,
        kind="entitlement_revoked",
        ref_id=ref,
        payload={"invoice_id": ref, "reason": "chain_reorg"},
    )

    sender = RecordingSender()
    await build(engine, sender).run_once()

    assert "access is active" in sender.sent[0].text
    assert "rolled back" in sender.sent[1].text


async def test_revocation_edits_the_grant_message(engine: AsyncEngine, outbox: Outbox) -> None:
    """A correction replaces the message it corrects (TZ 5.5, 3.5).

    Leaving "your access is active" on screen under a separate "actually, it was
    revoked" is how somebody keeps believing they still have what they paid for.
    """
    user_id = await outbox.user()
    ref = str(uuid.uuid4())
    await outbox.enqueue(user_id=user_id, kind="invoice_settled", ref_id=ref)

    sender = RecordingSender()
    notifier = build(engine, sender)
    await notifier.run_once()
    grant_message_id = await outbox.message_id_of("invoice_settled")
    assert grant_message_id is not None

    await outbox.enqueue(
        user_id=user_id,
        kind="entitlement_revoked",
        ref_id=ref,
        payload={"invoice_id": ref, "reason": "chain_reorg"},
    )
    await notifier.run_once()

    assert sender.sent[1].edits_message_id == grant_message_id


async def test_edit_target_is_scoped_to_its_own_invoice(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """Two invoices for one buyer must not cross-edit each other's messages."""
    user_id = await outbox.user()
    ref_a, ref_b = str(uuid.uuid4()), str(uuid.uuid4())
    await outbox.enqueue(user_id=user_id, kind="invoice_settled", ref_id=ref_a)
    await outbox.enqueue(user_id=user_id, kind="invoice_settled", ref_id=ref_b)

    sender = RecordingSender()
    notifier = build(engine, sender)
    await notifier.run_once()

    await outbox.enqueue(
        user_id=user_id,
        kind="entitlement_revoked",
        ref_id=ref_a,
        payload={"invoice_id": ref_a, "reason": "chain_reorg"},
    )
    await notifier.run_once()

    row_a = await outbox.row(1)
    assert row_a["ref_id"] == ref_a
    assert sender.sent[2].edits_message_id == row_a["message_id"]


async def test_edit_without_a_delivered_original_is_sent_as_new(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """No target found is not an error — the news still has to reach the user."""
    user_id = await outbox.user()
    ref = str(uuid.uuid4())
    await outbox.enqueue(
        user_id=user_id,
        kind="entitlement_revoked",
        ref_id=ref,
        payload={"invoice_id": ref, "reason": "chain_reorg"},
    )

    sender = RecordingSender()
    result = await build(engine, sender).run_once()

    assert result.sent == 1
    assert sender.sent[0].edits_message_id is None


async def test_claim_leases_the_row(engine: AsyncEngine, outbox: Outbox) -> None:
    """A claimed row is invisible to the next claimant until the lease expires.

    This stands in for the ``sending`` status the enum does not have, and it is
    what makes a second notifier instance — a rolling deploy, say — safe.
    """
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id)

    async with engine.begin() as conn:
        first = await repository.claim_batch(conn, limit=10, lease_seconds=300)
    async with engine.begin() as conn:
        second = await repository.claim_batch(conn, limit=10, lease_seconds=300)

    assert [c.id for c in first] == [notification_id]
    assert second == []


async def test_expired_lease_is_reclaimed(engine: AsyncEngine, outbox: Outbox) -> None:
    """A process that died mid-send costs one attempt and one lease, not the message."""
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(user_id=user_id)

    async with engine.begin() as conn:
        await repository.claim_batch(conn, limit=10, lease_seconds=-1)
    async with engine.begin() as conn:
        again = await repository.claim_batch(conn, limit=10, lease_seconds=300)

    assert [c.id for c in again] == [notification_id]
    # Two claims, two attempts: the crash is paid for out of the retry budget
    # rather than being free, which is what stops a crash loop from re-sending
    # the same message forever.
    assert again[0].attempts == 2


async def test_notifier_never_inserts_an_outbox_row(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """The notifier is a drain, not a source (TZ 5.7).

    Backed by the GRANT matrix rather than by this assertion — the notifier role
    holds ``SELECT, UPDATE`` on ``notifications`` and no INSERT (see
    ``test_grants.py``). This guards the code path: a future "resend as a new
    row" convenience would break the outbox's one-row-per-decision property, and
    would break here first.
    """
    user_id = await outbox.user()
    await outbox.enqueue(user_id=user_id)
    before = await outbox.count()

    await build(engine, RecordingSender()).run_once()

    assert await outbox.count() == before
