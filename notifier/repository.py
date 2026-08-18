"""Every statement the notifier runs, and the privilege each one needs.

The notifier's grants are narrow on purpose (migration 0002, tightened by 0004),
and the shape of this module follows from them rather than from taste:

===================  ==========================  ================================
table                privilege                   what it is for
===================  ==========================  ================================
``notifications``    ``SELECT, UPDATE``          claim, complete, retry, retire
``users``            ``SELECT``,                 chat id and language;
                     ``UPDATE (bot_blocked_at)`` mark a user who blocked the bot
``audit_log``        ``SELECT, INSERT``          append-only trail
``invoices`` etc.    ``SELECT``                  reference data only
===================  ==========================  ================================

Two consequences worth stating before someone tries to work around them:

* **No INSERT on ``notifications``.** The notifier cannot create a message. It
  is the outbox *drain*, and the outbox is written only in the transaction that
  made the money decision (TZ 5.7). A notifier that could enqueue would be a
  notifier that could deliver a message about a grant that never happened.
* **No grant on ``products``.** So no renderer can look up a product title, and
  every word of a message has to come out of ``payload_json`` — which is why
  the settler writes the amounts and symbols into the payload instead of the
  ids alone. This is the privilege boundary showing up as an API constraint,
  and it is the right way round: the process that talks to the internet cannot
  read the catalogue.

**On claiming.** ``notification_status`` has four values — ``queued``, ``sent``,
``failed``, ``dead`` — and no ``sending``. Rather than add one, a claimed row is
moved to ``failed`` *before* the send, with ``attempts`` incremented and
``next_attempt_at`` set one lease into the future. That reads oddly for a
heartbeat and is exactly right for money: a process that dies mid-send leaves a
row that says "attempt 3 started and never reported success", which is the truth
— nobody knows whether Telegram received it. Optimistically holding the row in
``queued`` until a failure is confirmed would mean a crash loop re-sends the
same message on every restart with ``attempts`` still at zero, and the user gets
the same "payment received" notice forty times.

The claim is one statement, and the send happens after its transaction commits.
Holding a transaction open across an HTTP call — with rate-limit sleeps inside
it — would pin ``ix_notifications_queue`` for the length of a Telegram incident.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

__all__ = [
    "ClaimedNotification",
    "claim_batch",
    "mark_sent",
    "schedule_retry",
    "mark_dead",
    "block_user",
    "retire_blocked_user",
    "dlq_size",
    "find_message_id",
    "record_audit",
]


@dataclass(frozen=True, slots=True)
class ClaimedNotification:
    """One outbox row, leased to this process for one delivery attempt."""

    id: int
    user_id: int
    kind: str
    ref_id: str
    dedup_key: str
    payload: dict[str, Any]
    attempts: int
    created_at: dt.datetime
    #: ``users.tg_id`` — the Telegram chat. Joined at claim time so the sender
    #: never needs a second query, and so a message can never be addressed by
    #: the internal ``users.id`` by accident.
    tg_id: int
    lang: str


#: Claim, in one statement.
#:
#: The inner SELECT carries ``FOR UPDATE ... SKIP LOCKED`` on ``notifications``
#: only (``OF n``): without that qualifier Postgres would also try to lock the
#: joined ``users`` rows, and the notifier holds no FOR UPDATE privilege there —
#: nor should two deliveries to one user serialise on the user row.
#:
#: ``u.bot_blocked_at IS NULL`` is the "прекращаем слать" half of TZ 5.5,
#: enforced in the query rather than after the fetch. A blocked user's rows are
#: retired separately (:func:`retire_blocked_user`) so they do not sit queued
#: forever; this predicate is what makes the window between the block being
#: recorded and the sweep running cost nothing.
SQL_CLAIM = sa.text(
    """
    WITH candidates AS (
        SELECT n.id
          FROM notifications n
          JOIN users u ON u.id = n.user_id
         WHERE u.bot_blocked_at IS NULL
           AND (
                 n.status = 'queued'
                 OR (n.status = 'failed'
                     AND (n.next_attempt_at IS NULL OR n.next_attempt_at <= now()))
               )
         ORDER BY n.created_at
         LIMIT :limit
           FOR UPDATE OF n SKIP LOCKED
    )
    UPDATE notifications n
       SET status          = 'failed',
           attempts        = n.attempts + 1,
           next_attempt_at = now() + make_interval(secs => :lease_seconds)
      FROM candidates c, users u
     WHERE n.id = c.id
       AND u.id = n.user_id
    RETURNING n.id, n.user_id, n.kind, n.ref_id, n.dedup_key, n.payload_json,
              n.attempts, n.created_at, u.tg_id, u.lang
    """
)


async def claim_batch(
    conn: AsyncConnection, *, limit: int, lease_seconds: float
) -> list[ClaimedNotification]:
    rows = (
        await conn.execute(SQL_CLAIM, {"limit": limit, "lease_seconds": lease_seconds})
    ).mappings()
    claimed = [
        ClaimedNotification(
            id=int(r["id"]),
            user_id=int(r["user_id"]),
            kind=str(r["kind"]),
            ref_id=str(r["ref_id"]),
            dedup_key=str(r["dedup_key"]),
            payload=dict(r["payload_json"] or {}),
            attempts=int(r["attempts"]),
            created_at=r["created_at"],
            tg_id=int(r["tg_id"]),
            lang=str(r["lang"]),
        )
        for r in rows
    ]
    # `created_at` order is lost by the UPDATE ... RETURNING (Postgres returns
    # rows in whatever order it updated them). Restoring it here is what keeps
    # TZ 5.5's "правки/отзывы идут в ту же очередь с тем же приоритетом" true in
    # practice: an edit must not overtake the message it edits.
    claimed.sort(key=lambda c: (c.created_at, c.id))
    return claimed


#: ``AND attempts = :attempts`` is a compare-and-set on the lease, not
#: decoration. Status alone would not do it: a lease that expires during a slow
#: send lets another instance re-claim the row, and the re-claim leaves the
#: status at ``failed`` — the value this statement would have matched. What the
#: re-claim cannot leave alone is ``attempts``, because incrementing it is what
#: claiming *is*. So the counter doubles as the lease generation, and a stale
#: winner updates zero rows and says so.
SQL_MARK_SENT = sa.text(
    """
    UPDATE notifications
       SET status          = 'sent',
           sent_at         = now(),
           message_id      = :message_id,
           last_error      = NULL,
           next_attempt_at = NULL
     WHERE id = :id
       AND status = 'failed'
       AND attempts = :attempts
    """
)


async def mark_sent(
    conn: AsyncConnection, *, notification_id: int, attempts: int, message_id: int
) -> bool:
    result = await conn.execute(
        SQL_MARK_SENT,
        {"id": notification_id, "attempts": attempts, "message_id": message_id},
    )
    return result.rowcount == 1


SQL_SCHEDULE_RETRY = sa.text(
    """
    UPDATE notifications
       SET status          = 'failed',
           last_error      = :last_error,
           next_attempt_at = now() + make_interval(secs => :delay_seconds)
     WHERE id = :id
       AND status = 'failed'
       AND attempts = :attempts
    """
)


async def schedule_retry(
    conn: AsyncConnection,
    *,
    notification_id: int,
    attempts: int,
    delay_seconds: float,
    last_error: str,
) -> bool:
    result = await conn.execute(
        SQL_SCHEDULE_RETRY,
        {
            "id": notification_id,
            "attempts": attempts,
            "delay_seconds": delay_seconds,
            # The column is unbounded TEXT, but an exception repr can carry a
            # whole response body; truncating keeps one misbehaving transport
            # from turning the outbox into a log file.
            "last_error": last_error[:2000],
        },
    )
    return result.rowcount == 1


#: The DLQ transition (TZ 5.5). Terminal, and reversible only by a human:
#: nothing in this package moves a row out of ``dead``. Week 5's `/dlq` command
#: is what sets ``status = 'queued', attempts = 0`` after the cause is fixed,
#: and everything it needs is on the row — ``attempts``, ``last_error``,
#: ``payload_json``, and the ``UNIQUE (kind, ref_id, dedup_key)`` that makes a
#: re-queue safe.
SQL_MARK_DEAD = sa.text(
    """
    UPDATE notifications
       SET status          = 'dead',
           last_error      = :last_error,
           next_attempt_at = NULL
     WHERE id = :id
       AND status <> 'sent'
    """
)


async def mark_dead(conn: AsyncConnection, *, notification_id: int, last_error: str) -> bool:
    result = await conn.execute(
        SQL_MARK_DEAD, {"id": notification_id, "last_error": last_error[:2000]}
    )
    return result.rowcount == 1


#: Column-scoped UPDATE (migration 0004): this is the only column of ``users``
#: the notifier can write, and it is the only one it needs.
#:
#: ``IS NULL`` in the WHERE makes the write idempotent and keeps the first
#: observation's timestamp — "when did this user block us" is the interesting
#: question, and re-stamping it on every later attempt answers "when did we last
#: try", which is what ``notifications.next_attempt_at`` is for.
SQL_BLOCK_USER = sa.text(
    """
    UPDATE users
       SET bot_blocked_at = now()
     WHERE id = :user_id
       AND bot_blocked_at IS NULL
    """
)


async def block_user(conn: AsyncConnection, *, user_id: int) -> bool:
    result = await conn.execute(SQL_BLOCK_USER, {"user_id": user_id})
    return result.rowcount == 1


#: "Пользователь заблокировал бота — помечаем и прекращаем слать" (TZ 5.5).
#:
#: The second half is this statement. Leaving the rest of a blocked user's queue
#: in ``queued`` would be quieter but wrong twice over: the rows are invisible to
#: the claim query and so would accumulate forever, and an operator reading the
#: outbox could not tell "never delivered because blocked" from "not delivered
#: yet". Retiring them into the DLQ answers both, and the DLQ is the right place
#: — a buyer who blocked the bot and therefore never received "access granted"
#: is a support case, not a rounding error.
SQL_RETIRE_BLOCKED = sa.text(
    """
    UPDATE notifications
       SET status          = 'dead',
           last_error      = :last_error,
           next_attempt_at = NULL
     WHERE user_id = :user_id
       AND status IN ('queued', 'failed')
    """
)


async def retire_blocked_user(
    conn: AsyncConnection, *, user_id: int, last_error: str = "bot_blocked"
) -> int:
    result = await conn.execute(
        SQL_RETIRE_BLOCKED, {"user_id": user_id, "last_error": last_error}
    )
    return int(result.rowcount)


SQL_DLQ_SIZE = sa.text("SELECT count(*) FROM notifications WHERE status = 'dead'")


async def dlq_size(conn: AsyncConnection) -> int:
    """Backing query for ``notchstave_dlq_size`` (TZ section 7).

    Counted rather than tracked incrementally, and that is the same reasoning
    :data:`settler.metrics.RECONCILE_DRIFT_USD` gives: a counter maintained in
    process memory resets to zero on restart and never notices a human draining
    the queue, so it would alert on a backlog that no longer exists and stay
    silent about one inherited from the previous process.
    """
    return int((await conn.execute(SQL_DLQ_SIZE)).scalar_one())


#: Resolve the message an edit should replace (TZ 5.5).
#:
#: Scoped to the same ``(user_id, kind, ref_id)`` and to rows that actually went
#: out. ``ORDER BY sent_at DESC`` because one invoice can legitimately produce
#: several messages of a kind over its life; the newest is the one on the user's
#: screen.
SQL_FIND_MESSAGE_ID = sa.text(
    """
    SELECT message_id
      FROM notifications
     WHERE user_id = :user_id
       AND kind = :kind
       AND ref_id = :ref_id
       AND status = 'sent'
       AND message_id IS NOT NULL
     ORDER BY sent_at DESC
     LIMIT 1
    """
)


async def find_message_id(
    conn: AsyncConnection, *, user_id: int, kind: str, ref_id: str
) -> int | None:
    row = (
        await conn.execute(
            SQL_FIND_MESSAGE_ID, {"user_id": user_id, "kind": kind, "ref_id": ref_id}
        )
    ).scalar_one_or_none()
    return None if row is None else int(row)


SQL_AUDIT = sa.text(
    """
    INSERT INTO audit_log (actor_kind, actor_id, action, target_kind, target_id, args_json)
    VALUES ('system', 'notifier', :action, 'notification', :target_id,
            CAST(:args AS jsonb))
    """
)


async def record_audit(
    conn: AsyncConnection, *, action: str, target_id: str, args: dict[str, Any]
) -> None:
    """Append-only trail for the two things a human may have to reconstruct.

    Not every delivery — that would bury `/resolve` and `/reconcile` decisions
    under thousands of routine rows in the one table TZ 5.8/T8 exists to keep
    readable. Only the terminal events: a row entering the DLQ, and a user being
    marked as having blocked the bot.
    """
    await conn.execute(
        SQL_AUDIT,
        {
            "action": action,
            "target_id": target_id,
            "args": json.dumps(args, default=str, sort_keys=True),
        },
    )
