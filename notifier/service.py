"""The delivery loop: claim, render, rate-limit, send, record.

**What this process is not allowed to do.** It makes no money decisions (TZ
section 4). It cannot insert an outbox row, cannot touch ``entitlements``,
cannot write anything on ``users`` except ``bot_blocked_at``. Everything it
sends was decided and committed by the settler in the same transaction as the
side effect it describes; the notifier's whole contribution is that the message
about that decision eventually reaches a person, exactly once, within Telegram's
limits.

**Where idempotency comes from, and where it does not.** ``UNIQUE (kind, ref_id,
dedup_key)`` on ``notifications`` is what makes redelivery impossible, and it
does that on the *write* side — the settler's ``ON CONFLICT DO NOTHING`` insert
(:func:`settler.repository.enqueue_notification`). Two settler workers racing on
one invoice produce one row, so there is one message, and re-running the whole
settlement produces no new row and therefore no second message. This module
deliberately adds no second dedup layer in Python: a Python-side "have I sent
this already" cache is a thing that can disagree with the database, and the
constraint cannot. What this module owes the guarantee is only that it never
turns one row into two sends, which the claim lease and the ``attempts``
compare-and-set are for.

**Order of operations in one attempt**, and each step is where it is on purpose:

1. **Claim** — one statement, transaction committed immediately. Attempts is
   incremented *before* the send, so a crash mid-send costs one attempt rather
   than an infinite loop of them.
2. **Render** — before the rate limiter, because a row nobody can render should
   not spend a token that a deliverable message could have used.
3. **Resolve an edit target** — a correction replaces the message it corrects
   (TZ 5.5), in the same queue, at the same priority, ordered by ``created_at``
   like everything else.
4. **Rate limit** — 30/sec globally, 1/sec per chat (TZ 5.5). Waited outside any
   database transaction.
5. **Send.**
6. **Record** — sent, retried with backoff, or retired into the DLQ.

Step 6 is the one that can be interrupted without anyone noticing, and the
consequence is stated rather than hidden: a crash between the send and the
record leaves the row leased and it is retried after the lease, which means one
duplicate message in exchange for never losing one. TZ 5.7 chooses that
direction explicitly for the grant notice ("падение между записью и отправкой
лечится повторной доставкой"), and applying the same preference everywhere else
keeps one rule instead of two.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass
from typing import Literal

from sqlalchemy.ext.asyncio import AsyncEngine

from notifier import backoff, metrics, render, repository
from notifier.config import NotifierConfig
from notifier.errors import (
    BotBlockedError,
    PermanentDeliveryError,
    RateLimitedError,
    TransientDeliveryError,
)
from notifier.ratelimit import RateLimiter
from notifier.repository import ClaimedNotification
from notifier.sender import MessageSender, OutgoingMessage

__all__ = ["Notifier", "PassResult", "Disposition"]

log = logging.getLogger("notchstave.notifier")

#: What happened to one claimed row. A closed set, because every caller of
#: :meth:`Notifier._deliver` either counts it or labels a metric with it, and a
#: fifth outcome invented later must not silently fall out of both.
Disposition = Literal["sent", "retry", "dead", "stale"]

SENT: Disposition = "sent"
RETRY: Disposition = "retry"
DEAD: Disposition = "dead"
STALE: Disposition = "stale"


@dataclass(frozen=True, slots=True)
class PassResult:
    """Summary of one pass, for the loop and for tests.

    ``stale`` counts rows whose completion lost the ``attempts``
    compare-and-set — the send finished after the lease expired and somebody
    else already owns the row. Normally zero; a non-zero value means
    ``lease_seconds`` is shorter than a real send takes, which is a
    configuration problem and not a bug, and is exactly the kind of thing that
    is invisible unless it is counted.
    """

    claimed: int = 0
    sent: int = 0
    retried: int = 0
    dead: int = 0
    stale: int = 0
    dlq_size: int = 0


class Notifier:
    """Drains ``notifications``. One instance per process."""

    def __init__(
        self,
        engine: AsyncEngine,
        *,
        sender: MessageSender,
        limiter: RateLimiter,
        config: NotifierConfig | None = None,
    ) -> None:
        self._engine = engine
        self._sender = sender
        self._limiter = limiter
        self.config = config or NotifierConfig()

    # -- one pass ----------------------------------------------------------

    async def run_once(self) -> PassResult:
        async with self._engine.begin() as conn:
            claimed = await repository.claim_batch(
                conn, limit=self.config.batch, lease_seconds=self.config.lease_seconds
            )

        counts: dict[Disposition, int] = {SENT: 0, RETRY: 0, DEAD: 0, STALE: 0}
        for row in claimed:
            counts[await self._deliver(row)] += 1

        # Read the gauge after the pass, so a message that died in this pass is
        # already counted. Its own connection, outside any delivery
        # transaction — this is a report, and it must not be able to roll a
        # delivery back.
        async with self._engine.connect() as conn:
            size = await repository.dlq_size(conn)
        metrics.DLQ_SIZE.set(size)

        return PassResult(
            claimed=len(claimed),
            sent=counts[SENT],
            retried=counts[RETRY],
            dead=counts[DEAD],
            stale=counts[STALE],
            dlq_size=size,
        )

    # -- one row -----------------------------------------------------------

    async def _deliver(self, row: ClaimedNotification) -> Disposition:
        try:
            rendered = render.render(row.kind, row.payload)
        except PermanentDeliveryError as exc:
            return await self._retire(row, reason="no_renderer", error=str(exc))

        edits_message_id: int | None = None
        if rendered.edits_kind is not None:
            async with self._engine.connect() as conn:
                edits_message_id = await repository.find_message_id(
                    conn, user_id=row.user_id, kind=rendered.edits_kind, ref_id=row.ref_id
                )

        waited = await self._limiter.acquire(row.tg_id)
        metrics.RATE_LIMIT_WAIT_SECONDS.observe(waited)

        message = OutgoingMessage(
            chat_id=row.tg_id, text=rendered.text, edits_message_id=edits_message_id
        )
        try:
            sent = await self._sender.send(message)
        except BotBlockedError as exc:
            return await self._handle_blocked(row, error=str(exc))
        except PermanentDeliveryError as exc:
            return await self._retire(row, reason="permanent", error=repr(exc))
        except TransientDeliveryError as exc:
            retry_after = exc.retry_after if isinstance(exc, RateLimitedError) else None
            return await self._handle_transient(row, error=repr(exc), retry_after=retry_after)
        except Exception as exc:  # noqa: BLE001
            # An unrecognised exception is treated as transient — see the
            # module docstring of `notifier.errors` for why that asymmetry is
            # the cheap mistake rather than the expensive one.
            log.exception("notification %s: unclassified delivery failure", row.id)
            return await self._handle_transient(row, error=repr(exc), retry_after=None)

        async with self._engine.begin() as conn:
            won = await repository.mark_sent(
                conn,
                notification_id=row.id,
                attempts=row.attempts,
                message_id=sent.message_id,
            )
        if not won:
            # The message went out; another claimant owns the row. Do not touch
            # it — it will be delivered again, which is the direction TZ 5.7
            # chooses, and lying about the outcome here would hide a lease
            # that is too short to be seen in `PassResult.stale`.
            log.warning(
                "notification %s: sent but the lease had expired (attempts=%s)",
                row.id,
                row.attempts,
            )
            return STALE

        metrics.DELIVERY_ATTEMPTS.labels(result="sent").inc()
        metrics.NOTIFICATIONS_SENT.labels(kind=row.kind).inc()
        metrics.DELIVERY_SECONDS.observe(max(0.0, _age_seconds(row)))
        return SENT

    # -- outcomes ----------------------------------------------------------

    async def _handle_transient(
        self, row: ClaimedNotification, *, error: str, retry_after: float | None
    ) -> Disposition:
        metrics.DELIVERY_ATTEMPTS.labels(result="transient").inc()
        if backoff.is_exhausted(row.attempts, self.config):
            return await self._retire(row, reason="retries_exhausted", error=error)

        delay = backoff.next_delay_seconds(row.attempts, self.config, retry_after=retry_after)
        async with self._engine.begin() as conn:
            won = await repository.schedule_retry(
                conn,
                notification_id=row.id,
                attempts=row.attempts,
                delay_seconds=delay,
                last_error=error,
            )
        if not won:
            return STALE
        log.info(
            "notification %s: attempt %s/%s failed, retrying in %.1fs (%s)",
            row.id,
            row.attempts,
            self.config.max_attempts,
            delay,
            error,
        )
        return RETRY

    async def _handle_blocked(self, row: ClaimedNotification, *, error: str) -> Disposition:
        """TZ 5.5: "помечаем и прекращаем слать" — both halves, one transaction.

        The mark and the retirement of everything else queued for that user
        commit together. Splitting them would leave a window in which the user
        is flagged but their queue is not retired, and those rows are invisible
        to the claim query — they would sit in ``queued`` until somebody noticed
        by hand.
        """
        metrics.DELIVERY_ATTEMPTS.labels(result="permanent").inc()
        async with self._engine.begin() as conn:
            newly_blocked = await repository.block_user(conn, user_id=row.user_id)
            retired = await repository.retire_blocked_user(
                conn, user_id=row.user_id, last_error=f"bot_blocked: {error}"[:2000]
            )
            await repository.record_audit(
                conn,
                action="notifier_bot_blocked",
                target_id=str(row.id),
                args={
                    "user_id": row.user_id,
                    "kind": row.kind,
                    "ref_id": row.ref_id,
                    "retired_notifications": retired,
                    "newly_blocked": newly_blocked,
                },
            )
        if newly_blocked:
            metrics.USERS_BLOCKED.inc()
        metrics.NOTIFICATIONS_DEAD.labels(reason="bot_blocked").inc(retired)
        log.info(
            "user %s blocked the bot; %d queued notification(s) retired", row.user_id, retired
        )
        return DEAD

    async def _retire(
        self, row: ClaimedNotification, *, reason: str, error: str
    ) -> Disposition:
        """Into the DLQ. Terminal until a human re-queues it (TZ 5.5)."""
        async with self._engine.begin() as conn:
            await repository.mark_dead(
                conn, notification_id=row.id, last_error=f"{reason}: {error}"
            )
            await repository.record_audit(
                conn,
                action="notifier_dlq",
                target_id=str(row.id),
                args={
                    "user_id": row.user_id,
                    "kind": row.kind,
                    "ref_id": row.ref_id,
                    "attempts": row.attempts,
                    "reason": reason,
                    "error": error[:500],
                },
            )
        metrics.NOTIFICATIONS_DEAD.labels(reason=reason).inc()
        log.error(
            "notification %s (%s) -> DLQ after %s attempt(s): %s [%s]",
            row.id,
            row.kind,
            row.attempts,
            reason,
            error,
        )
        return DEAD


def _age_seconds(row: ClaimedNotification) -> float:
    """Seconds since the outbox row was committed.

    ``created_at`` is ``TIMESTAMPTZ`` and comes back aware, so this is a plain
    subtraction. The naive branch is not dead code — it is what keeps a
    connection configured without timezone support from raising inside a
    metrics observation and failing a delivery that actually succeeded.
    """
    created = row.created_at
    now = dt.datetime.now(dt.UTC)
    if created.tzinfo is None:
        return (now.replace(tzinfo=None) - created).total_seconds()
    return (now - created).total_seconds()
