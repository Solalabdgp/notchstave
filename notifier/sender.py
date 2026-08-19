"""The Telegram boundary, as a protocol — and why aiogram is not in this file.

**Week 4 built the delivery loop against this protocol, before a Telegram client
existed.** The retry curve, the DLQ, the rate limiter and the outbox drain are
properties of *this* package and none of them need a live token to be correct or
to be tested. Week 5 added the real adapter, :class:`notifier.telegram
.AiogramSender`, and not one line of the delivery logic changed to accept it —
which is the claim this protocol was written to make good on.

It stays in its own module rather than joining the two doubles below, so that
importing the protocol never requires aiogram. ``notifier/tests/
requirements.txt`` deliberately installs no Telegram client, and the whole
delivery suite runs against the doubles here.

The protocol is deliberately narrower than aiogram's API: one method, taking a
value object, returning a message id. Everything the notifier needs from
Telegram is "put this text in front of this user, or replace what I put there
before". Anything wider would let Telegram's shape leak into the retry logic,
and the retry logic is the part with the tests.

``edits_message_id`` is how TZ 5.5's "правки/отзывы идут в ту же очередь с тем
же приоритетом" is satisfied. Note what that sentence rules out: a separate
edit queue, or a priority column that lets a correction jump the line. An edit
is an ordinary row in ``notifications``, claimed in ``created_at`` order like
everything else, and the only thing that makes it an edit is this field being
set by the time it reaches the sender.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from notifier.errors import BotBlockedError

__all__ = [
    "OutgoingMessage",
    "SentMessage",
    "MessageSender",
    "DryRunSender",
    "RecordingSender",
]

log = logging.getLogger("notchstave.notifier.sender")


@dataclass(frozen=True, slots=True)
class OutgoingMessage:
    """One message, fully resolved. No database handles, no ORM objects."""

    #: Telegram chat id — ``users.tg_id``, never ``users.id``. The two are both
    #: bigints and confusing them sends a stranger somebody else's receipt, so
    #: the field name says which one it is.
    chat_id: int
    text: str
    #: Set to edit an earlier message instead of sending a new one (TZ 5.5).
    edits_message_id: int | None = None


@dataclass(frozen=True, slots=True)
class SentMessage:
    """What Telegram gives back. ``message_id`` is stored on the outbox row."""

    message_id: int


class MessageSender(Protocol):
    """Deliver one message, or raise a :mod:`notifier.errors` exception.

    Implementations must translate their transport's failures into the
    transient/permanent split of :mod:`notifier.errors`. That translation is the
    single most important thing an implementation does — the notifier's whole
    retry policy is downstream of it — and it belongs next to the transport,
    which is the only place that knows what a given status code means.

    The real one is :class:`notifier.telegram.AiogramSender` (Week 5), in its
    own module so that this protocol stays importable without a Telegram client
    installed — which is what lets the whole delivery suite run without one. The
    mapping it owes this protocol, restated here because it is a property of the
    *contract* rather than of that implementation:
      * ``TelegramForbiddenError``            -> ``BotBlockedError``
      * ``TelegramRetryAfter``                -> ``RateLimitedError(retry_after)``
      * ``TelegramBadRequest`` ("message is not modified") -> success, no-op
      * ``TelegramBadRequest`` (anything else) -> ``PermanentDeliveryError``
      * ``TelegramNetworkError`` / 5xx        -> ``TransientDeliveryError``
    """

    async def send(self, message: OutgoingMessage) -> SentMessage: ...


class DryRunSender:
    """Logs instead of sending. For local runs against a real database.

    Not the default and not silently selectable: :func:`notifier.main
    .build_sender` refuses to start with this unless
    ``NOTIFIER_DRY_RUN=1`` is set explicitly, because a sender that marks rows
    ``sent`` without sending anything destroys the outbox — the one structure
    whose entire value is that an undelivered message is still there tomorrow.
    """

    def __init__(self) -> None:
        self._counter = 0

    async def send(self, message: OutgoingMessage) -> SentMessage:
        self._counter += 1
        log.info(
            "DRY RUN %s chat=%s: %s",
            "edit" if message.edits_message_id else "send",
            message.chat_id,
            message.text.replace("\n", " | "),
        )
        return SentMessage(message_id=self._counter)


@dataclass
class RecordingSender:
    """Test double: records everything, fails on a script.

    Kept in the shipped package rather than in the test tree for the same reason
    :class:`settler.locks.BrokenLock` is: it is the executable form of what this
    module claims the protocol is for. A change that makes the notifier depend
    on something aiogram-shaped will fail to construct this, here, rather than
    in Week 5 against a live bot.

    ``script`` is consumed one entry per call: an exception instance is raised,
    anything else is a success. When it runs out, every further call succeeds —
    "fail twice then work" is the shape of nearly every retry test, and having
    to pad the tail with successes obscures it.
    """

    script: list[BaseException | None] = field(default_factory=list)
    sent: list[OutgoingMessage] = field(default_factory=list)
    #: Chats that answer 403 no matter what — the standing state of a user who
    #: blocked the bot, which a one-shot script entry cannot express.
    blocked_chats: set[int] = field(default_factory=set)
    next_message_id: int = 1000

    async def send(self, message: OutgoingMessage) -> SentMessage:
        if message.chat_id in self.blocked_chats:
            raise BotBlockedError(f"chat {message.chat_id} blocked the bot")
        outcome = self.script.pop(0) if self.script else None
        if isinstance(outcome, BaseException):
            raise outcome
        self.sent.append(message)
        self.next_message_id += 1
        return SentMessage(message_id=self.next_message_id)

    def texts(self) -> Sequence[str]:
        return [m.text for m in self.sent]


#: Compile-time proof that both doubles still satisfy the protocol. mypy checks
#: the assignment; at runtime these are two objects nobody uses. A structural
#: protocol that nothing is ever *declared* to implement drifts silently, and
#: the drift surfaces in Week 5 against a live bot instead of in CI.
_DRY_RUN_IS_A_SENDER: MessageSender = DryRunSender()
_RECORDING_IS_A_SENDER: MessageSender = RecordingSender()
