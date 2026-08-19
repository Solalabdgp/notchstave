"""The aiogram implementation of :class:`notifier.sender.MessageSender`.

Week 4 built the delivery loop against a protocol with two test doubles and left
this file for Week 5, on the grounds that the retry curve, the DLQ and the rate
limiter are properties of :mod:`notifier` and need no live token to be correct.
This is the third implementation, and none of the delivery logic changed to
accept it.

**In its own module, imported lazily by** :func:`notifier.main.build_sender`.
The notifier is deployed as its own systemd unit and its test environment
deliberately does not install a Telegram client (see ``notifier/tests/
requirements.txt``); an ``import aiogram`` at the top of :mod:`notifier.sender`
would make the protocol itself un-importable without one. The same pattern the
Redis rate limiter already uses, for the same reason.

The translation table, and why each line is where it is
-------------------------------------------------------

Everything this class really does is turn aiogram's exceptions into the
transient/permanent split of :mod:`notifier.errors`. That translation *is* the
retry policy, and it belongs next to the transport because the transport is the
only place that knows what a given failure means.

``TelegramForbiddenError`` → :class:`~notifier.errors.BotBlockedError`
    403. The user blocked the bot or deleted the chat. Permanent, and handled
    specially rather than as a plain permanent failure: TZ 5.5 asks for two
    things — record it on the user, and stop sending *everything else* queued
    for them. Retrying against a 403 is also precisely the traffic that gets a
    bot rate-limited, so the retry budget saved here is spent on messages that
    can still land.

``TelegramRetryAfter`` → :class:`~notifier.errors.RateLimitedError`
    429 with Telegram's own number. It overrides the computed backoff, because
    our exponential curve is a guess about a server we cannot see and this is
    that server answering.

``TelegramBadRequest`` carrying "message is not modified" → **success**
    The one case where an error is the desired state. It means the edit we sent
    matches what is already on screen — which happens whenever a correction is
    redelivered after a crash between the send and the record (:mod:`notifier
    .service` documents that window and accepts it). Treating it as a failure
    would retry an edit that has already taken effect, ``max_attempts`` times,
    and then file a message about somebody's money in the DLQ as undelivered
    when it was delivered.

``TelegramBadRequest`` otherwise → :class:`~notifier.errors.PermanentDeliveryError`
    A malformed request does not become well-formed on the third try. Bad HTML
    in a rendered message lands here, and the DLQ is where it should be seen.

``TelegramNetworkError`` / ``TelegramServerError`` → transient
    Sockets and 5xx.

Anything unrecognised is left to propagate, and :mod:`notifier.service` treats
an unknown exception as transient. That asymmetry is stated in
:mod:`notifier.errors` and is deliberate: misclassifying a permanent failure as
transient costs a handful of wasted calls, misclassifying a transient failure as
permanent silently drops a message about money.

**No parse mode is set here.** The bot process configures HTML on its own
``Bot`` instance and :mod:`notifier.render` writes plain text today; a parse mode
imposed at this layer would reinterpret every existing rendered string, and an
address containing an underscore is not a formatting instruction.
"""

from __future__ import annotations

import logging

from aiogram import Bot
from aiogram.exceptions import (
    TelegramBadRequest,
    TelegramForbiddenError,
    TelegramNetworkError,
    TelegramRetryAfter,
    TelegramServerError,
)

from notifier.errors import (
    BotBlockedError,
    PermanentDeliveryError,
    RateLimitedError,
    TransientDeliveryError,
)
from notifier.sender import MessageSender, OutgoingMessage, SentMessage

__all__ = ["AiogramSender", "NOT_MODIFIED"]

log = logging.getLogger("notchstave.notifier.telegram")

#: Telegram's wording for "your edit changes nothing". Matched as a substring
#: because the full text carries a "Bad Request: " prefix and has varied in
#: punctuation over the years; the phrase itself has not.
NOT_MODIFIED = "message is not modified"


class AiogramSender:
    """One ``Bot`` session, one method, the translation table above.

    Holds the ``Bot`` rather than creating one per send: an ``aiohttp`` session
    per message would open a TLS connection per message, which at 30 messages a
    second (TZ 5.5's global ceiling) is 30 handshakes a second against a server
    that is already rate-limiting us.

    ``edits_message_id`` chooses between ``editMessageText`` and
    ``sendMessage``. Nothing else in the protocol needs to exist: the notifier
    asks Telegram for exactly one thing, which is to put a piece of text in front
    of a person or replace one it put there before (TZ 5.5).
    """

    __slots__ = ("_bot",)

    def __init__(self, bot: Bot) -> None:
        self._bot = bot

    @property
    def bot(self) -> Bot:
        return self._bot

    async def send(self, message: OutgoingMessage) -> SentMessage:
        try:
            if message.edits_message_id is not None:
                return await self._edit(message, message.edits_message_id)
            sent = await self._bot.send_message(
                chat_id=message.chat_id,
                text=message.text,
                disable_web_page_preview=True,
            )
            return SentMessage(message_id=sent.message_id)
        except TelegramForbiddenError as exc:
            raise BotBlockedError(f"chat {message.chat_id}: {exc}") from exc
        except TelegramRetryAfter as exc:
            raise RateLimitedError(float(exc.retry_after), str(exc)) from exc
        except TelegramBadRequest as exc:
            raise PermanentDeliveryError(f"chat {message.chat_id}: {exc}") from exc
        except (TelegramNetworkError, TelegramServerError) as exc:
            raise TransientDeliveryError(f"chat {message.chat_id}: {exc}") from exc

    async def _edit(self, message: OutgoingMessage, message_id: int) -> SentMessage:
        """An edit, with the one bad request that means success.

        Caught here rather than in :meth:`send`'s ladder because it is only ever
        an answer to an *edit*: a plain send cannot be "not modified", and a
        handler that swallowed the phrase on both paths would be swallowing it
        somewhere it cannot legitimately occur.
        """
        try:
            await self._bot.edit_message_text(
                chat_id=message.chat_id,
                message_id=message_id,
                text=message.text,
                disable_web_page_preview=True,
            )
        except TelegramBadRequest as exc:
            if NOT_MODIFIED not in str(exc).lower():
                raise
            log.info(
                "edit of message %s in chat %s was already applied",
                message_id,
                message.chat_id,
            )
        # The edited message keeps its id, so the outbox row's `message_id` does
        # not move. Returning the id we were given rather than reading one out
        # of the response is also what makes the "not modified" path able to
        # return at all — that branch has no response to read.
        return SentMessage(message_id=message_id)


#: The same compile-time proof :mod:`notifier.sender` makes about its doubles.
#: mypy checks the assignment; a drift between this class and the protocol fails
#: the type check here rather than against a live bot.
def _typecheck(bot: Bot) -> MessageSender:
    return AiogramSender(bot)
