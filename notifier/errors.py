"""Delivery failure modes, split by the only question that matters: retry or not.

Everything the notifier does with a failure follows from which side of this
split it falls on, so the split is a type and not a string comparison on an
exception message.

* :class:`TransientDeliveryError` — the message might still get through.
  Telegram 5xx, a socket timeout, a 429 with ``retry_after``. Backoff, try
  again, and give up into the DLQ only after ``max_attempts`` (TZ 5.5).
* :class:`PermanentDeliveryError` — it will never get through. Retrying is not
  merely useless, it is harmful: attempts against a chat that answers 403 are
  exactly the traffic that gets a bot rate-limited, and the retry budget spent
  on them is not spent on messages that could still land.

The default for an *unrecognised* exception is transient. That asymmetry is
deliberate: misclassifying a permanent failure as transient costs
``max_attempts`` wasted calls and then lands in the DLQ anyway, while
misclassifying a transient failure as permanent silently drops a message about
money. The cheap mistake is the one we make.
"""

from __future__ import annotations

__all__ = [
    "DeliveryError",
    "TransientDeliveryError",
    "RateLimitedError",
    "PermanentDeliveryError",
    "BotBlockedError",
    "UnrenderableNotificationError",
]


class DeliveryError(Exception):
    """Base class for anything that stopped a message from being delivered."""


class TransientDeliveryError(DeliveryError):
    """Try again later. Network trouble, Telegram 5xx, timeouts."""


class RateLimitedError(TransientDeliveryError):
    """Telegram answered 429 and told us how long to wait.

    ``retry_after`` is authoritative and overrides the computed backoff: our
    exponential curve is a guess about a server we cannot see, and this is that
    server telling us the answer. Ignoring it in favour of our own schedule is
    how a temporary limit becomes a longer one.
    """

    def __init__(self, retry_after: float, message: str = "") -> None:
        super().__init__(message or f"rate limited, retry after {retry_after}s")
        self.retry_after = retry_after


class PermanentDeliveryError(DeliveryError):
    """Never going to succeed. Straight to the DLQ, no attempts consumed."""


class BotBlockedError(PermanentDeliveryError):
    """Telegram 403: the user blocked the bot, or the chat no longer exists.

    Handled specially rather than as a plain permanent failure, because TZ 5.5
    asks for two distinct things: "помечаем" — record it on the user — "и
    прекращаем слать" — which is about every *other* message queued for that
    user, not only this one. See :func:`notifier.repository.retire_blocked_user`.
    """


class UnrenderableNotificationError(PermanentDeliveryError):
    """No renderer knows what to say about this ``kind``.

    A permanent failure on purpose, and the alternative is worth naming: a
    generic fallback template ("something happened with your invoice") would
    keep the queue draining and send a user a message about their money that
    nobody wrote. The settler is allowed to invent a new kind; the notifier is
    not allowed to guess what it means. The row lands in the DLQ, where
    ``notchstave_dlq_size`` makes the omission visible.
    """
