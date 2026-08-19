"""The Week 5 transport: aiogram's exceptions, mapped to the retry policy.

:mod:`notifier.telegram` is a translation table and almost nothing else, and the
translation *is* the retry policy — so what is worth testing is exactly the
table. Every row below is one line of the module docstring turned into an
assertion, plus the one asymmetry that matters:

**Misclassifying transient as permanent drops a message about money;
misclassifying permanent as transient wastes a few calls.** So the tests check
the direction of every mapping, and check that an unrecognised exception is left
to propagate rather than being guessed at (:mod:`notifier.service` treats an
unknown exception as transient, which is the safe default and only works if this
class does not swallow it first).

No Telegram is contacted. The ``Bot`` is replaced by a stub with the two methods
:class:`~notifier.telegram.AiogramSender` calls, because what is under test is
the ``except`` ladder and not aiogram's HTTP client — TZ section 8, "никаких
сетевых вызовов в CI".
"""

from __future__ import annotations

from typing import Any

import pytest

from notifier.errors import (
    BotBlockedError,
    PermanentDeliveryError,
    RateLimitedError,
    TransientDeliveryError,
)
from notifier.sender import OutgoingMessage

aiogram = pytest.importorskip("aiogram", reason="Week 5 transport; see requirements.txt")

from aiogram.exceptions import (  # noqa: E402
    TelegramBadRequest,
    TelegramForbiddenError,
    TelegramNetworkError,
    TelegramRetryAfter,
    TelegramServerError,
)

from notifier.telegram import NOT_MODIFIED, AiogramSender  # noqa: E402


class StubBot:
    """The two methods the sender calls, and a scripted outcome for each."""

    def __init__(self, raises: Exception | None = None) -> None:
        self.raises = raises
        self.sent: list[dict[str, Any]] = []
        self.edited: list[dict[str, Any]] = []

    async def send_message(self, **kwargs: Any) -> Any:
        self.sent.append(kwargs)
        if self.raises is not None:
            raise self.raises

        class _Sent:
            message_id = 9001

        return _Sent()

    async def edit_message_text(self, **kwargs: Any) -> Any:
        self.edited.append(kwargs)
        if self.raises is not None:
            raise self.raises
        return True


def _sender(raises: Exception | None = None) -> tuple[AiogramSender, StubBot]:
    bot = StubBot(raises)
    return AiogramSender(bot), bot  # type: ignore[arg-type]


def _bad_request(message: str) -> TelegramBadRequest:
    """aiogram's exceptions want the method that produced them."""
    from aiogram.methods import SendMessage

    return TelegramBadRequest(method=SendMessage(chat_id=1, text="x"), message=message)


def _forbidden() -> TelegramForbiddenError:
    from aiogram.methods import SendMessage

    return TelegramForbiddenError(
        method=SendMessage(chat_id=1, text="x"), message="bot was blocked by the user"
    )


def _retry_after(seconds: int) -> TelegramRetryAfter:
    from aiogram.methods import SendMessage

    return TelegramRetryAfter(
        method=SendMessage(chat_id=1, text="x"),
        message="Too Many Requests",
        retry_after=seconds,
    )


A_MESSAGE = OutgoingMessage(chat_id=555, text="Your payment landed.")


async def test_a_plain_send_returns_the_message_id_telegram_gave() -> None:
    sender, bot = _sender()

    result = await sender.send(A_MESSAGE)

    assert result.message_id == 9001
    assert bot.sent == [
        {
            "chat_id": 555,
            "text": "Your payment landed.",
            # Never a link preview: a rendered notification carries an explorer
            # URL and an unfurled card under every one of them is noise.
            "disable_web_page_preview": True,
        }
    ]
    # No parse mode at this layer — `notifier.render` writes plain text and an
    # address with an underscore in it is not a formatting instruction.
    assert "parse_mode" not in bot.sent[0]


async def test_an_edit_goes_to_edit_message_text_and_keeps_the_id() -> None:
    sender, bot = _sender()

    result = await sender.send(
        OutgoingMessage(chat_id=555, text="corrected", edits_message_id=77)
    )

    assert bot.sent == []
    assert bot.edited[0]["message_id"] == 77
    # The edited message keeps its id, so the outbox row's `message_id` does not
    # move under it.
    assert result.message_id == 77


async def test_a_403_becomes_bot_blocked_not_a_generic_permanent_failure() -> None:
    """TZ 5.5 wants two things from a 403: record it, and stop the rest.

    A plain ``PermanentDeliveryError`` would DLQ this one message and leave the
    next nine queued for the same chat to burn their retry budgets against a
    user who has removed the bot.
    """
    sender, _ = _sender(_forbidden())

    with pytest.raises(BotBlockedError):
        await sender.send(A_MESSAGE)


async def test_a_429_carries_telegrams_own_number() -> None:
    """Their answer beats our exponential guess about a server we cannot see."""
    sender, _ = _sender(_retry_after(37))

    with pytest.raises(RateLimitedError) as caught:
        await sender.send(A_MESSAGE)

    assert caught.value.retry_after == pytest.approx(37.0)


async def test_a_malformed_request_is_permanent(caplog: pytest.LogCaptureFixture) -> None:
    """Bad HTML does not become well-formed on the third try — DLQ it."""
    sender, _ = _sender(_bad_request("can't parse entities"))

    with pytest.raises(PermanentDeliveryError):
        await sender.send(A_MESSAGE)


@pytest.mark.parametrize(
    "exc",
    [TelegramNetworkError(method=None, message="socket"), TelegramServerError],  # type: ignore[arg-type]
    ids=["network", "server"],
)
async def test_sockets_and_5xx_are_transient(exc: Any) -> None:
    from aiogram.methods import SendMessage

    if isinstance(exc, type):
        exc = TelegramServerError(
            method=SendMessage(chat_id=1, text="x"), message="Bad Gateway"
        )
    sender, _ = _sender(exc)

    with pytest.raises(TransientDeliveryError):
        await sender.send(A_MESSAGE)


async def test_not_modified_on_an_edit_is_success(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The one case where an error is the desired state.

    It happens whenever a correction is redelivered after a crash between the
    send and the record — a window :mod:`notifier.service` documents and
    accepts. Treating it as a failure would retry an edit that has already taken
    effect and then file a message about somebody's money in the DLQ as
    undelivered, when it was delivered.
    """
    sender, _ = _sender(_bad_request(f"Bad Request: {NOT_MODIFIED}"))

    result = await sender.send(
        OutgoingMessage(chat_id=555, text="same as before", edits_message_id=88)
    )

    assert result.message_id == 88


async def test_not_modified_is_not_swallowed_on_a_plain_send() -> None:
    """A send cannot legitimately be "not modified".

    Catching the phrase on both paths would swallow it somewhere it can only
    mean that something else went wrong.
    """
    sender, _ = _sender(_bad_request(f"Bad Request: {NOT_MODIFIED}"))

    with pytest.raises(PermanentDeliveryError):
        await sender.send(A_MESSAGE)


async def test_an_unrecognised_exception_is_left_to_propagate() -> None:
    """The asymmetry, stated as a test.

    :mod:`notifier.service` treats an unknown exception as transient, which is
    the safe default — and it only works if this class does not classify it
    first.
    """
    sender, _ = _sender(ValueError("something nobody predicted"))

    with pytest.raises(ValueError):
        await sender.send(A_MESSAGE)


def test_build_sender_refuses_to_downgrade_to_a_dry_run_silently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing token is a startup failure, not a quiet no-op.

    The two states :func:`notifier.main.build_sender` must never confuse are
    "delivering" and "pretending to": a sender that always succeeds without
    sending marks every outbox row ``sent``, and the outbox's entire value is
    that an undelivered message about somebody's money is still there tomorrow.
    """
    from notifier import main as notifier_main

    monkeypatch.delenv("NOTIFIER_DRY_RUN", raising=False)
    monkeypatch.setattr(
        "core.telegram.load_bot_token",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no token")),
    )

    with pytest.raises(RuntimeError):
        notifier_main.build_sender()


def test_the_dry_run_is_still_selectable_and_still_not_the_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from notifier import main as notifier_main
    from notifier.sender import DryRunSender

    monkeypatch.setenv("NOTIFIER_DRY_RUN", "1")
    assert isinstance(notifier_main.build_sender(), DryRunSender)
