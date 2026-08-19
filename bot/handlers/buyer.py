"""The seven buyer-facing commands of TZ 3.1.

Every handler here has the same three-part shape, and the sameness is the point:

1. **Identify.** ``upsert_user`` on every command, not only on ``/start``. A
   user who blocked and unblocked the bot, or who was added to the database by
   an admin action, must not meet a foreign-key error on their first ``/buy``;
   and ``invoice_requests.user_id`` is a foreign key to ``users.id``, so the row
   has to exist before the request does.
2. **Ask the service layer.** Nothing in this module computes an amount, decides
   a status, or derives an address. TZ section 4: *"bot makes zero money
   decisions"* — it displays what the settler already decided and forwards user
   input for the deriver and the settler to act on.
3. **Render through :mod:`bot.texts`.** No f-strings with business meaning here.
   A handler that formats its own message is a handler whose copy cannot be read
   or tested without a dispatcher.

**Why every refusal is rendered from ``user_message`` and never from ``str(exc)``.**
:mod:`core.invoicing.errors` splits the two deliberately: ``str(exc)`` names
quota limits, observed counts and account ids and belongs in the log, while
``user_message`` is the sentence a buyer may read. Rendering the wrong one puts
the shape of the rate limiter in front of whoever is probing it.

**Why the error handling is a ladder and not one ``except``.**
:class:`~core.invoicing.errors.IntegrityFailure` does *not* inherit from
:class:`~core.invoicing.errors.InvoiceUnavailable`, specifically so that a
handler written to be friendly about quotas cannot swallow a suspected
compromise into "please try again later". So it is caught first and logged at
``critical``: the metric and the alert already fired inside the issuer, and what
this adds is the operator being able to see, in the bot's own log, which buyer
was looking at it.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid

from aiogram import Router
from aiogram.filters import Command, CommandObject, CommandStart
from aiogram.types import Message

from bot import texts
from bot.detect import parse_invoice_id
from bot.repository import AssetRow
from bot.services import BotServices
from core.invoicing import errors as E

__all__ = ["build_router", "sender_id", "issue_invoice"]

log = logging.getLogger("notchstave.bot.buyer")


def sender_id(message: Message) -> int | None:
    """``from_user.id``, or ``None`` for an update that has no human behind it.

    Channel posts and some service messages arrive without ``from_user``.
    Treating that as "no identity" rather than raising is what keeps a stray
    update from turning into a traceback in a handler that only ever wanted to
    greet somebody.
    """
    return None if message.from_user is None else message.from_user.id


async def _resolve_asset(services: BotServices, message: Message) -> AssetRow | None:
    asset = await services.repo.asset(
        chain_id=services.config.chain_id, symbol=services.config.asset_symbol
    )
    if asset is None:
        # The configured (chain, token) pair is not enabled in the database.
        # Answered with the catalogue sentence rather than a configuration
        # error, because from the buyer's side it is indistinguishable from the
        # asset having been switched off — which is a thing an operator does.
        await message.answer(E.UnknownAsset.user_message)
    return asset


async def cmd_start(message: Message, services: BotServices) -> None:
    """``/start`` — registration, onboarding, and the warnings of TZ 3.1 / 12."""
    tg_id = sender_id(message)
    if tg_id is None:
        return
    user = await services.repo.upsert_user(tg_id)
    asset = await services.repo.asset(
        chain_id=services.config.chain_id, symbol=services.config.asset_symbol
    )
    await message.answer(
        texts.start(
            is_new=user.is_new,
            chain_name=asset.chain_name if asset is not None else str(services.config.chain_id),
            asset_symbol=asset.symbol if asset is not None else services.config.asset_symbol,
        )
    )


async def cmd_shop(message: Message, services: BotServices) -> None:
    """``/shop`` — the catalogue with USD prices."""
    products = await services.repo.list_products()
    await message.answer(texts.shop(products))


async def cmd_buy(message: Message, command: CommandObject, services: BotServices) -> None:
    """``/buy <sku>`` — one address, one amount, one deadline, one payment link."""
    tg_id = sender_id(message)
    if tg_id is None:
        return
    sku = (command.args or "").strip().split(" ")[0] if command.args else ""
    if not sku:
        await message.answer(texts.buy_usage())
        return

    product = await services.repo.product_by_sku(sku)
    if product is None:
        await message.answer(texts.unknown_sku(sku))
        return

    asset = await _resolve_asset(services, message)
    if asset is None:
        return

    hd_account_id = await services.repo.active_hd_account_id()
    if hd_account_id is None:
        # Mid-rotation, or a fresh install with no account provisioned. Issuing
        # against a guessed account produces a valid address whose owner cannot
        # spend it, so this refuses rather than picking one.
        log.error("no active hd_accounts row: /buy cannot be served")
        await message.answer(
            "Payments are temporarily paused. Please try again shortly."
        )
        return

    user = await services.repo.upsert_user(tg_id)
    await issue_invoice(
        message,
        services,
        user_id=user.id,
        product_id=product.id,
        asset=asset,
        hd_account_id=hd_account_id,
    )


async def issue_invoice(
    message: Message,
    services: BotServices,
    *,
    user_id: int,
    product_id: int,
    asset: AssetRow,
    hd_account_id: int,
) -> None:
    """The ask-the-deriver round trip and the full refusal ladder.

    Split out of :func:`cmd_buy` because the free-text path reaches it too — a
    bare sku typed without ``/buy`` must take exactly this path, including every
    branch below, and the only way to be sure of that is for there to be one
    copy of it.
    """
    try:
        view = await services.invoices.acreate_invoice(
            user_id=user_id,
            product_id=product_id,
            chain_id=asset.chain_id,
            asset_id=asset.id,
            hd_account_id=hd_account_id,
            timeout=services.config.request_timeout_seconds,
        )
    except E.IntegrityFailure as exc:
        # Not an InvoiceUnavailable and must never be treated as one: "try again
        # later" would produce the same result, and the correct operator
        # response is to stop taking payments (TZ 5.8/T1.1, T1.3).
        log.critical(
            "integrity failure serving /buy for user_id=%s: %s: %s",
            user_id,
            type(exc).__name__,
            exc,
        )
        await message.answer(exc.user_message)
        return
    except E.InvoiceRequestInFlight as exc:
        # A double-tapped button, not an incident. `uq_invoice_requests_one_open
        # _per_user` answered before an advisory lock was even taken.
        log.info("user_id=%s already has an invoice request in flight", user_id)
        await message.answer(exc.user_message)
        return
    except E.InvoiceRequestTimeout as exc:
        # NOT "that failed". The request row stands and the deriver may still
        # answer it, so the honest advice is /status rather than a retry that
        # would burn the active-invoice quota on a duplicate.
        log.warning("invoice request timed out for user_id=%s: %s", user_id, exc)
        await message.answer(exc.user_message)
        return
    except E.QuotaExceeded as exc:
        log.info("quota %s stopped /buy for user_id=%s: %s", exc.scope, user_id, exc)
        await message.answer(exc.user_message)
        return
    except E.InvoicingError as exc:
        log.warning("/buy refused for user_id=%s (%s): %s", user_id, type(exc).__name__, exc)
        await message.answer(exc.user_message)
        return

    page_url = (
        f"{services.config.invoice_page_base_url}/i/{view.public_token}"
        if services.config.invoice_page_base_url
        else None
    )
    # One message, never edited afterwards (TZ 5.8/T1.5). Everything that
    # happens to this invoice later arrives as a new message, from the notifier.
    await message.answer(
        texts.invoice_issued(view, chain_name=asset.chain_name, page_url=page_url)
    )


async def cmd_status(message: Message, command: CommandObject, services: BotServices) -> None:
    """``/status <invoice_id>`` — state, amounts, confirmations. No address."""
    tg_id = sender_id(message)
    if tg_id is None:
        return
    raw = (command.args or "").strip()
    if not raw:
        await message.answer(texts.status_usage())
        return
    invoice_id = parse_invoice_id(raw)
    if invoice_id is None:
        await message.answer(texts.status_usage())
        return

    user = await services.repo.upsert_user(tg_id)
    await show_status(message, services, user_id=user.id, invoice_id=invoice_id)


async def show_status(
    message: Message, services: BotServices, *, user_id: int, invoice_id: uuid.UUID
) -> None:
    """The ownership-filtered read of TZ 5.8/T1.7, shared with the free-text path.

    ``user_id`` is part of the WHERE clause, not a check applied to the result:
    a filter written as a post-condition is a filter that a future refactor can
    drop without any test noticing, because the query still returns a row.
    """
    row = await services.repo.invoice_status(user_id=user_id, invoice_id=invoice_id)
    if row is None:
        # Same answer for "no such invoice" and "somebody else's invoice".
        await message.answer(texts.status_not_found())
        return
    await message.answer(texts.status(row, now=dt.datetime.now(dt.UTC)))


async def cmd_my(message: Message, services: BotServices) -> None:
    """``/my`` — purchase history and active access."""
    tg_id = sender_id(message)
    if tg_id is None:
        return
    user = await services.repo.upsert_user(tg_id)
    purchases = await services.repo.purchases(user_id=user.id)
    open_invoices = await services.repo.open_invoices(user_id=user.id)
    await message.answer(texts.my(purchases, open_invoices, now=dt.datetime.now(dt.UTC)))


async def cmd_verify(message: Message, command: CommandObject, services: BotServices) -> None:
    """``/verify <invoice_id>`` — the derivation proof of TZ 5.8/T1.4.

    The proof is fetched from the deriver rather than assembled here, and the
    reason is the whole point of the command: every value in the triple is also
    sitting in a table this process can read, and printing those would prove
    only that the database agrees with itself. Under the attacker T1 vector 1
    describes — someone holding UPDATE and nothing else — a database-sourced
    "proof" would print their address under a heading that says it is ours.

    ``user_id`` travels with the request and the deriver filters on it, so a
    proof for somebody else's invoice comes back as
    :class:`~core.invoicing.errors.InvoiceNotFound` — the same answer a
    non-existent id gets (T1.7).
    """
    tg_id = sender_id(message)
    if tg_id is None:
        return
    raw = (command.args or "").strip()
    invoice_id = parse_invoice_id(raw) if raw else None
    if invoice_id is None:
        await message.answer(texts.verify_usage())
        return

    user = await services.repo.upsert_user(tg_id)
    try:
        proof = await services.proofs.arequest_proof(
            user_id=user.id,
            invoice_id=invoice_id,
            timeout=services.config.request_timeout_seconds,
        )
    except E.InvoiceNotFound:
        await message.answer(texts.status_not_found())
        return
    except E.IntegrityFailure as exc:
        log.critical(
            "integrity failure proving invoice %s for user_id=%s: %s: %s",
            invoice_id,
            user.id,
            type(exc).__name__,
            exc,
        )
        await message.answer(exc.user_message)
        return
    except E.InvoicingError as exc:
        log.warning("/verify refused for user_id=%s (%s): %s", user.id, type(exc).__name__, exc)
        await message.answer(exc.user_message)
        return

    await message.answer(
        texts.verify_proof(proof, asked_by_owner=services.config.is_owner(tg_id))
    )


async def cmd_help(message: Message, services: BotServices) -> None:
    """``/help`` — "важнее, чем кажется" (TZ 3.1)."""
    asset = await services.repo.asset(
        chain_id=services.config.chain_id, symbol=services.config.asset_symbol
    )
    await message.answer(
        texts.help_text(
            chain_name=asset.chain_name if asset is not None else str(services.config.chain_id),
            asset_symbol=asset.symbol if asset is not None else services.config.asset_symbol,
        )
    )


def build_router() -> Router:
    """A **new** router every call, with the seven commands of TZ 3.1 on it.

    A factory and not a module-level ``router = Router()`` decorated in place.
    aiogram refuses to attach one router to two parents, so a module-level
    singleton can be included exactly once per process — which is fine for
    production, where there is one dispatcher, and fatal for a test suite that
    builds one per test. Discovering that from the second test rather than from
    the first is why the whole registration table now sits here, visible, in the
    order it is evaluated in.
    """
    router = Router(name="buyer")
    router.message.register(cmd_start, CommandStart())
    router.message.register(cmd_shop, Command("shop"))
    router.message.register(cmd_buy, Command("buy"))
    router.message.register(cmd_status, Command("status"))
    router.message.register(cmd_my, Command("my"))
    router.message.register(cmd_verify, Command("verify"))
    router.message.register(cmd_help, Command("help"))
    return router
