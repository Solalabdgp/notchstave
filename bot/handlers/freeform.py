"""Messages that are not commands — TZ 3.1's other half of support.

Half of what arrives in a payment bot's chat is a pasted value: a transaction
hash, an address, an invoice id copied out of an earlier message, or a sku typed
without the ``/buy``. Answering all four with "unknown command" is how a payment
question becomes a support ticket, so this router classifies by shape
(:mod:`bot.detect`) and routes to the same code the corresponding command would
have reached.

**The same code, not similar code.** An invoice id goes through
:func:`bot.handlers.buyer.show_status`, which carries the ``user_id`` predicate
of TZ 5.8/T1.7 inside its query; a sku goes through
:func:`bot.handlers.buyer.issue_invoice`, which carries the whole refusal ladder
including the quota answers. A convenience path that re-implemented either would
be a second place for the ownership filter or the integrity check to be missing,
and it would be the copy nobody re-reads.

**A sku is checked before it is acted on.** ``/buy`` on a mistyped code costs a
polite refusal; a *bare* mistyped word costs the same, because the catalogue
lookup happens first and a miss falls through to the help text. Nothing here
creates an invoice on a guess.

This router is registered last. Every command has already had its chance, so
what reaches here is genuinely uncommanded text.
"""

from __future__ import annotations

import logging
import uuid

from aiogram import F, Router
from aiogram.types import Message

from bot import texts
from bot.detect import InputKind, classify
from bot.handlers.buyer import issue_invoice, sender_id, show_status
from bot.services import BotServices

__all__ = ["build_router"]

log = logging.getLogger("notchstave.bot.freeform")


async def on_text(message: Message, services: BotServices) -> None:
    tg_id = sender_id(message)
    if tg_id is None or not message.text:
        return
    if message.text.startswith("/"):
        # A command that no router claimed. Answering it with the sku branch
        # below would try to buy "/pending" for anyone who typed it.
        await message.answer(texts.free_text_unknown())
        return

    detected = classify(message.text)

    if detected.kind is InputKind.TX_HASH:
        explorer = services.config.explorer_base_url
        await message.answer(
            texts.free_text_tx_hash(
                detected.value,
                explorer_url=f"{explorer}/tx/{detected.value}" if explorer else None,
            )
        )
        return

    if detected.kind is InputKind.ADDRESS:
        await message.answer(texts.free_text_address(detected.value))
        return

    if detected.kind is InputKind.INVOICE_ID:
        user = await services.repo.upsert_user(tg_id)
        await show_status(
            message, services, user_id=user.id, invoice_id=uuid.UUID(detected.value)
        )
        return

    if detected.kind is InputKind.SKU:
        product = await services.repo.product_by_sku(detected.value)
        if product is None:
            await message.answer(texts.free_text_unknown())
            return
        asset = await services.repo.asset(
            chain_id=services.config.chain_id, symbol=services.config.asset_symbol
        )
        hd_account_id = await services.repo.active_hd_account_id()
        if asset is None or hd_account_id is None:
            await message.answer("Payments are temporarily paused. Please try again shortly.")
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
        return

    await message.answer(texts.free_text_unknown())


def build_router() -> Router:
    """A new router every call — see :func:`bot.handlers.buyer.build_router`."""
    router = Router(name="freeform")
    router.message.register(on_text, F.text)
    return router
