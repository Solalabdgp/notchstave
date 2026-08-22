"""The four owner commands of TZ 3.4, as aiogram wiring over :mod:`settler.admin`.

**This module contains no money logic and must never acquire any.** Every
command below parses arguments, checks one ``tg_id``, calls one method on
:class:`settler.admin.client.AdminClient`, and renders the value object it gets
back. The decisions — the two-step threshold, the CAS on ``resolved_at``, the
entitlement insert, the audit row — all live on the other side of that call,
under the *settler's* database role, and since migration 0012 in the settler's
*process*: the call is a row in ``admin_action_requests`` and a wait on a
``NOTIFY``. Nothing in the signatures changed, which is why this module barely
did.

That split is the answer to TZ 5.8/T7. Its premise is that the owner's Telegram
account is captured; the ``tg_id`` check does nothing about that and is not
claimed to. What holds afterwards is structural: a compromised bot process can
issue commands and still cannot write ``entitlements`` (migration 0003 revokes
INSERT from every role but the settler's), and ``/resolve refund`` can only
record an obligation because nothing in this repository can build, sign or
broadcast a transaction (TZ 12). *"Компрометация самого привилегированного
аккаунта системы не приводит к потере средств"* is a claim the code has to keep
true, and the way it keeps it true is by not containing the capability.

**Why a denied command answers like an unknown one.** :func:`bot.texts
.admin_denied` returns the same sentence a mistyped word gets, and ``/help``
does not list these commands. Confirming that ``/resolve`` exists tells whoever
is probing that there is an owner account worth phishing, which is free
reconnaissance for a threat model whose premise is exactly that.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
import uuid

from aiogram import Router
from aiogram.filters import Command, CommandObject
from aiogram.types import BufferedInputFile, Message

from bot import admin_texts, texts
from bot.handlers.buyer import sender_id
from bot.services import BotServices
from settler.admin.errors import (
    AdminError,
    BalancesUnavailable,
    ConfirmationRequired,
    InvalidConfirmationCode,
    ResolutionNotApplicable,
    ReviewAlreadyResolved,
    ReviewNotFound,
)

__all__ = ["build_router"]

log = logging.getLogger("notchstave.bot.admin")

#: ``code=ABCD1234`` anywhere in the argument tail. A named token rather than a
#: positional one because the comment is free text and a positional code would
#: be indistinguishable from a one-word comment — which is how an owner ends up
#: crediting two hundred dollars by writing the word "urgent".
_CODE = re.compile(r"\bcode=([A-Za-z0-9]{4,32})\b")

_RESOLUTIONS = ("credit", "refund", "reject")


def _is_owner(message: Message, services: BotServices) -> bool:
    return services.config.is_owner(sender_id(message))


async def _deny(message: Message) -> None:
    log.warning(
        "admin command from non-owner tg_id=%s: %r",
        sender_id(message),
        (message.text or "")[:64],
    )
    await message.answer(texts.admin_denied())


async def cmd_pending(message: Message, services: BotServices) -> None:
    if not _is_owner(message, services):
        await _deny(message)
        return
    if services.admin is None:
        await message.answer(admin_texts.admin_unconfigured())
        return
    # `/pending` used to be a local query and could not fail in a way worth
    # catching. It is a request to another process now (migration 0012), so the
    # settler being down is a normal outcome and has to read as one rather than
    # as an aiogram traceback in a chat window.
    try:
        cases = await services.admin.pending(operator_id=services.config.owner_tg_id)
    except AdminError as exc:
        log.exception("/pending failed")
        await message.answer(f"Could not read the open cases: {exc}")
        return
    await message.answer(admin_texts.pending(cases))


async def cmd_resolve(message: Message, command: CommandObject, services: BotServices) -> None:
    """``/resolve <invoice_id> <credit|refund|reject> [comment]`` (TZ 3.4).

    The command takes an *invoice* id and :func:`settler.admin
    .resolve_manual_review` takes a *case* id; turning one into the other is
    this handler's job, and it refuses when the answer is not unique. A single
    invoice can carry an underpayment case and a stray-token case at the same
    time, and picking one for the owner would close a decision nobody made — so
    a case number is also accepted directly, which is the unambiguous form.
    """
    if not _is_owner(message, services):
        await _deny(message)
        return
    if services.admin is None or services.config.owner_tg_id is None:
        await message.answer(admin_texts.admin_unconfigured())
        return

    raw = (command.args or "").strip()
    parts = raw.split()
    if len(parts) < 2 or parts[1].lower() not in _RESOLUTIONS:
        await message.answer(admin_texts.resolve_usage())
        return

    target, verb = parts[0], parts[1].lower()
    tail = " ".join(parts[2:])
    match = _CODE.search(tail)
    confirmation_code = match.group(1) if match else None
    # Whitespace collapsed after the token is cut out, not just trimmed at the
    # ends: the comment goes into `audit_log.note` verbatim, and a gap left
    # where `code=ABCD1234` used to be is a permanent record of where a
    # confirmation code once was — legible to anyone reading the audit trail,
    # and pointless.
    comment = " ".join(_CODE.sub(" ", tail).split()) or None

    review_id = await _review_id_for(message, services, target)
    if review_id is None:
        return

    try:
        result = await services.admin.resolve(
            review_id,
            verb,
            services.config.owner_tg_id,
            comment,
            confirmation_code=confirmation_code,
        )
    except ConfirmationRequired as exc:
        # Raised *after* the commit that recorded the attempt (see AdminOps),
        # so this message is the second half of a control and not a dead end.
        await message.answer(admin_texts.confirmation_required(exc))
        return
    except InvalidConfirmationCode:
        await message.answer(
            "That confirmation code does not belong to this decision, or it has "
            "expired. Re-run the command without a code to get a fresh one."
        )
        return
    except ReviewNotFound:
        await message.answer(admin_texts.no_open_case(target))
        return
    except ReviewAlreadyResolved:
        await message.answer(
            "That case was already resolved. Your decision did <b>not</b> take "
            "effect — /pending shows what is still open."
        )
        return
    except ResolutionNotApplicable as exc:
        await message.answer(f"That resolution does not apply to this case: {exc}")
        return
    except AdminError as exc:
        log.exception("/resolve failed on case %s", review_id)
        await message.answer(f"Could not resolve this case: {exc}")
        return

    await message.answer(admin_texts.resolution(result))


async def _review_id_for(
    message: Message, services: BotServices, target: str
) -> int | None:
    """Accept a case number as itself, an invoice id by lookup, refuse ambiguity."""
    if target.isdigit():
        return int(target)
    try:
        invoice_id = uuid.UUID(target)
    except ValueError:
        await message.answer(admin_texts.resolve_usage())
        return None

    cases = await services.repo.open_cases_for_invoice(invoice_id)
    if not cases:
        await message.answer(admin_texts.no_open_case(invoice_id))
        return None
    if len(cases) > 1:
        await message.answer(admin_texts.ambiguous_cases(invoice_id, cases))
        return None
    return cases[0].review_id


async def cmd_sweeplist(message: Message, services: BotServices) -> None:
    """``/sweeplist`` — the CSV, and nothing else (TZ 3.4, TZ 12)."""
    if not _is_owner(message, services):
        await _deny(message)
        return
    if services.admin is None:
        await message.answer(admin_texts.admin_unconfigured())
        return

    asset = await services.repo.asset(
        chain_id=services.config.chain_id, symbol=services.config.asset_symbol
    )
    if asset is None:
        await message.answer(admin_texts.balances_unavailable())
        return

    # The file reference is decided before the file is sent, because
    # `generate_sweep_list` records it in the same transaction as the export
    # row. A Telegram `file_id` would only exist afterwards, and a record
    # pointing at a delivery that has not happened yet is worse than a filename
    # that names exactly what was produced.
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    filename = f"sweep-{asset.chain_id}-{asset.symbol.lower()}-{stamp}.csv"

    try:
        export = await services.admin.sweeplist(
            chain_id=asset.chain_id,
            asset_id=asset.id,
            file_ref=filename,
            operator_id=services.config.owner_tg_id,
        )
    except BalancesUnavailable:
        # The check that used to live at the top of this handler, now raised by
        # the process that owns the RPC pool. Same sentence for the owner: the
        # command cannot answer, and an export built against unreadable balances
        # would list every address as empty.
        await message.answer(admin_texts.balances_unavailable())
        return
    except AdminError as exc:
        log.exception("/sweeplist failed")
        await message.answer(f"Could not build the sweep list: {exc}")
        return

    await message.answer_document(
        BufferedInputFile(export.csv_text.encode("utf-8"), filename=filename),
        caption=admin_texts.sweeplist_caption(export),
    )


async def cmd_reconcile(message: Message, services: BotServices) -> None:
    """``/reconcile`` — the ledger against the chain (TZ 3.4)."""
    if not _is_owner(message, services):
        await _deny(message)
        return
    if services.admin is None:
        await message.answer(admin_texts.admin_unconfigured())
        return

    asset = await services.repo.asset(
        chain_id=services.config.chain_id, symbol=services.config.asset_symbol
    )
    if asset is None:
        await message.answer(admin_texts.balances_unavailable())
        return

    try:
        report = await services.admin.reconcile(
            chain_id=asset.chain_id,
            asset_id=asset.id,
            operator_id=services.config.owner_tg_id,
        )
    except BalancesUnavailable:
        await message.answer(admin_texts.balances_unavailable())
        return
    except Exception as exc:  # noqa: BLE001 — RPC and pricing both surface here
        # `UnknownRate` is the realistic one: a drift exists and cannot be
        # priced. Defaulting to a rate of 1 or 0 would either invent a
        # six-figure alert or silence the system's most serious one, so the
        # command reports that it could not answer.
        log.exception("/reconcile failed")
        await message.answer(f"Reconcile could not complete: {exc}")
        return

    await message.answer(admin_texts.reconcile_report(report))


def build_router() -> Router:
    """A new router every call — see :func:`bot.handlers.buyer.build_router`.

    The four commands are registered together and every one of them opens with
    the same owner check inside the handler, rather than with a router-level
    filter. A filter would be the tidier arrangement and is the wrong one here:
    an update that fails a router filter falls through to the *next* router, so
    a non-owner's ``/resolve`` would reach the free-text handler and be
    classified as a sku. Refusing inside the handler keeps the denial and the
    unknown-command sentence identical (:func:`bot.texts.admin_denied`) without
    the update ever leaving this module.
    """
    router = Router(name="admin")
    router.message.register(cmd_pending, Command("pending"))
    router.message.register(cmd_resolve, Command("resolve"))
    router.message.register(cmd_sweeplist, Command("sweeplist"))
    router.message.register(cmd_reconcile, Command("reconcile"))
    return router
