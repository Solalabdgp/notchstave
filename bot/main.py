"""Bot process entry point: wire the four collaborators, then poll.

    python -m bot.main

What this file does and nothing else: load configuration, build the objects
:mod:`bot.services` names, hand them to a :class:`~aiogram.Dispatcher`, and run
long polling until a signal arrives. Every decision worth arguing with is in the
module the object comes from, and the arguments are not repeated here.

**Long polling and not a webhook.** A webhook needs a public TLS endpoint on the
process that talks to Telegram, which is a second inbound surface next to the
api's invoice page and, more to the point, a second thing to get right in a
system whose whole shape is "no process in this repository runs a server"
(migration 0007's docstring). Polling costs one outbound connection and makes
the bot's reachability its own problem rather than the reverse proxy's. If
throughput ever demands a webhook, the handlers do not change.

**The token is loaded, the owner is resolved, and both can fail at startup.** A
process that starts without a token and discovers it on the first ``/start`` has
turned a configuration error into a customer-facing one. The owner's
``users.id`` is resolved the same way — through the ordinary upsert, so the
owner is a user row like everybody else and :class:`~settler.admin.AdminOps` can
be told which one it is (TZ 5.8/T7 wants admin notifications delivered to that
row's chat).

**There is no RPC pool here any more.** ``/reconcile`` and ``/sweeplist`` read
on-chain balances, and until migration 0012 this process built the pool that did
it — which meant the bot carried ``web3``, a provider rotation and a circuit
breaker (TZ 5.6) in order to run two commands whose results it has no grant to
write. Both now execute in the settler, which is where the pool went with them.
A deployment whose ``chains`` row has no ``rpc_urls`` still gets an honest
refusal, raised there and rendered here.

**The admin commands are a queue, not a call.** ``AdminOps`` used to be built on
this process's engine, and once migration 0009 gave every process its own login
role that stopped working: ``/resolve credit`` reaches ``INSERT INTO
entitlements`` as ``notchstave_bot_login``, which migration 0003 revoked in
writing. So this process builds an
:class:`~settler.admin.client.AdminClient` instead — the same four methods, the
same value objects, the same exception classes, one table in between.
"""

from __future__ import annotations

import asyncio
import logging
import os

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from bot.config import BotConfig
from bot.handlers import build_router
from bot.repository import BotRepository
from bot.services import BotServices
from core.db.roles import process_database_url
from core.db.roles import psycopg_dsn as roles_psycopg_dsn
from core.invoicing.client import InvoiceClient
from core.invoicing.integrity import load_integrity_key
from core.invoicing.proof import ProofClient
from core.telegram import load_bot_token
from settler.admin.client import AdminClient

log = logging.getLogger("notchstave.bot")

__all__ = ["build_engine", "psycopg_dsn", "build_services", "build_dispatcher", "main"]


def _database_url() -> str:
    """``BOT_DATABASE_URL`` — this process's own login, not the owner's.

    The bot connects as ``notchstave_bot_login`` (a member of
    ``notchstave_bot``). That role may INSERT a row in ``invoice_requests`` and
    may not answer one (0007), may not mint an invoice (0006) and may not write
    ``receive_addresses`` at all (0002/T1.2) — which is the entire reason `/buy`
    is a queue rather than a function call. None of it was enforced while this
    process connected with the repo-wide ``DATABASE_URL``, i.e. as the user that
    owns the tables. See :mod:`core.db.roles`.
    """
    return process_database_url("bot")


def build_engine(url: str | None = None) -> AsyncEngine:
    return create_async_engine(url or _database_url(), pool_pre_ping=True)


def psycopg_dsn(url: str | None = None) -> str:
    """The bot's own URL as a libpq connection string.

    The repo standardises on SQLAlchemy's ``postgresql+psycopg://`` form and
    psycopg does not understand the ``+driver`` suffix. The two invoicing
    clients talk to psycopg directly — they hold a ``LISTEN`` connection, which
    an ORM session is the wrong shape for — so this process needs both forms of
    the same URL rather than a second environment variable that can drift from
    the first.
    """
    return roles_psycopg_dsn(url or _database_url())


async def build_services(engine: AsyncEngine, config: BotConfig) -> BotServices:
    """Everything the handlers may reach for, built once."""
    key = load_integrity_key()
    dsn = psycopg_dsn()
    repo = BotRepository(engine)

    admin: AdminClient | None = None
    if config.owner_tg_id is not None:
        # The owner is an ordinary `users` row, and it is created here rather
        # than by hand for a reason that outlived the call it was written for:
        # the settler resolves `BOT_OWNER_TG_ID` to a `users.id` so the TZ
        # 5.8/T7 admin notifications have a destination, and it holds SELECT on
        # that table and cannot create the row itself (0002, 0003). This upsert
        # is what makes those alarms deliverable from the first start.
        await repo.upsert_user(config.owner_tg_id)
        # Not `AdminOps(engine, ...)`. That ran every owner money decision under
        # `notchstave_bot_login`, which migration 0003 revoked `INSERT` on
        # `entitlements` from in writing — invisible while every process shared
        # the owner connection, a production `permission denied` on
        # `/resolve credit` once migration 0009 gave each process its own role.
        # Review finding H1; migration 0012 is the fix and this line is it.
        admin = AdminClient(dsn)
    else:
        log.warning("BOT_OWNER_TG_ID is not set: the TZ 3.4 admin commands are disabled")

    return BotServices(
        config=config,
        repo=repo,
        invoices=InvoiceClient(dsn, key, timeout=config.request_timeout_seconds),
        proofs=ProofClient(dsn, key, timeout=config.request_timeout_seconds),
        admin=admin,
    )


def build_dispatcher(services: BotServices) -> Dispatcher:
    """A dispatcher with the routers attached and ``services`` in workflow data.

    aiogram injects anything in the dispatcher's workflow data into a handler
    that names it, which is why every handler signature ends in
    ``services: BotServices`` and why none of them import a singleton.
    """
    dispatcher = Dispatcher()
    dispatcher["services"] = services
    dispatcher.include_router(build_router())
    return dispatcher


async def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(levelname)s %(name)s %(message)s",
    )
    config = BotConfig.from_env()
    engine = build_engine()

    # HTML, set once on the client. `bot.texts` writes HTML and escapes
    # everything that came from outside (`bot.formatting.esc`); a per-call
    # parse_mode would be a thing to forget on the one message that carries an
    # address.
    telegram = Bot(
        token=load_bot_token(),
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )

    services = await build_services(engine, config)
    dispatcher = build_dispatcher(services)

    log.info(
        "bot started: chain=%s asset=%s owner=%s admin=%s",
        config.chain_id,
        config.asset_symbol,
        "set" if config.owner_tg_id is not None else "unset",
        "on" if services.admin is not None else "off",
    )
    try:
        # Drop whatever queued while the process was down. A restart must not
        # replay an hour of `/buy` presses into an hour of invoices, and the
        # people who sent them have long since given up or pressed again.
        await telegram.delete_webhook(drop_pending_updates=True)
        await dispatcher.start_polling(telegram)
    finally:
        await telegram.session.close()
        await engine.dispose()
        log.info("bot stopped")


if __name__ == "__main__":
    asyncio.run(main())
