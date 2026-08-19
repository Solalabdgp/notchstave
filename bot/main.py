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

**Why the RPC pool is built here and tolerated missing.** ``/reconcile`` and
``/sweeplist`` read on-chain balances through the watcher's pool — one rotation,
one circuit breaker, one budget (TZ 5.6), and there is no second pool in this
repository. Building it needs provider URLs on the ``chains`` row, which a fresh
checkout does not have. A failure here therefore disables those two commands
with a message that says so, rather than stopping the bot: a payment bot that
will not start because a *reconciliation* dependency is missing is a worse
outcome than two owner commands answering honestly.
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
from core.invoicing.client import InvoiceClient
from core.invoicing.integrity import load_integrity_key
from core.invoicing.proof import ProofClient
from core.telegram import load_bot_token
from settler.admin.balances import BalanceSource
from settler.admin.ops import AdminOps

log = logging.getLogger("notchstave.bot")

__all__ = ["build_engine", "psycopg_dsn", "build_services", "build_dispatcher", "main"]


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set")
    return url


def build_engine(url: str | None = None) -> AsyncEngine:
    return create_async_engine(url or _database_url(), pool_pre_ping=True)


def psycopg_dsn(url: str | None = None) -> str:
    """``DATABASE_URL`` as a libpq connection string.

    The repo standardises on SQLAlchemy's ``postgresql+psycopg://`` form and
    psycopg does not understand the ``+driver`` suffix. The two invoicing
    clients talk to psycopg directly — they hold a ``LISTEN`` connection, which
    an ORM session is the wrong shape for — so this process needs both forms of
    the same URL rather than a second environment variable that can drift from
    the first.
    """
    return (url or _database_url()).replace("postgresql+psycopg://", "postgresql://", 1)


async def build_balance_source(engine: AsyncEngine, chain_id: int) -> BalanceSource | None:
    """The watcher's RPC pool for one chain, or ``None`` with a reason logged.

    Imported inside the function because it pulls in ``web3``: a bot that cannot
    reconcile should still start in a couple of hundred milliseconds, and the
    two commands that need this are run by one person occasionally.
    """
    try:
        import sqlalchemy as sa

        from settler.admin.balances import RpcBalanceSource
        from watcher.config import WatcherSettings, build_pool
        from watcher.store.base import ChainConfigRow

        async with engine.begin() as conn:
            row = (
                await conn.execute(
                    sa.text(
                        "SELECT chain_id, name, rpc_urls, min_confirmations, "
                        "       credit_threshold_usd, use_finalized_tag, "
                        "       last_indexed_block, is_enabled "
                        "  FROM chains WHERE chain_id = :chain_id"
                    ),
                    {"chain_id": chain_id},
                )
            ).mappings().first()
        if row is None or not row["rpc_urls"]:
            log.warning(
                "chain %s has no rpc_urls: /reconcile and /sweeplist are disabled", chain_id
            )
            return None

        pool = build_pool(ChainConfigRow(**dict(row)), WatcherSettings.from_env())
        return RpcBalanceSource(pool)
    except Exception as exc:  # noqa: BLE001 — startup convenience, never a payment path
        log.warning(
            "no RPC balance source for chain %s (%s: %s): /reconcile and /sweeplist "
            "will say so rather than reconcile against zero",
            chain_id,
            type(exc).__name__,
            exc,
        )
        return None


async def build_services(engine: AsyncEngine, config: BotConfig) -> BotServices:
    """Everything the handlers may reach for, built once."""
    key = load_integrity_key()
    dsn = psycopg_dsn()
    repo = BotRepository(engine)

    admin: AdminOps | None = None
    if config.owner_tg_id is not None:
        # The owner is an ordinary `users` row. Creating it here rather than
        # requiring a manual INSERT means the admin notifications of TZ 5.8/T7
        # have somewhere to go from the first start.
        owner = await repo.upsert_user(config.owner_tg_id)
        admin = AdminOps(engine, owner_user_id=owner.id)
    else:
        log.warning("BOT_OWNER_TG_ID is not set: the TZ 3.4 admin commands are disabled")

    return BotServices(
        config=config,
        repo=repo,
        invoices=InvoiceClient(dsn, key, timeout=config.request_timeout_seconds),
        proofs=ProofClient(dsn, key, timeout=config.request_timeout_seconds),
        admin=admin,
        balances=await build_balance_source(engine, config.chain_id),
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
        "bot started: chain=%s asset=%s owner=%s admin=%s balances=%s",
        config.chain_id,
        config.asset_symbol,
        "set" if config.owner_tg_id is not None else "unset",
        "on" if services.admin is not None else "off",
        "on" if services.balances is not None else "off",
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
