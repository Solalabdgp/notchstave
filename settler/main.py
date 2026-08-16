"""Settler process entrypoint.

A poll loop, not a queue consumer, and that is a Week 2 decision worth stating:
the settler's work is a *function of database state*, not of a message. Every
pass recomputes from the ledger (TZ 5.3), so a missed tick costs latency and
nothing else — there is no event that can be lost, and no consumer offset that
can drift out of sync with the money. A Redis queue in front of this loop is a
latency optimisation for Week 4, in the same category as the advisory lock.

What one pass does, in this order:

1. **Reorgs first.** Rolling back a payment that no longer exists must happen
   before deciding anything else, or the same pass could grant access off a
   block that is already orphaned.
2. **Settle candidates.** Invoices that are live and have money against them.
3. **Sweep expired.** Windows that closed since the last pass.
4. **Anomalies.** Payments that no invoice will ever ask about — chiefly
   ``unassigned_payment``, which by definition has no invoice to settle.

Not wired here (deliberately, with owners named):

* metrics HTTP endpoint — TZ section 7 puts `/metrics` and `/healthz` on the
  api process; ``settler.metrics`` only defines the collectors.
* Redis — see :mod:`settler.locks`. ``REDIS_URL`` being unset is a supported
  production configuration, not a degraded one.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import uuid
from contextlib import suppress

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from settler.locks import InvoiceLock, NullLock
from settler.policy import MoneyPolicy
from settler.service import LIVE_INVOICE_STATUSES, Settler

log = logging.getLogger("notchstave.settler")

#: Invoices worth looking at: live, and with at least one payment that is not
#: already credited or written off. Anything else has no decision pending.
SQL_SETTLE_CANDIDATES = sa.text(
    """
    SELECT DISTINCT i.id
      FROM invoices i
      JOIN payments p ON p.invoice_id = i.id
     WHERE i.status::text = ANY(:live_statuses)
       AND p.status::text = ANY(:open_statuses)
     ORDER BY i.id
     LIMIT :limit
    """
).bindparams(
    sa.bindparam("live_statuses", type_=sa.ARRAY(sa.Text)),
    sa.bindparam("open_statuses", type_=sa.ARRAY(sa.Text)),
)

SQL_ENABLED_CHAINS = sa.text("SELECT chain_id FROM chains WHERE is_enabled ORDER BY chain_id")


def _database_url() -> str:
    """The repo-wide ``DATABASE_URL``, used as-is.

    No rewriting is needed and none is done: ``postgresql+psycopg://`` is the
    same URL for both modes, because psycopg 3 is one driver with a sync and an
    async face and SQLAlchemy picks the async one when the engine is async. A
    second driver (asyncpg) would mean a second set of type adapters for
    ``NUMERIC(78,0)`` in the one place where numeric behaviour is the product.
    """
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set")
    return url


def build_engine(url: str | None = None) -> AsyncEngine:
    return create_async_engine(url or _database_url(), pool_pre_ping=True)


def build_lock() -> InvoiceLock:
    """Redis if configured, nothing if not. Both are correct (TZ 5.8/T2.4)."""
    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        return NullLock()
    from redis.asyncio import Redis  # imported lazily: optional dependency

    from settler.locks import RedisAdvisoryLock

    return RedisAdvisoryLock(Redis.from_url(redis_url, decode_responses=True))


async def run_once(settler: Settler, engine: AsyncEngine, *, batch: int = 200) -> None:
    async with engine.connect() as conn:
        chain_ids = [int(r[0]) for r in (await conn.execute(SQL_ENABLED_CHAINS)).all()]

    for chain_id in chain_ids:
        reorg = await settler.handle_reorg(chain_id)
        if reorg.revoked_entitlement_ids:
            log.error(
                "reorg on chain %s revoked %d entitlement(s): %s",
                chain_id,
                len(reorg.revoked_entitlement_ids),
                reorg.revoked_entitlement_ids,
            )

    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                SQL_SETTLE_CANDIDATES,
                {
                    "live_statuses": list(LIVE_INVOICE_STATUSES),
                    "open_statuses": ["seen", "confirmed"],
                    "limit": batch,
                },
            )
        ).all()
    candidates: list[uuid.UUID] = [r[0] for r in rows]

    for invoice_id in candidates:
        settlement = await settler.settle(invoice_id)
        log.info("invoice %s -> %s", invoice_id, settlement.outcome)

    await settler.sweep_expired()
    await settler.review_anomalies()


async def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    interval = float(os.environ.get("SETTLER_POLL_INTERVAL_SECONDS", "5"))

    engine = build_engine()
    settler = Settler(engine, policy=MoneyPolicy.from_env(), lock=build_lock())

    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):  # Windows has no SIGTERM handler
            loop.add_signal_handler(sig, stopping.set)

    log.info("settler started, policy=%s", settler.policy.version)
    try:
        while not stopping.is_set():
            try:
                await run_once(settler, engine)
            except Exception:  # noqa: BLE001 — a bad pass must not kill the loop
                log.exception("settler pass failed")
            with suppress(TimeoutError):
                await asyncio.wait_for(stopping.wait(), timeout=interval)
    finally:
        await engine.dispose()
        log.info("settler stopped")


if __name__ == "__main__":
    asyncio.run(main())
