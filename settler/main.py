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
2. **Announce what has arrived.** TZ 3.5's «увидели ваш перевод», queued for
   every payment that has not had one. Before settlement, not after: when a
   payment is detected and credited on the same pass, the buyer should read "we
   see it" and then "you have access", and the notifier drains the outbox in
   insertion order. It is also after the reorg pass, so a payment whose block
   was just orphaned is already ``reverted`` and is never announced at all.
3. **Settle candidates.** Invoices that are live and have money against them.
4. **Expire stale quotes.** Unpaid invoices whose ``rate_locked_until`` has
   passed (TZ 5.5). Touches nothing that holds money.
5. **Sweep expired.** Top-up windows that closed since the last pass.
6. **Anomalies.** Payments that no invoice will ever ask about — chiefly
   ``unassigned_payment``, which by definition has no invoice to settle.
7. **Address pool.** Ask the deriver to latch every address that has seen money
   and to schedule the return of every address whose invoice is finished and
   never held any (TZ 5.1 p. 2, migration 0011), then publish the reserved-
   address gauge the T5.2 alert reads. Last in the pass because it reads what
   the six steps above have just decided.

The owner-facing commands of TZ 3.4 — `/pending`, `/resolve`, `/sweeplist`,
`/reconcile` — are **not** on this loop. They are in :mod:`settler.admin`,
called on demand, because each of them is a decision a human takes rather than a
state the database drifts into. `/reconcile` is the one that will eventually
want a schedule; see the TODO at the end of :mod:`settler.admin.reconcile`.

**This process needs ``INVOICE_INTEGRITY_KEY``** and refuses to start without
it. TZ 5.8/T1.3 names the settler as one of the three re-check points for
``integrity_mac`` ("при зачёте в settler"), and :func:`settler.service
.settle_invoice` verifies it under the same row lock the money decision is taken
on. `.env.example` already scoped the key to settler/api/bot; until Week 5 the
settler was the one of those three that never read it.

Not wired here (deliberately, with owners named):

* `/healthz` — TZ section 7 puts it on the api process, and unlike the point
  below there is no cross-process obstacle to that: `/healthz` is a live check
  (DB, Redis, watcher liveness per chain, at least one RPC provider), not a
  registry read, so one process can answer for the others by querying the same
  things they would.
* Redis — see :mod:`settler.locks`. ``REDIS_URL`` being unset is a supported
  production configuration, not a degraded one.

**`/metrics` is wired here**, on its own port (`SETTLER_METRICS_PORT`,
default 9103), the same pattern :mod:`watcher.main` already uses. An earlier
version of this docstring put `/metrics` on the api process too, following TZ
section 7's wording literally — but that cannot work as stated:
``prometheus_client``'s default registry is per-process memory, and the api
process is a different OS process from this one (see `docker-compose.yml`).
Nothing incremented here would be visible to a `collect()` running there
without ``PROMETHEUS_MULTIPROC_DIR`` wiring that does not exist in this repo.
Serving this process's own registry on its own port is what actually gets
these numbers into Prometheus this week; see :func:`settler.metrics
.start_exporter` for the full reasoning.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import os
import signal
import uuid
from contextlib import suppress

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from core.db.roles import process_database_url
from core.invoicing.integrity import load_integrity_key
from settler import metrics
from settler.locks import InvoiceLock, NullLock
from settler.policy import MoneyPolicy
from settler.service import DEFAULT_ADDRESS_COOLDOWN, LIVE_INVOICE_STATUSES, Settler

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
    """``SETTLER_DATABASE_URL`` — this process's own login, not the owner's.

    Not the repo-wide ``DATABASE_URL``, which is the schema owner and is now
    reserved for Alembic and the role-provisioning step. The settler connects as
    ``notchstave_settler_login``, a member of ``notchstave_settler``, so that the
    grant matrix in migrations 0002/0003/0006 is enforced by PostgreSQL rather
    than described by it — an owner connection is never denied anything on its
    own tables, which made every "the settler cannot do X" claim in TZ 5.8
    unenforced. :mod:`core.db.roles` holds the lookup and the argument.

    No URL rewriting is needed and none is done: ``postgresql+psycopg://`` is the
    same URL for both modes, because psycopg 3 is one driver with a sync and an
    async face and SQLAlchemy picks the async one when the engine is async. A
    second driver (asyncpg) would mean a second set of type adapters for
    ``NUMERIC(78,0)`` in the one place where numeric behaviour is the product.
    """
    return process_database_url("settler")


def build_engine(url: str | None = None) -> AsyncEngine:
    return create_async_engine(url or _database_url(), pool_pre_ping=True)


def _address_cooldown() -> dt.timedelta:
    """``SETTLER_ADDRESS_COOLDOWN_SECONDS``, or the default hour.

    Read here rather than inside :mod:`settler.service` for the reason
    :class:`settler.policy.MoneyPolicy` gives about its own thresholds: a test
    must be able to hand in a different value, and a settings singleton read
    three call frames down quietly makes that impossible.
    """
    raw = os.environ.get("SETTLER_ADDRESS_COOLDOWN_SECONDS", "").strip()
    return DEFAULT_ADDRESS_COOLDOWN if not raw else dt.timedelta(seconds=float(raw))


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

    # TZ 3.5, first bullet. Ordered ahead of settlement deliberately — see step 2
    # of the module docstring.
    await settler.notify_seen()

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

    # Rate-lock expiry before the top-up sweep, and the order is not cosmetic:
    # the rate pass only ever touches invoices with no payments, so running it
    # first means an invoice that acquired money since the last tick is already
    # excluded by the time the sweep decides between `expired` and
    # `manual_review`. Reversing them would not corrupt anything — both are CAS —
    # but it would make the log read as though the same invoice was considered
    # twice under two different rules.
    await settler.expire_stale()
    await settler.sweep_expired()
    await settler.review_anomalies()

    # Last, and last for a reason: it reads the state the four passes above have
    # just written. An invoice that expired thirty lines ago is already terminal
    # by the time this looks, so its address is asked for in the same tick rather
    # than in the next one — which for the pass that refills the address pool is
    # the difference between a shop that keeps working and one that runs out of
    # addresses in a week (TZ 5.1 p. 2, 5.8/T5.2).
    latched, released = await settler.sync_addresses()
    if latched or released:
        log.info(
            "address pool: asked the deriver to latch %d and release %d address(es)",
            latched,
            released,
        )


async def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    interval = float(os.environ.get("SETTLER_POLL_INTERVAL_SECONDS", "5"))
    metrics_port = int(os.environ.get("SETTLER_METRICS_PORT", "9103"))

    # Not fatal if it fails (a bad port, one already bound) — same call as
    # watcher.metrics.start_exporter, and the same reasoning: a settler running
    # without an exporter looks identical to a healthy one from the outside,
    # and TZ section 7 makes the dashboard part of the deliverable, so silence
    # here would be the wrong failure mode.
    try:
        metrics.start_exporter(metrics_port)
    except OSError:
        log.exception("could not start /metrics on port %d", metrics_port)

    # Before the engine and before the first pass: TZ 5.8/T1.3 makes the settler
    # one of the three processes that re-check `integrity_mac`, and a settler
    # that cannot check it must not start rather than credit money unchecked.
    # `load_integrity_key` raises with the credential name and the env var when
    # neither is present.
    integrity_key = load_integrity_key()

    engine = build_engine()
    settler = Settler(
        engine,
        policy=MoneyPolicy.from_env(),
        lock=build_lock(),
        integrity_key=integrity_key,
        address_cooldown=_address_cooldown(),
    )

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
