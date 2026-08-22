"""Watcher process entry point: one process, one chain (TZ section 4).

The loop is intentionally boring — every interesting decision has already been
made in the module it belongs to, and what is left here is wiring plus the
handful of choices that only make sense at the process level:

* **One chain per process.** `--chain-id` is required and there is no "watch
  everything" mode. TZ section 4 puts a watcher per network, and the reasons are
  operational rather than architectural: a stuck Ethereum provider must not stop
  Base from settling payments, the two chains have different block times and
  therefore different natural poll intervals, and `notchstave_head_lag_blocks`
  is only actionable when one process is behind on one thing.
* **Reorgs re-enter the loop immediately.** A step that reports a reorg has
  rolled the checkpoint back and returned early, so the next iteration re-walks
  from the ancestor without waiting out the poll interval. Sleeping there would
  leave the payment table describing an abandoned branch for a few seconds
  longer for no reason.
* **`ReorgTooDeep` stops the process.** It is the one error here that is not
  retried. A reorg deeper than the configured limit is either a chain-level
  event or a sign the watcher is talking to a node on a different network, and
  in both cases writing more blocks makes the eventual reconciliation harder.
  Exiting non-zero hands the decision to systemd and to a human, which is where
  TZ 5.4 wants it.
* **Everything else is retried with backoff.** A provider outage, a database
  blip, a malformed response: none of them are corruption, all of them are
  transient, and the checkpoint plus the idempotent writes mean a restart costs
  one re-walk of at most one step.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal
import sys

from watcher import metrics
from watcher.config import WatcherSettings, build_pool
from watcher.models import SyncOutcome
from watcher.rpc.pool import RpcPool
from watcher.store.base import WatcherStore
from watcher.traversal import ChainWalker, ReorgTooDeep, rewalk_after_reorg

logger = logging.getLogger("notchstave.watcher")

#: Backoff after an unexpected error in the loop. Short, because the watcher
#: falling behind is itself a payment problem, and bounded, because a provider
#: that is down stays down for minutes rather than milliseconds.
_ERROR_BACKOFF_SECONDS = (1.0, 2.0, 5.0, 10.0, 30.0)


def _log_step(outcome: SyncOutcome, chain_name: str) -> None:
    if outcome.reorg is not None:
        logger.warning(
            "chain=%s reorg depth=%d ancestor=%d — re-walking immediately",
            chain_name,
            outcome.reorg.depth,
            outcome.reorg.common_ancestor,
        )
        return
    if outcome.blocks_written or outcome.payments_written:
        logger.info(
            "chain=%s blocks=%d..%d written=%d payments=%d (dup %d) "
            "filter=%d addresses lag=%d",
            chain_name,
            outcome.from_block,
            outcome.to_block,
            outcome.blocks_written,
            outcome.payments_written,
            outcome.payments_conflicted,
            outcome.filter_size,
            outcome.head_lag,
        )


async def run_forever(
    walker: ChainWalker,
    *,
    poll_interval: float,
    stop: asyncio.Event,
) -> None:
    """Step until `stop` is set. Owns the error policy, nothing else."""
    failures = 0
    while not stop.is_set():
        try:
            outcome = await walker.step()
            failures = 0
        except ReorgTooDeep:
            logger.exception(
                "chain=%s refusing to continue: reorg deeper than the configured limit. "
                "This needs a human (TZ 5.4).",
                walker.chain.name,
            )
            raise
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - the loop is the last line of defence
            delay = _ERROR_BACKOFF_SECONDS[min(failures, len(_ERROR_BACKOFF_SECONDS) - 1)]
            failures += 1
            logger.exception(
                "chain=%s step failed (%d consecutive), retrying in %.1fs",
                walker.chain.name,
                failures,
                delay,
            )
            await _sleep_or_stop(stop, delay)
            continue

        _log_step(outcome, walker.chain.name)

        if outcome.reorg is not None:
            # Re-walk from the ancestor at once, and record the payments that
            # come back attached to a height that is no longer where they were
            # first seen (see `watcher/traversal.py`).
            with contextlib.suppress(Exception):
                await rewalk_after_reorg(walker, outcome.reorg)
            continue

        if outcome.head_lag > 0:
            # Still behind the head: keep going without sleeping.
            continue

        await _sleep_or_stop(stop, poll_interval)


async def _sleep_or_stop(stop: asyncio.Event, seconds: float) -> None:
    """Sleep, but wake up immediately on shutdown."""
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=seconds)


def _install_signal_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, AttributeError):
            # add_signal_handler is POSIX-only; on Windows the KeyboardInterrupt
            # path is what stops a dev run, and suppressing here keeps the same
            # entry point usable on both.
            loop.add_signal_handler(sig, stop.set)


async def run(chain_id: int, settings: WatcherSettings) -> int:
    """Open the store, build the pool from the `chains` row, and loop."""
    from watcher.store.postgres import PostgresWatcherStore

    if not settings.database_url:
        # Not DATABASE_URL: that one is the schema owner and belongs to Alembic.
        # The watcher connects as `notchstave_watcher_login`, a member of
        # `notchstave_watcher`, and there is deliberately no fallback — see
        # `core/db/roles.py` for why an owner fallback is the bug rather than the
        # convenience.
        logger.error(
            "WATCHER_DATABASE_URL is not set: the watcher connects as its own "
            "PostgreSQL login role (notchstave_watcher_login). See .env.example."
        )
        return 2

    store: WatcherStore = PostgresWatcherStore.from_dsn(settings.database_url)
    pool: RpcPool | None = None
    try:
        chain = await store.load_chain(chain_id)
        if not chain.is_enabled:
            logger.error("chain %s (%d) is disabled in `chains`", chain.name, chain_id)
            return 2

        if not metrics.start_exporter(settings.metrics_port):
            # Not fatal, but it must not be quiet: TZ section 7 makes the
            # dashboard part of the deliverable, and a watcher running without
            # an exporter looks identical to a healthy one from the outside.
            logger.warning(
                "prometheus_client is unavailable — running without /metrics on port %d",
                settings.metrics_port,
            )

        pool = build_pool(chain, settings)
        logger.info(
            "chain=%s id=%d providers=%s confirmations=%d finalized_tag=%s checkpoint=%d",
            chain.name,
            chain.chain_id,
            ",".join(pool.provider_names()),
            chain.min_confirmations,
            chain.use_finalized_tag,
            chain.last_indexed_block,
        )

        walker = ChainWalker(chain, pool, store, settings=settings.traversal)
        stop = asyncio.Event()
        _install_signal_handlers(stop)
        await run_forever(walker, poll_interval=settings.poll_interval_seconds, stop=stop)
        return 0
    except ReorgTooDeep:
        return 3
    finally:
        if pool is not None:
            await pool.aclose()
        await store.aclose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="notchstave-watcher",
        description="Watch one EVM chain for incoming payments to the address pool.",
    )
    parser.add_argument(
        "--chain-id",
        type=int,
        required=True,
        help="chains.chain_id to watch. One process per chain (TZ section 4).",
    )
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = WatcherSettings.from_env()
    try:
        return asyncio.run(run(args.chain_id, settings))
    except KeyboardInterrupt:  # pragma: no cover - interactive path
        return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
