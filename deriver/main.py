"""Deriver process entry point.

Wires together the pieces of this package and nothing else:

    redaction filter  ->  installed before anything else runs
    xpub credentials  ->  loaded from systemd LoadCredential=
    Deriver           ->  held for the process lifetime
    request loop      ->  claims invoice_requests, calls an injected issuer

The order matters. The logging filter goes in first, before any code that
touches a key, so that a failure during credential loading cannot be the thing
that prints one (TZ 5.8/T4).

**How other processes reach this one.** Through Postgres, and only through
Postgres: ``bot``/``api`` INSERT into ``invoice_requests`` and this loop answers
(migration 0007). That choice is argued in full in 0007's docstring and in
:mod:`deriver.requests`; the consequence for *this* file is that it still opens
no listening socket, imports no server framework and resolves no name. The one
connection it holds is the one it already had.

**What is deliberately not here: the invoice itself.** :func:`serve` takes an
:class:`~deriver.requests.InvoiceIssuer` rather than importing one, because this
package may not import ``core`` (``deriver/pyproject.toml``,
``tests/test_isolation.py``). The production issuer is built in
:mod:`core.invoicing.issuer`, which is also the process's real entry point:

    python -m core.invoicing.issuer

That module is the composition root — the only place where the key-holding half
and the business half of this process are joined. Running *this* module instead
is still supported and still does what it always did: load the keys, print the
fingerprints, exit, so an operator can compare them against the hardware wallet
before a single invoice exists.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from collections.abc import Callable
from types import FrameType
from typing import TYPE_CHECKING, Any

import psycopg

from deriver.pool import AddressDeriver
from deriver.redaction import install as install_redaction
from deriver.requests import (
    ABANDONED_ERROR_CODE,
    ABANDONED_USER_MESSAGE,
    DEFAULT_LEASE_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_RETENTION_SECONDS,
    InvoiceIssuer,
    InvoiceRequest,
    RefusedInvoice,
    complete,
    drain,
    listen_for_requests,
    prune_completed,
    reclaim_stale,
    refuse,
    requeue,
    wait_for_request,
)

if TYPE_CHECKING:  # pragma: no cover
    from deriver.service import Deriver

__all__ = [
    "build_deriver",
    "serve",
    "serve_one",
    "run_once",
    "housekeeping",
    "database_dsn",
    "main",
    "DEFAULT_POLL_INTERVAL_SECONDS",
]

logger = logging.getLogger("notchstave.deriver")

#: The safety tick, not the response time. Requests arrive by ``NOTIFY`` within
#: milliseconds of their commit; this interval only bounds how long a *missed*
#: notification costs — a reconnect between two commits, a restart — and how
#: often the lease sweep and the prune run. Five seconds matches
#: ``SETTLER_POLL_INTERVAL_SECONDS`` so the two loops in this system have one
#: number to reason about instead of two.
DEFAULT_POLL_INTERVAL_SECONDS = 5.0


def build_deriver(credentials_dir: str | None = None) -> Deriver:
    """Load every account xpub from systemd credentials and validate it.

    Every key is parsed at construction, so a wrong, private or non-account key
    fails here — at startup, loudly — rather than on the first customer's
    ``/buy``. Nothing is logged except fingerprints.

    ``deriver.service`` is imported here rather than at module scope, and that is
    a real constraint rather than a style choice: it is the only module in this
    package that pulls in ``bip_utils`` and ``coincurve``, and everything else in
    this file — the whole request loop — needs nothing but the two-method
    :class:`~deriver.pool.AddressDeriver` protocol. Keeping the curve out of the
    import graph is what lets the loop be tested from an environment that has the
    repository's dependencies and not the deriver's isolated ones, which is
    exactly the separation ``deriver/pyproject.toml`` exists to create.
    """
    from deriver.service import Deriver, load_accounts_from_credentials

    install_redaction()
    accounts = load_accounts_from_credentials(credentials_dir)
    deriver = Deriver(accounts)
    logger.info("deriver ready: %s", deriver)  # repr is fingerprints only
    return deriver


def database_dsn(url: str | None = None) -> str:
    """``DATABASE_URL`` as a libpq connection string.

    The repo standardises on SQLAlchemy's ``postgresql+psycopg://`` form
    (``.env.example``, ``alembic.ini``, ``migrations/env.py``) and psycopg does
    not understand the ``+driver`` suffix. Stripped here rather than solved with
    a second environment variable, which would be a second thing to keep in sync
    with the first. Duplicated from ``core.invoicing.tests.conftest`` on purpose:
    four lines copied is the price of not importing ``core`` from this package.
    """
    raw = url or os.environ.get("DATABASE_URL")
    if not raw:
        raise RuntimeError("DATABASE_URL is not set")
    return raw.replace("postgresql+psycopg://", "postgresql://", 1)


# ---------------------------------------------------------------------------
# One request
# ---------------------------------------------------------------------------


def serve_one(
    conn: psycopg.Connection[Any],
    deriver: AddressDeriver,
    issuer: InvoiceIssuer,
    request: InvoiceRequest,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> str:
    """Run the issuer for one claimed request and record the outcome.

    Returns one of ``issued`` / ``refused`` / ``retry`` / ``abandoned`` /
    ``lease_lost``, which the caller logs and (in the composition root) counts.

    The three exits, and why they commit differently:

    * **issued** — :func:`~deriver.requests.complete` runs in the issuer's own
      transaction, so the invoice and the answer become visible together. There
      is no instant at which an invoice exists and its asker has been told
      otherwise.
    * **refused** — roll back first. ``create_invoice`` guarantees that a
      rollback undoes everything it did, including an address it may have taken
      out of the pool; only then is the refusal written, in its own transaction,
      so it survives.
    * **raised** — same rollback, then either back to the queue or, once the
      attempt budget is spent, the same honest refusal. A request that keeps
      killing this process must not be able to keep killing this process.
    """
    try:
        outcome = issuer(conn, deriver, request)
    except Exception:
        # Broad on purpose: this is the boundary between one request and the
        # loop, and an exception escaping here would take down the process that
        # every other buyer is waiting on. The traceback is logged; the buyer
        # gets a sentence.
        conn.rollback()
        logger.exception(
            "invoice request %s failed on attempt %d", request.request_id, request.attempts
        )
        if requeue(conn, request.request_id, max_attempts=max_attempts):
            conn.commit()
            return "retry"
        refuse(
            conn,
            request.request_id,
            RefusedInvoice(
                error_code=ABANDONED_ERROR_CODE, error_message=ABANDONED_USER_MESSAGE
            ),
        )
        conn.commit()
        return "abandoned"

    if isinstance(outcome, RefusedInvoice):
        conn.rollback()
        refuse(conn, request.request_id, outcome)
        conn.commit()
        logger.info(
            "invoice request %s refused: %s", request.request_id, outcome.error_code
        )
        return "refused"

    if not complete(conn, request.request_id, outcome):
        # The lease expired while this pass was working and somebody else owns
        # the request now. Rolling back throws away a perfectly good invoice,
        # which is the correct trade: the alternative is committing one that no
        # reply points at, plus a second one from the other pass.
        conn.rollback()
        logger.error(
            "invoice request %s: lease lost mid-issuance, rolled back", request.request_id
        )
        return "lease_lost"

    conn.commit()
    logger.info(
        "invoice request %s -> invoice %s", request.request_id, outcome.invoice_id
    )
    return "issued"


def run_once(
    conn: psycopg.Connection[Any],
    deriver: AddressDeriver,
    issuer: InvoiceIssuer,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> list[str]:
    """Drain the queue. Returns one outcome label per request served.

    Drains rather than serving a single request per wakeup: notifications can
    coalesce, and a pass that handled one row and went back to sleep would leave
    the rest waiting for the safety tick.
    """
    return [
        serve_one(conn, deriver, issuer, request, max_attempts=max_attempts)
        for request in drain(conn)
    ]


def housekeeping(
    conn: psycopg.Connection[Any],
    *,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    retention_seconds: float = DEFAULT_RETENTION_SECONDS,
) -> tuple[int, int, int]:
    """Lease sweep plus prune. Returns ``(requeued, abandoned, pruned)``.

    Deliberately off the hot path — it runs on the idle tick, not on every
    wakeup, because both statements scan and neither has anything to do while
    requests are flowing.
    """
    requeued, abandoned = reclaim_stale(
        conn, lease_seconds=lease_seconds, max_attempts=max_attempts
    )
    pruned = prune_completed(conn, retention_seconds=retention_seconds)
    conn.commit()
    return requeued, abandoned, pruned


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


class _Stopper:
    """SIGINT/SIGTERM to a boolean, without asyncio.

    ``signal`` and not an ``asyncio.Event``: this process is synchronous by
    construction (``asyncio`` is on the deriver's forbidden-import list, and
    ``deriver.pool``'s statements are sync psycopg), so the loop needs the
    plainest possible shutdown latch.
    """

    __slots__ = ("stopping",)

    def __init__(self) -> None:
        self.stopping = False

    def install(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._handle)
            except (ValueError, OSError, AttributeError):  # pragma: no cover
                # Not the main thread, or a platform without this signal. A loop
                # that cannot latch still stops when its process is killed.
                logger.debug("could not install a handler for %s", sig)

    def _handle(self, signum: int, frame: FrameType | None) -> None:
        logger.info("signal %s received, finishing the current pass", signum)
        self.stopping = True


def serve(
    deriver: AddressDeriver,
    issuer: InvoiceIssuer,
    *,
    dsn: str | None = None,
    poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
    retention_seconds: float = DEFAULT_RETENTION_SECONDS,
    max_passes: int | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> None:
    """Answer ``invoice_requests`` until told to stop.

    **Two connections, not one.** ``LISTEN`` only delivers on a connection with
    no open transaction, and the working connection spends its life inside one.
    A single-connection version is deaf for exactly the window in which requests
    pile up, which is the window that matters.

    ``max_passes`` exists for the tests and for a ``--once`` style operator run;
    ``None`` means forever. ``should_stop`` is a second latch alongside the
    signal handler, for a caller that owns its own lifecycle — the integration
    tests run this loop in a thread, where :func:`signal.signal` is not available
    at all, and a loop that can only be stopped by a signal would be untestable
    exactly where it matters.

    **A connection failure ends the process, deliberately.** ``settler/main.py``
    swallows a bad pass because its work is a pure function of database state and
    the next tick recomputes it. This loop is not in that position: both of its
    connections are long-lived, and a psycopg connection that has dropped stays
    dropped — catching the error would produce a busy loop failing identically
    forever, with a queue filling up behind it and no signal anywhere. Letting it
    propagate hands the reconnect to the supervisor, which is the component that
    can actually perform one. Requests in flight are safe either way: the claim
    is committed, so the lease sweep on the next start recovers them.
    """
    stopper = _Stopper()
    stopper.install()

    def stop_now() -> bool:
        return stopper.stopping or (should_stop is not None and should_stop())

    target = database_dsn(dsn)
    listen_conn = psycopg.connect(target, autocommit=True)
    work_conn = psycopg.connect(target, autocommit=False)
    passes = 0
    try:
        listen_for_requests(listen_conn)
        logger.info(
            "deriver serving invoice requests (poll=%.1fs, lease=%.0fs)",
            poll_interval,
            lease_seconds,
        )
        # One sweep before the first wait: a restart inherits whatever the
        # previous process left in `processing`, and those buyers are already
        # waiting.
        housekeeping(
            work_conn,
            lease_seconds=lease_seconds,
            max_attempts=max_attempts,
            retention_seconds=retention_seconds,
        )

        while not stop_now() and (max_passes is None or passes < max_passes):
            passes += 1
            started = time.monotonic()
            outcomes = run_once(work_conn, deriver, issuer, max_attempts=max_attempts)
            if outcomes:
                logger.debug(
                    "pass served %d request(s) in %.0fms",
                    len(outcomes),
                    (time.monotonic() - started) * 1000,
                )
                # Straight back round: a burst is served in one pass, not one
                # request per tick.
                continue
            if stop_now():
                break
            woken = wait_for_request(listen_conn, timeout=poll_interval)
            if not woken:
                housekeeping(
                    work_conn,
                    lease_seconds=lease_seconds,
                    max_attempts=max_attempts,
                    retention_seconds=retention_seconds,
                )
    finally:
        work_conn.close()
        listen_conn.close()
        logger.info("deriver stopped after %d pass(es)", passes)


def main(argv: list[str] | None = None) -> int:
    """Startup self-check: load the keys, print the fingerprints, exit.

    Meant to be run once on the server after installing the credential, so the
    operator can compare the printed fingerprint against what the hardware
    wallet displays before any invoice is issued (TZ 5.1: until the control
    values match, not a single real payment may be accepted).

    Not the serving entry point. Serving needs an issuer and an issuer needs
    ``core.invoicing``, which this package may not import — see the module
    docstring and :mod:`core.invoicing.issuer`.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    install_redaction()

    args = sys.argv[1:] if argv is None else argv
    credentials_dir = args[0] if args else None

    try:
        deriver = build_deriver(credentials_dir)
    except Exception as exc:  # noqa: BLE001 - top level, message is already key-free
        logger.error("deriver failed to start: %s: %s", type(exc).__name__, exc)
        return 1

    for hd_account_id in deriver.hd_account_ids:
        # Fingerprint plus the first address: the two values an operator can
        # compare against the hardware wallet screen without any tooling.
        logger.info(
            "hd_account_id=%s fingerprint=%s first_address=%s",
            hd_account_id,
            deriver.fingerprint(hd_account_id),
            deriver.address(hd_account_id, 0),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
