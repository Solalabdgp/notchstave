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
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING, Any

import psycopg

from deriver import pool
from deriver.pool import AddressDeriver
from deriver.redaction import install as install_redaction
from deriver.requests import (
    ABANDONED_ERROR_CODE,
    ABANDONED_USER_MESSAGE,
    DEFAULT_LEASE_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_RETENTION_SECONDS,
    PROOF_ABANDONED_ERROR_CODE,
    PROOF_ABANDONED_USER_MESSAGE,
    AddressLifecycleRequest,
    InvoiceIssuer,
    InvoiceRequest,
    ProofIssuer,
    ProofRequest,
    RefusedInvoice,
    RefusedProof,
    complete,
    complete_address_request,
    complete_proof,
    drain,
    drain_address_requests,
    drain_proofs,
    listen_for_address_lifecycle,
    listen_for_proofs,
    listen_for_requests,
    prune_completed,
    prune_completed_address_requests,
    prune_completed_proofs,
    reclaim_stale,
    reclaim_stale_address_requests,
    reclaim_stale_proofs,
    refuse,
    refuse_address_request,
    refuse_proof,
    requeue,
    requeue_address_request,
    requeue_proof,
    wait_for_request,
)

if TYPE_CHECKING:  # pragma: no cover
    from deriver.service import Deriver

__all__ = [
    "build_deriver",
    "serve",
    "serve_one",
    "serve_one_proof",
    "serve_one_address_request",
    "run_once",
    "run_once_proofs",
    "run_once_address_requests",
    "release_due_everywhere",
    "housekeeping",
    "housekeeping_proofs",
    "housekeeping_address_requests",
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


#: Where systemd drops this process's connection URL. The URL carries a password,
#: so in production it is a credential file and not an environment variable —
#: same rule and same precedence as the xpub and the integrity key, and for the
#: same reason (an env var is readable from `docker inspect`, `/proc/<pid>/environ`
#: and a core dump).
DATABASE_URL_CREDENTIAL = "notchstave-deriver-database-url"


def database_dsn(url: str | None = None, *, credentials_dir: str | None = None) -> str:
    """``DERIVER_DATABASE_URL`` as a libpq connection string.

    **Not the repo-wide ``DATABASE_URL``.** That variable is the schema *owner*,
    and a table owner is never denied anything on its own tables — so while every
    process used it, the grant matrix of migrations 0002/0006/0007/0008 was never
    evaluated by PostgreSQL at all. This process connects as
    ``notchstave_deriver_login``, a member of ``notchstave_deriver``: the one role
    that may write ``receive_addresses`` (TZ 5.8/T1.2), mint an invoice (0006) and
    answer a request queue (0007/0008). Those are privileges worth holding
    *because* the other five roles provably do not hold them.

    Credential file first, environment second, nothing third. There is no
    fallback to a shared URL: a deriver that cannot find its own credentials must
    fail to start rather than quietly acquire more authority than it is supposed
    to have.

    The ``+driver`` suffix is stripped here because the repo standardises on
    SQLAlchemy's ``postgresql+psycopg://`` form (``.env.example``, ``alembic.ini``,
    ``migrations/env.py``) and psycopg does not understand it. Duplicated from
    :mod:`core.db.roles` on purpose: a dozen lines copied is the price of not
    importing ``core`` from this package, which ``deriver/pyproject.toml`` and
    ``deriver/tests/test_isolation.py`` exist to prevent.
    """
    raw = url
    if raw is None:
        raw_dir = credentials_dir or os.environ.get("CREDENTIALS_DIRECTORY")
        if raw_dir:
            candidate = Path(raw_dir) / DATABASE_URL_CREDENTIAL
            if candidate.is_file():
                raw = candidate.read_text(encoding="utf-8").rstrip("\r\n") or None
    if raw is None:
        raw = os.environ.get("DERIVER_DATABASE_URL")
    if not raw:
        raise RuntimeError(
            "DERIVER_DATABASE_URL is not set. The deriver connects as its own "
            "PostgreSQL login role (notchstave_deriver_login, a member of "
            "notchstave_deriver) so that migration 0002's grant matrix is "
            "enforced by the database and not merely documented by it. There is "
            "no fallback to DATABASE_URL: that is the schema owner. Production "
            f"delivers this as the systemd credential {DATABASE_URL_CREDENTIAL}."
        )
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


def serve_one_proof(
    conn: psycopg.Connection[Any],
    deriver: AddressDeriver,
    issuer: ProofIssuer,
    request: ProofRequest,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> str:
    """Run the proof issuer for one claimed request and record the outcome.

    Returns ``proven`` / ``refused`` / ``retry`` / ``abandoned`` / ``lease_lost``.

    Structurally identical to :func:`serve_one`, with one difference worth
    naming rather than leaving to be inferred: the ``lease_lost`` branch here
    throws away nothing. A proof is a read, so losing the race to another pass
    costs a recomputation and not an invoice — but it is still rolled back and
    still logged, because a lease that expires under a read means the read took
    thirty seconds, and that is worth seeing in a log either way.
    """
    try:
        outcome = issuer(conn, deriver, request)
    except Exception:
        conn.rollback()
        logger.exception(
            "proof request %s failed on attempt %d", request.request_id, request.attempts
        )
        if requeue_proof(conn, request.request_id, max_attempts=max_attempts):
            conn.commit()
            return "retry"
        refuse_proof(
            conn,
            request.request_id,
            RefusedProof(
                error_code=PROOF_ABANDONED_ERROR_CODE,
                error_message=PROOF_ABANDONED_USER_MESSAGE,
            ),
        )
        conn.commit()
        return "abandoned"

    if isinstance(outcome, RefusedProof):
        conn.rollback()
        refuse_proof(conn, request.request_id, outcome)
        conn.commit()
        logger.info(
            "proof request %s refused: %s", request.request_id, outcome.error_code
        )
        return "refused"

    if not complete_proof(conn, request.request_id, outcome):
        conn.rollback()
        logger.error("proof request %s: lease lost mid-proof, rolled back", request.request_id)
        return "lease_lost"

    conn.commit()
    logger.info("proof request %s -> invoice %s proven", request.request_id, request.invoice_id)
    return "proven"


def serve_one_address_request(
    conn: psycopg.Connection[Any],
    request: AddressLifecycleRequest,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> str:
    """Apply one address transition the settler asked for (migration 0011).

    Returns ``applied`` / ``noop`` / ``refused`` / ``retry`` / ``abandoned`` /
    ``lease_lost``.

    No issuer port here, unlike :func:`serve_one` and :func:`serve_one_proof`:
    the work is two statements in :mod:`deriver.pool`, both of them in this
    package, neither of them needing anything from ``core``. Injecting a
    callable to reach code that is already importable would be ceremony.

    **``noop`` is a success, not a silence.** ``schedule_release`` returns False
    when the address is no longer ``reserved`` and ``mark_address_funded``
    returns False when it is in a status the latch does not cover. Both mean the
    world moved on between the settler's sweep and this pass — an invoice paid,
    an address already latched — and the correct answer is to close the request,
    not to retry it three times and then declare a failure. The settler's next
    sweep re-derives the truth from the ledger either way.

    A genuinely unknown ``action`` is refused rather than ignored. It can only
    arrive from a deployment where the enum grew a value this binary does not
    know, and quietly marking such a row ``done`` would report success for work
    that never happened.
    """
    try:
        if request.action == "release":
            if request.cooldown_until is None:  # pragma: no cover - CHECK forbids it
                raise ValueError("release request without a cooldown_until")
            changed = pool.schedule_release(conn, request.address_id, request.cooldown_until)
        elif request.action == "mark_funded":
            changed = pool.mark_address_funded(conn, request.address_id)
        else:
            conn.rollback()
            refuse_address_request(
                conn,
                request.request_id,
                error_code="UnknownAddressAction",
                error_message=f"this deriver does not implement action {request.action!r}",
            )
            conn.commit()
            logger.error(
                "address request %s asks for unknown action %r",
                request.request_id,
                request.action,
            )
            return "refused"
    except Exception:
        # Same boundary as serve_one: one bad request must not take down the
        # process every other request is queued behind.
        conn.rollback()
        logger.exception(
            "address request %s (%s on address %d) failed on attempt %d",
            request.request_id,
            request.action,
            request.address_id,
            request.attempts,
        )
        if requeue_address_request(conn, request.request_id, max_attempts=max_attempts):
            conn.commit()
            return "retry"
        refuse_address_request(
            conn,
            request.request_id,
            error_code="AddressLifecycleFailed",
            error_message="the transition raised on every attempt; see the deriver log",
        )
        conn.commit()
        return "abandoned"

    if not complete_address_request(conn, request.request_id):
        conn.rollback()
        logger.error(
            "address request %s: lease lost mid-transition, rolled back", request.request_id
        )
        return "lease_lost"

    conn.commit()
    logger.info(
        "address request %s: %s on address %d -> %s",
        request.request_id,
        request.action,
        request.address_id,
        "applied" if changed else "already in that state",
    )
    return "applied" if changed else "noop"


def release_due_everywhere(conn: psycopg.Connection[Any]) -> int:
    """Return every address that now satisfies all three TZ 5.1 conditions.

    The second half of the release path, and the half nothing asks for: a
    ``release`` request only writes ``cooldown_until``, because condition 2 is a
    *deadline* and the address is not returnable until it passes. Somebody has
    to come back later, and this is that somebody.

    Run on the idle tick rather than per request. The predicate is
    time-dependent, so running it more often than the poll interval finds
    nothing new, and running it per request would make a burst of expiries scan
    the table once each.

    All three conditions stay in ``deriver.pool.SQL_RELEASE_DUE``'s WHERE clause
    and are deliberately not restated here — see that statement's comment for
    why a caller must not be able to release an address by taking a different
    code path.
    """
    released = 0
    for hd_account_id in pool.hd_account_ids(conn):
        freed = pool.release_due_addresses(conn, hd_account_id)
        released += len(freed)
        if freed:
            logger.info(
                "returned %d address(es) to the free pool on hd_account_id=%d: %s",
                len(freed),
                hd_account_id,
                [a.derivation_index for a in freed],
            )
    conn.commit()
    return released


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


def run_once_proofs(
    conn: psycopg.Connection[Any],
    deriver: AddressDeriver,
    issuer: ProofIssuer,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> list[str]:
    """Drain the proof queue. Returns one outcome label per request served."""
    return [
        serve_one_proof(conn, deriver, issuer, request, max_attempts=max_attempts)
        for request in drain_proofs(conn)
    ]


def run_once_address_requests(
    conn: psycopg.Connection[Any],
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> list[str]:
    """Drain the address-lifecycle queue. One outcome label per request."""
    return [
        serve_one_address_request(conn, request, max_attempts=max_attempts)
        for request in drain_address_requests(conn)
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


def housekeeping_proofs(
    conn: psycopg.Connection[Any],
    *,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    retention_seconds: float = DEFAULT_RETENTION_SECONDS,
) -> tuple[int, int, int]:
    """The same sweep for the proof queue (migration 0008).

    A separate function rather than a flag on :func:`housekeeping`, because
    :func:`serve` runs the proof half only when it was given a proof issuer —
    sweeping a queue nobody is serving would answer requests with "abandoned"
    that a correctly configured deployment is about to answer properly.
    """
    requeued, abandoned = reclaim_stale_proofs(
        conn, lease_seconds=lease_seconds, max_attempts=max_attempts
    )
    pruned = prune_completed_proofs(conn, retention_seconds=retention_seconds)
    conn.commit()
    return requeued, abandoned, pruned


def housekeeping_address_requests(
    conn: psycopg.Connection[Any],
    *,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    retention_seconds: float = DEFAULT_RETENTION_SECONDS,
) -> tuple[int, int, int]:
    """The same sweep for the lifecycle queue, plus the due-release pass.

    The extra step is why this is not a third copy of the two above: releasing
    an address whose cooldown has expired is a scheduled job with no queue row
    behind it (see :func:`release_due_everywhere`), and the idle tick is exactly
    where it belongs. Bundling it here rather than giving it its own timer keeps
    the loop in :func:`serve` to one shape.

    Unlike :func:`housekeeping_proofs`, this always runs — there is no optional
    port to gate it on, and a deployment whose settler is newer than its deriver
    would otherwise fill the queue with rows nobody ever answers.
    """
    requeued, abandoned = reclaim_stale_address_requests(
        conn, lease_seconds=lease_seconds, max_attempts=max_attempts
    )
    pruned = prune_completed_address_requests(conn, retention_seconds=retention_seconds)
    conn.commit()
    release_due_everywhere(conn)
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
    proof_issuer: ProofIssuer | None = None,
    dsn: str | None = None,
    poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
    retention_seconds: float = DEFAULT_RETENTION_SECONDS,
    max_passes: int | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> None:
    """Answer ``invoice_requests`` — and, given ``proof_issuer``, proofs too.

    **Two connections, not one.** ``LISTEN`` only delivers on a connection with
    no open transaction, and the working connection spends its life inside one.
    A single-connection version is deaf for exactly the window in which requests
    pile up, which is the window that matters.

    **One listener for all three queues.** Every ``LISTEN`` goes on the same
    connection, so a wakeup from any channel ends the wait and the pass then
    drains all of them. That is strictly better than three waits: a notification
    is only ever a hint here (the pass re-reads regardless), so the cost of being
    woken by another queue is one empty claim, and the alternative — a second
    connection parked on a second wait — would multiply the idle connections of a
    process whose whole design story is that it holds exactly one outbound link.

    The third queue is ``address_lifecycle_requests`` (migration 0011): the
    settler handing a receive address back to the pool, or latching it out of it
    for good. Unlike the two above it is not optional and takes no port — see
    :func:`serve_one_address_request`. Its housekeeping also carries the
    scheduled half of the return path (:func:`release_due_everywhere`), which is
    the pass that actually refills the free pool.

    ``proof_issuer`` is optional so that the invoice queue keeps working on a
    deploy where 0008 has not been applied yet, and so that a test that cares
    about issuance does not have to supply a second port. Production always
    passes one — :func:`core.invoicing.issuer.main` builds both.

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
    def sweep() -> None:
        housekeeping(
            work_conn,
            lease_seconds=lease_seconds,
            max_attempts=max_attempts,
            retention_seconds=retention_seconds,
        )
        if proof_issuer is not None:
            housekeeping_proofs(
                work_conn,
                lease_seconds=lease_seconds,
                max_attempts=max_attempts,
                retention_seconds=retention_seconds,
            )
        housekeeping_address_requests(
            work_conn,
            lease_seconds=lease_seconds,
            max_attempts=max_attempts,
            retention_seconds=retention_seconds,
        )

    try:
        listen_for_requests(listen_conn)
        if proof_issuer is not None:
            listen_for_proofs(listen_conn)
        listen_for_address_lifecycle(listen_conn)
        logger.info(
            "deriver serving invoice requests%s and address lifecycle "
            "(poll=%.1fs, lease=%.0fs)",
            ", derivation proofs" if proof_issuer is not None else "",
            poll_interval,
            lease_seconds,
        )
        # One sweep before the first wait: a restart inherits whatever the
        # previous process left in `processing`, and those buyers are already
        # waiting.
        sweep()

        while not stop_now() and (max_passes is None or passes < max_passes):
            passes += 1
            started = time.monotonic()
            outcomes = run_once(work_conn, deriver, issuer, max_attempts=max_attempts)
            if proof_issuer is not None:
                outcomes += run_once_proofs(
                    work_conn, deriver, proof_issuer, max_attempts=max_attempts
                )
            outcomes += run_once_address_requests(work_conn, max_attempts=max_attempts)
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
                sweep()
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
