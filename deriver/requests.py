"""The ask-the-deriver queue, deriver side (migration 0007).

``core.invoicing.service.create_invoice`` needs the xpub and the
``notchstave_deriver`` role in the same transaction, so an invoice is issued in
this process and nowhere else. ``bot`` and ``api`` therefore ask, and this module
is the half of the conversation that listens.

**Transport: a table plus ``LISTEN``/``NOTIFY``, not a socket.** The argument is
in migration 0007's docstring and is not repeated here; the consequence for this
file is the whole point of it — nothing below opens a socket, imports a server
framework, or resolves a name. The deriver keeps exactly the one outbound
connection it already had (Postgres, via psycopg) and gains a queue on top of
it, which is why ``tests/test_isolation.py`` still passes unmodified.

**This module knows nothing about invoices.** It moves rows between four states
and calls an :class:`InvoiceIssuer` that it is handed. That is not decoration:
``deriver`` may not import ``core`` (see ``deriver/pyproject.toml``), so the
business half — quotas, pricing, the MAC, the exception vocabulary — is injected
by a composition root outside this package (:mod:`core.invoicing.issuer`). The
seam is a port in the clean-architecture sense and it is what keeps the
dependency arrow pointing one way while the process is composed of both halves.

The state machine, and why it has four states rather than two
-------------------------------------------------------------

``pending -> processing -> done | failed``

The obvious design claims a row with ``FOR UPDATE SKIP LOCKED`` and does the
work inside the same transaction, so the claim and the answer commit together.
That is one round trip fewer and it is wrong here, for a specific reason: the
work is ``create_invoice``, which can take an address out of the pool and bump
``next_index``. If the process dies mid-work, the claim rolls back with it and
the row is instantly claimable again — by the same process on restart, in a
loop, with a request that kills it every time. Nothing bounds that.

So the claim is its own committed transaction, and it increments ``attempts``.
A request that crashes its server three times becomes ``failed`` with an honest
reason instead of an outage. The cost is a window: a row can sit in
``processing`` owned by a process that no longer exists.
:func:`reclaim_stale` closes it on a lease, exactly as ``notifications
.next_attempt_at`` does for the notifier (migration 0004).

The answer, in contrast, *does* commit with the work
:func:`complete` runs inside the caller's transaction, the same one
``create_invoice`` wrote the invoice in. Either both exist or neither does, so
there is no state where an invoice was issued and the asker was told it was not.
A refusal is the mirror image: the work transaction is rolled back first
(undoing the address reservation, per ``create_invoice``'s contract) and the
refusal is written afterwards in a transaction of its own.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import psycopg
from psycopg.rows import dict_row

from deriver.pool import AddressDeriver

__all__ = [
    "CHANNEL_REQUESTS",
    "REPLY_CHANNEL_PREFIX",
    "reply_channel",
    "InvoiceRequest",
    "IssuedInvoice",
    "RefusedInvoice",
    "InvoiceOutcome",
    "InvoiceIssuer",
    "listen_for_requests",
    "wait_for_request",
    "claim_next",
    "complete",
    "refuse",
    "requeue",
    "reclaim_stale",
    "prune_completed",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_LEASE_SECONDS",
    "DEFAULT_RETENTION_SECONDS",
]

log = logging.getLogger("notchstave.deriver.requests")

#: Must equal the constants in migration 0007 and in
#: ``core.invoicing.client``. A drifted channel name is a wakeup that never
#: arrives, which is indistinguishable from a slow deriver — so a test asserts
#: the three copies are the same string.
#:
#: Inbound is one shared channel (this process wants every request); replies go
#: to a channel per request, so a waiting bot handler is not woken by every
#: other buyer's answer. See migration 0007 for the fan-out argument.
CHANNEL_REQUESTS = "notchstave_invoice_requests"
REPLY_CHANNEL_PREFIX = "nsr_"


def reply_channel(request_id: uuid.UUID) -> str:
    """The channel migration 0007's trigger notifies when this request finishes.

    Computed identically here and in ``core.invoicing.client``, and identically
    again in PL/pgSQL inside the trigger. Three copies of one rule is one copy
    too many, and the alternative — the deriver sending the notification itself
    — is worse: it would fire on the write rather than on the commit, waking the
    client to read a row it cannot see yet.
    """
    return f"{REPLY_CHANNEL_PREFIX}{request_id.hex}"


#: Claims before a request is declared poison. Three, not one: the realistic
#: cause of a failed attempt is a serialisation failure or a restart, and both
#: succeed on the retry.
DEFAULT_MAX_ATTEMPTS = 3

#: How long a ``processing`` row is presumed to be genuinely in flight. Issuance
#: is a handful of statements in one transaction; thirty seconds is two orders of
#: magnitude of headroom, and the cost of it being too long is that one buyer
#: waits, not that anything is issued twice.
DEFAULT_LEASE_SECONDS = 30.0

#: Finished rows are kept an hour: long enough for a bot that reconnects to read
#: the answer to a question it asked before it restarted, short enough that the
#: table stays a queue instead of becoming a log. The invoice itself is the
#: durable record; this row is a receipt for the conversation about it.
DEFAULT_RETENTION_SECONDS = 3600.0


# ---------------------------------------------------------------------------
# The port
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InvoiceRequest:
    """One claimed row of ``invoice_requests``.

    Everything here was written by ``bot`` or ``api``, so everything here is
    input from outside this trust boundary — including ``user_id``. The issuer
    does not re-authenticate it (the bot verified the Telegram identity before
    inserting) but it also does not need to: the foreign keys make every field a
    reference to a row that already exists, and ``create_invoice`` enforces the
    quota against whichever ``user_id`` arrives. The worst a compromised bot can
    do through this table is spend its own users' quota.
    """

    request_id: uuid.UUID
    user_id: int
    product_id: int
    chain_id: int
    asset_id: int
    hd_account_id: int
    attempts: int
    requested_at: dt.datetime


@dataclass(frozen=True, slots=True)
class IssuedInvoice:
    """The issuer succeeded. ``result_json`` is opaque here, on purpose.

    This module does not parse it and does not build it: JSON is not on the
    deriver's stdlib allow-list (``tests/test_isolation.py``) precisely so that
    invoice *shape* cannot start leaking into the package whose only job is
    keys. The encoding lives in :mod:`core.invoicing.wire`.
    """

    invoice_id: uuid.UUID
    result_json: str


@dataclass(frozen=True, slots=True)
class RefusedInvoice:
    """The issuer declined, on purpose and finally.

    Returned rather than raised, and that distinction carries the retry policy.
    A refusal is an *answer*: a quota was hit, the product is not for sale, the
    address ceiling is full, the address failed to re-derive. Retrying it would
    produce the same answer more slowly. An exception escaping the issuer means
    something unexpected happened — a dropped connection, a deadlock — and those
    are worth another attempt. The queue can only tell the two apart if the
    issuer tells it, and this type is how.
    """

    error_code: str
    error_message: str
    #: Structured operator detail as JSON text, or ``None``. Opaque here for the
    #: same reason ``result_json`` is.
    error_detail: str | None = None


InvoiceOutcome = IssuedInvoice | RefusedInvoice


class InvoiceIssuer(Protocol):
    """What :mod:`core.invoicing.issuer` plugs into this loop.

    Contract, and every clause of it is load-bearing:

    * runs inside ``conn``'s transaction and commits nothing;
    * returns :class:`IssuedInvoice` having written the invoice into that same
      transaction, so the reply and the invoice commit together;
    * returns :class:`RefusedInvoice` for a business refusal, leaving the
      transaction in a state that is safe to roll back;
    * raises for anything else.
    """

    def __call__(
        self,
        conn: psycopg.Connection[Any],
        deriver: AddressDeriver,
        request: InvoiceRequest,
    ) -> InvoiceOutcome: ...


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

#: Claim-by-subquery with ``SKIP LOCKED``, the same shape as the address pool's
#: pickup and for the same reason: two deriver instances must not queue behind
#: each other on one row. ``attempts`` moves here and nowhere else.
#:
#: ``exclude`` is what keeps a retry a retry instead of a spin. A request that
#: fails unexpectedly goes straight back to ``pending``, and without this clause
#: the very next :func:`claim_next` in the same drain would pick it up again —
#: burning a three-attempt budget inside a millisecond, against a database that
#: has not had time to stop being unhappy. Excluding what this pass has already
#: touched makes one pass one attempt, so the retries are spaced by whatever
#: spaces the passes: a notification, or the safety tick.
SQL_CLAIM_NEXT = """
UPDATE invoice_requests AS r
   SET status = 'processing',
       attempts = r.attempts + 1,
       claimed_at = now()
 WHERE r.id = (
           SELECT inner_r.id
             FROM invoice_requests AS inner_r
            WHERE inner_r.status = 'pending'
              AND NOT (inner_r.id = ANY(%(exclude)s::uuid[]))
            ORDER BY inner_r.requested_at
              FOR UPDATE SKIP LOCKED
            LIMIT 1
       )
RETURNING r.id, r.user_id, r.product_id, r.chain_id, r.asset_id,
          r.hd_account_id, r.attempts, r.requested_at
"""

#: Compare-and-set on ``status``: zero rows means the lease expired and somebody
#: else took the request while this pass was working on it. The caller must then
#: roll back rather than commit an invoice nobody will be told about.
SQL_COMPLETE = """
UPDATE invoice_requests
   SET status = 'done',
       invoice_id = %(invoice_id)s,
       result_json = %(result_json)s::jsonb,
       completed_at = now()
 WHERE id = %(request_id)s
   AND status = 'processing'
RETURNING id
"""

SQL_REFUSE = """
UPDATE invoice_requests
   SET status = 'failed',
       error_code = %(error_code)s,
       error_message = %(error_message)s,
       error_detail = %(error_detail)s::jsonb,
       completed_at = now()
 WHERE id = %(request_id)s
   AND status = 'processing'
RETURNING id
"""

SQL_REQUEUE = """
UPDATE invoice_requests
   SET status = 'pending',
       claimed_at = NULL
 WHERE id = %(request_id)s
   AND status = 'processing'
   AND attempts < %(max_attempts)s
RETURNING id, attempts
"""

#: The lease sweep, half one: rows whose owner is gone and which have budget
#: left go back to the queue.
SQL_RECLAIM_STALE = """
UPDATE invoice_requests
   SET status = 'pending',
       claimed_at = NULL
 WHERE status = 'processing'
   AND claimed_at < now() - make_interval(secs => %(lease_seconds)s)
   AND attempts < %(max_attempts)s
RETURNING id
"""

#: Half two: rows out of budget are answered rather than left in limbo. A buyer
#: waiting on one of these gets a refusal instead of a timeout, and the
#: one-open-per-user index unblocks them.
SQL_ABANDON_STALE = """
UPDATE invoice_requests
   SET status = 'failed',
       error_code = %(error_code)s,
       error_message = %(error_message)s,
       completed_at = now()
 WHERE status = 'processing'
   AND claimed_at < now() - make_interval(secs => %(lease_seconds)s)
   AND attempts >= %(max_attempts)s
RETURNING id
"""

SQL_PRUNE = """
DELETE FROM invoice_requests
 WHERE status IN ('done', 'failed')
   AND completed_at < now() - make_interval(secs => %(retention_seconds)s)
"""

#: The class name the client will map back to an exception. Named here rather
#: than in the composition root because this is the one refusal the *transport*
#: authors, not the issuer.
ABANDONED_ERROR_CODE = "InvoiceRequestAbandoned"
ABANDONED_USER_MESSAGE = (
    "We could not create this invoice. Nothing was charged — please try again."
)


# ---------------------------------------------------------------------------
# Waking up
# ---------------------------------------------------------------------------


def listen_for_requests(conn: psycopg.Connection[Any]) -> None:
    """Subscribe this connection to the request channel.

    Must be an autocommit connection: ``LISTEN`` takes effect at commit, and a
    connection sitting in an open transaction will not deliver notifications at
    all. That is the one non-obvious rule of this transport and the reason
    :func:`deriver.main.serve` opens a second connection instead of reusing the
    working one — a listener that is also mid-``create_invoice`` is a listener
    that is deaf for the duration.
    """
    if not conn.autocommit:
        raise ValueError(
            "the listening connection must be autocommit; notifications are not "
            "delivered while a transaction is open"
        )
    conn.execute(f"LISTEN {CHANNEL_REQUESTS}")


def wait_for_request(conn: psycopg.Connection[Any], timeout: float) -> bool:
    """Block until a request arrives or ``timeout`` elapses. True if woken.

    The return value is advisory and the caller is expected to ignore it: a pass
    runs :func:`claim_next` until it comes back empty regardless, because a
    notification can be missed (a reconnect between two commits) and a spurious
    one costs a query. Waking is an optimisation over polling, never the
    correctness argument — which is the same stance ``settler/main.py`` takes
    about its own tick.
    """
    for _ in conn.notifies(timeout=timeout, stop_after=1):
        return True
    return False


# ---------------------------------------------------------------------------
# Moving a request through its states
# ---------------------------------------------------------------------------


def _row_to_request(row: dict[str, Any]) -> InvoiceRequest:
    return InvoiceRequest(
        request_id=row["id"],
        user_id=int(row["user_id"]),
        product_id=int(row["product_id"]),
        chain_id=int(row["chain_id"]),
        asset_id=int(row["asset_id"]),
        hd_account_id=int(row["hd_account_id"]),
        attempts=int(row["attempts"]),
        requested_at=row["requested_at"],
    )


def claim_next(
    conn: psycopg.Connection[Any], *, exclude: Sequence[uuid.UUID] = ()
) -> InvoiceRequest | None:
    """Take the oldest pending request, marking it ``processing``.

    Does not commit — but the caller is expected to, immediately and before
    doing any work. See the module docstring: the claim being durable *before*
    the work starts is what bounds a request that crashes its server.

    ``exclude`` names requests this pass has already attempted; see
    :data:`SQL_CLAIM_NEXT` for why that is not an optimisation.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SQL_CLAIM_NEXT, {"exclude": list(exclude)})
        row = cur.fetchone()
    return None if row is None else _row_to_request(row)


def complete(
    conn: psycopg.Connection[Any], request_id: uuid.UUID, issued: IssuedInvoice
) -> bool:
    """Write the answer. Call inside the transaction that wrote the invoice.

    ``False`` means the row was no longer ``processing`` — the lease expired and
    another pass owns the request now. The caller must roll back: committing
    would leave an invoice that this queue will never tell anyone about, and a
    second one on the way from the other pass.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            SQL_COMPLETE,
            {
                "request_id": request_id,
                "invoice_id": issued.invoice_id,
                "result_json": issued.result_json,
            },
        )
        return cur.fetchone() is not None


def refuse(
    conn: psycopg.Connection[Any], request_id: uuid.UUID, refusal: RefusedInvoice
) -> bool:
    """Record a business refusal. Call in a fresh transaction after a rollback."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            SQL_REFUSE,
            {
                "request_id": request_id,
                "error_code": refusal.error_code,
                "error_message": refusal.error_message,
                "error_detail": refusal.error_detail,
            },
        )
        return cur.fetchone() is not None


def requeue(
    conn: psycopg.Connection[Any],
    request_id: uuid.UUID,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> bool:
    """Put an unexpectedly failed request back. ``False`` once the budget is out.

    A ``False`` here is not an error to swallow: the caller answers the request
    with :func:`refuse` instead, so the buyer gets a sentence rather than a
    ten-second wait that ends in nothing.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SQL_REQUEUE, {"request_id": request_id, "max_attempts": max_attempts})
        return cur.fetchone() is not None


def reclaim_stale(
    conn: psycopg.Connection[Any],
    *,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> tuple[int, int]:
    """Recover rows abandoned by a dead process. Returns ``(requeued, abandoned)``.

    Safe to run concurrently with issuance and safe to run twice: both statements
    are compare-and-set on ``status = 'processing'`` plus a lease predicate, so
    a row that is genuinely in flight is untouched and a row that has already
    been recovered matches nothing.

    Re-running a reclaimed request cannot double-issue. ``create_invoice`` writes
    the invoice and :func:`complete` writes the reply in one transaction; if that
    transaction did not commit, no invoice exists, and if it did, the row is
    ``done`` and neither statement here can see it.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            SQL_RECLAIM_STALE, {"lease_seconds": lease_seconds, "max_attempts": max_attempts}
        )
        requeued = len(cur.fetchall())
        cur.execute(
            SQL_ABANDON_STALE,
            {
                "lease_seconds": lease_seconds,
                "max_attempts": max_attempts,
                "error_code": ABANDONED_ERROR_CODE,
                "error_message": ABANDONED_USER_MESSAGE,
            },
        )
        abandoned = len(cur.fetchall())
    if requeued or abandoned:
        log.warning(
            "reclaimed %d stale invoice request(s), abandoned %d past %d attempt(s)",
            requeued,
            abandoned,
            max_attempts,
        )
    return requeued, abandoned


def prune_completed(
    conn: psycopg.Connection[Any],
    *,
    retention_seconds: float = DEFAULT_RETENTION_SECONDS,
) -> int:
    """Delete finished rows past their retention. Returns how many.

    The deriver prunes its own queue rather than leaving it to the settler,
    because the settler has no grant on this table and giving it one would widen
    a role for housekeeping. Deleting a request never touches the invoice it
    produced: the foreign key runs request -> invoice, and ``ON DELETE RESTRICT``
    guards the other direction.
    """
    with conn.cursor() as cur:
        cur.execute(SQL_PRUNE, {"retention_seconds": retention_seconds})
        return cur.rowcount


def drain(conn: psycopg.Connection[Any]) -> Iterator[InvoiceRequest]:
    """Yield claimed requests until the queue is empty.

    Each yield has been committed as ``processing`` by this function, so the
    consumer starts every request from a durable claim. Written as a generator so
    the loop in :mod:`deriver.main` reads as "for each request" rather than as a
    hand-rolled while with a break.
    """
    attempted: list[uuid.UUID] = []
    while True:
        request = claim_next(conn, exclude=attempted)
        if request is None:
            conn.rollback()
            return
        conn.commit()
        attempted.append(request.request_id)
        yield request
