"""Ask the settler to run an owner command. The four calls the bot makes.

    from settler.admin.client import AdminClient

    admin = AdminClient(dsn)
    result = await admin.resolve(review_id, "credit", owner_tg_id)

This class is a drop-in for the four methods of
:class:`~settler.admin.ops.AdminOps` minus one argument — ``balances`` is gone,
because on-chain balances are now read in the process that executes the command
rather than in the one that requests it. Everything else is the same: the same
value objects come back, and the same exception classes come out.

That is the whole design goal. The commands used to be in-process calls, and
migration 0012 explains why they could not stay that way: after migration 0009
gave each process its own login role, ``AdminOps`` on the bot's engine reaches
``INSERT INTO entitlements`` as ``notchstave_bot_login`` and is denied, which is
migration 0003's single-writer rule finally being enforced rather than described.
Keeping the *call surface* identical is what let the change stay inside
``bot/main.py`` and four lines of ``bot/handlers/admin.py`` instead of spreading
through the handlers.

**Everything it raises is a** :class:`~settler.admin.errors.AdminError`. The
three additions to that hierarchy are the ones only a queue can produce:

* :class:`~settler.admin.errors.AdminUnavailable` — no answer in time. It means
  **nothing is known**, not "nothing happened": the row is not withdrawn and the
  settler may still serve it, which is why the message says to check ``/pending``
  rather than to try again.
* :class:`~settler.admin.errors.BalancesUnavailable` — the settler has no RPC
  pool for that chain. Previously the bot answered this itself, from its own
  missing pool.
* :class:`~settler.admin.errors.AdminActionFailed` — the settler raised
  something outside this vocabulary (``UnknownRate``, an open circuit breaker).

**Why it is synchronous underneath**, and why a connection per call: the same
two reasons :mod:`core.invoicing.client` gives for itself, and the same code
shape, deliberately. The wait is a blocking ``LISTEN`` on a connection with no
open transaction, which is what makes the round trip a notification rather than
a poll; ``LISTEN`` on a pooled connection that is sometimes mid-query is a source
of load-dependent misses. These four commands are run by one person
occasionally, so a connect per call is not a cost worth engineering away.

**The reply is not authenticated, and does not need to be.** 0007's reply
carries the address a buyer will pay and therefore carries a MAC. This one
carries a report on decisions the settler already committed under its own role;
an attacker with UPDATE on ``admin_action_requests`` can lie to the owner about
what happened and cannot cause any of it, because ``audit_log`` is append-only,
written on the far side, and disagrees. Migration 0012's docstring makes the
argument in full.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import psycopg
from psycopg.rows import dict_row

from core.invoicing.ids import uuid7
from settler.admin import wire
from settler.admin.errors import (
    AdminActionFailed,
    AdminError,
    AdminUnavailable,
    ConfirmationRequired,
)
from settler.admin.protocol import (
    ERROR_CLASSES,
    OP_PENDING,
    OP_RECONCILE,
    OP_RESOLVE,
    OP_SWEEPLIST,
    PendingCase,
    ReconcileReport,
    ResolutionResult,
    SweepExport,
    reply_channel,
)

__all__ = ["AdminClient", "DEFAULT_TIMEOUT_SECONDS", "CHAIN_TIMEOUT_SECONDS"]

log = logging.getLogger("notchstave.settler.admin.client")

#: `/pending` and `/resolve`: a claim, a transaction against local tables, and a
#: NOTIFY. Anything close to this number means the settler is down rather than
#: busy, and the right answer then is a clear message and not a longer wait.
DEFAULT_TIMEOUT_SECONDS = 20.0

#: `/reconcile` and `/sweeplist` read every reserved address over RPC, one
#: ``eth_call`` each, through a pool with a request budget (TZ 5.6). Minutes are
#: normal on a rate-limited provider, so these get their own deadline — and it is
#: still shorter than the queue's own lease, so a command that times out here is
#: one the settler is genuinely still working on.
CHAIN_TIMEOUT_SECONDS = 240.0

#: How often the wait re-reads the row even without a notification: the safety
#: net for a wakeup lost to a reconnect, not the mechanism.
DEFAULT_RECHECK_SECONDS = 0.25

SQL_INSERT_REQUEST = """
INSERT INTO admin_action_requests (id, op, args_json, requested_by)
VALUES (%(id)s, CAST(%(op)s AS admin_action_op), CAST(%(args_json)s AS jsonb),
        %(requested_by)s)
"""

SQL_READ_REQUEST = """
SELECT status::text AS status, result_json, error_code, error_message, error_detail
  FROM admin_action_requests
 WHERE id = %(id)s
"""


@dataclass(frozen=True, slots=True)
class _Reply:
    status: str
    result_json: dict[str, Any] | None
    error_code: str | None
    error_message: str | None
    error_detail: dict[str, Any] | None


class AdminClient:
    """A blocking client for the ``admin_action_requests`` round trip."""

    __slots__ = ("_dsn", "_timeout", "_chain_timeout", "_recheck")

    def __init__(
        self,
        dsn: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        chain_timeout: float = CHAIN_TIMEOUT_SECONDS,
        recheck_interval: float = DEFAULT_RECHECK_SECONDS,
    ) -> None:
        if timeout <= 0 or chain_timeout <= 0:
            raise ValueError("timeouts must be positive")
        self._dsn = dsn
        self._timeout = timeout
        self._chain_timeout = chain_timeout
        self._recheck = min(recheck_interval, timeout)

    # -- the four commands -------------------------------------------------

    async def pending(
        self, *, limit: int = 200, operator_id: int | None = None
    ) -> tuple[PendingCase, ...]:
        payload = await self._call(
            OP_PENDING, {"limit": limit}, requested_by=operator_id, timeout=self._timeout
        )
        cases = payload.get("cases")
        if not isinstance(cases, list):
            raise wire.AdminWireError("/pending answered without a `cases` list")
        return tuple(wire.decode(PendingCase, case) for case in cases)

    async def resolve(
        self,
        review_id: int,
        resolution: str,
        operator_id: int,
        comment: str | None = None,
        *,
        confirmation_code: str | None = None,
    ) -> ResolutionResult:
        payload = await self._call(
            OP_RESOLVE,
            {
                "review_id": review_id,
                # `str()` and not the enum: `AdminOps.resolve` accepts either and
                # the wire carries text, so normalising here keeps the settler
                # from having to guess which of the two it was handed.
                "resolution": str(resolution),
                "operator_id": operator_id,
                "comment": comment,
                "confirmation_code": confirmation_code,
            },
            requested_by=operator_id,
            timeout=self._timeout,
        )
        return wire.decode(ResolutionResult, payload)

    async def sweeplist(
        self,
        *,
        chain_id: int,
        asset_id: int,
        file_ref: str,
        operator_id: int | None = None,
        rate: Decimal | None = None,
    ) -> SweepExport:
        payload = await self._call(
            OP_SWEEPLIST,
            {
                "chain_id": chain_id,
                "asset_id": asset_id,
                "file_ref": file_ref,
                "operator_id": operator_id,
                "rate": None if rate is None else str(rate),
            },
            requested_by=operator_id,
            timeout=self._chain_timeout,
        )
        return wire.decode(SweepExport, payload)

    async def reconcile(
        self,
        *,
        chain_id: int,
        asset_id: int,
        rate: Decimal | None = None,
        operator_id: int | None = None,
    ) -> ReconcileReport:
        payload = await self._call(
            OP_RECONCILE,
            {
                "chain_id": chain_id,
                "asset_id": asset_id,
                "rate": None if rate is None else str(rate),
                "operator_id": operator_id,
            },
            requested_by=operator_id,
            timeout=self._chain_timeout,
        )
        return wire.decode(ReconcileReport, payload)

    # -- transport --------------------------------------------------------

    async def _call(
        self,
        op: str,
        args: dict[str, Any],
        *,
        requested_by: int | None,
        timeout: float,
    ) -> dict[str, Any]:
        """``to_thread`` for the same reason :mod:`core.invoicing.client` does it.

        The thread spends its whole life parked on a socket waiting for a
        notification, which is exactly the workload a thread is cheap for, and it
        keeps one implementation of the protocol rather than two that can
        disagree about a corner.
        """
        return await asyncio.to_thread(
            self._call_blocking, op, args, requested_by=requested_by, timeout=timeout
        )

    def _call_blocking(
        self,
        op: str,
        args: dict[str, Any],
        *,
        requested_by: int | None,
        timeout: float,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        request_id = uuid7(dt.datetime.now(dt.UTC))

        try:
            with psycopg.connect(self._dsn, autocommit=True) as conn:
                # LISTEN before the INSERT — 0007's ordering. The settler can
                # answer in less time than this function takes to reach its wait
                # loop, and a subscription taken out afterwards would miss the
                # notification entirely.
                conn.execute(f"LISTEN {reply_channel(request_id)}")
                conn.execute(
                    SQL_INSERT_REQUEST,
                    {
                        "id": request_id,
                        "op": op,
                        "args_json": json.dumps(args, separators=(",", ":")),
                        "requested_by": requested_by,
                    },
                )
                reply = self._wait(conn, request_id, deadline)
        except psycopg.Error as exc:
            # A database the bot cannot reach is not a command that failed, it is
            # a command that never happened — and it must not read as one that
            # did. `psycopg.Error` reaching an aiogram handler would be an
            # unhandled traceback in a chat window.
            raise AdminUnavailable(
                f"could not reach the admin queue for /{op}: {type(exc).__name__}: {exc}"
            ) from exc

        # No `ADMIN_ACTIONS.inc()` here, deliberately. `settler.admin.reviews`,
        # `.reconcile` and `.sweeplist` already increment that counter with
        # labels that say what was decided (`resolve.credit`, not `resolve`), and
        # they do it in the process that serves `/metrics`. A copy on this side
        # would double every action on the dashboard and would be written into a
        # registry nobody scrapes — the bot serves no `/metrics` by design, which
        # is exactly how `notchstave_active_reserved_addresses` came to be
        # published by the deriver and read by nobody.
        return self._interpret(reply, op, request_id)

    def _wait(
        self, conn: psycopg.Connection[Any], request_id: uuid.UUID, deadline: float
    ) -> _Reply:
        while True:
            reply = self._read(conn, request_id)
            if reply.status in ("done", "failed"):
                return reply

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AdminUnavailable(
                    f"the settler has not answered admin request {request_id} "
                    f"(still {reply.status}). The request stands and may yet be "
                    "served — check /pending before repeating it."
                )

            # The notification is a wakeup, never the answer: the loop re-reads
            # the row and decides from that, so a missed notification costs one
            # recheck interval and cannot cost correctness.
            for _ in conn.notifies(timeout=min(remaining, self._recheck), stop_after=1):
                break

    def _read(self, conn: psycopg.Connection[Any], request_id: uuid.UUID) -> _Reply:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(SQL_READ_REQUEST, {"id": request_id})
            row = cur.fetchone()
        if row is None:
            # The prune only touches finished rows past their retention, so this
            # means somebody deleted an in-flight request out of band.
            raise AdminUnavailable(f"admin request {request_id} vanished from the queue")
        return _Reply(
            status=row["status"],
            result_json=row["result_json"],
            error_code=row["error_code"],
            error_message=row["error_message"],
            error_detail=row["error_detail"],
        )

    def _interpret(self, reply: _Reply, op: str, request_id: uuid.UUID) -> dict[str, Any]:
        if reply.status == "failed":
            raise self._rebuild(reply, op)
        if not isinstance(reply.result_json, dict):
            # The `done_has_a_result` CHECK forbids a null; a non-object means
            # the settler and this client disagree about the encoding, which is
            # a deploy skew and not something the owner can act on.
            raise wire.AdminWireError(
                f"admin request {request_id} is done with an unreadable result"
            )
        return reply.result_json

    def _rebuild(self, reply: _Reply, op: str) -> AdminError:
        """Turn ``(error_code, error_message, error_detail)`` back into an exception.

        The class travels by name, so a refusal raised in the settler process is
        caught **by type** in the bot process — which is what lets
        ``bot/handlers/admin.py`` keep its ``except ReviewAlreadyResolved`` and
        its ``except ConfirmationRequired`` exactly as they were written against
        the in-process call.
        """
        detail = reply.error_detail or {}
        message = reply.error_message or f"/{op} was refused without a reason"
        cls = ERROR_CLASSES.get(reply.error_code or "", AdminActionFailed)

        if issubclass(cls, ConfirmationRequired):
            # The one refusal with a constructor of its own. A malformed detail
            # here would be an unhandled `KeyError` in front of an owner trying
            # to credit a buyer, so it degrades to the generic class instead.
            try:
                return ConfirmationRequired(
                    review_id=int(detail["review_id"]),
                    code=str(detail["code"]),
                    amount_usd=Decimal(str(detail["amount_usd"])),
                    limit_usd=Decimal(str(detail["limit_usd"])),
                    ttl_seconds=int(detail["ttl_seconds"]),
                )
            except (KeyError, ValueError, ArithmeticError):
                log.error("ConfirmationRequired arrived without its fields: %r", detail)
                return AdminActionFailed(message)
        return cls(message)
