"""The ask-the-settler queue, settler side (migration 0012).

:class:`~settler.admin.ops.AdminOps` needs a connection under
``notchstave_settler``, because ``/resolve credit`` writes ``entitlements`` and
migration 0003 revoked that from every other role in writing. The bot process
has no such connection and must not have one. So the bot asks, and this module
is the half of the conversation that answers.

The shape is 0007's, which is the shape :mod:`deriver.requests` already
implements, and the differences are the interesting part:

**It is async, and 0007's is not.** The deriver is synchronous by design — it is
a process with one job and no framework. The settler is an async engine and a
poll loop, so its queue worker takes an :class:`~sqlalchemy.ext.asyncio
.AsyncConnection` like everything else under ``settler/`` rather than opening a
second, synchronous connection story inside the same process.

**A stale claim is abandoned, never retried.** ``DEFAULT_MAX_ATTEMPTS`` is 1,
where the deriver's is 3, and the reason is what the two queues carry. A lost
invoice request costs a buyer one press of ``/buy``. A lost *admin* request may
have committed a manual credit before the process serving it died, and the
retry's compare-and-set on ``manual_reviews.resolved_at`` would then raise
:class:`~settler.admin.errors.ReviewAlreadyResolved` — telling the owner their
decision did **not** take effect, at the one moment when it did. "The settler
restarted while your command was in flight; check ``/pending``" is a worse
message and a true one, and this queue prefers the true one.

**The claim and the work are separate transactions**, for 0007's reason: the
work here is ``AdminOps``, which opens and commits its own transaction on
purpose (see that class on why the commit must precede the
``ConfirmationRequired`` raise). A claim held open across it would either fight
that boundary or silently widen it to include an RPC round trip.

What this module does not do
----------------------------

It does not authorise. ``requested_by`` is recorded and never checked — TZ
5.8/T7's premise is a captured owner account, so a caller claiming to be the
owner proves nothing, and the control that holds is the grant matrix on the far
side of this call. The owner check that does exist is in the bot, where the
Telegram identity lives, and it is there to keep strangers out of the command
surface rather than to protect the money.

It also does not decide anything about money. Every branch below ends in one
call to one ``AdminOps`` method; the decisions are in :mod:`settler.admin
.reviews`, :mod:`settler.admin.reconcile` and :mod:`settler.admin.sweeplist`,
where they were before this queue existed and where the tests still drive them
directly.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Protocol

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from settler.admin import wire
from settler.admin.balances import BalanceSource
from settler.admin.errors import (
    AdminError,
    BalancesUnavailable,
    ConfirmationRequired,
)
from settler.admin.ops import AdminOps
from settler.admin.protocol import (
    CHANNEL_ADMIN_REQUESTS,
    OP_PENDING,
    OP_RECONCILE,
    OP_RESOLVE,
    OP_SWEEPLIST,
)

__all__ = [
    "CHANNEL_ADMIN_REQUESTS",
    "DEFAULT_LEASE_SECONDS",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_RETENTION_SECONDS",
    "ABANDONED_ERROR_CODE",
    "AdminActionRequest",
    "BalanceProvider",
    "AdminWorker",
    "claim_next",
    "complete",
    "refuse",
    "abandon_stale",
    "prune_completed",
]

log = logging.getLogger("notchstave.settler.admin.queue")

#: How long a claim is honoured before another pass may declare the worker dead.
#: Generous next to 0007's 30s because ``/reconcile`` and ``/sweeplist`` read
#: every reserved address over RPC, one ``eth_call`` each, through a pool with a
#: request budget (TZ 5.6) — a few hundred addresses on a rate-limited provider
#: is minutes, not milliseconds, and a lease that expires mid-command would
#: abandon a request that is going perfectly well.
DEFAULT_LEASE_SECONDS = 300.0

#: One. See the module docstring: a second attempt at a money decision is worse
#: than an honest "it did not finish".
DEFAULT_MAX_ATTEMPTS = 1

#: How long an answered request stays readable. Long enough that a bot which
#: timed out at 60s can still find out what actually happened, short enough that
#: the table does not become an audit log — ``audit_log`` is the audit log, it is
#: append-only, and it already holds every decision this queue carried.
DEFAULT_RETENTION_SECONDS = 3600.0

ABANDONED_ERROR_CODE = "AdminUnavailable"
ABANDONED_MESSAGE = (
    "The settler stopped serving this command before it finished. Nothing is "
    "known about whether it took effect — check /pending before repeating it."
)


@dataclass(frozen=True, slots=True)
class AdminActionRequest:
    """One claimed row. Everything the worker needs and nothing else."""

    id: uuid.UUID
    op: str
    args: dict[str, Any]
    requested_by: int | None
    attempts: int


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

#: ``FOR UPDATE SKIP LOCKED``: two settlers on one database is a supported
#: deployment (the invoice loop is already safe under it, TZ 5.8/T2.4) and this
#: is what keeps them from serving the same command twice.
SQL_CLAIM_NEXT = sa.text(
    """
    UPDATE admin_action_requests
       SET status = 'processing',
           claimed_at = now(),
           attempts = attempts + 1
     WHERE id = (
             SELECT id
               FROM admin_action_requests
              WHERE status = 'pending'
              ORDER BY requested_at
              FOR UPDATE SKIP LOCKED
              LIMIT 1
           )
 RETURNING id, op::text AS op, args_json, requested_by, attempts
    """
)

SQL_COMPLETE = sa.text(
    """
    UPDATE admin_action_requests
       SET status = 'done',
           completed_at = now(),
           result_json = CAST(:result_json AS jsonb)
     WHERE id = :id
       AND status = 'processing'
    """
)

SQL_REFUSE = sa.text(
    """
    UPDATE admin_action_requests
       SET status = 'failed',
           completed_at = now(),
           error_code = :error_code,
           error_message = :error_message,
           error_detail = CAST(:error_detail AS jsonb)
     WHERE id = :id
       AND status = 'processing'
    """
)

#: The lease sweep. One statement, because "which rows are stale" and "fail
#: them" have to be one decision — reading the candidates and failing them in a
#: second statement leaves a window in which the worker everyone assumed was
#: dead completes normally and has its answer overwritten.
SQL_ABANDON_STALE = sa.text(
    """
    UPDATE admin_action_requests
       SET status = 'failed',
           completed_at = now(),
           error_code = :error_code,
           error_message = :error_message
     WHERE status = 'processing'
       AND claimed_at < now() - make_interval(secs => :lease_seconds)
 RETURNING id
    """
)

SQL_PRUNE = sa.text(
    """
    DELETE FROM admin_action_requests
     WHERE status IN ('done', 'failed')
       AND completed_at < now() - make_interval(secs => :retention_seconds)
    """
)


async def claim_next(conn: AsyncConnection) -> AdminActionRequest | None:
    """Take the oldest pending request, or ``None`` when there is nothing to do."""
    row = (await conn.execute(SQL_CLAIM_NEXT)).mappings().first()
    if row is None:
        return None
    return AdminActionRequest(
        id=row["id"],
        op=row["op"],
        args=dict(row["args_json"] or {}),
        requested_by=row["requested_by"],
        attempts=int(row["attempts"]),
    )


async def complete(conn: AsyncConnection, request_id: uuid.UUID, result: Any) -> bool:
    """Publish the answer. ``False`` means somebody else already finished it."""
    outcome = await conn.execute(
        SQL_COMPLETE,
        {"id": request_id, "result_json": _dumps(result)},
    )
    return outcome.rowcount == 1


async def refuse(
    conn: AsyncConnection,
    request_id: uuid.UUID,
    *,
    error_code: str,
    error_message: str,
    error_detail: dict[str, Any] | None = None,
) -> bool:
    """Publish a refusal. Same contract as :func:`complete`."""
    outcome = await conn.execute(
        SQL_REFUSE,
        {
            "id": request_id,
            "error_code": error_code,
            "error_message": error_message,
            "error_detail": _dumps(error_detail) if error_detail is not None else None,
        },
    )
    return outcome.rowcount == 1


async def abandon_stale(
    conn: AsyncConnection, *, lease_seconds: float = DEFAULT_LEASE_SECONDS
) -> tuple[uuid.UUID, ...]:
    """Fail every claim older than the lease. See ``DEFAULT_MAX_ATTEMPTS``."""
    rows = (
        await conn.execute(
            SQL_ABANDON_STALE,
            {
                "lease_seconds": lease_seconds,
                "error_code": ABANDONED_ERROR_CODE,
                "error_message": ABANDONED_MESSAGE,
            },
        )
    ).all()
    return tuple(r[0] for r in rows)


async def prune_completed(
    conn: AsyncConnection, *, retention_seconds: float = DEFAULT_RETENTION_SECONDS
) -> int:
    outcome = await conn.execute(SQL_PRUNE, {"retention_seconds": retention_seconds})
    return outcome.rowcount


def _dumps(value: Any) -> str:
    """JSON text for a ``jsonb`` bind.

    Passed as text and cast in SQL rather than handed to the driver as a dict:
    psycopg would adapt a ``dict`` to ``jsonb`` on its own, but a ``list`` — what
    ``/pending`` returns — adapts to a PostgreSQL array instead, and the failure
    is a type error at the far end of a money command. One rule for both.
    """
    return json.dumps(value, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Balances
# ---------------------------------------------------------------------------


class BalanceProvider(Protocol):
    """Where ``/reconcile`` and ``/sweeplist`` get on-chain balances.

    A protocol and not the pool itself, for the reason :mod:`settler.admin`
    states as an invariant: RPC lives behind
    :class:`~settler.admin.balances.BalanceSource` and the settler's money code
    holds no client. This adds one thing that protocol cannot express — the
    source is per chain, and building it can fail — so the failure is a raise
    rather than a ``None`` a caller might reconcile against.
    """

    async def for_chain(self, chain_id: int) -> BalanceSource:
        """Raises :class:`~settler.admin.errors.BalancesUnavailable`."""
        ...


# ---------------------------------------------------------------------------
# The worker
# ---------------------------------------------------------------------------


class AdminWorker:
    """Serve the queue: claim, execute, answer. One pass per settler tick.

    Owns no state beyond its collaborators, so a second worker on a second
    settler is a supported configuration rather than a race — the claim is
    ``FOR UPDATE SKIP LOCKED`` and every completion is a compare-and-set on
    ``status = 'processing'``.
    """

    def __init__(
        self,
        engine: AsyncEngine,
        ops: AdminOps,
        *,
        balances: BalanceProvider | None = None,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
        retention_seconds: float = DEFAULT_RETENTION_SECONDS,
        batch: int = 8,
    ) -> None:
        self._engine = engine
        self._ops = ops
        #: ``None`` is the fail-closed state and the ordinary one on a fresh
        #: checkout: `/reconcile` and `/sweeplist` then refuse with
        #: `BalancesUnavailable` instead of reconciling against zero.
        self._balances = balances
        self._lease = lease_seconds
        self._retention = retention_seconds
        #: A cap per pass, not per process. The settler's tick has six other
        #: steps and all of them are about money; a burst of admin commands must
        #: not be able to starve them.
        self._batch = batch

    async def run_once(self) -> int:
        """One pass. Returns how many requests were answered."""
        async with self._engine.begin() as conn:
            for request_id in await abandon_stale(conn, lease_seconds=self._lease):
                log.error(
                    "admin request %s abandoned: claimed longer ago than the lease", request_id
                )
            await prune_completed(conn, retention_seconds=self._retention)

        served = 0
        while served < self._batch:
            async with self._engine.begin() as conn:
                request = await claim_next(conn)
            if request is None:
                break
            await self._serve(request)
            served += 1
        return served

    async def _serve(self, request: AdminActionRequest) -> None:
        try:
            result = await self._execute(request)
        except AdminError as exc:
            await self._answer_refusal(request, exc)
            return
        except Exception as exc:  # noqa: BLE001 — RPC, pricing and psycopg all land here
            # Deliberately broad and deliberately not re-raised. An unhandled
            # exception here would leave the row `processing` until the lease
            # expires, i.e. would turn every unexpected failure into a five-minute
            # silence in front of an operator. `AdminActionFailed` carries the
            # message; the traceback stays in this process's log.
            log.exception("admin request %s (%s) failed", request.id, request.op)
            await self._answer_refusal(
                request,
                exc,
                code_override="AdminActionFailed",
            )
            return

        async with self._engine.begin() as conn:
            if not await complete(conn, request.id, result):
                log.warning("admin request %s was already finished by somebody else", request.id)

    async def _answer_refusal(
        self,
        request: AdminActionRequest,
        exc: BaseException,
        *,
        code_override: str | None = None,
    ) -> None:
        detail: dict[str, Any] | None = None
        if isinstance(exc, ConfirmationRequired):
            # The one refusal that carries data. Everything in it except the code
            # was already in the request; the code is the second half of the TZ
            # 5.8/T7 control and cannot be recomputed by the bot, which has no
            # confirmation key — that key lives with the settler on purpose.
            detail = {
                "review_id": exc.review_id,
                "code": exc.code,
                "amount_usd": str(exc.amount_usd),
                "limit_usd": str(exc.limit_usd),
                "ttl_seconds": exc.ttl_seconds,
            }
        async with self._engine.begin() as conn:
            await refuse(
                conn,
                request.id,
                error_code=code_override or type(exc).__name__,
                error_message=str(exc),
                error_detail=detail,
            )

    # -- dispatch ---------------------------------------------------------

    async def _execute(self, request: AdminActionRequest) -> Any:
        args = request.args
        if request.op == OP_PENDING:
            cases = await self._ops.pending(limit=_int(args, "limit", default=200))
            # Wrapped in an object rather than sent as a bare list: `result_json`
            # is `jsonb` and a top-level array is legal there, but every other
            # reply in this repository is an object, and a wrapper leaves room to
            # add a field without changing the JSON's shape.
            return {"cases": wire.encode(cases)}

        if request.op == OP_RESOLVE:
            result = await self._ops.resolve(
                _int(args, "review_id"),
                _str(args, "resolution"),
                _int(args, "operator_id"),
                _opt_str(args, "comment"),
                confirmation_code=_opt_str(args, "confirmation_code"),
            )
            return wire.encode(result)

        if request.op == OP_SWEEPLIST:
            chain_id = _int(args, "chain_id")
            export = await self._ops.sweeplist(
                chain_id=chain_id,
                asset_id=_int(args, "asset_id"),
                balances=await self._balance_source(chain_id),
                file_ref=_str(args, "file_ref"),
                operator_id=_opt_int(args, "operator_id"),
                rate=_opt_decimal(args, "rate"),
            )
            return wire.encode(export)

        if request.op == OP_RECONCILE:
            chain_id = _int(args, "chain_id")
            report = await self._ops.reconcile(
                chain_id=chain_id,
                asset_id=_int(args, "asset_id"),
                balances=await self._balance_source(chain_id),
                rate=_opt_decimal(args, "rate"),
                operator_id=_opt_int(args, "operator_id"),
            )
            return wire.encode(report)

        # Unreachable through the table: `op` is an enum column (migration 0012)
        # and PostgreSQL rejects anything else at INSERT. Kept because a future
        # value added to that enum and not to this dispatch should be a loud
        # refusal rather than a silent `None` result.
        raise wire.AdminWireError(f"no handler for admin op {request.op!r}")

    async def _balance_source(self, chain_id: int) -> BalanceSource:
        if self._balances is None:
            raise BalancesUnavailable(
                f"this settler has no RPC balance source for chain {chain_id}: "
                "set rpc_urls on the chains row and restart"
            )
        return await self._balances.for_chain(chain_id)


# ---------------------------------------------------------------------------
# Argument reading
# ---------------------------------------------------------------------------
#
# `args_json` arrives from another process and is read as data in every case
# below — named keys, bound as parameters, never interpolated. The helpers exist
# so that a missing or mistyped argument is one clear `AdminWireError` naming the
# field, rather than a `TypeError` from three frames inside `resolve_manual_review`
# that the owner sees as "Could not resolve this case: unsupported operand type".


def _int(args: dict[str, Any], name: str, *, default: int | None = None) -> int:
    value = args.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise wire.AdminWireError(f"admin argument {name!r} must be an integer, got {value!r}")
    return value


def _opt_int(args: dict[str, Any], name: str) -> int | None:
    return None if args.get(name) is None else _int(args, name)


def _str(args: dict[str, Any], name: str) -> str:
    value = args.get(name)
    if not isinstance(value, str):
        raise wire.AdminWireError(f"admin argument {name!r} must be a string, got {value!r}")
    return value


def _opt_str(args: dict[str, Any], name: str) -> str | None:
    return None if args.get(name) is None else _str(args, name)


def _opt_decimal(args: dict[str, Any], name: str) -> Decimal | None:
    value = args.get(name)
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except ArithmeticError as exc:
        raise wire.AdminWireError(
            f"admin argument {name!r} must be a decimal, got {value!r}"
        ) from exc
