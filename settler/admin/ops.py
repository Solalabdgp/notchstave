"""Transaction boundaries for the admin commands.

The same split :class:`settler.service.Settler` makes, for the same reason: the
functions in :mod:`settler.admin.reviews`, :mod:`settler.admin.reconcile` and
:mod:`settler.admin.sweeplist` take a connection and do the work, and this class
decides where a transaction begins and ends. Tests drive the functions directly
with their own connection; the bot drives this class. Neither can accidentally
change the other's transaction shape.

**The one thing this class does beyond opening transactions** is turn the
``CONFIRMATION_REQUIRED`` outcome into an exception, and it does so *after* the
commit. That ordering is the whole reason the class exists rather than being a
few `engine.begin()` blocks in the bot:

* the audit row recording that a large credit was attempted has to survive
  (TZ 5.8/T7 — an attempt by a captured account is precisely the event worth
  keeping), so the core function returns rather than raises;
* a caller must not be able to treat "credited" and "credit pending
  confirmation" as the same answer by forgetting to read a field, so somewhere
  the distinction has to become impossible to ignore.

Commit first, then raise, satisfies both. Neither half works alone.
"""

from __future__ import annotations

from decimal import Decimal

from sqlalchemy.ext.asyncio import AsyncEngine

from core.db import enums as E
from settler.admin.balances import BalanceSource
from settler.admin.errors import ConfirmationRequired
from settler.admin.policy import DEFAULT_ADMIN_POLICY, AdminPolicy
from settler.admin.reconcile import ReconcileReport, reconcile
from settler.admin.reviews import (
    PendingCase,
    ResolutionResult,
    list_pending,
    resolve_manual_review,
)
from settler.admin.sweeplist import SweepExport, generate_sweep_list
from settler.admin.twostep import ConfirmationKey, confirmation_key_from_env

__all__ = ["AdminOps"]


class AdminOps:
    """The four commands of TZ 3.4, each in its own transaction."""

    def __init__(
        self,
        engine: AsyncEngine,
        *,
        policy: AdminPolicy = DEFAULT_ADMIN_POLICY,
        confirmation_key: ConfirmationKey | None = None,
        owner_user_id: int | None = None,
    ) -> None:
        self._engine = engine
        self._policy = policy
        #: Read from the environment when not supplied. ``None`` is a valid and
        #: *safe* state: it makes a manual credit above the limit impossible
        #: rather than unconfirmed (see
        #: :class:`~settler.admin.errors.ConfirmationUnavailable`).
        self._key = (
            confirmation_key if confirmation_key is not None else confirmation_key_from_env()
        )
        self._owner_user_id = owner_user_id

    @property
    def policy(self) -> AdminPolicy:
        return self._policy

    async def pending(self, *, limit: int = 200) -> tuple[PendingCase, ...]:
        """`/pending`. Read-only apart from the open-cases gauge."""
        async with self._engine.begin() as conn:
            return await list_pending(conn, limit=limit)

    async def resolve(
        self,
        review_id: int,
        resolution: str | E.ManualReviewResolution,
        operator_id: int,
        comment: str | None = None,
        *,
        confirmation_code: str | None = None,
    ) -> ResolutionResult:
        """`/resolve`. Raises :class:`ConfirmationRequired` after committing.

        The commit is not incidental. By the time the exception leaves this
        method the attempt is already durable in ``audit_log``, which is what
        makes "somebody tried to credit two hundred dollars by hand at 03:14"
        answerable later even though the credit itself never happened.
        """
        async with self._engine.begin() as conn:
            result = await resolve_manual_review(
                conn,
                review_id,
                resolution,
                operator_id,
                comment,
                confirmation_code=confirmation_code,
                confirmation_key=self._key,
                admin_policy=self._policy,
                owner_user_id=self._owner_user_id,
            )
        if result.needs_confirmation:
            raise ConfirmationRequired(
                review_id=result.review_id,
                code=result.confirmation_code or "",
                amount_usd=result.amount_usd,
                limit_usd=self._policy.manual_credit_limit_usd,
                ttl_seconds=self._policy.confirmation_ttl_seconds,
            )
        return result

    async def reconcile(
        self,
        *,
        chain_id: int,
        asset_id: int,
        balances: BalanceSource,
        rate: Decimal | None = None,
        operator_id: int | None = None,
    ) -> ReconcileReport:
        """`/reconcile`. One transaction, so the finding and its audit row are one act."""
        async with self._engine.begin() as conn:
            return await reconcile(
                conn,
                chain_id=chain_id,
                asset_id=asset_id,
                balances=balances,
                admin_policy=self._policy,
                rate=rate,
                operator_id=operator_id,
                owner_user_id=self._owner_user_id,
            )

    async def sweeplist(
        self,
        *,
        chain_id: int,
        asset_id: int,
        balances: BalanceSource,
        file_ref: str,
        operator_id: int | None = None,
        rate: Decimal | None = None,
    ) -> SweepExport:
        """`/sweeplist`. Builds the CSV and records that it was built — nothing else."""
        async with self._engine.begin() as conn:
            return await generate_sweep_list(
                conn,
                chain_id=chain_id,
                asset_id=asset_id,
                balances=balances,
                file_ref=file_ref,
                operator_id=operator_id,
                admin_policy=self._policy,
                rate=rate,
            )
