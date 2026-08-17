"""`/reconcile` — the ledger against the chain (TZ 3.4).

> "`/reconcile` — сверка: сумма подтверждённых платежей в БД против фактических
> балансов адресов по RPC. **Расхождение — сигнал бага, а не повод подправить
> цифру руками.**"

**This is the most serious alert in the system.** TZ section 7 says so in as many
words — "`reconcile_drift_usd` больше порога → БД и цепь разошлись. Это баг в
учёте денег, самое серьёзное, что может случиться" — and TZ section 13 makes
``notchstave_reconcile_drift_usd = 0`` over the whole observation period a
release criterion alongside ``reverted_credits_total = 0``. Every other alert in
this project says something is slow, stuck or unusual. This one says the numbers
are wrong, and a payment system whose numbers are wrong has no other property
worth discussing.

Nothing in this module writes to ``payments``, ``invoices`` or
``receive_addresses``. That is the point of the sentence above: the response to a
drift is a human reading an audit trail, never an UPDATE that makes the
discrepancy go away.

----

**How the two sides are computed.**

*Expected* is ``SUM(payments.amount_raw)`` over ``confirmed`` and ``credited``,
per address, for one asset on one chain — TZ 3.4's "сумма подтверждённых
платежей в БД", verbatim. See :data:`settler.admin.repository
.SQL_LEDGER_BY_ADDRESS` for why the other three payment statuses are excluded and
why their absence produces genuine drift rather than a bug.

*Actual* is an on-chain balance read through the watcher's provider pool
(:mod:`settler.admin.balances`) — the same pool, the same rotation, the same
circuit breaker and the same request budget as indexing (TZ 5.6). There is no
second RPC pool in this repository.

**Swept addresses are reported, not silently skipped.** An address whose funds
have gone to cold storage has a large ledger figure and a zero balance; that is a
correct state, not a drift, so it is excluded from the arithmetic — but it is
counted and named in the report. Dropping such addresses from the comparison
without saying so is how a genuine theft *from* a swept address would go
unnoticed, which would turn the project's most important check into its blindest
spot.

**Drift is summed in absolute value, per address.** A surplus of a hundred on one
address and a shortfall of a hundred on another is two problems, and netting them
to zero would be the reconciliation reporting that everything is fine at the exact
moment it is not.

----

**The USD figure is an alert magnitude, not an accounting valuation**, and the
distinction is worth being explicit about because this is the one number that
reaches a dashboard. The authoritative drift is ``expected_raw`` vs
``actual_raw``: exact integers, no rounding, no price. Converting to dollars
needs a rate, and the settler has no rate service (TZ 5.7 gives one to the bot in
Week 5), so the fallback is the most recent ``invoices.rate_snapshot`` for the
asset — a price this system actually quoted and was paid at. For USDC the
question is degenerate; for ETH the resulting figure is right to within whatever
the market did since the last invoice, which is entirely good enough to decide
whether to wake somebody, and not good enough to put in a ledger.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from decimal import Decimal

from sqlalchemy.ext.asyncio import AsyncConnection

from core.db import enums as E
from settler import metrics
from settler import repository as repo
from settler.admin import repository as admin_repo
from settler.admin.balances import BalanceSource
from settler.admin.policy import DEFAULT_ADMIN_POLICY, AdminPolicy
from settler.amounts import raw_to_usd, sum_raw
from settler.service import CREDITABLE_PAYMENT_STATUSES

__all__ = ["AddressDrift", "ReconcileReport", "reconcile", "UnknownRate"]


class UnknownRate(Exception):
    """No rate is available to price a drift that exists.

    Raised rather than defaulting to 1.0 or to 0. A default of 1 would report a
    six-figure drift on a token worth cents; a default of 0 would report no drift
    at all, silencing the system's most serious alert with a division that never
    happened. Both are worse than telling the operator to pass a rate.
    """


@dataclass(frozen=True, slots=True)
class AddressDrift:
    """One address, both sides of the comparison."""

    address_id: int
    address: str
    derivation_index: int
    expected_raw: Decimal
    actual_raw: Decimal
    address_status: str
    swept_at: dt.datetime | None

    @property
    def drift_raw(self) -> Decimal:
        """Signed: positive means the chain holds more than the ledger knows."""
        return self.actual_raw - self.expected_raw

    @property
    def is_clean(self) -> bool:
        return self.drift_raw == 0


@dataclass(frozen=True, slots=True)
class ReconcileReport:
    """The answer to `/reconcile` for one asset on one chain."""

    chain_id: int
    asset_id: int
    asset_symbol: str
    checked: tuple[AddressDrift, ...] = ()
    #: Addresses excluded from the arithmetic because their funds are in cold
    #: storage. Named rather than dropped — see the module docstring.
    skipped_swept: tuple[AddressDrift, ...] = ()
    total_expected_raw: Decimal = Decimal(0)
    total_actual_raw: Decimal = Decimal(0)
    #: Sum of |drift| over checked addresses. Never netted.
    absolute_drift_raw: Decimal = Decimal(0)
    drift_usd: Decimal = Decimal(0)
    rate_used: Decimal = Decimal(0)
    #: ``caller`` / ``latest_invoice_snapshot`` / ``none`` — so a report can be
    #: read six months later without guessing where its dollars came from.
    rate_source: str = "none"
    threshold_usd: Decimal = Decimal(0)
    manual_review_ids: tuple[int, ...] = ()
    notification_ids: tuple[int, ...] = ()
    audit_ids: tuple[int, ...] = field(default_factory=tuple)
    policy_version: str = ""

    @property
    def drifting(self) -> tuple[AddressDrift, ...]:
        return tuple(d for d in self.checked if not d.is_clean)

    @property
    def alert(self) -> bool:
        """Past the threshold: TZ section 7's most serious condition."""
        return self.drift_usd > self.threshold_usd


async def reconcile(
    conn: AsyncConnection,
    *,
    chain_id: int,
    asset_id: int,
    balances: BalanceSource,
    admin_policy: AdminPolicy = DEFAULT_ADMIN_POLICY,
    rate: Decimal | None = None,
    operator_id: int | None = None,
    owner_user_id: int | None = None,
) -> ReconcileReport:
    """Compare the ledger with the chain for one asset (TZ 3.4).

    Read-only against the money tables. The only rows this writes are a
    ``manual_reviews`` case and ``audit_log`` entries — the record that the check
    ran, what it found, and who asked. "Расхождение — сигнал бага, а не повод
    подправить цифру руками."

    Args:
        chain_id, asset_id: what to reconcile. One asset at a time, because
            ``sweep_exports.asset_id`` and the balance read are both per-asset
            and a mixed report would have to sum unlike units.
        balances: any :class:`~settler.admin.balances.BalanceSource`. Production
            passes :class:`~settler.admin.balances.RpcBalanceSource` wrapping the
            watcher's pool for this chain; tests pass a scripted one, which is
            how TZ section 8's "никаких сетевых вызовов в CI" holds.
        rate: USD per whole token. Omitted → the most recent
            ``invoices.rate_snapshot`` for the asset.
        operator_id: the owner's Telegram id when a human ran the command.
            ``None`` for a scheduled run, which is recorded as ``system``.
        owner_user_id: when set, a drift above threshold also queues a message
            into the owner's chat rather than only raising a metric.

    Raises:
        LookupError: no such asset.
        UnknownRate: a drift exists and cannot be priced.
    """
    asset = await admin_repo.load_asset(conn, asset_id)
    if asset is None:
        raise LookupError(f"asset {asset_id} does not exist")
    if asset.chain_id != chain_id:
        raise ValueError(
            f"asset {asset_id} belongs to chain {asset.chain_id}, not {chain_id}"
        )

    ledger = await admin_repo.ledger_by_address(
        conn, chain_id=chain_id, asset_id=asset_id, statuses=CREDITABLE_PAYMENT_STATUSES
    )

    checked: list[AddressDrift] = []
    skipped: list[AddressDrift] = []
    for row in ledger:
        if row.swept_at is not None:
            # Funds moved to cold storage offline. Named in the report, kept out
            # of the arithmetic.
            skipped.append(
                AddressDrift(
                    address_id=row.address_id,
                    address=row.address,
                    derivation_index=row.derivation_index,
                    expected_raw=row.expected_raw,
                    actual_raw=Decimal(0),
                    address_status=row.address_status,
                    swept_at=row.swept_at,
                )
            )
            continue
        actual = await balances.balance_of(address=row.address, asset=asset)
        checked.append(
            AddressDrift(
                address_id=row.address_id,
                address=row.address,
                derivation_index=row.derivation_index,
                expected_raw=row.expected_raw,
                actual_raw=Decimal(actual),
                address_status=row.address_status,
                swept_at=None,
            )
        )

    # `sum_raw`, not `sum`: these are uint256 base units and Python's default
    # decimal context silently rounds to 28 significant digits. See
    # `settler.amounts.RAW_PRECISION`.
    total_expected = sum_raw(d.expected_raw for d in checked)
    total_actual = sum_raw(d.actual_raw for d in checked)
    absolute_drift = sum_raw(abs(d.drift_raw) for d in checked)

    rate_used, rate_source = await _resolve_rate(conn, asset_id, rate, absolute_drift)
    drift_usd = (
        raw_to_usd(absolute_drift, asset.decimals, rate_used)
        if rate_used > 0
        else Decimal(0)
    )

    # Set on every run, including clean ones. A gauge only written when something
    # is wrong cannot distinguish "reconciled, all square" from "reconcile has
    # not run since the restart", and those two need very different responses.
    metrics.RECONCILE_DRIFT_USD.labels(chain=str(chain_id)).set(float(drift_usd))
    metrics.ADMIN_ACTIONS.labels(action="reconcile").inc()

    actor_id = "settler" if operator_id is None else str(operator_id)
    actor_kind = (
        str(E.ActorKind.SYSTEM) if operator_id is None else str(E.ActorKind.OWNER)
    )
    drifting = tuple(d for d in checked if not d.is_clean)

    audit_ids: list[int] = [
        await repo.write_audit(
            conn,
            actor_kind=actor_kind,
            actor_id=actor_id,
            action="admin.reconcile",
            target_kind="asset",
            target_id=f"{chain_id}:{asset_id}",
            before_state=None,
            after_state=None,
            args={
                "asset_symbol": asset.symbol,
                "addresses_checked": len(checked),
                "addresses_skipped_swept": len(skipped),
                "total_expected_raw": str(total_expected),
                "total_actual_raw": str(total_actual),
                "absolute_drift_raw": str(absolute_drift),
                "drift_usd": str(drift_usd),
                "rate_used": str(rate_used),
                "rate_source": rate_source,
                "threshold_usd": str(admin_policy.reconcile_drift_threshold_usd),
                # Every drifting address by name, in the append-only table. The
                # report object is transient; this row is what somebody reads
                # while working out which of six deployments introduced the bug.
                "drifting": [
                    {
                        "address": d.address,
                        "derivation_index": d.derivation_index,
                        "expected_raw": str(d.expected_raw),
                        "actual_raw": str(d.actual_raw),
                        "drift_raw": str(d.drift_raw),
                    }
                    for d in drifting
                ],
            },
            policy_version=admin_policy.version,
        )
    ]

    review_ids: list[int] = []
    notifications: list[int] = []
    if drift_usd > admin_policy.reconcile_drift_threshold_usd:
        # A drift is a property of the address *set*, not of one row, but
        # `manual_reviews` must point at an invoice or a payment
        # (`targets_something`, migration 0001). Anchored to the most recent
        # payment on the first drifting address — the row an investigator opens
        # first anyway. When there is nothing to anchor to, the case is skipped
        # rather than attempted: an INSERT that trips a CHECK would abort the
        # whole transaction and take the audit row with it, losing the finding
        # entirely in order to record it. See the TODO at the end of this module.
        anchor = await _anchor_payment_id(conn, drifting)
        if anchor is not None:
            review_id = await repo.open_manual_review(
                conn,
                kind=str(E.ManualReviewKind.RECONCILE_DRIFT),
                invoice_id=None,
                payment_id=anchor,
                note=(
                    f"/reconcile drift {drift_usd} USD on chain {chain_id} asset "
                    f"{asset.symbol}: expected_raw={total_expected} actual_raw={total_actual} "
                    f"over {len(drifting)} address(es). TZ section 7 — the ledger and the "
                    f"chain disagree; do not adjust the figures by hand."
                ),
                policy_version=admin_policy.version,
            )
            if review_id is not None:
                review_ids.append(review_id)

        if owner_user_id is not None:
            echo = await repo.enqueue_notification(
                conn,
                user_id=owner_user_id,
                kind="reconcile_drift",
                ref_id=f"{chain_id}:{asset_id}",
                # Keyed on the figure: a drift that grows produces a new message,
                # a drift that stays put does not re-alert every run.
                dedup_key=str(absolute_drift),
                payload={
                    "chain_id": chain_id,
                    "asset_id": asset_id,
                    "asset": asset.symbol,
                    "drift_usd": str(drift_usd),
                    "absolute_drift_raw": str(absolute_drift),
                    "addresses": [d.address for d in drifting],
                    "policy_version": admin_policy.version,
                },
            )
            if echo is not None:
                notifications.append(echo)

    return ReconcileReport(
        chain_id=chain_id,
        asset_id=asset_id,
        asset_symbol=asset.symbol,
        checked=tuple(checked),
        skipped_swept=tuple(skipped),
        total_expected_raw=total_expected,
        total_actual_raw=total_actual,
        absolute_drift_raw=absolute_drift,
        drift_usd=drift_usd,
        rate_used=rate_used,
        rate_source=rate_source,
        threshold_usd=admin_policy.reconcile_drift_threshold_usd,
        manual_review_ids=tuple(review_ids),
        notification_ids=tuple(notifications),
        audit_ids=tuple(audit_ids),
        policy_version=admin_policy.version,
    )


async def _resolve_rate(
    conn: AsyncConnection, asset_id: int, rate: Decimal | None, drift_raw: Decimal
) -> tuple[Decimal, str]:
    if rate is not None:
        return rate, "caller"
    snapshot = await admin_repo.latest_rate_for_asset(conn, asset_id)
    if snapshot is not None and snapshot > 0:
        return snapshot, "latest_invoice_snapshot"
    if drift_raw == 0:
        # Nothing to price. A fresh deployment with no invoices reconciles
        # cleanly and says so, rather than failing on a missing rate it never
        # needed.
        return Decimal(0), "none"
    raise UnknownRate(
        f"asset {asset_id} has a drift of {drift_raw} base units and no rate to "
        "price it with: no invoice has ever quoted this asset. Pass `rate=` "
        "explicitly rather than letting the most serious alert in the system go "
        "un-raised."
    )


async def _anchor_payment_id(
    conn: AsyncConnection, drifting: tuple[AddressDrift, ...]
) -> int | None:
    """A payment row to hang the drift case on.

    ``manual_reviews`` requires ``invoice_id IS NOT NULL OR payment_id IS NOT
    NULL`` (the ``targets_something`` CHECK in migration 0001), and a
    reconciliation drift is a property of an address set rather than of any one
    row. Rather than widen the CHECK — a migration on a shipped schema, to make
    one case type nullable in both columns — the case is anchored to the most
    recent payment on the first drifting address, which is the row an
    investigator would open first anyway.

    ``None`` when no drifting address has a payment at all: money on a derived
    address the watcher never indexed, which is itself a serious finding. The
    caller skips the case in that situation and the drift still reaches
    ``audit_log`` and the metric — see the TODO at the end of this module.
    """
    for entry in drifting:
        payment_id = await admin_repo.latest_payment_id_for_address(conn, entry.address_id)
        if payment_id is not None:
            return payment_id
    return None


# TODO(week4, schema): a reconciliation drift on an address with no payment rows
# at all — money on a derived address the watcher never indexed — currently has
# nothing to anchor a `manual_reviews` case to, because `targets_something`
# demands an invoice or a payment. It is recorded in `audit_log` and raises
# `notchstave_reconcile_drift_usd`, so it is not lost, but it does not appear in
# `/pending`. The clean fix is a third nullable target column (`address_id`) on
# `manual_reviews` with the CHECK widened to accept it, which is a migration on a
# table this package shares with the settler and belongs in the Week 4 batch
# alongside `payments.block_hash`.
#
# TODO(week4, scheduling): `/reconcile` is on-demand only. TZ section 13 wants
# `reconcile_drift_usd = 0` over a seven-day observation window, which needs it
# on a schedule — the same poll loop as `settler/main.py`, at a much lower
# frequency, with `operator_id=None`. Deliberately not wired in Week 3: a
# scheduled reconcile spends RPC budget on every chain on every tick, and the
# budget policy for that belongs with the rest of the Week 4 provider work.
