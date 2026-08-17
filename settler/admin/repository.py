"""SQL behind the four admin commands of TZ 3.4.

Same conventions as :mod:`settler.repository`, and for the same reasons: raw
statements because the statements *are* the argument, the database's clock
because workers do not agree on the time, explicit enum casts because
``manual_review_resolution = text`` is not an operator PostgreSQL knows.

One rule specific to this module. **Nothing here writes ``receive_addresses``.**
``/sweeplist`` and ``/reconcile`` both read the address pool and neither touches
it: marking an address swept is a write to the one table migration 0002 reserves
for the deriver (TZ 5.8/T1.2), and a sweep export is a report about what the
owner is *about to* do offline, not a record that they did it. The ``swept_at``
column is set by the deriver once the owner confirms the offline transaction —
which is also why :data:`SQL_SWEEP_CANDIDATES` filters on ``swept_at IS NULL``
rather than on anything this package could have written.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.ext.asyncio import AsyncConnection

__all__ = [
    "ReviewRow",
    "AssetRow",
    "LedgerRow",
    "SweepCandidate",
    "SQL_LOCK_REVIEW",
    "SQL_RESOLVE_REVIEW",
    "SQL_PENDING_CASES",
    "SQL_LEDGER_BY_ADDRESS",
    "SQL_SWEEP_CANDIDATES",
    "lock_review",
    "resolve_review",
    "pending_cases",
    "open_review_count",
    "invoice_received_total",
    "load_asset",
    "latest_rate_for_asset",
    "ledger_by_address",
    "latest_payment_id_for_address",
    "sweep_candidates",
    "record_sweep_export",
]

_TEXT_ARRAY = pg.ARRAY(sa.Text)


# ---------------------------------------------------------------------------
# Row shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReviewRow:
    """One ``manual_reviews`` row, read under lock."""

    id: int
    kind: str
    invoice_id: uuid.UUID | None
    payment_id: int | None
    opened_at: dt.datetime
    resolved_at: dt.datetime | None
    operator_id: int | None
    resolution: str | None
    note: str | None
    policy_version: str | None


@dataclass(frozen=True, slots=True)
class AssetRow:
    """An allow-listed payment asset, with what a balance read needs."""

    id: int
    chain_id: int
    contract_address: str | None
    symbol: str
    decimals: int
    is_native: bool


@dataclass(frozen=True, slots=True)
class LedgerRow:
    """What the database believes one address holds, for one asset."""

    address_id: int
    address: str
    derivation_index: int
    chain_id: int
    asset_id: int
    expected_raw: Decimal
    payment_count: int
    address_status: str
    swept_at: dt.datetime | None


@dataclass(frozen=True, slots=True)
class SweepCandidate:
    """An address the owner may still have to sweep by hand (TZ 3.4, 5.1)."""

    address_id: int
    derivation_index: int
    address: str
    chain_id: int


# ---------------------------------------------------------------------------
# Manual reviews (`/pending`, `/resolve`)
# ---------------------------------------------------------------------------

#: ``FOR UPDATE`` on the case row: two owners resolving the same case, or one
#: owner whose message was delivered twice, must serialise here. The CAS in
#: :data:`SQL_RESOLVE_REVIEW` would catch it anyway; the lock is what stops the
#: *second* caller from doing the expensive half of the work (granting, writing
#: a refund) before finding out.
#:
#: Deliberately not joined to ``invoices``: a review may have no invoice
#: (``unassigned_payment``), which makes it the nullable side of an outer join,
#: and PostgreSQL refuses ``FOR UPDATE`` there. The invoice is locked separately
#: through :func:`settler.repository.lock_invoice`, which is also the function
#: that already knows how to assemble decimals, rate and chain policy in one
#: snapshot.
SQL_LOCK_REVIEW = sa.text(
    """
    SELECT mr.id, mr.kind::text AS kind, mr.invoice_id, mr.payment_id,
           mr.opened_at, mr.resolved_at, mr.operator_id,
           mr.resolution::text AS resolution, mr.note, mr.policy_version
      FROM manual_reviews mr
     WHERE mr.id = :review_id
       FOR UPDATE OF mr
    """
)

#: CAS on ``resolved_at IS NULL`` (TZ 5.8/T2.2 applied to a human decision).
#:
#: ``policy_version`` is overwritten with the version in force at *resolution*
#: time, and the opening version is preserved in the ``before_state`` of the
#: audit row. TZ 5.8/T8 wants the answer to "почему этот инвойс закрыт именно
#: так" to be readable from the decision record; the decision here is the
#: resolution, so the resolution's rules are the ones the row should carry, with
#: the case's original rules one join away in an append-only table.
SQL_RESOLVE_REVIEW = sa.text(
    """
    UPDATE manual_reviews
       SET resolved_at    = now(),
           operator_id    = :operator_id,
           resolution     = CAST(:resolution AS manual_review_resolution),
           note           = :note,
           policy_version = :policy_version
     WHERE id = :review_id
       AND resolved_at IS NULL
    """
)

#: TZ 3.4 — "счета, зависшие в неоднозначных состояниях (недоплата, переплата,
#: чужой токен, чужая сеть)".
#:
#: Driven by ``manual_reviews.resolved_at IS NULL`` and not by
#: ``invoices.status``, because the two are not the same set and the difference
#: is the interesting part: a payment-level anomaly (a stray USDT transfer)
#: opens a case without moving the invoice at all, and an invoice that reached
#: ``manual_review`` always has a case. Listing by invoice status would hide the
#: first kind, which is exactly the kind that has money sitting on an address
#: with nobody looking at it.
SQL_PENDING_CASES = sa.text(
    """
    SELECT mr.id, mr.kind::text AS kind, mr.invoice_id, mr.payment_id,
           mr.opened_at, mr.note, mr.policy_version,
           i.status::text        AS invoice_status,
           i.amount_due_raw, i.amount_due_usd, i.user_id,
           a.symbol              AS asset_symbol,
           a.decimals            AS asset_decimals,
           COALESCE((
               SELECT SUM(p.amount_raw)
                 FROM payments p
                WHERE p.invoice_id = i.id
                  AND p.status::text = ANY(:creditable_statuses)
           ), 0)                 AS received_raw
      FROM manual_reviews mr
      LEFT JOIN invoices i ON i.id = mr.invoice_id
      LEFT JOIN assets   a ON a.id = i.asset_id
     WHERE mr.resolved_at IS NULL
     ORDER BY mr.opened_at, mr.id
     LIMIT :limit
    """
).bindparams(sa.bindparam("creditable_statuses", type_=_TEXT_ARRAY))

SQL_OPEN_REVIEW_COUNT = sa.text(
    "SELECT count(*) FROM manual_reviews WHERE resolved_at IS NULL"
)

#: What actually arrived on an invoice, with no confirmation gate.
#:
#: The gate is deliberately absent, unlike :data:`settler.repository
#: .SQL_SETTLED_TOTAL`. That query answers "how much may be credited
#: automatically right now", and the depth rules of TZ 5.4 are the whole point
#: of it. This one answers "how much money is on this invoice", which is the
#: figure a human needs in front of them to decide, and the confirmation depth is
#: their judgement to apply — a case that has been open for a day is not waiting
#: on three more blocks.
SQL_INVOICE_RECEIVED_TOTAL = sa.text(
    """
    SELECT COALESCE(SUM(p.amount_raw), 0) AS received_raw,
           COUNT(*)                       AS payment_count
      FROM payments p
     WHERE p.invoice_id = :invoice_id
       AND p.asset_id   = :asset_id
       AND p.chain_id   = :chain_id
       AND p.status::text = ANY(:statuses)
       AND (p.anomaly IS NULL OR p.anomaly::text = ANY(:creditable_anomalies))
    """
).bindparams(
    sa.bindparam("statuses", type_=_TEXT_ARRAY),
    sa.bindparam("creditable_anomalies", type_=_TEXT_ARRAY),
)


async def lock_review(conn: AsyncConnection, review_id: int) -> ReviewRow | None:
    row = (await conn.execute(SQL_LOCK_REVIEW, {"review_id": review_id})).mappings().first()
    if row is None:
        return None
    return ReviewRow(
        id=int(row["id"]),
        kind=row["kind"],
        invoice_id=row["invoice_id"],
        payment_id=None if row["payment_id"] is None else int(row["payment_id"]),
        opened_at=row["opened_at"],
        resolved_at=row["resolved_at"],
        operator_id=None if row["operator_id"] is None else int(row["operator_id"]),
        resolution=row["resolution"],
        note=row["note"],
        policy_version=row["policy_version"],
    )


async def resolve_review(
    conn: AsyncConnection,
    review_id: int,
    *,
    resolution: str,
    operator_id: int,
    note: str | None,
    policy_version: str,
) -> bool:
    """``False`` means somebody resolved it first. Not an error here — a fact."""
    result = await conn.execute(
        SQL_RESOLVE_REVIEW,
        {
            "review_id": review_id,
            "resolution": resolution,
            "operator_id": operator_id,
            "note": note,
            "policy_version": policy_version,
        },
    )
    return result.rowcount == 1


async def pending_cases(
    conn: AsyncConnection, *, creditable_statuses: tuple[str, ...], limit: int = 200
) -> list[dict[str, Any]]:
    rows = (
        await conn.execute(
            SQL_PENDING_CASES,
            {"creditable_statuses": list(creditable_statuses), "limit": limit},
        )
    ).mappings().all()
    return [dict(r) for r in rows]


async def open_review_count(conn: AsyncConnection) -> int:
    return int((await conn.execute(SQL_OPEN_REVIEW_COUNT)).scalar_one())


async def invoice_received_total(
    conn: AsyncConnection,
    invoice_id: uuid.UUID,
    *,
    asset_id: int,
    chain_id: int,
    statuses: tuple[str, ...],
    creditable_anomalies: tuple[str, ...],
) -> tuple[Decimal, int]:
    row = (
        await conn.execute(
            SQL_INVOICE_RECEIVED_TOTAL,
            {
                "invoice_id": invoice_id,
                "asset_id": asset_id,
                "chain_id": chain_id,
                "statuses": list(statuses),
                "creditable_anomalies": list(creditable_anomalies),
            },
        )
    ).mappings().one()
    return Decimal(row["received_raw"]), int(row["payment_count"])


# ---------------------------------------------------------------------------
# Assets and rates
# ---------------------------------------------------------------------------

SQL_LOAD_ASSET = sa.text(
    """
    SELECT a.id, a.chain_id, a.contract_address, a.symbol, a.decimals, a.is_native
      FROM assets a
     WHERE a.id = :asset_id
    """
)

#: The most recent quote this system actually used for the asset.
#:
#: A deliberate approximation, and the docstring of :func:`reconcile` says so out
#: loud. There is no live rate service in the settler (TZ 5.7 puts one in the bot
#: for Week 5) and inventing an HTTP call here would put a third-party outage in
#: the path of the system's own audit. ``rate_snapshot`` is a real number this
#: system quoted and was paid at, which is the right order of magnitude for
#: turning a drift in base units into a dollar figure for an alert threshold. It
#: is not an accounting valuation and must not be used as one — the authoritative
#: drift figure is ``expected_raw`` vs ``actual_raw``, both exact integers.
SQL_LATEST_RATE_FOR_ASSET = sa.text(
    """
    SELECT i.rate_snapshot
      FROM invoices i
     WHERE i.asset_id = :asset_id
     ORDER BY i.created_at DESC
     LIMIT 1
    """
)


async def load_asset(conn: AsyncConnection, asset_id: int) -> AssetRow | None:
    row = (await conn.execute(SQL_LOAD_ASSET, {"asset_id": asset_id})).mappings().first()
    if row is None:
        return None
    return AssetRow(
        id=int(row["id"]),
        chain_id=int(row["chain_id"]),
        contract_address=row["contract_address"],
        symbol=row["symbol"],
        decimals=int(row["decimals"]),
        is_native=bool(row["is_native"]),
    )


async def latest_rate_for_asset(conn: AsyncConnection, asset_id: int) -> Decimal | None:
    value = (
        await conn.execute(SQL_LATEST_RATE_FOR_ASSET, {"asset_id": asset_id})
    ).scalar_one_or_none()
    return None if value is None else Decimal(value)


# ---------------------------------------------------------------------------
# `/reconcile` (TZ 3.4, section 7 alert)
# ---------------------------------------------------------------------------

#: What the ledger says each address holds, for one asset.
#:
#: Three filter decisions, all of them about what "should be there" means:
#:
#: * **statuses**: ``confirmed`` and ``credited`` only, verbatim from TZ 3.4
#:   ("сумма подтверждённых платежей в БД"). ``seen`` is money we have noticed
#:   but not accepted; ``reverted`` is money that stopped existing;
#:   ``ignored_dust`` is money we declined to count. All three would show up
#:   on-chain and are therefore genuine drift — which is the correct answer, not
#:   a bug: dust and unconfirmed transfers really do sit on the address, and the
#:   threshold is what decides whether that is worth waking someone.
#: * **swept addresses are excluded by the caller**, not here, so that they can be
#:   *reported* as excluded rather than silently dropped. An address whose money
#:   has gone to cold storage has a large ledger figure and a zero balance, and
#:   quietly removing it from a reconciliation report is how a real theft from a
#:   swept address would go unnoticed.
#: * every address that has ever seen a payment for this asset is included, even
#:   at zero, so that "no drift" is a statement about a known set of addresses.
SQL_LEDGER_BY_ADDRESS = sa.text(
    """
    SELECT ra.id                         AS address_id,
           ra.address,
           ra.derivation_index,
           ra.status::text               AS address_status,
           ra.swept_at,
           :chain_id                     AS chain_id,
           :asset_id                     AS asset_id,
           COALESCE(SUM(p.amount_raw) FILTER (
               WHERE p.status::text = ANY(:statuses)
           ), 0)                         AS expected_raw,
           COUNT(p.id) FILTER (
               WHERE p.status::text = ANY(:statuses)
           )                             AS payment_count
      FROM receive_addresses ra
      JOIN payments p ON p.address_id = ra.id
                     AND p.asset_id  = :asset_id
                     AND p.chain_id  = :chain_id
     GROUP BY ra.id, ra.address, ra.derivation_index, ra.status, ra.swept_at
     ORDER BY ra.derivation_index
    """
).bindparams(sa.bindparam("statuses", type_=_TEXT_ARRAY))


async def ledger_by_address(
    conn: AsyncConnection, *, chain_id: int, asset_id: int, statuses: tuple[str, ...]
) -> list[LedgerRow]:
    rows = (
        await conn.execute(
            SQL_LEDGER_BY_ADDRESS,
            {"chain_id": chain_id, "asset_id": asset_id, "statuses": list(statuses)},
        )
    ).mappings().all()
    return [
        LedgerRow(
            address_id=int(r["address_id"]),
            address=r["address"],
            derivation_index=int(r["derivation_index"]),
            chain_id=int(r["chain_id"]),
            asset_id=int(r["asset_id"]),
            expected_raw=Decimal(r["expected_raw"]),
            payment_count=int(r["payment_count"]),
            address_status=r["address_status"],
            swept_at=r["swept_at"],
        )
        for r in rows
    ]


#: The row a reconciliation drift case is anchored to — see
#: :func:`settler.admin.reconcile._anchor_payment_id` for why a drift needs an
#: anchor at all.
SQL_LATEST_PAYMENT_FOR_ADDRESS = sa.text(
    """
    SELECT p.id
      FROM payments p
     WHERE p.address_id = :address_id
     ORDER BY p.block_number DESC, p.id DESC
     LIMIT 1
    """
)


async def latest_payment_id_for_address(conn: AsyncConnection, address_id: int) -> int | None:
    value = (
        await conn.execute(SQL_LATEST_PAYMENT_FOR_ADDRESS, {"address_id": address_id})
    ).scalar_one_or_none()
    return None if value is None else int(value)


# ---------------------------------------------------------------------------
# `/sweeplist` (TZ 3.4, 5.1)
# ---------------------------------------------------------------------------

#: Addresses the owner may still have to sweep.
#:
#: ``ever_funded OR EXISTS(payment)`` rather than ``ever_funded`` alone. The flag
#: is written by the deriver when it notices funds; the payment row is written by
#: the watcher the moment a transfer is indexed. They are two processes and there
#: is a window between them, and a sweep list that misses an address because one
#: of the two has not caught up yet is a sweep list that leaves money behind. The
#: union is the conservative reading, and being conservative costs one line in a
#: CSV.
#:
#: ``swept_at IS NULL`` is the only exclusion. Not ``status <> 'swept'``: the
#: timestamp is the fact, the status is a label, and TZ 6 makes ``swept_at``
#: conditional on both (``swept_at IS NULL OR (ever_funded AND status =
#: 'swept')``), so the timestamp is the stricter of the two tests.
SQL_SWEEP_CANDIDATES = sa.text(
    """
    SELECT DISTINCT ra.id AS address_id, ra.derivation_index, ra.address, :chain_id AS chain_id
      FROM receive_addresses ra
     WHERE ra.swept_at IS NULL
       AND (
             ra.ever_funded
             OR EXISTS (
                   SELECT 1 FROM payments p
                    WHERE p.address_id = ra.id
                      AND p.chain_id   = :chain_id
                      AND p.asset_id   = :asset_id
                 )
           )
     ORDER BY ra.derivation_index
    """
)

SQL_INSERT_SWEEP_EXPORT = sa.text(
    """
    INSERT INTO sweep_exports (address_count, total_raw, asset_id, file_ref, operator_id)
    VALUES (:address_count, :total_raw, :asset_id, :file_ref, :operator_id)
    RETURNING id, generated_at
    """
)


async def sweep_candidates(
    conn: AsyncConnection, *, chain_id: int, asset_id: int
) -> list[SweepCandidate]:
    rows = (
        await conn.execute(SQL_SWEEP_CANDIDATES, {"chain_id": chain_id, "asset_id": asset_id})
    ).mappings().all()
    return [
        SweepCandidate(
            address_id=int(r["address_id"]),
            derivation_index=int(r["derivation_index"]),
            address=r["address"],
            chain_id=int(r["chain_id"]),
        )
        for r in rows
    ]


async def record_sweep_export(
    conn: AsyncConnection,
    *,
    address_count: int,
    total_raw: Decimal,
    asset_id: int,
    file_ref: str,
    operator_id: int | None,
) -> tuple[int, dt.datetime]:
    row = (
        await conn.execute(
            SQL_INSERT_SWEEP_EXPORT,
            {
                "address_count": address_count,
                "total_raw": total_raw,
                "asset_id": asset_id,
                "file_ref": file_ref,
                "operator_id": operator_id,
            },
        )
    ).mappings().one()
    return int(row["id"]), row["generated_at"]
