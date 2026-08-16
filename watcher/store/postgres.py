"""PostgreSQL implementation of :class:`watcher.store.base.WatcherStore`.

Raw SQL through SQLAlchemy Core, not the ORM. The reasoning is the one written
down in `deriver/pool.py`: these statements are the money-adjacent part of the
process, and a reviewer should be able to read all of them in one file instead
of reconstructing them from mapper configuration. The ORM models in
`core/db/models.py` remain the single source of truth for the *schema* — this
module only issues statements against it.

Connection: `postgresql+psycopg://` (the DSN used everywhere in this repo)
driven by SQLAlchemy's async engine, which the psycopg 3 dialect supports
without a second driver dependency.

The role this connects as is `notchstave_watcher`, whose grants are listed in
`watcher/store/base.py`. If a statement here ever needs a privilege that role
does not have, that is a design question — not a reason to widen the grant.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from watcher.models import (
    AssetRef,
    BlockHeader,
    PaymentWriteResult,
    StoredBlock,
    TransferEvent,
    WatchedAddress,
)
from watcher.store.base import ChainConfigRow

__all__ = ["PostgresWatcherStore", "SQL_INSERT_PAYMENT", "SQL_WATCHED_ADDRESSES"]


# ---------------------------------------------------------------------------
# Statements. Module constants so the tests can assert on their shape and so
# the important ones can be read side by side.
# ---------------------------------------------------------------------------

SQL_LOAD_CHAIN = """
SELECT chain_id, name, rpc_urls, min_confirmations, credit_threshold_usd,
       use_finalized_tag, last_indexed_block, is_enabled
  FROM chains
 WHERE chain_id = :chain_id
"""

SQL_LOAD_ASSETS = """
SELECT id, chain_id, contract_address, symbol, decimals, is_native, is_enabled
  FROM assets
 WHERE chain_id = :chain_id
"""

#: The hot filter (TZ 5.2): only addresses that can still receive money for us.
#: `priority` implements the degradation order of TZ 5.8/T5.6 — addresses that
#: already hold somebody's money are filtered first, so if the watcher ever does
#: fall behind, it falls behind on empty addresses.
#:
#: Not scoped by chain on purpose: the same address exists on every EVM network,
#: and the second watcher seeing a transfer to an address whose invoice lives on
#: another chain is exactly the `wrong_chain` detection of TZ 5.5.
SQL_WATCHED_ADDRESSES = """
SELECT ra.id AS address_id,
       ra.address AS address,
       CASE
           WHEN i.status IN ('seen', 'partially_paid') THEN 0
           WHEN i.status = 'awaiting' THEN 1
           ELSE 2
       END AS priority
  FROM receive_addresses ra
  LEFT JOIN invoices i ON i.id = ra.current_invoice_id
 WHERE ra.status = 'reserved'
    OR (ra.ever_funded AND ra.swept_at IS NULL)
 ORDER BY priority, ra.derivation_index
"""

SQL_COUNT_RESERVED = """
SELECT count(*) AS reserved FROM receive_addresses WHERE status = 'reserved'
"""

SQL_CANONICAL_BLOCK = """
SELECT number, hash, parent_hash, status
  FROM blocks
 WHERE chain_id = :chain_id
   AND number = :number
   AND status <> 'orphaned'
"""

SQL_LATEST_CANONICAL_BLOCK = """
SELECT number, hash, parent_hash, status
  FROM blocks
 WHERE chain_id = :chain_id
   AND status <> 'orphaned'
 ORDER BY number DESC
 LIMIT 1
"""

#: `uq_blocks_chain_id_hash` makes a restart mid-walk a no-op rather than an
#: error. The partial unique index on (chain_id, number) WHERE status <>
#: 'orphaned' is what forbids two canonical blocks at one height — which is why
#: a reorg must orphan the loser *before* the winner is inserted.
SQL_INSERT_BLOCK = """
INSERT INTO blocks (chain_id, number, hash, parent_hash, timestamp, status)
VALUES (:chain_id, :number, :hash, :parent_hash, :timestamp, CAST(:status AS block_status))
ON CONFLICT (chain_id, hash) DO NOTHING
RETURNING id
"""

SQL_ORPHAN_ABOVE = """
UPDATE blocks
   SET status = 'orphaned'
 WHERE chain_id = :chain_id
   AND number > :number
   AND status <> 'orphaned'
RETURNING number
"""

SQL_PROMOTE_CONFIRMED = """
UPDATE blocks
   SET status = 'confirmed'
 WHERE chain_id = :chain_id
   AND number <= :up_to
   AND status = 'pending'
RETURNING number
"""

SQL_SET_CHECKPOINT = """
UPDATE chains
   SET last_indexed_block = :number
 WHERE chain_id = :chain_id
"""

#: The one statement in this process that touches money, and the reason it is a
#: single `INSERT ... SELECT` rather than a read followed by a write.
#:
#: TZ 5.3: "payments.invoice_id проставляется один раз, в той же транзакции, что
#: и вставка платежа, из receive_addresses.current_invoice_id". Doing the lookup
#: inside the INSERT makes that literally true — there is no window in which the
#: address could be re-bound between reading it and writing the payment, and
#: there is no code path that could later change the binding (the column is
#: immutable, enforced by a trigger from migration 0001).
#:
#: `invoice_id` is set only when all five conditions hold, and `anomaly` names
#: the first one that failed. The resulting invariant — `invoice_id IS NOT NULL`
#: exactly when `anomaly IS NULL` — is asserted by the tests:
#:
#:   1. the asset is enabled                    else `wrong_asset`
#:   2. the address has a current invoice        else `unassigned_payment`
#:   3. that invoice is on THIS chain            else `wrong_chain`
#:   4. the block is at or above `reserved_from_block`  else `orphan_payment`
#:   5. the invoice expects THIS asset           else `wrong_asset`
#:
#: Condition 5 deserves its own note, because binding the payment anyway would
#: look harmless. The settled total in TZ 5.3 is `SUM(amount_raw)` over a
#: payment's `invoice_id` — it does not filter by asset. So attaching a USDT
#: transfer to a USDC invoice would inflate that sum by whatever the sender
#: chose, and 10 USDT of a worthless token would settle a 10 USDC invoice. The
#: payment is recorded (the money is real and is on our address), it is flagged,
#: and it is left for a human (TZ 5.5, `wrong_asset` -> `manual_review`).
#:
#: What is NOT decided here: dust, lateness, under/overpayment, confirmations.
#: Those are policy with configurable thresholds, and policy lives in the
#: settler (TZ section 4).
SQL_INSERT_PAYMENT = """
INSERT INTO payments (chain_id, tx_hash, log_index, block_number, address_id,
                      invoice_id, asset_id, amount_raw, sender, status, anomaly)
SELECT :chain_id,
       :tx_hash,
       :log_index,
       :block_number,
       ra.id,
       CASE
           WHEN :asset_enabled
            AND i.id IS NOT NULL
            AND i.chain_id = :chain_id
            AND i.asset_id = :asset_id
            AND :block_number >= COALESCE(ra.reserved_from_block, 0)
           THEN i.id
       END,
       :asset_id,
       CAST(:amount_raw AS NUMERIC),
       :sender,
       'seen',
       CAST(
           CASE
               WHEN NOT :asset_enabled THEN 'wrong_asset'
               WHEN i.id IS NULL THEN 'unassigned_payment'
               WHEN i.chain_id <> :chain_id THEN 'wrong_chain'
               WHEN :block_number < COALESCE(ra.reserved_from_block, 0)
                   THEN 'orphan_payment'
               WHEN i.asset_id <> :asset_id THEN 'wrong_asset'
           END AS payment_anomaly
       )
  FROM receive_addresses ra
  LEFT JOIN invoices i ON i.id = ra.current_invoice_id
 WHERE ra.id = :address_id
ON CONFLICT (chain_id, tx_hash, log_index) DO NOTHING
RETURNING id, invoice_id, anomaly
"""

#: Append-only trail for the one reorg case the grants cannot express — see
#: `watcher/traversal.py`. `actor_kind = 'system'` and `actor_id = 'watcher'`
#: are the conventions of `core.db.enums.ActorKind`.
SQL_AUDIT_REOBSERVED = """
INSERT INTO audit_log (actor_kind, actor_id, action, target_kind, target_id,
                       before_state, after_state, args_json)
VALUES ('system', :actor_id, :action, 'payment', :target_id,
        CAST(:before_state AS JSONB), CAST(:after_state AS JSONB),
        CAST(:args_json AS JSONB))
"""


class PostgresWatcherStore:
    """The real store. One engine, one short transaction per operation.

    Short transactions are the point: a watcher that holds a transaction open
    across an RPC round trip pins an idle-in-transaction connection for as long
    as the slowest provider takes, and blocks the settler behind it.
    """

    def __init__(self, engine: AsyncEngine, *, actor_id: str = "watcher") -> None:
        self._engine = engine
        self._actor_id = actor_id

    @classmethod
    def from_dsn(cls, dsn: str, *, actor_id: str = "watcher", echo: bool = False) -> (
        PostgresWatcherStore
    ):
        return cls(create_async_engine(dsn, echo=echo, pool_pre_ping=True), actor_id=actor_id)

    # ------------------------------------------------------------- config --
    async def load_chain(self, chain_id: int) -> ChainConfigRow:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(sa.text(SQL_LOAD_CHAIN), {"chain_id": chain_id})
            ).mappings().first()
        if row is None:
            raise LookupError(f"chains row {chain_id} does not exist; seed it before watching")
        return ChainConfigRow(
            chain_id=int(row["chain_id"]),
            name=str(row["name"]),
            rpc_urls=tuple(row["rpc_urls"] or ()),
            min_confirmations=int(row["min_confirmations"]),
            credit_threshold_usd=Decimal(row["credit_threshold_usd"]),
            use_finalized_tag=bool(row["use_finalized_tag"]),
            last_indexed_block=int(row["last_indexed_block"]),
            is_enabled=bool(row["is_enabled"]),
        )

    async def load_assets(self, chain_id: int) -> list[AssetRef]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(sa.text(SQL_LOAD_ASSETS), {"chain_id": chain_id})
            ).mappings().all()
        return [
            AssetRef(
                asset_id=int(row["id"]),
                chain_id=int(row["chain_id"]),
                contract_lower=(
                    str(row["contract_address"]).lower() if row["contract_address"] else None
                ),
                symbol=str(row["symbol"]),
                decimals=int(row["decimals"]),
                is_native=bool(row["is_native"]),
                is_enabled=bool(row["is_enabled"]),
            )
            for row in rows
        ]

    async def load_watched_addresses(self) -> list[WatchedAddress]:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(sa.text(SQL_WATCHED_ADDRESSES))).mappings().all()
        return [
            WatchedAddress(
                address_id=int(row["address_id"]),
                address=str(row["address"]),
                priority=int(row["priority"]),
            )
            for row in rows
        ]

    async def count_reserved_addresses(self) -> int:
        async with self._engine.connect() as conn:
            row = (await conn.execute(sa.text(SQL_COUNT_RESERVED))).mappings().first()
        return int(row["reserved"]) if row else 0

    # ------------------------------------------------------------- blocks --
    async def canonical_block(self, chain_id: int, number: int) -> StoredBlock | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    sa.text(SQL_CANONICAL_BLOCK), {"chain_id": chain_id, "number": number}
                )
            ).mappings().first()
        return _to_stored_block(row)

    async def latest_canonical_block(self, chain_id: int) -> StoredBlock | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(sa.text(SQL_LATEST_CANONICAL_BLOCK), {"chain_id": chain_id})
            ).mappings().first()
        return _to_stored_block(row)

    async def insert_block(self, chain_id: int, header: BlockHeader, status: str) -> bool:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                sa.text(SQL_INSERT_BLOCK),
                {
                    "chain_id": chain_id,
                    "number": header.number,
                    "hash": header.hash,
                    "parent_hash": header.parent_hash,
                    "timestamp": header.timestamp,
                    "status": status,
                },
            )
            return result.first() is not None

    async def orphan_blocks_above(self, chain_id: int, number: int) -> tuple[int, ...]:
        async with self._engine.begin() as conn:
            rows = await conn.execute(
                sa.text(SQL_ORPHAN_ABOVE), {"chain_id": chain_id, "number": number}
            )
            return tuple(int(row[0]) for row in rows)

    async def promote_confirmed_blocks(self, chain_id: int, up_to_number: int) -> int:
        if up_to_number < 0:
            return 0
        async with self._engine.begin() as conn:
            rows = await conn.execute(
                sa.text(SQL_PROMOTE_CONFIRMED), {"chain_id": chain_id, "up_to": up_to_number}
            )
            return len(rows.fetchall())

    async def set_checkpoint(self, chain_id: int, number: int) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                sa.text(SQL_SET_CHECKPOINT), {"chain_id": chain_id, "number": number}
            )

    # ----------------------------------------------------------- payments --
    async def insert_payments(
        self, events: Sequence[TransferEvent], *, asset_enabled: dict[int, bool] | None = None
    ) -> PaymentWriteResult:
        """Insert a batch; report which rows were new and which already existed.

        One transaction for the whole batch: a block is written all-or-nothing,
        so a crash mid-batch re-processes the block from scratch rather than
        leaving half of it recorded — which, combined with the unique key, is
        the entire idempotency story (TZ 5.8/T3.1).
        """
        if not events:
            return PaymentWriteResult()

        enabled = asset_enabled or {}
        inserted: list[TransferEvent] = []
        conflicted: list[TransferEvent] = []
        async with self._engine.begin() as conn:
            for event in events:
                result = await conn.execute(
                    sa.text(SQL_INSERT_PAYMENT),
                    {
                        "chain_id": event.chain_id,
                        "tx_hash": event.tx_hash,
                        "log_index": event.log_index,
                        "block_number": event.block_number,
                        "address_id": event.address_id,
                        "asset_id": event.asset_id,
                        "asset_enabled": enabled.get(event.asset_id, True),
                        "amount_raw": str(event.amount_raw),
                        "sender": event.sender,
                    },
                )
                if result.first() is None:
                    conflicted.append(event)
                else:
                    inserted.append(event)
        return PaymentWriteResult(tuple(inserted), tuple(conflicted))

    async def record_reobserved_payments(
        self, chain_id: int, events: Sequence[TransferEvent], reason: str
    ) -> None:
        if not events:
            return
        async with self._engine.begin() as conn:
            for event in events:
                await conn.execute(
                    sa.text(SQL_AUDIT_REOBSERVED),
                    {
                        "actor_id": self._actor_id,
                        "action": "payment_reobserved_after_reorg",
                        "target_id": f"{chain_id}:{event.tx_hash}:{event.log_index}",
                        "before_state": None,
                        "after_state": json.dumps(
                            {
                                "block_number": event.block_number,
                                "block_hash": event.block_hash,
                            }
                        ),
                        "args_json": json.dumps(
                            {"reason": reason, "address_id": event.address_id}
                        ),
                    },
                )

    async def aclose(self) -> None:
        await self._engine.dispose()


def _to_stored_block(row: Any) -> StoredBlock | None:
    if row is None:
        return None
    return StoredBlock(
        number=int(row["number"]),
        hash=str(row["hash"]),
        parent_hash=str(row["parent_hash"]),
        status=str(row["status"]),
    )
