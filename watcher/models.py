"""Plain dataclasses passed between the RPC, detection, traversal and store layers.

Deliberately free of SQLAlchemy, web3 and `core.db`. Two reasons:

* the detection and traversal logic is the part that has to be tested without a
  database and without a network, and an import of `core.db.models` would drag
  in a live driver stack for what is arithmetic over hex strings;
* the same shapes are what a future second indexer (or a replay tool over saved
  RPC responses) would consume.

String conventions, chosen to match the CHECK constraints in migration 0001 so
that a value can never be rejected at the database boundary after being carried
through three layers:

* `tx_hash`, `block_hash`, `parent_hash` — lowercase 0x-hex
  (`payments.tx_hash` and `blocks.hash` accept `^0x[0-9a-f]{64}$`, lowercase only);
* `address` on a :class:`WatchedAddress` — exactly the string stored in
  `receive_addresses.address`, i.e. EIP-55 checksummed;
* every address the watcher *derives from a log topic* — lowercase. The watcher
  has no keccak implementation and does not need one: it matches lowercase
  against `WatchedAddress.address_lower` and then writes the stored checksummed
  string back. `payments.sender` is therefore stored lowercase, which its CHECK
  (`^0x[0-9a-fA-F]{40}$`) allows and which costs nothing, because the sender is
  informational only and is never a refund destination (TZ 5.5).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "AssetRef",
    "WatchedAddress",
    "BlockHeader",
    "StoredBlock",
    "TransferEvent",
    "PaymentWriteResult",
    "ReorgReport",
    "SyncOutcome",
]

#: `payments.log_index` value reserved for native-coin transfers, which have no
#: log at all (see the column comment in `core/db/models.py`).
NATIVE_LOG_INDEX = -1


@dataclass(frozen=True, slots=True)
class AssetRef:
    """One row of `assets`, as the watcher needs it.

    `contract_lower` is NULL for the native coin. `is_enabled=False` rows are
    still loaded on purpose: a transfer of a known-but-disabled token is
    `wrong_asset` and must be *recorded*, while a token that is not in `assets`
    at all is invisible to this process — see `detect/erc20.py`.
    """

    asset_id: int
    chain_id: int
    contract_lower: str | None
    symbol: str
    decimals: int
    is_native: bool
    is_enabled: bool


@dataclass(frozen=True, slots=True)
class WatchedAddress:
    """A receive address that belongs in the `eth_getLogs` filter (TZ 5.2).

    `priority` implements the filter-degradation rule of TZ 5.8/T5.6: when the
    address set approaches the ceiling and the filter has to be split into more
    chunks than the budget likes, the chunks that already hold somebody's money
    go first. Lower number = earlier.
    """

    address_id: int
    #: Exactly as stored in `receive_addresses.address` (EIP-55 checksummed).
    address: str
    priority: int = 0

    @property
    def address_lower(self) -> str:
        return self.address.lower()


@dataclass(frozen=True, slots=True)
class BlockHeader:
    """A block as fetched from RPC.

    `raw` keeps the provider's payload when the block was requested with full
    transactions, because native-coin detection reads `raw["transactions"]`
    (`detect/native.py`). It is None for header-only fetches so that a
    header-only walk does not hold megabytes of transaction bodies per block.
    """

    number: int
    hash: str
    parent_hash: str
    timestamp: dt.datetime
    raw: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class StoredBlock:
    """A row of `blocks` as read back for the parent-hash comparison."""

    number: int
    hash: str
    parent_hash: str
    status: str


@dataclass(frozen=True, slots=True)
class TransferEvent:
    """One observed incoming transfer, before any money logic touches it.

    This is a *fact*, not a payment decision: which invoice it belongs to,
    whether it is dust, whether it is late, and whether it credits anything are
    all resolved later, in SQL at insert time for the mechanical parts
    (`store/postgres.py`) and in the settler for everything else.
    """

    chain_id: int
    tx_hash: str
    log_index: int
    block_number: int
    block_hash: str
    #: The receive address that got the money, as stored (checksummed).
    to_address: str
    address_id: int
    asset_id: int
    amount_raw: int
    #: Lowercase; informational only (TZ 5.5 — never a refund destination).
    sender: str | None = None

    @property
    def is_native(self) -> bool:
        return self.log_index == NATIVE_LOG_INDEX


@dataclass(frozen=True, slots=True)
class PaymentWriteResult:
    """Outcome of one `INSERT ... ON CONFLICT DO NOTHING` batch.

    `conflicted` is not noise. During a normal restart it means "already
    recorded, nothing to do". During a re-walk after a reorg it means the row
    survived with a `block_number` that may now point at an orphaned block, and
    the settler has to be told — see `traversal.py`.
    """

    inserted: tuple[TransferEvent, ...] = ()
    conflicted: tuple[TransferEvent, ...] = ()

    @property
    def inserted_count(self) -> int:
        return len(self.inserted)

    @property
    def conflicted_count(self) -> int:
        return len(self.conflicted)


@dataclass(frozen=True, slots=True)
class ReorgReport:
    """What a reorg rollback did (TZ 5.4).

    `depth` is the number of block heights that stopped being canonical, which
    is what `notchstave_reorgs_total{chain,depth}` is labelled by.
    """

    chain_id: int
    common_ancestor: int
    orphaned_numbers: tuple[int, ...]

    @property
    def depth(self) -> int:
        return len(self.orphaned_numbers)


@dataclass(slots=True)
class SyncOutcome:
    """Result of one traversal step, for the loop and for the logs."""

    chain_id: int
    head: int
    from_block: int
    to_block: int
    blocks_written: int = 0
    payments_written: int = 0
    payments_conflicted: int = 0
    reorg: ReorgReport | None = None
    filter_size: int = 0
    #: Rows that were newly written by this step.
    events: list[TransferEvent] = field(default_factory=list)
    #: Rows that hit `ON CONFLICT DO NOTHING`, i.e. were already in the table.
    #: Kept separately from `events` because the two mean opposite things to the
    #: caller: during a re-walk after a reorg it is *these* that need the audit
    #: trail (`traversal.rewalk_after_reorg`), since their stored `block_number`
    #: may now point at an orphaned block while the newly inserted ones cannot.
    conflicted_events: list[TransferEvent] = field(default_factory=list)

    @property
    def head_lag(self) -> int:
        """Feeds `notchstave_head_lag_blocks{chain}` (TZ section 7)."""
        return max(self.head - self.to_block, 0)
