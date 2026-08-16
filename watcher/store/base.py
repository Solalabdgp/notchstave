"""The storage contract the watcher programs against.

Every method here maps onto a privilege the `notchstave_watcher` role actually
holds (migration 0002). That is not a coincidence — the protocol is written so
that an operation the role is not allowed to perform cannot even be expressed:

    chains              SELECT, UPDATE   -> load_chain, set_checkpoint
    blocks              SELECT, I, U     -> canonical_block, insert_block,
                                            orphan_blocks_above, promote_confirmed
    payments            SELECT, INSERT   -> insert_payments          (no update)
    receive_addresses   SELECT           -> load_watched_addresses
    invoices            SELECT           -> (joined inside insert_payments)
    assets              SELECT           -> load_assets
    audit_log           SELECT, INSERT   -> record_reobserved_payments

Note what is missing: there is no `revert_payments`, no `credit`, no
`mark_address_funded`. The watcher cannot revert a payment even if a future
maintainer decides it should — the grant is not there, and the protocol offers
no method to try. Marking blocks orphaned is as far as the reorg handling goes
on this side; the money consequences belong to the settler (TZ section 4).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Protocol, runtime_checkable

from watcher.models import (
    AssetRef,
    BlockHeader,
    PaymentWriteResult,
    StoredBlock,
    TransferEvent,
    WatchedAddress,
)

__all__ = ["ChainConfigRow", "WatcherStore"]


class ChainConfigRow:
    """A row of `chains` — the watcher's entire network configuration (TZ 6).

    Base and Ethereum mainnet are rows, never constants: TZ section 2 makes the
    second network the thing that proves the design is genuinely multi-chain,
    and a hardcoded chain id or RPC URL anywhere in this package would quietly
    undo that. `is_l2` is not a column; the L2-specific behaviour TZ 5.4
    describes is driven by `use_finalized_tag`, which is what actually changes:
    whether "deep enough" is a confirmation count or a `finalized` tag.
    """

    __slots__ = (
        "chain_id",
        "name",
        "rpc_urls",
        "min_confirmations",
        "credit_threshold_usd",
        "use_finalized_tag",
        "last_indexed_block",
        "is_enabled",
    )

    def __init__(
        self,
        chain_id: int,
        name: str,
        rpc_urls: Sequence[str],
        min_confirmations: int,
        credit_threshold_usd: Decimal,
        use_finalized_tag: bool,
        last_indexed_block: int,
        is_enabled: bool = True,
    ) -> None:
        self.chain_id = chain_id
        self.name = name
        self.rpc_urls = tuple(rpc_urls)
        self.min_confirmations = min_confirmations
        self.credit_threshold_usd = credit_threshold_usd
        self.use_finalized_tag = use_finalized_tag
        self.last_indexed_block = last_indexed_block
        self.is_enabled = is_enabled

    def __repr__(self) -> str:
        # RPC URLs carry API keys in the path. A config object that prints them
        # puts a credential into every debug log and every traceback, so the
        # count is shown instead of the values (same rule as TZ 5.1's redacted
        # config repr for the xpub).
        return (
            f"<ChainConfigRow {self.name} id={self.chain_id} "
            f"providers={len(self.rpc_urls)} confirmations={self.min_confirmations} "
            f"finalized_tag={self.use_finalized_tag} checkpoint={self.last_indexed_block}>"
        )


@runtime_checkable
class WatcherStore(Protocol):
    """Async persistence operations. Implementations own their transactions."""

    async def load_chain(self, chain_id: int) -> ChainConfigRow:
        """Read the `chains` row. Raises `LookupError` when it does not exist."""
        ...

    async def load_assets(self, chain_id: int) -> list[AssetRef]:
        """Every asset row for this chain, including disabled ones.

        Disabled assets stay in the filter on purpose: a transfer of a known but
        not-accepted token is `wrong_asset` and has to be *recorded* so a human
        can decide (TZ 5.5). Dropping it from the filter would turn a documented
        anomaly into an invisible one.
        """
        ...

    async def load_watched_addresses(self) -> list[WatchedAddress]:
        """The hot filter set (TZ 5.2 optimisation), ordered by priority.

        Included: addresses reserved by a live invoice, and addresses that still
        hold unswept funds. Excluded: `free` addresses (nobody was told to pay
        them) and `swept` ones (their money is already in cold storage).

        Deliberately *not* filtered by chain. A receive address exists at the
        same value on every EVM network (TZ section 2), so the Ethereum watcher
        has to watch addresses whose invoice was issued on Base — that is
        precisely how a `wrong_chain` payment gets noticed instead of vanishing
        (TZ 5.5).
        """
        ...

    async def canonical_block(self, chain_id: int, number: int) -> StoredBlock | None:
        """The non-orphaned block stored at this height, if any."""
        ...

    async def latest_canonical_block(self, chain_id: int) -> StoredBlock | None:
        """Highest non-orphaned stored block — the anchor for the parent check."""
        ...

    async def insert_block(self, chain_id: int, header: BlockHeader, status: str) -> bool:
        """Store a header. False when it was already there (restart, re-walk)."""
        ...

    async def orphan_blocks_above(self, chain_id: int, number: int) -> tuple[int, ...]:
        """Mark every stored block above `number` as `orphaned`; return heights.

        This is the whole of the watcher's reorg write path. Payments inside
        those blocks keep their status until the settler acts on them — the
        watcher has no UPDATE on `payments` by design (TZ 5.8/T1.2 reasoning
        applied to the money tables).
        """
        ...

    async def promote_confirmed_blocks(self, chain_id: int, up_to_number: int) -> int:
        """Move `pending` blocks at or below `up_to_number` to `confirmed`.

        Bookkeeping, not a money decision: it records how deep a block is now
        buried. Whether that depth is enough for a given invoice depends on the
        amount and on `use_finalized_tag`, and that judgement is the settler's
        (TZ 5.4).
        """
        ...

    async def insert_payments(
        self,
        events: Sequence[TransferEvent],
        *,
        asset_enabled: Mapping[int, bool] | None = None,
    ) -> PaymentWriteResult:
        """Write raw transfers, `ON CONFLICT DO NOTHING` (TZ 5.5, 5.8/T3.1).

        `asset_enabled` maps `asset_id -> assets.is_enabled` for this chain. It
        is passed in rather than re-read inside the statement because the caller
        has already loaded the asset table to build its filter, and re-joining
        `assets` per payment would buy nothing: a token being switched off
        mid-block is not a race anyone needs to win.

        The invoice binding happens inside this statement, in the same
        transaction as the insert, read from `receive_addresses.current_invoice_id`
        — exactly as TZ 5.3 requires, and never afterwards: the column is
        immutable and a trigger enforces it.
        """
        ...

    async def set_checkpoint(self, chain_id: int, number: int) -> None:
        """Advance (or rewind, after a reorg) `chains.last_indexed_block`."""
        ...

    async def record_reobserved_payments(
        self, chain_id: int, events: Sequence[TransferEvent], reason: str
    ) -> None:
        """Leave an audit trail for payments re-seen during a post-reorg re-walk.

        See `watcher/traversal.py` for why this exists: `ON CONFLICT DO NOTHING`
        keeps the original row, whose `block_number` may now point at an
        orphaned block, and the settler needs to be told rather than left to
        conclude the payment disappeared.
        """
        ...

    async def count_reserved_addresses(self) -> int:
        """Feeds `notchstave_active_reserved_addresses` (TZ 5.8/T5)."""
        ...

    async def aclose(self) -> None:
        """Release the connection pool."""
        ...
