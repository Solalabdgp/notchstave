"""Test doubles: a scripted RPC client and an in-memory store.

TZ section 8: "RPC в тестах мокается сохранёнными ответами. Никаких сетевых
вызовов в CI." Both doubles below exist to make that literally true — nothing in
`tests/watcher/` opens a socket, and neither `web3` nor `sqlalchemy` needs to be
installed to run the suite.

The store double is the more important of the two, and the reason is worth
stating: **it enforces the same uniqueness rules as the real schema.** A fake
that accepts everything would make the idempotency tests pass by construction
and prove nothing at all. So :class:`InMemoryWatcherStore` implements

* `UNIQUE (chain_id, tx_hash, log_index)` on payments, with the insert reporting
  conflicts the way `ON CONFLICT DO NOTHING` does;
* `UNIQUE (chain_id, hash)` on blocks;
* the partial unique index `uq_blocks_canonical_height` — at most one
  non-orphaned block per height — which is the constraint the reorg path has to
  respect and the one a naive rollback breaks.

What it does *not* model, and what therefore still needs a database to verify,
is the SQL inside `SQL_INSERT_PAYMENT`: the invoice binding, the `anomaly`
classification and the immutability trigger. Those are integration territory,
and pretending otherwise here would be the same mistake as a fake that accepts
everything. See the TODO at the bottom of this file.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any

from watcher.models import (
    AssetRef,
    BlockHeader,
    PaymentWriteResult,
    StoredBlock,
    TransferEvent,
    WatchedAddress,
)
from watcher.rpc.client import BlockTag, RpcClient
from watcher.rpc.errors import RpcError, RpcErrorClass
from watcher.store.base import ChainConfigRow

__all__ = [
    "FakeRpcClient",
    "ScriptedRpcClient",
    "InMemoryWatcherStore",
    "make_chain",
    "make_log",
    "make_block",
]


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def _hex(value: int) -> str:
    return hex(value)


def make_block(
    number: int,
    *,
    block_hash: str,
    parent_hash: str,
    timestamp: int = 1_700_000_000,
    transactions: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """A provider block object with the fields the watcher actually reads."""
    return {
        "number": _hex(number),
        "hash": block_hash,
        "parentHash": parent_hash,
        "timestamp": _hex(timestamp),
        "transactions": list(transactions or ()),
    }


def make_log(
    *,
    contract: str,
    to_address: str,
    amount: int,
    block_number: int,
    block_hash: str,
    tx_hash: str,
    log_index: int,
    from_address: str = "0x" + "11" * 20,
    topic0: str | None = None,
    extra_topic: bool = False,
    removed: bool = False,
) -> dict[str, Any]:
    """An `eth_getLogs` entry shaped exactly as a provider returns one.

    `extra_topic=True` produces the four-topic ERC-721 form, which shares the
    `Transfer(address,address,uint256)` signature hash with ERC-20 and is the
    trap `watcher/detect/erc20.py` exists to avoid.
    """
    from watcher.detect.erc20 import TRANSFER_TOPIC0, address_to_topic

    topics = [
        topic0 or TRANSFER_TOPIC0,
        address_to_topic(from_address),
        address_to_topic(to_address),
    ]
    if extra_topic:
        topics.append("0x" + f"{amount:064x}")
    return {
        "address": contract,
        "topics": topics,
        "data": "0x" + f"{amount:064x}",
        "blockNumber": _hex(block_number),
        "blockHash": block_hash,
        "transactionHash": tx_hash,
        "logIndex": _hex(log_index),
        "removed": removed,
    }


def make_chain(
    chain_id: int = 8453,
    *,
    name: str = "test-chain",
    min_confirmations: int = 3,
    use_finalized_tag: bool = False,
    last_indexed_block: int = 0,
    rpc_urls: Sequence[str] = ("https://provider-a.example/v2/KEY",),
) -> ChainConfigRow:
    return ChainConfigRow(
        chain_id=chain_id,
        name=name,
        rpc_urls=rpc_urls,
        min_confirmations=min_confirmations,
        credit_threshold_usd=Decimal("20"),
        use_finalized_tag=use_finalized_tag,
        last_indexed_block=last_indexed_block,
        is_enabled=True,
    )


# ---------------------------------------------------------------------------
# RPC doubles
# ---------------------------------------------------------------------------


class FakeRpcClient(RpcClient):
    """Replays saved responses out of dicts keyed by block number.

    `blocks` maps height -> provider block object. Swapping that dict mid-test
    is how a reorg is simulated: the same heights start answering with a
    different branch, which is exactly what a real reorg looks like from the
    client side.
    """

    def __init__(
        self,
        name: str = "fake",
        *,
        blocks: Mapping[int, dict[str, Any]] | None = None,
        logs: Sequence[dict[str, Any]] = (),
        receipts: Mapping[str, dict[str, Any]] | None = None,
        head: int | None = None,
        finalized: int | None = None,
    ) -> None:
        self.name = name
        self.blocks: dict[int, dict[str, Any]] = dict(blocks or {})
        self.logs: list[dict[str, Any]] = list(logs)
        self.receipts: dict[str, dict[str, Any]] = dict(receipts or {})
        self._head = head
        self._finalized = finalized
        #: Every filter object this client was asked for, in order. The chunking
        #: tests assert on this rather than on the results, because "did not
        #: lose a payment" and "did not send one enormous request" are different
        #: claims and both matter.
        self.log_calls: list[dict[str, Any]] = []
        self.block_calls: list[int | str] = []
        self.closed = False

    @property
    def head(self) -> int:
        if self._head is not None:
            return self._head
        return max(self.blocks) if self.blocks else 0

    async def block_number(self, tag: BlockTag = "latest") -> int:
        if tag == "finalized":
            if self._finalized is None:
                raise RpcError(
                    "provider does not serve the 'finalized' tag",
                    error_class=RpcErrorClass.MALFORMED_RESPONSE,
                    provider=self.name,
                )
            return self._finalized
        return self.head

    async def get_block(
        self, block: int | BlockTag, *, full_transactions: bool = False
    ) -> dict[str, Any]:
        self.block_calls.append(block)
        if isinstance(block, str):
            block = self.head
        payload = self.blocks.get(block)
        if payload is None:
            raise RpcError(
                f"block {block} unknown to provider",
                error_class=RpcErrorClass.MALFORMED_RESPONSE,
                provider=self.name,
                method="eth_getBlockByNumber",
            )
        if not full_transactions:
            stripped = dict(payload)
            stripped["transactions"] = [
                tx["hash"] if isinstance(tx, dict) else tx
                for tx in payload.get("transactions", [])
            ]
            return stripped
        return payload

    async def get_logs(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        self.log_calls.append(params)
        from_block = int(params["fromBlock"], 16)
        to_block = int(params["toBlock"], 16)
        topics = params.get("topics") or []
        wanted_topic0 = topics[0] if topics else None
        recipients = set(topics[2]) if len(topics) > 2 and topics[2] else None
        contracts = {c.lower() for c in params.get("address", [])} or None

        selected: list[dict[str, Any]] = []
        for log in self.logs:
            if not (from_block <= int(log["blockNumber"], 16) <= to_block):
                continue
            if wanted_topic0 and log["topics"][0] != wanted_topic0:
                continue
            if recipients is not None and log["topics"][2] not in recipients:
                continue
            if contracts is not None and log["address"].lower() not in contracts:
                continue
            selected.append(log)
        return selected

    async def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        return self.receipts.get(tx_hash)

    async def aclose(self) -> None:
        self.closed = True


class ScriptedRpcClient(RpcClient):
    """Answers with a fixed script of outcomes, for failure-path tests.

    Each entry is either an exception to raise or a value to return, consumed in
    order; the last entry repeats once the script runs out so a test only has to
    describe the part it cares about.
    """

    def __init__(self, name: str, script: Sequence[Any]) -> None:
        self.name = name
        self.script = list(script)
        self.calls = 0
        self.closed = False

    def _next(self) -> Any:
        if not self.script:
            raise RpcError("empty script", error_class=RpcErrorClass.SERVER_ERROR)
        index = min(self.calls, len(self.script) - 1)
        self.calls += 1
        outcome = self.script[index]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def block_number(self, tag: BlockTag = "latest") -> int:
        return int(self._next())

    async def get_block(
        self, block: int | BlockTag, *, full_transactions: bool = False
    ) -> dict[str, Any]:
        return dict(self._next())

    async def get_logs(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return list(self._next())

    async def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        return self._next()

    async def aclose(self) -> None:
        self.closed = True


# ---------------------------------------------------------------------------
# Store double
# ---------------------------------------------------------------------------


class InMemoryWatcherStore:
    """A `WatcherStore` that enforces the schema's uniqueness rules.

    Not a mock: the constraints are the part under test, so they are real here.
    """

    def __init__(
        self,
        chain: ChainConfigRow,
        *,
        addresses: Sequence[WatchedAddress] = (),
        assets: Sequence[AssetRef] = (),
    ) -> None:
        self.chain = chain
        self._addresses = list(addresses)
        self._assets = list(assets)
        #: (chain_id, number) -> list of stored blocks, newest last. A height can
        #: hold several rows once a reorg has orphaned the losers.
        self.blocks: list[dict[str, Any]] = []
        #: (chain_id, tx_hash, log_index) -> the row that won the insert race.
        self.payments: dict[tuple[int, str, int], TransferEvent] = {}
        self.audit: list[dict[str, Any]] = []
        self.closed = False

    # ------------------------------------------------------------- config --
    async def load_chain(self, chain_id: int) -> ChainConfigRow:
        if chain_id != self.chain.chain_id:
            raise LookupError(chain_id)
        return self.chain

    async def load_assets(self, chain_id: int) -> list[AssetRef]:
        return [asset for asset in self._assets if asset.chain_id == chain_id]

    async def load_watched_addresses(self) -> list[WatchedAddress]:
        return sorted(self._addresses, key=lambda a: (a.priority, a.address_id))

    async def count_reserved_addresses(self) -> int:
        return sum(1 for address in self._addresses if address.priority <= 1)

    # ------------------------------------------------------------- blocks --
    def _canonical_rows(self, chain_id: int) -> list[dict[str, Any]]:
        return [
            row
            for row in self.blocks
            if row["chain_id"] == chain_id and row["status"] != "orphaned"
        ]

    async def canonical_block(self, chain_id: int, number: int) -> StoredBlock | None:
        for row in self._canonical_rows(chain_id):
            if row["number"] == number:
                return StoredBlock(
                    number=row["number"],
                    hash=row["hash"],
                    parent_hash=row["parent_hash"],
                    status=row["status"],
                )
        return None

    async def latest_canonical_block(self, chain_id: int) -> StoredBlock | None:
        rows = self._canonical_rows(chain_id)
        if not rows:
            return None
        row = max(rows, key=lambda r: r["number"])
        return StoredBlock(
            number=row["number"],
            hash=row["hash"],
            parent_hash=row["parent_hash"],
            status=row["status"],
        )

    async def insert_block(self, chain_id: int, header: BlockHeader, status: str) -> bool:
        # UNIQUE (chain_id, hash) -> ON CONFLICT DO NOTHING.
        for row in self.blocks:
            if row["chain_id"] == chain_id and row["hash"] == header.hash:
                return False
        # Partial unique index: at most one non-orphaned block per height.
        if status != "orphaned":
            clash = await self.canonical_block(chain_id, header.number)
            if clash is not None:
                raise AssertionError(
                    f"uq_blocks_canonical_height violated: height {header.number} already "
                    f"holds canonical {clash.hash}, refusing {header.hash}. "
                    "The reorg path must orphan the loser before inserting the winner."
                )
        self.blocks.append(
            {
                "chain_id": chain_id,
                "number": header.number,
                "hash": header.hash,
                "parent_hash": header.parent_hash,
                "timestamp": header.timestamp,
                "status": status,
            }
        )
        return True

    async def orphan_blocks_above(self, chain_id: int, number: int) -> tuple[int, ...]:
        orphaned: list[int] = []
        for row in self.blocks:
            if (
                row["chain_id"] == chain_id
                and row["number"] > number
                and row["status"] != "orphaned"
            ):
                row["status"] = "orphaned"
                orphaned.append(row["number"])
        return tuple(orphaned)

    async def promote_confirmed_blocks(self, chain_id: int, up_to_number: int) -> int:
        promoted = 0
        for row in self.blocks:
            if (
                row["chain_id"] == chain_id
                and row["number"] <= up_to_number
                and row["status"] == "pending"
            ):
                row["status"] = "confirmed"
                promoted += 1
        return promoted

    async def set_checkpoint(self, chain_id: int, number: int) -> None:
        self.chain = ChainConfigRow(
            chain_id=self.chain.chain_id,
            name=self.chain.name,
            rpc_urls=self.chain.rpc_urls,
            min_confirmations=self.chain.min_confirmations,
            credit_threshold_usd=self.chain.credit_threshold_usd,
            use_finalized_tag=self.chain.use_finalized_tag,
            last_indexed_block=number,
            is_enabled=self.chain.is_enabled,
        )

    # ----------------------------------------------------------- payments --
    async def insert_payments(
        self,
        events: Sequence[TransferEvent],
        *,
        asset_enabled: Mapping[int, bool] | None = None,
    ) -> PaymentWriteResult:
        inserted: list[TransferEvent] = []
        conflicted: list[TransferEvent] = []
        for event in events:
            key = (event.chain_id, event.tx_hash, event.log_index)
            if key in self.payments:
                conflicted.append(event)
                continue
            self.payments[key] = event
            inserted.append(event)
        return PaymentWriteResult(tuple(inserted), tuple(conflicted))

    async def record_reobserved_payments(
        self, chain_id: int, events: Sequence[TransferEvent], reason: str
    ) -> None:
        for event in events:
            self.audit.append(
                {
                    "action": "payment_reobserved_after_reorg",
                    "chain_id": chain_id,
                    "tx_hash": event.tx_hash,
                    "log_index": event.log_index,
                    "block_number": event.block_number,
                    "block_hash": event.block_hash,
                    "reason": reason,
                }
            )

    async def aclose(self) -> None:
        self.closed = True


# TODO(week 3, integration): the statements this double cannot stand in for are
# in `watcher/store/postgres.py` — `SQL_INSERT_PAYMENT`'s invoice binding and
# `anomaly` classification, and the `payments_invoice_id_immutable` trigger.
# They need a real Postgres, gated on NOTCHSTAVE_TEST_DSN the same way
# `deriver/tests/test_pool.py` gates its locking tests. The unit suite proves
# the traversal and decoding logic; it does not yet prove the SQL.
