"""Block traversal, `parent_hash` verification and reorg rollback (TZ 5.4).

TZ section 8 asks for two things this file provides:

* "интеграционный тест с подменённым RPC: подаём цепочку блоков, затем
  альтернативную ветку, проверяем откат" — `test_alternative_branch_*` below,
  driven end to end through a real `ChainWalker`, a real `RpcPool` and a store
  double that enforces the schema's uniqueness constraints;
* "повторная обработка одного блока не создаёт дублей платежей" —
  `test_reprocessing_*`.

The third item TZ section 8 names — reorg *after* access has been granted, with
the entitlement revoked and `reverted_credits` rising — is deliberately **not**
here, and its absence is a boundary rather than a gap. Granting and revoking
access is the settler's, and the `notchstave_watcher` role has no UPDATE on
`payments` and no access to `entitlements` at all. What this file proves is the
half the watcher owns: the reorg is *detected*, the blocks are orphaned, the
checkpoint rewinds, and the payment rows the settler must act on are identifiable.
The revocation test belongs in the settler's suite and is cross-referenced here
so that neither side assumes the other covered it.
"""

from __future__ import annotations

import asyncio
import random

import pytest

from tests.watcher.fakes import (
    FakeRpcClient,
    InMemoryWatcherStore,
    make_block,
    make_chain,
    make_log,
)
from watcher.detect.erc20 import TRANSFER_TOPIC0
from watcher.models import AssetRef, WatchedAddress
from watcher.rpc.breaker import CircuitBreaker, RequestBudget
from watcher.rpc.client import ProviderSlot
from watcher.rpc.pool import ChunkPolicy, RpcPool
from watcher.traversal import ChainWalker, ReorgTooDeep, TraversalSettings, rewalk_after_reorg

CHAIN_ID = 8453
USDC = "0x1111111111111111111111111111111111110001"
POOL_ADDRESS = "0xAbC0000000000000000000000000000000000001"

GENESIS = "0x" + "00" * 32


def h(tag: str) -> str:
    """A distinct, well-formed 32-byte block hash from a short label."""
    return "0x" + (tag.encode().hex() * 32)[:64]


def usdc_asset() -> AssetRef:
    return AssetRef(
        asset_id=1,
        chain_id=CHAIN_ID,
        contract_lower=USDC,
        symbol="USDC",
        decimals=6,
        is_native=False,
        is_enabled=True,
    )


def build_walker(
    client: FakeRpcClient,
    *,
    chain=None,
    settings: TraversalSettings | None = None,
) -> tuple[ChainWalker, InMemoryWatcherStore]:
    chain = chain or make_chain(CHAIN_ID, min_confirmations=2)
    store = InMemoryWatcherStore(
        chain,
        addresses=[WatchedAddress(address_id=7, address=POOL_ADDRESS, priority=0)],
        assets=[usdc_asset()],
    )
    pool = RpcPool(
        CHAIN_ID,
        [
            ProviderSlot(
                client=client,
                breaker=CircuitBreaker(client.name),
                budget=RequestBudget(client.name, None),
            )
        ],
        chunks=ChunkPolicy(max_block_span=50, max_addresses=100),
        rng=random.Random(0),
        sleep=lambda _s: asyncio.sleep(0),
    )
    walker = ChainWalker(
        chain, pool, store, settings=settings or TraversalSettings(max_blocks_per_step=10)
    )
    return walker, store


def linear_chain(prefix: str, heights: range, *, parent_of_first: str = GENESIS) -> dict:
    """A chain of blocks whose `parent_hash` links line up."""
    blocks: dict[int, dict] = {}
    parent = parent_of_first
    for number in heights:
        block_hash = h(f"{prefix}{number}")
        blocks[number] = make_block(
            number, block_hash=block_hash, parent_hash=parent, timestamp=1_700_000_000 + number
        )
        parent = block_hash
    return blocks


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_walks_from_the_checkpoint_to_the_head_and_stores_a_linked_chain() -> None:
    client = FakeRpcClient("alchemy", blocks=linear_chain("a", range(1, 6)), head=5)
    walker, store = build_walker(client)

    outcome = asyncio.run(walker.step())

    assert outcome.from_block == 1
    assert outcome.to_block == 5
    assert outcome.blocks_written == 5
    assert store.chain.last_indexed_block == 5
    # Every stored block points at the one below it.
    stored = sorted(store.blocks, key=lambda r: r["number"])
    for lower, upper in zip(stored, stored[1:], strict=False):
        assert upper["parent_hash"] == lower["hash"]


def test_logs_are_fetched_for_the_whole_span_not_per_block() -> None:
    """TZ 5.2 wants tens of blocks per `eth_getLogs`, not one.

    Per-block requests are the version that looks simpler and costs 200 requests
    per step instead of one — the difference between keeping up with Base on a
    free tier and not.
    """
    client = FakeRpcClient("alchemy", blocks=linear_chain("a", range(1, 11)), head=10)
    walker, _ = build_walker(client)

    asyncio.run(walker.step())

    assert len(client.log_calls) == 1
    call = client.log_calls[0]
    assert int(call["fromBlock"], 16) == 1
    assert int(call["toBlock"], 16) == 10
    assert call["topics"][0] == TRANSFER_TOPIC0


def test_a_payment_in_the_span_is_recorded_once_with_the_stored_address() -> None:
    blocks = linear_chain("a", range(1, 4))
    log = make_log(
        contract=USDC,
        to_address=POOL_ADDRESS,
        amount=25_000_000,
        block_number=2,
        block_hash=blocks[2]["hash"],
        tx_hash="0x" + "cd" * 32,
        log_index=0,
    )
    client = FakeRpcClient("alchemy", blocks=blocks, logs=[log], head=3)
    walker, store = build_walker(client)

    outcome = asyncio.run(walker.step())

    assert outcome.payments_written == 1
    (event,) = store.payments.values()
    assert event.amount_raw == 25_000_000
    assert event.to_address == POOL_ADDRESS  # checksummed, as stored
    assert event.block_number == 2


def test_blocks_near_the_head_stay_pending_until_they_are_buried() -> None:
    """`min_confirmations=2`: the head and the one below it are not confirmed yet."""
    client = FakeRpcClient("alchemy", blocks=linear_chain("a", range(1, 6)), head=5)
    walker, store = build_walker(client, chain=make_chain(CHAIN_ID, min_confirmations=3))

    asyncio.run(walker.step())

    by_number = {row["number"]: row["status"] for row in store.blocks}
    assert by_number[5] == "pending"
    assert by_number[4] == "pending"
    assert by_number[1] == "confirmed"


# ---------------------------------------------------------------------------
# Reorgs (TZ 5.4)
# ---------------------------------------------------------------------------


def test_alternative_branch_is_detected_by_parent_hash_and_rolled_back() -> None:
    """Feed a chain, then swap in a competing branch — the core TZ 5.4 test.

    Branch A occupies heights 1..5. Branch B shares heights 1..3 and diverges at
    4. The walker must notice at height 4 that the provider's `parent_hash` no
    longer matches what is stored at 3... which it does, so it must keep walking
    and notice at 5 instead. Either way the outcome is the same: a common
    ancestor is found, everything above it is orphaned, and the checkpoint
    rewinds to it.
    """
    branch_a = linear_chain("a", range(1, 6))
    client = FakeRpcClient("alchemy", blocks=branch_a, head=5)
    walker, store = build_walker(client)

    asyncio.run(walker.step())
    assert store.chain.last_indexed_block == 5

    # The chain reorganises: heights 1..3 survive, 4 and 5 are replaced.
    branch_b = dict(branch_a)
    parent = branch_a[3]["hash"]
    for number in (4, 5, 6):
        block_hash = h(f"b{number}")
        branch_b[number] = make_block(number, block_hash=block_hash, parent_hash=parent)
        parent = block_hash
    client.blocks = branch_b
    client._head = 6

    outcome = asyncio.run(walker.step())

    assert outcome.reorg is not None
    assert outcome.reorg.common_ancestor == 3
    assert set(outcome.reorg.orphaned_numbers) == {4, 5}
    assert outcome.reorg.depth == 2
    assert store.chain.last_indexed_block == 3, "checkpoint must rewind to the ancestor"

    orphaned = {row["number"] for row in store.blocks if row["status"] == "orphaned"}
    assert orphaned == {4, 5}
    # Heights 1..3 were never touched.
    survivors = {
        row["number"]: row["hash"] for row in store.blocks if row["status"] != "orphaned"
    }
    assert survivors == {n: branch_a[n]["hash"] for n in (1, 2, 3)}


def test_rewalking_after_a_reorg_stores_the_new_branch() -> None:
    """The recovery half: after the rollback the winning branch is written.

    This is also what proves the rollback respected `uq_blocks_canonical_height`
    — the store double raises if a second canonical block appears at a height
    whose loser was not orphaned first.
    """
    branch_a = linear_chain("a", range(1, 6))
    client = FakeRpcClient("alchemy", blocks=branch_a, head=5)
    walker, store = build_walker(client)
    asyncio.run(walker.step())

    branch_b = dict(branch_a)
    parent = branch_a[3]["hash"]
    for number in (4, 5):
        block_hash = h(f"b{number}")
        branch_b[number] = make_block(number, block_hash=block_hash, parent_hash=parent)
        parent = block_hash
    client.blocks = branch_b

    first = asyncio.run(walker.step())
    assert first.reorg is not None

    second = asyncio.run(walker.step())
    assert second.reorg is None
    assert second.to_block == 5

    canonical = {
        row["number"]: row["hash"] for row in store.blocks if row["status"] != "orphaned"
    }
    assert canonical[4] == branch_b[4]["hash"]
    assert canonical[5] == branch_b[5]["hash"]


def test_payment_that_survives_a_reorg_at_a_new_height_is_flagged_for_the_settler() -> None:
    """The third reorg case from `watcher/traversal.py`'s docstring.

    Same `(tx_hash, log_index)`, different height. `ON CONFLICT DO NOTHING`
    keeps the original row, whose `block_number` now points at an orphaned
    block, and the watcher cannot fix it — it has no UPDATE on `payments`. So it
    writes an `audit_log` entry the settler consumes as "this payment is back,
    at this height" instead of concluding it was reverted. Without this the
    money silently vanishes from any query that joins on canonical blocks.
    """
    branch_a = linear_chain("a", range(1, 6))
    tx_hash = "0x" + "cd" * 32
    log_a = make_log(
        contract=USDC,
        to_address=POOL_ADDRESS,
        amount=10_000_000,
        block_number=4,
        block_hash=branch_a[4]["hash"],
        tx_hash=tx_hash,
        log_index=0,
    )
    client = FakeRpcClient("alchemy", blocks=branch_a, logs=[log_a], head=5)
    walker, store = build_walker(client)
    asyncio.run(walker.step())
    assert len(store.payments) == 1

    # Reorg: the same transaction is re-included, now at height 5.
    branch_b = dict(branch_a)
    parent = branch_a[3]["hash"]
    for number in (4, 5):
        block_hash = h(f"b{number}")
        branch_b[number] = make_block(number, block_hash=block_hash, parent_hash=parent)
        parent = block_hash
    client.blocks = branch_b
    client.logs = [
        make_log(
            contract=USDC,
            to_address=POOL_ADDRESS,
            amount=10_000_000,
            block_number=5,
            block_hash=branch_b[5]["hash"],
            tx_hash=tx_hash,
            log_index=0,
        )
    ]

    reorg_step = asyncio.run(walker.step())
    assert reorg_step.reorg is not None

    outcome = asyncio.run(rewalk_after_reorg(walker, reorg_step.reorg))

    assert outcome.payments_written == 0, "the unique key must keep the original row"
    assert outcome.payments_conflicted == 1
    assert len(store.payments) == 1, "no duplicate payment row"
    assert len(store.audit) == 1, "the settler must be told the payment came back"
    entry = store.audit[0]
    assert entry["action"] == "payment_reobserved_after_reorg"
    assert entry["block_number"] == 5, "the audit trail carries the height actually seen"


def test_reorg_at_the_tip_without_a_new_block_is_detected() -> None:
    """A short reorg replaces the tip and the head does not move.

    This is the blind spot `_verify_tail` exists to close, and it is the shape a
    short reorg most often takes: a competing block of the same height wins, the
    chain continues from it, and for one poll `checkpoint == head` still holds.
    Without the tail check the walk returns immediately, re-verifies nothing, and
    the stored block at that height stays wrong forever — along with every
    payment recorded against it.
    """
    branch_a = linear_chain("a", range(1, 4))
    client = FakeRpcClient("alchemy", blocks=branch_a, head=3)
    walker, store = build_walker(client)

    asyncio.run(walker.step())
    assert store.chain.last_indexed_block == 3

    # Height 3 is replaced. The head does NOT advance.
    replaced = dict(branch_a)
    replaced[3] = make_block(3, block_hash=h("b3"), parent_hash=branch_a[2]["hash"])
    client.blocks = replaced

    outcome = asyncio.run(walker.step())

    assert outcome.reorg is not None, "a tip replacement with no new block must be caught"
    assert outcome.reorg.common_ancestor == 2
    assert outcome.reorg.orphaned_numbers == (3,)
    assert store.chain.last_indexed_block == 2


def test_reorg_that_happens_mid_step_is_caught_by_the_forward_parent_check() -> None:
    """The chain changes between two header fetches inside one step.

    This is the path `_check_parent` owns, as opposed to `_verify_tail`: blocks
    1..4 are already written when the branch switches, and block 5 arrives
    claiming a parent that is not the block 4 just stored. Nothing about the
    stored tip was wrong when the step began, so only the forward check can see
    it.
    """
    branch_a = linear_chain("a", range(1, 6))
    branch_b = dict(branch_a)
    parent = branch_a[3]["hash"]
    for number in (4, 5):
        block_hash = h(f"b{number}")
        branch_b[number] = make_block(number, block_hash=block_hash, parent_hash=parent)
        parent = block_hash

    class SwitchingClient(FakeRpcClient):
        """Serves branch A until height 4 has been handed out, then branch B."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.switched = False

        async def get_block(self, block, *, full_transactions: bool = False):
            result = await super().get_block(block, full_transactions=full_transactions)
            if block == 4 and not self.switched:
                self.switched = True
                self.blocks = dict(branch_b)
            return result

    client = SwitchingClient("alchemy", blocks=branch_a, head=5)
    walker, store = build_walker(client)

    outcome = asyncio.run(walker.step())

    assert outcome.reorg is not None
    assert outcome.reorg.common_ancestor == 3
    assert outcome.reorg.orphaned_numbers == (4,)
    assert store.chain.last_indexed_block == 3
    # Block 4 from branch A was written and then orphaned; nothing canonical
    # survives above the ancestor.
    canonical = {row["number"] for row in store.blocks if row["status"] != "orphaned"}
    assert canonical == {1, 2, 3}


def test_a_lagging_provider_does_not_trigger_a_rollback() -> None:
    """"I don't have that block" is not evidence of a reorg.

    Rolling back on a provider that has fallen behind would let one slow node
    orphan a chain that is perfectly correct — turning an availability problem
    into a data problem.
    """
    branch_a = linear_chain("a", range(1, 4))
    client = FakeRpcClient("alchemy", blocks=branch_a, head=3)
    walker, store = build_walker(client)
    asyncio.run(walker.step())

    # The provider forgets everything above height 1 (a fresh, still-syncing node).
    client.blocks = {1: branch_a[1]}
    client._head = 1

    outcome = asyncio.run(walker.step())

    assert outcome.reorg is None
    assert store.chain.last_indexed_block == 3, "checkpoint must not rewind on an outage"
    assert not any(row["status"] == "orphaned" for row in store.blocks)


def test_reorg_deeper_than_the_limit_refuses_to_continue() -> None:
    """Not recoverable automatically, and deliberately so.

    A reorg past the configured depth on a payment chain is either a chain-level
    event or a sign the watcher is pointed at a different network. Writing more
    blocks in that state produces a history nobody can reconcile afterwards.
    """
    branch_a = linear_chain("a", range(1, 11))
    client = FakeRpcClient("alchemy", blocks=branch_a, head=10)
    walker, _ = build_walker(
        client, settings=TraversalSettings(max_blocks_per_step=20, max_reorg_depth=2)
    )
    asyncio.run(walker.step())

    # A branch that shares nothing above height 1.
    client.blocks = linear_chain("z", range(1, 12))

    with pytest.raises(ReorgTooDeep):
        asyncio.run(walker.step())


def test_a_log_from_a_block_we_did_not_verify_is_dropped() -> None:
    """The provider moved branch between the header fetch and the log fetch.

    Recording it would attach a payment to a height whose stored block says
    something else — the one inconsistency the reorg machinery cannot repair
    afterwards, because the watcher has no UPDATE on `payments`.
    """
    blocks = linear_chain("a", range(1, 4))
    stale = make_log(
        contract=USDC,
        to_address=POOL_ADDRESS,
        amount=1_000_000,
        block_number=2,
        block_hash=h("ghost"),  # not the hash the walker verified at height 2
        tx_hash="0x" + "ee" * 32,
        log_index=0,
    )
    client = FakeRpcClient("alchemy", blocks=blocks, logs=[stale], head=3)
    walker, store = build_walker(client)

    outcome = asyncio.run(walker.step())

    assert outcome.payments_written == 0
    assert store.payments == {}


# ---------------------------------------------------------------------------
# Idempotency (TZ section 8)
# ---------------------------------------------------------------------------


def test_reprocessing_the_same_block_creates_no_duplicate_payments() -> None:
    """TZ section 8: "повторная обработка одного блока не создаёт дублей".

    The checkpoint is rewound by hand to simulate a crash between writing the
    payments and committing the checkpoint — the exact window a restart lands
    in. The unique key `(chain_id, tx_hash, log_index)` plus `ON CONFLICT DO
    NOTHING` is what makes the redo free.
    """
    blocks = linear_chain("a", range(1, 4))
    log = make_log(
        contract=USDC,
        to_address=POOL_ADDRESS,
        amount=25_000_000,
        block_number=2,
        block_hash=blocks[2]["hash"],
        tx_hash="0x" + "cd" * 32,
        log_index=0,
    )
    client = FakeRpcClient("alchemy", blocks=blocks, logs=[log], head=3)
    walker, store = build_walker(client)

    first = asyncio.run(walker.step())
    assert first.payments_written == 1

    asyncio.run(store.set_checkpoint(CHAIN_ID, 0))
    second = asyncio.run(walker.step())

    assert second.payments_written == 0
    assert second.payments_conflicted == 1
    assert len(store.payments) == 1
    assert second.blocks_written == 0, "block inserts are idempotent too"


def test_two_transfers_in_one_transaction_are_distinct_payments() -> None:
    """Same `tx_hash`, different `log_index` — the unique key must not merge them.

    A wallet batching two transfers into one transaction is ordinary, and
    collapsing them would under-count the money that arrived.
    """
    blocks = linear_chain("a", range(1, 3))
    tx_hash = "0x" + "cd" * 32
    logs = [
        make_log(
            contract=USDC,
            to_address=POOL_ADDRESS,
            amount=amount,
            block_number=1,
            block_hash=blocks[1]["hash"],
            tx_hash=tx_hash,
            log_index=index,
        )
        for index, amount in ((0, 4_000_000), (1, 6_000_000))
    ]
    client = FakeRpcClient("alchemy", blocks=blocks, logs=logs, head=2)
    walker, store = build_walker(client)

    outcome = asyncio.run(walker.step())

    assert outcome.payments_written == 2
    assert sum(e.amount_raw for e in store.payments.values()) == 10_000_000


def test_cold_start_does_not_replay_the_chain_from_genesis() -> None:
    """A checkpoint of 0 means "no checkpoint", not "start at block zero".

    Replaying an L2 from genesis to find invoices created yesterday would spend
    the whole request budget before reaching a single relevant block.
    """
    client = FakeRpcClient("alchemy", blocks=linear_chain("a", range(9_000, 9_011)), head=9_010)
    walker, _ = build_walker(
        client,
        settings=TraversalSettings(max_blocks_per_step=5, initial_lookback_blocks=10),
    )

    outcome = asyncio.run(walker.step())

    assert outcome.from_block == 9_001
    assert min(n for n in client.block_calls if isinstance(n, int)) >= 9_000


def test_an_empty_address_pool_costs_no_log_requests() -> None:
    """No invoices means nothing to look for — and the budget is finite."""
    client = FakeRpcClient("alchemy", blocks=linear_chain("a", range(1, 4)), head=3)
    chain = make_chain(CHAIN_ID)
    store = InMemoryWatcherStore(chain, addresses=[], assets=[usdc_asset()])
    pool = RpcPool(
        CHAIN_ID,
        [
            ProviderSlot(
                client=client,
                breaker=CircuitBreaker(client.name),
                budget=RequestBudget(client.name, None),
            )
        ],
        rng=random.Random(0),
        sleep=lambda _s: asyncio.sleep(0),
    )
    walker = ChainWalker(chain, pool, store)

    asyncio.run(walker.step())

    assert client.log_calls == []
