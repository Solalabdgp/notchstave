"""The abstract RPC client — this project's `Fetcher`.

`scraping-platform/app/workers/fetchers/base.py` defines one abstract method
family, normalises every failure into a single exception carrying an
`error_class`, and keeps call sites free of concrete engines so that adding
Playwright was a registry entry rather than a refactor. TZ 5.6 asks for the
same pattern here, and the payoff is the same in both directions:

* swapping web3.py for a hand-rolled JSON-RPC client, or pointing the watcher
  at a local node, is a constructor change;
* the tests replay saved provider payloads through a fake implementing this
  ABC, so the whole traversal and detection stack runs with no network at all.

The method set is deliberately small: no `send_raw_transaction`, no account
access, no signing. That is not minimalism for its own sake — TZ section 12 and
the architectural test in TZ section 8 require that this codebase contain no
code path capable of signing or broadcasting a transaction, and a client
interface that cannot express one is the cheapest way to keep that true as the
code grows.

**Week 3 addition, and why it does not weaken the rule above.** `/reconcile`
and `/sweeplist` (TZ 3.4) need the *actual* balance of a receive address, which
is `eth_getBalance` for a native coin and an `eth_call` of `balanceOf` for an
ERC-20. Both are read-only JSON-RPC methods: neither takes a signature, neither
changes state, and a node serving them over a public HTTPS endpoint cannot be
made to move a coin by them. The invariant the architectural test protects is
"nothing here can sign or broadcast", not "nothing here can read", and
`/reconcile` is the check that catches the case where the ledger and the chain
have silently diverged — the most serious alert in TZ section 7. Refusing to
read balances in order to keep the interface small would mean the system cannot
audit its own books, which is a strictly worse trade.

They live on this ABC rather than in a second client next to the settler for
the reason TZ 5.6 gives: one pool, one rotation, one circuit breaker, one
request budget. A second HTTP path to the same providers would be outside all
four.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from watcher.rpc.breaker import CircuitBreaker, RequestBudget

__all__ = ["RpcClient", "ProviderSlot", "BlockTag"]

#: `latest` is the head as the node sees it. `safe` and `finalized` are the
#: OP-stack / post-Merge tags TZ 5.4 leans on for large amounts: on an L2 like
#: Base a confirmation count on the sequencer means nothing until the batch has
#: reached L1, so "thirty blocks deep" and "finalized" are different questions.
#: The watcher only *records* which tag a block satisfied; deciding that a given
#: invoice needs `finalized` is the settler's call (TZ section 4).
BlockTag = str


class RpcClient(ABC):
    """One provider endpoint. Implementations must be safe to reuse across calls.

    Every method raises :class:`watcher.rpc.errors.RpcError` and nothing else —
    a provider-library exception escaping this boundary would defeat the whole
    taxonomy, because the pool decides between "retry", "fail over" and "split
    the range" purely from `error_class`.
    """

    #: Safe label (host only, never the key-bearing URL). Used as a metric label.
    name: str

    @abstractmethod
    async def block_number(self, tag: BlockTag = "latest") -> int:
        """Height of the block referenced by `tag`.

        Raises:
            RpcError: transport failure, or a provider that does not know the tag
                (some do not implement `safe`/`finalized` — TZ 5.4 says to check
                this per provider rather than assume).
        """

    @abstractmethod
    async def get_block(
        self, block: int | BlockTag, *, full_transactions: bool = False
    ) -> dict[str, Any]:
        """`eth_getBlockByNumber`. Returns the raw provider mapping.

        `full_transactions=True` is only used by native-coin detection
        (`watcher/detect/native.py`); the ERC-20 path never needs transaction
        bodies and must not pay for them.

        Raises:
            RpcError: including `malformed_response` when the answer is missing
                the header fields the reorg check depends on.
        """

    @abstractmethod
    async def get_logs(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """`eth_getLogs` with an already-built filter object.

        The filter is built by the caller (`watcher/detect/erc20.py`) rather than
        assembled from keyword arguments here, so that the exact object sent to
        the node is a value the tests can assert on.

        Raises:
            RpcError: `range_too_large` when the provider refuses the span —
                the caller must halve, not fail over.
        """

    @abstractmethod
    async def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        """`eth_getTransactionReceipt`, or None if the node does not have it.

        Used only to confirm that a native-coin transfer actually succeeded: a
        reverted transaction still sits in the block with its `value` field
        intact, and crediting one would be paying out for a payment that never
        happened. ERC-20 needs no such check — logs of a reverted transaction
        are discarded by the node, so a `Transfer` log is itself proof of
        success.
        """

    @abstractmethod
    async def get_balance(self, address: str, block: int | BlockTag = "latest") -> int:
        """`eth_getBalance` — native-coin balance of `address`, in wei.

        Read-only. Used by `/reconcile` and `/sweeplist` (TZ 3.4) and by nothing
        in the indexing path: the watcher detects payments from logs and blocks,
        never from balances, because a balance is a state and a payment is an
        event.

        Raises:
            RpcError: transport failure, or a non-hex answer.
        """

    @abstractmethod
    async def call(self, params: dict[str, Any], block: int | BlockTag = "latest") -> str:
        """`eth_call` — evaluate a read-only contract call, returning raw hex data.

        `params` is the transaction object (`{"to": ..., "data": ...}`) built by
        the caller, for the same reason `get_logs` takes an assembled filter: the
        exact object sent to the node is then a value a test can assert on.

        Only ever used with `balanceOf(address)` (see
        `settler.admin.balances`). `eth_call` executes against a *pending* state
        copy inside the node and cannot produce a transaction — it is the
        read half of the contract ABI, not the write half.

        Raises:
            RpcError: transport failure, a revert, or a non-hex answer.
        """

    async def aclose(self) -> None:  # noqa: B027 - see below
        """Release connection-level resources.

        Concrete, empty and deliberately **not** abstract, which is what B027
        flags. A client that holds no connection — the scripted doubles in
        ``tests/watcher/fakes.py``, or a future in-process client — has nothing
        to release, and forcing every implementation to write ``pass`` buys no
        safety while making the ABC harder to implement correctly. Leaking a real
        connection pool is caught by the implementation's own tests, not by a
        decorator.
        """

    async def __aenter__(self) -> RpcClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()


@dataclass(slots=True)
class ProviderSlot:
    """A client plus the two guards that decide whether it may be used.

    Ordering inside `RpcPool` is the rotation order: primaries first (Alchemy,
    QuickNode), independent fallback last (Ankr). "Independent" is the operative
    word in TZ 5.6 — two providers reselling the same upstream infrastructure
    fail together, so the third slot exists to not share a failure domain, not
    to add a third of anything.
    """

    client: RpcClient
    breaker: CircuitBreaker
    budget: RequestBudget

    @property
    def name(self) -> str:
        return self.client.name

    @property
    def available(self) -> bool:
        """Cheap pre-check for logging/metrics. The pool still calls `allow()`."""
        return self.breaker.state != "open"
