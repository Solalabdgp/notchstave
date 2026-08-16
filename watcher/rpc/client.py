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

The method set is deliberately small. Everything the watcher needs is here and
nothing else is: no `eth_call`, no `send_raw_transaction`, no account access.
That is not minimalism for its own sake — TZ section 12 and the architectural
test in TZ section 8 require that this codebase contain no code path capable of
signing or broadcasting a transaction, and a client interface that cannot
express one is the cheapest way to keep that true as the code grows.
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

    async def aclose(self) -> None:
        """Release connection-level resources."""

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
