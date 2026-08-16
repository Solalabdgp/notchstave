"""RPC provider pool (TZ 5.6).

Three providers per chain — Alchemy and QuickNode as primaries, Ankr as an
independent third fallback — with a circuit breaker each, exponential backoff
with jitter, a request budget, and `eth_getLogs` chunked over both axes (block
range and address list).

The contract is the one from `scraping-platform/app/workers/fetchers/base.py`,
which TZ 5.6 explicitly says is reused rather than reinvented: an abstract
client, one exception type carrying an `error_class` string so that the caller
branches on a taxonomy instead of parsing messages, and call sites that never
import a concrete implementation. `RpcClient` is the `Fetcher` of this project;
`RpcError` is its `FetchError`.

Layout:

    errors.py       the taxonomy, the exception, and message/code classification
    breaker.py      circuit breaker (closed/open/half_open) + request budget
    client.py       the abstract client + the shape of a provider slot
    web3_client.py  the web3.py implementation (the only module importing web3)
    pool.py         failover, backoff, chunking, cross-provider agreement checks
"""

from watcher.rpc.breaker import BreakerPolicy, BreakerState, CircuitBreaker, RequestBudget
from watcher.rpc.client import ProviderSlot, RpcClient
from watcher.rpc.errors import RpcError, RpcErrorClass, classify_json_rpc_error
from watcher.rpc.pool import ChunkPolicy, RetryPolicy, RpcPool

__all__ = [
    "BreakerPolicy",
    "BreakerState",
    "ChunkPolicy",
    "CircuitBreaker",
    "ProviderSlot",
    "RequestBudget",
    "RetryPolicy",
    "RpcClient",
    "RpcError",
    "RpcErrorClass",
    "RpcPool",
    "classify_json_rpc_error",
]
