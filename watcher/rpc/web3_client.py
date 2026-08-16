"""web3.py implementation of :class:`watcher.rpc.client.RpcClient`.

TZ 5.1 is explicit that RPC access goes through web3.py and that no bespoke
JSON-RPC client is written for this project. This module is the only place in
the repository that imports it, which is what keeps the rest of the watcher
testable against saved payloads.

Its entire job is translation in two directions:

* **outbound** — an `AsyncWeb3` call, made through the raw provider interface
  (`make_request`) rather than the typed `w3.eth.*` helpers. That is deliberate:
  the typed helpers normalise results into `AttributeDict` with `HexBytes`
  values, and this watcher wants the provider's own JSON shapes, because those
  are exactly what the fixtures in `tests/watcher/fixtures/` replay. One shape
  in tests and another in production is how a decoder passes its tests and then
  mis-parses a real block.
* **inbound** — every failure becomes an :class:`RpcError` with an
  `error_class` from the taxonomy. Nothing web3-shaped escapes this module.

The import of web3 is lazy (inside `__init__`) so that `import watcher.rpc`
works in an environment where only the pure logic is under test — the same
reason the deriver keeps its dependency set physically separate.
"""

from __future__ import annotations

import asyncio
from typing import Any

from watcher.rpc.client import BlockTag, RpcClient
from watcher.rpc.errors import RpcError, RpcErrorClass, classify_json_rpc_error

__all__ = ["Web3RpcClient"]

#: Header fields the reorg check in `traversal.py` cannot work without. A block
#: missing any of them is a malformed response, not a block.
REQUIRED_BLOCK_FIELDS = ("number", "hash", "parentHash", "timestamp")


class Web3RpcClient(RpcClient):
    """One endpoint, spoken to over web3.py's async HTTP provider.

    `label` must already be the safe, key-free provider name — see
    `watcher.config.provider_label`. The URL itself is stored only to build the
    provider and is never put into an exception, a log line or a metric label.
    """

    def __init__(
        self,
        label: str,
        url: str,
        *,
        request_timeout: float = 15.0,
    ) -> None:
        # Local import: keeps `watcher.rpc` importable without web3 installed.
        from web3 import AsyncHTTPProvider, AsyncWeb3

        self.name = label
        self._timeout = request_timeout
        self._provider = AsyncHTTPProvider(
            url,
            # web3 v7's AsyncHTTPProvider retries ClientError/TimeoutError on its
            # own, five times with its own backoff, before the exception ever
            # reaches this class. Two independent retry loops is not twice the
            # resilience: it multiplies the request count, hides failures from
            # the circuit breaker (which would see one slow call instead of five
            # failures) and blows the budget from TZ 5.6 without the budget ever
            # being consulted. Retry policy lives in `RpcPool` and nowhere else,
            # so the provider's own is switched off.
            exception_retry_configuration=None,
        )
        # Timeouts are enforced by `asyncio.wait_for` below rather than through
        # `request_kwargs={"timeout": ...}`: the async provider forwards those
        # kwargs to aiohttp, whose `timeout` parameter wants a `ClientTimeout`
        # object, not a number, and getting that wrong fails at request time
        # instead of at construction time.
        self._w3 = AsyncWeb3(self._provider)

    # ---------------------------------------------------------------- plumbing --
    async def _request(self, method: str, params: list[Any]) -> Any:
        """One JSON-RPC round trip, with every failure mapped to the taxonomy."""
        try:
            response = await asyncio.wait_for(
                self._provider.make_request(method, params),  # type: ignore[arg-type]
                timeout=self._timeout,
            )
        except asyncio.TimeoutError as exc:
            raise RpcError(
                f"timeout calling {method}",
                error_class=RpcErrorClass.TIMEOUT,
                provider=self.name,
                method=method,
            ) from exc
        except Exception as exc:  # noqa: BLE001 - the boundary exists to flatten these
            # Anything web3 or the transport raises (connection reset, DNS,
            # malformed JSON) lands here. Catching broadly is the point of this
            # class: one exception type crosses the boundary, chosen by the
            # taxonomy rather than by whatever library happened to fail.
            raise RpcError(
                f"transport failure calling {method}: {type(exc).__name__}",
                error_class=RpcErrorClass.TRANSPORT,
                provider=self.name,
                method=method,
            ) from exc

        if not isinstance(response, dict):
            raise RpcError(
                f"{method} returned {type(response).__name__}, expected a JSON-RPC object",
                error_class=RpcErrorClass.MALFORMED_RESPONSE,
                provider=self.name,
                method=method,
            )

        error = response.get("error")
        if error:
            code = error.get("code") if isinstance(error, dict) else None
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise RpcError(
                f"{method} failed: {message}",
                error_class=classify_json_rpc_error(code, message),
                provider=self.name,
                method=method,
            )

        if "result" not in response:
            raise RpcError(
                f"{method} returned neither result nor error",
                error_class=RpcErrorClass.MALFORMED_RESPONSE,
                provider=self.name,
                method=method,
            )
        return response["result"]

    @staticmethod
    def _block_param(block: int | BlockTag) -> str:
        return hex(block) if isinstance(block, int) else str(block)

    # ----------------------------------------------------------------- calls --
    async def block_number(self, tag: BlockTag = "latest") -> int:
        if tag == "latest":
            result = await self._request("eth_blockNumber", [])
            return int(result, 16)
        # `safe` / `finalized` have no dedicated method: they are block
        # parameters. TZ 5.4 warns that provider support for them varies, and a
        # provider that does not implement a tag answers with a null result
        # rather than an error — which would otherwise silently read as "block
        # zero" and rewind the watcher to genesis.
        block = await self._request("eth_getBlockByNumber", [tag, False])
        if not isinstance(block, dict) or block.get("number") is None:
            raise RpcError(
                f"provider does not serve the '{tag}' block tag",
                error_class=RpcErrorClass.MALFORMED_RESPONSE,
                provider=self.name,
                method="eth_getBlockByNumber",
            )
        return int(block["number"], 16)

    async def get_block(
        self, block: int | BlockTag, *, full_transactions: bool = False
    ) -> dict[str, Any]:
        result = await self._request(
            "eth_getBlockByNumber", [self._block_param(block), full_transactions]
        )
        if result is None:
            # A height the node does not have. Not an outage: during a reorg the
            # canonical tip legitimately moves below where we were reading.
            raise RpcError(
                f"block {block} unknown to provider",
                error_class=RpcErrorClass.MALFORMED_RESPONSE,
                provider=self.name,
                method="eth_getBlockByNumber",
            )
        if not isinstance(result, dict) or any(f not in result for f in REQUIRED_BLOCK_FIELDS):
            raise RpcError(
                f"block {block} is missing header fields required for reorg checks",
                error_class=RpcErrorClass.MALFORMED_RESPONSE,
                provider=self.name,
                method="eth_getBlockByNumber",
            )
        return result

    async def get_logs(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        result = await self._request("eth_getLogs", [params])
        if not isinstance(result, list):
            raise RpcError(
                "eth_getLogs did not return a list",
                error_class=RpcErrorClass.MALFORMED_RESPONSE,
                provider=self.name,
                method="eth_getLogs",
            )
        return result

    async def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        result = await self._request("eth_getTransactionReceipt", [tx_hash])
        if result is None:
            return None
        if not isinstance(result, dict):
            raise RpcError(
                "eth_getTransactionReceipt returned a non-object",
                error_class=RpcErrorClass.MALFORMED_RESPONSE,
                provider=self.name,
                method="eth_getTransactionReceipt",
            )
        return result

    async def aclose(self) -> None:
        disconnect = getattr(self._provider, "disconnect", None)
        if disconnect is None:
            return
        result = disconnect()
        if asyncio.iscoroutine(result):
            await result
