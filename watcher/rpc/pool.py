"""The provider pool: rotation, backoff, budget, and chunked `eth_getLogs` (TZ 5.6).

Three providers per chain in a fixed rotation. Every request walks the rotation
until one provider answers or all of them refuse; within a provider, retryable
failures get a bounded number of attempts with exponential backoff and full
jitter.

Three decisions in here are worth reading before changing anything.

**Backoff uses full jitter, not "delay ± 10%".** `sleep(random(0, 2**n * base))`
is the AWS formulation, and the reason it matters here is that a watcher with
three providers and a retry loop is a small thundering herd of one: after a
provider-wide blip, a deterministic backoff synchronises every retry onto the
same instants, which is precisely when the provider is least able to answer.
The RNG is injected so the tests can pin the delays.

**`range_too_large` splits, it never fails over.** All three providers cap
`eth_getLogs`; a filter too wide for one is too wide for the next, so failing
over spends three requests to learn one fact. `get_transfer_logs` halves the
block span, and when the span is already one block it halves the *address*
group instead — a single block can exceed a response cap purely by having too
many matching addresses in the filter, and no amount of block splitting fixes
that.

**Chunk sizes are configuration, not constants.** TZ 5.2 says the thresholds
"подбираются под конкретного провайдера и выносятся в конфиг, а не в код", and
:class:`ChunkPolicy` is that config object. The adaptive halving above sits on
top: the configured value is the starting point, not a guarantee.

Cross-provider agreement (`block_hash_agreement`) implements the payment-specific
part of TZ 5.6 — before crediting a large amount, ask a second provider whether
the block exists at all. The watcher only *measures* the disagreement and
records it; refusing to credit is the settler's decision, because it is a money
decision.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from watcher import metrics
from watcher.rpc.breaker import STATE_TO_METRIC
from watcher.rpc.client import BlockTag, ProviderSlot
from watcher.rpc.errors import RpcError, RpcErrorClass

__all__ = ["RetryPolicy", "ChunkPolicy", "RpcPool", "AllProvidersUnavailable"]

Sleeper = Callable[[float], Awaitable[None]]


class AllProvidersUnavailable(RpcError):
    """Every slot refused or failed. Carries the last real error as `__cause__`."""

    def __init__(self, method: str, chain_id: int, tried: Sequence[str]) -> None:
        super().__init__(
            f"no provider could serve {method} on chain {chain_id} "
            f"(tried: {', '.join(tried) or 'none'})",
            error_class=RpcErrorClass.NO_PROVIDER,
            method=method,
        )


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Per-provider retry behaviour."""

    #: Attempts against one provider before moving to the next. Two, not five:
    #: with three providers in the rotation, moving on is cheaper than insisting.
    max_attempts_per_provider: int = 2
    base_delay_seconds: float = 0.25
    max_delay_seconds: float = 8.0
    #: Multiplier applied on top of the computed delay when the provider
    #: explicitly said "you are going too fast".
    rate_limit_delay_multiplier: float = 3.0

    def delay_for(self, attempt: int, error_class: str, rng: random.Random) -> float:
        """Full jitter: uniform(0, min(cap, base * 2**attempt))."""
        ceiling = min(self.base_delay_seconds * (2**attempt), self.max_delay_seconds)
        if error_class == RpcErrorClass.RATE_LIMITED:
            ceiling = min(ceiling * self.rate_limit_delay_multiplier, self.max_delay_seconds)
        return rng.uniform(0.0, ceiling)


@dataclass(frozen=True, slots=True)
class ChunkPolicy:
    """How wide a single `eth_getLogs` may be before it is split (TZ 5.2)."""

    #: Blocks per request. Providers publish very different caps for this and
    #: change them without notice, hence config + adaptive halving.
    max_block_span: int = 500
    #: Addresses per `topics[2]` array. The array gives OR semantics, so one
    #: request covers a batch — until the provider's cap on the array size.
    max_addresses: int = 100
    #: Floor for the halving loop. Below one block there is nothing to split.
    min_block_span: int = 1
    #: Floor for address-group halving; a group of one address that still
    #: overflows means the provider cannot serve us at all and the error is
    #: propagated rather than silently swallowed.
    min_addresses: int = 1

    def __post_init__(self) -> None:
        if self.max_block_span < 1:
            raise ValueError("max_block_span must be >= 1")
        if self.max_addresses < 1:
            raise ValueError("max_addresses must be >= 1")


def chunk_ranges(from_block: int, to_block: int, span: int) -> Iterator[tuple[int, int]]:
    """Inclusive [from, to] split into inclusive spans of at most `span` blocks."""
    if to_block < from_block:
        return
    span = max(span, 1)
    start = from_block
    while start <= to_block:
        end = min(start + span - 1, to_block)
        yield start, end
        start = end + 1


def chunk_sequence(items: Sequence[Any], size: int) -> Iterator[Sequence[Any]]:
    """Split a sequence into consecutive groups of at most `size`.

    Order is preserved, which is what makes the priority ordering of TZ 5.8/T5.6
    meaningful: the addresses that already hold money are at the front of the
    list and therefore land in the first chunks.
    """
    size = max(size, 1)
    for offset in range(0, len(items), size):
        yield items[offset : offset + size]


class RpcPool:
    """Failover across an ordered list of providers for one chain."""

    def __init__(
        self,
        chain_id: int,
        slots: Sequence[ProviderSlot],
        *,
        retry: RetryPolicy | None = None,
        chunks: ChunkPolicy | None = None,
        rng: random.Random | None = None,
        sleep: Sleeper | None = None,
    ) -> None:
        if not slots:
            raise ValueError("an RpcPool needs at least one provider slot")
        self.chain_id = chain_id
        self.slots = list(slots)
        self.retry = retry or RetryPolicy()
        self.chunks = chunks or ChunkPolicy()
        self._rng = rng or random.Random()
        self._sleep: Sleeper = sleep or asyncio.sleep
        self._chain_label = str(chain_id)

    # ------------------------------------------------------------ internals --
    def _record_attempt(self, slot: ProviderSlot, method: str) -> None:
        metrics.rpc_requests_total.labels(provider=slot.name, method=method).inc()

    def _record_error(self, slot: ProviderSlot, exc: RpcError) -> None:
        metrics.rpc_errors_total.labels(provider=slot.name, chain=self._chain_label).inc()
        metrics.breaker_state.labels(provider=slot.name, chain=self._chain_label).set(
            STATE_TO_METRIC.get(slot.breaker.state, 0.0)
        )

    async def _call_slot(
        self,
        slot: ProviderSlot,
        method: str,
        operation: Callable[[ProviderSlot], Awaitable[Any]],
    ) -> Any:
        """Run one operation against one provider, with retries and backoff.

        Raises the last :class:`RpcError` so the caller can decide about failover.
        """
        last: RpcError | None = None
        for attempt in range(self.retry.max_attempts_per_provider):
            # Budget first, breaker second, and the order is load-bearing.
            # `CircuitBreaker.allow()` has a side effect in the half-open state:
            # it hands out the single trial permit and latches it until the
            # result is recorded. If the budget check came second and failed,
            # that permit would be consumed by a request that was never made and
            # never recorded, and the breaker would sit in half-open refusing
            # every subsequent call forever — a provider permanently removed
            # from the rotation by a transient budget window. Asking the
            # side-effect-free guard first makes the leak impossible rather than
            # merely unlikely.
            if not slot.budget.try_spend():
                raise RpcError(
                    f"request budget exhausted for {slot.name}",
                    error_class=RpcErrorClass.BUDGET_EXHAUSTED,
                    provider=slot.name,
                    method=method,
                )
            if not slot.breaker.allow():
                raise RpcError(
                    f"circuit open for {slot.name}",
                    error_class=RpcErrorClass.CIRCUIT_OPEN,
                    provider=slot.name,
                    method=method,
                )

            self._record_attempt(slot, method)
            try:
                result = await operation(slot)
            except RpcError as exc:
                last = exc
                if exc.counts_as_provider_failure:
                    slot.breaker.record_failure()
                self._record_error(slot, exc)

                # Our own bug, or a filter the provider will never accept: both
                # are answers, not outages, and both are useless to retry here.
                if exc.error_class == RpcErrorClass.INVALID_REQUEST or exc.should_split_range:
                    raise
                if not exc.retryable or attempt == self.retry.max_attempts_per_provider - 1:
                    raise
                delay = exc.retry_after or self.retry.delay_for(attempt, exc.error_class, self._rng)
                await self._sleep(delay)
            else:
                slot.breaker.record_success()
                metrics.breaker_state.labels(
                    provider=slot.name, chain=self._chain_label
                ).set(STATE_TO_METRIC[slot.breaker.state])
                return result

        raise last if last is not None else RpcError(  # pragma: no cover - unreachable
            f"{method} exhausted retries without an error", error_class=RpcErrorClass.SERVER_ERROR
        )

    async def _run(
        self, method: str, operation: Callable[[ProviderSlot], Awaitable[Any]]
    ) -> Any:
        """Walk the rotation until somebody answers."""
        tried: list[str] = []
        last: RpcError | None = None
        for slot in self.slots:
            tried.append(slot.name)
            try:
                return await self._call_slot(slot, method, operation)
            except RpcError as exc:
                last = exc
                if not exc.should_failover:
                    # `range_too_large` and `invalid_request` end the walk: the
                    # next provider would give the same answer.
                    raise
        failure = AllProvidersUnavailable(method, self.chain_id, tried)
        raise failure from last

    # -------------------------------------------------------------- queries --
    async def block_number(self, tag: BlockTag = "latest") -> int:
        return int(await self._run("eth_blockNumber", lambda s: s.client.block_number(tag)))

    async def get_block(
        self, block: int | BlockTag, *, full_transactions: bool = False
    ) -> dict[str, Any]:
        # Annotated intermediate rather than a bare `return await`: `_run` is
        # deliberately `Any` (it forwards whatever the operation returns), and
        # under mypy --strict an `Any` crossing a typed boundary is exactly what
        # `no-any-return` exists to catch. Naming the type here is where the
        # provider's untyped JSON becomes this project's typed value.
        result: dict[str, Any] = await self._run(
            "eth_getBlockByNumber",
            lambda s: s.client.get_block(block, full_transactions=full_transactions),
        )
        return result

    async def get_logs(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = await self._run(
            "eth_getLogs", lambda s: s.client.get_logs(params)
        )
        return result

    async def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        result: dict[str, Any] | None = await self._run(
            "eth_getTransactionReceipt", lambda s: s.client.get_transaction_receipt(tx_hash)
        )
        return result

    # ------------------------------------------------------------- balances --
    #
    # Read-only, and used only by the owner-facing reports of TZ 3.4
    # (`/reconcile`, `/sweeplist`) through `settler.admin.balances`. They go
    # through `_run` like everything else, which is the whole reason they are
    # here rather than in a second client: the rotation, the circuit breaker,
    # the backoff and the request budget of TZ 5.6 apply to a reconcile sweep
    # exactly as they apply to indexing. A reconcile that hammered a rate-limited
    # provider outside the budget would take the watcher down with it.

    async def get_balance(self, address: str, *, block: int | BlockTag = "latest") -> int:
        return int(
            await self._run("eth_getBalance", lambda s: s.client.get_balance(address, block))
        )

    async def call(self, params: dict[str, Any], *, block: int | BlockTag = "latest") -> str:
        return str(await self._run("eth_call", lambda s: s.client.call(params, block)))

    # ---------------------------------------------------------- chunked logs --
    async def get_logs_chunked(
        self,
        *,
        from_block: int,
        to_block: int,
        addresses: Sequence[str] | None,
        topics: Sequence[Any],
        address_topics: Sequence[str],
    ) -> list[dict[str, Any]]:
        """`eth_getLogs` over a block range and a batch of recipient addresses.

        `addresses` is the contract filter (which token contracts to listen to);
        `address_topics` is the padded receive-address list that goes into
        `topics[2]`, where an array means OR (TZ 5.2). `topics` carries the
        leading positions, normally `[TRANSFER_TOPIC0, None]`.

        Both axes are chunked, and both halve on `range_too_large`. Results are
        concatenated in request order; de-duplication is not needed because the
        chunks partition the space — a log belongs to exactly one block range and
        its recipient belongs to exactly one address group.
        """
        collected: list[dict[str, Any]] = []
        for group in chunk_sequence(list(address_topics), self.chunks.max_addresses):
            for start, end in chunk_ranges(from_block, to_block, self.chunks.max_block_span):
                collected.extend(
                    await self._get_logs_adaptive(
                        from_block=start,
                        to_block=end,
                        addresses=addresses,
                        topics=list(topics),
                        address_topics=list(group),
                    )
                )
        return collected

    async def _get_logs_adaptive(
        self,
        *,
        from_block: int,
        to_block: int,
        addresses: Sequence[str] | None,
        topics: list[Any],
        address_topics: list[str],
    ) -> list[dict[str, Any]]:
        """One chunk, halving on `range_too_large` until it fits or cannot shrink."""
        params: dict[str, Any] = {
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
            "topics": [*topics, address_topics],
        }
        if addresses:
            params["address"] = list(addresses)

        try:
            return await self.get_logs(params)
        except RpcError as exc:
            if not exc.should_split_range:
                raise

            span = to_block - from_block + 1
            if span > self.chunks.min_block_span:
                middle = from_block + span // 2 - 1
                left = await self._get_logs_adaptive(
                    from_block=from_block,
                    to_block=middle,
                    addresses=addresses,
                    topics=topics,
                    address_topics=address_topics,
                )
                right = await self._get_logs_adaptive(
                    from_block=middle + 1,
                    to_block=to_block,
                    addresses=addresses,
                    topics=topics,
                    address_topics=address_topics,
                )
                return left + right

            # One block that still overflows: the filter is too wide across the
            # address axis, not the block axis.
            if len(address_topics) > self.chunks.min_addresses:
                half = len(address_topics) // 2
                left = await self._get_logs_adaptive(
                    from_block=from_block,
                    to_block=to_block,
                    addresses=addresses,
                    topics=topics,
                    address_topics=address_topics[:half],
                )
                right = await self._get_logs_adaptive(
                    from_block=from_block,
                    to_block=to_block,
                    addresses=addresses,
                    topics=topics,
                    address_topics=address_topics[half:],
                )
                return left + right

            # Single block, single address, still refused. Nothing left to split;
            # this is a provider limitation the operator has to know about, so it
            # propagates instead of being swallowed into a silent gap in
            # detection — a lost payment is worse than a loud failure.
            raise

    # -------------------------------------------------- cross-provider check --
    async def block_hash_agreement(self, number: int) -> tuple[bool, dict[str, str | None]]:
        """Ask every healthy provider for the same height and compare hashes.

        TZ 5.6: "расхождение между провайдерами — это сигнал, а не шум". Returns
        `(agreed, {provider: hash})`; a provider that fails or is circuit-broken
        contributes `None` and is not counted as disagreement — silence is not a
        contradiction.

        Only *measures*. Whether a disagreement blocks a credit is a money
        decision and belongs to the settler (TZ section 4).
        """
        answers: dict[str, str | None] = {}
        for slot in self.slots:
            try:
                block = await self._call_slot(
                    slot,
                    "eth_getBlockByNumber",
                    # `number` is a parameter of this method and never changes
                    # inside the loop, so the usual late-binding default-argument
                    # guard is unnecessary here — and it cost mypy the ability to
                    # infer the lambda's type.
                    lambda s: s.client.get_block(number, full_transactions=False),
                )
            except RpcError:
                answers[slot.name] = None
                continue
            raw_hash = block.get("hash") if isinstance(block, dict) else None
            answers[slot.name] = str(raw_hash).lower() if raw_hash else None

        seen = {value for value in answers.values() if value}
        agreed = len(seen) <= 1
        if not agreed:
            metrics.provider_disagreement_total.labels(chain=self._chain_label).inc()
        return agreed, answers

    # ------------------------------------------------------------- lifecycle --
    async def aclose(self) -> None:
        for slot in self.slots:
            await slot.client.aclose()

    async def __aenter__(self) -> RpcPool:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    def provider_names(self) -> Iterable[str]:
        return (slot.name for slot in self.slots)
