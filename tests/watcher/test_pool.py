"""Provider pool: failover, backoff, budget, and chunked `eth_getLogs` (TZ 5.6).

Two requirements from TZ section 8 are pinned here:

* "провайдер с ошибками выводится из ротации и возвращается после остывания" —
  the pool half of it (the breaker half is in `test_breaker.py`);
* "чанкование фильтра по адресам не теряет платежи на границе чанка" — the
  boundary case, which is the bug that would otherwise be found by a customer
  whose payment landed on address 101 of 150.

No sleeping and no randomness: both the sleeper and the RNG are injected, so the
backoff is asserted rather than waited out.
"""

from __future__ import annotations

import asyncio
import random

import pytest

from tests.watcher.fakes import FakeRpcClient, ScriptedRpcClient, make_log
from watcher.detect.erc20 import TRANSFER_TOPIC0, address_to_topic
from watcher.rpc.breaker import BreakerPolicy, BreakerState, CircuitBreaker, RequestBudget
from watcher.rpc.client import ProviderSlot
from watcher.rpc.errors import RpcError, RpcErrorClass
from watcher.rpc.pool import (
    AllProvidersUnavailable,
    ChunkPolicy,
    RetryPolicy,
    RpcPool,
    chunk_ranges,
    chunk_sequence,
)

CHAIN_ID = 8453
USDC = "0x1111111111111111111111111111111111110001"


class _FakeClock:
    """Monotonic clock that only moves when a test says so."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class RecordingSleeper:
    """Captures backoff delays instead of waiting them out."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


def slot(client, *, failure_threshold: int = 3, limit: int | None = None) -> ProviderSlot:
    return ProviderSlot(
        client=client,
        breaker=CircuitBreaker(client.name, BreakerPolicy(failure_threshold=failure_threshold)),
        budget=RequestBudget(client.name, limit),
    )


def build_pool(*slots, sleeper=None, retry=None, chunks=None) -> RpcPool:
    return RpcPool(
        CHAIN_ID,
        list(slots),
        retry=retry or RetryPolicy(max_attempts_per_provider=2, base_delay_seconds=0.25),
        chunks=chunks,
        rng=random.Random(1234),
        sleep=sleeper or RecordingSleeper(),
    )


# ---------------------------------------------------------------------------
# Rotation and failover
# ---------------------------------------------------------------------------


def test_first_healthy_provider_answers_and_the_others_are_not_touched() -> None:
    primary = ScriptedRpcClient("alchemy", [100])
    secondary = ScriptedRpcClient("quicknode", [999])
    pool = build_pool(slot(primary), slot(secondary))

    assert asyncio.run(pool.block_number()) == 100
    assert secondary.calls == 0, "a working primary must not cost a second request"


def test_failover_moves_to_the_next_provider() -> None:
    down = ScriptedRpcClient(
        "alchemy",
        [RpcError("connection reset", error_class=RpcErrorClass.TRANSPORT, provider="alchemy")],
    )
    up = ScriptedRpcClient("quicknode", [4242])
    pool = build_pool(slot(down), slot(up))

    assert asyncio.run(pool.block_number()) == 4242


def test_every_provider_failing_raises_a_named_error_listing_who_was_tried() -> None:
    """`no_provider_available` means "slow down", not "the chain is gone"."""
    clients = [
        ScriptedRpcClient(
            name,
            [RpcError("boom", error_class=RpcErrorClass.SERVER_ERROR, provider=name)],
        )
        for name in ("alchemy", "quicknode", "ankr")
    ]
    pool = build_pool(*(slot(c) for c in clients))

    with pytest.raises(AllProvidersUnavailable) as excinfo:
        asyncio.run(pool.block_number())

    assert excinfo.value.error_class == RpcErrorClass.NO_PROVIDER
    message = str(excinfo.value)
    for name in ("alchemy", "quicknode", "ankr"):
        assert name in message


def test_retryable_failure_is_retried_against_the_same_provider_first() -> None:
    """Two attempts, then move on — insisting is more expensive than rotating."""
    flaky = ScriptedRpcClient(
        "alchemy",
        [
            RpcError("timeout", error_class=RpcErrorClass.TIMEOUT, provider="alchemy"),
            77,
        ],
    )
    sleeper = RecordingSleeper()
    pool = build_pool(slot(flaky), sleeper=sleeper)

    assert asyncio.run(pool.block_number()) == 77
    assert flaky.calls == 2
    assert len(sleeper.delays) == 1, "a retry must back off before trying again"


def test_backoff_uses_full_jitter_inside_the_computed_ceiling() -> None:
    """`uniform(0, min(cap, base * 2**attempt))`, not a fixed delay.

    A deterministic backoff synchronises every retry in the process onto the
    same instants, which is exactly when a recovering provider is least able to
    answer.
    """
    retry = RetryPolicy(max_attempts_per_provider=3, base_delay_seconds=0.5, max_delay_seconds=8.0)
    rng = random.Random(7)
    for attempt in range(3):
        ceiling = min(0.5 * (2**attempt), 8.0)
        delay = retry.delay_for(attempt, RpcErrorClass.TIMEOUT, rng)
        assert 0.0 <= delay <= ceiling


def test_rate_limited_backs_off_harder_than_a_plain_timeout() -> None:
    retry = RetryPolicy(base_delay_seconds=1.0, max_delay_seconds=100.0)
    rng = random.Random(0)
    timeout_ceiling = max(
        retry.delay_for(0, RpcErrorClass.TIMEOUT, random.Random(i)) for i in range(200)
    )
    limited_ceiling = max(
        retry.delay_for(0, RpcErrorClass.RATE_LIMITED, random.Random(i)) for i in range(200)
    )
    assert limited_ceiling > timeout_ceiling
    assert rng is not None  # keeps the fixture honest about determinism


def test_our_own_bad_request_is_not_retried_and_not_failed_over() -> None:
    """`invalid_request` is a bug in this codebase.

    Retrying it across three providers turns one bug into triple the error rate
    and buries it in noise.
    """
    broken = ScriptedRpcClient(
        "alchemy",
        [RpcError("invalid params", error_class=RpcErrorClass.INVALID_REQUEST, provider="alchemy")],
    )
    spare = ScriptedRpcClient("quicknode", [1])
    pool = build_pool(slot(broken), slot(spare))

    with pytest.raises(RpcError) as excinfo:
        asyncio.run(pool.block_number())
    assert excinfo.value.error_class == RpcErrorClass.INVALID_REQUEST
    assert broken.calls == 1
    assert spare.calls == 0


def test_a_failing_provider_is_dropped_from_rotation_once_its_breaker_opens() -> None:
    """TZ section 8: "провайдер с ошибками выводится из ротации"."""
    bad = ScriptedRpcClient(
        "alchemy",
        [RpcError("down", error_class=RpcErrorClass.SERVER_ERROR, provider="alchemy")],
    )
    good = ScriptedRpcClient("quicknode", [5])
    bad_slot = slot(bad, failure_threshold=2)
    pool = build_pool(bad_slot, slot(good))

    for _ in range(3):
        asyncio.run(pool.block_number())

    assert bad_slot.breaker.state == BreakerState.OPEN
    calls_after_open = bad.calls
    asyncio.run(pool.block_number())
    assert bad.calls == calls_after_open, "an open breaker must cost zero requests"


def test_budget_exhaustion_does_not_strand_a_half_open_breaker() -> None:
    """Regression: the budget check must come before `breaker.allow()`.

    `allow()` hands out the single half-open trial permit and latches it until a
    result is recorded. If the budget check ran second and refused, that permit
    would be consumed by a request that was never made and never recorded, and
    the provider would sit in half-open rejecting everything forever — removed
    from the rotation permanently by a transient budget window.
    """
    clock = _FakeClock()
    client = ScriptedRpcClient("alchemy", [1])
    provider = ProviderSlot(
        client=client,
        breaker=CircuitBreaker(
            "alchemy", BreakerPolicy(failure_threshold=1, cooldown_seconds=10.0), clock=clock
        ),
        budget=RequestBudget("alchemy", limit=1, clock=clock),
    )
    pool = build_pool(provider)

    # Put the breaker into half-open (cooldown elapsed) with the budget already
    # spent — the exact overlap where the ordering matters.
    provider.breaker.record_failure()
    clock.advance(11.0)
    assert provider.breaker.state == BreakerState.HALF_OPEN
    assert provider.budget.try_spend() is True  # spends the only unit

    with pytest.raises(AllProvidersUnavailable) as excinfo:
        asyncio.run(pool.block_number())
    assert excinfo.value.__cause__ is not None
    assert excinfo.value.__cause__.error_class == RpcErrorClass.BUDGET_EXHAUSTED
    assert client.calls == 0, "the request was never made"

    # The assertion that catches the regression: the trial permit was never
    # handed out, so the provider is still probeable. With the checks in the
    # wrong order this is False and the provider is stranded for good.
    assert provider.breaker.state == BreakerState.HALF_OPEN
    assert provider.breaker.allow() is True


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------


def test_chunk_ranges_partition_the_span_without_gaps_or_overlap() -> None:
    covered: list[int] = []
    for start, end in chunk_ranges(100, 250, 40):
        covered.extend(range(start, end + 1))
    assert covered == list(range(100, 251))


def test_chunk_sequence_preserves_priority_order() -> None:
    """Order carries meaning: funded addresses are at the front (TZ 5.8/T5.6)."""
    items = list(range(10))
    assert [list(c) for c in chunk_sequence(items, 4)] == [
        [0, 1, 2, 3],
        [4, 5, 6, 7],
        [8, 9],
    ]


def test_chunking_addresses_does_not_lose_a_payment_on_a_chunk_boundary() -> None:
    """TZ section 8, verbatim: "чанкование фильтра по адресам не теряет платежи
    на границе чанка".

    150 watched addresses, a chunk size of 100, and the payment lands on the
    address that sits exactly on the boundary — index 99 (last of chunk one) and
    index 100 (first of chunk two) are both checked, because an off-by-one in
    either direction only shows up on one of them.
    """
    addresses = [f"0x{i:040x}" for i in range(1, 151)]

    for boundary_index in (99, 100):
        target = addresses[boundary_index]
        log = make_log(
            contract=USDC,
            to_address=target,
            amount=1_000_000,
            block_number=500,
            block_hash="0x" + "ab" * 32,
            tx_hash="0x" + f"{boundary_index:064x}"[:64],
            log_index=0,
        )
        client = FakeRpcClient("alchemy", logs=[log])
        pool = build_pool(slot(client), chunks=ChunkPolicy(max_block_span=50, max_addresses=100))

        found = asyncio.run(
            pool.get_logs_chunked(
                from_block=500,
                to_block=500,
                addresses=[USDC],
                topics=[TRANSFER_TOPIC0, None],
                address_topics=[address_to_topic(a) for a in addresses],
            )
        )

        assert len(found) == 1, f"payment on boundary address #{boundary_index} was lost"
        assert len(client.log_calls) == 2, "150 addresses at 100 per chunk is two requests"


def test_block_span_is_chunked_rather_than_sent_as_one_wide_filter() -> None:
    client = FakeRpcClient("alchemy", logs=[])
    pool = build_pool(slot(client), chunks=ChunkPolicy(max_block_span=25, max_addresses=100))

    asyncio.run(
        pool.get_logs_chunked(
            from_block=1000,
            to_block=1099,
            addresses=[USDC],
            topics=[TRANSFER_TOPIC0, None],
            address_topics=[address_to_topic("0x" + "01" * 20)],
        )
    )

    assert len(client.log_calls) == 4
    spans = [
        (int(call["fromBlock"], 16), int(call["toBlock"], 16)) for call in client.log_calls
    ]
    assert spans == [(1000, 1024), (1025, 1049), (1050, 1074), (1075, 1099)]


def test_range_too_large_halves_the_span_instead_of_failing_over() -> None:
    """All three providers cap `eth_getLogs`; failing over spends three requests
    to learn one fact. Splitting is the only response that makes progress."""

    class NarrowClient(FakeRpcClient):
        """Refuses any filter wider than two blocks, the way a provider does."""

        async def get_logs(self, params):
            span = int(params["toBlock"], 16) - int(params["fromBlock"], 16) + 1
            if span > 2:
                self.log_calls.append(params)
                raise RpcError(
                    "query returned more than 10000 results",
                    error_class=RpcErrorClass.RANGE_TOO_LARGE,
                    provider=self.name,
                )
            return await super().get_logs(params)

    payload = make_log(
        contract=USDC,
        to_address="0x" + "01" * 20,
        amount=5,
        block_number=7,
        block_hash="0x" + "ab" * 32,
        tx_hash="0x" + "cd" * 32,
        log_index=0,
    )
    narrow = NarrowClient("alchemy", logs=[payload])
    spare = ScriptedRpcClient("quicknode", [[]])
    pool = build_pool(
        slot(narrow), slot(spare), chunks=ChunkPolicy(max_block_span=8, max_addresses=100)
    )

    found = asyncio.run(
        pool.get_logs_chunked(
            from_block=1,
            to_block=8,
            addresses=[USDC],
            topics=[TRANSFER_TOPIC0, None],
            address_topics=[address_to_topic("0x" + "01" * 20)],
        )
    )

    assert len(found) == 1, "splitting must still find the payment"
    assert spare.calls == 0, "range_too_large must never trigger failover"


# ---------------------------------------------------------------------------
# Cross-provider agreement (TZ 5.6)
# ---------------------------------------------------------------------------


def test_disagreement_between_providers_is_reported() -> None:
    """TZ 5.6: "расхождение между провайдерами — это сигнал, а не шум"."""
    from tests.watcher.fakes import make_block

    a = FakeRpcClient(
        "alchemy",
        blocks={9: make_block(9, block_hash="0x" + "aa" * 32, parent_hash="0x" + "00" * 32)},
    )
    b = FakeRpcClient(
        "quicknode",
        blocks={9: make_block(9, block_hash="0x" + "bb" * 32, parent_hash="0x" + "00" * 32)},
    )
    pool = build_pool(slot(a), slot(b))

    agreed, answers = asyncio.run(pool.block_hash_agreement(9))
    assert agreed is False
    assert set(answers) == {"alchemy", "quicknode"}


def test_a_silent_provider_is_not_counted_as_disagreement() -> None:
    """Silence is not a contradiction — otherwise every outage looks like a fork."""
    from tests.watcher.fakes import make_block

    a = FakeRpcClient(
        "alchemy",
        blocks={9: make_block(9, block_hash="0x" + "aa" * 32, parent_hash="0x" + "00" * 32)},
    )
    down = ScriptedRpcClient(
        "ankr", [RpcError("down", error_class=RpcErrorClass.TRANSPORT, provider="ankr")]
    )
    pool = build_pool(slot(a), slot(down))

    agreed, answers = asyncio.run(pool.block_hash_agreement(9))
    assert agreed is True
    assert answers["ankr"] is None
