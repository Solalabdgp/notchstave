"""Circuit breaker and request budget (TZ 5.6, TZ section 8 "Пул провайдеров").

The requirement in TZ section 8 is one line — "провайдер с ошибками выводится из
ротации и возвращается после остывания" — and it contains two claims that fail
independently, so they are tested separately: removal on failure, and *return*
after the cooldown. A breaker that opens and never closes is the more dangerous
bug of the two, because it looks like resilience right up to the moment the
watcher has no providers left.

Time is injected everywhere. A test that proves a 30-second cooldown by sleeping
for 30 seconds is a test nobody runs.
"""

from __future__ import annotations

import pytest

from watcher.rpc.breaker import (
    STATE_TO_METRIC,
    BreakerPolicy,
    BreakerState,
    CircuitBreaker,
    RequestBudget,
)


class FakeClock:
    """A monotonic clock that only moves when a test says so."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


# ---------------------------------------------------------------------------
# The state machine
# ---------------------------------------------------------------------------


def test_starts_closed_and_allows_traffic(clock) -> None:
    breaker = CircuitBreaker("alchemy", clock=clock)
    assert breaker.state == BreakerState.CLOSED
    assert breaker.allow() is True


def test_failures_below_the_threshold_do_not_open(clock) -> None:
    """Two strikes out of three is still a working provider.

    Opening on the first error would take a healthy node out of rotation for a
    single dropped packet, which trades one slow request for thirty seconds of
    reduced redundancy.
    """
    breaker = CircuitBreaker("alchemy", BreakerPolicy(failure_threshold=3), clock=clock)
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state == BreakerState.CLOSED
    assert breaker.allow() is True


def test_threshold_failures_open_the_circuit_and_block_traffic(clock) -> None:
    breaker = CircuitBreaker(
        "alchemy", BreakerPolicy(failure_threshold=3, cooldown_seconds=30.0), clock=clock
    )
    for _ in range(3):
        breaker.record_failure()

    assert breaker.state == BreakerState.OPEN
    assert breaker.allow() is False
    assert breaker.cooldown_remaining == pytest.approx(30.0)


def test_provider_returns_to_rotation_after_the_cooldown(clock) -> None:
    """The half of TZ section 8's requirement that is easy to get wrong."""
    breaker = CircuitBreaker(
        "alchemy", BreakerPolicy(failure_threshold=2, cooldown_seconds=30.0), clock=clock
    )
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.allow() is False

    clock.advance(29.9)
    assert breaker.allow() is False, "cooldown must not expire early"

    clock.advance(0.2)
    assert breaker.state == BreakerState.HALF_OPEN
    assert breaker.allow() is True, "cooldown elapsed: one trial call must be let through"

    breaker.record_success()
    assert breaker.state == BreakerState.CLOSED
    assert breaker.allow() is True


def test_half_open_admits_exactly_one_trial_call(clock) -> None:
    """The point of half-open: probe with one request, not with the full load.

    Letting everything through the moment the cooldown expires is how a
    recovering provider gets knocked straight back over.
    """
    breaker = CircuitBreaker(
        "alchemy", BreakerPolicy(failure_threshold=1, cooldown_seconds=10.0), clock=clock
    )
    breaker.record_failure()
    clock.advance(11.0)

    assert breaker.allow() is True
    assert breaker.allow() is False, "the second concurrent call must not get a permit"


def test_failed_trial_reopens_immediately_without_re_reaching_the_threshold(clock) -> None:
    breaker = CircuitBreaker(
        "alchemy", BreakerPolicy(failure_threshold=3, cooldown_seconds=10.0), clock=clock
    )
    for _ in range(3):
        breaker.record_failure()
    clock.advance(11.0)
    assert breaker.allow() is True  # trial

    breaker.record_failure()
    assert breaker.state == BreakerState.OPEN
    assert breaker.allow() is False


def test_cooldown_grows_with_each_trip_and_is_capped(clock) -> None:
    """A provider down for an hour should not be probed 120 times during it."""
    breaker = CircuitBreaker(
        "ankr",
        BreakerPolicy(
            failure_threshold=1,
            cooldown_seconds=10.0,
            cooldown_backoff_factor=2.0,
            max_cooldown_seconds=45.0,
        ),
        clock=clock,
    )
    observed: list[float] = []
    for _ in range(5):
        breaker.record_failure()
        observed.append(breaker.cooldown_remaining)
        clock.advance(breaker.cooldown_remaining + 0.1)
        breaker.allow()  # consume the trial permit so the next failure is a re-trip

    # approx, not equality: the test's own clock accumulates float error by
    # advancing `remaining + 0.1` five times. The breaker's arithmetic is exact;
    # the measurement is not, and asserting on the measurement to nine decimal
    # places would be testing IEEE 754.
    assert observed[:3] == pytest.approx([10.0, 20.0, 40.0])
    assert observed[3] == pytest.approx(45.0), "cooldown must stop doubling at the cap"
    assert observed[4] == pytest.approx(45.0)


def test_success_forgets_the_trip_history(clock) -> None:
    """After recovery the next outage starts from the short cooldown again.

    Otherwise a provider that has a bad day in the morning is punished with
    five-minute cooldowns for the rest of its life.
    """
    policy = BreakerPolicy(failure_threshold=1, cooldown_seconds=10.0, max_cooldown_seconds=300.0)
    breaker = CircuitBreaker("quicknode", policy, clock=clock)

    breaker.record_failure()
    clock.advance(11.0)
    breaker.allow()
    breaker.record_failure()  # second trip -> 20s
    assert breaker.cooldown_remaining == pytest.approx(20.0)

    clock.advance(21.0)
    breaker.allow()
    breaker.record_success()

    breaker.record_failure()
    assert breaker.cooldown_remaining == pytest.approx(10.0)


def test_state_metric_mapping_covers_every_state() -> None:
    """Grafana cannot chart a string, so the states have numeric twins."""
    assert set(STATE_TO_METRIC) == {
        BreakerState.CLOSED,
        BreakerState.OPEN,
        BreakerState.HALF_OPEN,
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"failure_threshold": 0},
        {"cooldown_seconds": 0},
        {"cooldown_backoff_factor": 0.5},
    ],
)
def test_nonsense_policies_are_rejected_at_construction(kwargs) -> None:
    with pytest.raises(ValueError):
        BreakerPolicy(**kwargs)


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------


def test_budget_stops_a_runaway_loop_within_a_window(clock) -> None:
    budget = RequestBudget("alchemy", limit=3, window_seconds=60.0, clock=clock)
    assert [budget.try_spend() for _ in range(4)] == [True, True, True, False]
    assert budget.remaining == 0


def test_budget_window_rolls(clock) -> None:
    budget = RequestBudget("alchemy", limit=2, window_seconds=60.0, clock=clock)
    budget.try_spend()
    budget.try_spend()
    assert budget.try_spend() is False

    clock.advance(60.1)
    assert budget.try_spend() is True
    assert budget.spent == 1


def test_budget_total_is_monotone_across_windows(clock) -> None:
    """`total` feeds the spend counter; it must not reset with the window."""
    budget = RequestBudget("alchemy", limit=2, window_seconds=10.0, clock=clock)
    budget.try_spend()
    budget.try_spend()
    clock.advance(11.0)
    budget.try_spend()
    assert budget.total == 3
    assert budget.spent == 1


def test_unmetered_budget_never_refuses(clock) -> None:
    """`limit=None` is the local-node setting."""
    budget = RequestBudget("local", limit=None, clock=clock)
    assert all(budget.try_spend() for _ in range(1000))
    assert budget.remaining is None
