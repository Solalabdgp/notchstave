"""The TZ 5.5 policy table, cell by cell, with no database in the way.

TZ 5.5 asks for "матрица кейсов таблицей, по одному тесту на ячейку". That is
what this file is. It tests :func:`settler.policy.classify` directly because the
classification is a pure function of five numbers and a clock reading — running
it through Postgres would make each case slower and would test the plumbing
rather than the policy. The plumbing is tested in ``test_settlement.py``, where
the same outcomes are checked through the database.

Two properties get their own tests below because they are the ones most likely
to be "simplified" by a later reader who has not read the TZ:

* the underpayment tolerance is a **min** of percentage and cap, the
  overpayment tolerance is a **max** of percentage and floor;
* an underpayment beyond tolerance is never auto-credited, in any state.
"""

from __future__ import annotations

import datetime as dt
from decimal import Decimal

import pytest

from settler.policy import DEFAULT_POLICY, MoneyPolicy, Outcome, classify

#: 10 USDC at 1 USD, 6 decimals — the reference invoice for the table.
DUE = Decimal(10_000_000)
DECIMALS = 6
RATE = Decimal(1)

NOW = dt.datetime(2026, 8, 17, 12, 0, tzinfo=dt.UTC)
WINDOW_OPEN = NOW + dt.timedelta(hours=1)
WINDOW_CLOSED = NOW - dt.timedelta(hours=1)

#: min(0.5% of 10 USDC, 1 USD) = min(50_000, 1_000_000) = 50_000 base units.
UNDERPAY_TOLERANCE = Decimal(50_000)
#: max(5% of 10 USDC, 5 USD) = max(500_000, 5_000_000) = 5_000_000 base units.
OVERPAY_TOLERANCE = Decimal(5_000_000)


def decide(total: Decimal | int, *, window_until: dt.datetime = WINDOW_OPEN) -> Outcome:
    return classify(
        due_raw=DUE,
        total_raw=Decimal(total),
        decimals=DECIMALS,
        rate=RATE,
        now=NOW,
        topup_window_until=window_until,
        policy=DEFAULT_POLICY,
    ).outcome


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "total", "window_until", "expected"),
    [
        # TZ 5.3 — nothing creditable has arrived.
        ("nothing arrived", 0, WINDOW_OPEN, Outcome.NO_FUNDS),
        # TZ 5.5.1 — inside the tolerance, both edges.
        ("short by 1 unit", DUE - 1, WINDOW_OPEN, Outcome.UNDERPAID_TOLERATED),
        (
            "short by exactly the tolerance",
            DUE - UNDERPAY_TOLERANCE,
            WINDOW_OPEN,
            Outcome.UNDERPAID_TOLERATED,
        ),
        # TZ 5.5.2 — one base unit past the tolerance, window still open.
        (
            "one unit past tolerance, window open",
            DUE - UNDERPAY_TOLERANCE - 1,
            WINDOW_OPEN,
            Outcome.PARTIALLY_PAID,
        ),
        ("half paid, window open", DUE // 2, WINDOW_OPEN, Outcome.PARTIALLY_PAID),
        # TZ 5.5.3 — the same shortfall after the window closes. Never automatic.
        (
            "one unit past tolerance, window closed",
            DUE - UNDERPAY_TOLERANCE - 1,
            WINDOW_CLOSED,
            Outcome.UNDERPAID_MANUAL_REVIEW,
        ),
        ("half paid, window closed", DUE // 2, WINDOW_CLOSED, Outcome.UNDERPAID_MANUAL_REVIEW),
        # A shortfall inside the tolerance is settled whether the window is open
        # or not: the tolerance absorbs a withdrawal fee, and a fee does not
        # become a debt at midnight.
        (
            "inside tolerance, window closed",
            DUE - UNDERPAY_TOLERANCE,
            WINDOW_CLOSED,
            Outcome.UNDERPAID_TOLERATED,
        ),
        # Exact.
        ("exact", DUE, WINDOW_OPEN, Outcome.PAID),
        # TZ 5.5 overpayment, both edges.
        ("over by 1 unit", DUE + 1, WINDOW_OPEN, Outcome.OVERPAID_CREDITED),
        (
            "over by exactly the tolerance",
            DUE + OVERPAY_TOLERANCE,
            WINDOW_OPEN,
            Outcome.OVERPAID_CREDITED,
        ),
        (
            "one unit past the overpay tolerance",
            DUE + OVERPAY_TOLERANCE + 1,
            WINDOW_OPEN,
            Outcome.OVERPAID_REFUND_PENDING,
        ),
        ("double the bill", DUE * 2, WINDOW_OPEN, Outcome.OVERPAID_REFUND_PENDING),
    ],
)
def test_policy_table(label: str, total: int, window_until: dt.datetime, expected: Outcome) -> None:
    assert decide(total, window_until=window_until) is expected, label


# ---------------------------------------------------------------------------
# The two asymmetries
# ---------------------------------------------------------------------------


def test_underpay_tolerance_is_the_smaller_of_percentage_and_cap() -> None:
    """"0.5% и не более 1 USD в абсолюте, что меньше" (TZ 5.5.1).

    The cap exists so that the tolerance stays an exchange withdrawal fee
    instead of scaling into a discount: 0.5% of a 1000 USDC invoice would be
    5 USD of free product per sale.
    """
    small = Decimal(1_000_000)  # 1 USDC — percentage is the smaller of the two
    large = Decimal(1_000_000_000)  # 1000 USDC — the 1 USD cap is

    assert DEFAULT_POLICY.underpay_tolerance_raw(small, DECIMALS, RATE) == Decimal(5_000)
    assert DEFAULT_POLICY.underpay_tolerance_raw(large, DECIMALS, RATE) == Decimal(1_000_000)

    # The property, not just the two data points: the tolerance never exceeds
    # one dollar however large the invoice gets.
    one_usd_raw = Decimal(1_000_000)
    for due in (Decimal(10**k) for k in range(6, 14)):
        assert DEFAULT_POLICY.underpay_tolerance_raw(due, DECIMALS, RATE) <= one_usd_raw


def test_overpay_tolerance_is_the_larger_of_percentage_and_floor() -> None:
    """"5% или 5 USD, что больше" (TZ 5.5 overpayment).

    The floor exists so that dust does not open a refund case, which is a human
    task with a gas cost attached — the opposite pressure to the underpayment
    side, and the reason the two are not the same expression with a sign flip.
    """
    small = Decimal(1_000_000)  # 1 USDC — the 5 USD floor dominates
    large = Decimal(1_000_000_000)  # 1000 USDC — 5% dominates

    assert DEFAULT_POLICY.overpay_tolerance_raw(small, DECIMALS, RATE) == Decimal(5_000_000)
    assert DEFAULT_POLICY.overpay_tolerance_raw(large, DECIMALS, RATE) == Decimal(50_000_000)

    five_usd_raw = Decimal(5_000_000)
    for due in (Decimal(10**k) for k in range(6, 14)):
        assert DEFAULT_POLICY.overpay_tolerance_raw(due, DECIMALS, RATE) >= five_usd_raw


def test_a_token_payment_is_never_auto_credited() -> None:
    """"Это дыра, через которую платят 1% от цены и получают товар." (TZ 5.5.1)

    One percent of the bill must not settle it in any window state, under any
    tolerance configuration a reasonable operator would choose.
    """
    one_percent = DUE // 100
    assert decide(one_percent, window_until=WINDOW_OPEN) is Outcome.PARTIALLY_PAID
    assert decide(one_percent, window_until=WINDOW_CLOSED) is Outcome.UNDERPAID_MANUAL_REVIEW

    generous = MoneyPolicy(
        version="generous",
        underpay_tolerance_pct=Decimal("0.10"),
        underpay_tolerance_cap_usd=Decimal("100"),
    )
    decision = classify(
        due_raw=DUE,
        total_raw=one_percent,
        decimals=DECIMALS,
        rate=RATE,
        now=NOW,
        topup_window_until=WINDOW_CLOSED,
        policy=generous,
    )
    assert decision.outcome is Outcome.UNDERPAID_MANUAL_REVIEW


# ---------------------------------------------------------------------------
# The numbers carried with the decision
# ---------------------------------------------------------------------------


def test_decision_carries_the_shortfall_the_user_is_told_about() -> None:
    """The message to the buyer must not be recomputed downstream (TZ 5.5.2)."""
    decision = classify(
        due_raw=DUE,
        total_raw=DUE - Decimal(2_000_000),
        decimals=DECIMALS,
        rate=RATE,
        now=NOW,
        topup_window_until=WINDOW_OPEN,
        policy=DEFAULT_POLICY,
    )
    assert decision.outcome is Outcome.PARTIALLY_PAID
    assert decision.delta_raw == Decimal(-2_000_000)
    assert decision.shortfall_raw == Decimal(2_000_000)
    assert decision.excess_raw == Decimal(0)


def test_decision_carries_the_excess_that_becomes_a_refund() -> None:
    decision = classify(
        due_raw=DUE,
        total_raw=DUE + Decimal(9_000_000),
        decimals=DECIMALS,
        rate=RATE,
        now=NOW,
        topup_window_until=WINDOW_OPEN,
        policy=DEFAULT_POLICY,
    )
    assert decision.outcome is Outcome.OVERPAID_REFUND_PENDING
    assert decision.excess_raw == Decimal(9_000_000)
    assert decision.shortfall_raw == Decimal(0)


def test_from_env_with_nothing_set_reproduces_the_defaults() -> None:
    """Regression: a slotted dataclass does not expose its defaults on the class.

    ``MoneyPolicy`` is ``slots=True``, so ``MoneyPolicy.underpay_tolerance_pct``
    is the slot descriptor and not ``Decimal("0.005")``. An earlier version of
    :meth:`MoneyPolicy.from_env` read the fallbacks off the class, which built a
    policy whose thresholds were ``member_descriptor`` objects — and since
    ``settler/main.py`` constructs the production policy with exactly this call,
    every threshold comparison in the running settler would have raised, and
    ``policy_version`` would have been a repr in the audit log.

    The assertion is deliberately on values and types rather than on equality
    with ``DEFAULT_POLICY``: the point is that what comes out is arithmetic, not
    a descriptor that happens to compare equal to another descriptor.
    """
    from_env = MoneyPolicy.from_env(env={})

    assert from_env == DEFAULT_POLICY
    assert isinstance(from_env.version, str)
    for value in (
        from_env.underpay_tolerance_pct,
        from_env.underpay_tolerance_cap_usd,
        from_env.overpay_tolerance_pct,
        from_env.overpay_tolerance_floor_usd,
    ):
        assert isinstance(value, Decimal)

    # The real proof: it can be used to decide something.
    assert from_env.underpay_tolerance_raw(DUE, DECIMALS, RATE) == UNDERPAY_TOLERANCE
    assert from_env.overpay_tolerance_raw(DUE, DECIMALS, RATE) == OVERPAY_TOLERANCE


def test_from_env_reads_overrides() -> None:
    """"Все пороги — конфиг." (TZ 5.5) — and the version travels with them."""
    policy = MoneyPolicy.from_env(
        env={
            "SETTLER_POLICY_VERSION": "2026-09-01.looser",
            "SETTLER_UNDERPAY_TOLERANCE_CAP_USD": "2",
            "SETTLER_OVERPAY_TOLERANCE_FLOOR_USD": "10",
        }
    )

    assert policy.version == "2026-09-01.looser"
    assert policy.underpay_tolerance_cap_usd == Decimal(2)
    assert policy.overpay_tolerance_floor_usd == Decimal(10)
    # Untouched keys keep the defaults rather than becoming None.
    assert policy.underpay_tolerance_pct == DEFAULT_POLICY.underpay_tolerance_pct

    # A 1000 USDC invoice now tolerates 2 USD short instead of 1.
    assert policy.underpay_tolerance_raw(
        Decimal(1_000_000_000), DECIMALS, RATE
    ) == Decimal(2_000_000)


def test_tolerances_follow_the_invoice_rate_not_a_live_quote() -> None:
    """TZ 5.5 rate table: the snapshot is the only rate that may be used.

    At 2000 USD/ETH the one-dollar underpayment cap is 5e14 wei; at 4000 it is
    half that. Both are computed from the invoice's own ``rate_snapshot``, so
    re-running the settler tomorrow cannot change yesterday's verdict.
    """
    eth_decimals = 18
    due = Decimal(10) ** 18  # 1 ETH

    at_2000 = DEFAULT_POLICY.underpay_tolerance_raw(due, eth_decimals, Decimal(2000))
    at_4000 = DEFAULT_POLICY.underpay_tolerance_raw(due, eth_decimals, Decimal(4000))

    assert at_2000 == Decimal(5 * 10**14)
    assert at_4000 == Decimal("2.5e14")
    assert at_4000 * 2 == at_2000
