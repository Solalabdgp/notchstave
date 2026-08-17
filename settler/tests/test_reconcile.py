"""`/reconcile` — the ledger against the chain (TZ 3.4, section 7).

TZ section 7 calls a drift here "самое серьёзное, что может случиться", and TZ
section 13 makes ``notchstave_reconcile_drift_usd = 0`` a release criterion. So
this file checks two things with equal care: that a real discrepancy is found and
raised, and that the *ordinary* states of a payment system — money still
confirming, funds already swept to cold storage — are not reported as
discrepancies. A reconciliation that cries wolf is a reconciliation that gets
muted, and a muted one is worth less than none.

**No network.** TZ section 8: "RPC в тестах мокается сохранёнными ответами.
Никаких сетевых вызовов в CI." Two doubles are used and the choice between them
is deliberate:

* :class:`~settler.admin.balances.StaticBalanceSource` for the accounting cases,
  where the RPC layer is not what is under test;
* the watcher's own :class:`~tests.watcher.fakes.FakeRpcClient` behind a real
  :class:`~watcher.rpc.pool.RpcPool` for the wiring test, which is what proves
  the settler reads balances through the *shared* pool of TZ 5.6 rather than
  through something it invented.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncConnection

from core.db import enums as E
from settler import metrics
from settler.admin.balances import (
    BALANCE_OF_SELECTOR,
    RpcBalanceSource,
    StaticBalanceSource,
    encode_balance_of,
)
from settler.admin.policy import AdminPolicy
from settler.admin.reconcile import UnknownRate, reconcile
from settler.admin.repository import AssetRow
from settler.service import settle_invoice
from settler.tests.conftest import Scenario, World, count, sample_value

USDC = 1_000_000

#: Drift of more than a dollar is an incident; less is dust.
POLICY = AdminPolicy(reconcile_drift_threshold_usd=Decimal("1"))


async def _paid_invoice(
    conn: AsyncConnection, world: World, *, amount: int = 10 * USDC
) -> Scenario:
    """One settled invoice whose money is on a known address."""
    scenario = await world.scenario(amount_due_raw=amount)
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=amount,
        block_number=90,
    )
    assert (await settle_invoice(conn, scenario.invoice_id)).granted
    return scenario


async def test_a_matching_chain_and_ledger_reconcile_clean(
    conn: AsyncConnection, world: World
) -> None:
    scenario = await _paid_invoice(conn, world)
    balances = StaticBalanceSource({(scenario.asset_id, scenario.address): 10 * USDC})

    report = await reconcile(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=balances,
        admin_policy=POLICY,
    )

    assert report.total_expected_raw == Decimal(10 * USDC)
    assert report.total_actual_raw == Decimal(10 * USDC)
    assert report.absolute_drift_raw == 0
    assert report.drifting == ()
    assert not report.alert
    assert report.manual_review_ids == ()
    # A clean run is still a run, and it says so on the record (TZ 5.8/T7).
    assert await count(conn, "audit_log", "action = 'admin.reconcile'") == 1


async def test_money_missing_from_the_chain_is_the_loudest_finding(
    conn: AsyncConnection, world: World
) -> None:
    """The ledger says ten dollars are on an address; the chain says four.

    Whatever the cause — a bug in the settler, a lying provider, a genuine loss —
    the response is identical and is not to adjust the figure: a case is opened,
    the gauge rises, and a human reads an append-only trail.
    """
    scenario = await _paid_invoice(conn, world)
    balances = StaticBalanceSource({(scenario.asset_id, scenario.address): 4 * USDC})

    report = await reconcile(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=balances,
        admin_policy=POLICY,
    )

    assert report.absolute_drift_raw == Decimal(6 * USDC)
    assert report.drift_usd == Decimal(6)
    assert report.alert
    assert len(report.drifting) == 1
    assert report.drifting[0].drift_raw == Decimal(-6 * USDC)
    assert len(report.manual_review_ids) == 1
    assert await count(
        conn, "manual_reviews", "kind = 'reconcile_drift' AND resolved_at IS NULL"
    ) == 1
    assert (
        sample_value(metrics.RECONCILE_DRIFT_USD, chain=str(scenario.chain_id)) == 6.0
    )
    # Nothing in the money tables moved. "Расхождение — сигнал бага, а не повод
    # подправить цифру руками."
    assert await count(conn, "payments", "status = 'credited'") == 1


async def test_unexpected_money_on_the_chain_is_drift_too(
    conn: AsyncConnection, world: World
) -> None:
    """A surplus is as much a bug as a shortfall.

    A ledger that under-counts what is on our addresses means a payment the
    watcher never indexed — i.e. a buyer who paid and was never credited. That it
    is "in our favour" is exactly why it would otherwise go unnoticed.
    """
    scenario = await _paid_invoice(conn, world)
    balances = StaticBalanceSource({(scenario.asset_id, scenario.address): 25 * USDC})

    report = await reconcile(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=balances,
        admin_policy=POLICY,
    )

    assert report.drifting[0].drift_raw == Decimal(15 * USDC)
    assert report.alert


async def test_opposite_drifts_on_two_addresses_do_not_cancel_out(
    conn: AsyncConnection, world: World
) -> None:
    """Two problems, not zero problems.

    Summing signed drift would report a clean reconciliation for an address that
    is six dollars short and another that is six dollars over — the single most
    dangerous false negative this check can produce, because the two are almost
    certainly the same bug moving money between addresses.
    """
    first = await _paid_invoice(conn, world)
    second = await _paid_invoice(conn, world)
    balances = StaticBalanceSource(
        {
            (first.asset_id, first.address): 4 * USDC,
            (second.asset_id, second.address): 16 * USDC,
        }
    )

    report = await reconcile(
        conn,
        chain_id=first.chain_id,
        asset_id=first.asset_id,
        balances=balances,
        admin_policy=POLICY,
    )

    assert report.total_actual_raw == report.total_expected_raw  # nets to zero
    assert report.absolute_drift_raw == Decimal(12 * USDC)
    assert report.alert
    assert len(report.drifting) == 2


async def test_a_swept_address_is_reported_and_not_counted(
    conn: AsyncConnection, world: World
) -> None:
    """The most important false positive to avoid — and the one to avoid hiding.

    After an offline sweep the ledger figure stays and the balance goes to zero.
    That is correct, so it must not raise an alert; but silently dropping such
    addresses from the comparison would blind the check to a theft *from* a swept
    address, so they are named in the report instead.
    """
    scenario = await _paid_invoice(conn, world)
    await world.mark_swept(scenario.address_id)
    balances = StaticBalanceSource({})

    report = await reconcile(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=balances,
        admin_policy=POLICY,
    )

    assert report.checked == ()
    assert len(report.skipped_swept) == 1
    assert report.skipped_swept[0].address == scenario.address
    assert report.skipped_swept[0].expected_raw == Decimal(10 * USDC)
    assert not report.alert
    assert balances.calls == [], "a swept address must not cost an RPC call"


async def test_money_still_confirming_is_not_yet_expected(
    conn: AsyncConnection, world: World
) -> None:
    """``seen`` is not ``confirmed``, and TZ 3.4 says the ledger side is confirmed money.

    A transfer one block old is on the chain and not yet in the expected total.
    The resulting surplus is real drift by the arithmetic — which is why the
    threshold exists, and why the drift is reported rather than defined away.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC, head_block=91)
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=91,
        status=E.PaymentStatus.SEEN,
    )
    balances = StaticBalanceSource({(scenario.asset_id, scenario.address): 10 * USDC})

    report = await reconcile(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=balances,
        admin_policy=POLICY,
    )

    assert report.total_expected_raw == 0
    assert report.absolute_drift_raw == Decimal(10 * USDC)
    assert report.alert


async def test_dust_below_the_threshold_does_not_wake_anybody(
    conn: AsyncConnection, world: World
) -> None:
    scenario = await _paid_invoice(conn, world)
    balances = StaticBalanceSource(
        {(scenario.asset_id, scenario.address): 10 * USDC + 100_000}  # +$0.10
    )

    report = await reconcile(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=balances,
        admin_policy=POLICY,
    )

    assert report.drifting != ()
    assert report.drift_usd == Decimal("0.1")
    assert not report.alert
    assert report.manual_review_ids == ()


async def test_the_report_says_where_its_dollars_came_from(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 5.8/T8 applied to a report: a figure without its rate is not an answer."""
    scenario = await _paid_invoice(conn, world)
    balances = StaticBalanceSource({(scenario.asset_id, scenario.address): 4 * USDC})

    from_snapshot = await reconcile(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=balances,
        admin_policy=POLICY,
    )
    assert from_snapshot.rate_source == "latest_invoice_snapshot"
    assert from_snapshot.rate_used == Decimal(1)

    from_caller = await reconcile(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=balances,
        admin_policy=POLICY,
        rate=Decimal("2"),
    )
    assert from_caller.rate_source == "caller"
    assert from_caller.drift_usd == Decimal(12)


async def test_a_drift_that_cannot_be_priced_is_refused_rather_than_silenced(
    conn: AsyncConnection, world: World
) -> None:
    """Neither 1.0 nor 0.0 is an acceptable default for a rate.

    Defaulting to zero would report no drift and silence the system's most
    serious alert with arithmetic that never happened; defaulting to one would
    report a six-figure drift on a token worth cents. Both are worse than saying
    "pass a rate".
    """
    chain_id = await world.chain()
    asset_id = await world.asset(chain_id, symbol="WETH", decimals=18)
    hd_id = await world.hd_account()
    address_id, address = await world.address(hd_id, index=61)
    await world.payment(
        chain_id=chain_id,
        asset_id=asset_id,
        address_id=address_id,
        invoice_id=None,
        amount_raw=10**18,
        block_number=90,
        status=E.PaymentStatus.CONFIRMED,
        anomaly=E.PaymentAnomaly.UNASSIGNED_PAYMENT,
    )
    balances = StaticBalanceSource({(asset_id, address): 0})

    with pytest.raises(UnknownRate):
        await reconcile(
            conn, chain_id=chain_id, asset_id=asset_id, balances=balances, admin_policy=POLICY
        )


async def test_an_empty_system_reconciles_clean_without_a_rate(
    conn: AsyncConnection, world: World
) -> None:
    """A fresh deployment must not fail its own health check on a missing price."""
    chain_id = await world.chain()
    asset_id = await world.asset(chain_id)

    report = await reconcile(
        conn,
        chain_id=chain_id,
        asset_id=asset_id,
        balances=StaticBalanceSource({}),
        admin_policy=POLICY,
    )

    assert report.checked == ()
    assert report.drift_usd == 0
    assert report.rate_source == "none"
    assert not report.alert


async def test_the_owner_is_told_about_a_drift(conn: AsyncConnection, world: World) -> None:
    scenario = await _paid_invoice(conn, world)
    balances = StaticBalanceSource({(scenario.asset_id, scenario.address): 0})

    report = await reconcile(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=balances,
        admin_policy=POLICY,
        owner_user_id=scenario.user_id,
    )

    assert report.alert
    assert await count(conn, "notifications", "kind = 'reconcile_drift'") == 1


async def test_repeating_the_same_finding_does_not_repeat_the_alarm(
    conn: AsyncConnection, world: World
) -> None:
    """A drift that has not changed is one incident, not one per run."""
    scenario = await _paid_invoice(conn, world)
    balances = StaticBalanceSource({(scenario.asset_id, scenario.address): 0})
    kwargs: dict[str, Any] = {
        "chain_id": scenario.chain_id,
        "asset_id": scenario.asset_id,
        "balances": balances,
        "admin_policy": POLICY,
        "owner_user_id": scenario.user_id,
    }

    await reconcile(conn, **kwargs)
    await reconcile(conn, **kwargs)

    assert await count(conn, "notifications", "kind = 'reconcile_drift'") == 1
    assert await count(conn, "manual_reviews", "kind = 'reconcile_drift'") == 1
    # Both runs are on the record, even though only one alarm was raised.
    assert await count(conn, "audit_log", "action = 'admin.reconcile'") == 2


# ---------------------------------------------------------------------------
# The RPC wiring (TZ 5.6 — one pool, not two)
# ---------------------------------------------------------------------------


def _slot(client: Any) -> Any:
    """One provider slot, wired exactly as ``tests/watcher/test_pool.py`` wires one."""
    from watcher.rpc.breaker import BreakerPolicy, CircuitBreaker, RequestBudget
    from watcher.rpc.client import ProviderSlot

    return ProviderSlot(
        client=client,
        breaker=CircuitBreaker(client.name, BreakerPolicy()),
        budget=RequestBudget(client.name, limit=None),
    )


async def test_balances_are_read_through_the_watchers_pool(
    conn: AsyncConnection, world: World
) -> None:
    """The settler reuses :class:`RpcPool`; it does not open its own transport.

    TZ 5.6 gives the project one rotation, one circuit breaker per provider, one
    backoff policy and one request budget. A reconciliation sweep outside all
    four could exhaust a provider's rate limit that the watcher believed it was
    managing, and take payment detection down as a side effect of an audit.

    The double here is the watcher's own ``FakeRpcClient``, replaying a stored
    ``eth_call`` answer — the same pattern ``tests/watcher/`` uses, so no socket
    is opened anywhere in this suite.
    """
    from tests.watcher.fakes import FakeRpcClient
    from watcher.rpc.pool import RpcPool

    scenario = await _paid_invoice(conn, world)
    asset = await _asset_row(conn, scenario.asset_id)

    calldata = encode_balance_of(scenario.address)
    client = FakeRpcClient(
        "fake-alchemy", call_results={calldata: "0x" + f"{10 * USDC:064x}"}
    )
    pool = RpcPool(scenario.chain_id, [_slot(client)])

    report = await reconcile(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=RpcBalanceSource(pool),
        admin_policy=POLICY,
    )

    assert report.absolute_drift_raw == 0
    assert not report.alert
    # The call really went out as an ERC-20 `balanceOf` to the token contract.
    assert client.call_calls == [{"to": asset.contract_address, "data": calldata}]
    assert calldata.startswith(BALANCE_OF_SELECTOR)


async def test_a_native_asset_is_read_with_get_balance_not_a_contract_call(
    conn: AsyncConnection, world: World
) -> None:
    """ETH has no ``balanceOf``; asking a contract for it would return nonsense."""
    import sqlalchemy as sa

    from tests.watcher.fakes import FakeRpcClient
    from watcher.rpc.pool import RpcPool

    chain_id = await world.chain()
    await conn.execute(
        sa.text(
            """
            INSERT INTO assets (chain_id, contract_address, symbol, decimals, is_native)
            VALUES (:chain_id, NULL, 'ETH', 18, true)
            """
        ),
        {"chain_id": chain_id},
    )
    asset_id = (
        await conn.execute(
            sa.text("SELECT id FROM assets WHERE chain_id = :c AND is_native"),
            {"c": chain_id},
        )
    ).scalar_one()

    hd_id = await world.hd_account()
    native_address_id, address = await world.address(hd_id, index=91)
    await world.payment(
        chain_id=chain_id,
        asset_id=asset_id,
        address_id=native_address_id,
        invoice_id=None,
        amount_raw=10**18,
        block_number=90,
        status=E.PaymentStatus.CONFIRMED,
        anomaly=E.PaymentAnomaly.UNASSIGNED_PAYMENT,
    )

    client = FakeRpcClient("fake-ankr", balances={address: 10**18})
    pool = RpcPool(chain_id, [_slot(client)])

    report = await reconcile(
        conn,
        chain_id=chain_id,
        asset_id=asset_id,
        balances=RpcBalanceSource(pool),
        admin_policy=POLICY,
        rate=Decimal("3000"),
    )

    assert report.absolute_drift_raw == 0
    assert client.call_calls == []
    assert [addr for addr, _block in client.balance_calls] == [address]


async def _asset_row(conn: AsyncConnection, asset_id: int) -> AssetRow:
    from settler.admin import repository as admin_repo

    asset = await admin_repo.load_asset(conn, asset_id)
    assert asset is not None
    return asset


def test_balance_of_encoding_matches_the_known_selector() -> None:
    """``keccak256("balanceOf(address)")[:4]`` and a 32-byte left-padded argument.

    Asserted against a literal rather than recomputed, because the constant in
    :mod:`settler.admin.balances` is itself hand-written — see the comment there
    on why no keccak implementation is imported into this repository. Two
    hand-written values agreeing is a weak check; one hand-written value agreeing
    with the universally published one is the check that matters.
    """
    calldata = encode_balance_of("0xAbC0000000000000000000000000000000000001")
    assert calldata == (
        "0x70a08231" + "0" * 24 + "abc0000000000000000000000000000000000001"
    )
    assert len(calldata) == 2 + 8 + 64


def test_a_reconcile_report_is_readable_long_after_the_run() -> None:
    """The dataclass carries its own thresholds and rate, not a pointer to today's.

    Same reasoning as ``policy_version`` on a settlement (TZ 5.8/T8): a report
    that says "drift 6.00, threshold: whatever the config says now" cannot be
    checked against the decision it justified.
    """
    from settler.admin.reconcile import ReconcileReport

    report = ReconcileReport(
        chain_id=8453,
        asset_id=1,
        asset_symbol="USDC",
        drift_usd=Decimal("6"),
        threshold_usd=Decimal("1"),
        rate_used=Decimal("1"),
        rate_source="caller",
        policy_version="test-admin-1",
    )
    assert report.alert
    assert report.policy_version == "test-admin-1"
    assert report.threshold_usd == Decimal("1")
    assert report.rate_source == "caller"
