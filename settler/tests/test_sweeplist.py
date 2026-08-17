"""`/sweeplist` — the CSV, and the record that it was produced (TZ 3.4, 5.1).

"Это **всё**, что бот делает для вывода средств." So the tests are about three
narrow things: the file says the right numbers, the export is recorded, and
nothing in the address pool was written. The last one is the easiest to break by
accident and the most expensive to get wrong — writing ``receive_addresses``
belongs to the deriver alone (TZ 5.8/T1.2), and a `/sweeplist` that helpfully
marked addresses swept would mark them before the offline transaction that
actually sweeps them was even signed.
"""

from __future__ import annotations

import csv
import io
from decimal import Decimal

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

from settler import metrics
from settler.admin.balances import StaticBalanceSource
from settler.admin.policy import AdminPolicy
from settler.admin.sweeplist import CSV_HEADER, generate_sweep_list
from settler.service import settle_invoice
from settler.tests.conftest import Scenario, World, count, sample_value

USDC = 1_000_000
POLICY = AdminPolicy()


async def _funded_address(
    conn: AsyncConnection, world: World, *, amount: int
) -> Scenario:
    """One address holding settled money, flagged funded as the deriver would."""
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
    await world.mark_funded(scenario.address_id)
    return scenario


def _parse(csv_text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(csv_text)))


async def test_the_export_totals_exactly_what_the_chain_holds(
    conn: AsyncConnection, world: World
) -> None:
    """``total_raw`` is the sum of the balances actually read, to the base unit.

    Summed from the same numbers the CSV prints rather than from the ledger:
    the whole purpose of the file is to tell the owner what is *there*, and a
    total derived from what should be there would agree with the ledger even
    when the chain does not — which is precisely the case `/reconcile` exists to
    catch and this file must not paper over.
    """
    first = await _funded_address(conn, world, amount=10 * USDC)
    second = await _funded_address(conn, world, amount=7 * USDC)
    balances = StaticBalanceSource(
        {
            (first.asset_id, first.address): 10 * USDC,
            (second.asset_id, second.address): 7 * USDC,
        }
    )

    export = await generate_sweep_list(
        conn,
        chain_id=first.chain_id,
        asset_id=first.asset_id,
        balances=balances,
        file_ref="sweep-2026-08-17.csv",
        operator_id=770_001,
        admin_policy=POLICY,
    )

    assert export.total_raw == Decimal(17 * USDC)
    assert export.address_count == 2
    rows = _parse(export.csv_text)
    assert sum(int(r["balance_raw"]) for r in rows) == 17 * USDC


async def test_a_partly_moved_balance_is_reported_as_it_is_not_as_it_should_be(
    conn: AsyncConnection, world: World
) -> None:
    """The ledger says ten; the chain says three; the CSV says three.

    An owner about to build a transaction by hand needs the amount that can
    actually be spent. A CSV printing the expected figure would produce a sweep
    that fails on an insufficient balance, at a hardware wallet, offline, with no
    stack trace.
    """
    scenario = await _funded_address(conn, world, amount=10 * USDC)
    balances = StaticBalanceSource({(scenario.asset_id, scenario.address): 3 * USDC})

    export = await generate_sweep_list(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=balances,
        file_ref="partial.csv",
        admin_policy=POLICY,
    )

    assert export.total_raw == Decimal(3 * USDC)
    assert _parse(export.csv_text)[0]["balance_raw"] == str(3 * USDC)


async def test_an_empty_address_is_checked_and_left_out_of_the_file(
    conn: AsyncConnection, world: World
) -> None:
    """A row that needs no action is how the row that does gets missed."""
    holding = await _funded_address(conn, world, amount=10 * USDC)
    empty = await _funded_address(conn, world, amount=5 * USDC)
    balances = StaticBalanceSource({(holding.asset_id, holding.address): 10 * USDC})

    export = await generate_sweep_list(
        conn,
        chain_id=holding.chain_id,
        asset_id=holding.asset_id,
        balances=balances,
        file_ref="one-row.csv",
        admin_policy=POLICY,
    )

    assert export.candidates_checked == 2
    assert export.address_count == 1
    assert [r["address"] for r in _parse(export.csv_text)] == [holding.address]
    assert empty.address not in export.csv_text


async def test_an_already_swept_address_does_not_come_back(
    conn: AsyncConnection, world: World
) -> None:
    scenario = await _funded_address(conn, world, amount=10 * USDC)
    await world.mark_swept(scenario.address_id)

    export = await generate_sweep_list(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=StaticBalanceSource({(scenario.asset_id, scenario.address): 10 * USDC}),
        file_ref="after-sweep.csv",
        admin_policy=POLICY,
    )

    assert export.candidates_checked == 0
    assert export.rows == ()
    assert export.total_raw == 0


async def test_an_address_the_deriver_has_not_flagged_yet_is_still_listed(
    conn: AsyncConnection, world: World
) -> None:
    """``ever_funded`` and the payment row are written by two different processes.

    There is a window between the watcher indexing a transfer and the deriver
    flagging the address, and a sweep list that trusted only the flag would leave
    money behind for exactly as long as that window lasts. The union of the two
    is the conservative reading and costs one line in a CSV.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )
    flagged = (
        await conn.execute(
            sa.text("SELECT ever_funded FROM receive_addresses WHERE id = :id"),
            {"id": scenario.address_id},
        )
    ).scalar_one()
    assert flagged is False, "precondition: the deriver has not caught up yet"

    export = await generate_sweep_list(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=StaticBalanceSource({(scenario.asset_id, scenario.address): 10 * USDC}),
        file_ref="race.csv",
        admin_policy=POLICY,
    )

    assert export.address_count == 1


async def test_the_export_is_recorded_and_the_address_pool_is_not_touched(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 5.8/T1.2 and TZ section 9's weekly spot-check, in one test."""
    scenario = await _funded_address(conn, world, amount=10 * USDC)
    before = (
        await conn.execute(
            sa.text(
                "SELECT status::text AS status, swept_at, ever_funded "
                "  FROM receive_addresses WHERE id = :id"
            ),
            {"id": scenario.address_id},
        )
    ).mappings().one()

    export = await generate_sweep_list(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=StaticBalanceSource({(scenario.asset_id, scenario.address): 10 * USDC}),
        file_ref="tg:BQACAgIAAx0",
        operator_id=770_001,
        admin_policy=POLICY,
    )

    row = (
        await conn.execute(
            sa.text(
                "SELECT address_count, total_raw, asset_id, file_ref, operator_id "
                "  FROM sweep_exports WHERE id = :id"
            ),
            {"id": export.export_id},
        )
    ).mappings().one()
    assert row["address_count"] == 1
    assert Decimal(row["total_raw"]) == Decimal(10 * USDC)
    assert row["asset_id"] == scenario.asset_id
    assert row["file_ref"] == "tg:BQACAgIAAx0"
    assert row["operator_id"] == 770_001

    after = (
        await conn.execute(
            sa.text(
                "SELECT status::text AS status, swept_at, ever_funded "
                "  FROM receive_addresses WHERE id = :id"
            ),
            {"id": scenario.address_id},
        )
    ).mappings().one()
    assert dict(after) == dict(before), "the export is a report, not a state change"

    assert await count(conn, "audit_log", "action = 'admin.sweeplist'") == 1


async def test_the_csv_has_the_columns_the_tz_asks_for(
    conn: AsyncConnection, world: World
) -> None:
    """"индекс деривации, адрес, актив, баланс" — plus the exact base-unit figure.

    The human-readable balance is what an owner checks against a block explorer;
    ``balance_raw`` is what a signing tool consumes and the only exact form,
    since a uint256 does not survive a float.
    """
    scenario = await _funded_address(conn, world, amount=10 * USDC)

    export = await generate_sweep_list(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=StaticBalanceSource({(scenario.asset_id, scenario.address): 10 * USDC}),
        file_ref="columns.csv",
        admin_policy=POLICY,
    )

    rows = _parse(export.csv_text)
    assert tuple(rows[0].keys()) == CSV_HEADER
    assert rows[0]["asset"] == "USDC"
    assert rows[0]["balance"] == "10"
    assert rows[0]["balance_raw"] == "10000000"
    assert int(rows[0]["derivation_index"]) >= 0
    # Deterministic bytes: no \r, so the file can be hashed and compared.
    assert "\r" not in export.csv_text
    assert export.csv_text.endswith("\n")


async def test_a_huge_balance_survives_the_csv_intact(
    conn: AsyncConnection, world: World
) -> None:
    """A uint256 does not fit in a double, and this file precedes a real transfer.

    ``NUMERIC(78, 0)`` all the way to the string: any accidental trip through
    ``float`` would round the last dozen digits, and the owner would sign a
    transaction for the wrong amount with no way to notice.
    """
    scenario = await _funded_address(conn, world, amount=10 * USDC)
    enormous = 2**200 + 12_345
    export = await generate_sweep_list(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=StaticBalanceSource({(scenario.asset_id, scenario.address): enormous}),
        file_ref="big.csv",
        admin_policy=POLICY,
    )

    assert export.total_raw == Decimal(enormous)
    assert _parse(export.csv_text)[0]["balance_raw"] == str(enormous)


async def test_the_unswept_balance_gauge_follows_the_export(
    conn: AsyncConnection, world: World
) -> None:
    """TZ section 7 — "на горячих адресах скопилось слишком много. Пора свипать"."""
    scenario = await _funded_address(conn, world, amount=10 * USDC)

    await generate_sweep_list(
        conn,
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        balances=StaticBalanceSource({(scenario.asset_id, scenario.address): 10 * USDC}),
        file_ref="gauge.csv",
        admin_policy=POLICY,
        rate=Decimal("1"),
    )

    assert (
        sample_value(metrics.UNSWEPT_BALANCE_USD, chain=str(scenario.chain_id)) == 10.0
    )


async def test_exporting_an_unknown_asset_is_an_error(conn: AsyncConnection) -> None:
    with pytest.raises(LookupError):
        await generate_sweep_list(
            conn,
            chain_id=8453,
            asset_id=999,
            balances=StaticBalanceSource({}),
            file_ref="nope.csv",
            admin_policy=POLICY,
        )
