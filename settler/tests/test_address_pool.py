"""The address pool actually refills — TZ 5.1 p. 2, end to end.

The finding this file pins down was not a bug in a statement; it was a whole
mechanism that existed, was tested in isolation, and was called by nobody.
``deriver/pool.py`` has shipped ``schedule_release``, ``release_due_addresses``
and ``mark_address_funded`` since Week 1. ``create_invoice`` takes an address out
of the pool. Nothing put one back, so ``hd_accounts.max_active_addresses`` —
documented as a ceiling on *simultaneously* reserved addresses — was in practice
a lifetime issuance cap, reached by ordinary successful traffic in days, with no
automatic recovery on the far side of it.

Two halves are under test here and they run in two different processes, so both
sides are exercised for real rather than mocked at the seam:

* the **settler** decides — it is the process that owns ``invoices`` and
  ``payments`` and the only one that moves an invoice into a terminal status —
  and, holding SELECT and nothing else on ``receive_addresses`` (TZ 5.8/T1.2),
  it can only *ask*;
* the **deriver** applies, through ``deriver.main.serve_one_address_request``
  and ``deriver.pool``, over a plain synchronous psycopg connection to the same
  database.

The deriver half is driven here rather than in ``deriver/tests`` on purpose:
that suite runs against a scripted fake connection so it can live in the
deriver's isolated environment without Postgres, which is right for what it
covers and cannot prove that an address ends up ``free``. This one can.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import AsyncGenerator
from typing import Any

import psycopg
import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from core.db import enums as E
from core.db.roles import psycopg_dsn
from deriver import main as deriver_main
from deriver import requests as deriver_requests
from settler import metrics
from settler import repository as repo
from settler.service import (
    DEFAULT_ADDRESS_COOLDOWN,
    publish_reserved_address_gauge,
    sync_address_lifecycle,
)
from settler.tests.conftest import World, database_url


@pytest.fixture
async def sync_conn(engine: AsyncEngine) -> AsyncGenerator[psycopg.Connection[Any], None]:
    """A synchronous psycopg connection, which is what the deriver has.

    ``deriver.pool`` is deliberately sync — ``asyncio`` is on that package's
    forbidden-import list — so exercising it means opening the same kind of
    connection the deriver process opens, against the same database the async
    engine above is using. Taking the engine as a dependency is not decoration:
    it is what makes this fixture run *after* the per-test TRUNCATE.
    """
    conn = psycopg.connect(psycopg_dsn(database_url()), autocommit=False)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


async def _requests(conn: AsyncConnection) -> list[dict[str, Any]]:
    rows = await conn.execute(
        sa.text(
            "SELECT address_id, invoice_id, action::text AS action, "
            "       cooldown_until, status::text AS status "
            "  FROM address_lifecycle_requests ORDER BY address_id, action"
        )
    )
    return [dict(r) for r in rows.mappings().all()]


async def _address_row(conn: AsyncConnection, address_id: int) -> dict[str, Any]:
    row = await conn.execute(
        sa.text(
            "SELECT status::text AS status, ever_funded, cooldown_until, "
            "       current_invoice_id "
            "  FROM receive_addresses WHERE id = :id"
        ),
        {"id": address_id},
    )
    return dict(row.mappings().one())


def _gauge(chain_id: int) -> float:
    for family in metrics.ACTIVE_RESERVED_ADDRESSES.collect():
        for sample in family.samples:
            if sample.labels.get("chain") == str(chain_id):
                return float(sample.value)
    return 0.0


# ---------------------------------------------------------------------------
# What the settler asks for
# ---------------------------------------------------------------------------


async def test_an_expired_invoice_that_never_saw_money_gives_its_address_back(
    conn: AsyncConnection, world: World
) -> None:
    """The ordinary case, and the one that was leaking: an unpaid invoice.

    Most invoices in a real shop end here — somebody pressed ``/buy``, thought
    better of it, and the address was pinned forever.
    """
    s = await world.scenario()
    await conn.execute(
        sa.text("UPDATE invoices SET status = 'expired' WHERE id = :id"), {"id": s.invoice_id}
    )

    latched, released = await sync_address_lifecycle(conn)

    assert (latched, released) == (0, 1)
    (request,) = await _requests(conn)
    assert request["action"] == "release"
    assert request["address_id"] == s.address_id
    assert request["invoice_id"] == s.invoice_id
    assert request["status"] == "pending"
    assert request["cooldown_until"] is not None


async def test_the_cooldown_is_the_topup_window_plus_the_configured_rest(
    conn: AsyncConnection, world: World
) -> None:
    """Condition 2 of TZ 5.1, with the arithmetic where a reviewer can see it.

    The floor is the top-up window, not the moment of expiry: a buyer who sends
    money late is sending it to an address they copied out of a message, and the
    window is exactly how long the system promised to keep listening.
    """
    s = await world.scenario(topup_window=dt.timedelta(hours=24))
    window = (
        await conn.execute(
            sa.text("SELECT topup_window_until FROM invoices WHERE id = :id"),
            {"id": s.invoice_id},
        )
    ).scalar_one()
    await conn.execute(
        sa.text("UPDATE invoices SET status = 'expired' WHERE id = :id"), {"id": s.invoice_id}
    )

    await sync_address_lifecycle(conn, cooldown=dt.timedelta(minutes=30))

    (request,) = await _requests(conn)
    assert request["cooldown_until"] == window + dt.timedelta(minutes=30)


async def test_a_live_invoice_keeps_its_address(
    conn: AsyncConnection, world: World
) -> None:
    """Condition 3. Nothing is asked for while the buyer can still pay."""
    s = await world.scenario()
    assert s.invoice_id is not None

    assert await sync_address_lifecycle(conn) == (0, 0)
    assert await _requests(conn) == []


async def test_an_address_that_saw_money_is_latched_and_never_released(
    conn: AsyncConnection, world: World
) -> None:
    """Condition 1, the one-way latch — TZ 5.1: ``ever_funded`` is forever.

    The invoice is settled and terminal, so condition 3 is satisfied and
    condition 2 would be in a day. Neither matters: an address that has held
    money must never be handed to anybody else, because a late transfer to it
    would credit a stranger.
    """
    s = await world.scenario()
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=s.amount_due_raw,
        block_number=90,
        status=E.PaymentStatus.CREDITED,
        confirmations_at_credit=3,
    )
    await conn.execute(
        sa.text("UPDATE invoices SET status = 'paid', settled_at = now() WHERE id = :id"),
        {"id": s.invoice_id},
    )

    latched, released = await sync_address_lifecycle(conn)

    assert (latched, released) == (1, 0)
    (request,) = await _requests(conn)
    assert request["action"] == "mark_funded"
    assert request["cooldown_until"] is None


async def test_dust_counts_as_money_for_the_latch(
    conn: AsyncConnection, world: World
) -> None:
    """``ignored_dust`` is below the credit threshold and still somebody's coin.

    The reuse rule is about the address's history, not about whether the amount
    was worth crediting — and an address with dust on it is an address whose
    balance a future tenant would see.
    """
    s = await world.scenario()
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=1,
        block_number=90,
        status=E.PaymentStatus.IGNORED_DUST,
        anomaly=E.PaymentAnomaly.DUST,
    )
    await conn.execute(
        sa.text("UPDATE invoices SET status = 'expired' WHERE id = :id"), {"id": s.invoice_id}
    )

    latched, released = await sync_address_lifecycle(conn)

    assert (latched, released) == (1, 0)
    assert [r["action"] for r in await _requests(conn)] == ["mark_funded"]


async def test_a_free_pool_address_that_received_money_is_latched_too(
    conn: AsyncConnection, world: World
) -> None:
    """The ``unassigned_payment`` case (TZ 5.5), and the worst row in the table.

    Money landed on an address nobody has reserved. It is first in line for the
    next ``/buy``, so without the latch the next buyer is shown an address with a
    stranger's balance on it — and every reconcile from then on reports a drift
    that has an innocent explanation nobody can find.
    """
    hd_id = await world.hd_account()
    chain_id = await world.chain()
    asset_id = await world.asset(chain_id)
    address_id, _ = await world.address(hd_id, index=777)
    await world.payment(
        chain_id=chain_id,
        asset_id=asset_id,
        address_id=address_id,
        invoice_id=None,
        amount_raw=5_000_000,
        block_number=90,
        anomaly=E.PaymentAnomaly.UNASSIGNED_PAYMENT,
    )

    latched, released = await sync_address_lifecycle(conn)

    assert (latched, released) == (1, 0)
    (request,) = await _requests(conn)
    assert request["action"] == "mark_funded"
    assert request["invoice_id"] is None


async def test_a_reverted_payment_does_not_latch_the_address(
    conn: AsyncConnection, world: World
) -> None:
    """Money in an orphaned block stopped existing (TZ 5.4).

    Latching on it would retire an address for a payment the chain no longer
    contains. If the transaction is re-included the watcher writes a fresh row in
    a live status, which matches the latch query on the very next pass — so the
    conservative-looking choice here is the one that stays correct in both
    directions.
    """
    s = await world.scenario()
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=s.amount_due_raw,
        block_number=90,
        status=E.PaymentStatus.REVERTED,
    )
    await conn.execute(
        sa.text("UPDATE invoices SET status = 'expired' WHERE id = :id"), {"id": s.invoice_id}
    )

    latched, released = await sync_address_lifecycle(conn)

    assert latched == 0
    # And it is not released either: the payments row is still there, so the
    # release query's own `NOT EXISTS (payments)` refuses to schedule it. An
    # address that has been touched at all stays out of circulation until a human
    # or a re-inclusion settles what happened.
    assert released == 0


async def test_running_the_sweep_twice_asks_once(
    conn: AsyncConnection, world: World
) -> None:
    """``uq_address_lifecycle_open_per_action`` doing its job.

    The settler polls, so the sweep re-derives the same candidate on every tick
    until the deriver acts. Without the index that is a queue that grows at the
    poll rate.
    """
    s = await world.scenario()
    await conn.execute(
        sa.text("UPDATE invoices SET status = 'expired' WHERE id = :id"), {"id": s.invoice_id}
    )

    first = await sync_address_lifecycle(conn)
    second = await sync_address_lifecycle(conn)

    assert first == (0, 1)
    assert second == (0, 0)
    assert len(await _requests(conn)) == 1


async def test_the_sweep_stops_asking_once_the_deriver_has_acted(
    conn: AsyncConnection, world: World
) -> None:
    """Convergence, which is what makes a lost request harmless.

    Nothing tracks what has already been asked for. The candidate queries stop
    matching because the *world* changed — ``cooldown_until`` is set — and that
    is the property that lets the settler re-ask safely forever.
    """
    s = await world.scenario()
    await conn.execute(
        sa.text("UPDATE invoices SET status = 'expired' WHERE id = :id"), {"id": s.invoice_id}
    )
    await sync_address_lifecycle(conn)

    # Stand in for the deriver: the request is served and the cooldown written.
    await conn.execute(
        sa.text("UPDATE address_lifecycle_requests SET status = 'done', completed_at = now()")
    )
    await conn.execute(
        sa.text(
            "UPDATE receive_addresses SET cooldown_until = now() + interval '1 hour' "
            " WHERE id = :id"
        ),
        {"id": s.address_id},
    )

    assert await sync_address_lifecycle(conn) == (0, 0)


# ---------------------------------------------------------------------------
# What the deriver does with it
# ---------------------------------------------------------------------------


async def test_the_whole_round_trip_returns_the_address_to_the_free_pool(
    engine: AsyncEngine, sync_conn: psycopg.Connection[Any]
) -> None:
    """settler asks -> deriver schedules -> cooldown passes -> address is free.

    The test the finding needed and did not have. Every earlier test in the
    repository stopped at one side of the process boundary; this one crosses it,
    with the settler's async engine and the deriver's synchronous psycopg
    connection both pointed at the same Postgres.

    The cooldown is set in the past by the test rather than waited out — the
    deadline is a day away in production and this suite may not sleep — but the
    predicate that reads it is ``deriver.pool.SQL_RELEASE_DUE``, untouched, with
    all three TZ 5.1 conditions still in its WHERE clause.
    """
    async with engine.begin() as c:
        world = World(c)
        s = await world.scenario()
        await c.execute(
            sa.text("UPDATE invoices SET status = 'expired' WHERE id = :id"),
            {"id": s.invoice_id},
        )
        await sync_address_lifecycle(c, cooldown=dt.timedelta(seconds=0))

    served = deriver_main.run_once_address_requests(sync_conn)
    assert served == ["applied"]

    # The cooldown is in the future (top-up window + 0s), so the address is not
    # free yet — condition 2 is a deadline, not a flag.
    async with engine.connect() as c:
        row = await _address_row(c, s.address_id)
    assert row["status"] == str(E.AddressStatus.RESERVED)
    assert row["cooldown_until"] is not None

    with sync_conn.cursor() as cur:
        cur.execute(
            "UPDATE receive_addresses SET cooldown_until = now() - interval '1 minute' "
            " WHERE id = %(id)s",
            {"id": s.address_id},
        )
    sync_conn.commit()

    assert deriver_main.release_due_everywhere(sync_conn) == 1

    async with engine.connect() as c:
        row = await _address_row(c, s.address_id)
    assert row["status"] == str(E.AddressStatus.FREE)
    assert row["current_invoice_id"] is None
    assert row["cooldown_until"] is None
    assert row["ever_funded"] is False


async def test_a_funded_address_is_latched_and_the_release_pass_will_not_take_it(
    engine: AsyncEngine, sync_conn: psycopg.Connection[Any]
) -> None:
    """The other direction of the same round trip, and the one that must not fail open.

    ``ever_funded`` is a one-way latch and the release statement excludes it, so
    even a cooldown written by mistake cannot bring the address back.
    """
    async with engine.begin() as c:
        world = World(c)
        s = await world.scenario()
        await world.payment(
            chain_id=s.chain_id,
            asset_id=s.asset_id,
            address_id=s.address_id,
            invoice_id=s.invoice_id,
            amount_raw=s.amount_due_raw,
            block_number=90,
            status=E.PaymentStatus.CREDITED,
            confirmations_at_credit=3,
        )
        await c.execute(
            sa.text("UPDATE invoices SET status = 'paid', settled_at = now() WHERE id = :id"),
            {"id": s.invoice_id},
        )
        await sync_address_lifecycle(c)

    assert deriver_main.run_once_address_requests(sync_conn) == ["applied"]

    async with engine.connect() as c:
        row = await _address_row(c, s.address_id)
    assert row["status"] == str(E.AddressStatus.FUNDED)
    assert row["ever_funded"] is True

    # Force the one condition that could still let it out, and watch the other
    # two hold.
    with sync_conn.cursor() as cur:
        cur.execute(
            "UPDATE receive_addresses SET cooldown_until = now() - interval '1 day' "
            " WHERE id = %(id)s",
            {"id": s.address_id},
        )
    sync_conn.commit()

    assert deriver_main.release_due_everywhere(sync_conn) == 0
    async with engine.connect() as c:
        assert (await _address_row(c, s.address_id))["status"] == str(E.AddressStatus.FUNDED)


async def test_an_unknown_action_is_refused_rather_than_marked_done(
    engine: AsyncEngine, sync_conn: psycopg.Connection[Any]
) -> None:
    """A deriver older than its settler must not report work it did not do.

    The enum lives in the database, so a request naming a value this binary does
    not implement is a real deployment ordering, not a hypothetical. Quietly
    completing it would tell the settler an address had moved when it had not.
    """
    async with engine.begin() as c:
        world = World(c)
        s = await world.scenario()

    request = deriver_requests.AddressLifecycleRequest(
        request_id=uuid.uuid4(),
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        action="teleport",
        cooldown_until=None,
        attempts=1,
        requested_at=dt.datetime.now(dt.UTC),
    )
    with sync_conn.cursor() as cur:
        cur.execute(
            "INSERT INTO address_lifecycle_requests "
            "       (id, address_id, invoice_id, action, status, attempts, claimed_at) "
            "VALUES (%(id)s, %(address_id)s, %(invoice_id)s, 'mark_funded', "
            "        'processing', 1, now())",
            {
                "id": request.request_id,
                "address_id": s.address_id,
                "invoice_id": s.invoice_id,
            },
        )
    sync_conn.commit()

    assert deriver_main.serve_one_address_request(sync_conn, request) == "refused"

    async with engine.connect() as c:
        row = (
            await c.execute(
                sa.text(
                    "SELECT status::text AS status, error_code "
                    "  FROM address_lifecycle_requests WHERE id = :id"
                ),
                {"id": request.request_id},
            )
        ).mappings().one()
    assert row["status"] == "failed"
    assert row["error_code"] == "UnknownAddressAction"
    async with engine.connect() as c:
        assert (await _address_row(c, s.address_id))["ever_funded"] is False


# ---------------------------------------------------------------------------
# The metric that was supposed to catch all of this
# ---------------------------------------------------------------------------


async def test_the_reserved_gauge_counts_addresses_and_comes_back_down(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 5.8/T5.2 — the series the 80%-of-ceiling alert reads.

    It moved here from ``core/invoicing/tests/test_quotas_t5.py``, where it
    asserted on a count of live *invoices* set inside the deriver process — a
    different quantity, in a registry with no exporter in front of it. Two things
    are asserted that the old test could not: that the number is a count of rows
    in ``receive_addresses``, and that it goes back **down**, which is the whole
    point of a ceiling alert.
    """
    first = await world.scenario()
    second = await world.scenario()
    assert first.chain_id == second.chain_id

    await publish_reserved_address_gauge(conn)
    assert _gauge(first.chain_id) == 2.0

    await conn.execute(
        sa.text(
            "UPDATE receive_addresses "
            "   SET status = 'free', current_invoice_id = NULL, reserved_from_block = NULL "
            " WHERE id = :id"
        ),
        {"id": second.address_id},
    )
    await publish_reserved_address_gauge(conn)
    assert _gauge(first.chain_id) == 1.0


async def test_the_gauge_reports_zero_for_a_quiet_chain(
    conn: AsyncConnection, world: World
) -> None:
    """An enabled chain with nothing reserved must publish a 0, not nothing.

    A gauge that is only written when the number is non-zero keeps reporting the
    last value it saw, and an alert that cannot come back down stops being read.
    """
    chain_id = await world.chain(chain_id=42161)

    counts = await publish_reserved_address_gauge(conn)

    assert counts[chain_id] == 0
    assert _gauge(chain_id) == 0.0


# ---------------------------------------------------------------------------
# The string that would fail silently
# ---------------------------------------------------------------------------


def test_the_channel_name_is_the_same_in_both_processes() -> None:
    """A drifted channel name is a wakeup that never arrives.

    Which is indistinguishable from a slow deriver, and would degrade this queue
    to the poll interval without a single error anywhere — the same reason
    migration 0007's channel constants are asserted equal.
    """
    assert (
        repo.CHANNEL_ADDRESS_LIFECYCLE
        == deriver_requests.CHANNEL_ADDRESS_LIFECYCLE
        == "notchstave_address_lifecycle"
    )


def test_the_default_cooldown_is_not_zero() -> None:
    """A zero cooldown deletes condition 2 rather than configuring it.

    Worth an assertion because the value is a plain constant with no schema
    behind it, and "return the address immediately" is exactly what somebody
    reaches for when the pool is under pressure — which is the moment the
    protection matters most.
    """
    assert DEFAULT_ADDRESS_COOLDOWN > dt.timedelta(0)
