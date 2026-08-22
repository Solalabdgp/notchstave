"""The bot asks, the settler executes — migration 0012, review finding H1.

The finding this file exists for is narrow and was invisible for five weeks:
``bot/main.py`` built :class:`~settler.admin.ops.AdminOps` on the *bot's*
engine, so every owner money decision ran under whatever role the bot process
held. While all six processes shared the schema owner's ``DATABASE_URL`` that
worked, because a table owner is never denied anything on its own tables.
Migration 0009 gave each process its own login role and turned it into a
production ``permission denied`` on ``/resolve credit`` — migration 0003 having
revoked ``INSERT`` on ``entitlements`` from ``notchstave_bot`` in writing.

:func:`test_the_bot_role_cannot_credit_but_the_queue_can` is the whole finding in
one test: the same command, the same case, once as the old code ran it and once
through the queue. The first is denied by PostgreSQL and the second grants the
product.

Everything else here is the transport: that the two ends agree on the channel
names and the operation set, that four value objects survive a round trip
through ``jsonb`` unchanged, that a refusal arrives as the same exception class
the handler used to catch in-process, and — the case a queue adds and a function
call does not have — that a settler which never answers produces a clear
``AdminUnavailable`` rather than a hung command or, worse, a silent success.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import os
import re
import uuid
from decimal import Decimal
from typing import Any

import psycopg
import pytest
import sqlalchemy as sa
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from core.db.roles import login_role, password_var, psycopg_dsn
from settler.admin import protocol, queue, wire
from settler.admin.balances import StaticBalanceSource
from settler.admin.client import AdminClient
from settler.admin.errors import (
    AdminUnavailable,
    BalancesUnavailable,
    ConfirmationRequired,
    ReviewAlreadyResolved,
)
from settler.admin.ops import AdminOps
from settler.admin.policy import AdminPolicy
from settler.admin.queue import AdminWorker
from settler.admin.reconcile import AddressDrift, ReconcileReport
from settler.admin.reviews import PendingCase, ResolutionOutcome, ResolutionResult
from settler.admin.sweeplist import SweepExport, SweepRow
from settler.admin.twostep import ConfirmationKey
from settler.policy import Outcome
from settler.service import settle_invoice
from settler.tests.conftest import REPO_ROOT, Scenario, World, count, database_url

MIGRATION_0012 = (
    REPO_ROOT / "migrations" / "versions" / "0012_admin_action_requests.py"
).read_text(encoding="utf-8")

USDC = 1_000_000
OPERATOR = 880_001

KEY = ConfirmationKey(b"test-admin-queue-confirmation-key")

CLOSED_WINDOW: dict[str, Any] = {
    "age": dt.timedelta(minutes=30),
    "expires_in": dt.timedelta(minutes=15),
    "topup_window": dt.timedelta(0),
}


# ---------------------------------------------------------------------------
# The contract both ends read
# ---------------------------------------------------------------------------


def test_the_channel_names_are_one_string_in_three_files() -> None:
    """0007's hazard, restated for this queue.

    A drifted channel name produces no error anywhere: the bot subscribes to a
    channel nobody notifies, the settler notifies a channel nobody hears, and the
    round trip silently degrades to the settler's poll interval. That is a
    latency regression indistinguishable from load, which is why the three copies
    are asserted equal rather than trusted.
    """
    assert (
        f'CHANNEL_ADMIN_REQUESTS = "{protocol.CHANNEL_ADMIN_REQUESTS}"' in MIGRATION_0012
    )
    assert f'REPLY_CHANNEL_PREFIX = "{protocol.REPLY_CHANNEL_PREFIX}"' in MIGRATION_0012
    assert queue.CHANNEL_ADMIN_REQUESTS == protocol.CHANNEL_ADMIN_REQUESTS


def test_the_operations_are_the_migrations_enum() -> None:
    """The dispatch in :class:`~settler.admin.queue.AdminWorker` reads this column.

    An op added to the enum and not to the dispatch is a request that can be
    inserted and never answered; an op in the dispatch and not in the enum is a
    command the bot cannot send. Both are silent, so the two lists are pinned to
    each other.
    """
    declared = re.search(r"^OPS = \(([^)]*)\)", MIGRATION_0012, re.MULTILINE)
    assert declared is not None
    assert tuple(re.findall(r'"([^"]+)"', declared.group(1))) == protocol.OPS


def test_a_reply_channel_fits_postgresqls_identifier_limit() -> None:
    """63 bytes, and the prefix plus 32 hex characters is 36."""
    channel = protocol.reply_channel(uuid.uuid4())
    assert channel.startswith(protocol.REPLY_CHANNEL_PREFIX)
    assert len(channel.encode()) < 63


# ---------------------------------------------------------------------------
# The wire
# ---------------------------------------------------------------------------


def _resolution_result() -> ResolutionResult:
    return ResolutionResult(
        review_id=7,
        resolution="credit",
        outcome=ResolutionOutcome.CREDITED,
        invoice_id=uuid.UUID("018f0000-0000-7000-8000-000000000001"),
        operator_id=OPERATOR,
        # Two digits of scale that must survive: `Decimal("240.50")` and
        # `Decimal("240.5")` are equal and are not the same string in a message
        # about money.
        amount_usd=Decimal("240.50"),
        policy_version="test-1",
        audit_id=99,
        entitlement_id=5,
        credited_payment_ids=(1, 2, 3),
        notification_ids=(11,),
        invoice_status_after="credited",
        lost_grant_race=False,
    )


def test_a_resolution_survives_the_round_trip_exactly() -> None:
    original = _resolution_result()
    restored = wire.decode(ResolutionResult, wire.encode(original))
    assert restored == original
    # Equality is not enough for the two fields a message is built out of: an
    # enum that came back as a bare string compares equal (StrEnum) and fails
    # the `is` check `bot.admin_texts` branches on, and a decimal that lost its
    # scale renders as "240.5".
    assert restored.outcome is ResolutionOutcome.CREDITED
    assert str(restored.amount_usd) == "240.50"


def test_a_pending_case_survives_the_round_trip() -> None:
    case = PendingCase(
        review_id=3,
        kind="underpaid",
        invoice_id=uuid.UUID("018f0000-0000-7000-8000-000000000002"),
        payment_id=None,
        opened_at=dt.datetime(2026, 8, 23, 12, 0, 0, 123456, tzinfo=dt.UTC),
        note="short by 6",
        policy_version="test-1",
        invoice_status="manual_review",
        user_id=42,
        asset_symbol="USDC",
        asset_decimals=6,
        amount_due_raw=Decimal("10000000"),
        amount_due_usd=Decimal("10.000000"),
        received_raw=Decimal("4000000"),
    )
    restored = wire.decode(PendingCase, wire.encode(case))
    assert restored == case
    # Microseconds, and the offset. `opened_at` is rendered into a message the
    # owner reads; a timestamp rounded to the second by the transport would be a
    # different moment from the one in `audit_log`.
    assert restored.opened_at == case.opened_at
    assert restored.opened_at.tzinfo is not None
    assert restored.shortfall_raw == Decimal("6000000")


def test_a_sweep_export_survives_the_round_trip_with_its_rows() -> None:
    export = SweepExport(
        export_id=1,
        generated_at=dt.datetime(2026, 8, 23, 12, 0, tzinfo=dt.UTC),
        chain_id=8453,
        asset_id=1,
        asset_symbol="USDC",
        file_ref="sweep-8453-usdc.csv",
        rows=(
            SweepRow(
                derivation_index=0,
                address="0x" + "11" * 20,
                asset_symbol="USDC",
                balance_raw=Decimal("12345678901234567890123456789"),
                decimals=6,
            ),
        ),
        candidates_checked=4,
        total_raw=Decimal("12345678901234567890123456789"),
        total_usd=Decimal("1.5"),
        csv_text="derivation_index,address\n0,0x11\n",
        audit_id=2,
        policy_version="test-1",
    )
    restored = wire.decode(SweepExport, wire.encode(export))
    assert restored == export
    # A NUMERIC(78,0) balance, well past 2^53. This is the number the operator
    # signs a transfer against; a JSON float here would be a rounded amount on a
    # sweep list.
    assert restored.rows[0].balance_raw == export.rows[0].balance_raw


def test_a_reconcile_report_survives_the_round_trip_with_both_tuples() -> None:
    drift = AddressDrift(
        address_id=1,
        address="0x" + "22" * 20,
        derivation_index=3,
        expected_raw=Decimal("1000000"),
        actual_raw=Decimal("1500000"),
        address_status="reserved",
        swept_at=None,
    )
    report = ReconcileReport(
        chain_id=8453,
        asset_id=1,
        asset_symbol="USDC",
        checked=(drift,),
        skipped_swept=(),
        total_expected_raw=Decimal("1000000"),
        total_actual_raw=Decimal("1500000"),
        absolute_drift_raw=Decimal("500000"),
        drift_usd=Decimal("0.50"),
        rate_used=Decimal("1"),
        rate_source="caller",
        threshold_usd=Decimal("25"),
        manual_review_ids=(4,),
        notification_ids=(),
        audit_ids=(9,),
        policy_version="test-1",
    )
    restored = wire.decode(ReconcileReport, wire.encode(report))
    assert restored == report
    assert restored.drifting == (drift,)
    assert restored.alert is False


def test_the_wire_refuses_a_type_it_has_no_form_for() -> None:
    """The reflective codec's one real risk, closed deliberately.

    A field added to one of the four value objects with a type this module does
    not know must fail here rather than arrive in the bot as ``repr(obj)``.
    """
    with pytest.raises(wire.AdminWireError):
        wire.encode({"a": 1})


def test_the_wire_refuses_a_missing_field_rather_than_defaulting() -> None:
    """``ReconcileReport``'s defaults mean "nothing was found".

    Reading them out of a truncated payload would report a clean reconciliation
    of a chain nobody managed to read — the one wrong answer this report must
    never give.
    """
    payload = wire.encode(_resolution_result())
    del payload["amount_usd"]
    with pytest.raises(wire.AdminWireError, match="amount_usd"):
        wire.decode(ResolutionResult, payload)


def test_the_wire_does_not_read_a_bool_as_an_integer() -> None:
    payload = wire.encode(_resolution_result())
    payload["review_id"] = True
    with pytest.raises(wire.AdminWireError, match="review_id"):
        wire.decode(ResolutionResult, payload)


# ---------------------------------------------------------------------------
# Fixtures for the round trips
# ---------------------------------------------------------------------------


async def _underpaid_case(conn: AsyncConnection, world: World) -> tuple[Scenario, int]:
    """An invoice short of its bill, parked in ``manual_review`` by the settler.

    Built by running the real settler rather than by inserting a
    ``manual_reviews`` row, for the reason ``test_admin_resolve.py`` gives: a
    hand-written case can be shaped in ways production never produces.
    """
    scenario = await world.scenario(
        amount_due_raw=10 * USDC, amount_due_usd="10", **CLOSED_WINDOW
    )
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=4 * USDC,
        block_number=90,
    )
    result = await settle_invoice(conn, scenario.invoice_id)
    assert result.outcome is Outcome.UNDERPAID_MANUAL_REVIEW
    review_id = (
        await conn.execute(
            sa.text(
                "SELECT id FROM manual_reviews WHERE invoice_id = :i AND resolved_at IS NULL"
            ),
            {"i": scenario.invoice_id},
        )
    ).scalar_one()
    return scenario, int(review_id)


def owner_dsn() -> str:
    return psycopg_dsn(database_url())


async def _drain(worker: AdminWorker, stopping: asyncio.Event) -> int:
    """Stand in for :func:`settler.main.serve_admin_requests` with a tight tick."""
    served = 0
    while not stopping.is_set():
        served += await worker.run_once()
        await asyncio.sleep(0.02)
    return served


async def _with_worker(worker: AdminWorker, call: Any) -> Any:
    """Run one client call against a worker that stops when the call returns."""
    stopping = asyncio.Event()
    drain = asyncio.create_task(_drain(worker, stopping))
    try:
        return await call
    finally:
        stopping.set()
        await drain


# ---------------------------------------------------------------------------
# The round trip
# ---------------------------------------------------------------------------


async def test_a_resolve_through_the_queue_grants_the_product(engine: AsyncEngine) -> None:
    """The command the finding is about, end to end.

    The assertions are on the *database*, not on the reply: the reply is a
    report and the report is not the decision. What has to be true afterwards is
    that an entitlement exists and the case is closed, exactly as it was when
    ``AdminOps`` ran inside the bot process.
    """
    async with engine.begin() as conn:
        scenario, review_id = await _underpaid_case(conn, World(conn))

    worker = AdminWorker(engine, AdminOps(engine, confirmation_key=KEY))
    client = AdminClient(owner_dsn(), timeout=20.0)

    result = await _with_worker(
        worker, client.resolve(review_id, "credit", OPERATOR, "goodwill")
    )

    assert result.outcome is ResolutionOutcome.CREDITED
    assert result.review_id == review_id
    assert result.invoice_id == scenario.invoice_id
    assert result.entitlement_id is not None

    async with engine.connect() as conn:
        assert await count(conn, "entitlements", "revoked_at IS NULL") == 1
        assert await count(conn, "manual_reviews", "resolved_at IS NOT NULL") == 1
        # The audit row is written on the settler's side of the queue and names
        # the operator the bot passed through — TZ 5.8/T7 wants "кто и когда".
        assert await count(conn, "audit_log", "actor_id = :a", a=str(OPERATOR)) >= 1


async def test_the_queue_answers_the_same_thing_the_direct_call_does(
    engine: AsyncEngine,
) -> None:
    """Two identical cases, one resolved each way. The reports must agree.

    Not a tautology: the queue's answer goes through ``jsonb`` and back, so this
    is where a field that :mod:`settler.admin.wire` silently drops would show up
    as a difference against the object the caller used to get.
    """
    async with engine.begin() as conn:
        world = World(conn)
        _, first = await _underpaid_case(conn, world)
        _, second = await _underpaid_case(conn, world)

    ops = AdminOps(engine, confirmation_key=KEY)
    direct = await ops.resolve(first, "reject", OPERATOR, "duplicate")

    worker = AdminWorker(engine, ops)
    client = AdminClient(owner_dsn(), timeout=20.0)
    relayed = await _with_worker(worker, client.resolve(second, "reject", OPERATOR, "duplicate"))

    ignored = {"review_id", "invoice_id", "audit_id", "notification_ids"}
    for field in ResolutionResult.__dataclass_fields__:
        if field in ignored:
            continue
        assert getattr(relayed, field) == getattr(direct, field), field


async def test_pending_round_trips_every_case(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        world = World(conn)
        await _underpaid_case(conn, world)
        await _underpaid_case(conn, world)

    worker = AdminWorker(engine, AdminOps(engine, confirmation_key=KEY))
    client = AdminClient(owner_dsn(), timeout=20.0)

    cases = await _with_worker(worker, client.pending(operator_id=OPERATOR))
    assert len(cases) == 2
    assert all(isinstance(case, PendingCase) for case in cases)
    assert all(case.received_raw == Decimal(4 * USDC) for case in cases)


async def test_confirmation_required_arrives_with_the_code_and_the_code_works(
    engine: AsyncEngine,
) -> None:
    """TZ 5.8/T7's two-step control across a process boundary.

    The code is issued by the settler, which holds the confirmation key; the bot
    has none and cannot compute one. So the code has to travel, and it has to
    travel as :class:`~settler.admin.errors.ConfirmationRequired` rather than as
    a generic failure, because ``bot/handlers/admin.py`` catches that class by
    name to render the second-step message.
    """
    async with engine.begin() as conn:
        scenario, review_id = await _underpaid_case(conn, World(conn))

    ops = AdminOps(
        engine,
        policy=AdminPolicy(manual_credit_limit_usd=Decimal("1")),
        confirmation_key=KEY,
    )
    worker = AdminWorker(engine, ops)
    client = AdminClient(owner_dsn(), timeout=20.0)

    with pytest.raises(ConfirmationRequired) as raised:
        await _with_worker(worker, client.resolve(review_id, "credit", OPERATOR))

    exc = raised.value
    assert exc.review_id == review_id
    assert exc.code
    assert exc.amount_usd == Decimal("10")
    assert exc.limit_usd == Decimal("1")

    async with engine.connect() as conn:
        # Nothing was granted, and the attempt is on the record anyway — the
        # ordering `AdminOps` exists for, preserved across the queue.
        assert await count(conn, "entitlements") == 0
        assert await count(conn, "audit_log", "actor_id = :a", a=str(OPERATOR)) >= 1

    confirmed = await _with_worker(
        worker, client.resolve(review_id, "credit", OPERATOR, confirmation_code=exc.code)
    )
    assert confirmed.outcome is ResolutionOutcome.CREDITED
    assert confirmed.invoice_id == scenario.invoice_id


async def test_a_refusal_arrives_as_the_class_the_handler_catches(
    engine: AsyncEngine,
) -> None:
    async with engine.begin() as conn:
        _, review_id = await _underpaid_case(conn, World(conn))

    ops = AdminOps(engine, confirmation_key=KEY)
    await ops.resolve(review_id, "reject", OPERATOR)

    worker = AdminWorker(engine, ops)
    client = AdminClient(owner_dsn(), timeout=20.0)
    with pytest.raises(ReviewAlreadyResolved):
        await _with_worker(worker, client.resolve(review_id, "credit", OPERATOR))


async def test_sweeplist_without_a_balance_source_refuses_rather_than_exporting(
    engine: AsyncEngine,
) -> None:
    """Fail closed. An export built against unreadable balances lists nothing.

    The check used to sit in ``bot/handlers/admin.py`` (``services.balances is
    None``); it now lives in the process that owns the pool, and the bot renders
    the same sentence off the exception.
    """
    async with engine.begin() as conn:
        scenario = await World(conn).scenario()

    worker = AdminWorker(engine, AdminOps(engine), balances=None)
    client = AdminClient(owner_dsn(), timeout=20.0)

    with pytest.raises(BalancesUnavailable):
        await _with_worker(
            worker,
            client.sweeplist(
                chain_id=scenario.chain_id,
                asset_id=scenario.asset_id,
                file_ref="sweep.csv",
                operator_id=OPERATOR,
            ),
        )

    async with engine.connect() as conn:
        assert await count(conn, "sweep_exports") == 0


class _OneSource:
    """A :class:`~settler.admin.queue.BalanceProvider` over a fixed reading."""

    def __init__(self, balances: dict[tuple[int, str], int]) -> None:
        self._source = StaticBalanceSource(dict(balances))

    async def for_chain(self, chain_id: int) -> StaticBalanceSource:
        return self._source


async def test_sweeplist_through_the_queue_produces_the_csv(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        world = World(conn)
        scenario = await world.scenario()
        await world.mark_funded(scenario.address_id)

    worker = AdminWorker(
        engine,
        AdminOps(engine),
        balances=_OneSource({(scenario.asset_id, scenario.address): 7 * USDC}),
    )
    client = AdminClient(owner_dsn(), timeout=20.0)

    export = await _with_worker(
        worker,
        client.sweeplist(
            chain_id=scenario.chain_id,
            asset_id=scenario.asset_id,
            file_ref="sweep.csv",
            operator_id=OPERATOR,
            rate=Decimal("1"),
        ),
    )
    assert export.address_count == 1
    assert export.rows[0].address == scenario.address
    assert export.total_raw == Decimal(7 * USDC)
    assert scenario.address in export.csv_text

    async with engine.connect() as conn:
        # The row 0003 grants the settler and revoked from nobody else. Before
        # migration 0012 this INSERT ran on the bot's connection.
        assert await count(conn, "sweep_exports") == 1


# ---------------------------------------------------------------------------
# When the settler is not there
# ---------------------------------------------------------------------------


async def test_no_settler_means_admin_unavailable_and_the_request_stands(
    engine: AsyncEngine,
) -> None:
    """The failure mode a queue adds and a function call does not have.

    Two things are asserted and the second is the important one: the owner is
    told the command did not complete, **and** the row is still ``pending`` — so
    the message says "check /pending before repeating it" rather than inviting a
    second credit of the same case.
    """
    async with engine.begin() as conn:
        _, review_id = await _underpaid_case(conn, World(conn))

    client = AdminClient(owner_dsn(), timeout=1.0, recheck_interval=0.05)
    with pytest.raises(AdminUnavailable):
        await client.resolve(review_id, "credit", OPERATOR)

    async with engine.connect() as conn:
        assert await count(conn, "admin_action_requests", "status = 'pending'") == 1
        assert await count(conn, "entitlements") == 0


async def test_an_unreachable_database_is_admin_unavailable_not_a_traceback() -> None:
    """`psycopg.Error` must not reach an aiogram handler."""
    client = AdminClient("host=127.0.0.1 port=1 dbname=nope connect_timeout=1", timeout=2.0)
    with pytest.raises(AdminUnavailable):
        await client.pending()


async def test_an_abandoned_claim_answers_the_waiting_bot(engine: AsyncEngine) -> None:
    """A worker that died mid-command must not leave the owner waiting silently.

    ``DEFAULT_MAX_ATTEMPTS`` is 1 here where the deriver's is 3, so the sweep
    fails the request instead of requeuing it — see :mod:`settler.admin.queue` on
    why a second attempt at a money decision is worse than an honest "it did not
    finish".
    """
    request_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            sa.text(
                "INSERT INTO admin_action_requests (id, op, args_json, status, claimed_at, "
                "                                   attempts) "
                "VALUES (:id, 'pending', '{}'::jsonb, 'processing', "
                "        now() - interval '1 hour', 1)"
            ),
            {"id": request_id},
        )

    async with engine.begin() as conn:
        abandoned = await queue.abandon_stale(conn, lease_seconds=60.0)
    assert abandoned == (request_id,)

    async with engine.connect() as conn:
        row = (
            await conn.execute(
                sa.text(
                    "SELECT status::text AS status, error_code FROM admin_action_requests "
                    " WHERE id = :id"
                ),
                {"id": request_id},
            )
        ).mappings().one()
    assert row["status"] == "failed"
    assert row["error_code"] == queue.ABANDONED_ERROR_CODE


async def test_a_finished_request_is_pruned_and_an_open_one_is_not(
    engine: AsyncEngine,
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sa.text(
                "INSERT INTO admin_action_requests (id, op, args_json, status, completed_at, "
                "                                   result_json) "
                "VALUES (:id, 'pending', '{}'::jsonb, 'done', now() - interval '2 hours', "
                "        '{}'::jsonb)"
            ),
            {"id": uuid.uuid4()},
        )
        await conn.execute(
            sa.text(
                "INSERT INTO admin_action_requests (id, op, args_json) "
                "VALUES (:id, 'pending', '{}'::jsonb)"
            ),
            {"id": uuid.uuid4()},
        )

    async with engine.begin() as conn:
        assert await queue.prune_completed(conn, retention_seconds=3600.0) == 1
    async with engine.connect() as conn:
        assert await count(conn, "admin_action_requests") == 1


# ---------------------------------------------------------------------------
# The finding itself
# ---------------------------------------------------------------------------


def _login_url(process: str) -> str | None:
    """The SQLAlchemy URL for one process's own login, or ``None``.

    Same construction as ``test_login_roles.py``: host, port and database from
    ``DATABASE_URL``, credentials swapped, password from the variable
    ``python -m core.db.roles`` reads.
    """
    password = os.environ.get(password_var(process))
    if not password:
        return None
    url = make_url(database_url()).set(username=login_role(process), password=password)
    return url.render_as_string(hide_password=False)


@pytest.fixture
def bot_url() -> str:
    url = _login_url("bot")
    if url is None:
        pytest.skip("no bot login password; run `python -m core.db.roles`")
    with psycopg.connect(owner_dsn(), autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (login_role("bot"),))
        if cur.fetchone() is None:
            pytest.skip("login roles missing; 0009 had no CREATEROLE")
    return url


async def test_the_bot_role_cannot_credit_but_the_queue_can(
    engine: AsyncEngine, bot_url: str
) -> None:
    """Review finding H1, both halves, on one case.

    First half: ``AdminOps`` on a connection authenticated as
    ``notchstave_bot_login`` — which is exactly what ``bot/main.py`` built until
    migration 0012 — is refused by PostgreSQL when ``/resolve credit`` reaches
    ``INSERT INTO entitlements``. That is the production failure the finding
    reported, and no test in this suite could see it before, because every other
    fixture connects as the schema owner.

    Second half: the identical command through the queue, executed by a worker
    on the settler's engine, grants the product.
    """
    async with engine.begin() as conn:
        _, review_id = await _underpaid_case(conn, World(conn))

    bot_engine = create_async_engine(bot_url, poolclass=sa.pool.NullPool)
    try:
        with pytest.raises(sa.exc.ProgrammingError) as denied:
            await AdminOps(bot_engine, confirmation_key=KEY).resolve(
                review_id, "credit", OPERATOR
            )
        assert "permission denied" in str(denied.value).lower()
    finally:
        await bot_engine.dispose()

    async with engine.connect() as conn:
        assert await count(conn, "entitlements") == 0

    worker = AdminWorker(engine, AdminOps(engine, confirmation_key=KEY))
    client = AdminClient(psycopg_dsn(bot_url), timeout=20.0)
    result = await _with_worker(worker, client.resolve(review_id, "credit", OPERATOR))

    assert result.outcome is ResolutionOutcome.CREDITED
    async with engine.connect() as conn:
        assert await count(conn, "entitlements", "revoked_at IS NULL") == 1


async def test_the_bot_role_cannot_answer_its_own_admin_request(bot_url: str) -> None:
    """0007's asymmetry, pointing the other way (migration 0012).

    A bot that could UPDATE this table would report decisions the settler never
    took — which is the whole thing the queue exists to prevent, since the bot is
    the process TZ 5.8/T7 assumes is compromised.
    """
    with psycopg.connect(psycopg_dsn(bot_url), autocommit=True) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE admin_action_requests SET status = 'done'")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM admin_action_requests")


async def test_the_settler_role_cannot_enqueue_an_admin_request() -> None:
    """A settler that can ask itself is a settler that can credit without an owner."""
    url = _login_url("settler")
    if url is None:
        pytest.skip("no settler login password; run `python -m core.db.roles`")
    with psycopg.connect(psycopg_dsn(url), autocommit=True) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "INSERT INTO admin_action_requests (id, op) "
                "VALUES (gen_random_uuid(), 'resolve')"
            )
