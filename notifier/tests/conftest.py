"""Test rig for the notifier: a real Postgres, the real migrations.

Same argument as ``settler/tests/conftest.py``, applied to a different set of
guarantees. What the notifier claims is true is claimed by PostgreSQL on its
behalf: ``FOR UPDATE ... SKIP LOCKED`` handing one row to exactly one claimant,
``UPDATE ... WHERE attempts = :attempts`` reporting zero affected rows when the
lease has moved on, ``UNIQUE (kind, ref_id, dedup_key)`` refusing a duplicate
outbox row, and the column-scoped GRANT of migration 0004 refusing a write to
``users.internal_balance_usd``. A mock can be told to return any of those
answers, which proves only that the test author knew what the answer should be.

So the schema is built by ``alembic upgrade head``, not
``Base.metadata.create_all`` — the grants live in migrations 0002/0003/0004 and
``create_all`` does not run them, which would turn the privilege test into a
test of nothing.

**Why the rig commits and the settler's rig does not.** The settler's functions
run inside the caller's transaction, so its tests hold one open transaction and
assert through it. The notifier is the opposite by design: it opens its own
short transactions around a claim and around a completion, and never holds one
across a network call. A fixture that seeded rows inside an uncommitted
transaction would therefore seed rows the notifier cannot see — so every helper
here commits, and the tests read the same way production does.

Redis is treated differently again. The rate limiter's *algorithm* is exercised
against the in-process implementation, where a test can own the clock and assert
about microseconds without sleeping. The *Redis* implementation is exercised
against a real server when ``REDIS_URL`` is set (the compose file sets it) and
skipped otherwise, so a developer without Redis still gets the full delivery
suite. The one thing never skipped is the Redis-off path —
``test_no_redis.py`` — because "the system stays correct with Redis removed" is
a standing requirement in this repo (TZ 5.8/T2.4), not an optional extra.

    docker compose -f docker-compose.test.yml run --rm notifier-tests
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys
import uuid
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_URL = "postgresql+psycopg://notchstave:testpw@localhost:55432/notchstave_test"

_DATA_TABLES = (
    "audit_log",
    "notifications",
    "manual_reviews",
    "refunds",
    "entitlements",
    "payments",
    "invoices",
    "receive_addresses",
    "blocks",
    "hd_accounts",
    "sweep_exports",
    "rate_limits",
    "users",
    "products",
    "assets",
    "chains",
)


def database_url() -> str:
    return os.environ.get("DATABASE_URL", DEFAULT_URL)


def redis_url() -> str | None:
    return os.environ.get("REDIS_URL")


@pytest.fixture(scope="session", autouse=True)
def _schema() -> None:
    """Build the schema once per session from the migrations that ship.

    The presence check looks for migration 0004's column rather than for a
    table: a developer whose database was migrated before this week's work would
    otherwise be told the schema is present and then fail on
    ``next_attempt_at``, which is a confusing way to learn about a migration.
    """
    engine = sa.create_engine(database_url(), poolclass=NullPool)
    try:
        with engine.connect() as connection:
            current = connection.execute(
                sa.text(
                    """
                    SELECT 1 FROM information_schema.columns
                     WHERE table_name = 'notifications' AND column_name = 'next_attempt_at'
                    """
                )
            ).scalar()
    finally:
        engine.dispose()

    if current:
        return

    from alembic import command
    from alembic.config import Config

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    command.upgrade(cfg, "head")


@pytest.fixture
async def engine() -> AsyncGenerator[AsyncEngine, None]:
    """A fresh engine and an empty database for every test.

    ``NullPool`` for the same reason the settler's rig uses it: the claim tests
    open several connections to prove that ``SKIP LOCKED`` hands a row to one of
    them, and a pool would turn "two concurrent claimants" into "one connection
    taking turns" — queueing in SQLAlchemy instead of in Postgres, which is the
    opposite of what is under test.
    """
    eng = create_async_engine(database_url(), poolclass=NullPool)
    async with eng.begin() as connection:
        await connection.execute(
            sa.text(f"TRUNCATE {', '.join(_DATA_TABLES)} RESTART IDENTITY CASCADE")
        )
    try:
        yield eng
    finally:
        await eng.dispose()


class Outbox:
    """Writes the rows the settler would have written, and reads them back.

    Inserts go through raw SQL rather than through
    :func:`settler.repository.enqueue_notification` on purpose: the notifier is
    a separate process and must be testable against the *table*, not against the
    settler's code. If the two ever disagree about the contract, this rig is
    where it shows.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._n = 0

    def _next(self) -> int:
        self._n += 1
        return self._n

    async def user(self, *, tg_id: int | None = None, blocked: bool = False) -> int:
        n = self._next()
        async with self._engine.begin() as conn:
            row = await conn.execute(
                sa.text(
                    """
                    INSERT INTO users (tg_id, lang, bot_blocked_at)
                    VALUES (:tg_id, 'en', CASE WHEN :blocked THEN now() ELSE NULL END)
                    RETURNING id
                    """
                ),
                {"tg_id": tg_id if tg_id is not None else 500_000 + n, "blocked": blocked},
            )
            return int(row.scalar_one())

    async def enqueue(
        self,
        *,
        user_id: int,
        kind: str = "invoice_settled",
        ref_id: str | None = None,
        dedup_key: str = "1",
        payload: dict[str, Any] | None = None,
        status: str = "queued",
        attempts: int = 0,
        age_seconds: float | None = None,
        next_attempt_at: dt.datetime | None = None,
    ) -> int:
        """One outbox row. The defaults render successfully with the real renderers.

        ``age_seconds`` defaults to a value that decreases with each call, so
        insertion order and ``created_at`` order agree — which the ordering
        assertions depend on and which ``now()`` alone would not give, since two
        rows written a millisecond apart can share a timestamp.
        """
        n = self._next()
        ref = ref_id if ref_id is not None else str(uuid.uuid4())
        body = payload if payload is not None else {"invoice_id": ref, "outcome": "paid"}
        async with self._engine.begin() as conn:
            row = await conn.execute(
                sa.text(
                    """
                    INSERT INTO notifications (user_id, kind, ref_id, dedup_key, payload_json,
                                               status, attempts, created_at, next_attempt_at)
                    VALUES (:user_id, :kind, :ref_id, :dedup_key, CAST(:payload AS jsonb),
                            CAST(:status AS notification_status), :attempts,
                            now() - make_interval(secs => :age), :next_attempt_at)
                    RETURNING id
                    """
                ),
                {
                    "user_id": user_id,
                    "kind": kind,
                    "ref_id": ref,
                    "dedup_key": dedup_key,
                    "payload": json.dumps(body, default=str, sort_keys=True),
                    "status": status,
                    "attempts": attempts,
                    "age": float(max(0, 10_000 - n)) if age_seconds is None else age_seconds,
                    "next_attempt_at": next_attempt_at,
                },
            )
            return int(row.scalar_one())

    async def row(self, notification_id: int) -> dict[str, Any]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                sa.text("SELECT * FROM notifications WHERE id = :id"), {"id": notification_id}
            )
            return dict(result.mappings().one())

    async def status(self, notification_id: int) -> str:
        return str((await self.row(notification_id))["status"])

    async def attempts(self, notification_id: int) -> int:
        return int((await self.row(notification_id))["attempts"])

    async def blocked_at(self, user_id: int) -> dt.datetime | None:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                sa.text("SELECT bot_blocked_at FROM users WHERE id = :id"), {"id": user_id}
            )
            value = result.scalar_one()
        return None if value is None else dt.datetime.fromisoformat(str(value))

    async def message_id_of(self, kind: str) -> int | None:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                sa.text(
                    "SELECT message_id FROM notifications WHERE kind = :kind "
                    "ORDER BY id DESC LIMIT 1"
                ),
                {"kind": kind},
            )
            value = result.scalar_one_or_none()
        return None if value is None else int(value)

    async def count(self, where: str = "TRUE", **params: object) -> int:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                sa.text(f"SELECT count(*) FROM notifications WHERE {where}"), params
            )
            return int(result.scalar_one())

    async def audit_count(self, action: str) -> int:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE action = :action"),
                {"action": action},
            )
            return int(result.scalar_one())

    async def expire_lease(self, notification_id: int) -> None:
        """Make a claimed row eligible again without waiting for the lease.

        Used by the tests that drive several attempts through the backoff curve:
        a real ``next_attempt_at`` is minutes away, and a test that waited for it
        would not be run.
        """
        async with self._engine.begin() as conn:
            await conn.execute(
                sa.text(
                    "UPDATE notifications SET next_attempt_at = now() - interval '1 second' "
                    "WHERE id = :id"
                ),
                {"id": notification_id},
            )


@pytest.fixture
def outbox(engine: AsyncEngine) -> Outbox:
    return Outbox(engine)


def sample_value(metric: object, name_suffix: str = "", **labels: str) -> float:
    """Current value of one Prometheus sample, read through ``collect()``.

    Same helper and same reasoning as the settler's rig: assertions travel the
    path ``/metrics`` travels, and they compare deltas rather than absolutes
    because the collectors are process-global and other tests in the same
    session have already moved them.
    """
    for family in metric.collect():  # type: ignore[attr-defined]
        for sample in family.samples:
            if name_suffix and not sample.name.endswith(name_suffix):
                continue
            if all(sample.labels.get(k) == v for k, v in labels.items()):
                return float(sample.value)
    return 0.0
