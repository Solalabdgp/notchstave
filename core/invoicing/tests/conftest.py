"""Test rig for invoice issuance: a real Postgres, the real migrations, real pool SQL.

Same argument as ``settler/tests/conftest.py`` and it applies harder here. What
:func:`core.invoicing.service.create_invoice` claims is that a hundred ``/buy``
presses produce three invoices, that ``next_index`` does not move while the pool
has stock, and that twenty concurrent presses from one person cannot get past
the quota. Every one of those is a property of ``pg_advisory_xact_lock``, ``FOR
UPDATE SKIP LOCKED``, a partial unique index and a deferred foreign key. A mock
can be told to return any answer about all four.

So: a real Postgres 17, schema built by ``alembic upgrade head`` (not
``create_all`` — the deferred FK of migration 0006 and the triggers of 0001 only
exist in the migrations), and :mod:`deriver.pool` imported and called for real,
because its reservation statement is the thing under test as much as anything in
``core``.

**Synchronous, one connection per actor.** The service is sync psycopg (see its
module docstring); the concurrency tests therefore use real threads with real
separate connections, which is closer to production than twenty coroutines
sharing an event loop would be.

**The deriver is faked, deliberately, and only in one respect.** ``FakeDeriver``
below implements the same two-method surface as
:class:`deriver.service.Deriver` with a hash instead of secp256k1. Real
derivation — BIP-32 vectors, the five reference addresses, determinism — is
already tested in ``deriver/tests`` against the actual xpub, and that package
installs into its own isolated environment on purpose. What these tests need
from a deriver is the *shape* of its contract: ``address()`` is a pure function
of ``(account, index)`` and ``verify()`` re-derives and compares. Faking the
curve does not weaken the T1 tests one bit, because what they exercise is what
happens when ``verify()`` says no.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import sys
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg.rows import dict_row

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import deriver.pool as pool  # noqa: E402
from core.invoicing.integrity import IntegrityKey  # noqa: E402
from core.invoicing.service import InvoiceView, create_invoice  # noqa: E402

__all__ = [
    "pool",
    "FakeDeriver",
    "Shop",
    "World",
    "TEST_INTEGRITY_KEY",
    "buy",
    "database_url",
    "psycopg_dsn",
    "scalar",
    "count_rows",
    "invoice_row",
    "address_row",
    "next_index",
    "counter_value",
    "sample_value",
    "utc",
]

DEFAULT_URL = "postgresql+psycopg://notchstave:testpw@localhost:55432/notchstave_test"

#: Every table these tests write, truncated between them. ``CASCADE`` sorts out
#: the foreign keys; ``RESTART IDENTITY`` lets an assertion name "address 1"
#: without depending on how many tests ran before.
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

#: Long enough to satisfy :class:`IntegrityKey`'s 16-byte floor, fixed so a
#: failing MAC assertion is reproducible.
TEST_INTEGRITY_KEY = IntegrityKey(b"notchstave-test-integrity-key-0123456789")


def database_url() -> str:
    return os.environ.get("DATABASE_URL", DEFAULT_URL)


def psycopg_dsn() -> str:
    """SQLAlchemy's ``postgresql+psycopg://`` URL as a libpq connection string.

    The repo standardises on the SQLAlchemy form in ``.env.example``, alembic.ini
    and docker-compose, and psycopg does not understand the ``+driver`` suffix.
    Stripping it here keeps one ``DATABASE_URL`` for the whole project rather
    than a second variable that can drift out of sync with the first.
    """
    return database_url().replace("postgresql+psycopg://", "postgresql://", 1)


@pytest.fixture(scope="session", autouse=True)
def _schema() -> None:
    """Bring the database to head, always.

    Unconditional, unlike the settler's equivalent, which short-circuits when
    ``invoices`` already exists. That optimisation is correct there and wrong
    here: this suite was added together with migration 0006, so "the schema
    exists" and "the schema is current" stopped being the same statement. A
    skipped upgrade would run these tests against a NOT DEFERRABLE foreign key
    and fail with an integrity error that looks like a bug in the service.
    """
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", database_url())
    command.upgrade(cfg, "head")


@pytest.fixture
def conn() -> Iterator[psycopg.Connection[Any]]:
    """A fresh connection and an empty database for every test.

    ``autocommit=False``: :func:`create_invoice` is written to run inside the
    caller's transaction and several tests assert on what a rollback undoes, so
    the transaction boundary has to be the test's to control.
    """
    connection = psycopg.connect(psycopg_dsn(), autocommit=False)
    try:
        with connection.cursor() as cur:
            cur.execute(f"TRUNCATE {', '.join(_DATA_TABLES)} RESTART IDENTITY CASCADE")
        connection.commit()
        yield connection
    finally:
        connection.rollback()
        connection.close()


# ---------------------------------------------------------------------------
# A deriver-shaped object with a hash where the curve should be
# ---------------------------------------------------------------------------


class FakeDeriver:
    """Deterministic, pure, and structurally identical to the real thing.

    ``verify`` re-derives and compares case-insensitively, which is what
    :meth:`deriver.derivation.addresses_equal` does for EIP-55 checksummed
    addresses — so a test that lower-cases an address in the database does not
    accidentally trip the mismatch path for the wrong reason.
    """

    def __init__(self, salt: str = "notchstave-test") -> None:
        self._salt = salt

    def address(self, hd_account_id: int, derivation_index: int) -> str:
        digest = hashlib.sha256(
            f"{self._salt}/{hd_account_id}/{derivation_index}".encode()
        ).hexdigest()
        return "0x" + digest[:40]

    def verify(self, address: str, hd_account_id: int, derivation_index: int) -> bool:
        return address.lower() == self.address(hd_account_id, derivation_index).lower()


@pytest.fixture
def deriver() -> FakeDeriver:
    return FakeDeriver()


@pytest.fixture
def key() -> IntegrityKey:
    return TEST_INTEGRITY_KEY


# ---------------------------------------------------------------------------
# Object graph builders
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Shop:
    """The catalog and account a ``/buy`` needs, already wired."""

    chain_id: int
    asset_id: int
    asset_symbol: str
    asset_contract: str
    product_id: int
    user_id: int
    hd_account_id: int
    head_block: int


class World:
    """Inserts rows that satisfy every CHECK, so tests do not have to."""

    def __init__(self, conn: psycopg.Connection[Any]) -> None:
        self._conn = conn
        self._n = 0

    def _next(self) -> int:
        self._n += 1
        return self._n

    def _one(self, sql: str, params: dict[str, Any]) -> Any:
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
        assert row is not None
        return row[0]

    def chain(self, *, chain_id: int = 8453, last_indexed_block: int = 100) -> int:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO chains (chain_id, name, rpc_urls, min_confirmations,
                                    last_indexed_block, is_enabled)
                VALUES (%(chain_id)s, %(name)s, '{}', 3, %(block)s, true)
                ON CONFLICT (chain_id) DO UPDATE
                    SET last_indexed_block = EXCLUDED.last_indexed_block
                """,
                {
                    "chain_id": chain_id,
                    "name": f"chain-{chain_id}",
                    "block": last_indexed_block,
                },
            )
        return chain_id

    def asset(
        self,
        chain_id: int,
        *,
        symbol: str = "USDC",
        decimals: int = 6,
        is_enabled: bool = True,
    ) -> tuple[int, str]:
        contract = _address(f"token-{chain_id}-{symbol}")
        asset_id = self._one(
            """
            INSERT INTO assets (chain_id, contract_address, symbol, decimals,
                                is_native, is_enabled)
            VALUES (%(chain_id)s, %(contract)s, %(symbol)s, %(decimals)s, false, %(enabled)s)
            ON CONFLICT (chain_id, contract_address) DO UPDATE
                SET is_enabled = EXCLUDED.is_enabled
            RETURNING id
            """,
            {
                "chain_id": chain_id,
                "contract": contract,
                "symbol": symbol,
                "decimals": decimals,
                "enabled": is_enabled,
            },
        )
        return int(asset_id), contract

    def product(self, *, price_usd: str = "10.00", active: bool = True) -> int:
        n = self._next()
        return int(
            self._one(
                """
                INSERT INTO products (sku, title, price_usd, kind, content_ref, active)
                VALUES (%(sku)s, %(title)s, %(price)s, 'one_off', %(ref)s, %(active)s)
                RETURNING id
                """,
                {
                    "sku": f"sku-{n}",
                    "title": f"Product {n}",
                    "price": Decimal(price_usd),
                    "ref": f"file-{n}",
                    "active": active,
                },
            )
        )

    def user(self) -> int:
        n = self._next()
        return int(
            self._one(
                "INSERT INTO users (tg_id, lang) VALUES (%(tg_id)s, 'en') RETURNING id",
                {"tg_id": 500_000 + n},
            )
        )

    def hd_account(self, *, next_index: int = 0, max_active_addresses: int = 500) -> int:
        return int(
            self._one(
                """
                INSERT INTO hd_accounts (label, xpub_fingerprint, path_prefix,
                                         next_index, max_active_addresses)
                VALUES ('test', 'deadbeef', 'm/44''/60''/0''',
                        %(next_index)s, %(ceiling)s)
                RETURNING id
                """,
                {"next_index": next_index, "ceiling": max_active_addresses},
            )
        )

    def prefill_pool(self, hd_account_id: int, deriver: FakeDeriver, count: int) -> list[int]:
        """Put ``count`` free addresses in the pool and move ``next_index`` past them.

        This is what the gap-limit pre-fill of TZ 5.1 p. 2 does in production —
        derive ahead so that ``/buy`` finds stock instead of advancing the index.
        """
        ids: list[int] = []
        for index in range(count):
            ids.append(
                int(
                    self._one(
                        """
                        INSERT INTO receive_addresses
                               (hd_account_id, derivation_index, address, status)
                        VALUES (%(account)s, %(index)s, %(address)s, 'free')
                        RETURNING id
                        """,
                        {
                            "account": hd_account_id,
                            "index": index,
                            "address": deriver.address(hd_account_id, index),
                        },
                    )
                )
            )
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE hd_accounts SET next_index = %(n)s WHERE id = %(id)s",
                {"n": count, "id": hd_account_id},
            )
        return ids

    def shop(
        self,
        *,
        price_usd: str = "10.00",
        decimals: int = 6,
        symbol: str = "USDC",
        max_active_addresses: int = 500,
        pooled_addresses: int = 0,
        deriver: FakeDeriver | None = None,
        head_block: int = 100,
    ) -> Shop:
        chain_id = self.chain(last_indexed_block=head_block)
        asset_id, contract = self.asset(chain_id, symbol=symbol, decimals=decimals)
        product_id = self.product(price_usd=price_usd)
        user_id = self.user()
        hd_account_id = self.hd_account(max_active_addresses=max_active_addresses)
        if pooled_addresses:
            assert deriver is not None, "prefilling the pool needs a deriver"
            self.prefill_pool(hd_account_id, deriver, pooled_addresses)
        return Shop(
            chain_id=chain_id,
            asset_id=asset_id,
            asset_symbol=symbol,
            asset_contract=contract,
            product_id=product_id,
            user_id=user_id,
            hd_account_id=hd_account_id,
            head_block=head_block,
        )


@pytest.fixture
def world(conn: psycopg.Connection[Any]) -> World:
    return World(conn)


def buy(
    conn: psycopg.Connection[Any],
    deriver: FakeDeriver,
    key: IntegrityKey,
    shop: Shop,
    **kwargs: Any,
) -> InvoiceView:
    """One ``/buy`` against a :class:`Shop`, wired to the real ``deriver.pool``.

    Every test that presses ``/buy`` goes through here, so the production wiring
    — which module supplies the reservation SQL — is asserted once by
    construction rather than repeated in a dozen call sites where one of them
    could quietly diverge.
    """
    return create_invoice(
        conn,
        deriver,
        key,
        user_id=shop.user_id,
        product_id=shop.product_id,
        chain_id=shop.chain_id,
        asset_id=shop.asset_id,
        hd_account_id=shop.hd_account_id,
        pool=pool,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _address(label: str) -> str:
    return "0x" + hashlib.sha256(label.encode()).hexdigest()[:40]


def scalar(conn: psycopg.Connection[Any], sql: str, **params: Any) -> Any:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
    return None if row is None else row[0]


def count_rows(
    conn: psycopg.Connection[Any], table: str, where: str = "TRUE", **params: Any
) -> int:
    return int(scalar(conn, f"SELECT count(*) FROM {table} WHERE {where}", **params))


def invoice_row(conn: psycopg.Connection[Any], invoice_id: uuid.UUID) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM invoices WHERE id = %(id)s", {"id": invoice_id})
        row = cur.fetchone()
    assert row is not None
    return row


def address_row(conn: psycopg.Connection[Any], address_id: int) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM receive_addresses WHERE id = %(id)s", {"id": address_id})
        row = cur.fetchone()
    assert row is not None
    return row


def next_index(conn: psycopg.Connection[Any], hd_account_id: int) -> int:
    return int(
        scalar(conn, "SELECT next_index FROM hd_accounts WHERE id = %(id)s", id=hd_account_id)
    )


def counter_value(metric: object) -> float:
    """Current value of an unlabelled Prometheus counter.

    Read through ``collect()`` rather than the private ``_value``, so the
    assertion travels the path ``/metrics`` travels. Tests compare deltas, never
    absolutes: the collectors are process-global and other tests in the same
    session have already moved them.
    """
    for family in metric.collect():  # type: ignore[attr-defined]
        for sample in family.samples:
            if sample.name.endswith("_total") and not sample.labels:
                return float(sample.value)
    return 0.0


def sample_value(metric: object, name_suffix: str = "", **labels: str) -> float:
    """Current value of one labelled sample; ``0.0`` for a never-seen child."""
    for family in metric.collect():  # type: ignore[attr-defined]
        for sample in family.samples:
            if name_suffix and not sample.name.endswith(name_suffix):
                continue
            if all(sample.labels.get(k) == v for k, v in labels.items()):
                return float(sample.value)
    return 0.0


def utc(**kwargs: Any) -> dt.datetime:
    """A timezone-aware moment offset from now, for readable deadline arithmetic."""
    return dt.datetime.now(dt.UTC) + dt.timedelta(**kwargs)
