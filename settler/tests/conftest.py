"""Test rig for the settler: a real Postgres, the real migrations, no mocks.

Why there is no in-memory database and no fake connection anywhere in this
directory: every guarantee the settler makes is a guarantee PostgreSQL makes on
its behalf. ``entitlements_active_uniq`` refusing a second grant, ``SELECT FOR
UPDATE`` serialising twenty workers, the ``BEFORE UPDATE`` trigger refusing to
rebind a payment, ``UPDATE ... WHERE status = ANY(...)`` reporting zero affected
rows — a mock can be told to return any of those answers, which proves only that
the test author knew what the answer should be. Under a mock these tests would
pass against an implementation with the constraints dropped.

So the schema is built by ``alembic upgrade head`` — not ``Base.metadata
.create_all``, which would silently omit the trigger and produce a suite that
passes while the property it claims to test does not exist in the database.

Connection handling: one engine per test with :class:`~sqlalchemy.pool.NullPool`.
Pooling would quietly turn "twenty concurrent connections" into "five
connections taking turns", and the queueing would happen in SQLAlchemy instead
of in Postgres — which is the opposite of what the concurrency tests are for.

See ``docker-compose.test.yml`` for the one command that runs all of this.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import sys
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.db import enums as E  # noqa: E402

DEFAULT_URL = "postgresql+psycopg://notchstave:testpw@localhost:55432/notchstave_test"

#: The key every invoice built here is MAC'd under (TZ 5.8/T1.3).
#:
#: Set into the environment at import time, before anything reads it, because
#: :func:`settler.service.settle_invoice` loads the process key through
#: :func:`core.invoicing.integrity.load_integrity_key` and a settler that cannot
#: find one refuses to run — which is the correct production behaviour and would
#: otherwise make this whole suite depend on a shell variable.
#:
#: The important half is the *other* one: :meth:`World.invoice` computes a real
#: MAC over the row it writes. Until Week 5 it wrote ``ab`` repeated 32 times,
#: which satisfied the ``octet_length = 32`` CHECK and nothing else — so a test
#: could not have caught a settler that never verified the MAC, because every
#: invoice in the suite carried one that could not verify. A fixture that makes
#: the check unfalsifiable is worse than no fixture.
TEST_INTEGRITY_KEY_MATERIAL = "settler-tests-integrity-key-not-a-secret"
os.environ.setdefault("INVOICE_INTEGRITY_KEY", TEST_INTEGRITY_KEY_MATERIAL)

from core.invoicing.integrity import IntegrityKey, compute_mac  # noqa: E402

TEST_INTEGRITY_KEY = IntegrityKey(os.environ["INVOICE_INTEGRITY_KEY"])

#: Tables holding test data, in no particular order — ``CASCADE`` sorts out the
#: foreign keys, and ``RESTART IDENTITY`` means an assertion can say "entitlement
#: 1" without depending on how many tests ran before it.
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


@pytest.fixture(scope="session", autouse=True)
def _schema() -> None:
    """Build the schema once per session, from the migrations that ship.

    Idempotent on purpose: the compose file already runs ``alembic upgrade
    head`` before pytest, and a developer running pytest by hand against a
    database that is already migrated should not pay for it twice.
    """
    sync_url = database_url()
    engine = sa.create_engine(sync_url, poolclass=NullPool)
    try:
        with engine.connect() as conn:
            has_schema = bool(
                conn.execute(sa.text("SELECT to_regclass('public.invoices')")).scalar()
            )
    finally:
        engine.dispose()

    if has_schema:
        return

    from alembic import command
    from alembic.config import Config

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    command.upgrade(cfg, "head")


@pytest.fixture
async def engine() -> AsyncGenerator[AsyncEngine, None]:
    """A fresh engine and an empty database for every test."""
    eng = create_async_engine(database_url(), poolclass=NullPool)
    async with eng.begin() as conn:
        await conn.execute(
            sa.text(f"TRUNCATE {', '.join(_DATA_TABLES)} RESTART IDENTITY CASCADE")
        )
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest.fixture
async def conn(engine: AsyncEngine) -> AsyncGenerator[AsyncConnection, None]:
    """One transaction for tests that do not care about concurrency.

    Committed rather than rolled back, because :func:`settler.service
    .settle_invoice` is written to run inside the caller's transaction and the
    assertions that follow read through the same connection.
    """
    async with engine.begin() as connection:
        yield connection


# ---------------------------------------------------------------------------
# Object graph builders
# ---------------------------------------------------------------------------
#
# Notchstave's schema is heavily constrained — composite foreign keys tying an
# invoice's chain to its asset's chain, partial unique indexes on live invoices,
# CHECKs coupling an address's status to its reservation. That is a feature, and
# it means "just insert an invoice" is not a one-liner. These builders keep the
# constraint bookkeeping in one place so that a test reads as the scenario it is
# about, not as fifteen INSERTs.


@dataclass(frozen=True, slots=True)
class Scenario:
    """Ids of one fully wired invoice, ready to be paid."""

    chain_id: int
    asset_id: int
    product_id: int
    user_id: int
    address_id: int
    address: str
    invoice_id: uuid.UUID
    amount_due_raw: Decimal
    decimals: int
    head_block: int


class World:
    """Inserts rows that satisfy every CHECK, so tests do not have to."""

    def __init__(self, conn: AsyncConnection) -> None:
        self._conn = conn
        self._n = 0
        #: Two invoices in one test normally share a network and a derivation
        #: account, exactly as they would in production. `chains` is upserted and
        #: the HD account is cached so that a test needing two invoices does not
        #: have to know that `uq_hd_accounts_single_active` allows only one
        #: active account at a time.
        self._hd_account_id: int | None = None

    def _next(self) -> int:
        self._n += 1
        return self._n

    async def chain(
        self,
        *,
        chain_id: int = 8453,
        min_confirmations: int = 3,
        credit_threshold_usd: Decimal | int = 20,
        use_finalized_tag: bool = True,
        last_indexed_block: int = 100,
    ) -> int:
        await self._conn.execute(
            sa.text(
                """
                INSERT INTO chains (chain_id, name, rpc_urls, min_confirmations,
                                    credit_threshold_usd, use_finalized_tag,
                                    last_indexed_block, is_enabled)
                VALUES (:chain_id, :name, '{}', :min_confirmations,
                        :credit_threshold_usd, :use_finalized_tag,
                        :last_indexed_block, true)
                ON CONFLICT (chain_id) DO UPDATE
                    SET min_confirmations    = EXCLUDED.min_confirmations,
                        credit_threshold_usd = EXCLUDED.credit_threshold_usd,
                        use_finalized_tag    = EXCLUDED.use_finalized_tag,
                        last_indexed_block   = EXCLUDED.last_indexed_block
                """
            ),
            {
                "chain_id": chain_id,
                "name": f"chain-{chain_id}",
                "min_confirmations": min_confirmations,
                "credit_threshold_usd": Decimal(credit_threshold_usd),
                "use_finalized_tag": use_finalized_tag,
                "last_indexed_block": last_indexed_block,
            },
        )
        return chain_id

    async def finalize(self, chain_id: int, number: int) -> int:
        """Mark one height final, the way the watcher does (TZ 5.4).

        The settler reads finality as ``blocks.status = 'confirmed'`` and takes
        the finalized head to be the highest such block — see the module
        docstring of :mod:`settler.confirmations` for why that is an explicit
        contract between the two processes rather than an assumption.
        """
        return await self.block(chain_id, number, status=E.BlockStatus.CONFIRMED)

    async def block(
        self,
        chain_id: int,
        number: int,
        *,
        status: E.BlockStatus = E.BlockStatus.CONFIRMED,
        variant: str = "",
    ) -> int:
        """Idempotent per height, because ``uq_blocks_canonical_height`` is.

        Two scenarios in one test share a chain and therefore share its
        finalized head; asking for the same height twice is the normal case, not
        a mistake worth failing over.
        """
        existing = (
            await self._conn.execute(
                sa.text(
                    """
                    SELECT id FROM blocks
                     WHERE chain_id = :chain_id AND number = :number AND status <> 'orphaned'
                    """
                ),
                {"chain_id": chain_id, "number": number},
            )
        ).scalar_one_or_none()
        if existing is not None:
            return int(existing)

        row = await self._conn.execute(
            sa.text(
                """
                INSERT INTO blocks (chain_id, number, hash, parent_hash, timestamp, status)
                VALUES (:chain_id, :number, :hash, :parent_hash, now(),
                        CAST(:status AS block_status))
                RETURNING id
                """
            ),
            {
                "chain_id": chain_id,
                "number": number,
                # `variant` is how a test writes the replacement block a reorg
                # produces: same height, different hash, which is the whole
                # point of `uq_blocks_chain_id_hash` allowing both to coexist
                # while `uq_blocks_canonical_height` allows only one to be
                # canonical.
                "hash": _hash(f"block-{chain_id}-{number}{variant}"),
                "parent_hash": _hash(f"block-{chain_id}-{number - 1}"),
                "status": str(status),
            },
        )
        return int(row.scalar_one())

    async def orphan_block(self, chain_id: int, number: int) -> None:
        """Reorg the height out from under whatever is sitting on it.

        An UPDATE rather than an INSERT because ``uq_blocks_canonical_height``
        allows only one non-orphaned block per height — which is exactly the
        invariant a reorg respects: the old block stops being canonical.
        """
        await self._conn.execute(
            sa.text(
                """
                UPDATE blocks SET status = 'orphaned'
                 WHERE chain_id = :chain_id AND number = :number
                """
            ),
            {"chain_id": chain_id, "number": number},
        )

    async def asset(
        self,
        chain_id: int,
        *,
        symbol: str = "USDC",
        decimals: int = 6,
        contract: str | None = None,
    ) -> int:
        row = await self._conn.execute(
            sa.text(
                """
                INSERT INTO assets (chain_id, contract_address, symbol, decimals,
                                    is_native, is_enabled)
                VALUES (:chain_id, :contract, :symbol, :decimals, false, true)
                ON CONFLICT (chain_id, contract_address) DO UPDATE
                    SET symbol = EXCLUDED.symbol
                RETURNING id
                """
            ),
            {
                "chain_id": chain_id,
                "contract": contract or _address(f"token-{chain_id}-{symbol}"),
                "symbol": symbol,
                "decimals": decimals,
            },
        )
        return int(row.scalar_one())

    async def product(
        self, *, kind: E.ProductKind = E.ProductKind.ONE_OFF, subscription_days: int | None = None
    ) -> int:
        n = self._next()
        row = await self._conn.execute(
            sa.text(
                """
                INSERT INTO products (sku, title, price_usd, kind, content_ref,
                                      subscription_days, active)
                VALUES (:sku, :title, 10.00, CAST(:kind AS product_kind), :ref,
                        :days, true)
                RETURNING id
                """
            ),
            {
                "sku": f"sku-{n}",
                "title": f"Product {n}",
                "kind": str(kind),
                "ref": f"file-{n}",
                "days": subscription_days,
            },
        )
        return int(row.scalar_one())

    async def user(self) -> int:
        n = self._next()
        row = await self._conn.execute(
            sa.text("INSERT INTO users (tg_id, lang) VALUES (:tg_id, 'en') RETURNING id"),
            {"tg_id": 100_000 + n},
        )
        return int(row.scalar_one())

    async def hd_account(self) -> int:
        if self._hd_account_id is not None:
            return self._hd_account_id
        row = await self._conn.execute(
            sa.text(
                """
                INSERT INTO hd_accounts (label, xpub_fingerprint, path_prefix, next_index)
                VALUES ('test', 'deadbeef', 'm/44''/60''/0''', 0)
                RETURNING id
                """
            )
        )
        self._hd_account_id = int(row.scalar_one())
        return self._hd_account_id

    async def mark_funded(self, address_id: int) -> None:
        """Money has arrived on this address (TZ 5.1 — ``ever_funded`` is forever).

        Written as one UPDATE touching three columns because the CHECKs in
        migration 0001 couple them: ``free_state_clean`` forbids ``ever_funded``
        on a ``free`` row and ``funds_imply_ever_funded`` forbids a
        ``first_seen_funds_at`` without the flag. Setting them one at a time
        fails, which is the schema doing its job and not something a test helper
        should have to rediscover.
        """
        await self._conn.execute(
            sa.text(
                """
                UPDATE receive_addresses
                   SET status = 'funded',
                       ever_funded = true,
                       first_seen_funds_at = COALESCE(first_seen_funds_at, now())
                 WHERE id = :id
                """
            ),
            {"id": address_id},
        )

    async def mark_swept(self, address_id: int) -> None:
        """The owner moved the funds to cold storage offline (TZ 5.1).

        In production this UPDATE is the deriver's — no other role may write
        ``receive_addresses`` (TZ 5.8/T1.2). Here it is the test standing in for
        the offline half of the sweep, which is the part that by design has no
        code at all.
        """
        await self._conn.execute(
            sa.text(
                """
                UPDATE receive_addresses
                   SET status = 'swept',
                       ever_funded = true,
                       first_seen_funds_at = COALESCE(first_seen_funds_at, now()),
                       swept_at = now()
                 WHERE id = :id
                """
            ),
            {"id": address_id},
        )

    async def address(self, hd_account_id: int, *, index: int) -> tuple[int, str]:
        """A free pool address. Reservation happens once an invoice exists."""
        addr = _address(f"receive-{hd_account_id}-{index}")
        row = await self._conn.execute(
            sa.text(
                """
                INSERT INTO receive_addresses (hd_account_id, derivation_index, address, status)
                VALUES (:hd_account_id, :index, :address, 'free')
                RETURNING id
                """
            ),
            {"hd_account_id": hd_account_id, "index": index, "address": addr},
        )
        return int(row.scalar_one()), addr

    async def invoice(
        self,
        *,
        user_id: int,
        product_id: int,
        chain_id: int,
        asset_id: int,
        address_id: int,
        amount_due_raw: Decimal | int,
        amount_due_usd: Decimal | str = "10",
        rate_snapshot: Decimal | str = "1",
        status: E.InvoiceStatus = E.InvoiceStatus.AWAITING,
        age: dt.timedelta = dt.timedelta(minutes=30),
        expires_in: dt.timedelta = dt.timedelta(minutes=15),
        topup_window: dt.timedelta = dt.timedelta(hours=24),
        rate_lock: dt.timedelta | None = None,
        reserved_from_block: int = 0,
        policy_version: str = "test-policy",
    ) -> uuid.UUID:
        """One invoice, with its address reserved to it.

        ``age`` and ``expires_in`` are relative to now and are how a test says
        "this invoice's top-up window has already closed" without sleeping:
        ``created_at`` has to be written explicitly because the CHECKs require
        ``created_at < expires_at <= topup_window_until``, so an expired invoice
        cannot be built by moving the deadline alone.

        ``rate_lock`` is the offset of ``rate_locked_until`` from ``created_at``,
        and defaults to ``expires_at`` — which is how invoices are issued in
        practice, the quote and the invoice having the same life. It is a
        separate knob because TZ 5.5 gives the two deadlines different jobs (see
        :func:`settler.service.expire_stale_invoices`), and a test for the rate
        lock that could only move it by moving the expiry would not be testing
        the rate lock.
        """
        invoice_id = uuid.uuid4()
        created_at = dt.datetime.now(dt.UTC) - age
        expires_at = created_at + expires_in
        rate_locked_until = expires_at if rate_lock is None else created_at + rate_lock
        # The address is read back rather than passed in because the MAC is
        # taken over the string in `receive_addresses.address` exactly as
        # stored, EIP-55 case included (core/invoicing/integrity.py). A caller
        # that had to supply it separately could supply a different one, and the
        # resulting invoice would fail its own MAC for a reason that has nothing
        # to do with the property under test.
        address = (
            await self._conn.execute(
                sa.text("SELECT address FROM receive_addresses WHERE id = :id"),
                {"id": address_id},
            )
        ).scalar_one()
        integrity_mac = compute_mac(
            TEST_INTEGRITY_KEY,
            invoice_id=invoice_id,
            chain_id=chain_id,
            asset_id=asset_id,
            address=address,
            amount_due_raw=Decimal(amount_due_raw),
            expires_at=expires_at,
        )
        await self._conn.execute(
            sa.text(
                """
                INSERT INTO invoices (id, user_id, product_id, chain_id, asset_id, address_id,
                                      amount_due_raw, amount_due_usd, rate_snapshot,
                                      rate_locked_until, status, expires_at,
                                      topup_window_until, created_at, integrity_mac,
                                      public_token, policy_version)
                VALUES (:id, :user_id, :product_id, :chain_id, :asset_id, :address_id,
                        :amount_due_raw, :amount_due_usd, :rate_snapshot,
                        :rate_locked_until, CAST(:status AS invoice_status), :expires_at,
                        :topup_window_until, :created_at,
                        decode(:mac, 'hex'), :public_token, :policy_version)
                """
            ),
            {
                "id": invoice_id,
                "rate_locked_until": rate_locked_until,
                "user_id": user_id,
                "product_id": product_id,
                "chain_id": chain_id,
                "asset_id": asset_id,
                "address_id": address_id,
                "amount_due_raw": Decimal(amount_due_raw),
                "amount_due_usd": Decimal(amount_due_usd),
                "rate_snapshot": Decimal(rate_snapshot),
                "status": str(status),
                "expires_at": expires_at,
                "topup_window_until": expires_at + topup_window,
                "created_at": created_at,
                "mac": integrity_mac.hex(),
                "public_token": uuid.uuid4().hex,
                "policy_version": policy_version,
            },
        )
        await self._conn.execute(
            sa.text(
                """
                UPDATE receive_addresses
                   SET status = 'reserved',
                       current_invoice_id = :invoice_id,
                       reserved_from_block = :reserved_from_block
                 WHERE id = :address_id
                """
            ),
            {
                "invoice_id": invoice_id,
                "address_id": address_id,
                "reserved_from_block": reserved_from_block,
            },
        )
        return invoice_id

    async def payment(
        self,
        *,
        chain_id: int,
        asset_id: int,
        address_id: int,
        invoice_id: uuid.UUID | None,
        amount_raw: Decimal | int,
        block_number: int,
        status: E.PaymentStatus = E.PaymentStatus.SEEN,
        anomaly: E.PaymentAnomaly | None = None,
        log_index: int | None = None,
        tx_hash: str | None = None,
        confirmations_at_credit: int | None = None,
    ) -> int:
        n = self._next()
        row = await self._conn.execute(
            sa.text(
                """
                INSERT INTO payments (chain_id, tx_hash, log_index, block_number, address_id,
                                      invoice_id, asset_id, amount_raw, sender, status,
                                      anomaly, confirmations_at_credit)
                VALUES (:chain_id, :tx_hash, :log_index, :block_number, :address_id,
                        :invoice_id, :asset_id, :amount_raw, :sender,
                        CAST(:status AS payment_status),
                        CAST(:anomaly AS payment_anomaly), :confirmations)
                RETURNING id
                """
            ),
            {
                "chain_id": chain_id,
                "tx_hash": tx_hash or _hash(f"tx-{n}"),
                "log_index": n if log_index is None else log_index,
                "block_number": block_number,
                "address_id": address_id,
                "invoice_id": invoice_id,
                "asset_id": asset_id,
                "amount_raw": Decimal(amount_raw),
                "sender": _address(f"sender-{n}"),
                "status": str(status),
                "anomaly": None if anomaly is None else str(anomaly),
                "confirmations": confirmations_at_credit,
            },
        )
        return int(row.scalar_one())

    async def scenario(
        self,
        *,
        amount_due_raw: Decimal | int = 10_000_000,
        amount_due_usd: str = "10",
        rate_snapshot: str = "1",
        decimals: int = 6,
        min_confirmations: int = 3,
        credit_threshold_usd: Decimal | int = 20,
        head_block: int = 100,
        finalized_block: int | None = 95,
        subscription_days: int | None = None,
        topup_window: dt.timedelta = dt.timedelta(hours=24),
        age: dt.timedelta = dt.timedelta(minutes=30),
        expires_in: dt.timedelta = dt.timedelta(minutes=15),
        rate_lock: dt.timedelta | None = None,
    ) -> Scenario:
        """The whole graph for the common case: one buyer, one invoice."""
        chain_id = await self.chain(
            min_confirmations=min_confirmations,
            credit_threshold_usd=credit_threshold_usd,
            last_indexed_block=head_block,
        )
        if finalized_block is not None:
            await self.finalize(chain_id, finalized_block)
        asset_id = await self.asset(chain_id, decimals=decimals)
        product_id = await self.product(
            kind=E.ProductKind.SUBSCRIPTION if subscription_days else E.ProductKind.ONE_OFF,
            subscription_days=subscription_days,
        )
        user_id = await self.user()
        hd_id = await self.hd_account()
        address_id, address = await self.address(hd_id, index=self._next())
        invoice_id = await self.invoice(
            user_id=user_id,
            product_id=product_id,
            chain_id=chain_id,
            asset_id=asset_id,
            address_id=address_id,
            amount_due_raw=amount_due_raw,
            amount_due_usd=amount_due_usd,
            rate_snapshot=rate_snapshot,
            topup_window=topup_window,
            age=age,
            expires_in=expires_in,
            rate_lock=rate_lock,
        )
        return Scenario(
            chain_id=chain_id,
            asset_id=asset_id,
            product_id=product_id,
            user_id=user_id,
            address_id=address_id,
            address=address,
            invoice_id=invoice_id,
            amount_due_raw=Decimal(amount_due_raw),
            decimals=decimals,
            head_block=head_block,
        )


@pytest.fixture
def world(conn: AsyncConnection) -> World:
    return World(conn)


# ---------------------------------------------------------------------------
# Deterministic fake identifiers
# ---------------------------------------------------------------------------
#
# The schema CHECKs the *shape* of hashes and addresses (`^0x[0-9a-f]{64}$`,
# `^0x[0-9a-fA-F]{40}$`), so tests need well-formed values. Derived from a label
# by hashing rather than written by hand: a hand-written constant reused by
# accident in two fixtures collides with a UNIQUE index and produces a failure
# that looks like a bug in the settler.


def _hash(label: str) -> str:
    return "0x" + hashlib.sha256(label.encode()).hexdigest()


def _address(label: str) -> str:
    return "0x" + hashlib.sha256(label.encode()).hexdigest()[:40]


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------


def counter_value(metric: object) -> float:
    """Current value of an unlabelled Prometheus counter.

    Read through ``collect()`` rather than the private ``_value`` so that the
    assertion goes through the same path the ``/metrics`` endpoint does. Tests
    compare a delta, never an absolute: the collectors are process-global and
    other tests in the same session have already moved them.
    """
    for family in metric.collect():  # type: ignore[attr-defined]
        for sample in family.samples:
            if sample.name.endswith("_total") and not sample.labels:
                return float(sample.value)
    return 0.0


def sample_value(metric: object, name_suffix: str = "", **labels: str) -> float:
    """Current value of one labelled sample.

    Same reasoning as :func:`counter_value` — read through ``collect()`` so the
    assertion travels the path ``/metrics`` travels — extended to families with
    labels, which is every metric the admin commands touch. Returns ``0.0`` for a
    label combination that has never been observed, matching how Prometheus
    itself treats an unseen child.
    """
    for family in metric.collect():  # type: ignore[attr-defined]
        for sample in family.samples:
            if name_suffix and not sample.name.endswith(name_suffix):
                continue
            if all(sample.labels.get(k) == v for k, v in labels.items()):
                return float(sample.value)
    return 0.0


async def count(conn: AsyncConnection, table: str, where: str = "TRUE", **params: object) -> int:
    row = await conn.execute(sa.text(f"SELECT count(*) FROM {table} WHERE {where}"), params)
    return int(row.scalar_one())


async def invoice_status(conn: AsyncConnection, invoice_id: uuid.UUID) -> str:
    row = await conn.execute(
        sa.text("SELECT status::text FROM invoices WHERE id = :id"), {"id": invoice_id}
    )
    return str(row.scalar_one())


async def payment_status(conn: AsyncConnection, payment_id: int) -> str:
    row = await conn.execute(
        sa.text("SELECT status::text FROM payments WHERE id = :id"), {"id": payment_id}
    )
    return str(row.scalar_one())
