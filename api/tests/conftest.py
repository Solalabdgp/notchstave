"""Test rig for the api: the real app, the real middleware, a real Postgres.

Three decisions, and each is what makes a failure here mean something.

**The application is the real one.** Every test drives
:func:`api.main.create_app` through :class:`starlette.testclient.TestClient`, so
the security-headers middleware, the exception handlers, the static mount and
FastAPI's own validation are all in the path. The alternative — calling
``await invoice_page(token, deps)`` directly — passes happily against an app
that never registered the CSP middleware, against an ``IntegrityFailure`` that
falls through to a 500, and against a route mounted at the wrong path. All three
are real ways to ship a payment page that leaks or breaks.

**The database is real and so are the invoices in it.** Invoices are created by
:func:`core.invoicing.service.create_invoice` through the ``buy`` helper the
invoicing suite already uses, not by an ``INSERT`` with a plausible-looking
``integrity_mac``. That matters more here than anywhere else in the repo: what
the api is being tested on is that it refuses to render an invoice whose MAC
does not verify, and a fixture that wrote its own MAC would be testing the
fixture. The one test that *wants* a bad MAC corrupts a real row afterwards.

**The dependencies are injected, never monkeypatched.**
:class:`~api.deps.ApiDependencies` is what :func:`api.main.create_app` takes, so
a test picks its deriver and its Telegram secret by constructing the object.
Nothing here reaches into a module global, which is what lets two apps with
different postures — a verifying deriver and ``MAC_ONLY`` — exist in one test
session without seeing each other's wiring.

The object-graph builders come from ``core/invoicing/tests/conftest.py`` by
import rather than by copy, for the reason that file gives at length: "just
insert an invoice" is fifteen statements against a schema with enough CHECKs
that a second copy would drift from the migrations independently.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import psycopg
import pytest
from starlette.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.config import ApiConfig  # noqa: E402
from api.deps import ApiDependencies, psycopg_connector  # noqa: E402
from api.main import create_app  # noqa: E402
from api.telegram import WebAppSecret, derive_webapp_secret  # noqa: E402
from core.db import enums as E  # noqa: E402
from core.invoicing.integrity import IntegrityKey  # noqa: E402
from core.invoicing.service import MAC_ONLY, AddressDeriver, InvoiceView, MacOnly  # noqa: E402
from core.invoicing.tests.conftest import (  # noqa: E402
    _DATA_TABLES,
    TEST_INTEGRITY_KEY,
    FakeDeriver,
    Shop,
    World,
    buy,
    database_url,
    psycopg_dsn,
)

__all__ = [
    "BOT_TOKEN",
    "Rig",
    "sign_init_data",
]

#: Shape-valid and obviously fake, matching ``bot/tests/conftest.py``. The
#: WebApp secret is derived from it exactly as production derives it from the
#: real token, so what the suite verifies is the real key schedule and not a
#: 32-byte constant that happens to be the right length.
BOT_TOKEN = "42:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


# ---------------------------------------------------------------------------
# Schema, connection, world
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def _schema() -> None:
    """Bring the database to head, unconditionally.

    Same choice as ``core/invoicing/tests/conftest.py`` and for the same reason:
    "the schema exists" and "the schema is current" stopped being the same
    statement once migrations kept arriving, and a skipped upgrade fails later
    with an integrity error that reads like a bug in the service.
    """
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", database_url())
    command.upgrade(cfg, "head")


@pytest.fixture
def conn() -> Iterator[psycopg.Connection[Any]]:
    """The *fixture's* connection: builds the world, then commits it.

    ``autocommit=False`` because :func:`core.invoicing.service.create_invoice`
    is written to run inside the caller's transaction. Everything a test builds
    must be committed before it calls the client, since the application opens
    its own connections (that is what production does) and an uncommitted row is
    invisible to them — and, worse, an open write transaction here would make
    the app's connection block rather than fail, turning a missing ``commit()``
    into a hang instead of an assertion error. The helpers below all commit.
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


@pytest.fixture
def world(conn: psycopg.Connection[Any]) -> World:
    return World(conn)


@pytest.fixture
def deriver() -> FakeDeriver:
    return FakeDeriver()


@pytest.fixture
def key() -> IntegrityKey:
    return TEST_INTEGRITY_KEY


# ---------------------------------------------------------------------------
# The application under test
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rig:
    """A live client plus the dependencies it was built from."""

    client: TestClient
    deps: ApiDependencies


@pytest.fixture
def build_rig(
    key: IntegrityKey, deriver: FakeDeriver
) -> Iterator[Callable[..., Rig]]:
    """Factory for a real app. Every knob a test might want to change is here.

    A factory rather than a plain ``client`` fixture because the postures worth
    testing differ by construction: ``MAC_ONLY`` versus a verifying deriver is
    exactly the difference TZ section 9 draws between what the api can check and
    what only the deriver can, and ``webapp_secret=None`` is the misconfigured
    deployment that must answer 503 rather than 401.
    """
    clients: list[TestClient] = []

    def make(
        *,
        address_deriver: AddressDeriver | MacOnly | None = None,
        # Two parameters rather than one nullable parameter with a sentinel: the
        # interesting case is "this deployment has no Telegram credential", and
        # spelling that `telegram=False` reads as the deliberate choice it is,
        # where `webapp_secret=None` reads like a test that forgot to pass one.
        telegram: bool = True,
        webapp_secret: WebAppSecret | None = None,
        config: ApiConfig | None = None,
    ) -> Rig:
        resolved_config = config or ApiConfig(database_url=database_url())
        secret: WebAppSecret | None = None
        if telegram:
            secret = webapp_secret or derive_webapp_secret(BOT_TOKEN)
        deps = ApiDependencies(
            config=resolved_config,
            connect=psycopg_connector(resolved_config),
            integrity_key=key,
            deriver=deriver if address_deriver is None else address_deriver,
            webapp_secret=secret,
        )
        # `raise_server_exceptions=False` so that a route which lets an exception
        # escape produces a 500 response the test can assert on, instead of the
        # exception surfacing in the test and looking like a broken fixture. The
        # point of several tests below is precisely that nothing escapes.
        client = TestClient(create_app(deps), raise_server_exceptions=False)
        clients.append(client)
        return Rig(client=client, deps=deps)

    yield make

    for client in clients:
        client.close()


@pytest.fixture
def rig(build_rig: Callable[..., Rig]) -> Rig:
    """The default posture: a verifying deriver and a configured Telegram secret.

    The deriver is real (well, ``FakeDeriver`` — a hash where the curve should
    be, see the invoicing suite) rather than ``MAC_ONLY``, so the default path
    through these tests exercises both T1 checks. Production runs ``MAC_ONLY``
    and there are tests for that specifically; making it the default here would
    mean the address-derivation check had no coverage at all from this suite.
    """
    return build_rig()


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Seeded:
    """One committed invoice and the shop it came from."""

    view: InvoiceView
    shop: Shop

    @property
    def token(self) -> str:
        return self.view.public_token

    @property
    def invoice_id(self) -> uuid.UUID:
        return self.view.invoice_id


@pytest.fixture
def seed(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> Callable[..., Seeded]:
    """Build a shop, press ``/buy`` once, commit. Returns the verified view."""

    def make(*, head_block: int = 100, **kwargs: Any) -> Seeded:
        shop = world.shop(pooled_addresses=4, deriver=deriver, head_block=head_block)
        view = buy(conn, deriver, key, shop, **kwargs)
        conn.commit()
        return Seeded(view=view, shop=shop)

    return make


@pytest.fixture
def pay(conn: psycopg.Connection[Any]) -> Callable[..., int]:
    """Insert one payment against an invoice and commit it.

    Raw SQL rather than a settler call: what the status endpoint is being tested
    on is that it reports the ledger, so the test needs to be able to write a
    ledger state the settler would take several steps to reach — a `seen`
    payment two blocks below the head, for instance — and assert the page says
    the right thing about it.
    """
    counter = [0]

    def make(
        *,
        seeded: Seeded,
        amount_raw: Decimal | int,
        block_number: int,
        status: E.PaymentStatus = E.PaymentStatus.SEEN,
        anomaly: E.PaymentAnomaly | None = None,
    ) -> int:
        counter[0] += 1
        n = counter[0]
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO payments (chain_id, tx_hash, log_index, block_number,
                                      address_id, invoice_id, asset_id, amount_raw,
                                      sender, status, anomaly, confirmations_at_credit)
                VALUES (%(chain_id)s, %(tx_hash)s, %(log_index)s, %(block_number)s,
                        %(address_id)s, %(invoice_id)s, %(asset_id)s, %(amount_raw)s,
                        %(sender)s, CAST(%(status)s AS payment_status),
                        CAST(%(anomaly)s AS payment_anomaly), %(confirmations)s)
                RETURNING id
                """,
                {
                    "chain_id": seeded.view.chain_id,
                    "tx_hash": "0x" + hashlib.sha256(f"tx-{n}".encode()).hexdigest(),
                    "log_index": n,
                    "block_number": block_number,
                    "address_id": seeded.view.address_id,
                    "invoice_id": seeded.view.invoice_id,
                    "asset_id": seeded.view.asset_id,
                    "amount_raw": Decimal(amount_raw),
                    "sender": "0x" + "ab" * 20,
                    "status": str(status),
                    "anomaly": None if anomaly is None else str(anomaly),
                    # The CHECK requires this whenever status is `credited`.
                    "confirmations": 3 if status == E.PaymentStatus.CREDITED else None,
                },
            )
            row = cur.fetchone()
            assert row is not None
        conn.commit()
        return int(row[0])

    return make


@pytest.fixture
def set_invoice_status(conn: psycopg.Connection[Any]) -> Callable[..., None]:
    """Move ``invoices.status`` directly and commit.

    The api reads the settler's verdict and never recomputes it (TZ section 4),
    so the way to test what the page says about a `manual_review` invoice is to
    put one in that state — not to build the settlement history that would get
    it there, which is the settler suite's job and is tested there.
    """

    def apply(invoice_id: uuid.UUID, status: E.InvoiceStatus) -> None:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE invoices SET status = CAST(%(s)s AS invoice_status) WHERE id = %(id)s",
                {"s": str(status), "id": invoice_id},
            )
        conn.commit()

    return apply


@pytest.fixture
def grant(conn: psycopg.Connection[Any]) -> Callable[..., None]:
    """Write the ``entitlements`` row — the last rung of the TZ 3.2 ladder."""

    def apply(seeded: Seeded) -> None:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO entitlements (user_id, product_id, invoice_id, granted_at)
                VALUES (%(user_id)s, %(product_id)s, %(invoice_id)s, now())
                """,
                {
                    "user_id": seeded.view.user_id,
                    "product_id": seeded.view.product_id,
                    "invoice_id": seeded.view.invoice_id,
                },
            )
        conn.commit()

    return apply


# ---------------------------------------------------------------------------
# Telegram initData
# ---------------------------------------------------------------------------


def sign_init_data(
    secret: WebAppSecret,
    fields: Mapping[str, str],
) -> str:
    """Produce a genuinely signed ``initData`` string.

    This is Telegram's algorithm run forwards, written out here rather than
    imported from :mod:`api.telegram`, so that the test does not verify a
    signature against the same code that produced it. If
    :func:`api.telegram.verify_init_data` and this function ever disagree about
    the data-check string — the sort order, the newline join, which field is
    removed — the suite fails instead of agreeing with itself.
    """
    check = "\n".join(f"{k}={fields[k]}" for k in sorted(fields))
    digest = hmac.new(secret.raw, check.encode("utf-8"), hashlib.sha256).hexdigest()
    return urlencode({**fields, "hash": digest})


def init_data_fields(
    *, user_id: int, auth_date: int, **extra: str
) -> dict[str, str]:
    """The field set a real Mini App sends, minus ``hash``."""
    return {
        "user": json.dumps(
            {"id": user_id, "first_name": "Test", "language_code": "en"},
            separators=(",", ":"),
        ),
        "auth_date": str(auth_date),
        **extra,
    }


def tma(init_data: str) -> dict[str, str]:
    """The ``Authorization`` header the endpoints expect."""
    return {"Authorization": f"tma {init_data}"}


__all__ += [
    "MAC_ONLY",
    "Rig",
    "Seeded",
    "init_data_fields",
    "tma",
]
