"""Test rig for the bot: the real Dispatcher, a fake Telegram, a real Postgres.

Three decisions, and each of them is what makes a failure here mean something.

**The dispatcher is real.** Updates are fed through
:meth:`aiogram.Dispatcher.feed_update`, so command parsing, router priority and
aiogram's dependency injection are all exercised as they are in production. The
alternative — calling ``cmd_buy(message, command, services)`` directly — passes
happily against ``Command("bui")``, against a router registered after the
catch-all text handler, and against a handler whose ``services`` argument
aiogram would never have filled in. Every one of those is a real way to ship a
bot that answers nothing.

**Telegram is replaced at the session boundary, not above it.**
:class:`RecordingSession` is a genuine :class:`aiogram.client.session.base
.BaseSession`, so ``message.answer(...)`` builds a real
:class:`~aiogram.methods.send_message.SendMessage`, applies the real default
``parse_mode``, and lands in :attr:`RecordingSession.calls` as the object that
would have gone over the wire. Assertions are therefore about what Telegram
receives, which is the only thing a buyer ever sees.

**The database is real; the two invoicing clients are not.**
:class:`~bot.repository.BotRepository` is raw SQL whose entire job is the
ownership predicate of TZ 5.8/T1.7 and three correlated aggregates — a mock of
it would prove only that the test author knows what the answer should be, which
is the same argument ``settler/tests/conftest.py`` makes at greater length. The
clients, by contrast, are ``LISTEN``/``NOTIFY`` round trips to a *deriver
process that is not running in this suite*; they are faked so that the refusal
ladder of :mod:`bot.handlers.buyer` can be driven through every class in
:mod:`core.invoicing.errors`, which is the thing under test on that side. The
clients' own protocol has its own tests in ``core/invoicing/tests``.

The object graph builders come from ``settler/tests/conftest.py`` by import.
Notchstave's schema is constrained enough that "just insert an invoice" is
fifteen statements, and a second copy of those would be a second thing to keep
in step with the migrations.
"""

from __future__ import annotations

import datetime as dt
import sys
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.base import BaseSession
from aiogram.enums import ParseMode
from aiogram.methods import SendDocument, SendMessage, TelegramMethod
from aiogram.methods.base import TelegramType
from aiogram.types import Chat, Message, Update, User
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bot.config import BotConfig  # noqa: E402
from bot.main import build_dispatcher  # noqa: E402
from bot.repository import BotRepository  # noqa: E402
from bot.services import BotServices  # noqa: E402
from core.invoicing.client import InvoiceClient  # noqa: E402
from core.invoicing.proof import DerivationProof, ProofClient  # noqa: E402
from core.invoicing.service import InvoiceView  # noqa: E402
from settler.admin.balances import BalanceSource  # noqa: E402
from settler.admin.ops import AdminOps  # noqa: E402
from settler.admin.reviews import PendingCase, ResolutionResult  # noqa: E402
from settler.tests.conftest import _DATA_TABLES, World, database_url  # noqa: E402

#: The owner of every test deployment. A number rather than a fixture value so
#: that a test asserting "this is denied" can pick any other number and be sure
#: it is not accidentally the owner.
OWNER_TG_ID = 4242
#: Anybody else.
BUYER_TG_ID = 777_001
OTHER_TG_ID = 777_002

#: Shape-valid and obviously fake. aiogram validates the token's *format* at
#: construction, so this cannot be "test".
FAKE_TOKEN = "42:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


# ---------------------------------------------------------------------------
# Schema and engine
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def _schema() -> None:
    """Build the schema once per session from the migrations that ship.

    Same fixture and the same reasoning as ``settler/tests/conftest.py``: not
    ``Base.metadata.create_all``, because the deferred foreign key of 0006 and
    the ``derivation_proof_requests`` CHECKs of 0008 exist only in the
    migrations, and idempotent because the compose file already ran
    ``alembic upgrade head``.
    """
    engine = sa.create_engine(database_url(), poolclass=NullPool)
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
    """A fresh engine and an empty database for every test.

    ``NullPool`` for the same reason the settler uses it: the repository opens
    one short transaction per call and a pooled connection would make "did this
    handler commit" a question about SQLAlchemy rather than about the code.
    """
    eng = create_async_engine(database_url(), poolclass=NullPool)
    async with eng.begin() as conn:
        await conn.execute(
            sa.text(f"TRUNCATE {', '.join(_DATA_TABLES)} RESTART IDENTITY CASCADE")
        )
    try:
        yield eng
    finally:
        await eng.dispose()


# ---------------------------------------------------------------------------
# The catalogue the handlers read
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Shop:
    """One chain, one asset, one product, one HD account — v1's whole world."""

    chain_id: int
    chain_name: str
    asset_id: int
    asset_symbol: str
    asset_decimals: int
    min_confirmations: int
    hd_account_id: int
    product_id: int
    product_sku: str
    product_title: str
    head_block: int


@pytest.fixture
async def shop(engine: AsyncEngine) -> Shop:
    """The catalogue, **committed** before the test body runs.

    Committed and not left open in the caller's transaction, because
    :class:`~bot.repository.BotRepository` opens its own connection per call —
    exactly as it does in production — and would not see uncommitted rows. This
    is the one place the bot suite has to differ from the settler's, where the
    code under test runs inside the test's own transaction.
    """
    async with engine.begin() as conn:
        world = World(conn)
        chain_id = await world.chain(min_confirmations=3, last_indexed_block=100)
        asset_id = await world.asset(chain_id, symbol="USDC", decimals=6)
        product_id = await world.product()
        hd_account_id = await world.hd_account()
        row = (
            await conn.execute(
                sa.text("SELECT sku, title FROM products WHERE id = :id"),
                {"id": product_id},
            )
        ).mappings().one()
    return Shop(
        chain_id=chain_id,
        chain_name=f"chain-{chain_id}",
        asset_id=asset_id,
        asset_symbol="USDC",
        asset_decimals=6,
        min_confirmations=3,
        hd_account_id=hd_account_id,
        product_id=product_id,
        product_sku=str(row["sku"]),
        product_title=str(row["title"]),
        head_block=100,
    )


async def make_user(engine: AsyncEngine, tg_id: int) -> int:
    """``users.id`` for a Telegram id, created if absent."""
    async with engine.begin() as conn:
        return int(
            (
                await conn.execute(
                    sa.text(
                        """
                        INSERT INTO users (tg_id, lang) VALUES (:tg_id, 'en')
                        ON CONFLICT (tg_id) DO UPDATE SET lang = users.lang
                        RETURNING id
                        """
                    ),
                    {"tg_id": tg_id},
                )
            ).scalar_one()
        )


async def make_invoice(
    engine: AsyncEngine,
    shop: Shop,
    *,
    user_id: int,
    index: int,
    status: str = "awaiting",
    amount_due_raw: int = 10_000_000,
    amount_due_usd: str = "10",
    age: dt.timedelta = dt.timedelta(minutes=5),
    expires_in: dt.timedelta = dt.timedelta(minutes=15),
) -> tuple[uuid.UUID, int]:
    """One invoice with its address reserved, committed. Returns ``(id, address_id)``."""
    from core.db import enums as E

    async with engine.begin() as conn:
        world = World(conn)
        address_id, _ = await world.address(shop.hd_account_id, index=index)
        invoice_id = await world.invoice(
            user_id=user_id,
            product_id=shop.product_id,
            chain_id=shop.chain_id,
            asset_id=shop.asset_id,
            address_id=address_id,
            amount_due_raw=amount_due_raw,
            amount_due_usd=amount_due_usd,
            status=E.InvoiceStatus(status),
            age=age,
            expires_in=expires_in,
        )
    return invoice_id, address_id


#: An EIP-55 checksummed address, so that a test asserting the message carries
#: the address "character for character" (TZ 3.1) is asserting about the case
#: too. Taken from the EIP-55 reference vectors rather than invented.
CHECKSUMMED_ADDRESS = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


def an_invoice_view(
    shop: Shop,
    *,
    user_id: int,
    invoice_id: uuid.UUID | None = None,
    address: str = CHECKSUMMED_ADDRESS,
    amount_due_raw: int = 12_500_000,
    status: str = "awaiting",
    expires_in: dt.timedelta = dt.timedelta(minutes=15),
) -> InvoiceView:
    """What a successful ``/buy`` round trip returns.

    Built by hand rather than read back from the database on purpose: in
    production this object never comes from a row the bot read — it comes from
    the deriver, already verified, over the reply channel (TZ 5.8/T1.1, T1.3).
    A fixture that fetched it from ``invoices`` would be testing a path that
    does not exist.
    """
    now = dt.datetime.now(dt.UTC)
    return InvoiceView(
        invoice_id=invoice_id or uuid.uuid4(),
        public_token=uuid.uuid4().hex,
        user_id=user_id,
        product_id=shop.product_id,
        chain_id=shop.chain_id,
        asset_id=shop.asset_id,
        address_id=1,
        address=address,
        hd_account_id=shop.hd_account_id,
        derivation_index=17,
        amount_due_raw=Decimal(amount_due_raw),
        amount_due_usd=Decimal("12.50"),
        rate_snapshot=Decimal("1"),
        rate_locked_until=now + expires_in,
        status=status,
        expires_at=now + expires_in,
        topup_window_until=now + expires_in + dt.timedelta(hours=24),
        created_at=now,
        integrity_mac=b"\x00" * 32,
        policy_version="test-policy",
        asset_symbol=shop.asset_symbol,
        asset_decimals=shop.asset_decimals,
        asset_contract="0x" + "11" * 20,
        asset_is_native=False,
    )


def a_proof(
    invoice_id: uuid.UUID,
    *,
    address: str = CHECKSUMMED_ADDRESS,
    fingerprint: str = "deadbeef",
    path: str = "m/44'/60'/0'/0/17",
) -> DerivationProof:
    """What a successful ``/verify`` round trip returns.

    The MAC is not recomputed here because the bot never checks it — the check
    lives in :meth:`core.invoicing.proof.ProofClient._interpret`, which is
    faked away in this suite and tested where it lives. What the bot owes is
    that every field reaches the message, which is what the tests assert.
    """
    return DerivationProof(
        invoice_id=invoice_id,
        xpub_fingerprint=fingerprint,
        derivation_path=path,
        derivation_index=17,
        address=address,
        proof_mac=b"\x00" * 32,
    )


# ---------------------------------------------------------------------------
# Telegram, replaced at the session boundary
# ---------------------------------------------------------------------------


class RecordingSession(BaseSession):
    """A ``BaseSession`` that answers every call locally and keeps the request.

    Subclassing the session rather than patching ``Bot.send_message`` means the
    method objects in :attr:`calls` are the ones aiogram built: the default
    ``parse_mode`` has been applied, ``chat_id`` has been filled in from the
    message, and a ``BufferedInputFile`` is attached the way it would be on the
    wire. Asserting on those is asserting on what Telegram would receive.
    """

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[TelegramMethod[Any]] = []
        self._message_id = 1000

    async def close(self) -> None:
        return None

    async def make_request(
        self,
        bot: Bot,
        method: TelegramMethod[TelegramType],
        timeout: int | None = None,
    ) -> TelegramType:
        self.calls.append(method)
        self._message_id += 1

        if isinstance(method, (SendMessage, SendDocument)):
            text = method.text if isinstance(method, SendMessage) else (method.caption or "")
            reply = Message(
                message_id=self._message_id,
                date=dt.datetime.now(dt.UTC),
                chat=Chat(id=int(cast(int, method.chat_id)), type="private"),
                text=text,
            ).as_(bot)
            return cast(TelegramType, reply)

        # `delete_webhook`, `get_me` and friends. Nothing in the handler suite
        # reads these; returning True keeps a stray call from raising instead of
        # being visible in `calls`.
        return cast(TelegramType, True)

    async def stream_content(
        self,
        url: str,
        headers: dict[str, Any] | None = None,
        timeout: int = 30,
        chunk_size: int = 65536,
        raise_for_status: bool = True,
    ) -> AsyncGenerator[bytes, None]:  # pragma: no cover - nothing downloads files
        yield b""

    # -- assertions helpers ------------------------------------------------

    @property
    def texts(self) -> list[str]:
        """Every message body sent, in order. Captions count as bodies."""
        out: list[str] = []
        for call in self.calls:
            if isinstance(call, SendMessage):
                out.append(call.text)
            elif isinstance(call, SendDocument):
                out.append(call.caption or "")
        return out

    @property
    def last(self) -> str:
        assert self.texts, "no message was sent"
        return self.texts[-1]

    @property
    def documents(self) -> list[SendDocument]:
        return [c for c in self.calls if isinstance(c, SendDocument)]


# ---------------------------------------------------------------------------
# The two invoicing round trips, faked
# ---------------------------------------------------------------------------


@dataclass
class FakeInvoiceClient:
    """Stands in for the deriver queue of migration 0007.

    Records the keyword arguments it was called with — which is how the "each
    command makes the right service call" tests check that ``/buy`` forwarded
    the *resolved* product, asset and HD account rather than something it made
    up — and raises whatever :attr:`error` holds, so the refusal ladder can be
    driven through every class in :mod:`core.invoicing.errors`.
    """

    view: InvoiceView | None = None
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def acreate_invoice(
        self,
        *,
        user_id: int,
        product_id: int,
        chain_id: int,
        asset_id: int,
        hd_account_id: int,
        timeout: float | None = None,
    ) -> InvoiceView:
        self.calls.append(
            {
                "user_id": user_id,
                "product_id": product_id,
                "chain_id": chain_id,
                "asset_id": asset_id,
                "hd_account_id": hd_account_id,
                "timeout": timeout,
            }
        )
        if self.error is not None:
            raise self.error
        assert self.view is not None, "FakeInvoiceClient needs a view or an error"
        return self.view


@dataclass
class FakeProofClient:
    """Stands in for the ``derivation_proof_requests`` queue of migration 0008.

    Notably it does **not** filter by ``user_id`` itself. That is the point of
    the IDOR test: the bot's job is to pass the caller's ``users.id`` down, and
    the fake asserts it arrived, because in production the ownership predicate
    lives inside :func:`core.invoicing.service.verify_invoice_address` on the
    deriver's side (TZ 5.8/T1.7) and a bot-side filter would be a second copy of
    a rule that must have exactly one.
    """

    proof: DerivationProof | None = None
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def arequest_proof(
        self,
        *,
        user_id: int,
        invoice_id: uuid.UUID,
        timeout: float | None = None,
    ) -> DerivationProof:
        self.calls.append(
            {"user_id": user_id, "invoice_id": invoice_id, "timeout": timeout}
        )
        if self.error is not None:
            raise self.error
        assert self.proof is not None, "FakeProofClient needs a proof or an error"
        return self.proof


@dataclass
class FakeAdminOps:
    """Stands in for :class:`settler.admin.ops.AdminOps`.

    The money logic behind it has its own suite against a real database
    (``settler/tests/test_admin_resolve.py``, ``test_reconcile.py``,
    ``test_sweeplist.py``). What the bot owes is narrower and is what this
    records: that a non-owner never reaches these methods at all, and that an
    owner reaches them with the arguments they typed.
    """

    pending_cases: tuple[PendingCase, ...] = ()
    resolution: ResolutionResult | None = None
    resolve_error: Exception | None = None
    reconcile_result: Any = None
    reconcile_error: Exception | None = None
    sweep_result: Any = None
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    async def pending(self, *, limit: int = 200) -> tuple[PendingCase, ...]:
        self.calls.append(("pending", {"limit": limit}))
        return self.pending_cases

    async def resolve(
        self,
        review_id: int,
        resolution: str,
        operator_id: int,
        comment: str | None = None,
        *,
        confirmation_code: str | None = None,
    ) -> ResolutionResult:
        self.calls.append(
            (
                "resolve",
                {
                    "review_id": review_id,
                    "resolution": resolution,
                    "operator_id": operator_id,
                    "comment": comment,
                    "confirmation_code": confirmation_code,
                },
            )
        )
        if self.resolve_error is not None:
            raise self.resolve_error
        assert self.resolution is not None
        return self.resolution

    async def reconcile(self, **kwargs: Any) -> Any:
        self.calls.append(("reconcile", kwargs))
        if self.reconcile_error is not None:
            raise self.reconcile_error
        return self.reconcile_result

    async def sweeplist(self, **kwargs: Any) -> Any:
        self.calls.append(("sweeplist", kwargs))
        return self.sweep_result


@dataclass
class FakeBalanceSource:
    """Enough of :class:`settler.admin.balances.BalanceSource` to be present.

    Its *presence* is what the admin handlers branch on; the balances themselves
    are consumed inside :class:`FakeAdminOps`, which never calls it.
    """

    async def balance_of(self, *, address: str, asset: Any) -> Decimal:
        return Decimal(0)  # pragma: no cover - AdminOps is faked above it


# ---------------------------------------------------------------------------
# The harness
# ---------------------------------------------------------------------------


@dataclass
class Harness:
    """One wired bot, plus the two things every test does with it."""

    bot: Bot
    dispatcher: Dispatcher
    session: RecordingSession
    services: BotServices
    invoices: FakeInvoiceClient
    proofs: FakeProofClient
    admin: FakeAdminOps
    _update_id: int = 0

    async def send(self, text: str, *, tg_id: int = BUYER_TG_ID) -> str:
        """Feed one text message through the real dispatcher, return the reply.

        Returns the *last* body sent, because every handler in this bot answers
        exactly once; a test that expects two messages reads
        ``harness.session.texts`` instead.
        """
        before = len(self.session.texts)
        self._update_id += 1
        update = Update(
            update_id=self._update_id,
            message=Message(
                message_id=self._update_id,
                date=dt.datetime.now(dt.UTC),
                chat=Chat(id=tg_id, type="private"),
                from_user=User(id=tg_id, is_bot=False, first_name="Test"),
                text=text,
            ),
        )
        await self.dispatcher.feed_update(self.bot, update)
        sent = self.session.texts[before:]
        return sent[-1] if sent else ""

    @property
    def texts(self) -> list[str]:
        return self.session.texts


@pytest.fixture
async def harness(engine: AsyncEngine, shop: Shop) -> AsyncGenerator[Harness, None]:
    """The default deployment: owner configured, admin ops available."""
    async for h in _harness(engine, shop, owner_tg_id=OWNER_TG_ID, with_admin=True):
        yield h


@pytest.fixture
async def ownerless(engine: AsyncEngine, shop: Shop) -> AsyncGenerator[Harness, None]:
    """A deployment with ``BOT_OWNER_TG_ID`` unset — the fresh-checkout state."""
    async for h in _harness(engine, shop, owner_tg_id=None, with_admin=False):
        yield h


async def _harness(
    engine: AsyncEngine,
    shop: Shop,
    *,
    owner_tg_id: int | None,
    with_admin: bool,
) -> AsyncGenerator[Harness, None]:
    session = RecordingSession()
    bot = Bot(
        token=FAKE_TOKEN,
        session=session,
        # Mirrors `bot.main.main`. Without it `bot.texts`' HTML would be sent as
        # plain text, and a test asserting on a rendered address would pass
        # while a buyer saw `<code>0x…</code>`.
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )

    invoices = FakeInvoiceClient()
    proofs = FakeProofClient()
    admin = FakeAdminOps()

    services = BotServices(
        config=BotConfig(
            owner_tg_id=owner_tg_id,
            chain_id=shop.chain_id,
            asset_symbol=shop.asset_symbol,
            request_timeout_seconds=1.0,
            invoice_page_base_url="https://pay.example",
            explorer_base_url="https://explorer.example",
        ),
        repo=BotRepository(engine),
        # The three casts are the seam this suite is built on. `BotServices`
        # names concrete classes because production has exactly one
        # implementation of each and a Protocol per collaborator would be three
        # more names for no second caller; the fakes above implement the methods
        # the handlers actually use, and `cast` says so in one visible place
        # rather than by loosening the dataclass.
        invoices=cast(InvoiceClient, invoices),
        proofs=cast(ProofClient, proofs),
        admin=cast(AdminOps, admin) if with_admin else None,
        balances=cast(BalanceSource, FakeBalanceSource()) if with_admin else None,
    )

    dispatcher = build_dispatcher(services)
    try:
        yield Harness(
            bot=bot,
            dispatcher=dispatcher,
            session=session,
            services=services,
            invoices=invoices,
            proofs=proofs,
            admin=admin,
        )
    finally:
        await bot.session.close()
