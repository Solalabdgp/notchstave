"""Every SQL statement the bot runs, and the short list of what it may write.

Same conventions as :mod:`settler.repository` — raw statements, because the
statements are the argument; the database's clock, because processes do not
agree on the time; explicit enum casts, because ``status = text`` is not an
operator PostgreSQL knows.

**What this process is allowed to do**, from migrations 0002/0003/0006, and it
is a short list on purpose (TZ section 4, 5.8/T1.2):

* ``users`` — read and write. The only table the bot creates rows in, and
  ``/start`` is the only thing that does it.
* ``products``, ``assets``, ``chains``, ``hd_accounts``, ``receive_addresses``,
  ``payments``, ``entitlements`` — **read only**.
* ``invoices`` — read and update, but *not* insert: migration 0006 moved
  issuance behind the deriver's role, which is why every ``/buy`` in this
  package goes through :class:`core.invoicing.client.InvoiceClient` rather than
  through a statement here.
* ``manual_reviews`` — read, for turning an invoice id into the review id the
  admin commands take. The *decision* is written by the settler's role through
  :class:`settler.admin.AdminOps`, never from here.

**No address leaves this module.** ``/status`` and ``/my`` deliberately do not
select ``receive_addresses.address``. TZ 5.3 requires ``deriver.verify`` before
any address reaches a human and this process has no xpub, so the only addresses
it can honestly show are the one that arrives verified from
:class:`~core.invoicing.client.InvoiceClient` and the one that comes back inside
a derivation proof (:mod:`core.invoicing.proof`). Not selecting the column at
all is a stronger guarantee than remembering not to render it — and it aligns
with TZ 5.8/T1.5, which wants the address on screen exactly once, in a message
that is never edited.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from decimal import Decimal

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from core.db import enums as E

__all__ = [
    "UserRow",
    "ProductRow",
    "AssetRow",
    "InvoiceStatusRow",
    "PurchaseRow",
    "OpenInvoiceRow",
    "OpenCaseRow",
    "BotRepository",
]

_LIVE = tuple(str(s) for s in E.LIVE_INVOICE_STATUSES)
_CREDITED = tuple(E.CREDITABLE_PAYMENT_STATUSES)


@dataclass(frozen=True, slots=True)
class UserRow:
    id: int
    tg_id: int
    #: True when ``/start`` created the row rather than finding it. Drives the
    #: difference between an onboarding message and a welcome back, and nothing
    #: else — never a permission.
    is_new: bool


@dataclass(frozen=True, slots=True)
class ProductRow:
    id: int
    sku: str
    title: str
    price_usd: Decimal
    kind: str
    subscription_days: int | None


@dataclass(frozen=True, slots=True)
class AssetRow:
    id: int
    chain_id: int
    symbol: str
    decimals: int
    chain_name: str
    min_confirmations: int


@dataclass(frozen=True, slots=True)
class InvoiceStatusRow:
    """What ``/status`` prints: "сколько пришло, сколько подтверждений, чего ждём".

    Deliberately carries no address — see the module docstring.
    """

    invoice_id: uuid.UUID
    status: str
    product_title: str
    product_sku: str
    amount_due_raw: Decimal
    amount_due_usd: Decimal
    asset_symbol: str
    asset_decimals: int
    chain_name: str
    min_confirmations: int
    expires_at: dt.datetime
    topup_window_until: dt.datetime
    created_at: dt.datetime
    public_token: str
    #: ``SUM(amount_raw)`` over confirmed/credited payments — the aggregate TZ
    #: 5.3 insists on, never an incremental counter.
    received_raw: Decimal
    #: Payments seen but not yet counted, and how far the least-confirmed of
    #: them has to go. ``None`` when nothing is in flight.
    pending_count: int
    pending_raw: Decimal
    least_confirmations: int | None

    @property
    def missing_raw(self) -> Decimal:
        gap = self.amount_due_raw - self.received_raw
        return gap if gap > 0 else Decimal(0)


@dataclass(frozen=True, slots=True)
class PurchaseRow:
    """One line of ``/my`` — a granted entitlement, live or revoked."""

    product_title: str
    product_sku: str
    kind: str
    invoice_id: uuid.UUID
    granted_at: dt.datetime
    expires_at: dt.datetime | None
    revoked_at: dt.datetime | None
    content_ref: str

    def is_active(self, now: dt.datetime) -> bool:
        if self.revoked_at is not None:
            return False
        return self.expires_at is None or self.expires_at > now


@dataclass(frozen=True, slots=True)
class OpenInvoiceRow:
    """One line of ``/my``'s "still waiting for payment" section."""

    invoice_id: uuid.UUID
    product_title: str
    status: str
    amount_due_usd: Decimal
    expires_at: dt.datetime


@dataclass(frozen=True, slots=True)
class OpenCaseRow:
    """An unresolved ``manual_reviews`` row, for ``/resolve <invoice_id> ...``."""

    review_id: int
    kind: str


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------

#: ``/start``. ``ON CONFLICT DO UPDATE`` rather than ``DO NOTHING``, so the
#: statement always returns a row and the caller never needs a second query for
#: the ordinary case of a returning user. ``xmax = 0`` is the standard way to
#: ask PostgreSQL "did this INSERT actually insert": on a conflict-update the
#: row carries the id of the transaction that locked it, on a fresh insert it is
#: zero.
#:
#: ``bot_blocked_at`` is cleared, and that is not housekeeping. TZ 5.5 has the
#: notifier stop sending to a chat that answered 403; a user pressing ``/start``
#: is Telegram's own proof that the block is gone, and it is the only signal
#: this system will ever get. Leaving the flag set would mute a buyer forever
#: because they once removed the bot.
SQL_UPSERT_USER = sa.text(
    """
    INSERT INTO users (tg_id, lang)
    VALUES (:tg_id, :lang)
    ON CONFLICT (tg_id) DO UPDATE
       SET lang = COALESCE(NULLIF(EXCLUDED.lang, ''), users.lang),
           bot_blocked_at = NULL
    RETURNING id, tg_id, (xmax = 0) AS is_new
    """
)

SQL_LIST_PRODUCTS = sa.text(
    """
    SELECT id, sku, title, price_usd, kind::text AS kind, subscription_days
      FROM products
     WHERE active
     ORDER BY price_usd, id
    """
)

#: Case-insensitive on the sku, because a sku is typed by hand into a chat and
#: ``/buy MONTHLY`` failing where ``/buy monthly`` works is a support ticket
#: rather than a security property. The uniqueness of skus is a database
#: constraint on the exact string; this lookup is deliberately more forgiving
#: than the constraint and can therefore never return two rows for one input
#: that the constraint would have allowed — ``uq_products_sku`` is on the plain
#: column, so two skus differing only in case are legal and ``LIMIT 1`` with a
#: deterministic order is what stops that from being a coin flip.
SQL_PRODUCT_BY_SKU = sa.text(
    """
    SELECT id, sku, title, price_usd, kind::text AS kind, subscription_days
      FROM products
     WHERE active AND lower(sku) = lower(:sku)
     ORDER BY sku, id
     LIMIT 1
    """
)

SQL_ASSET = sa.text(
    """
    SELECT a.id, a.chain_id, a.symbol, a.decimals,
           c.name AS chain_name, c.min_confirmations
      FROM assets a
      JOIN chains c ON c.chain_id = a.chain_id
     WHERE a.chain_id = :chain_id
       AND upper(a.symbol) = upper(:symbol)
       AND a.is_enabled
       AND c.is_enabled
     LIMIT 1
    """
)

SQL_ACTIVE_HD_ACCOUNT = sa.text(
    "SELECT id FROM hd_accounts WHERE is_active ORDER BY id LIMIT 1"
)

#: ``/status``. One statement, three aggregates, and the ``user_id`` predicate
#: is not optional: TZ 5.8/T1.7 wants a status request filtered by the verified
#: Telegram identity and not by the invoice id alone. A caller that forgets it
#: gets a syntax error rather than somebody else's invoice, because the
#: parameter is required by the statement.
#:
#: Confirmations are computed as ``last_indexed_block - block_number + 1`` from
#: the chain row rather than stored on the payment, for the reason TZ 5.4 gives
#: about reorgs: a stored depth is a number that was true once, and the whole
#: question ``/status`` answers is what is true now.
SQL_INVOICE_STATUS = sa.text(
    """
    SELECT i.id                AS invoice_id,
           i.status::text      AS status,
           p.title             AS product_title,
           p.sku               AS product_sku,
           i.amount_due_raw,
           i.amount_due_usd,
           a.symbol            AS asset_symbol,
           a.decimals          AS asset_decimals,
           c.name              AS chain_name,
           c.min_confirmations AS min_confirmations,
           i.expires_at,
           i.topup_window_until,
           i.created_at,
           i.public_token,
           COALESCE((
               SELECT sum(pay.amount_raw)
                 FROM payments pay
                WHERE pay.invoice_id = i.id
                  AND pay.status::text = ANY(:credited)
           ), 0)               AS received_raw,
           COALESCE((
               SELECT count(*)
                 FROM payments pay
                WHERE pay.invoice_id = i.id
                  AND pay.status::text = 'seen'
           ), 0)               AS pending_count,
           COALESCE((
               SELECT sum(pay.amount_raw)
                 FROM payments pay
                WHERE pay.invoice_id = i.id
                  AND pay.status::text = 'seen'
           ), 0)               AS pending_raw,
           (
               SELECT min(c.last_indexed_block - pay.block_number + 1)
                 FROM payments pay
                WHERE pay.invoice_id = i.id
                  AND pay.status::text = 'seen'
           )                   AS least_confirmations
      FROM invoices i
      JOIN products p ON p.id = i.product_id
      JOIN assets   a ON a.id = i.asset_id AND a.chain_id = i.chain_id
      JOIN chains   c ON c.chain_id = i.chain_id
     WHERE i.id = :invoice_id
       AND i.user_id = :user_id
    """
)

SQL_PURCHASES = sa.text(
    """
    SELECT p.title AS product_title, p.sku AS product_sku, p.kind::text AS kind,
           p.content_ref, e.invoice_id, e.granted_at, e.expires_at, e.revoked_at
      FROM entitlements e
      JOIN products p ON p.id = e.product_id
     WHERE e.user_id = :user_id
     ORDER BY e.granted_at DESC
     LIMIT :limit
    """
)

SQL_OPEN_INVOICES = sa.text(
    """
    SELECT i.id AS invoice_id, p.title AS product_title, i.status::text AS status,
           i.amount_due_usd, i.expires_at
      FROM invoices i
      JOIN products p ON p.id = i.product_id
     WHERE i.user_id = :user_id
       AND i.status::text = ANY(:live)
     ORDER BY i.created_at DESC
     LIMIT :limit
    """
)

#: TZ 3.4 spells ``/resolve`` with an *invoice* id; :func:`settler.admin
#: .resolve_manual_review` takes a *review* id, and its docstring says the bot
#: is what resolves one into the other. This is that statement. It can return
#: more than one row — an invoice can carry an underpayment case and a stray
#: token case at once — and the handler refuses rather than picking, because
#: guessing which case an owner meant is how the wrong one gets credited.
SQL_OPEN_CASES_FOR_INVOICE = sa.text(
    """
    SELECT id AS review_id, kind::text AS kind
      FROM manual_reviews
     WHERE invoice_id = :invoice_id
       AND resolved_at IS NULL
     ORDER BY id
    """
)


class BotRepository:
    """Short transactions over the shared async engine. Holds no state.

    Every method opens its own transaction and closes it, which is the right
    shape for a chat handler: the unit of work is one message, nothing here
    spans a network call to Telegram, and a handler that awaited an API call
    with a transaction open would hold a connection for as long as Telegram
    felt like taking.
    """

    __slots__ = ("_engine",)

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def upsert_user(self, tg_id: int, *, lang: str = "en") -> UserRow:
        async with self._engine.begin() as conn:
            row = (
                await conn.execute(SQL_UPSERT_USER, {"tg_id": tg_id, "lang": lang})
            ).mappings().one()
        return UserRow(id=int(row["id"]), tg_id=int(row["tg_id"]), is_new=bool(row["is_new"]))

    async def list_products(self) -> tuple[ProductRow, ...]:
        async with self._engine.begin() as conn:
            rows = (await conn.execute(SQL_LIST_PRODUCTS)).mappings().all()
        return tuple(_product(r) for r in rows)

    async def product_by_sku(self, sku: str) -> ProductRow | None:
        async with self._engine.begin() as conn:
            row = (await conn.execute(SQL_PRODUCT_BY_SKU, {"sku": sku})).mappings().first()
        return None if row is None else _product(row)

    async def asset(self, *, chain_id: int, symbol: str) -> AssetRow | None:
        async with self._engine.begin() as conn:
            row = (
                await conn.execute(SQL_ASSET, {"chain_id": chain_id, "symbol": symbol})
            ).mappings().first()
        if row is None:
            return None
        return AssetRow(
            id=int(row["id"]),
            chain_id=int(row["chain_id"]),
            symbol=str(row["symbol"]),
            decimals=int(row["decimals"]),
            chain_name=str(row["chain_name"]),
            min_confirmations=int(row["min_confirmations"]),
        )

    async def active_hd_account_id(self) -> int | None:
        async with self._engine.begin() as conn:
            return (await conn.execute(SQL_ACTIVE_HD_ACCOUNT)).scalar_one_or_none()

    async def invoice_status(
        self, *, user_id: int, invoice_id: uuid.UUID
    ) -> InvoiceStatusRow | None:
        """``None`` for "no such invoice", including "not this user's" (T1.7).

        One return value for both, deliberately: distinguishing them tells an
        enumeration attempt that its guess was real, which is the single bit it
        is fishing for.
        """
        async with self._engine.begin() as conn:
            row = (
                await conn.execute(
                    SQL_INVOICE_STATUS,
                    {
                        "invoice_id": invoice_id,
                        "user_id": user_id,
                        "credited": list(_CREDITED),
                    },
                )
            ).mappings().first()
        if row is None:
            return None
        least = row["least_confirmations"]
        return InvoiceStatusRow(
            invoice_id=row["invoice_id"],
            status=str(row["status"]),
            product_title=str(row["product_title"]),
            product_sku=str(row["product_sku"]),
            amount_due_raw=Decimal(row["amount_due_raw"]),
            amount_due_usd=Decimal(row["amount_due_usd"]),
            asset_symbol=str(row["asset_symbol"]),
            asset_decimals=int(row["asset_decimals"]),
            chain_name=str(row["chain_name"]),
            min_confirmations=int(row["min_confirmations"]),
            expires_at=row["expires_at"],
            topup_window_until=row["topup_window_until"],
            created_at=row["created_at"],
            public_token=str(row["public_token"]),
            received_raw=Decimal(row["received_raw"]),
            pending_count=int(row["pending_count"]),
            pending_raw=Decimal(row["pending_raw"]),
            least_confirmations=None if least is None else max(int(least), 0),
        )

    async def purchases(self, *, user_id: int, limit: int = 20) -> tuple[PurchaseRow, ...]:
        async with self._engine.begin() as conn:
            rows = (
                await conn.execute(SQL_PURCHASES, {"user_id": user_id, "limit": limit})
            ).mappings().all()
        return tuple(
            PurchaseRow(
                product_title=str(r["product_title"]),
                product_sku=str(r["product_sku"]),
                kind=str(r["kind"]),
                invoice_id=r["invoice_id"],
                granted_at=r["granted_at"],
                expires_at=r["expires_at"],
                revoked_at=r["revoked_at"],
                content_ref=str(r["content_ref"]),
            )
            for r in rows
        )

    async def open_invoices(self, *, user_id: int, limit: int = 10) -> tuple[OpenInvoiceRow, ...]:
        async with self._engine.begin() as conn:
            rows = (
                await conn.execute(
                    SQL_OPEN_INVOICES,
                    {"user_id": user_id, "live": list(_LIVE), "limit": limit},
                )
            ).mappings().all()
        return tuple(
            OpenInvoiceRow(
                invoice_id=r["invoice_id"],
                product_title=str(r["product_title"]),
                status=str(r["status"]),
                amount_due_usd=Decimal(r["amount_due_usd"]),
                expires_at=r["expires_at"],
            )
            for r in rows
        )

    async def open_cases_for_invoice(self, invoice_id: uuid.UUID) -> tuple[OpenCaseRow, ...]:
        async with self._engine.begin() as conn:
            rows = (
                await conn.execute(SQL_OPEN_CASES_FOR_INVOICE, {"invoice_id": invoice_id})
            ).mappings().all()
        return tuple(
            OpenCaseRow(review_id=int(r["review_id"]), kind=str(r["kind"])) for r in rows
        )


def _product(row: sa.RowMapping) -> ProductRow:
    return ProductRow(
        id=int(row["id"]),
        sku=str(row["sku"]),
        title=str(row["title"]),
        price_usd=Decimal(row["price_usd"]),
        kind=str(row["kind"]),
        subscription_days=(
            None if row["subscription_days"] is None else int(row["subscription_days"])
        ),
    )
