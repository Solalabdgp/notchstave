"""SQLAlchemy 2.0 declarative models — the whole Notchstave schema (TZ section 6).

Design rules that the schema itself enforces, so that code cannot forget them:

* `payments.invoice_id` is immutable — a `BEFORE UPDATE OF invoice_id` trigger
  rejects any change of a non-NULL value (TZ 5.3, 5.8/T3.2). The trigger lives
  in migration 0001; there is no ORM-level equivalent on purpose.
* One active entitlement per invoice — partial unique index
  `entitlements_active_uniq ... WHERE revoked_at IS NULL` (TZ 5.8/T2.1).
* One payment per `(chain_id, tx_hash, log_index)` — replay is impossible
  regardless of how many times a log is redelivered (TZ 5.5, 5.8/T3.1).
* An address never silently changes hands: `UNIQUE (hd_account_id,
  derivation_index)`, `UNIQUE (address)`, plus CHECKs that keep a funded/swept
  address out of the free pool forever (TZ 5.1, 5.8/T3.3).
* The account xpub is not a column anywhere. Only `xpub_fingerprint`
  (TZ 5.1 note, 5.8/T4).

Amounts are raw base units (NUMERIC(78,0)). Settled totals are always computed
as `SUM(payments.amount_raw)`; there is deliberately no incremental counter on
`invoices` (TZ 5.3).
"""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal
from typing import Any, Optional

import sqlalchemy as sa
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, BYTEA, JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.db import enums as E
from core.db.base import (
    AMOUNT_RAW,
    BIP32_PATH_PREFIX_RE,
    Base,
    EVM_ADDRESS_RE,
    FINGERPRINT_RE,
    PRICE_USD,
    RATE,
    TX_HASH_RE,
    USD_AMOUNT,
)

__all__ = [
    "Chain",
    "Block",
    "HDAccount",
    "ReceiveAddress",
    "Asset",
    "Product",
    "User",
    "Invoice",
    "Payment",
    "Entitlement",
    "Refund",
    "ManualReview",
    "SweepExport",
    "Notification",
    "AuditLogEntry",
    "RateLimit",
    "PAYMENTS_INVOICE_ID_IMMUTABLE_FN",
    "PAYMENTS_INVOICE_ID_IMMUTABLE_TRIGGER",
]

PAYMENTS_INVOICE_ID_IMMUTABLE_FN = "notchstave_payments_invoice_id_immutable"
PAYMENTS_INVOICE_ID_IMMUTABLE_TRIGGER = "payments_invoice_id_immutable"


def _enum(py_enum: type, name: str) -> sa.Enum:
    """Native PostgreSQL enum bound to a Python enum, stored by `.value`."""
    return sa.Enum(
        py_enum,
        name=name,
        native_enum=True,
        validate_strings=True,
        values_callable=lambda en: [m.value for m in en],
    )


def _now() -> Any:
    return sa.text("now()")


TS = DateTime(timezone=True)


# ---------------------------------------------------------------------------
# Chain / block bookkeeping
# ---------------------------------------------------------------------------


class Chain(Base):
    """One EVM network. Base (8453) and Ethereum mainnet (1) in v1 (TZ 2)."""

    __tablename__ = "chains"

    #: The real EVM chain id — natural key, no surrogate.
    chain_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    rpc_urls: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=sa.text("'{}'::text[]")
    )
    min_confirmations: Mapped[int] = mapped_column(Integer, nullable=False)
    #: Above this USD value the credit waits for a finalized block instead of a
    #: confirmation count (TZ 5.4).
    credit_threshold_usd: Mapped[Decimal] = mapped_column(
        USD_AMOUNT, nullable=False, server_default=sa.text("20")
    )
    #: OP-stack `safe`/`finalized` tags are meaningful; plain L1 counters are not.
    use_finalized_tag: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa.text("false")
    )
    last_indexed_block: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=sa.text("0")
    )
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa.text("true")
    )
    created_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())

    __table_args__ = (
        CheckConstraint("min_confirmations >= 1", name="min_confirmations_positive"),
        CheckConstraint("credit_threshold_usd >= 0", name="credit_threshold_non_negative"),
        CheckConstraint("last_indexed_block >= 0", name="last_indexed_block_non_negative"),
        {"comment": "One row per EVM network the watcher indexes (TZ 5.2)."},
    )


class Block(Base):
    """Block header chain used for reorg detection (TZ 5.4).

    `parent_hash` is checked against the previously stored block before a block
    is accepted; on mismatch the tail is walked back to the common ancestor and
    the abandoned blocks become `orphaned`, which in turn reverts their payments.
    """

    __tablename__ = "blocks"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    chain_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("chains.chain_id", ondelete="RESTRICT"),
        nullable=False,
    )
    number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    hash: Mapped[str] = mapped_column(String(66), nullable=False)
    parent_hash: Mapped[str] = mapped_column(String(66), nullable=False)
    timestamp: Mapped[dt.datetime] = mapped_column(TS, nullable=False)
    status: Mapped[E.BlockStatus] = mapped_column(
        _enum(E.BlockStatus, "block_status"), nullable=False
    )
    created_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())

    __table_args__ = (
        UniqueConstraint("chain_id", "hash", name="uq_blocks_chain_id_hash"),
        # At most one canonical block per height. An orphaned sibling may coexist,
        # which is exactly what a reorg produces.
        Index(
            "uq_blocks_canonical_height",
            "chain_id",
            "number",
            unique=True,
            postgresql_where=sa.text("status <> 'orphaned'"),
        ),
        Index("ix_blocks_chain_id_number", "chain_id", "number"),
        CheckConstraint("number >= 0", name="number_non_negative"),
        CheckConstraint(f"hash ~ '{TX_HASH_RE}'", name="hash_format"),
        CheckConstraint(f"parent_hash ~ '{TX_HASH_RE}'", name="parent_hash_format"),
        {"comment": "Block headers; `status` drives reorg rollback (TZ 5.4)."},
    )


# ---------------------------------------------------------------------------
# HD derivation
# ---------------------------------------------------------------------------


class HDAccount(Base):
    """An account-level derivation branch, e.g. `m/44'/60'/0'` (TZ 5.1).

    The xpub itself is NEVER stored — it reaches only the `deriver` process via
    systemd `LoadCredential=`. This table keeps the 4-byte BIP-32 fingerprint so
    that any process can assert "the deriver is using the key I think it is"
    and so that `/verify` can publish a derivation proof (TZ 5.8/T1.4, T4).

    A second row with `path_prefix = m/44'/60'/1'` is how xpub rotation after a
    leak is performed — that is why this is a table and not a config constant.
    """

    __tablename__ = "hd_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    label: Mapped[str] = mapped_column(Text, nullable=False)
    xpub_fingerprint: Mapped[str] = mapped_column(String(8), nullable=False)
    path_prefix: Mapped[str] = mapped_column(Text, nullable=False)
    #: Next index to derive when the free pool is empty. Bumped only with
    #: `UPDATE ... RETURNING` inside the reservation transaction (TZ 5.1, p. 3).
    next_index: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=sa.text("0")
    )
    #: BIP-44 gap-limit headroom to keep pre-derived (TZ 5.1, p. 2).
    gap_reserve: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=sa.text("20")
    )
    #: Hard ceiling on simultaneously reserved addresses (TZ 5.8/T5.2).
    max_active_addresses: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=sa.text("500")
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa.text("true")
    )
    created_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())

    __table_args__ = (
        UniqueConstraint("path_prefix", name="uq_hd_accounts_path_prefix"),
        # Rotation means "new account becomes the one issuing invoices"; the old
        # one stays watch-only. Exactly one issuing account at a time.
        Index(
            "uq_hd_accounts_single_active",
            "is_active",
            unique=True,
            postgresql_where=sa.text("is_active"),
        ),
        CheckConstraint(f"xpub_fingerprint ~ '{FINGERPRINT_RE}'", name="fingerprint_format"),
        CheckConstraint(f"path_prefix ~ '{BIP32_PATH_PREFIX_RE}'", name="path_prefix_format"),
        CheckConstraint("next_index >= 0", name="next_index_non_negative"),
        CheckConstraint("gap_reserve >= 0", name="gap_reserve_non_negative"),
        CheckConstraint("max_active_addresses > 0", name="max_active_addresses_positive"),
        {"comment": "Derivation accounts. The xpub itself is never stored (TZ 5.1)."},
    )


class ReceiveAddress(Base):
    """A derived receive address and its lifecycle in the reuse pool (TZ 5.1).

    Writes are restricted to the `notchstave_deriver` role at the grant level
    (migration 0002, TZ 5.8/T1.2): an address can only be *derived*, never
    *declared*.

    Reuse rules, all three mandatory (TZ 5.1, p. 2):
      1. `ever_funded` = true forbids returning to `free` forever;
      2. return happens only after `cooldown_until` (top-up window + cooldown);
      3. `reserved_from_block` pins the reservation to a chain height — a payment
         mined below it belongs to the previous tenant (`orphan_payment`).

    Note the address is chain-agnostic: the same key derives the same address on
    every EVM network, which is precisely why `wrong_chain` exists (TZ 5.5).
    """

    __tablename__ = "receive_addresses"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    hd_account_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("hd_accounts.id", ondelete="RESTRICT"), nullable=False
    )
    derivation_index: Mapped[int] = mapped_column(Integer, nullable=False)
    #: EIP-55 checksummed.
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    status: Mapped[E.AddressStatus] = mapped_column(
        _enum(E.AddressStatus, "address_status"),
        nullable=False,
        server_default=sa.text("'free'"),
    )
    current_invoice_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("invoices.id", ondelete="RESTRICT", use_alter=True),
        nullable=True,
    )
    reserved_from_block: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    cooldown_until: Mapped[Optional[dt.datetime]] = mapped_column(TS, nullable=True)
    ever_funded: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa.text("false")
    )
    first_seen_funds_at: Mapped[Optional[dt.datetime]] = mapped_column(TS, nullable=True)
    swept_at: Mapped[Optional[dt.datetime]] = mapped_column(TS, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())

    hd_account: Mapped[HDAccount] = relationship("HDAccount", lazy="raise")
    current_invoice: Mapped[Optional["Invoice"]] = relationship(
        "Invoice",
        foreign_keys=[current_invoice_id],
        post_update=True,
        lazy="raise",
    )

    __table_args__ = (
        UniqueConstraint(
            "hd_account_id", "derivation_index", name="uq_receive_addresses_account_index"
        ),
        UniqueConstraint("address", name="uq_receive_addresses_address"),
        # Pool pickup: ... WHERE status='free' ORDER BY derivation_index
        #              FOR UPDATE SKIP LOCKED LIMIT 1   (TZ 5.1 p. 3)
        Index(
            "ix_receive_addresses_free_pool",
            "hd_account_id",
            "derivation_index",
            postgresql_where=sa.text("status = 'free'"),
        ),
        Index(
            "ix_receive_addresses_current_invoice_id",
            "current_invoice_id",
            postgresql_where=sa.text("current_invoice_id IS NOT NULL"),
        ),
        CheckConstraint("derivation_index >= 0", name="derivation_index_non_negative"),
        CheckConstraint(f"address ~ '{EVM_ADDRESS_RE}'", name="address_format"),
        CheckConstraint(
            "status <> 'free' OR (current_invoice_id IS NULL "
            "AND reserved_from_block IS NULL AND NOT ever_funded)",
            name="free_state_clean",
        ),
        CheckConstraint(
            "status <> 'reserved' OR (current_invoice_id IS NOT NULL "
            "AND reserved_from_block IS NOT NULL)",
            name="reserved_state_bound",
        ),
        CheckConstraint(
            "first_seen_funds_at IS NULL OR ever_funded", name="funds_imply_ever_funded"
        ),
        CheckConstraint(
            "swept_at IS NULL OR (ever_funded AND status = 'swept')", name="swept_state"
        ),
        CheckConstraint("reserved_from_block IS NULL OR reserved_from_block >= 0",
                        name="reserved_from_block_non_negative"),
        {
            "comment": (
                "Derived receive addresses. Only the deriver role may write "
                "(TZ 5.8/T1.2). ever_funded=true bars the address from the pool "
                "permanently (TZ 5.1)."
            )
        },
    )


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------


class Asset(Base):
    """An accepted token on a chain. Explicit allow-list only (TZ 12)."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("chains.chain_id", ondelete="RESTRICT"), nullable=False
    )
    #: NULL for the native coin, contract address otherwise.
    contract_address: Mapped[Optional[str]] = mapped_column(String(42), nullable=True)
    symbol: Mapped[str] = mapped_column(String(16), nullable=False)
    decimals: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    is_native: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa.text("false")
    )
    #: Anything not enabled is `wrong_asset` -> manual review (TZ 5.5).
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa.text("true")
    )
    created_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())

    __table_args__ = (
        # Target of the composite FKs that keep invoice/payment chain_id in sync
        # with the asset's own chain.
        UniqueConstraint("id", "chain_id", name="uq_assets_id_chain_id"),
        UniqueConstraint("chain_id", "contract_address", name="uq_assets_chain_contract"),
        Index(
            "uq_assets_native_per_chain",
            "chain_id",
            unique=True,
            postgresql_where=sa.text("is_native"),
        ),
        CheckConstraint("decimals BETWEEN 0 AND 36", name="decimals_range"),
        CheckConstraint(
            "(is_native AND contract_address IS NULL) "
            "OR (NOT is_native AND contract_address IS NOT NULL)",
            name="native_has_no_contract",
        ),
        CheckConstraint(
            f"contract_address IS NULL OR contract_address ~ '{EVM_ADDRESS_RE}'",
            name="contract_address_format",
        ),
        {"comment": "Allow-listed payment assets (TZ 12: no arbitrary tokens)."},
    )


class Product(Base):
    """Sellable item (TZ 3.1 `/shop`, 3.3)."""

    __tablename__ = "products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sku: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    price_usd: Mapped[Decimal] = mapped_column(PRICE_USD, nullable=False)
    kind: Mapped[E.ProductKind] = mapped_column(_enum(E.ProductKind, "product_kind"), nullable=False)
    #: File id / URL / whatever the delivery layer resolves.
    content_ref: Mapped[str] = mapped_column(Text, nullable=False)
    #: Only for `subscription`: entitlement lifetime in days.
    subscription_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=sa.text("true"))
    created_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())

    __table_args__ = (
        UniqueConstraint("sku", name="uq_products_sku"),
        CheckConstraint("price_usd > 0", name="price_positive"),
        CheckConstraint(
            "(kind = 'subscription') = (subscription_days IS NOT NULL)",
            name="subscription_days_matches_kind",
        ),
        CheckConstraint(
            "subscription_days IS NULL OR subscription_days > 0",
            name="subscription_days_positive",
        ),
        {"comment": "Catalog. `kind` decides whether the entitlement expires."},
    )


class User(Base):
    """Telegram user (TZ 6)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tg_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    lang: Mapped[str] = mapped_column(String(8), nullable=False, server_default=sa.text("'en'"))
    #: Tolerated overpayment credited towards future purchases (TZ 5.5).
    internal_balance_usd: Mapped[Decimal] = mapped_column(
        USD_AMOUNT, nullable=False, server_default=sa.text("0")
    )
    settings_json: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    #: Set when Telegram reports the bot was blocked; notifier stops sending (TZ 5.7).
    bot_blocked_at: Mapped[Optional[dt.datetime]] = mapped_column(TS, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())

    __table_args__ = (
        UniqueConstraint("tg_id", name="uq_users_tg_id"),
        CheckConstraint("internal_balance_usd >= 0", name="internal_balance_non_negative"),
        {"comment": "Bot users. internal_balance_usd holds tolerated overpayment."},
    )


# ---------------------------------------------------------------------------
# Money
# ---------------------------------------------------------------------------


class Invoice(Base):
    """The payment state machine (TZ 6, 5.5).

    `id` is a UUIDv7 generated by the application, never a serial: the public
    invoice page and `/status` must not be enumerable (TZ 5.8/T1.7).

    There is intentionally NO `amount_paid_raw` column. The settled total is
    always `SUM(payments.amount_raw)` over confirmed/credited rows — an
    incremental counter is exactly the mechanism that double-credits on replay
    (TZ 5.3).
    """

    __tablename__ = "invoices"

    id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    product_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("products.id", ondelete="RESTRICT"), nullable=False
    )
    chain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("chains.chain_id", ondelete="RESTRICT"), nullable=False
    )
    asset_id: Mapped[int] = mapped_column(Integer, nullable=False)
    address_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("receive_addresses.id", ondelete="RESTRICT"), nullable=False
    )
    amount_due_raw: Mapped[Decimal] = mapped_column(AMOUNT_RAW, nullable=False)
    amount_due_usd: Mapped[Decimal] = mapped_column(USD_AMOUNT, nullable=False)
    #: USD per whole token, frozen at creation (TZ 5.5 rate table).
    rate_snapshot: Mapped[Decimal] = mapped_column(RATE, nullable=False)
    rate_locked_until: Mapped[dt.datetime] = mapped_column(TS, nullable=False)
    status: Mapped[E.InvoiceStatus] = mapped_column(
        _enum(E.InvoiceStatus, "invoice_status"),
        nullable=False,
        server_default=sa.text("'awaiting'"),
    )
    expires_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False)
    #: Late top-ups are still credited until this moment (TZ 5.5 underpayment).
    topup_window_until: Mapped[dt.datetime] = mapped_column(TS, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())
    settled_at: Mapped[Optional[dt.datetime]] = mapped_column(TS, nullable=True)
    #: HMAC-SHA256 over (id, chain_id, asset_id, address, amount_due_raw,
    #: expires_at). The key lives in systemd credentials, never in this database
    #: (TZ 5.8/T1.3).
    integrity_mac: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    #: Unguessable token for the public invoice page (TZ 5.8/T1.7).
    public_token: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Which version of the money-policy config decided this invoice (TZ 5.8/T8).
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)

    address: Mapped[ReceiveAddress] = relationship(
        "ReceiveAddress", foreign_keys=[address_id], lazy="raise"
    )
    payments: Mapped[list["Payment"]] = relationship(
        "Payment", back_populates="invoice", lazy="raise"
    )

    __table_args__ = (
        # Keeps `invoices.chain_id` and `assets.chain_id` from ever diverging;
        # a cross-chain mismatch would silently break `wrong_chain` handling.
        ForeignKeyConstraint(
            ["asset_id", "chain_id"],
            ["assets.id", "assets.chain_id"],
            name="fk_invoices_asset_id_chain_id_assets",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("public_token", name="uq_invoices_public_token"),
        # An address may back at most one LIVE invoice at a time. This is the
        # schema-level half of the reuse rules in TZ 5.1 / 5.8-T3.3.
        Index(
            "uq_invoices_active_address",
            "address_id",
            unique=True,
            postgresql_where=sa.text(
                "status IN ('awaiting', 'seen', 'partially_paid')"
            ),
        ),
        # Quota check for TZ 5.8/T5.1 (max active invoices per user).
        Index(
            "ix_invoices_user_active",
            "user_id",
            postgresql_where=sa.text("status IN ('awaiting', 'seen', 'partially_paid')"),
        ),
        Index("ix_invoices_status_expires_at", "status", "expires_at"),
        Index("ix_invoices_chain_id_status", "chain_id", "status"),
        Index("ix_invoices_user_id_created_at", "user_id", "created_at"),
        CheckConstraint("amount_due_raw > 0", name="amount_due_raw_positive"),
        CheckConstraint("amount_due_usd > 0", name="amount_due_usd_positive"),
        CheckConstraint("rate_snapshot > 0", name="rate_snapshot_positive"),
        CheckConstraint("topup_window_until >= expires_at", name="topup_window_after_expiry"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        CheckConstraint("settled_at IS NULL OR settled_at >= created_at", name="settled_after_creation"),
        CheckConstraint("octet_length(integrity_mac) = 32", name="integrity_mac_length"),
        {
            "comment": (
                "Invoice state machine. No paid-amount counter on purpose: the "
                "total is SUM(payments.amount_raw) (TZ 5.3)."
            )
        },
    )


class Payment(Base):
    """A single incoming on-chain transfer (TZ 5.2, 5.3).

    `UNIQUE (chain_id, tx_hash, log_index)` + `ON CONFLICT DO NOTHING` on insert
    makes redelivery of the same log a no-op (TZ 5.5, 5.8/T3.1).

    `invoice_id` is written once, in the same transaction as the insert, copied
    from `receive_addresses.current_invoice_id`. A `BEFORE UPDATE OF invoice_id`
    trigger (migration 0001) rejects any later change of a non-NULL value. There
    is no code path that re-binds a payment; disputed money is resolved through
    `manual_reviews` + an explicit credit, which leaves a trace (TZ 5.3, 5.8/T3.2).
    """

    __tablename__ = "payments"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    chain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("chains.chain_id", ondelete="RESTRICT"), nullable=False
    )
    tx_hash: Mapped[str] = mapped_column(String(66), nullable=False)
    #: -1 is reserved for native-coin transfers, which have no log (TZ 5.2).
    log_index: Mapped[int] = mapped_column(Integer, nullable=False)
    block_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    address_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("receive_addresses.id", ondelete="RESTRICT"), nullable=False
    )
    invoice_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("invoices.id", ondelete="RESTRICT"),
        nullable=True,
    )
    asset_id: Mapped[int] = mapped_column(Integer, nullable=False)
    amount_raw: Mapped[Decimal] = mapped_column(AMOUNT_RAW, nullable=False)
    #: Informational only — never a safe refund destination (TZ 5.5).
    sender: Mapped[Optional[str]] = mapped_column(String(42), nullable=True)
    status: Mapped[E.PaymentStatus] = mapped_column(
        _enum(E.PaymentStatus, "payment_status"),
        nullable=False,
        server_default=sa.text("'seen'"),
    )
    confirmations_at_credit: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    anomaly: Mapped[Optional[E.PaymentAnomaly]] = mapped_column(
        _enum(E.PaymentAnomaly, "payment_anomaly"), nullable=True
    )
    created_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())

    invoice: Mapped[Optional[Invoice]] = relationship(
        "Invoice", back_populates="payments", foreign_keys=[invoice_id], lazy="raise"
    )

    __table_args__ = (
        UniqueConstraint(
            "chain_id", "tx_hash", "log_index", name="uq_payments_chain_tx_log"
        ),
        ForeignKeyConstraint(
            ["asset_id", "chain_id"],
            ["assets.id", "assets.chain_id"],
            name="fk_payments_asset_id_chain_id_assets",
            ondelete="RESTRICT",
        ),
        # SUM(amount_raw) per invoice over creditable statuses (TZ 5.3).
        Index(
            "ix_payments_invoice_id_status",
            "invoice_id",
            "status",
            postgresql_where=sa.text("invoice_id IS NOT NULL"),
        ),
        # Reorg rollback walks payments by height.
        Index("ix_payments_chain_id_block_number", "chain_id", "block_number"),
        Index("ix_payments_address_id_block_number", "address_id", "block_number"),
        Index(
            "ix_payments_open",
            "status",
            postgresql_where=sa.text("status IN ('seen', 'confirmed')"),
        ),
        Index(
            "ix_payments_anomaly",
            "anomaly",
            postgresql_where=sa.text("anomaly IS NOT NULL"),
        ),
        CheckConstraint("amount_raw > 0", name="amount_raw_positive"),
        CheckConstraint("block_number >= 0", name="block_number_non_negative"),
        CheckConstraint("log_index >= -1", name="log_index_valid"),
        CheckConstraint(f"tx_hash ~ '{TX_HASH_RE}'", name="tx_hash_format"),
        CheckConstraint(f"sender IS NULL OR sender ~ '{EVM_ADDRESS_RE}'", name="sender_format"),
        CheckConstraint(
            "status <> 'credited' OR confirmations_at_credit IS NOT NULL",
            name="credited_records_confirmations",
        ),
        CheckConstraint(
            "confirmations_at_credit IS NULL OR confirmations_at_credit >= 0",
            name="confirmations_non_negative",
        ),
        {
            "comment": (
                "Raw incoming transfers. invoice_id is immutable, enforced by "
                "trigger payments_invoice_id_immutable (TZ 5.3, 5.8/T3)."
            )
        },
    )


class Entitlement(Base):
    """Proof that access was granted for an invoice (TZ 3.3, 5.8/T2).

    The partial unique index below is the only real protection against a double
    grant. Two settler workers racing on the same invoice: one inserts, the other
    hits the constraint and quietly loses the race — no side effects.

    The index is partial rather than plain because a reorg revokes the grant
    (`revoked_at`), after which the same invoice must be grantable again (TZ 5.4).
    """

    __tablename__ = "entitlements"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    product_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("products.id", ondelete="RESTRICT"), nullable=False
    )
    invoice_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("invoices.id", ondelete="RESTRICT"), nullable=False
    )
    granted_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())
    #: NULL = perpetual (one-off product).
    expires_at: Mapped[Optional[dt.datetime]] = mapped_column(TS, nullable=True)
    revoked_at: Mapped[Optional[dt.datetime]] = mapped_column(TS, nullable=True)
    revoke_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        # TZ 5.8/T2.1, verbatim.
        Index(
            "entitlements_active_uniq",
            "invoice_id",
            unique=True,
            postgresql_where=sa.text("revoked_at IS NULL"),
        ),
        Index("ix_entitlements_user_id_expires_at", "user_id", "expires_at"),
        CheckConstraint(
            "revoked_at IS NOT NULL OR revoke_reason IS NULL", name="revoke_reason_needs_revocation"
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= granted_at", name="revoked_after_granted"
        ),
        {
            "comment": (
                "One active grant per invoice, enforced by the partial unique "
                "index entitlements_active_uniq (TZ 5.8/T2)."
            )
        },
    )


class Refund(Base):
    """A refund OBLIGATION. Nothing here sends money (TZ 5.5, 12).

    An automated refund would require a spending key on the server, which would
    invalidate the entire custody model. The owner executes the transfer offline
    and then closes the row.
    """

    __tablename__ = "refunds"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    invoice_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("invoices.id", ondelete="RESTRICT"), nullable=False
    )
    amount_raw: Mapped[Decimal] = mapped_column(AMOUNT_RAW, nullable=False)
    asset_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False
    )
    #: Explicitly asked from the user; the sender address is NOT trustworthy.
    to_address: Mapped[Optional[str]] = mapped_column(String(42), nullable=True)
    status: Mapped[E.RefundStatus] = mapped_column(
        _enum(E.RefundStatus, "refund_status"),
        nullable=False,
        server_default=sa.text("'pending'"),
    )
    operator_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())
    executed_at: Mapped[Optional[dt.datetime]] = mapped_column(TS, nullable=True)

    __table_args__ = (
        # Repeated processing of the same overpayment must not stack up requests.
        Index(
            "uq_refunds_pending_per_invoice",
            "invoice_id",
            unique=True,
            postgresql_where=sa.text("status = 'pending'"),
        ),
        Index("ix_refunds_status", "status"),
        CheckConstraint("amount_raw > 0", name="amount_raw_positive"),
        CheckConstraint(
            f"to_address IS NULL OR to_address ~ '{EVM_ADDRESS_RE}'", name="to_address_format"
        ),
        CheckConstraint(
            "status <> 'executed' OR (executed_at IS NOT NULL "
            "AND to_address IS NOT NULL AND operator_id IS NOT NULL)",
            name="executed_requires_details",
        ),
        {"comment": "Accounting only — the bot never sends an outgoing transfer (TZ 12)."},
    )


class ManualReview(Base):
    """A case that must not be auto-settled (TZ 5.5, 3.4 `/pending`, `/resolve`)."""

    __tablename__ = "manual_reviews"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    kind: Mapped[E.ManualReviewKind] = mapped_column(
        _enum(E.ManualReviewKind, "manual_review_kind"), nullable=False
    )
    invoice_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("invoices.id", ondelete="RESTRICT"), nullable=True
    )
    payment_id: Mapped[Optional[int]] = mapped_column(
        BigInteger, ForeignKey("payments.id", ondelete="RESTRICT"), nullable=True
    )
    opened_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())
    resolved_at: Mapped[Optional[dt.datetime]] = mapped_column(TS, nullable=True)
    operator_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    resolution: Mapped[Optional[E.ManualReviewResolution]] = mapped_column(
        _enum(E.ManualReviewResolution, "manual_review_resolution"), nullable=True
    )
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    #: Policy config version in force when the case was opened (TZ 5.8/T8).
    policy_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    __table_args__ = (
        # One open case per payment; reprocessing must not spam `/pending`.
        Index(
            "uq_manual_reviews_open_payment",
            "payment_id",
            unique=True,
            postgresql_where=sa.text("resolved_at IS NULL AND payment_id IS NOT NULL"),
        ),
        Index(
            "ix_manual_reviews_open",
            "opened_at",
            postgresql_where=sa.text("resolved_at IS NULL"),
        ),
        Index("ix_manual_reviews_invoice_id", "invoice_id"),
        CheckConstraint(
            "invoice_id IS NOT NULL OR payment_id IS NOT NULL", name="targets_something"
        ),
        CheckConstraint(
            "(resolved_at IS NULL AND resolution IS NULL) "
            "OR (resolved_at IS NOT NULL AND resolution IS NOT NULL "
            "AND operator_id IS NOT NULL)",
            name="resolution_complete",
        ),
        {"comment": "Human-decided cases; every resolution keeps its author (TZ 5.8/T8)."},
    )


class SweepExport(Base):
    """A generated `/sweeplist` CSV. One-way channel to the offline perimeter (TZ 3.4)."""

    __tablename__ = "sweep_exports"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    generated_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())
    address_count: Mapped[int] = mapped_column(Integer, nullable=False)
    total_raw: Mapped[Decimal] = mapped_column(AMOUNT_RAW, nullable=False)
    asset_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False
    )
    file_ref: Mapped[str] = mapped_column(Text, nullable=False)
    operator_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    __table_args__ = (
        Index("ix_sweep_exports_generated_at", "generated_at"),
        CheckConstraint("address_count >= 0", name="address_count_non_negative"),
        CheckConstraint("total_raw >= 0", name="total_raw_non_negative"),
        {"comment": "Audit trail of sweep CSV exports. Signing happens offline (TZ 5.1)."},
    )


# ---------------------------------------------------------------------------
# Delivery, audit, quotas
# ---------------------------------------------------------------------------


class Notification(Base):
    """Transactional outbox for user-facing messages (TZ 5.7, 5.8/T2.5).

    The row is inserted in the SAME transaction that grants the entitlement, so
    a crash between granting and sending re-sends instead of re-granting.
    `UNIQUE (kind, ref_id, dedup_key)` makes redelivery idempotent.
    """

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    #: e.g. payment_seen / invoice_paid / underpaid / payment_reverted.
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    #: Identifier of whatever the message is about (invoice uuid, payment id...).
    ref_id: Mapped[str] = mapped_column(String(64), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    status: Mapped[E.NotificationStatus] = mapped_column(
        _enum(E.NotificationStatus, "notification_status"),
        nullable=False,
        server_default=sa.text("'queued'"),
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa.text("0"))
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sent_at: Mapped[Optional[dt.datetime]] = mapped_column(TS, nullable=True)
    #: Telegram message id, so the bot can prove it never edits an address message.
    message_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())

    __table_args__ = (
        UniqueConstraint("kind", "ref_id", "dedup_key", name="uq_notifications_dedup"),
        # Outbox drain: ... WHERE status='queued' ORDER BY created_at
        #               FOR UPDATE SKIP LOCKED
        Index(
            "ix_notifications_queue",
            "created_at",
            postgresql_where=sa.text("status = 'queued'"),
        ),
        Index("ix_notifications_user_id", "user_id"),
        CheckConstraint("attempts >= 0", name="attempts_non_negative"),
        CheckConstraint("status <> 'sent' OR sent_at IS NOT NULL", name="sent_has_timestamp"),
        {"comment": "Outbox. Written in the same transaction as the side effect (TZ 5.7)."},
    )


class AuditLogEntry(Base):
    """Append-only record of every admin action and every money decision.

    Append-only is enforced by GRANTs in migration 0002: application roles get
    INSERT and SELECT, never UPDATE or DELETE (TZ 5.8/T7, T8).
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    actor_kind: Mapped[E.ActorKind] = mapped_column(_enum(E.ActorKind, "actor_kind"), nullable=False)
    #: tg_id for owner/user, process name for system.
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    before_state: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    after_state: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    args_json: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    #: Which policy config version applied at decision time (TZ 5.8/T8).
    policy_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(TS, nullable=False, server_default=_now())

    __table_args__ = (
        Index("ix_audit_log_created_at", "created_at"),
        Index("ix_audit_log_target_kind_target_id", "target_kind", "target_id"),
        Index("ix_audit_log_action", "action"),
        {"comment": "Append-only. App roles have no UPDATE/DELETE (TZ 5.8/T7)."},
    )


class RateLimit(Base):
    """Source of truth for invoice-creation quotas (TZ 5.8/T5.1).

    Redis is a cache in front of this table, never the authority: flushing or
    restarting Redis must not open the gate.
    """

    __tablename__ = "rate_limits"

    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    #: Start of the counting window (hour granularity by default).
    window_start: Mapped[dt.datetime] = mapped_column(TS, primary_key=True)
    invoices_created: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=sa.text("0")
    )
    #: Behavioural cooldown after N consecutive expired invoices (TZ 5.8/T5.5).
    cooldown_until: Mapped[Optional[dt.datetime]] = mapped_column(TS, nullable=True)
    consecutive_expired: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=sa.text("0")
    )

    __table_args__ = (
        Index("ix_rate_limits_window_start", "window_start"),
        CheckConstraint("invoices_created >= 0", name="invoices_created_non_negative"),
        CheckConstraint("consecutive_expired >= 0", name="consecutive_expired_non_negative"),
        {"comment": "Quota authority; Redis only caches it (TZ 5.8/T5)."},
    )
