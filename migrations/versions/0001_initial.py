"""initial schema

Full Notchstave schema from scratch: TZ section 6, with the constraints that
sections 5.1 / 5.3 / 5.4 / 5.5 / 5.8 describe in prose translated into real DDL.

The three load-bearing pieces, all of them here rather than in application code:

* ``payments_invoice_id_immutable`` — BEFORE UPDATE OF invoice_id trigger that
  refuses to change a non-NULL binding (TZ 5.3, 5.8/T3.2).
* ``entitlements_active_uniq`` — partial unique index on ``entitlements
  (invoice_id) WHERE revoked_at IS NULL`` (TZ 5.8/T2.1).
* ``uq_payments_chain_tx_log`` — UNIQUE (chain_id, tx_hash, log_index), the
  reason a redelivered log can never be credited twice (TZ 5.5, 5.8/T3.1).

Role GRANTs live in 0002 so that this migration runs on a database where the
migrating user cannot create roles.

Revision ID: 0001
Revises:
Create Date: 2026-08-15

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# --------------------------------------------------------------------------
# Native enum types. Created explicitly so that a type shared by two tables is
# not created twice by create_table.
# --------------------------------------------------------------------------
ENUM_DEFS: dict[str, tuple[str, ...]] = {
    "block_status": ("pending", "confirmed", "orphaned"),
    "address_status": ("free", "reserved", "funded", "swept"),
    "invoice_status": (
        "awaiting",
        "seen",
        "partially_paid",
        "paid",
        "overpaid",
        "expired",
        "manual_review",
        "cancelled",
        "reverted",
    ),
    "payment_status": ("seen", "confirmed", "credited", "reverted", "ignored_dust"),
    "payment_anomaly": (
        "wrong_asset",
        "wrong_chain",
        "late",
        "dust",
        "orphan_payment",
        "unassigned_payment",
    ),
    "product_kind": ("one_off", "subscription"),
    "refund_status": ("pending", "executed", "declined"),
    "manual_review_kind": (
        "underpaid",
        "overpaid",
        "wrong_asset",
        "wrong_chain",
        "late_payment",
        "orphan_payment",
        "unassigned_payment",
        "address_mismatch",
        "mac_failure",
        "reconcile_drift",
    ),
    "manual_review_resolution": ("credit", "refund", "reject"),
    "notification_status": ("queued", "sent", "failed", "dead"),
    "actor_kind": ("owner", "user", "system"),
}


def pg_enum(name: str) -> postgresql.ENUM:
    """Reference an already-created enum type (never re-create it)."""
    return postgresql.ENUM(*ENUM_DEFS[name], name=name, create_type=False)


EVM_ADDRESS_RE = r"^0x[0-9a-fA-F]{40}$"
TX_HASH_RE = r"^0x[0-9a-f]{64}$"
# Exactly three hardened levels: m/44'/60'/<account>'  (TZ 5.1, rule 1 — the
# apostrophes are what stop an attacker who holds the account xpub from walking
# up to the master key). The old pattern `^m(/\d+''?)+$` made the apostrophe
# optional and the depth free, so `m/44/60/0` passed the CHECK.
# '' -> one literal apostrophe inside a SQL string literal.
BIP32_PATH_PREFIX_RE = r"^m/44''/60''/\d+''$"
FINGERPRINT_RE = r"^[0-9a-f]{8}$"

AMOUNT_RAW = sa.Numeric(78, 0)  # full uint256 range, exact
USD_AMOUNT = sa.Numeric(18, 6)
RATE = sa.Numeric(38, 18)
PRICE_USD = sa.Numeric(12, 2)
TS = sa.DateTime(timezone=True)


PAYMENTS_INVOICE_ID_IMMUTABLE_SQL = """
CREATE OR REPLACE FUNCTION notchstave_payments_invoice_id_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
    -- A payment is bound to its invoice once, at insert time, from
    -- receive_addresses.current_invoice_id. Re-binding would let a disputed
    -- payment be moved between invoices without leaving a trace, which is the
    -- whole point of TZ 5.3 / 5.8-T3.2. Manual decisions go through
    -- manual_reviews plus an explicit credit instead.
    IF OLD.invoice_id IS NOT NULL
       AND NEW.invoice_id IS DISTINCT FROM OLD.invoice_id THEN
        RAISE EXCEPTION
            'payments.invoice_id is immutable (payment %, bound to %, refused rebind to %)',
            OLD.id, OLD.invoice_id, NEW.invoice_id
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$fn$;
"""


def upgrade() -> None:
    # ---------------------------------------------------------------- enums
    for name, values in ENUM_DEFS.items():
        rendered = ", ".join(f"'{v}'" for v in values)
        op.execute(f"CREATE TYPE {name} AS ENUM ({rendered})")

    # --------------------------------------------------------------- chains
    op.create_table(
        "chains",
        sa.Column("chain_id", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "rpc_urls",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
        sa.Column("min_confirmations", sa.Integer(), nullable=False),
        sa.Column(
            "credit_threshold_usd", USD_AMOUNT, server_default=sa.text("20"), nullable=False
        ),
        sa.Column(
            "use_finalized_tag", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column(
            "last_indexed_block", sa.BigInteger(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "min_confirmations >= 1", name="min_confirmations_positive"
        ),
        sa.CheckConstraint(
            "credit_threshold_usd >= 0", name="credit_threshold_non_negative"
        ),
        sa.CheckConstraint(
            "last_indexed_block >= 0", name="last_indexed_block_non_negative"
        ),
        sa.PrimaryKeyConstraint("chain_id", name="pk_chains"),
        comment="One row per EVM network the watcher indexes (TZ 5.2).",
    )

    # --------------------------------------------------------------- blocks
    op.create_table(
        "blocks",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("chain_id", sa.BigInteger(), nullable=False),
        sa.Column("number", sa.BigInteger(), nullable=False),
        sa.Column("hash", sa.String(length=66), nullable=False),
        sa.Column("parent_hash", sa.String(length=66), nullable=False),
        sa.Column("timestamp", TS, nullable=False),
        sa.Column("status", pg_enum("block_status"), nullable=False),
        sa.Column("created_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("number >= 0", name="number_non_negative"),
        sa.CheckConstraint(f"hash ~ '{TX_HASH_RE}'", name="hash_format"),
        sa.CheckConstraint(
            f"parent_hash ~ '{TX_HASH_RE}'", name="parent_hash_format"
        ),
        sa.ForeignKeyConstraint(
            ["chain_id"],
            ["chains.chain_id"],
            name="fk_blocks_chain_id_chains",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_blocks"),
        sa.UniqueConstraint("chain_id", "hash", name="uq_blocks_chain_id_hash"),
        comment="Block headers; `status` drives reorg rollback (TZ 5.4).",
    )
    # Exactly one canonical block per height; an orphaned sibling may coexist.
    op.create_index(
        "uq_blocks_canonical_height",
        "blocks",
        ["chain_id", "number"],
        unique=True,
        postgresql_where=sa.text("status <> 'orphaned'"),
    )
    op.create_index("ix_blocks_chain_id_number", "blocks", ["chain_id", "number"])

    # ----------------------------------------------------------- hd_accounts
    op.create_table(
        "hd_accounts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("label", sa.Text(), nullable=False),
        # 4-byte BIP-32 fingerprint as lowercase hex. The xpub itself is never
        # stored anywhere in this database (TZ 5.1, 5.8/T4).
        sa.Column("xpub_fingerprint", sa.String(length=8), nullable=False),
        sa.Column("path_prefix", sa.Text(), nullable=False),
        sa.Column("next_index", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("gap_reserve", sa.Integer(), server_default=sa.text("20"), nullable=False),
        sa.Column(
            "max_active_addresses", sa.Integer(), server_default=sa.text("500"), nullable=False
        ),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            f"xpub_fingerprint ~ '{FINGERPRINT_RE}'", name="fingerprint_format"
        ),
        sa.CheckConstraint(
            f"path_prefix ~ '{BIP32_PATH_PREFIX_RE}'", name="path_prefix_format"
        ),
        sa.CheckConstraint("next_index >= 0", name="next_index_non_negative"),
        sa.CheckConstraint("gap_reserve >= 0", name="gap_reserve_non_negative"),
        sa.CheckConstraint(
            "max_active_addresses > 0", name="max_active_addresses_positive"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_hd_accounts"),
        sa.UniqueConstraint("path_prefix", name="uq_hd_accounts_path_prefix"),
        comment="Derivation accounts. The xpub itself is never stored (TZ 5.1).",
    )
    # xpub rotation (TZ 5.8/T4): the new account issues invoices, the old one
    # stays watch-only. Exactly one issuing account at any moment.
    op.create_index(
        "uq_hd_accounts_single_active",
        "hd_accounts",
        ["is_active"],
        unique=True,
        postgresql_where=sa.text("is_active"),
    )

    # ----------------------------------------------------- receive_addresses
    op.create_table(
        "receive_addresses",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("hd_account_id", sa.Integer(), nullable=False),
        sa.Column("derivation_index", sa.Integer(), nullable=False),
        sa.Column("address", sa.String(length=42), nullable=False),
        sa.Column(
            "status", pg_enum("address_status"), server_default=sa.text("'free'"), nullable=False
        ),
        sa.Column("current_invoice_id", postgresql.UUID(as_uuid=True), nullable=True),
        # Chain head height at reservation time. A payment mined below it
        # belongs to the previous tenant of a reused address (TZ 5.1, 5.8/T3.3).
        sa.Column("reserved_from_block", sa.BigInteger(), nullable=True),
        sa.Column("cooldown_until", TS, nullable=True),
        sa.Column("ever_funded", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("first_seen_funds_at", TS, nullable=True),
        sa.Column("swept_at", TS, nullable=True),
        sa.Column("created_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "derivation_index >= 0", name="derivation_index_non_negative"
        ),
        sa.CheckConstraint(
            f"address ~ '{EVM_ADDRESS_RE}'", name="address_format"
        ),
        # Condition 1 of the reuse rules: a funded address never re-enters the pool.
        sa.CheckConstraint(
            "status <> 'free' OR (current_invoice_id IS NULL "
            "AND reserved_from_block IS NULL AND NOT ever_funded)",
            name="free_state_clean",
        ),
        sa.CheckConstraint(
            "status <> 'reserved' OR (current_invoice_id IS NOT NULL "
            "AND reserved_from_block IS NOT NULL)",
            name="reserved_state_bound",
        ),
        sa.CheckConstraint(
            "first_seen_funds_at IS NULL OR ever_funded",
            name="funds_imply_ever_funded",
        ),
        sa.CheckConstraint(
            "swept_at IS NULL OR (ever_funded AND status = 'swept')",
            name="swept_state",
        ),
        sa.CheckConstraint(
            "reserved_from_block IS NULL OR reserved_from_block >= 0",
            name="reserved_from_block_non_negative",
        ),
        sa.ForeignKeyConstraint(
            ["hd_account_id"],
            ["hd_accounts.id"],
            name="fk_receive_addresses_hd_account_id_hd_accounts",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_receive_addresses"),
        sa.UniqueConstraint(
            "hd_account_id", "derivation_index", name="uq_receive_addresses_account_index"
        ),
        sa.UniqueConstraint("address", name="uq_receive_addresses_address"),
        comment=(
            "Derived receive addresses. Only the deriver role may write "
            "(TZ 5.8/T1.2). ever_funded=true bars the address from the pool "
            "permanently (TZ 5.1)."
        ),
    )
    # Backs the pool pickup query:
    #   SELECT id FROM receive_addresses
    #    WHERE hd_account_id=$1 AND status='free'
    #    ORDER BY derivation_index FOR UPDATE SKIP LOCKED LIMIT 1  (TZ 5.1 p.3)
    op.create_index(
        "ix_receive_addresses_free_pool",
        "receive_addresses",
        ["hd_account_id", "derivation_index"],
        postgresql_where=sa.text("status = 'free'"),
    )
    op.create_index(
        "ix_receive_addresses_current_invoice_id",
        "receive_addresses",
        ["current_invoice_id"],
        postgresql_where=sa.text("current_invoice_id IS NOT NULL"),
    )

    # --------------------------------------------------------------- assets
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("chain_id", sa.BigInteger(), nullable=False),
        sa.Column("contract_address", sa.String(length=42), nullable=True),
        sa.Column("symbol", sa.String(length=16), nullable=False),
        sa.Column("decimals", sa.SmallInteger(), nullable=False),
        sa.Column("is_native", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("decimals BETWEEN 0 AND 36", name="decimals_range"),
        sa.CheckConstraint(
            "(is_native AND contract_address IS NULL) "
            "OR (NOT is_native AND contract_address IS NOT NULL)",
            name="native_has_no_contract",
        ),
        sa.CheckConstraint(
            f"contract_address IS NULL OR contract_address ~ '{EVM_ADDRESS_RE}'",
            name="contract_address_format",
        ),
        sa.ForeignKeyConstraint(
            ["chain_id"],
            ["chains.chain_id"],
            name="fk_assets_chain_id_chains",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_assets"),
        # Target of the composite FKs that pin invoice/payment chain_id to the
        # asset's own chain.
        sa.UniqueConstraint("id", "chain_id", name="uq_assets_id_chain_id"),
        sa.UniqueConstraint("chain_id", "contract_address", name="uq_assets_chain_contract"),
        comment="Allow-listed payment assets (TZ 12: no arbitrary tokens).",
    )
    op.create_index(
        "uq_assets_native_per_chain",
        "assets",
        ["chain_id"],
        unique=True,
        postgresql_where=sa.text("is_native"),
    )

    # ------------------------------------------------------------- products
    op.create_table(
        "products",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("sku", sa.String(length=64), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("price_usd", PRICE_USD, nullable=False),
        sa.Column("kind", pg_enum("product_kind"), nullable=False),
        sa.Column("content_ref", sa.Text(), nullable=False),
        sa.Column("subscription_days", sa.Integer(), nullable=True),
        sa.Column("active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("price_usd > 0", name="price_positive"),
        sa.CheckConstraint(
            "(kind = 'subscription') = (subscription_days IS NOT NULL)",
            name="subscription_days_matches_kind",
        ),
        sa.CheckConstraint(
            "subscription_days IS NULL OR subscription_days > 0",
            name="subscription_days_positive",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_products"),
        sa.UniqueConstraint("sku", name="uq_products_sku"),
        comment="Catalog. `kind` decides whether the entitlement expires.",
    )

    # ---------------------------------------------------------------- users
    op.create_table(
        "users",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("tg_id", sa.BigInteger(), nullable=False),
        sa.Column("lang", sa.String(length=8), server_default=sa.text("'en'"), nullable=False),
        sa.Column(
            "internal_balance_usd", USD_AMOUNT, server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "settings_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("bot_blocked_at", TS, nullable=True),
        sa.Column("created_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "internal_balance_usd >= 0", name="internal_balance_non_negative"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("tg_id", name="uq_users_tg_id"),
        comment="Bot users. internal_balance_usd holds tolerated overpayment.",
    )

    # ------------------------------------------------------------- invoices
    op.create_table(
        "invoices",
        # UUIDv7 generated by the application — never a serial (TZ 5.8/T1.7).
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column("chain_id", sa.BigInteger(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("address_id", sa.BigInteger(), nullable=False),
        sa.Column("amount_due_raw", AMOUNT_RAW, nullable=False),
        sa.Column("amount_due_usd", USD_AMOUNT, nullable=False),
        sa.Column("rate_snapshot", RATE, nullable=False),
        sa.Column("rate_locked_until", TS, nullable=False),
        sa.Column(
            "status",
            pg_enum("invoice_status"),
            server_default=sa.text("'awaiting'"),
            nullable=False,
        ),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("topup_window_until", TS, nullable=False),
        sa.Column("created_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.Column("settled_at", TS, nullable=True),
        # HMAC-SHA256; the key lives in systemd credentials, never here (5.8/T1.3).
        sa.Column("integrity_mac", postgresql.BYTEA(), nullable=False),
        sa.Column("public_token", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.CheckConstraint("amount_due_raw > 0", name="amount_due_raw_positive"),
        sa.CheckConstraint("amount_due_usd > 0", name="amount_due_usd_positive"),
        sa.CheckConstraint("rate_snapshot > 0", name="rate_snapshot_positive"),
        sa.CheckConstraint(
            "topup_window_until >= expires_at", name="topup_window_after_expiry"
        ),
        sa.CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        sa.CheckConstraint(
            "settled_at IS NULL OR settled_at >= created_at",
            name="settled_after_creation",
        ),
        sa.CheckConstraint(
            "octet_length(integrity_mac) = 32", name="integrity_mac_length"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_invoices_user_id_users", ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["products.id"],
            name="fk_invoices_product_id_products",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["chain_id"],
            ["chains.chain_id"],
            name="fk_invoices_chain_id_chains",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["address_id"],
            ["receive_addresses.id"],
            name="fk_invoices_address_id_receive_addresses",
            ondelete="RESTRICT",
        ),
        # Keeps invoices.chain_id and assets.chain_id from ever diverging.
        sa.ForeignKeyConstraint(
            ["asset_id", "chain_id"],
            ["assets.id", "assets.chain_id"],
            name="fk_invoices_asset_id_chain_id_assets",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_invoices"),
        sa.UniqueConstraint("public_token", name="uq_invoices_public_token"),
        comment=(
            "Invoice state machine. No paid-amount counter on purpose: the "
            "total is SUM(payments.amount_raw) (TZ 5.3)."
        ),
    )
    # An address backs at most one live invoice at a time — the schema half of
    # the address-reuse rules (TZ 5.1, 5.8/T3.3).
    op.create_index(
        "uq_invoices_active_address",
        "invoices",
        ["address_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('awaiting', 'seen', 'partially_paid')"),
    )
    # Quota check for TZ 5.8/T5.1 (max active invoices per user).
    op.create_index(
        "ix_invoices_user_active",
        "invoices",
        ["user_id"],
        postgresql_where=sa.text("status IN ('awaiting', 'seen', 'partially_paid')"),
    )
    op.create_index("ix_invoices_status_expires_at", "invoices", ["status", "expires_at"])
    op.create_index("ix_invoices_chain_id_status", "invoices", ["chain_id", "status"])
    op.create_index("ix_invoices_user_id_created_at", "invoices", ["user_id", "created_at"])

    # Circular reference: receive_addresses.current_invoice_id -> invoices.id,
    # added after both tables exist.
    op.create_foreign_key(
        "fk_receive_addresses_current_invoice_id_invoices",
        "receive_addresses",
        "invoices",
        ["current_invoice_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    # ------------------------------------------------------------- payments
    op.create_table(
        "payments",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("chain_id", sa.BigInteger(), nullable=False),
        sa.Column("tx_hash", sa.String(length=66), nullable=False),
        # -1 marks a native-coin transfer, which has no log (TZ 5.2).
        sa.Column("log_index", sa.Integer(), nullable=False),
        sa.Column("block_number", sa.BigInteger(), nullable=False),
        sa.Column("address_id", sa.BigInteger(), nullable=False),
        sa.Column("invoice_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("amount_raw", AMOUNT_RAW, nullable=False),
        sa.Column("sender", sa.String(length=42), nullable=True),
        sa.Column(
            "status", pg_enum("payment_status"), server_default=sa.text("'seen'"), nullable=False
        ),
        sa.Column("confirmations_at_credit", sa.Integer(), nullable=True),
        sa.Column("anomaly", pg_enum("payment_anomaly"), nullable=True),
        sa.Column("created_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("amount_raw > 0", name="amount_raw_positive"),
        sa.CheckConstraint("block_number >= 0", name="block_number_non_negative"),
        sa.CheckConstraint("log_index >= -1", name="log_index_valid"),
        sa.CheckConstraint(f"tx_hash ~ '{TX_HASH_RE}'", name="tx_hash_format"),
        sa.CheckConstraint(
            f"sender IS NULL OR sender ~ '{EVM_ADDRESS_RE}'", name="sender_format"
        ),
        sa.CheckConstraint(
            "status <> 'credited' OR confirmations_at_credit IS NOT NULL",
            name="credited_records_confirmations",
        ),
        sa.CheckConstraint(
            "confirmations_at_credit IS NULL OR confirmations_at_credit >= 0",
            name="confirmations_non_negative",
        ),
        sa.ForeignKeyConstraint(
            ["chain_id"],
            ["chains.chain_id"],
            name="fk_payments_chain_id_chains",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["address_id"],
            ["receive_addresses.id"],
            name="fk_payments_address_id_receive_addresses",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["invoices.id"],
            name="fk_payments_invoice_id_invoices",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "chain_id"],
            ["assets.id", "assets.chain_id"],
            name="fk_payments_asset_id_chain_id_assets",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_payments"),
        # The single reason a redelivered log cannot be credited twice
        # (TZ 5.5, 5.8/T3.1). Inserts use ON CONFLICT DO NOTHING.
        sa.UniqueConstraint("chain_id", "tx_hash", "log_index", name="uq_payments_chain_tx_log"),
        comment=(
            "Raw incoming transfers. invoice_id is immutable, enforced by "
            "trigger payments_invoice_id_immutable (TZ 5.3, 5.8/T3)."
        ),
    )
    # SUM(amount_raw) per invoice over creditable statuses (TZ 5.3).
    op.create_index(
        "ix_payments_invoice_id_status",
        "payments",
        ["invoice_id", "status"],
        postgresql_where=sa.text("invoice_id IS NOT NULL"),
    )
    op.create_index("ix_payments_chain_id_block_number", "payments", ["chain_id", "block_number"])
    op.create_index(
        "ix_payments_address_id_block_number", "payments", ["address_id", "block_number"]
    )
    op.create_index(
        "ix_payments_open",
        "payments",
        ["status"],
        postgresql_where=sa.text("status IN ('seen', 'confirmed')"),
    )
    op.create_index(
        "ix_payments_anomaly",
        "payments",
        ["anomaly"],
        postgresql_where=sa.text("anomaly IS NOT NULL"),
    )

    # ---- immutability trigger on payments.invoice_id (TZ 5.3, 5.8/T3.2) ----
    op.execute(PAYMENTS_INVOICE_ID_IMMUTABLE_SQL)
    op.execute(
        """
        CREATE TRIGGER payments_invoice_id_immutable
        BEFORE UPDATE OF invoice_id ON payments
        FOR EACH ROW
        EXECUTE FUNCTION notchstave_payments_invoice_id_immutable();
        """
    )

    # --------------------------------------------------------- entitlements
    op.create_table(
        "entitlements",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column("invoice_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("granted_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", TS, nullable=True),
        sa.Column("revoked_at", TS, nullable=True),
        sa.Column("revoke_reason", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "revoked_at IS NOT NULL OR revoke_reason IS NULL",
            name="revoke_reason_needs_revocation",
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= granted_at",
            name="revoked_after_granted",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_entitlements_user_id_users", ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["products.id"],
            name="fk_entitlements_product_id_products",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["invoices.id"],
            name="fk_entitlements_invoice_id_invoices",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_entitlements"),
        comment=(
            "One active grant per invoice, enforced by the partial unique "
            "index entitlements_active_uniq (TZ 5.8/T2)."
        ),
    )
    # TZ 5.8/T2.1 verbatim. Partial, not plain: after a reorg revokes the grant
    # the same invoice must become grantable again (TZ 5.4).
    op.create_index(
        "entitlements_active_uniq",
        "entitlements",
        ["invoice_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.create_index(
        "ix_entitlements_user_id_expires_at", "entitlements", ["user_id", "expires_at"]
    )

    # -------------------------------------------------------------- refunds
    op.create_table(
        "refunds",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("invoice_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("amount_raw", AMOUNT_RAW, nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("to_address", sa.String(length=42), nullable=True),
        sa.Column(
            "status",
            pg_enum("refund_status"),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column("operator_id", sa.BigInteger(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.Column("executed_at", TS, nullable=True),
        sa.CheckConstraint("amount_raw > 0", name="amount_raw_positive"),
        sa.CheckConstraint(
            f"to_address IS NULL OR to_address ~ '{EVM_ADDRESS_RE}'",
            name="to_address_format",
        ),
        sa.CheckConstraint(
            "status <> 'executed' OR (executed_at IS NOT NULL "
            "AND to_address IS NOT NULL AND operator_id IS NOT NULL)",
            name="executed_requires_details",
        ),
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["invoices.id"],
            name="fk_refunds_invoice_id_invoices",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name="fk_refunds_asset_id_assets", ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_refunds"),
        comment="Accounting only — the bot never sends an outgoing transfer (TZ 12).",
    )
    # Reprocessing the same overpayment must not stack up refund requests.
    op.create_index(
        "uq_refunds_pending_per_invoice",
        "refunds",
        ["invoice_id"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index("ix_refunds_status", "refunds", ["status"])

    # ------------------------------------------------------- manual_reviews
    op.create_table(
        "manual_reviews",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("kind", pg_enum("manual_review_kind"), nullable=False),
        sa.Column("invoice_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("payment_id", sa.BigInteger(), nullable=True),
        sa.Column("opened_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.Column("resolved_at", TS, nullable=True),
        sa.Column("operator_id", sa.BigInteger(), nullable=True),
        sa.Column("resolution", pg_enum("manual_review_resolution"), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("policy_version", sa.String(length=32), nullable=True),
        sa.CheckConstraint(
            "invoice_id IS NOT NULL OR payment_id IS NOT NULL",
            name="targets_something",
        ),
        sa.CheckConstraint(
            "(resolved_at IS NULL AND resolution IS NULL) "
            "OR (resolved_at IS NOT NULL AND resolution IS NOT NULL "
            "AND operator_id IS NOT NULL)",
            name="resolution_complete",
        ),
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["invoices.id"],
            name="fk_manual_reviews_invoice_id_invoices",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["payment_id"],
            ["payments.id"],
            name="fk_manual_reviews_payment_id_payments",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_manual_reviews"),
        comment="Human-decided cases; every resolution keeps its author (TZ 5.8/T8).",
    )
    op.create_index(
        "uq_manual_reviews_open_payment",
        "manual_reviews",
        ["payment_id"],
        unique=True,
        postgresql_where=sa.text("resolved_at IS NULL AND payment_id IS NOT NULL"),
    )
    op.create_index(
        "ix_manual_reviews_open",
        "manual_reviews",
        ["opened_at"],
        postgresql_where=sa.text("resolved_at IS NULL"),
    )
    op.create_index("ix_manual_reviews_invoice_id", "manual_reviews", ["invoice_id"])

    # -------------------------------------------------------- sweep_exports
    op.create_table(
        "sweep_exports",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("generated_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.Column("address_count", sa.Integer(), nullable=False),
        sa.Column("total_raw", AMOUNT_RAW, nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("file_ref", sa.Text(), nullable=False),
        sa.Column("operator_id", sa.BigInteger(), nullable=True),
        sa.CheckConstraint(
            "address_count >= 0", name="address_count_non_negative"
        ),
        sa.CheckConstraint("total_raw >= 0", name="total_raw_non_negative"),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name="fk_sweep_exports_asset_id_assets",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_sweep_exports"),
        comment="Audit trail of sweep CSV exports. Signing happens offline (TZ 5.1).",
    )
    op.create_index("ix_sweep_exports_generated_at", "sweep_exports", ["generated_at"])

    # -------------------------------------------------------- notifications
    op.create_table(
        "notifications",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(length=48), nullable=False),
        sa.Column("ref_id", sa.String(length=64), nullable=False),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column(
            "payload_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "status",
            pg_enum("notification_status"),
            server_default=sa.text("'queued'"),
            nullable=False,
        ),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("sent_at", TS, nullable=True),
        sa.Column("message_id", sa.BigInteger(), nullable=True),
        sa.Column("created_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("attempts >= 0", name="attempts_non_negative"),
        sa.CheckConstraint(
            "status <> 'sent' OR sent_at IS NOT NULL", name="sent_has_timestamp"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_notifications_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_notifications"),
        # Delivery de-duplication (TZ 5.8/T2.5).
        sa.UniqueConstraint("kind", "ref_id", "dedup_key", name="uq_notifications_dedup"),
        comment="Outbox. Written in the same transaction as the side effect (TZ 5.7).",
    )
    # Outbox drain: WHERE status='queued' ORDER BY created_at FOR UPDATE SKIP LOCKED.
    op.create_index(
        "ix_notifications_queue",
        "notifications",
        ["created_at"],
        postgresql_where=sa.text("status = 'queued'"),
    )
    op.create_index("ix_notifications_user_id", "notifications", ["user_id"])

    # ------------------------------------------------------------ audit_log
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("actor_kind", pg_enum("actor_kind"), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_kind", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("before_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("after_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "args_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("policy_version", sa.String(length=32), nullable=True),
        sa.Column("created_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_audit_log"),
        comment="Append-only. App roles have no UPDATE/DELETE (TZ 5.8/T7).",
    )
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])
    op.create_index(
        "ix_audit_log_target_kind_target_id", "audit_log", ["target_kind", "target_id"]
    )
    op.create_index("ix_audit_log_action", "audit_log", ["action"])

    # ---------------------------------------------------------- rate_limits
    op.create_table(
        "rate_limits",
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("window_start", TS, nullable=False),
        sa.Column("invoices_created", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("cooldown_until", TS, nullable=True),
        sa.Column(
            "consecutive_expired", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.CheckConstraint(
            "invoices_created >= 0", name="invoices_created_non_negative"
        ),
        sa.CheckConstraint(
            "consecutive_expired >= 0", name="consecutive_expired_non_negative"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_rate_limits_user_id_users", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("user_id", "window_start", name="pk_rate_limits"),
        comment="Quota authority; Redis only caches it (TZ 5.8/T5).",
    )
    op.create_index("ix_rate_limits_window_start", "rate_limits", ["window_start"])


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS payments_invoice_id_immutable ON payments")
    op.execute("DROP FUNCTION IF EXISTS notchstave_payments_invoice_id_immutable()")

    op.drop_table("rate_limits")
    op.drop_table("audit_log")
    op.drop_table("notifications")
    op.drop_table("sweep_exports")
    op.drop_table("manual_reviews")
    op.drop_table("refunds")
    op.drop_table("entitlements")
    op.drop_table("payments")
    # Break the invoices <-> receive_addresses cycle before dropping either.
    op.drop_constraint(
        "fk_receive_addresses_current_invoice_id_invoices",
        "receive_addresses",
        type_="foreignkey",
    )
    op.drop_table("invoices")
    op.drop_table("users")
    op.drop_table("products")
    op.drop_table("assets")
    op.drop_table("receive_addresses")
    op.drop_table("hd_accounts")
    op.drop_table("blocks")
    op.drop_table("chains")

    for name in reversed(list(ENUM_DEFS)):
        op.execute(f"DROP TYPE IF EXISTS {name}")
