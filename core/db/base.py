"""Declarative base and shared column types.

Naming convention is fixed here so that hand-written Alembic migrations and
`--autogenerate` produce identical constraint/index names. Do not change it
after the first migration is applied anywhere.
"""

from __future__ import annotations

from sqlalchemy import MetaData, Numeric
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for every Notchstave table."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# --- shared numeric domains -------------------------------------------------
#
# On-chain amounts are ALWAYS stored in the token's base units (raw uint256),
# never as floats and never pre-divided by `decimals`. NUMERIC(78, 0) covers the
# full uint256 range (2**256 - 1 has 78 decimal digits) with exact arithmetic,
# which is what `SUM(amount_raw)` in TZ 5.3 relies on.
AMOUNT_RAW = Numeric(78, 0)

# Fiat side. 6 decimals is enough for USD accounting and for USDC-equivalents.
USD_AMOUNT = Numeric(18, 6)

# Price snapshot (USD per 1 whole token) taken at invoice creation time.
RATE = Numeric(38, 18)

# Catalog price, human-facing.
PRICE_USD = Numeric(12, 2)

# --- reusable CHECK fragments ----------------------------------------------
EVM_ADDRESS_RE = r"^0x[0-9a-fA-F]{40}$"
TX_HASH_RE = r"^0x[0-9a-f]{64}$"
# m/44'/60'/0'  — hardened on all three upper levels (TZ 5.1, rule 1).
BIP32_PATH_PREFIX_RE = r"^m(/\d+'?)+$"
# BIP-32 key fingerprint, 4 bytes rendered as lowercase hex.
FINGERPRINT_RE = r"^[0-9a-f]{8}$"
