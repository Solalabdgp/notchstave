"""Notchstave data layer.

`Base.metadata` is the single source of truth for the schema; Alembic
(`migrations/env.py`) points at it directly.

Nothing in this package opens a connection or reads a secret. In particular the
account-level xpub is NEVER stored here — only `hd_accounts.xpub_fingerprint`
(4-byte BIP-32 fingerprint) for verification. See TZ 5.1 / 5.8-T4.
"""

from core.db import enums, models
from core.db.base import Base

__all__ = ["Base", "enums", "models"]
