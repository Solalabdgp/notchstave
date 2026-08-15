"""Alembic environment for Notchstave.

`target_metadata` is wired to `core.db.Base` — the single source of schema
truth (see `core/db/__init__.py`). Importing `core.db.models` is what registers
every table on that metadata; without the import, autogenerate would happily
propose dropping the whole schema.

The connection string comes from the DATABASE_URL environment variable, never
from alembic.ini, so the same config works unmodified across local docker
compose, CI and Hetzner (TZ section 9: secrets never live in
docker-compose.yml or in git).

Both sync (`postgresql+psycopg://`) and async (`postgresql+asyncpg://`) URLs
work; the async branch is selected automatically from the driver name.
"""

from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection

# Make `core.*` importable no matter which directory alembic was invoked from.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.db import models  # noqa: E402,F401  (import registers every table)
from core.db.base import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    """DATABASE_URL is required; fail loudly instead of using a silent default."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. Example:\n"
            "  DATABASE_URL=postgresql+psycopg://notchstave:secret"
            "@localhost:5432/notchstave alembic upgrade head"
        )
    return url


def _is_async_url(url: str) -> bool:
    return any(driver in url for driver in ("+asyncpg", "+aiopg", "+psycopg_async"))


def _configure(connection: Connection | None = None, url: str | None = None) -> None:
    context.configure(
        connection=connection,
        url=url,
        target_metadata=target_metadata,
        # Without these two, a type change or a dropped server_default drifts
        # silently between models and the deployed schema — unacceptable in a
        # schema whose constraints are the security model (TZ 6).
        compare_type=True,
        compare_server_default=True,
        include_schemas=False,
        # One transaction per migration: a failed 0001 leaves nothing behind.
        transaction_per_migration=True,
        render_as_batch=False,
    )


def run_migrations_offline() -> None:
    """`alembic upgrade head --sql` — emit DDL without touching a database."""
    _configure(url=_database_url())
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    _configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


def _run_migrations_online_sync() -> None:
    from sqlalchemy import create_engine

    engine = create_engine(_database_url(), poolclass=pool.NullPool, future=True)
    try:
        with engine.connect() as connection:
            _do_run_migrations(connection)
    finally:
        engine.dispose()


async def _run_migrations_online_async() -> None:
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(_database_url(), poolclass=pool.NullPool)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_do_run_migrations)
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    if _is_async_url(_database_url()):
        asyncio.run(_run_migrations_online_async())
    else:
        _run_migrations_online_sync()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
