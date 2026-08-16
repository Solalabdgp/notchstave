"""Persistence for the watcher: the protocol, and the PostgreSQL implementation.

Split in two so that the traversal and detection logic can be driven end to end
against an in-memory double (`tests/watcher/fakes.py`) that enforces the same
uniqueness rules as the database. The protocol is the contract both sides agree
on; the SQL lives in one file where a reviewer can read every money-adjacent
statement without chasing call sites — the same arrangement the deriver uses in
`deriver/pool.py`.

Import `watcher.store.postgres` only where a database is actually wanted: it
pulls in SQLAlchemy, while `watcher.store.base` is plain dataclasses.
"""

from watcher.store.base import ChainConfigRow, WatcherStore

__all__ = ["ChainConfigRow", "WatcherStore"]
