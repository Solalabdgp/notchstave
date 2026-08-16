"""An advisory Redis lock that is allowed to be wrong.

**Read this before touching anything in this file.**

TZ 5.8/T2.4, verbatim: "Redis-лок — оптимизация, а не гарантия... Redlock не
даёт корректности при рассинхроне часов, паузах GC и сетевых разделениях.
Правило записывается прямо в ТЗ, чтобы оно не потерялось при реализации:
**корректность держит PostgreSQL, Redis только экономит работу.** Если убрать
Redis целиком, система обязана остаться корректной — это отдельный тест."

So, concretely, what keeps a double grant from happening is:

1. ``SELECT ... FOR UPDATE`` on the invoice row — every worker doing money work
   on one invoice is serialised by Postgres (T2.3);
2. the CAS status transition — the loser sees zero affected rows (T2.2);
3. ``entitlements_active_uniq`` — and if both of the above were somehow wrong,
   the partial unique index still refuses the second grant (T2.1).

This lock adds none of that. It only stops twenty workers from opening twenty
transactions to discover that nineteen of them have nothing to do. If Redis is
down, flushed, partitioned, or lying, the worst outcome is wasted CPU.

That claim is not a comment — it is a test. ``test_race_twenty_workers`` runs
the same scenario three ways: with no lock at all, with a working lock, and
with a **deliberately broken** lock that hands the same invoice to every caller
at once. All three must produce exactly one entitlement. If a change to this
file ever makes the "broken lock" case fail, the change moved correctness into
Redis, which is precisely the thing the TZ forbids.
"""

from __future__ import annotations

import contextlib
import uuid
from collections.abc import AsyncIterator, Awaitable
from typing import Any, Protocol, runtime_checkable

__all__ = ["RedisLike", "InvoiceLock", "NullLock", "RedisAdvisoryLock", "BrokenLock"]


@runtime_checkable
class RedisLike(Protocol):
    """The two calls this module needs from ``redis.asyncio.Redis``.

    Typed structurally so that the settler does not import redis at all when it
    is not configured — and so the tests can pass in a fake without pretending
    to run a server.

    Declared as returning :class:`~collections.abc.Awaitable` rather than with
    ``async def``: ``async def`` in a Protocol demands a ``Coroutine``, and
    ``redis.asyncio.Redis`` annotates these two as returning ``Awaitable``. A
    real client would then fail to satisfy the protocol it was written for —
    the structural type has to describe the library, not an idealised version
    of it.
    """

    def set(
        self, name: str, value: str, *, nx: bool = ..., px: int | None = ...
    ) -> Awaitable[Any]: ...

    def eval(self, script: str, numkeys: int, *args: Any) -> Awaitable[Any]: ...


class InvoiceLock(Protocol):
    """Advisory, best-effort mutual exclusion on one invoice."""

    def acquire(self, invoice_id: uuid.UUID) -> contextlib.AbstractAsyncContextManager[bool]: ...


class NullLock:
    """No Redis configured. Everyone proceeds; Postgres sorts it out.

    This is the default, and it is a fully supported production configuration —
    not a degraded mode. Removing Redis removes an optimisation, nothing else.
    """

    @contextlib.asynccontextmanager
    async def acquire(self, invoice_id: uuid.UUID) -> AsyncIterator[bool]:
        yield True


#: Release compares the token before deleting, so a worker whose lock already
#: expired cannot delete a lock that now belongs to somebody else. This is
#: hygiene, not a correctness claim — see the module docstring.
_RELEASE_LUA = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
else
    return 0
end
"""


class RedisAdvisoryLock:
    """``SET invoice:<id> <token> NX PX <ttl>``, released with a compare-and-delete.

    A failed acquisition means "someone else is probably on it, come back
    later" — never "this invoice is settled". The caller reports
    :data:`settler.policy.Outcome.SKIPPED_BUSY` and the scan picks the invoice
    up on the next pass, which is why an expired-but-uncompleted lock costs one
    polling interval and nothing more.
    """

    def __init__(self, redis: RedisLike, *, ttl_ms: int = 30_000, prefix: str = "invoice:") -> None:
        self._redis = redis
        self._ttl_ms = ttl_ms
        self._prefix = prefix

    @contextlib.asynccontextmanager
    async def acquire(self, invoice_id: uuid.UUID) -> AsyncIterator[bool]:
        key = f"{self._prefix}{invoice_id}"
        token = uuid.uuid4().hex
        acquired = False
        try:
            acquired = bool(await self._redis.set(key, token, nx=True, px=self._ttl_ms))
        except Exception:  # noqa: BLE001 — an unreachable Redis must not stop settlement
            # Fail *open*: if the optimisation is unavailable, do the work.
            # Failing closed would make Redis a correctness dependency through
            # the back door, which is the exact thing T2.4 forbids.
            yield True
            return

        try:
            yield acquired
        finally:
            if acquired:
                with contextlib.suppress(Exception):
                    await self._redis.eval(_RELEASE_LUA, 1, key, token)


class BrokenLock:
    """A lock that grants everything to everyone. Test instrument, T2.4.

    Kept in the shipped package rather than in the test tree because it is the
    executable form of the guarantee this module claims: correctness must not
    change when the lock is replaced by this.
    """

    @contextlib.asynccontextmanager
    async def acquire(self, invoice_id: uuid.UUID) -> AsyncIterator[bool]:
        yield True
