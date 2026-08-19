"""TZ 5.8/T5 quotas: what stops ``/buy`` from being a free address generator.

The attack is in the TZ and it is not about disk::

    Адреса активных инвойсов идут в topics[2] фильтра eth_getLogs. Провайдеры
    ограничивают размер массива, поэтому рост числа адресов линейно множит число
    запросов... Атакующий, не потратив ни цента, останавливает приём денег — это
    и есть настоящий ущерб.

Four of the six countermeasures live here (5.1 quotas, 5.2 ceiling — raised by
the pool and translated in :mod:`core.invoicing.service`, 5.4 short TTL — a
number in :mod:`core.invoicing.config`, 5.5 behavioural cooldown). 5.3, the
reuse pool, is the deriver's and is the only one that makes the gap-limit half
of the attack structurally impossible rather than merely expensive.

----

**The advisory lock is not optional and not the same thing as the Redis lock in
the settler.** TZ 5.8/T5.1: *"Проверка идёт под advisory-локом по ``user_id``,
иначе параллельные ``/buy`` пролезают мимо счётчика (та же гонка, что в T2,
только на другом объекте)."*

``pg_advisory_xact_lock`` — PostgreSQL's, held for the transaction, released by
COMMIT or ROLLBACK with no ``finally`` to forget. Contrast :mod:`settler.locks`,
which is a Redis lock explicitly allowed to be wrong because correctness there
is carried by a unique index. Here there is no unique index to fall back on:
"this user has at most three live invoices" is a *count*, and a count cannot be
expressed as a constraint on a row. Serialising the check-and-insert is the
mechanism, not an optimisation, which is why it is in Postgres and in the same
transaction as the INSERT.

**Redis, if configured, may only ever say no.** TZ 5.8/T5.1 again: *"Счётчик в
Redis для скорости, но решение подтверждается запросом к БД в той же транзакции
— сброс или перезапуск Redis не должен открывать шлюз."* :class:`QuotaCache`
below is therefore shaped so that its optimistic answer is unusable: it can
short-circuit a *rejection*, and a cache miss, a flush or an unreachable server
simply means the database decides. There is no code path in which a Redis
answer permits something the database would have refused.

**Where the authoritative numbers come from.** Not from ``rate_limits``. The
active count and the hourly count are both computed from ``invoices`` itself —
``invoices`` is append-only for the issuing role (no DELETE grant anywhere in
migration 0002) so it cannot be trimmed to make room, while a counter column
can be set back to zero by anything that can write it. ``rate_limits`` is kept
in step as an auditable mirror and is the *home* of the one piece of state that
is not derivable from ``invoices``: the behavioural cooldown deadline.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Protocol

import psycopg
from psycopg.rows import dict_row

from core.db import enums as E
from core.invoicing.config import InvoicingPolicy
from core.invoicing.errors import (
    BehaviouralCooldown,
    HourlyQuotaExceeded,
    QuotaExceeded,
    TooManyActiveInvoices,
)
from core.invoicing.metrics import RATELIMIT_HITS

__all__ = [
    "ADVISORY_NAMESPACE",
    "QuotaCache",
    "NullQuotaCache",
    "RedisQuotaCache",
    "QuotaSnapshot",
    "lock_user",
    "snapshot",
    "enforce",
    "record_issued",
    "note_refusal",
]

#: Namespace for ``pg_advisory_xact_lock(int4, int4)``. Advisory locks share one
#: cluster-wide space, so a bare ``user_id`` would collide with any other
#: subsystem — present or future, in this database or another one on the same
#: server — that also locks by a small integer. Arbitrary constant, never
#: reused: grep for it before adding a second advisory lock anywhere.
ADVISORY_NAMESPACE = 0x4E4F5443  # "NOTC"

#: Statuses that hold an address and are still waiting for money. Mirrors the
#: predicate of ``uq_invoices_active_address`` and ``ix_invoices_user_active``;
#: these three places are one rule and must move together.
_LIVE = tuple(str(s) for s in E.LIVE_INVOICE_STATUSES)

_EXPIRED = str(E.InvoiceStatus.EXPIRED)


# ---------------------------------------------------------------------------
# Optional Redis fast path
# ---------------------------------------------------------------------------


class QuotaCache(Protocol):
    """A cache that is allowed to refuse and never allowed to permit.

    :meth:`refuses` answers "is this user already known to be over a limit". A
    ``True`` short-circuits before the transaction opens and saves a lock plus
    two counts; a ``False`` means nothing at all and the database is consulted
    exactly as if there were no cache. That asymmetry is the whole contract, and
    it is what makes "flush Redis" a performance event rather than a security
    one.
    """

    def refuses(self, user_id: int) -> bool: ...

    def note_issued(self, user_id: int, *, ttl_seconds: int, limit: int) -> None: ...


class NullQuotaCache:
    """No Redis configured. Every decision goes to PostgreSQL. Fully supported."""

    def refuses(self, user_id: int) -> bool:
        return False

    def note_issued(self, user_id: int, *, ttl_seconds: int, limit: int) -> None:
        return None


class _RedisLike(Protocol):
    """The three calls :class:`RedisQuotaCache` needs from ``redis.Redis``.

    Structural, like :class:`settler.locks.RedisLike`, so that nothing in
    ``core`` imports redis when it is not configured — and so a test can pass a
    dictionary-backed fake without pretending to run a server.
    """

    def get(self, name: str) -> Any: ...

    def incr(self, name: str) -> Any: ...

    def expire(self, name: str, time: int) -> Any: ...


class RedisQuotaCache:
    """An hourly counter in Redis, consulted only to reject early.

    Every method swallows connection errors and degrades to "no opinion". That
    is not sloppiness about error handling: an exception here would turn an
    unreachable cache into an outage of the purchase flow, which is precisely
    the coupling the TZ forbids in the other direction too.
    """

    def __init__(self, redis: _RedisLike, *, prefix: str = "invoice-quota:") -> None:
        self._redis = redis
        self._prefix = prefix
        self._limits: dict[int, int] = {}

    def _key(self, user_id: int) -> str:
        return f"{self._prefix}{user_id}"

    def refuses(self, user_id: int) -> bool:
        limit = self._limits.get(user_id)
        if limit is None:
            # Nothing has been recorded for this user in this process yet, so
            # there is no limit to compare against. Ask the database.
            return False
        try:
            raw = self._redis.get(self._key(user_id))
        except Exception:  # noqa: BLE001 — an unreachable cache is not an outage
            return False
        if raw is None:
            return False
        try:
            return int(raw) >= limit
        except (TypeError, ValueError):  # pragma: no cover - corrupt value
            return False

    def note_issued(self, user_id: int, *, ttl_seconds: int, limit: int) -> None:
        self._limits[user_id] = limit
        try:
            self._redis.incr(self._key(user_id))
            self._redis.expire(self._key(user_id), ttl_seconds)
        except Exception:  # noqa: BLE001
            return None


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class QuotaSnapshot:
    """What the database says about this user, as of inside the lock."""

    user_id: int
    active_invoices: int
    invoices_in_window: int
    window_start: dt.datetime
    cooldown_until: dt.datetime | None
    expired_streak: int


SQL_LOCK_USER = "SELECT pg_advisory_xact_lock(%(namespace)s, %(key)s)"

SQL_COUNT_ACTIVE = """
SELECT count(*) AS n
  FROM invoices
 WHERE user_id = %(user_id)s
   AND status = ANY(%(live)s::invoice_status[])
"""

SQL_COUNT_IN_WINDOW = """
SELECT count(*) AS n
  FROM invoices
 WHERE user_id = %(user_id)s
   AND created_at >= %(window_start)s
"""

SQL_COOLDOWN = """
SELECT max(cooldown_until) AS cooldown_until
  FROM rate_limits
 WHERE user_id = %(user_id)s
"""

#: The last N invoices, newest first. The streak is the run of ``expired`` at
#: the head of this list; anything else stops the count.
SQL_RECENT_STATUSES = """
SELECT status::text AS status
  FROM invoices
 WHERE user_id = %(user_id)s
 ORDER BY created_at DESC, id DESC
 LIMIT %(limit)s
"""

#: Hour-bucketed mirror of the decision, upserted in the same transaction as the
#: invoice. ``invoices_created`` is incremented rather than set, so two issuances
#: in the same hour under the same lock cannot lose one another.
SQL_RECORD_ISSUED = """
INSERT INTO rate_limits (user_id, window_start, invoices_created, consecutive_expired)
VALUES (%(user_id)s, date_trunc('hour', %(now)s), 1, %(consecutive_expired)s)
ON CONFLICT (user_id, window_start) DO UPDATE
    SET invoices_created    = rate_limits.invoices_created + 1,
        consecutive_expired = EXCLUDED.consecutive_expired
RETURNING invoices_created
"""

#: Written when the streak trips. Stored on the current hour's row and read back
#: with ``max(cooldown_until)`` over the user, so a window roll cannot lose it.
SQL_SET_COOLDOWN = """
INSERT INTO rate_limits (user_id, window_start, invoices_created,
                         cooldown_until, consecutive_expired)
VALUES (%(user_id)s, date_trunc('hour', %(now)s), 0, %(cooldown_until)s,
        %(consecutive_expired)s)
ON CONFLICT (user_id, window_start) DO UPDATE
    SET cooldown_until      = GREATEST(
            COALESCE(rate_limits.cooldown_until, EXCLUDED.cooldown_until),
            EXCLUDED.cooldown_until),
        consecutive_expired = EXCLUDED.consecutive_expired
RETURNING cooldown_until
"""


def lock_user(conn: psycopg.Connection[Any], user_id: int) -> None:
    """Serialise every quota decision for one user (TZ 5.8/T5.1).

    Transaction-scoped, so there is no release path to get wrong and no lock
    left behind by a crashed worker. It blocks rather than skipping: two
    simultaneous ``/buy`` presses from one person must both get a definite
    answer, and the second one's answer depends on the first one's outcome.

    The 64-bit ``user_id`` is folded to 31 bits for the ``(int4, int4)`` form.
    A collision between two users whose ids differ only above bit 31 costs them
    a moment of shared serialisation and nothing else — they are still counted
    separately, because the counting is done by the SQL below and not by the
    lock.
    """
    with conn.cursor() as cur:
        cur.execute(
            SQL_LOCK_USER,
            {"namespace": ADVISORY_NAMESPACE, "key": int(user_id) & 0x7FFF_FFFF},
        )


def _expired_streak(rows: list[dict[str, Any]]) -> int:
    """Length of the run of ``expired`` at the head of the recent-invoice list.

    ``cancelled`` breaks the streak, and that is a deliberate choice worth
    defending: cancelling returns the address to the pool immediately, which is
    the behaviour the cooldown exists to encourage. A script that evades the
    cooldown by cancelling every invoice is a script that is no longer holding
    addresses — it has stopped performing the attack in order to avoid the
    countermeasure, which is the outcome we wanted.
    """
    streak = 0
    for row in rows:
        if row["status"] != _EXPIRED:
            break
        streak += 1
    return streak


def snapshot(
    conn: psycopg.Connection[Any],
    user_id: int,
    *,
    policy: InvoicingPolicy,
    now: dt.datetime,
) -> QuotaSnapshot:
    """Read every number the quota decision needs, inside the caller's transaction.

    Call :func:`lock_user` first. Reading these counts without the lock produces
    a snapshot that was true and is no longer, which is the exact race TZ
    5.8/T5.1 names.
    """
    window_start = now - policy.quota_window
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SQL_COUNT_ACTIVE, {"user_id": user_id, "live": list(_LIVE)})
        active = int((cur.fetchone() or {"n": 0})["n"])

        cur.execute(SQL_COUNT_IN_WINDOW, {"user_id": user_id, "window_start": window_start})
        in_window = int((cur.fetchone() or {"n": 0})["n"])

        cur.execute(SQL_COOLDOWN, {"user_id": user_id})
        cooldown_row = cur.fetchone() or {"cooldown_until": None}

        cur.execute(
            SQL_RECENT_STATUSES,
            {"user_id": user_id, "limit": policy.expired_streak_limit},
        )
        recent = list(cur.fetchall())

    return QuotaSnapshot(
        user_id=user_id,
        active_invoices=active,
        invoices_in_window=in_window,
        window_start=window_start,
        cooldown_until=cooldown_row["cooldown_until"],
        expired_streak=_expired_streak(recent),
    )


def note_refusal(error: QuotaExceeded) -> None:
    """Bump ``notchstave_invoice_ratelimit_hits_total`` with the error's own scope."""
    RATELIMIT_HITS.labels(scope=error.scope).inc()


def enforce(
    conn: psycopg.Connection[Any],
    snap: QuotaSnapshot,
    *,
    policy: InvoicingPolicy,
    now: dt.datetime,
) -> None:
    """Raise the right :class:`QuotaExceeded` subclass, or return.

    Order matters and is from most to least sticky: a user in cooldown is told
    about the cooldown, not about a count they cannot do anything about. Each
    refusal increments the metric with its own ``scope`` label before raising,
    so a caller that forgets to handle one still leaves a trace on the dashboard
    TZ section 7 asks for.
    """
    if snap.cooldown_until is not None and snap.cooldown_until > now:
        error = BehaviouralCooldown(
            f"user_id={snap.user_id} is in behavioural cooldown until "
            f"{snap.cooldown_until.isoformat()} (TZ 5.8/T5.5)",
            limit=policy.expired_streak_limit,
            observed=snap.expired_streak,
            retry_at=snap.cooldown_until,
        )
        note_refusal(error)
        raise error

    # The streak is evaluated *before* the counts because it is the condition
    # that creates state: tripping it writes a deadline that outlives this
    # request, and a user who is about to be put in cooldown should be told that
    # rather than being told they have three invoices open.
    if snap.expired_streak >= policy.expired_streak_limit:
        until = now + policy.cooldown
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                SQL_SET_COOLDOWN,
                {
                    "user_id": snap.user_id,
                    "now": now,
                    "cooldown_until": until,
                    "consecutive_expired": snap.expired_streak,
                },
            )
            row = cur.fetchone()
        effective = row["cooldown_until"] if row is not None else until
        error = BehaviouralCooldown(
            f"user_id={snap.user_id} has {snap.expired_streak} consecutive expired "
            f"invoices (limit {policy.expired_streak_limit}); cooldown until "
            f"{effective.isoformat()} (TZ 5.8/T5.5)",
            limit=policy.expired_streak_limit,
            observed=snap.expired_streak,
            retry_at=effective,
        )
        note_refusal(error)
        raise error

    if snap.active_invoices >= policy.max_active_invoices_per_user:
        active_error = TooManyActiveInvoices(
            f"user_id={snap.user_id} has {snap.active_invoices} live invoices, "
            f"limit is {policy.max_active_invoices_per_user} (TZ 5.8/T5.1)",
            limit=policy.max_active_invoices_per_user,
            observed=snap.active_invoices,
        )
        note_refusal(active_error)
        raise active_error

    if snap.invoices_in_window >= policy.max_invoices_per_hour:
        hourly_error = HourlyQuotaExceeded(
            f"user_id={snap.user_id} created {snap.invoices_in_window} invoices since "
            f"{snap.window_start.isoformat()}, limit is {policy.max_invoices_per_hour} "
            "(TZ 5.8/T5.1)",
            limit=policy.max_invoices_per_hour,
            observed=snap.invoices_in_window,
            retry_at=snap.window_start + policy.quota_window,
        )
        note_refusal(hourly_error)
        raise hourly_error


def record_issued(
    conn: psycopg.Connection[Any],
    user_id: int,
    *,
    now: dt.datetime,
    expired_streak: int,
) -> int:
    """Mirror the issuance into ``rate_limits``, in the issuance transaction.

    Same transaction as the ``invoices`` INSERT on purpose: a counter that
    commits separately from the thing it counts is a counter that can be walked
    past by crashing at the right moment, in either direction — over-counting a
    rolled-back invoice or under-counting a committed one.

    Returns the new hour-bucket count, which the caller feeds to the Redis
    cache so the fast path starts from a true number rather than from zero.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            SQL_RECORD_ISSUED,
            {"user_id": user_id, "now": now, "consecutive_expired": expired_streak},
        )
        row = cur.fetchone()
    return int(row["invoices_created"]) if row is not None else 1
