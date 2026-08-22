"""The address pool: hand out receive addresses, take them back safely.

Raw SQL over psycopg 3 on purpose. The deriver does not import ``core`` (see
``deriver/pyproject.toml`` for why the isolation is mechanical rather than
social), and the handful of statements below do not need an ORM. It is also
the only process with INSERT/UPDATE on ``receive_addresses`` and UPDATE on
``hd_accounts`` — enforced by the grants in migration 0002, not by convention
(TZ 5.8/T1.2).

**Allocation order (TZ 5.1, p. 3).** Free pool first, ``next_index`` only when
the pool is empty. That ordering is not an optimisation: it makes the consumed
index space a function of *peak concurrent invoices* rather than of total
``/buy`` presses ever, which is the only measure that makes the gap-limit
attack in TZ 5.8/T5 structurally impossible instead of merely expensive.

**The race.** ``FOR UPDATE SKIP LOCKED`` does two things at once: two
simultaneous ``/buy`` calls cannot take the same row, and they do not queue
behind each other on it — the second one skips to the next free address instead
of blocking. ``UNIQUE (hd_account_id, derivation_index)`` is the backstop under
that, in the spirit of TZ 5.8/T2: code can be wrong, a unique index cannot.

----

**A schema-level ordering constraint the caller has to know about.**

``invoices.address_id`` is NOT NULL and references ``receive_addresses.id``,
while ``receive_addresses.current_invoice_id`` references ``invoices.id``, and
neither foreign key is DEFERRABLE (migration 0001). The CHECK constraint
``reserved_state_bound`` additionally forbids ``status='reserved'`` with a NULL
``current_invoice_id``. Together these make a single-statement "derive a brand
new address and bind it to a brand new invoice" impossible: each row needs the
other to exist first, and the two writes belong to different database roles in
different processes anyway.

Holding the row lock across the gap does not work either, and the reason is
worth writing down: inserting the invoice takes a ``FOR KEY SHARE`` lock on the
referenced ``receive_addresses`` row, which conflicts with the ``FOR UPDATE``
the deriver would be holding — the api would block until the deriver's
transaction ended.

So there are two entry points here, and they exist for different situations:

* :func:`reserve_address_for_invoice` — the fused statement TZ 5.1 p. 3 spells
  out. Correct and race-free in one shot, and the right call once the FK cycle
  is broken (make one of the two constraints DEFERRABLE INITIALLY DEFERRED, or
  let ``invoices.address_id`` be nullable until binding).
* :func:`allocate_free_address` + :func:`bind_address_to_invoice` — the
  two-phase protocol that works against the schema exactly as it stands today:
  deriver puts a free address in the pool, api inserts the invoice pointing at
  it, deriver binds it. The window between phases is covered by the partial
  unique index ``uq_invoices_active_address``, so a lost race surfaces as a
  constraint violation on the api's insert rather than as two invoices sharing
  an address.

Which one Week 2 adopts is an invoice-creation decision, not a deriver one.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

import psycopg
from psycopg.rows import dict_row

__all__ = [
    "PoolError",
    "AddressPoolExhausted",
    "AddressNotBindable",
    "InactiveHDAccount",
    "PooledAddress",
    "allocate_free_address",
    "bind_address_to_invoice",
    "reserve_address_for_invoice",
    "schedule_release",
    "release_due_addresses",
    "mark_address_funded",
    "verify_stored_address",
    "hd_account_ids",
]


class AddressDeriver(Protocol):
    """Structural type for what this module needs from :class:`deriver.service.Deriver`."""

    def address(self, hd_account_id: int, derivation_index: int) -> str: ...

    def verify(self, address: str, hd_account_id: int, derivation_index: int) -> bool: ...


class PoolError(Exception):
    """Base class for address-pool failures."""


class AddressPoolExhausted(PoolError):
    """``max_active_addresses`` reached (TZ 5.8/T5.2).

    Deliberately a distinct exception: the caller must answer the user with an
    honest "not right now, try again later" and raise the alert, not return a
    500 and not quietly derive one more address. The ceiling exists to bound
    the ``eth_getLogs`` filter size, so exceeding it degrades payment detection
    for everyone — which is the actual damage in T5, not the disk space.
    """


class AddressNotBindable(PoolError):
    """The address was not in a state that allows binding it to this invoice."""


class InactiveHDAccount(PoolError):
    """No active ``hd_accounts`` row with this id (or it is mid-rotation)."""


@dataclass(frozen=True, slots=True)
class PooledAddress:
    """A row of ``receive_addresses`` as this module hands it around."""

    address_id: int
    hd_account_id: int
    derivation_index: int
    address: str
    #: True when this address was freshly derived rather than reused. Feeds the
    #: `address_index_gap` metric (TZ 5.1 p. 2, 5.8/T5).
    newly_derived: bool


# --------------------------------------------------------------------------
# SQL. Kept as module constants so the tests can assert on their shape without
# a live database, and so a reviewer can read the money-critical statements in
# one place instead of hunting them through call sites.
# --------------------------------------------------------------------------

#: TZ 5.1 p. 3, verbatim in intent: take the lowest-numbered free address,
#: skipping any row another transaction is already working on.
SQL_TAKE_FREE_FROM_POOL = """
UPDATE receive_addresses AS ra
   SET status = 'reserved',
       current_invoice_id = %(invoice_id)s,
       reserved_from_block = %(reserved_from_block)s,
       cooldown_until = NULL
 WHERE ra.id = (
           SELECT inner_ra.id
             FROM receive_addresses AS inner_ra
            WHERE inner_ra.hd_account_id = %(hd_account_id)s
              AND inner_ra.status = 'free'
              AND NOT inner_ra.ever_funded
              AND (inner_ra.cooldown_until IS NULL OR inner_ra.cooldown_until <= now())
            ORDER BY inner_ra.derivation_index
              FOR UPDATE SKIP LOCKED
            LIMIT 1
       )
RETURNING ra.id, ra.hd_account_id, ra.derivation_index, ra.address
"""

#: Same pickup, but leaves the row free — phase 1 of the two-phase protocol.
#: `FOR UPDATE SKIP LOCKED` still applies: it is what keeps two concurrent
#: callers from being handed the same candidate inside overlapping transactions.
SQL_PEEK_FREE_FROM_POOL = """
SELECT id, hd_account_id, derivation_index, address
  FROM receive_addresses
 WHERE hd_account_id = %(hd_account_id)s
   AND status = 'free'
   AND NOT ever_funded
   AND (cooldown_until IS NULL OR cooldown_until <= now())
 ORDER BY derivation_index
   FOR UPDATE SKIP LOCKED
 LIMIT 1
"""

#: Locks the account row so that the index bump below is serialised. Only
#: reached when the pool is empty, so this is not the hot path.
SQL_LOCK_ACCOUNT = """
SELECT ha.id,
       ha.next_index,
       ha.max_active_addresses,
       ha.path_prefix,
       ha.xpub_fingerprint,
       (SELECT count(*)
          FROM receive_addresses ra
         WHERE ra.hd_account_id = ha.id
           AND ra.status = 'reserved') AS active_addresses
  FROM hd_accounts ha
 WHERE ha.id = %(hd_account_id)s
   AND ha.is_active
   FOR UPDATE
"""

#: `RETURNING next_index - 1` gives the index this caller just claimed. The
#: increment and the claim are one statement, so there is no read-then-write
#: window for two callers to land on the same index (TZ 5.1 p. 3).
SQL_BUMP_NEXT_INDEX = """
UPDATE hd_accounts
   SET next_index = next_index + 1
 WHERE id = %(hd_account_id)s
   AND is_active
RETURNING next_index - 1 AS derivation_index
"""

SQL_INSERT_ADDRESS = """
INSERT INTO receive_addresses
       (hd_account_id, derivation_index, address, status,
        current_invoice_id, reserved_from_block)
VALUES (%(hd_account_id)s, %(derivation_index)s, %(address)s, %(status)s,
        %(invoice_id)s, %(reserved_from_block)s)
RETURNING id, hd_account_id, derivation_index, address
"""

#: Compare-and-set, in the style TZ 5.8/T2.2 requires for money-adjacent state:
#: the expected current state is in the WHERE clause, and zero affected rows
#: means somebody else already moved it.
SQL_BIND_ADDRESS = """
UPDATE receive_addresses
   SET status = 'reserved',
       current_invoice_id = %(invoice_id)s,
       reserved_from_block = %(reserved_from_block)s,
       cooldown_until = NULL
 WHERE id = %(address_id)s
   AND status = 'free'
   AND current_invoice_id IS NULL
   AND NOT ever_funded
RETURNING id, hd_account_id, derivation_index, address
"""

#: Condition 2 of the three reuse rules: the address becomes returnable only
#: after the top-up window plus `address_cooldown`, so that a late top-up lands
#: in its own invoice and not in a stranger's (TZ 5.1 p. 2, 5.8/T3.3).
SQL_SCHEDULE_RELEASE = """
UPDATE receive_addresses
   SET cooldown_until = %(cooldown_until)s
 WHERE id = %(address_id)s
   AND status = 'reserved'
RETURNING id, cooldown_until
"""

#: All three conditions in one WHERE clause:
#:   `NOT ever_funded`         -> condition 1, funded addresses never come back;
#:   `cooldown_until <= now()` -> condition 2, the top-up window has closed;
#:   invoice no longer live    -> the address is genuinely done with its tenant.
#: Condition 3 (`reserved_from_block`) is not enforced here because it is a
#: property of the *next* reservation, set when the address is handed out again.
SQL_RELEASE_DUE = """
UPDATE receive_addresses AS ra
   SET status = 'free',
       current_invoice_id = NULL,
       reserved_from_block = NULL,
       cooldown_until = NULL
 WHERE ra.hd_account_id = %(hd_account_id)s
   AND ra.status = 'reserved'
   AND NOT ra.ever_funded
   AND ra.cooldown_until IS NOT NULL
   AND ra.cooldown_until <= now()
   AND NOT EXISTS (
           SELECT 1
             FROM invoices i
            WHERE i.id = ra.current_invoice_id
              AND i.status IN ('awaiting', 'seen', 'partially_paid')
       )
RETURNING ra.id, ra.derivation_index, ra.address
"""

#: One-way latch. `ever_funded` is never cleared anywhere in this codebase —
#: grep for it and the only writes are this statement's `true` (TZ 5.1 p. 2,
#: condition 1).
SQL_MARK_FUNDED = """
UPDATE receive_addresses
   SET status = 'funded',
       ever_funded = true,
       first_seen_funds_at = COALESCE(first_seen_funds_at, now())
 WHERE id = %(address_id)s
   AND status IN ('free', 'reserved', 'funded')
RETURNING id, derivation_index, address, ever_funded
"""

#: Every derivation account, active or not. Not filtered on ``is_active``, and
#: that is deliberate: :func:`release_due_addresses` is keyed per account and an
#: account taken out of service mid-rotation (TZ 5.8/T4) still has reserved
#: addresses on it whose invoices are finished. Leaving those pinned forever
#: would make a rotation a permanent leak of index space on the old account —
#: small, but exactly the kind of "it only happens once" that nobody notices for
#: a year. The release predicate is identical either way, so including inactive
#: accounts costs one no-op statement per sweep and closes the case.
SQL_ALL_HD_ACCOUNT_IDS = "SELECT id FROM hd_accounts ORDER BY id"

SQL_SELECT_ADDRESS_ROW = """
SELECT id, hd_account_id, derivation_index, address, status
  FROM receive_addresses
 WHERE id = %(address_id)s
"""


# --------------------------------------------------------------------------
# Operations
# --------------------------------------------------------------------------


def _fetch_active_account(cur: psycopg.Cursor[Any], hd_account_id: int) -> dict[str, Any]:
    cur.execute(SQL_LOCK_ACCOUNT, {"hd_account_id": hd_account_id})
    account = cur.fetchone()
    if account is None:
        raise InactiveHDAccount(
            f"hd_account_id={hd_account_id} is missing or not active; "
            "an inactive account is watch-only until its final sweep (TZ 5.8/T4 rotation)"
        )
    return account


def _derive_new_address(
    cur: psycopg.Cursor[Any],
    deriver: AddressDeriver,
    hd_account_id: int,
    *,
    invoice_id: uuid.UUID | None,
    reserved_from_block: int | None,
) -> PooledAddress:
    """Bump ``next_index``, derive, insert. Only called when the pool is empty."""
    account = _fetch_active_account(cur, hd_account_id)

    if account["active_addresses"] >= account["max_active_addresses"]:
        raise AddressPoolExhausted(
            f"hd_account_id={hd_account_id} has {account['active_addresses']} reserved "
            f"addresses, ceiling is {account['max_active_addresses']} (TZ 5.8/T5.2)"
        )

    cur.execute(SQL_BUMP_NEXT_INDEX, {"hd_account_id": hd_account_id})
    bumped = cur.fetchone()
    if bumped is None:  # pragma: no cover - the lock above already proved it exists
        raise InactiveHDAccount(f"hd_account_id={hd_account_id} vanished mid-transaction")
    derivation_index = int(bumped["derivation_index"])

    address = deriver.address(hd_account_id, derivation_index)
    status = "free" if invoice_id is None else "reserved"

    cur.execute(
        SQL_INSERT_ADDRESS,
        {
            "hd_account_id": hd_account_id,
            "derivation_index": derivation_index,
            "address": address,
            "status": status,
            "invoice_id": invoice_id,
            "reserved_from_block": reserved_from_block,
        },
    )
    row = cur.fetchone()
    if row is None:  # pragma: no cover
        raise PoolError("address insert returned no row")
    return PooledAddress(
        address_id=int(row["id"]),
        hd_account_id=int(row["hd_account_id"]),
        derivation_index=int(row["derivation_index"]),
        address=row["address"],
        newly_derived=True,
    )


def allocate_free_address(
    conn: psycopg.Connection[Any],
    deriver: AddressDeriver,
    hd_account_id: int,
) -> PooledAddress:
    """Phase 1: guarantee a free address exists and return it, still ``free``.

    Pool first, ``next_index`` only if the pool is empty (TZ 5.1 p. 3). The
    returned address is *not* bound to an invoice — the caller inserts the
    invoice against ``address_id`` and then calls :func:`bind_address_to_invoice`.

    Does not commit. The caller owns the transaction, because in the intended
    flow this call is one step of a longer unit of work.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SQL_PEEK_FREE_FROM_POOL, {"hd_account_id": hd_account_id})
        row = cur.fetchone()
        if row is not None:
            return PooledAddress(
                address_id=int(row["id"]),
                hd_account_id=int(row["hd_account_id"]),
                derivation_index=int(row["derivation_index"]),
                address=row["address"],
                newly_derived=False,
            )
        return _derive_new_address(
            cur, deriver, hd_account_id, invoice_id=None, reserved_from_block=None
        )


def bind_address_to_invoice(
    conn: psycopg.Connection[Any],
    address_id: int,
    invoice_id: uuid.UUID,
    reserved_from_block: int,
) -> PooledAddress:
    """Phase 2: move a specific free address to ``reserved`` for this invoice.

    ``reserved_from_block`` is the chain head at reservation time and is the
    third reuse condition (TZ 5.1 p. 2): a payment mined below it belongs to
    the address's previous tenant and is never credited to this invoice — it
    becomes ``orphan_payment`` and goes to manual review (TZ 5.8/T3.3).

    Raises rather than returning False on a lost race: by this point the caller
    has already inserted an invoice pointing at this address, so a failure to
    bind is an inconsistency that must abort the transaction, not a value to
    branch on.
    """
    if reserved_from_block < 0:
        raise ValueError("reserved_from_block must be a non-negative block height")

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            SQL_BIND_ADDRESS,
            {
                "address_id": address_id,
                "invoice_id": invoice_id,
                "reserved_from_block": reserved_from_block,
            },
        )
        row = cur.fetchone()
        if row is None:
            raise AddressNotBindable(
                f"address_id={address_id} is not free and unbound; it was taken, "
                "funded or released between allocation and binding"
            )
        return PooledAddress(
            address_id=int(row["id"]),
            hd_account_id=int(row["hd_account_id"]),
            derivation_index=int(row["derivation_index"]),
            address=row["address"],
            newly_derived=False,
        )


def reserve_address_for_invoice(
    conn: psycopg.Connection[Any],
    deriver: AddressDeriver,
    hd_account_id: int,
    invoice_id: uuid.UUID,
    reserved_from_block: int,
) -> PooledAddress:
    """Single-statement allocation: pool first, derive only if the pool is empty.

    This is TZ 5.1 p. 3 as written, and it is race-free without a second phase.
    Its precondition is that the ``invoices`` row already exists — see the
    module docstring for the foreign-key cycle that currently makes that
    precondition awkward for a brand-new address, and for what has to change in
    the schema before this becomes the default path.
    """
    if reserved_from_block < 0:
        raise ValueError("reserved_from_block must be a non-negative block height")

    params = {
        "hd_account_id": hd_account_id,
        "invoice_id": invoice_id,
        "reserved_from_block": reserved_from_block,
    }
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SQL_TAKE_FREE_FROM_POOL, params)
        row = cur.fetchone()
        if row is not None:
            return PooledAddress(
                address_id=int(row["id"]),
                hd_account_id=int(row["hd_account_id"]),
                derivation_index=int(row["derivation_index"]),
                address=row["address"],
                newly_derived=False,
            )
        return _derive_new_address(
            cur,
            deriver,
            hd_account_id,
            invoice_id=invoice_id,
            reserved_from_block=reserved_from_block,
        )


def schedule_release(
    conn: psycopg.Connection[Any],
    address_id: int,
    cooldown_until: dt.datetime,
) -> bool:
    """Mark when this address may return to the pool (top-up window + cooldown).

    Called when an invoice expires unpaid. It does not free anything by itself —
    :func:`release_due_addresses` does that once the moment has passed and the
    other two conditions still hold.
    """
    if cooldown_until.tzinfo is None:
        raise ValueError("cooldown_until must be timezone-aware")
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            SQL_SCHEDULE_RELEASE, {"address_id": address_id, "cooldown_until": cooldown_until}
        )
        return cur.fetchone() is not None


def release_due_addresses(
    conn: psycopg.Connection[Any],
    hd_account_id: int,
) -> list[PooledAddress]:
    """Return every address that satisfies all three reuse conditions to the pool.

    The three conditions are in the SQL, not in Python, so that a future caller
    cannot accidentally release an address by taking a different code path
    (TZ 5.1 p. 2). An address that has ever held funds is excluded permanently.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SQL_RELEASE_DUE, {"hd_account_id": hd_account_id})
        return [
            PooledAddress(
                address_id=int(row["id"]),
                hd_account_id=hd_account_id,
                derivation_index=int(row["derivation_index"]),
                address=row["address"],
                newly_derived=False,
            )
            for row in cur.fetchall()
        ]


def mark_address_funded(conn: psycopg.Connection[Any], address_id: int) -> bool:
    """Latch ``ever_funded``; the address can never re-enter the free pool.

    The settler owns the money decisions but has only SELECT on
    ``receive_addresses`` (migration 0002), so it asks the deriver to perform
    this transition. Idempotent — re-running it on an already-funded address
    changes nothing and still reports success.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SQL_MARK_FUNDED, {"address_id": address_id})
        return cur.fetchone() is not None


def hd_account_ids(conn: psycopg.Connection[Any]) -> list[int]:
    """Every derivation account id, so a sweep can visit all of them.

    :func:`release_due_addresses` takes one account at a time — its statement is
    keyed on ``hd_account_id`` so that a release pass touches one account's rows
    and cannot lock the whole table. Somebody has to enumerate them, and the
    deriver is the process that owns this table's writes anyway.
    """
    with conn.cursor() as cur:
        cur.execute(SQL_ALL_HD_ACCOUNT_IDS)
        return [int(row[0]) for row in cur.fetchall()]


def verify_stored_address(
    conn: psycopg.Connection[Any],
    deriver: AddressDeriver,
    address_id: int,
) -> bool:
    """Re-derive a stored row's address and compare (TZ 5.8/T1.1, database side).

    ``Deriver.verify`` checks an address someone handed us; this checks what is
    actually sitting in ``receive_addresses``. Both matter: the first catches a
    tampered ``invoices.address``, this one catches a tampered pool row, which
    is what the watcher builds its filter from.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SQL_SELECT_ADDRESS_ROW, {"address_id": address_id})
        row = cur.fetchone()
    if row is None:
        return False
    return deriver.verify(row["address"], int(row["hd_account_id"]), int(row["derivation_index"]))
