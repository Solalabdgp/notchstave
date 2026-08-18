"""Every SQL statement the settler runs, in one readable place.

Why raw SQL instead of the ORM, in the one package that owns money: the
statements below *are* the correctness argument. TZ 5.8/T2.2 does not say "use
optimistic locking", it says the only permitted form is
``UPDATE ... WHERE id=$1 AND status=<expected>`` and that a read-check-write in
Python is a review failure. A reviewer must be able to see that literal shape,
and a test must be able to drive it directly — see
``settler/tests/test_concurrency.py::test_cas_reports_the_loss_instead_of_overwriting``,
which asserts on the rowcount contract, and the twenty-worker test above it,
which is what that contract exists for. Neither works when the statement is
assembled three call frames away by a query builder.

Everything here takes an :class:`~sqlalchemy.ext.asyncio.AsyncConnection` and
does exactly one thing. Transaction boundaries live in :mod:`settler.service`;
no function in this module commits.

Two conventions worth knowing before reading:

* **The clock is the database's.** Every timestamp is ``now()`` evaluated in
  Postgres. Twenty workers on three hosts do not agree on what time it is, and
  a top-up window that closes at a different instant per worker is a bug that
  only shows up under load.
* **Enum parameters are cast explicitly** (``CAST(:status AS payment_status)``).
  The driver sends a Python string as ``text``, and ``payment_status = text``
  is not an operator Postgres knows. The cast is what makes a typo fail at the
  database boundary instead of writing garbage into a money column — the same
  reason ``core.db.enums`` uses native enum types in the first place.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

__all__ = [
    "InvoiceContext",
    "PaymentRow",
    "SQL_LOCK_INVOICE",
    "SQL_CAS_INVOICE_STATUS",
    "SQL_SETTLED_TOTAL",
    "SQL_INSERT_ENTITLEMENT",
    "SQL_REVOKE_ENTITLEMENTS",
    "SQL_REVERT_PAYMENTS_IN_ORPHANED_BLOCKS",
    "lock_invoice",
    "invoice_payments",
    "settled_total_raw",
    "finalized_head",
    "promote_payment_to_confirmed",
    "credit_payment",
    "cas_invoice_status",
    "insert_entitlement",
    "enqueue_notification",
    "open_manual_review",
    "create_refund_request",
    "write_audit",
    "payments_in_orphaned_blocks",
    "revert_payments_in_orphaned_blocks",
    "revoke_entitlements_for_invoices",
    "unsettle_invoices",
    "expire_invoice",
    "expire_invoice_past_rate_lock",
    "invoices_past_topup_window",
    "invoices_past_rate_lock",
    "unreviewed_anomalous_payments",
    "credit_internal_balance",
    "is_active_entitlement_conflict",
    "ENTITLEMENTS_ACTIVE_UNIQ",
    "SQL_CREDIT_INTERNAL_BALANCE",
    "SQL_EXPIRE_INVOICE_PAST_RATE_LOCK",
]

#: The partial unique index that is the real defence against a double grant
#: (TZ 5.8/T2.1). Named here because the code recognises *this* constraint by
#: name when deciding whether an IntegrityError means "lost the race" (benign)
#: or "something else broke" (not benign).
ENTITLEMENTS_ACTIVE_UNIQ = "entitlements_active_uniq"

_TEXT_ARRAY = pg.ARRAY(sa.Text)


# ---------------------------------------------------------------------------
# Row shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InvoiceContext:
    """An invoice plus everything needed to decide about it, read under lock.

    Assembled by one query on purpose: a second round trip to fetch the chain's
    confirmation policy would be a second snapshot, and the whole point of
    holding the row lock is that the decision is taken against one consistent
    picture.
    """

    invoice_id: uuid.UUID
    user_id: int
    product_id: int
    chain_id: int
    asset_id: int
    address_id: int
    amount_due_raw: Decimal
    amount_due_usd: Decimal
    rate_snapshot: Decimal
    status: str
    expires_at: dt.datetime
    topup_window_until: dt.datetime
    settled_at: dt.datetime | None
    policy_version: str
    address: str
    asset_decimals: int
    asset_symbol: str
    asset_chain_id: int
    min_confirmations: int
    credit_threshold_usd: Decimal
    use_finalized_tag: bool
    last_indexed_block: int
    product_kind: str
    subscription_days: int | None
    db_now: dt.datetime


@dataclass(frozen=True, slots=True)
class PaymentRow:
    """One incoming transfer bound to the invoice."""

    id: int
    chain_id: int
    tx_hash: str
    log_index: int
    block_number: int
    asset_id: int
    amount_raw: Decimal
    sender: str | None
    status: str
    anomaly: str | None
    confirmations_at_credit: int | None
    #: TZ section 7 — ``notchstave_payment_credit_seconds`` measures from this
    #: timestamp (first detection, written by the watcher on insert) to the
    #: entitlement's ``granted_at``. Added here, not derived elsewhere, so the
    #: histogram reads the same row the credit decision was made from rather
    #: than a second, possibly-stale query.
    created_at: dt.datetime


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

#: TZ 5.8/T2.3 — "SELECT ... FROM invoices WHERE id=$1 FOR UPDATE в начале
#: транзакции settler. Вся денежная работа по одному инвойсу сериализуется на
#: этой строке."
#:
#: ``FOR UPDATE OF i`` and not a bare ``FOR UPDATE``: the join pulls in chains,
#: assets and products, and a bare FOR UPDATE would try to lock those rows too.
#: The settler role holds no UPDATE on ``chains``/``products``/``assets``
#: (migration 0002), so that would fail with a permission error — and if it did
#: not, it would serialise every invoice on the whole planet behind one chain
#: row.
SQL_LOCK_INVOICE = sa.text(
    """
    SELECT i.id, i.user_id, i.product_id, i.chain_id, i.asset_id, i.address_id,
           i.amount_due_raw, i.amount_due_usd, i.rate_snapshot,
           i.status::text        AS status,
           i.expires_at, i.topup_window_until, i.settled_at, i.policy_version,
           ra.address            AS address,
           a.decimals            AS asset_decimals,
           a.symbol              AS asset_symbol,
           a.chain_id            AS asset_chain_id,
           c.min_confirmations, c.credit_threshold_usd, c.use_finalized_tag,
           c.last_indexed_block,
           p.kind::text          AS product_kind,
           p.subscription_days,
           now()                 AS db_now
      FROM invoices i
      JOIN receive_addresses ra ON ra.id = i.address_id
      JOIN assets   a  ON a.id = i.asset_id
      JOIN chains   c  ON c.chain_id = i.chain_id
      JOIN products p  ON p.id = i.product_id
     WHERE i.id = :invoice_id
       FOR UPDATE OF i
    """
)

#: TZ 5.3 — "Сумма, набранная по инвойсу, всегда считается агрегатом
#: SUM(amount_raw) ... Никакого инкрементного счётчика в invoices — инкремент
#: это ровно тот механизм, который при повторной обработке события начисляет
#: дважды."
#:
#: The three extra predicates are not decoration:
#:  * ``asset_id`` / ``chain_id`` must match the invoice — a transfer of another
#:    token, or the same token on another network, is `wrong_asset` /
#:    `wrong_chain` and is never summed into the bill (TZ 5.5);
#:  * ``anomaly`` is either absent or ``late``; a late payment inside the
#:    top-up window is creditable by TZ 5.5, everything else needs a human.
#:  * dust never reaches here — the watcher writes it as ``ignored_dust``,
#:    which is not in the status filter.
#:
#: ``block_number <= :max_creditable_block`` is the confirmation gate of TZ 5.4
#: expressed as a height. Both regimes reduce to one cutoff: "head minus
#: min_confirmations" for a small payment, and additionally "no higher than the
#: finalized head" for one above ``credit_threshold_usd``. Putting the gate in
#: the aggregate rather than in Python is what keeps the TZ 5.3 rule intact —
#: the settled total stays a single ``SUM`` over the ledger, not a number the
#: application assembled and could assemble differently next time.
SQL_SETTLED_TOTAL = sa.text(
    """
    SELECT COALESCE(SUM(p.amount_raw), 0) AS total_raw,
           COUNT(*)                       AS payment_count
      FROM payments p
     WHERE p.invoice_id = :invoice_id
       AND p.status::text = ANY(:statuses)
       AND p.asset_id = :asset_id
       AND p.chain_id = :chain_id
       AND p.block_number <= :max_creditable_block
       AND (p.anomaly IS NULL OR p.anomaly::text = ANY(:creditable_anomalies))
    """
).bindparams(
    sa.bindparam("statuses", type_=_TEXT_ARRAY),
    sa.bindparam("creditable_anomalies", type_=_TEXT_ARRAY),
)

SQL_INVOICE_PAYMENTS = sa.text(
    """
    SELECT p.id, p.chain_id, p.tx_hash, p.log_index, p.block_number, p.asset_id,
           p.amount_raw, p.sender, p.status::text AS status,
           p.anomaly::text AS anomaly, p.confirmations_at_credit, p.created_at
      FROM payments p
     WHERE p.invoice_id = :invoice_id
     ORDER BY p.block_number, p.log_index, p.id
    """
)

#: The watcher's notion of finality, read through ``blocks.status`` — see the
#: module docstring of :mod:`settler.confirmations` for why this is an explicit
#: inter-module contract and not an assumption.
SQL_FINALIZED_HEAD = sa.text(
    """
    SELECT MAX(b.number) AS finalized_head
      FROM blocks b
     WHERE b.chain_id = :chain_id
       AND b.status = 'confirmed'
    """
)


async def lock_invoice(conn: AsyncConnection, invoice_id: uuid.UUID) -> InvoiceContext | None:
    row = (await conn.execute(SQL_LOCK_INVOICE, {"invoice_id": invoice_id})).mappings().first()
    if row is None:
        return None
    return InvoiceContext(
        invoice_id=row["id"],
        user_id=row["user_id"],
        product_id=row["product_id"],
        chain_id=row["chain_id"],
        asset_id=row["asset_id"],
        address_id=row["address_id"],
        amount_due_raw=Decimal(row["amount_due_raw"]),
        amount_due_usd=Decimal(row["amount_due_usd"]),
        rate_snapshot=Decimal(row["rate_snapshot"]),
        status=row["status"],
        expires_at=row["expires_at"],
        topup_window_until=row["topup_window_until"],
        settled_at=row["settled_at"],
        policy_version=row["policy_version"],
        address=row["address"],
        asset_decimals=int(row["asset_decimals"]),
        asset_symbol=row["asset_symbol"],
        asset_chain_id=int(row["asset_chain_id"]),
        min_confirmations=int(row["min_confirmations"]),
        credit_threshold_usd=Decimal(row["credit_threshold_usd"]),
        use_finalized_tag=bool(row["use_finalized_tag"]),
        last_indexed_block=int(row["last_indexed_block"]),
        product_kind=row["product_kind"],
        subscription_days=row["subscription_days"],
        db_now=row["db_now"],
    )


async def invoice_payments(conn: AsyncConnection, invoice_id: uuid.UUID) -> list[PaymentRow]:
    rows = (await conn.execute(SQL_INVOICE_PAYMENTS, {"invoice_id": invoice_id})).mappings().all()
    return [
        PaymentRow(
            id=r["id"],
            chain_id=r["chain_id"],
            tx_hash=r["tx_hash"],
            log_index=r["log_index"],
            block_number=r["block_number"],
            asset_id=r["asset_id"],
            amount_raw=Decimal(r["amount_raw"]),
            sender=r["sender"],
            status=r["status"],
            anomaly=r["anomaly"],
            confirmations_at_credit=r["confirmations_at_credit"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


async def settled_total_raw(
    conn: AsyncConnection,
    invoice_id: uuid.UUID,
    *,
    asset_id: int,
    chain_id: int,
    statuses: tuple[str, ...],
    creditable_anomalies: tuple[str, ...],
    max_creditable_block: int,
) -> Decimal:
    row = (
        await conn.execute(
            SQL_SETTLED_TOTAL,
            {
                "invoice_id": invoice_id,
                "asset_id": asset_id,
                "chain_id": chain_id,
                "statuses": list(statuses),
                "creditable_anomalies": list(creditable_anomalies),
                "max_creditable_block": max_creditable_block,
            },
        )
    ).mappings().one()
    return Decimal(row["total_raw"])


async def finalized_head(conn: AsyncConnection, chain_id: int) -> int | None:
    value = (await conn.execute(SQL_FINALIZED_HEAD, {"chain_id": chain_id})).scalar_one_or_none()
    return None if value is None else int(value)


# ---------------------------------------------------------------------------
# Compare-and-set writes (TZ 5.8/T2.2)
# ---------------------------------------------------------------------------

#: The only permitted shape of an invoice status transition.
#:
#: TZ 5.8/T2.2 spells the statement out as
#: ``UPDATE invoices SET status='paid', settled_at=now() WHERE id=$1 AND
#: status='confirmed'``. Two deviations, both deliberate:
#:
#: 1. ``status='confirmed'`` does not exist. The invoice state machine shipped
#:    in migration 0001 (and listed in TZ 6) is
#:    ``awaiting / seen / partially_paid / paid / overpaid / expired /
#:    manual_review / cancelled / reverted`` — the TZ text of T2.2 and the TZ
#:    data model of section 6 disagree, and the schema is the one that is
#:    already deployed. "A confirmed invoice" is therefore expressed as *an
#:    invoice in a live status whose payments are confirmed*, and the expected
#:    state in the WHERE clause is the live set. Inventing a ninth status to
#:    match a code sample would have meant a migration on a shipped schema.
#: 2. The expected set is passed as a parameter instead of being hard-coded,
#:    because the same statement is used for every transition. What matters for
#:    T2.2 is that the expected state is *in the WHERE clause* and that zero
#:    affected rows is treated as "someone else got here first" — not that the
#:    literal is inline.
SQL_CAS_INVOICE_STATUS = sa.text(
    """
    UPDATE invoices
       SET status     = CAST(:new_status AS invoice_status),
           settled_at = CASE
                            WHEN :mark_settled THEN now()
                            WHEN :clear_settled THEN NULL
                            ELSE settled_at
                        END
     WHERE id = :invoice_id
       AND status::text = ANY(:expected)
    """
).bindparams(sa.bindparam("expected", type_=_TEXT_ARRAY))

SQL_PROMOTE_PAYMENT_CONFIRMED = sa.text(
    """
    UPDATE payments
       SET status = 'confirmed'
     WHERE id = :payment_id
       AND status = 'seen'
    """
)

SQL_CREDIT_PAYMENT = sa.text(
    """
    UPDATE payments
       SET status = 'credited',
           confirmations_at_credit = :confirmations
     WHERE id = :payment_id
       AND status = 'confirmed'
    """
)


async def cas_invoice_status(
    conn: AsyncConnection,
    invoice_id: uuid.UUID,
    *,
    new_status: str,
    expected: tuple[str, ...],
    mark_settled: bool = False,
    clear_settled: bool = False,
) -> bool:
    """Compare-and-set. ``False`` means somebody else already moved the row.

    A ``False`` here is not an error and must not be retried: TZ 5.8/T2.2 —
    "Ноль затронутых строк означает, что состояние уже изменил кто-то другой,
    и обработчик обязан выйти."
    """
    result = await conn.execute(
        SQL_CAS_INVOICE_STATUS,
        {
            "invoice_id": invoice_id,
            "new_status": new_status,
            "expected": list(expected),
            "mark_settled": mark_settled,
            "clear_settled": clear_settled,
        },
    )
    return result.rowcount == 1


async def promote_payment_to_confirmed(conn: AsyncConnection, payment_id: int) -> bool:
    result = await conn.execute(SQL_PROMOTE_PAYMENT_CONFIRMED, {"payment_id": payment_id})
    return result.rowcount == 1


async def credit_payment(conn: AsyncConnection, payment_id: int, confirmations: int) -> bool:
    """``confirmed -> credited``, CAS again (TZ 5.8/T3.1).

    This is what makes "credit the same confirmed payment twice" impossible
    even if the same event is delivered twice.
    """
    result = await conn.execute(
        SQL_CREDIT_PAYMENT, {"payment_id": payment_id, "confirmations": confirmations}
    )
    return result.rowcount == 1


# ---------------------------------------------------------------------------
# Grant / outbox / review / refund
# ---------------------------------------------------------------------------

SQL_INSERT_ENTITLEMENT = sa.text(
    """
    INSERT INTO entitlements (user_id, product_id, invoice_id, granted_at, expires_at)
    VALUES (
        :user_id,
        :product_id,
        :invoice_id,
        now(),
        CASE
            WHEN CAST(:subscription_days AS integer) IS NULL THEN NULL
            ELSE now() + make_interval(days => CAST(:subscription_days AS integer))
        END
    )
    RETURNING id
    """
)


def is_active_entitlement_conflict(exc: IntegrityError) -> bool:
    """Is this the partial unique index of TZ 5.8/T2.1, or something worse?

    Distinguishing the two matters. A violation of ``entitlements_active_uniq``
    means a concurrent worker granted first, and the correct behaviour is to
    finish quietly — "не «падает с ошибкой», а именно тихо признаёт, что
    проиграл гонку". Any other integrity error (a broken foreign key, a failed
    CHECK) is a real bug and must keep propagating.
    """
    orig = getattr(exc, "orig", None)
    diag = getattr(orig, "diag", None)
    constraint = getattr(diag, "constraint_name", None)
    if constraint == ENTITLEMENTS_ACTIVE_UNIQ:
        return True
    # Fallback for drivers that do not expose diagnostics: the index name is in
    # the message text. Kept as a second path, never as the only one.
    return constraint is None and ENTITLEMENTS_ACTIVE_UNIQ in str(orig)


async def insert_entitlement(
    conn: AsyncConnection,
    *,
    user_id: int,
    product_id: int,
    invoice_id: uuid.UUID,
    subscription_days: int | None,
) -> int | None:
    """Grant access. ``None`` means the race was lost, not that it failed.

    The INSERT runs inside a SAVEPOINT because a constraint violation aborts
    the *whole* transaction in Postgres — without the savepoint, losing the
    race would also throw away the outbox row and the audit entry written in
    the same transaction.
    """
    try:
        async with conn.begin_nested():
            result = await conn.execute(
                SQL_INSERT_ENTITLEMENT,
                {
                    "user_id": user_id,
                    "product_id": product_id,
                    "invoice_id": invoice_id,
                    "subscription_days": subscription_days,
                },
            )
            return int(result.scalar_one())
    except IntegrityError as exc:
        if is_active_entitlement_conflict(exc):
            return None
        raise


SQL_ENQUEUE_NOTIFICATION = sa.text(
    """
    INSERT INTO notifications (user_id, kind, ref_id, dedup_key, payload_json, status)
    VALUES (:user_id, :kind, :ref_id, :dedup_key, CAST(:payload AS jsonb), 'queued')
    ON CONFLICT (kind, ref_id, dedup_key) DO NOTHING
    RETURNING id
    """
)


async def enqueue_notification(
    conn: AsyncConnection,
    *,
    user_id: int,
    kind: str,
    ref_id: str,
    dedup_key: str,
    payload: dict[str, Any],
) -> int | None:
    """Transactional outbox (TZ 5.7, 5.8/T2.5).

    Written in the same transaction as the side effect it describes. A crash
    between granting and sending re-sends; a crash between sending and granting
    cannot happen, because there is no separate "sending" step here at all —
    the notifier drains this table.

    ``None`` means the row already existed: ``UNIQUE (kind, ref_id, dedup_key)``
    absorbed a duplicate, which is exactly what it is for.
    """
    result = await conn.execute(
        SQL_ENQUEUE_NOTIFICATION,
        {
            "user_id": user_id,
            "kind": kind,
            "ref_id": ref_id,
            "dedup_key": dedup_key,
            "payload": json.dumps(payload, default=str, sort_keys=True),
        },
    )
    row = result.first()
    return None if row is None else int(row[0])


#: One open case per (kind, invoice) and — through
#: ``uq_manual_reviews_open_payment`` — one open case per payment. Reprocessing
#: an invoice every few seconds must not turn `/pending` into a firehose.
SQL_OPEN_MANUAL_REVIEW = sa.text(
    """
    INSERT INTO manual_reviews (kind, invoice_id, payment_id, note, policy_version)
    SELECT CAST(:kind AS manual_review_kind), :invoice_id, :payment_id, :note, :policy_version
     WHERE NOT EXISTS (
             SELECT 1
               FROM manual_reviews mr
              WHERE mr.resolved_at IS NULL
                AND mr.kind = CAST(:kind AS manual_review_kind)
                AND mr.invoice_id IS NOT DISTINCT FROM :invoice_id
                AND mr.payment_id IS NOT DISTINCT FROM :payment_id
           )
    RETURNING id
    """
)


async def open_manual_review(
    conn: AsyncConnection,
    *,
    kind: str,
    invoice_id: uuid.UUID | None,
    payment_id: int | None,
    note: str,
    policy_version: str,
) -> int | None:
    """Open a case for a human. ``None`` means an identical one is already open."""
    try:
        async with conn.begin_nested():
            result = await conn.execute(
                SQL_OPEN_MANUAL_REVIEW,
                {
                    "kind": kind,
                    "invoice_id": invoice_id,
                    "payment_id": payment_id,
                    "note": note,
                    "policy_version": policy_version,
                },
            )
            row = result.first()
            return None if row is None else int(row[0])
    except IntegrityError as exc:
        # uq_manual_reviews_open_payment — the same "already open" answer, just
        # discovered by the index instead of by the NOT EXISTS.
        if "uq_manual_reviews_open_payment" in str(getattr(exc, "orig", exc)):
            return None
        raise


#: ``to_address`` is left NULL on purpose (TZ 5.5): "адрес отправителя — не
#: надёжный адрес для возврата ... при возврате свыше порога бот запрашивает у
#: пользователя адрес для возврата явно". The sender is recorded in the note
#: as reference material for the owner, never as a destination.
SQL_CREATE_REFUND = sa.text(
    """
    INSERT INTO refunds (invoice_id, amount_raw, asset_id, to_address, status, note)
    VALUES (:invoice_id, :amount_raw, :asset_id, NULL, 'pending', :note)
    ON CONFLICT (invoice_id) WHERE status = 'pending' DO NOTHING
    RETURNING id
    """
)


async def create_refund_request(
    conn: AsyncConnection,
    *,
    invoice_id: uuid.UUID,
    amount_raw: Decimal,
    asset_id: int,
    note: str,
) -> int | None:
    result = await conn.execute(
        SQL_CREATE_REFUND,
        {
            "invoice_id": invoice_id,
            "amount_raw": amount_raw,
            "asset_id": asset_id,
            "note": note,
        },
    )
    row = result.first()
    return None if row is None else int(row[0])


SQL_WRITE_AUDIT = sa.text(
    """
    INSERT INTO audit_log (actor_kind, actor_id, action, target_kind, target_id,
                           before_state, after_state, args_json, policy_version)
    VALUES (CAST(:actor_kind AS actor_kind), :actor_id, :action, :target_kind, :target_id,
            CAST(:before_state AS jsonb), CAST(:after_state AS jsonb),
            CAST(:args AS jsonb), :policy_version)
    RETURNING id
    """
)


async def write_audit(
    conn: AsyncConnection,
    *,
    actor_id: str,
    action: str,
    target_kind: str,
    target_id: str,
    before_state: dict[str, Any] | None,
    after_state: dict[str, Any] | None,
    args: dict[str, Any],
    policy_version: str,
    actor_kind: str = "system",
) -> int:
    """Append-only record of a money decision (TZ 5.8/T8).

    The settler role holds INSERT and SELECT on ``audit_log`` and nothing else
    (migrations 0002 and 0003), so this is structurally append-only: there is no
    code path that could edit a decision after the fact even if one were written.

    ``actor_kind`` defaults to ``system`` — the settler acting on its own, which
    is every caller in :mod:`settler.service`. The admin commands of TZ 3.4 pass
    ``owner``, because "the owner decided this" and "the policy table decided
    this" are the two answers `/pending` and a post-incident review need to tell
    apart, and an ``actor_id`` string alone does not separate them reliably.

    Note on the vocabulary: TZ 5.8/T7 speaks of admin actions, while the
    ``actor_kind`` enum shipped in migration 0001 offers ``owner / user /
    system``. There is exactly one admin in this system and TZ 3.4 calls them
    the owner ("доступные только владельцу по фиксированному tg_id"), so
    ``owner`` is that role under the name the schema already uses. Adding an
    ``admin`` value would be an enum migration for a synonym.

    Returns the id of the row, so a caller can reference the audit entry from
    the record it is about to write.
    """
    result = await conn.execute(
        SQL_WRITE_AUDIT,
        {
            "actor_kind": actor_kind,
            "actor_id": actor_id,
            "action": action,
            "target_kind": target_kind,
            "target_id": target_id,
            "before_state": None if before_state is None else json.dumps(before_state, default=str),
            "after_state": None if after_state is None else json.dumps(after_state, default=str),
            "args": json.dumps(args, default=str, sort_keys=True),
            "policy_version": policy_version,
        },
    )
    return int(result.scalar_one())


# ---------------------------------------------------------------------------
# Internal balance (TZ 5.5 overpayment, migration 0003)
# ---------------------------------------------------------------------------

#: The one statement allowed to touch a user's balance.
#:
#: Additive, never absolute. Migration 0003 grants the settler ``UPDATE
#: (internal_balance_usd)`` and nothing else on ``users``, so PostgreSQL already
#: refuses to let this role write any other column; what the *statement* adds is
#: that the role cannot **set** a balance either, only add to it. Between the two
#: — a column-level grant and an additive statement — a compromised settler can
#: make a balance too large, which is a loud accounting error `/reconcile`
#: surfaces, and cannot make one disappear, which would be a silent theft.
#:
#: ``delta > 0`` is in the WHERE clause rather than in Python for the usual
#: reason: a guard that lives in the statement cannot be skipped by a future
#: caller that forgot about it.
SQL_CREDIT_INTERNAL_BALANCE = sa.text(
    """
    UPDATE users
       SET internal_balance_usd = internal_balance_usd + :delta_usd
     WHERE id = :user_id
       AND :delta_usd > 0
    RETURNING internal_balance_usd
    """
)


async def credit_internal_balance(
    conn: AsyncConnection, *, user_id: int, delta_usd: Decimal
) -> Decimal | None:
    """Add ``delta_usd`` to a user's internal balance (TZ 5.5, overpayment).

    ``None`` means nothing was written — either the delta was not positive or
    the user is gone. Both are the caller's business to report, not this
    function's to raise about.

    **Idempotency is the caller's job and is not optional.** This is the one
    place in the settler that increments rather than recomputes, which is
    exactly the mechanism TZ 5.3 forbids for the settled total. It is
    unavoidable here — a balance *is* a running figure, there is no ledger to
    re-sum — so the protection is moved one level up: :func:`settler.service
    ._apply_settlement` credits only when the ``overpaid_credited`` outbox row
    was actually inserted, and ``UNIQUE (kind, ref_id, dedup_key)`` on
    ``notifications`` makes that insert happen exactly once per grant. Re-running
    the settler over a settled invoice therefore cannot credit twice.
    """
    row = (
        await conn.execute(
            SQL_CREDIT_INTERNAL_BALANCE, {"user_id": user_id, "delta_usd": delta_usd}
        )
    ).first()
    return None if row is None else Decimal(row[0])


# ---------------------------------------------------------------------------
# Reorg (TZ 5.4)
# ---------------------------------------------------------------------------

#: A payment belongs to a height, and a height whose only block is orphaned no
#: longer contains anything. The ``NOT EXISTS`` guard means the rollback only
#: fires while the height is genuinely empty — once the watcher has written a
#: replacement block at that height, this statement stops touching it.
#:
#: LIMITATION, stated rather than hidden: ``payments`` stores ``block_number``
#: but not ``block_hash`` (TZ 6), so "was this exact transaction re-included in
#: the replacement block" cannot be answered from the database. A payment that
#: survives a reorg is therefore reverted here and must be re-credited through
#: `/reconcile` plus a manual review. Fixing it properly is a schema change
#: (add ``payments.block_hash``, revert by hash) and is written up as a TODO in
#: :mod:`settler.service` — a settler cannot add a column to a table it is not
#: the owner of.
SQL_REVERT_PAYMENTS_IN_ORPHANED_BLOCKS = sa.text(
    """
    UPDATE payments p
       SET status = 'reverted'
     WHERE p.chain_id = :chain_id
       AND p.status::text = ANY(:live_statuses)
       AND EXISTS (
             SELECT 1 FROM blocks b
              WHERE b.chain_id = p.chain_id
                AND b.number   = p.block_number
                AND b.status   = 'orphaned'
           )
       AND NOT EXISTS (
             SELECT 1 FROM blocks b2
              WHERE b2.chain_id = p.chain_id
                AND b2.number   = p.block_number
                AND b2.status  <> 'orphaned'
           )
    RETURNING p.id, p.invoice_id, p.amount_raw, p.status::text AS status
    """
).bindparams(sa.bindparam("live_statuses", type_=_TEXT_ARRAY))

SQL_PAYMENTS_IN_ORPHANED_BLOCKS = sa.text(
    """
    SELECT p.id, p.invoice_id, p.amount_raw, p.status::text AS status, p.block_number
      FROM payments p
     WHERE p.chain_id = :chain_id
       AND p.status::text = ANY(:live_statuses)
       AND EXISTS (
             SELECT 1 FROM blocks b
              WHERE b.chain_id = p.chain_id
                AND b.number   = p.block_number
                AND b.status   = 'orphaned'
           )
       AND NOT EXISTS (
             SELECT 1 FROM blocks b2
              WHERE b2.chain_id = p.chain_id
                AND b2.number   = p.block_number
                AND b2.status  <> 'orphaned'
           )
     ORDER BY p.block_number, p.id
    """
).bindparams(sa.bindparam("live_statuses", type_=_TEXT_ARRAY))

#: TZ 5.4 — "если по откаченному платежу доступ уже выдан — доступ отзывается".
#: UPDATE, never DELETE: the grant happened, and a system that erases the fact
#: cannot answer "why does this user have the file" three months later. The
#: partial unique index only covers rows with ``revoked_at IS NULL``, so
#: revoking also makes a future re-grant of the same invoice legal again
#: (TZ 5.8/T2.1).
SQL_REVOKE_ENTITLEMENTS = sa.text(
    """
    UPDATE entitlements
       SET revoked_at = now(),
           revoke_reason = :reason
     WHERE invoice_id = ANY(CAST(:invoice_ids AS uuid[]))
       AND revoked_at IS NULL
    RETURNING id, invoice_id, user_id, product_id
    """
)


async def payments_in_orphaned_blocks(
    conn: AsyncConnection, chain_id: int, *, live_statuses: tuple[str, ...]
) -> list[dict[str, Any]]:
    rows = (
        await conn.execute(
            SQL_PAYMENTS_IN_ORPHANED_BLOCKS,
            {"chain_id": chain_id, "live_statuses": list(live_statuses)},
        )
    ).mappings().all()
    return [dict(r) for r in rows]


async def revert_payments_in_orphaned_blocks(
    conn: AsyncConnection, chain_id: int, *, live_statuses: tuple[str, ...]
) -> list[dict[str, Any]]:
    rows = (
        await conn.execute(
            SQL_REVERT_PAYMENTS_IN_ORPHANED_BLOCKS,
            {"chain_id": chain_id, "live_statuses": list(live_statuses)},
        )
    ).mappings().all()
    return [dict(r) for r in rows]


async def revoke_entitlements_for_invoices(
    conn: AsyncConnection, invoice_ids: list[uuid.UUID], *, reason: str
) -> list[dict[str, Any]]:
    if not invoice_ids:
        return []
    rows = (
        await conn.execute(
            SQL_REVOKE_ENTITLEMENTS,
            {"invoice_ids": [str(i) for i in invoice_ids], "reason": reason},
        )
    ).mappings().all()
    return [dict(r) for r in rows]


#: Back out of a settled state after a reorg. TZ 5.4 says the invoice "возвраща-
#: ется в состояние ожидания" — which is only meaningful while the buyer can
#: still pay. Past the top-up window there is nothing to wait for, so the row
#: lands in ``reverted``, the terminal state that says "this was settled and
#: then the money disappeared". Both branches clear ``settled_at``.
SQL_UNSETTLE_INVOICE = sa.text(
    """
    UPDATE invoices
       SET status = CASE
                        WHEN now() < topup_window_until THEN CAST('awaiting' AS invoice_status)
                        ELSE CAST('reverted' AS invoice_status)
                    END,
           settled_at = NULL
     WHERE id = :invoice_id
       AND status::text = ANY(:expected)
    RETURNING status::text AS status
    """
).bindparams(sa.bindparam("expected", type_=_TEXT_ARRAY))


async def unsettle_invoices(
    conn: AsyncConnection, invoice_ids: list[uuid.UUID], *, expected: tuple[str, ...]
) -> dict[uuid.UUID, str]:
    out: dict[uuid.UUID, str] = {}
    for invoice_id in invoice_ids:
        row = (
            await conn.execute(
                SQL_UNSETTLE_INVOICE, {"invoice_id": invoice_id, "expected": list(expected)}
            )
        ).first()
        if row is not None:
            out[invoice_id] = row[0]
    return out


# ---------------------------------------------------------------------------
# Expiry / anomaly sweeps (TZ 5.5)
# ---------------------------------------------------------------------------

#: CAS again, with the deadline evaluated by the database rather than compared
#: against a timestamp the application read a moment earlier. A worker whose
#: clock runs fast must not be able to expire an invoice early.
SQL_EXPIRE_INVOICE = sa.text(
    """
    UPDATE invoices
       SET status = CAST(:new_status AS invoice_status)
     WHERE id = :invoice_id
       AND status::text = ANY(:expected)
       AND now() > topup_window_until
    """
).bindparams(sa.bindparam("expected", type_=_TEXT_ARRAY))


async def expire_invoice(
    conn: AsyncConnection,
    invoice_id: uuid.UUID,
    *,
    new_status: str,
    expected: tuple[str, ...],
) -> bool:
    result = await conn.execute(
        SQL_EXPIRE_INVOICE,
        {
            "invoice_id": invoice_id,
            "new_status": new_status,
            "expected": list(expected),
        },
    )
    return result.rowcount == 1


#: Invoices whose top-up window has closed. TZ 5.5 splits them in two, and the
#: split is the whole point: an invoice nobody ever paid simply expires, while
#: an invoice that received money and is still short goes to a human. The second
#: kind must never expire silently — that would be money accepted for nothing.
SQL_INVOICES_PAST_TOPUP_WINDOW = sa.text(
    """
    SELECT i.id,
           i.user_id,
           i.status::text AS status,
           EXISTS (
               SELECT 1 FROM payments p
                WHERE p.invoice_id = i.id
                  AND p.status::text = ANY(:money_statuses)
           ) AS has_money
      FROM invoices i
     WHERE i.status::text = ANY(:live_statuses)
       AND now() > i.topup_window_until
     ORDER BY i.topup_window_until
     LIMIT :limit
    """
).bindparams(
    sa.bindparam("money_statuses", type_=_TEXT_ARRAY),
    sa.bindparam("live_statuses", type_=_TEXT_ARRAY),
)


async def invoices_past_topup_window(
    conn: AsyncConnection,
    *,
    live_statuses: tuple[str, ...],
    money_statuses: tuple[str, ...],
    limit: int = 500,
) -> list[dict[str, Any]]:
    rows = (
        await conn.execute(
            SQL_INVOICES_PAST_TOPUP_WINDOW,
            {
                "live_statuses": list(live_statuses),
                "money_statuses": list(money_statuses),
                "limit": limit,
            },
        )
    ).mappings().all()
    return [dict(r) for r in rows]


#: The anomaly rows of the TZ 5.5 table that arrive as *payments* rather than as
#: a verdict on an invoice: ``wrong_asset``, ``wrong_chain``, ``orphan_payment``,
#: ``unassigned_payment``. The watcher classifies them; the settler's job is to
#: make sure each one ends up in front of a human exactly once.
SQL_UNREVIEWED_ANOMALOUS_PAYMENTS = sa.text(
    """
    SELECT p.id, p.chain_id, p.invoice_id, p.amount_raw, p.sender,
           p.block_number, p.anomaly::text AS anomaly, p.status::text AS status
      FROM payments p
     WHERE p.anomaly IS NOT NULL
       AND p.anomaly::text = ANY(:anomalies)
       AND NOT EXISTS (
             SELECT 1 FROM manual_reviews mr
              WHERE mr.payment_id = p.id
                AND mr.resolved_at IS NULL
           )
     ORDER BY p.id
     LIMIT :limit
    """
).bindparams(sa.bindparam("anomalies", type_=_TEXT_ARRAY))


async def unreviewed_anomalous_payments(
    conn: AsyncConnection, *, anomalies: tuple[str, ...], limit: int = 500
) -> list[dict[str, Any]]:
    rows = (
        await conn.execute(
            SQL_UNREVIEWED_ANOMALOUS_PAYMENTS, {"anomalies": list(anomalies), "limit": limit}
        )
    ).mappings().all()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Rate-lock expiry (TZ 5.5, "Курс уехал между выставлением и оплатой")
# ---------------------------------------------------------------------------

#: Invoices whose quoted rate has gone stale **and which hold no money at all**.
#:
#: The second half of that sentence is the entire design of this query, so it is
#: worth stating why rather than leaving it to be inferred from a ``NOT EXISTS``.
#:
#: TZ 5.5 gives two rules that overlap here. "Курс фиксируется в момент создания
#: инвойса и действует ``rate_locked_until`` ... После — инвойс истекает" says a
#: stale quote ends the invoice. "Окно доплаты живёт дольше самого инвойса,
#: потому что человек, который уже отправил деньги, находится в другом
#: положении, чем человек, который просто не заплатил" says a buyer who has
#: already paid something keeps their invoice alive past its expiry.
#:
#: They only look contradictory. The rate lock protects *us* from quoting a price
#: and being paid at it an hour later; the top-up window protects *the buyer* who
#: is mid-payment. So the split is by whether money arrived: an invoice nobody
#: paid expires when the quote goes stale, and an invoice holding money is left
#: alone here and routed by :data:`SQL_INVOICES_PAST_TOPUP_WINDOW` — which sends
#: it to ``manual_review``, not to ``expired``, because "деньги никогда не
#: списываются молча по таймеру".
#:
#: Payments in *any* status count as money for this test, including
#: ``ignored_dust`` and ``reverted``. Deliberately wider than the creditable set:
#: this query decides whether a human should look, and an address that has seen a
#: transfer is a different situation from one that never has, whatever the
#: watcher made of it.
SQL_INVOICES_PAST_RATE_LOCK = sa.text(
    """
    SELECT i.id,
           i.user_id,
           i.status::text     AS status,
           i.rate_locked_until,
           i.topup_window_until
      FROM invoices i
     WHERE i.status::text = ANY(:live_statuses)
       AND now() > i.rate_locked_until
       AND NOT EXISTS (SELECT 1 FROM payments p WHERE p.invoice_id = i.id)
     ORDER BY i.rate_locked_until
     LIMIT :limit
    """
).bindparams(sa.bindparam("live_statuses", type_=_TEXT_ARRAY))

#: CAS, with both deadline and emptiness re-checked *inside* the UPDATE.
#:
#: The ``NOT EXISTS`` is repeated here rather than trusted from the SELECT
#: because the gap between the two statements is exactly long enough for a
#: payment to land: the watcher inserts into ``payments`` from its own
#: transaction, and expiring an invoice that acquired money a millisecond ago
#: would be the one failure mode this whole function exists to avoid.
SQL_EXPIRE_INVOICE_PAST_RATE_LOCK = sa.text(
    """
    UPDATE invoices
       SET status = CAST('expired' AS invoice_status)
     WHERE id = :invoice_id
       AND status::text = ANY(:expected)
       AND now() > rate_locked_until
       AND NOT EXISTS (SELECT 1 FROM payments p WHERE p.invoice_id = invoices.id)
    """
).bindparams(sa.bindparam("expected", type_=_TEXT_ARRAY))


async def invoices_past_rate_lock(
    conn: AsyncConnection, *, live_statuses: tuple[str, ...], limit: int = 500
) -> list[dict[str, Any]]:
    rows = (
        await conn.execute(
            SQL_INVOICES_PAST_RATE_LOCK,
            {"live_statuses": list(live_statuses), "limit": limit},
        )
    ).mappings().all()
    return [dict(r) for r in rows]


async def expire_invoice_past_rate_lock(
    conn: AsyncConnection, invoice_id: uuid.UUID, *, expected: tuple[str, ...]
) -> bool:
    result = await conn.execute(
        SQL_EXPIRE_INVOICE_PAST_RATE_LOCK,
        {"invoice_id": invoice_id, "expected": list(expected)},
    )
    return result.rowcount == 1
