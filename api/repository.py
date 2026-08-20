"""Reads for the live status line. No money decisions, by construction.

TZ section 4 is explicit that ``api`` *"только читает то, что settler уже
решил"*, and this module is where that rule is either kept or quietly broken.
It is kept by never computing a verdict: the invoice's status comes out of
``invoices.status``, the credited total is the ``SUM`` over ``payments`` that TZ
5.3 mandates, and the grant is the presence of an ``entitlements`` row. Nothing
here decides whether an invoice is paid — it reports that the settler decided
so.

The one arithmetic this module does perform is the confirmation count, and it is
copied rather than invented::

    confirmations = max(0, chains.last_indexed_block - payments.block_number + 1)

which is character-for-character what ``settler/service.py`` and
``settler/admin/reviews.py`` compute. The page must not be able to say ``3/3``
while the settler still thinks a payment is one short; sharing the expression is
how that is prevented, and the integration test asserts the two agree.

**Why the head is the watcher's head and not the network's.** ``chains
.last_indexed_block`` is where the watcher has actually indexed to. If the
watcher lags, the page shows fewer confirmations than the chain has. That is the
conservative direction and matches ``settler.confirmations
.creditable_cutoff_height``, which uses the same number for the same reason: a
page that runs ahead of the settler promises access the settler has not granted.

**Grants used.** ``notchstave_api`` has SELECT on ``invoices``, ``payments``,
``chains``, ``assets``, ``entitlements`` and ``products`` (migration 0002). It
has no UPDATE on ``payments`` and no access at all to the outbox, so nothing in
this file could mutate settlement state even if it tried to.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import psycopg
from psycopg.rows import dict_row

from core.db import enums as E

__all__ = [
    "InvoiceProgress",
    "PaymentProgress",
    "load_progress",
    "database_reachable",
]

#: TZ 5.3 — the settled total is a SUM over these statuses and never an
#: incremental counter. Imported from the enum module rather than spelled here,
#: so a new creditable status cannot make this page disagree with the settler.
_CREDITABLE = tuple(E.CREDITABLE_PAYMENT_STATUSES)

#: Payments that are on-chain but not yet credited. These are the rows the
#: "увидели транзакцию, N/M подтверждений" line of TZ 3.2 is about.
_PENDING = (str(E.PaymentStatus.SEEN),)


@dataclass(frozen=True, slots=True)
class PaymentProgress:
    """One incoming transfer, as far as the buyer's page is concerned."""

    tx_hash: str
    amount_raw: Decimal
    status: str
    block_number: int
    confirmations: int
    #: ``None`` for a payment the settler has already credited — the count
    #: stopped being interesting the moment it was enough.
    anomaly: str | None


@dataclass(frozen=True, slots=True)
class InvoiceProgress:
    """Everything the status line needs, already read from the ledger.

    Deliberately separate from :class:`core.invoicing.service.InvoiceView`:
    that type is the *verified* invoice and carries the address, and it may only
    be produced by code that ran the T1 checks. This one carries no address at
    all, which is what lets the status endpoint be cheap and frequent without
    re-running a MAC verification every two seconds on data that cannot contain
    an address to substitute.
    """

    invoice_id: uuid.UUID
    status: str
    expires_at: dt.datetime
    topup_window_until: dt.datetime
    amount_due_raw: Decimal
    #: SUM over confirmed/credited rows (TZ 5.3).
    amount_paid_raw: Decimal
    #: SUM over rows the watcher has seen but the settler has not credited.
    amount_pending_raw: Decimal
    required_confirmations: int
    head_block: int
    payments: tuple[PaymentProgress, ...]
    #: A live, unrevoked ``entitlements`` row — the last rung of the TZ 3.2
    #: ladder, and the only one that is not a property of ``invoices.status``.
    access_granted: bool
    settled_at: dt.datetime | None

    @property
    def amount_outstanding_raw(self) -> Decimal:
        """What is still owed. Never negative — an overpaid invoice owes zero."""
        return max(Decimal(0), self.amount_due_raw - self.amount_paid_raw)

    @property
    def confirmations(self) -> int | None:
        """Progress towards the threshold, or ``None`` when nothing is pending.

        The **minimum** across pending payments, not the maximum: with two
        transfers against one invoice the buyer is waiting on the slower one,
        and a page that showed the faster one's count would promise a credit
        that is not coming yet.
        """
        counts = [p.confirmations for p in self.payments if p.status in _PENDING]
        return min(counts) if counts else None


SQL_INVOICE = """
SELECT i.id                 AS invoice_id,
       i.status::text       AS status,
       i.expires_at         AS expires_at,
       i.topup_window_until AS topup_window_until,
       i.amount_due_raw     AS amount_due_raw,
       i.settled_at         AS settled_at,
       c.min_confirmations  AS min_confirmations,
       c.last_indexed_block AS last_indexed_block,
       -- Aggregated in the same round trip rather than in a second query: the
       -- two must describe one instant, and two statements on an autocommit
       -- connection can straddle a settler commit and show a payment as
       -- credited while the invoice still reads `seen`.
       COALESCE((SELECT sum(p.amount_raw) FROM payments p
                  WHERE p.invoice_id = i.id
                    AND p.status = ANY(%(creditable)s::payment_status[])), 0)
                            AS amount_paid_raw,
       COALESCE((SELECT sum(p.amount_raw) FROM payments p
                  WHERE p.invoice_id = i.id
                    AND p.status = ANY(%(pending)s::payment_status[])), 0)
                            AS amount_pending_raw,
       EXISTS (SELECT 1 FROM entitlements e
                WHERE e.invoice_id = i.id AND e.revoked_at IS NULL)
                            AS access_granted
  FROM invoices i
  JOIN chains c ON c.chain_id = i.chain_id
 WHERE i.id = %(invoice_id)s
"""

#: Ordered oldest first so the page's list is stable across polls — a list that
#: reorders itself under the reader is how a buyer convinces themselves they saw
#: a different address a moment ago.
SQL_PAYMENTS = """
SELECT p.tx_hash            AS tx_hash,
       p.amount_raw         AS amount_raw,
       p.status::text       AS status,
       p.block_number       AS block_number,
       p.anomaly::text      AS anomaly
  FROM payments p
 WHERE p.invoice_id = %(invoice_id)s
 ORDER BY p.block_number, p.id
"""


def load_progress(
    conn: psycopg.Connection[Any], invoice_id: uuid.UUID
) -> InvoiceProgress | None:
    """The status half of the page. ``None`` when there is no such invoice.

    ``None`` rather than an exception because the caller has, by this point,
    already proved the invoice exists and is visible to whoever is asking — the
    public token was resolved, or the ``initData`` user matched. Reaching this
    and finding nothing means the row was deleted between the two queries, which
    is a "come back in a second", not a 500.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            SQL_INVOICE,
            {
                "invoice_id": invoice_id,
                "creditable": list(_CREDITABLE),
                "pending": list(_PENDING),
            },
        )
        row = cur.fetchone()
        if row is None:
            return None

        cur.execute(SQL_PAYMENTS, {"invoice_id": invoice_id})
        payment_rows = cur.fetchall()

    head = int(row["last_indexed_block"])
    payments = tuple(
        PaymentProgress(
            tx_hash=str(p["tx_hash"]),
            amount_raw=Decimal(p["amount_raw"]),
            status=str(p["status"]),
            block_number=int(p["block_number"]),
            # Identical expression to settler/service.py — see module docstring.
            confirmations=max(0, head - int(p["block_number"]) + 1),
            anomaly=None if p["anomaly"] is None else str(p["anomaly"]),
        )
        for p in payment_rows
    )

    return InvoiceProgress(
        invoice_id=row["invoice_id"],
        status=str(row["status"]),
        expires_at=row["expires_at"],
        topup_window_until=row["topup_window_until"],
        amount_due_raw=Decimal(row["amount_due_raw"]),
        amount_paid_raw=Decimal(row["amount_paid_raw"]),
        amount_pending_raw=Decimal(row["amount_pending_raw"]),
        required_confirmations=int(row["min_confirmations"]),
        head_block=head,
        payments=payments,
        access_granted=bool(row["access_granted"]),
        settled_at=row["settled_at"],
    )


def database_reachable(conn: psycopg.Connection[Any]) -> bool:
    """``/healthz``'s only question, and deliberately the cheapest possible one.

    ``SELECT 1`` and not a count over ``invoices``: a health check that touches
    a money table gets slower exactly when the system is under the load that
    makes the check matter, and a probe that times out under load is a probe
    that takes a healthy process out of rotation during a traffic spike.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT 1")
        return cur.fetchone() is not None
