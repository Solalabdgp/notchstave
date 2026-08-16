"""Prometheus counters owned by the settler (TZ section 7).

Only the metrics this process can honestly report are defined here — head lag
and RPC budget belong to the watcher, delivery latency to the notifier.

Three of these have a normal value of zero, and TZ section 7 puts them in a
separate block on the dashboard for that reason: any movement is an incident,
not load.

* ``notchstave_reverted_credits_total`` — product was handed over for money
  that no longer exists. "Разбор немедленный."
* ``notchstave_orphan_payments_total`` — money on a reused address outside its
  reservation window (5.8/T3.3).
* ``notchstave_unassigned_payments_total`` — money on our address with no live
  invoice behind it.

``notchstave_double_grant_blocked_total`` is the odd one out: a non-zero value
is not an outage, it is proof the partial unique index of T2.1 did its job. TZ
section 7 — "Ненулевое значение не авария, но повод посмотреть на
конкурентность."
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

__all__ = [
    "INVOICES_SETTLED",
    "REVERTED_CREDITS",
    "DOUBLE_GRANT_BLOCKED",
    "ORPHAN_PAYMENTS",
    "UNASSIGNED_PAYMENTS",
    "MANUAL_REVIEW_OPEN",
    "PAYMENT_CREDIT_SECONDS",
]

INVOICES_SETTLED = Counter(
    "notchstave_invoices_settled_total",
    "Invoices closed by the settler, by outcome of the TZ 5.5 policy table.",
    ["outcome"],
)

REVERTED_CREDITS = Counter(
    "notchstave_reverted_credits_total",
    "Entitlements revoked because the paying block was reorged out (TZ 5.4).",
)

DOUBLE_GRANT_BLOCKED = Counter(
    "notchstave_double_grant_blocked_total",
    "Times entitlements_active_uniq stopped a second grant (TZ 5.8/T2.1).",
)

ORPHAN_PAYMENTS = Counter(
    "notchstave_orphan_payments_total",
    "Payments below reserved_from_block of a reused address (TZ 5.8/T3.3).",
    ["chain"],
)

UNASSIGNED_PAYMENTS = Counter(
    "notchstave_unassigned_payments_total",
    "Payments to a known address with no live invoice behind it (TZ 5.5).",
    ["chain"],
)

MANUAL_REVIEW_OPEN = Gauge(
    "notchstave_manual_review_open",
    "Manual review cases currently open (TZ 3.4 /pending).",
)

PAYMENT_CREDIT_SECONDS = Histogram(
    "notchstave_payment_credit_seconds",
    "Seconds from first detection of a payment to the entitlement being granted.",
    buckets=(1, 5, 15, 30, 60, 120, 300, 900, 1800, 3600),
)
