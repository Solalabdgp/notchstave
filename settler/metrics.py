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

from prometheus_client import Counter, Gauge, Histogram, start_http_server

from core import metrics as core_metrics

__all__ = [
    "start_exporter",
    "INVOICES_SETTLED",
    "REVERTED_CREDITS",
    "DOUBLE_GRANT_BLOCKED",
    "ORPHAN_PAYMENTS",
    "UNASSIGNED_PAYMENTS",
    "MAC_FAILURES",
    "MANUAL_REVIEW_OPEN",
    "PAYMENT_CREDIT_SECONDS",
    "RECONCILE_DRIFT_USD",
    "UNSWEPT_BALANCE_USD",
    "ADMIN_ACTIONS",
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

# The two families below are shared with the watcher and declared in
# :mod:`core.metrics`, not here.
#
# The watcher classifies the anomaly from the block; the settler turns it into a
# case a human reads, and TZ section 7's alert is about the second event. Both
# increments are legitimate — but two `Counter(...)` calls for one name raise
# `DuplicateTimeseries` as soon as one process imports both packages, which is
# what `/reconcile` now does by reusing the watcher's RPC pool (TZ 5.6). One
# declaration site, two callers.
ORPHAN_PAYMENTS = core_metrics.orphan_payments_total

UNASSIGNED_PAYMENTS = core_metrics.unassigned_payments_total

#: TZ 5.8/T1.3 names three observation points for this counter — "перед
#: отправкой сообщения с адресом, при рендере страницы инвойса, **при зачёте в
#: settler**". The bot and the api reached it through
#: :mod:`core.invoicing.metrics`; this alias is the third one, and until it
#: existed the settlement checkpoint the TZ asks for was not implemented at all.
#: Same family, one declaration site, three callers.
MAC_FAILURES = core_metrics.invoice_mac_failures_total

MANUAL_REVIEW_OPEN = Gauge(
    "notchstave_manual_review_open",
    "Manual review cases currently open (TZ 3.4 /pending).",
)

PAYMENT_CREDIT_SECONDS = Histogram(
    "notchstave_payment_credit_seconds",
    "Seconds from first detection of a payment to the entitlement being granted.",
    buckets=(1, 5, 15, 30, 60, 120, 300, 900, 1800, 3600),
)

#: The most serious alert in the system (TZ section 7): "БД и цепь разошлись.
#: Это баг в учёте денег, самое серьёзное, что может случиться."
#:
#: A Gauge and not a Counter, because the quantity is a *current* discrepancy
#: that a later sweep or a late-indexed payment can legitimately close. A Counter
#: would keep alerting about a drift that no longer exists, and an alert that
#: stays red after the problem is fixed stops being read.
#:
#: Set by `settler.admin.reconcile` on every run, including runs that find
#: nothing — writing an explicit zero is what distinguishes "reconciled, all
#: square" from "reconcile has not run since the last restart", which look
#: identical on a gauge that is only touched when something is wrong.
RECONCILE_DRIFT_USD = Gauge(
    "notchstave_reconcile_drift_usd",
    "Absolute USD difference between confirmed payments in the ledger and "
    "on-chain balances of the receive addresses holding them (TZ 3.4 /reconcile).",
    ["chain"],
)

#: How much money is sitting on hot receive addresses right now (TZ section 7).
#: Alert threshold is an operational decision, not a bug: "На горячих адресах
#: скопилось слишком много. Пора свипать офлайн." Computed as a by-product of
#: `/sweeplist`, which is the command whose whole purpose is answering it.
UNSWEPT_BALANCE_USD = Gauge(
    "notchstave_unswept_balance_usd",
    "USD value on receive addresses that have been funded and not yet swept.",
    ["chain"],
)

#: TZ 5.8/T7 — every owner action on money, by action. The point of the metric is
#: not volume: it is that a captured owner account cannot act at a rate nobody
#: can see. Pairs with the per-action notification the TZ requires and with the
#: append-only `audit_log` rows.
ADMIN_ACTIONS = Counter(
    "notchstave_admin_actions_total",
    "Owner actions on money, by action (TZ 3.4 admin commands, 5.8/T7).",
    ["action"],
)


def start_exporter(port: int) -> bool:
    """Expose this process's own ``/metrics``. Same call surface as
    :func:`watcher.metrics.start_exporter`, and the reason there are now two
    copies rather than one shared helper is worth writing down.

    TZ section 7 says ``/metrics`` lives on the api process, and
    :mod:`settler.main`'s module docstring used to repeat that as the reason
    nothing here was wired. That statement does not survive the process
    boundary: settler, notifier and (eventually) api are separate OS
    processes, and ``prometheus_client``'s default registry is per-process
    memory — a Counter incremented in the settler's address space is not
    visible to a `collect()` call running in api's, import or no import.
    Making the stated design true would need every process to write to
    ``PROMETHEUS_MULTIPROC_DIR`` and api to read it back with
    ``multiprocess.MultiProcessCollector``, which is a real pattern but is not
    wired anywhere in this repo, and building it is out of scope for landing
    real metric *values* this week.

    Until that lands (or is deliberately chosen against), each process serves
    its own registry on its own port — exactly the pattern
    ``watcher.metrics.start_exporter`` already uses in production. Wired from
    :func:`settler.main.main`, gated on ``SETTLER_METRICS_PORT`` the same way
    ``WATCHER_METRICS_PORT`` gates the watcher's.
    """
    start_http_server(port)
    return True
