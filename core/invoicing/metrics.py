"""Prometheus families owned by invoice issuance (TZ section 7).

Two are declared here because this is the only component that can observe them:

    notchstave_invoices_created_total{chain,asset}
    notchstave_invoice_ratelimit_hits_total{scope}

Three are **re-exported** from :mod:`core.metrics` rather than declared, because
they have a second observer in another process and a name claimed twice raises
``DuplicateTimeseries`` the moment one process imports both modules:

    notchstave_address_mismatch_total        also checked by the settler (T1.1)
    notchstave_invoice_mac_failures_total    also checked by the settler (T1.3)
    notchstave_active_reserved_addresses     also reported by the watcher (T5.2)

See the docstring of :mod:`core.metrics` for the full argument; the short
version is that ``/reconcile`` already made this a real crash once, not a
hypothetical one.

**Why ``invoices_created_total`` is labelled by asset and not by product.** TZ
section 7 specifies ``{chain,asset}`` and the reason shows up in the alert next
door: the number this metric is read against is ``active_reserved_addresses``,
which is per chain. A ``{product}`` label would multiply the series by the
catalog for a question the ``invoices`` table answers better with a GROUP BY.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

from core import metrics as core_metrics

__all__ = [
    "INVOICES_CREATED",
    "RATELIMIT_HITS",
    "INVOICE_REQUESTS",
    "INVOICE_REQUEST_SECONDS",
    "ADDRESS_MISMATCH",
    "MAC_FAILURES",
    "ACTIVE_RESERVED_ADDRESSES",
]

INVOICES_CREATED = Counter(
    "notchstave_invoices_created_total",
    "Invoices issued, by chain and asset (TZ section 7).",
    ["chain", "asset"],
)

#: TZ 5.8/T5 — "срабатывания квот на создание инвойса". The ``scope`` label
#: values are supplied by the exceptions themselves
#: (:attr:`core.invoicing.errors.QuotaExceeded.scope`) rather than written out at
#: each call site, so the metric and the refusal can never end up describing the
#: same event with different words.
#:
#: Values in use: ``active_invoices``, ``hourly``, ``cooldown``, ``addresses``.
RATELIMIT_HITS = Counter(
    "notchstave_invoice_ratelimit_hits_total",
    "Invoice creations refused by a TZ 5.8/T5 quota, by which quota fired.",
    ["scope"],
)

#: The ask-the-deriver round trip of migration 0007, measured **on the asking
#: side** — in ``bot``/``api``, not in the deriver.
#:
#: That placement is a deliberate constraint, not a convenience. Prometheus is a
#: pull system, so a counter is only worth incrementing in a process that serves
#: ``/metrics``, and the deriver must not: it is the one process holding key
#: material (TZ 5.8/T4), and giving it a listening HTTP socket to report on its
#: own health would trade the thing being protected for a graph. The asker sees
#: everything that matters anyway — it knows whether it got an invoice, a
#: refusal or nothing at all, and it is the only one that can measure the latency
#: a buyer actually experienced. What the deriver knows and this does not is
#: visible in SQL: ``SELECT status, count(*) FROM invoice_requests GROUP BY 1``.
#:
#: ``outcome`` values: ``issued``, ``refused``, ``timeout``, ``in_flight``
#: (rejected at the door by the one-open-per-user index), ``tampered``.
INVOICE_REQUESTS = Counter(
    "notchstave_invoice_requests_total",
    "Invoice requests sent to the deriver by bot/api, by how they came back.",
    ["outcome"],
)

#: Buckets stop at 10s because that is the client's default give-up point, and
#: start at 10ms because the expected value is a single NOTIFY hop. A histogram
#: whose whole distribution sits in the first bucket is the answer this design
#: is claiming; leaving the tail buckets in is how a regression to polling
#: latency would show up rather than being averaged away.
INVOICE_REQUEST_SECONDS = Histogram(
    "notchstave_invoice_request_seconds",
    "Wall-clock seconds from asking the deriver for an invoice to holding one.",
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

ADDRESS_MISMATCH = core_metrics.address_mismatch_total
MAC_FAILURES = core_metrics.invoice_mac_failures_total
ACTIVE_RESERVED_ADDRESSES = core_metrics.active_reserved_addresses
