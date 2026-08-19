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

from prometheus_client import Counter

from core import metrics as core_metrics

__all__ = [
    "INVOICES_CREATED",
    "RATELIMIT_HITS",
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

ADDRESS_MISMATCH = core_metrics.address_mismatch_total
MAC_FAILURES = core_metrics.invoice_mac_failures_total
ACTIVE_RESERVED_ADDRESSES = core_metrics.active_reserved_addresses
