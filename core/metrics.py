"""Prometheus metric families declared by more than one process.

Almost every metric in TZ section 7 has exactly one owner, and
:mod:`watcher.metrics` states the rule this module exists to keep: *"a metric
declared by two processes is a metric that reads differently depending on which
one scraped last."* Five families break the one-owner pattern honestly, because
two processes genuinely observe the same event from different sides:

    notchstave_orphan_payments_total{chain}
    notchstave_unassigned_payments_total{chain}
    notchstave_address_mismatch_total
    notchstave_invoice_mac_failures_total
    notchstave_active_reserved_addresses{chain}

The **watcher** classifies an incoming transfer as ``orphan_payment`` or
``unassigned_payment`` — it is the only component that sees the block. The
**settler** is what turns that classification into a case a human will read
(``settler.service.review_anomalous_payments``), and TZ section 7's alert
("`orphan_payments_total` вырос → обязателен ручной разбор") is about the second
event, not the first.

The next two are the T1 security counters, and TZ 5.8/T1.1 and T1.3 name their
observation points explicitly: the address is re-derived and the MAC re-checked
*"перед отправкой сообщения с адресом, при рендере страницы инвойса, при зачёте
в settler"* — three call sites in three processes. A counter whose whole meaning
is "somebody, somewhere, saw a tampered invoice" cannot be owned by one of them.

``notchstave_active_reserved_addresses`` moved here for the same reason in Week
5. The watcher sets it from the filter it is about to build; the invoicing
service sets it the moment it takes an address out of the pool, which is the
earlier and more actionable of the two readings — the T5 alert fires at 80% of
the ceiling, and waiting for the next watcher pass to notice is a scrape
interval of blindness during exactly the burst the alert is for.

Declaring the family twice does not merely produce two readings: it raises
``DuplicateTimeseries`` the instant one process imports both packages. That
stopped being hypothetical in Week 3, when `/reconcile` gave the settler a
reason to import :mod:`watcher.rpc.pool` — the shared provider pool of TZ 5.6 —
and with it, transitively, :mod:`watcher.metrics`. The collision was a
guaranteed crash on the first `/reconcile` in production, and the fix is one
declaration site rather than two collectors racing to claim a name.

**The no-op fallback** is the same idiom :mod:`watcher.metrics` uses and exists
for the same reason: unit tests for pure logic must run in a bare checkout with
nothing but pytest installed, and neither the watcher's detection tests nor the
deriver's isolated environment should have to install a metrics library to
exercise arithmetic. The stubs never stand in for the real thing in production —
each process starts its exporter explicitly and says so if the library is
missing.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "PROMETHEUS_AVAILABLE",
    "orphan_payments_total",
    "unassigned_payments_total",
    "address_mismatch_total",
    "invoice_mac_failures_total",
    "active_reserved_addresses",
]


class _NoopMetric:
    """Same call surface as a prometheus metric family, and does nothing."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.value: float = 0.0

    def labels(self, *_args: Any, **_kwargs: Any) -> _NoopMetric:
        return self

    def inc(self, amount: float = 1.0) -> None:
        self.value += amount

    def dec(self, amount: float = 1.0) -> None:
        self.value -= amount

    def set(self, value: float) -> None:
        self.value = value

    def observe(self, _value: float) -> None:
        return None


try:  # pragma: no cover - exercised implicitly by whichever env runs the tests
    from prometheus_client import Counter, Gauge

    PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover
    Counter = Gauge = _NoopMetric  # type: ignore[assignment, misc]
    PROMETHEUS_AVAILABLE = False


#: TZ 5.8/T3.3 — a payment mined below its address's ``reserved_from_block``
#: belongs to the previous tenant of a reused address and is never credited to
#: the current invoice. Normal value zero.
orphan_payments_total = Counter(
    "notchstave_orphan_payments_total",
    "Payments mined below their address's reserved_from_block (TZ 5.8/T3.3).",
    ["chain"],
)

#: Money on an address we derived, with no live invoice behind it. Not a loss —
#: the funds are sweepable — but always a human decision (TZ 5.5).
unassigned_payments_total = Counter(
    "notchstave_unassigned_payments_total",
    "Payments to a known address with no live invoice behind it.",
    ["chain"],
)

#: TZ 5.8/T1.1 — the address stored against an invoice did not re-derive from
#: the account xpub. Normal value is zero and stays zero forever; the alert in
#: TZ section 7 is ``> 0``, with no rate and no threshold, because there is no
#: benign reading of this number.
#:
#: Unlabelled on purpose. A ``{chain}`` or ``{invoice}`` label would invite the
#: question "which chain is compromised", and the answer to a non-zero value is
#: not "look at the label" — it is "stop issuing invoices and go and look at the
#: database". Anything that makes this counter feel like a dashboard series
#: rather than a fire alarm works against it.
address_mismatch_total = Counter(
    "notchstave_address_mismatch_total",
    "Invoice addresses that failed to re-derive from the xpub (TZ 5.8/T1.1). "
    "Normal value is zero; any increment is a suspected compromise.",
)

#: TZ 5.8/T1.3 — ``integrity_mac`` did not match a re-computation over the
#: invoice's significant tuple. Same reading, different tamper: the address may
#: still derive correctly while the amount, the chain or the deadline was
#: edited underneath it.
invoice_mac_failures_total = Counter(
    "notchstave_invoice_mac_failures_total",
    "Invoices whose integrity_mac did not verify (TZ 5.8/T1.3). "
    "Normal value is zero; any increment means the row was changed outside the app.",
)

#: TZ 5.8/T5.2 — how much of the derivation account's ceiling is in use. Alert
#: at 80%, because the ceiling is what bounds the ``eth_getLogs`` filter and the
#: damage in T5 is degraded payment detection, not disk.
#:
#: A Gauge with two writers in two processes (see the module docstring). Both
#: report a count of reserved addresses; the invoicing service reports it at the
#: moment the count changes, the watcher when it rebuilds its filter.
active_reserved_addresses = Gauge(
    "notchstave_active_reserved_addresses",
    "Receive addresses currently reserved by a live invoice (TZ 5.8/T5.2).",
    ["chain"],
)
