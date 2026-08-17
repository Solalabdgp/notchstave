"""Prometheus metric families declared by more than one process.

Almost every metric in TZ section 7 has exactly one owner, and
:mod:`watcher.metrics` states the rule this module exists to keep: *"a metric
declared by two processes is a metric that reads differently depending on which
one scraped last."* Two families break the one-owner pattern honestly, because
two processes genuinely observe the same event from different sides:

    notchstave_orphan_payments_total{chain}
    notchstave_unassigned_payments_total{chain}

The **watcher** classifies an incoming transfer as ``orphan_payment`` or
``unassigned_payment`` — it is the only component that sees the block. The
**settler** is what turns that classification into a case a human will read
(``settler.service.review_anomalous_payments``), and TZ section 7's alert
("`orphan_payments_total` вырос → обязателен ручной разбор") is about the second
event, not the first.

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
    from prometheus_client import Counter

    PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover
    Counter = _NoopMetric  # type: ignore[assignment, misc]
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
