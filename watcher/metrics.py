"""Prometheus metrics for the watcher, named exactly as in TZ section 7.

Names are copied from the spec verbatim rather than invented here, because the
alert rules and the Grafana dashboard in TZ section 7 refer to them by name:

    notchstave_head_lag_blocks{chain}            watcher's distance from head
    notchstave_rpc_errors_total{provider,chain}
    notchstave_rpc_requests_total{provider,method}   budget spend
    notchstave_provider_disagreement_total{chain}    TZ 5.6 cross-check
    notchstave_reorgs_total{chain,depth}
    notchstave_payment_detect_seconds                block timestamp -> row in DB
    notchstave_getlogs_filter_size{chain}            TZ 5.8/T5 early warning
    notchstave_active_reserved_addresses{chain}
    notchstave_orphan_payments_total{chain}
    notchstave_unassigned_payments_total{chain}

Everything else in TZ section 7 belongs to a different process (`invoices_*`,
`reverted_credits_total`, `reconcile_drift_usd`, `dlq_size`, ...) and is not
declared here — a metric declared by two processes is a metric that reads
differently depending on which one scraped last.

**On the no-op fallback.** `prometheus_client` is a declared dependency of the
root package, but the unit tests for detection and reorg logic must run in a
bare checkout with nothing but pytest installed (the same rule the deriver's
tests follow). So the import is guarded and degrades to stubs with the same
call surface. The stubs are not a substitute for the real thing in production:
`main.py` starts the exporter explicitly and logs loudly if the library is
missing, rather than silently running blind.

`notchstave_payment_detect_seconds` measures block timestamp -> row committed,
so its lower bound is the block time of the chain, not zero. That is the number
TZ section 7 asks for ("от блока до появления платежа в БД"), and reading it as
"watcher latency" would be wrong.
"""

from __future__ import annotations

from typing import Any

from core import metrics as core_metrics

__all__ = [
    "PROMETHEUS_AVAILABLE",
    "head_lag_blocks",
    "rpc_errors_total",
    "rpc_requests_total",
    "provider_disagreement_total",
    "reorgs_total",
    "payment_detect_seconds",
    "getlogs_filter_size",
    "active_reserved_addresses",
    "orphan_payments_total",
    "unassigned_payments_total",
    "breaker_state",
    "start_exporter",
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
    from prometheus_client import Counter, Gauge, Histogram, start_http_server

    PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover
    Counter = Gauge = Histogram = _NoopMetric  # type: ignore[assignment, misc]
    start_http_server = None  # type: ignore[assignment]
    PROMETHEUS_AVAILABLE = False


head_lag_blocks = Gauge(
    "notchstave_head_lag_blocks",
    "Blocks between the chain head and the last block this watcher indexed.",
    ["chain"],
)

rpc_errors_total = Counter(
    "notchstave_rpc_errors_total",
    "RPC failures by provider and chain.",
    # Exactly the two labels TZ section 7 specifies. `error_class` is tempting
    # as a third, and it is deliberately left out: it multiplies the series
    # count by the size of the taxonomy for a question that the log line already
    # answers, and the alert in TZ section 7 is about the rate, not the reason.
    ["provider", "chain"],
)

rpc_requests_total = Counter(
    "notchstave_rpc_requests_total",
    "RPC requests issued, i.e. provider budget spend.",
    ["provider", "method"],
)

provider_disagreement_total = Counter(
    "notchstave_provider_disagreement_total",
    "Two providers returned different hashes for the same height (TZ 5.6).",
    ["chain"],
)

reorgs_total = Counter(
    "notchstave_reorgs_total",
    "Chain reorganisations observed, labelled by depth in blocks.",
    ["chain", "depth"],
)

payment_detect_seconds = Histogram(
    "notchstave_payment_detect_seconds",
    "Seconds from the block timestamp to the payment row being written.",
    buckets=(1, 2, 5, 10, 20, 30, 60, 120, 300, 600),
)

getlogs_filter_size = Gauge(
    "notchstave_getlogs_filter_size",
    "Addresses in the current eth_getLogs filter — leading indicator of "
    "detection degradation under TZ 5.8/T5.",
    ["chain"],
)

# Re-exported, not re-declared. These families are written by the watcher (which
# classifies the anomaly, and which counts the addresses going into its filter)
# and by another process that observes the same fact from the other side — the
# settler, which opens the manual-review case, and the invoicing service, which
# is what makes an address reserved in the first place. The docstring at the top
# of this module is the reason that has to be one collector rather than two: a
# name claimed twice raises DuplicateTimeseries the moment a single process
# imports both packages, which is exactly what `/reconcile` does since it reuses
# this package's RPC pool. See core/metrics.py.
orphan_payments_total = core_metrics.orphan_payments_total
unassigned_payments_total = core_metrics.unassigned_payments_total
active_reserved_addresses = core_metrics.active_reserved_addresses

breaker_state = Gauge(
    "notchstave_rpc_breaker_state",
    "Circuit breaker per provider: 0 closed, 1 half-open, 2 open. Not in the "
    "TZ section 7 list — added because an alert on head_lag tells you the "
    "watcher is behind, and this tells you which provider to blame.",
    ["provider", "chain"],
)


def start_exporter(port: int) -> bool:
    """Expose /metrics. Returns False when prometheus_client is not installed."""
    if not PROMETHEUS_AVAILABLE or start_http_server is None:  # pragma: no cover
        return False
    start_http_server(port)  # pragma: no cover
    return True  # pragma: no cover
