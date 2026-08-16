"""The RPC failure taxonomy.

Modelled on `FetchError(error_class=...)` from
`scraping-platform/app/workers/fetchers/base.py`: a single exception type that
carries *what kind* of failure this was, so that the retry policy, the metric
label and the log line all read the same string and nobody has to grep an
error message at runtime. TZ 5.6 says the pattern is reused from there and from
Perchwatch; this module is that reuse.

The classes are not decorative — each one answers a different question:

    transport_error   the socket broke            -> retry, then fail over
    timeout           no answer in time           -> retry, then fail over
    rate_limited      429 / -32005 style          -> back off harder, fail over
    server_error      5xx / internal RPC error    -> retry, then fail over
    malformed_response  answer was not usable     -> fail over (this provider lies)
    range_too_large   filter too wide for this provider -> SPLIT, do not fail over
    invalid_request   our request is wrong        -> terminal, do not retry
    circuit_open      breaker refused the call    -> next provider
    budget_exhausted  request budget spent        -> next provider
    no_provider       every slot refused          -> the caller must slow down

Two of these deserve the emphasis:

**`range_too_large` must never trigger failover.** Every provider will reject
the same over-wide `eth_getLogs`, so trying all three burns the budget three
times to learn one fact. The correct response is to halve the range — which is
what `RpcPool.get_transfer_logs` does.

**`invalid_request` must never be retried.** A malformed filter or a bad
parameter is a bug in this codebase, and retrying it across three providers
turns one bug into three times the error rate and hides it behind noise.

Nothing in this module imports web3, so the classification is unit-testable on
saved provider payloads with no network stack installed.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "RpcErrorClass",
    "RpcError",
    "classify_json_rpc_error",
    "classify_http_status",
]


class RpcErrorClass:
    """String constants, not an enum, on purpose.

    They are used as Prometheus label values and as free-form strings in logs;
    an enum would only add `.value` noise at every call site. Kept as a class
    rather than module-level names so that `RpcErrorClass.TIMEOUT` reads as a
    taxonomy member and cannot be confused with a local variable.
    """

    TRANSPORT: Final = "transport_error"
    TIMEOUT: Final = "timeout"
    RATE_LIMITED: Final = "rate_limited"
    SERVER_ERROR: Final = "server_error"
    MALFORMED_RESPONSE: Final = "malformed_response"
    RANGE_TOO_LARGE: Final = "range_too_large"
    INVALID_REQUEST: Final = "invalid_request"
    CIRCUIT_OPEN: Final = "circuit_open"
    BUDGET_EXHAUSTED: Final = "budget_exhausted"
    NO_PROVIDER: Final = "no_provider_available"


#: Worth another attempt against the *same* provider after a backoff.
RETRYABLE_SAME_PROVIDER: Final[frozenset[str]] = frozenset(
    {
        RpcErrorClass.TRANSPORT,
        RpcErrorClass.TIMEOUT,
        RpcErrorClass.SERVER_ERROR,
    }
)

#: Worth trying the next provider in the rotation.
FAILOVER: Final[frozenset[str]] = frozenset(
    {
        RpcErrorClass.TRANSPORT,
        RpcErrorClass.TIMEOUT,
        RpcErrorClass.RATE_LIMITED,
        RpcErrorClass.SERVER_ERROR,
        RpcErrorClass.MALFORMED_RESPONSE,
        RpcErrorClass.CIRCUIT_OPEN,
        RpcErrorClass.BUDGET_EXHAUSTED,
    }
)

#: Counts against the provider's circuit breaker. `range_too_large` and
#: `invalid_request` do not: the provider answered correctly, we asked badly,
#: and tripping a breaker on our own bug would take a healthy node out of
#: rotation for no reason.
COUNTS_AS_PROVIDER_FAILURE: Final[frozenset[str]] = frozenset(
    {
        RpcErrorClass.TRANSPORT,
        RpcErrorClass.TIMEOUT,
        RpcErrorClass.RATE_LIMITED,
        RpcErrorClass.SERVER_ERROR,
        RpcErrorClass.MALFORMED_RESPONSE,
    }
)


class RpcError(RuntimeError):
    """Any failure to obtain a usable RPC answer.

    `provider` is a *label* (host, no path, no query) — never the endpoint URL.
    Provider URLs carry API keys in the path, so putting one into an exception
    message would leak a credential into every log line and every traceback the
    moment something breaks. `watcher.config.provider_label` is what produces
    the safe form, and a test asserts a key cannot survive it.
    """

    def __init__(
        self,
        message: str,
        *,
        error_class: str,
        provider: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.error_class = error_class
        self.provider = provider
        self.method = method
        self.status_code = status_code
        #: Seconds the provider asked us to wait, when it says so (`Retry-After`).
        self.retry_after = retry_after

    @property
    def retryable(self) -> bool:
        return self.error_class in RETRYABLE_SAME_PROVIDER

    @property
    def should_failover(self) -> bool:
        return self.error_class in FAILOVER

    @property
    def should_split_range(self) -> bool:
        return self.error_class == RpcErrorClass.RANGE_TOO_LARGE

    @property
    def counts_as_provider_failure(self) -> bool:
        return self.error_class in COUNTS_AS_PROVIDER_FAILURE

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.provider:
            parts.append(f"provider={self.provider}")
        if self.method:
            parts.append(f"method={self.method}")
        parts.append(f"class={self.error_class}")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
#
# JSON-RPC error codes are standardised; the *messages* are not. Providers word
# "your filter is too wide" differently and change the wording without notice,
# so the substring lists below are heuristics, and they are allowed to miss.
# A miss degrades to a plain retry/failover, which is slower but still correct —
# the only thing lost is the chance to split the range immediately instead of
# after a wasted round trip. That asymmetry is why heuristics are acceptable
# here and would not be acceptable in the settler.

#: Wording seen from EVM providers when a `eth_getLogs` filter is too wide,
#: either in block span or in response size.
_RANGE_MARKERS: Final[tuple[str, ...]] = (
    "query returned more than",
    "response size exceeded",
    "log response size exceeded",
    "block range",
    "range too large",
    "exceeds the range",
    "too many results",
    "query timeout exceeded",
    "limit exceeded",
)

_RATE_MARKERS: Final[tuple[str, ...]] = (
    "rate limit",
    "too many requests",
    "throughput",
    "capacity exceeded",
    "quota",
)


def classify_json_rpc_error(code: int | None, message: str | None) -> str:
    """Map a JSON-RPC `error` object onto the taxonomy.

    Codes that matter here:

    * ``-32600``/``-32602``/``-32601`` — invalid request / invalid params /
      method not found. Ours to fix, terminal.
    * ``-32005`` — "limit exceeded" in the de-facto convention. Ambiguous by
      design: providers use it both for "you are querying too fast" and for
      "that filter returns too much", so the message decides which, and the
      range reading wins when both match — splitting is cheap and always safe,
      whereas treating a too-wide filter as rate limiting makes the watcher
      sleep forever without ever narrowing the query.
    * ``-32000``/``-32603`` — generic server-side failure.
    """
    text = (message or "").lower()

    if any(marker in text for marker in _RANGE_MARKERS):
        return RpcErrorClass.RANGE_TOO_LARGE
    if any(marker in text for marker in _RATE_MARKERS):
        return RpcErrorClass.RATE_LIMITED

    if code in (-32600, -32601, -32602):
        return RpcErrorClass.INVALID_REQUEST
    if code == -32005:
        # Neither marker list matched; the conservative reading is rate limiting,
        # because backing off is harmless and splitting a filter that was not too
        # wide would multiply the request count.
        return RpcErrorClass.RATE_LIMITED
    # -32000 (generic server error) and -32603 (internal error) both mean "the
    # node failed", which is a retry, and anything unrecognised is treated the
    # same way: an unknown failure is a failure, not a licence to give up.
    return RpcErrorClass.SERVER_ERROR


def classify_http_status(status: int) -> str:
    """Map a transport-level HTTP status onto the taxonomy."""
    if status == 429:
        return RpcErrorClass.RATE_LIMITED
    if status in (401, 403):
        # A bad or revoked API key. Retrying cannot fix it and failing over is
        # right, but it must be loud: this is the failure mode that silently
        # takes a provider out of the rotation for days.
        return RpcErrorClass.INVALID_REQUEST
    if status == 413:
        return RpcErrorClass.RANGE_TOO_LARGE
    if 500 <= status < 600:
        return RpcErrorClass.SERVER_ERROR
    if 400 <= status < 500:
        return RpcErrorClass.INVALID_REQUEST
    return RpcErrorClass.SERVER_ERROR
