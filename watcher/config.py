"""Runtime configuration: environment + the `chains` row -> a live provider pool.

Two rules shape this module, and both are worth stating because they are the
kind of thing that is easy to get subtly wrong and impossible to notice
afterwards.

**No network is hardcoded.** Base and Ethereum mainnet are rows in `chains`
(TZ section 2 and 6): chain id, confirmations, `use_finalized_tag` and the
provider list all come from the database. Nothing in `watcher/` names a chain.
The only thing this module contributes on top of the row is the taste of the
retry/chunk policies, which are per-provider tuning rather than per-network
facts.

**Provider URLs are secrets, and are treated as such.** An Alchemy or QuickNode
endpoint carries the API key inside the path — `https://base-mainnet.g.alchemy
.com/v2/<KEY>`. That has two consequences:

1. Nothing may log, repr, or export a URL. Every provider is identified by
   :func:`provider_label`, which keeps the host and drops everything else, and
   that label is what goes into `notchstave_rpc_requests_total{provider,...}`,
   into every log line and into every `RpcError`. A metric label carrying an API
   key would publish it on `/metrics`, which is exactly the leak TZ 5.8/T4
   forbids for the xpub, applied to the other credential in the system.
2. `chains.rpc_urls` is a database column, and the database is not where API
   keys belong — TZ 5.8 puts credentials in systemd credentials, not in rows a
   compromised `api` role can `SELECT`. So a stored URL may be a template:
   `https://base-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}`. The row keeps the
   provider identity and the ordering (which is genuinely per-chain config), the
   environment keeps the secret, and :func:`expand_rpc_url` joins them at
   startup. A template whose variable is unset is a startup failure, loudly, and
   never a silent request to a URL with the literal text `${...}` in it.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from watcher.rpc.breaker import BreakerPolicy, CircuitBreaker, RequestBudget
from watcher.rpc.client import ProviderSlot, RpcClient
from watcher.rpc.pool import ChunkPolicy, RetryPolicy, RpcPool
from watcher.store.base import ChainConfigRow
from watcher.traversal import TraversalSettings

__all__ = [
    "provider_label",
    "expand_rpc_url",
    "MissingProviderCredential",
    "ProviderPolicy",
    "WatcherSettings",
    "build_slots",
    "build_pool",
]

#: `${NAME}` inside a stored RPC URL. Deliberately not `$NAME`: an unbraced
#: form would make a URL containing a literal `$` ambiguous, and there is no
#: reason to accept ambiguity in a string that becomes a network destination.
_ENV_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class MissingProviderCredential(RuntimeError):
    """A stored RPC URL references an environment variable that is not set.

    Fatal at startup by design. The alternative — dropping the provider and
    carrying on with two — degrades the pool silently, and a watcher quietly
    running on a thinner rotation than the operator believes is precisely the
    state in which the next provider outage becomes a payment outage.
    """


def provider_label(url: str) -> str:
    """A safe, stable name for a provider endpoint: scheme-less host, no path.

    ``https://base-mainnet.g.alchemy.com/v2/SECRET`` -> ``base-mainnet.g.alchemy.com``

    The host alone is enough to tell Alchemy from QuickNode from Ankr on a
    dashboard, and it is the largest part of the URL that provably contains no
    credential. Userinfo (``https://user:pass@host``) is dropped as well —
    `urlsplit().hostname` already excludes it, which is why this uses `hostname`
    and not a string split.
    """
    parts = urlsplit(url.strip())
    host = parts.hostname
    if host:
        return host
    # Not a URL at all (a bare hostname, a unix socket path, a typo). Falling
    # back to the whole string would be the one branch that could leak a key,
    # so it is truncated to something that is still recognisable in a log but
    # cannot carry a 32-character token.
    cleaned = url.strip().split("/")[0]
    return cleaned[:40] or "unknown-provider"


def expand_rpc_url(url: str, env: Mapping[str, str] | None = None) -> str:
    """Substitute `${VAR}` placeholders from the environment.

    Raises:
        MissingProviderCredential: when a referenced variable is unset or empty.
    """
    source = os.environ if env is None else env
    missing: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = source.get(name)
        if not value:
            missing.append(name)
            return ""
        return value

    expanded = _ENV_PLACEHOLDER.sub(replace, url)
    if missing:
        raise MissingProviderCredential(
            f"provider URL for {provider_label(url)} needs "
            f"{', '.join(sorted(set(missing)))}, which is unset"
        )
    return expanded


@dataclass(frozen=True, slots=True)
class ProviderPolicy:
    """Per-provider limits, applied in rotation order.

    A list rather than one shared policy because the three providers are not
    interchangeable: the free tiers differ by an order of magnitude, and Ankr
    (the independent fallback of TZ 5.6) is there to still be answering when the
    primaries are not — which it will not be if it has already been used at the
    same rate as them. Giving the fallback a smaller budget is what keeps it a
    fallback rather than a third primary.
    """

    requests_per_minute: int | None = None
    breaker: BreakerPolicy = field(default_factory=BreakerPolicy)
    request_timeout_seconds: float = 15.0


@dataclass(frozen=True, slots=True)
class WatcherSettings:
    """Everything the watcher needs that is *not* per-network.

    Per-network values (chain id, confirmations, finalized tag, provider list)
    live in `chains` and arrive as a :class:`ChainConfigRow`. What is here is
    tuning that follows the provider and the deployment, not the chain.
    """

    database_url: str = ""
    metrics_port: int = 9102
    poll_interval_seconds: float = 3.0
    #: Applied to slot 0, 1, 2 ... in rotation order; the last entry repeats if
    #: a chain lists more providers than there are policies.
    provider_policies: tuple[ProviderPolicy, ...] = (
        ProviderPolicy(requests_per_minute=600),  # Alchemy, primary
        ProviderPolicy(requests_per_minute=600),  # QuickNode, primary
        ProviderPolicy(requests_per_minute=120),  # Ankr, independent fallback
    )
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    chunks: ChunkPolicy = field(default_factory=ChunkPolicy)
    traversal: TraversalSettings = field(default_factory=TraversalSettings)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> WatcherSettings:
        """Read the handful of values that are genuinely deployment-level.

        Anything absent keeps its default. Nothing here reads an RPC URL: those
        come from the `chains` row and are expanded per provider, so that adding
        Ethereum mainnet in Week 4 is an `INSERT`, not an env-var rollout.
        """
        source = os.environ if env is None else env

        def number(name: str, fallback: float) -> float:
            raw = source.get(name)
            if not raw:
                return fallback
            try:
                return float(raw)
            except ValueError:
                return fallback

        return cls(
            database_url=source.get("DATABASE_URL", ""),
            metrics_port=int(number("WATCHER_METRICS_PORT", 9102)),
            poll_interval_seconds=number("WATCHER_POLL_INTERVAL_SECONDS", 3.0),
            chunks=ChunkPolicy(
                max_block_span=int(number("WATCHER_GETLOGS_BLOCK_SPAN", 500)),
                max_addresses=int(number("WATCHER_GETLOGS_ADDRESS_BATCH", 100)),
            ),
            traversal=TraversalSettings(
                max_blocks_per_step=int(number("WATCHER_BLOCKS_PER_STEP", 200)),
                initial_lookback_blocks=int(number("WATCHER_INITIAL_LOOKBACK", 1_000)),
                max_reorg_depth=int(number("WATCHER_MAX_REORG_DEPTH", 64)),
                provider_crosscheck_every=int(number("WATCHER_CROSSCHECK_EVERY", 0)),
                enable_native_transfers=(
                    source.get("WATCHER_ENABLE_NATIVE", "").lower() in ("1", "true", "yes")
                ),
            ),
        )

    def policy_for(self, index: int) -> ProviderPolicy:
        if not self.provider_policies:
            return ProviderPolicy()
        return self.provider_policies[min(index, len(self.provider_policies) - 1)]


def build_slots(
    chain: ChainConfigRow,
    settings: WatcherSettings,
    *,
    client_factory: object | None = None,
    env: Mapping[str, str] | None = None,
) -> list[ProviderSlot]:
    """Turn `chains.rpc_urls` into ready provider slots, in rotation order.

    `client_factory(label, url, request_timeout=...) -> RpcClient` is injected so
    the tests can build a whole pool out of replaying fakes. The default imports
    :class:`watcher.rpc.web3_client.Web3RpcClient` lazily — importing web3 at
    module scope would make `import watcher.config` require the network stack,
    and the point of the layering is that most of this package does not.
    """
    if not chain.rpc_urls:
        raise ValueError(
            f"chains row {chain.chain_id} ({chain.name}) lists no rpc_urls; "
            "the watcher needs at least one provider, and TZ 5.6 wants three"
        )

    factory = client_factory
    if factory is None:
        from watcher.rpc.web3_client import Web3RpcClient

        factory = Web3RpcClient

    slots: list[ProviderSlot] = []
    for index, raw_url in enumerate(chain.rpc_urls):
        policy = settings.policy_for(index)
        label = provider_label(raw_url)
        url = expand_rpc_url(raw_url, env)
        client = factory(  # type: ignore[operator]
            label, url, request_timeout=policy.request_timeout_seconds
        )
        slots.append(
            ProviderSlot(
                client=client,
                breaker=CircuitBreaker(label, policy.breaker),
                budget=RequestBudget(label, policy.requests_per_minute, window_seconds=60.0),
            )
        )
    return slots


def build_pool(
    chain: ChainConfigRow,
    settings: WatcherSettings,
    *,
    slots: Sequence[ProviderSlot] | None = None,
    client_factory: object | None = None,
    env: Mapping[str, str] | None = None,
) -> RpcPool:
    """A configured :class:`RpcPool` for one chain."""
    resolved = list(slots) if slots is not None else build_slots(
        chain, settings, client_factory=client_factory, env=env
    )
    return RpcPool(
        chain.chain_id,
        resolved,
        retry=settings.retry,
        chunks=settings.chunks,
    )


# TODO(week 4): a CI check that no module lets a raw provider URL reach a logger
# or a metric label, scanning the way `deriver/tests/test_no_private_key.py`
# scans for the xpub. Until that exists the guarantee rests on review plus
# `tests/watcher/test_config.py::test_provider_label_never_carries_a_key`, which
# proves the label is safe but cannot prove every call site uses it.
