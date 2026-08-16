"""Configuration: no hardcoded network, no leaked API key (TZ 2, 5.6, 5.8).

Two properties, and the second one is the one that would go unnoticed until it
was already on a public dashboard.

**No network is hardcoded.** TZ section 2 makes the second chain the thing that
proves the design is genuinely multi-chain. A grep-style test is the only way to
keep that true as the code grows — a single `if chain_id == 8453` added in a
hurry undoes it silently.

**Provider URLs carry credentials.** An Alchemy or QuickNode endpoint has the
API key in the path. `notchstave_rpc_requests_total{provider,...}` is scraped by
Prometheus and rendered on a dashboard, so a label built from the raw URL
publishes the key. TZ 5.8/T4 forbids exactly this for the xpub; the same rule
applies to the other credential in the system.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from tests.watcher.fakes import make_chain
from watcher.config import (
    MissingProviderCredential,
    ProviderPolicy,
    WatcherSettings,
    build_pool,
    build_slots,
    expand_rpc_url,
    provider_label,
)

WATCHER_DIR = Path(__file__).resolve().parents[2] / "watcher"


class RecordingClient:
    """Captures what `build_slots` handed it, without touching a network."""

    instances: list[RecordingClient] = []

    def __init__(self, label: str, url: str, *, request_timeout: float = 15.0) -> None:
        self.name = label
        self.url = url
        self.request_timeout = request_timeout
        RecordingClient.instances.append(self)

    async def aclose(self) -> None:
        return None


@pytest.fixture(autouse=True)
def _reset_recording() -> None:
    RecordingClient.instances = []


# ---------------------------------------------------------------------------
# Credential hygiene
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://base-mainnet.g.alchemy.com/v2/SUPERSECRETKEY", "base-mainnet.g.alchemy.com"),
        (
            "https://weathered-frost.base-mainnet.quiknode.pro/0123456789abcdef/",
            "weathered-frost.base-mainnet.quiknode.pro",
        ),
        ("https://rpc.ankr.com/base/TOKEN123", "rpc.ankr.com"),
        # Userinfo is a credential too, and `hostname` is what drops it.
        ("https://user:hunter2@node.example.com/rpc", "node.example.com"),
    ],
)
def test_provider_label_never_carries_a_key(url: str, expected: str) -> None:
    label = provider_label(url)
    assert label == expected
    for secret in ("SUPERSECRETKEY", "0123456789abcdef", "TOKEN123", "hunter2"):
        assert secret not in label


def test_provider_label_survives_a_url_it_cannot_parse() -> None:
    """The fallback branch is the only one that could leak, so it is bounded.

    Returning the whole string on a parse failure is the obvious implementation
    and the wrong one: a malformed URL still contains the key.
    """
    label = provider_label("not-a-url-at-all-" + "K" * 200)
    assert len(label) <= 40


# ---------------------------------------------------------------------------
# Env expansion: keys stay out of the database
# ---------------------------------------------------------------------------


def test_stored_url_template_is_expanded_from_the_environment() -> None:
    """`chains.rpc_urls` keeps the provider identity; the env keeps the secret.

    A row a compromised `api` role can `SELECT` is not where an API key belongs
    (TZ 5.8), so the stored form is a template.
    """
    expanded = expand_rpc_url(
        "https://base-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}",
        {"ALCHEMY_API_KEY": "realkey"},
    )
    assert expanded == "https://base-mainnet.g.alchemy.com/v2/realkey"


def test_a_url_without_placeholders_is_left_alone() -> None:
    plain = "https://rpc.example.com/v1"
    assert expand_rpc_url(plain, {}) == plain


def test_an_unset_placeholder_is_a_startup_failure_not_a_silent_request() -> None:
    """Degrading to two providers quietly is worse than not starting.

    A watcher running on a thinner rotation than the operator believes is exactly
    the state in which the next provider outage becomes a payment outage.
    """
    with pytest.raises(MissingProviderCredential) as excinfo:
        expand_rpc_url("https://x.example.com/v2/${NOT_SET_ANYWHERE}", {})
    assert "NOT_SET_ANYWHERE" in str(excinfo.value)


def test_the_failure_message_does_not_echo_the_rest_of_the_url() -> None:
    message = ""
    try:
        expand_rpc_url("https://x.example.com/v2/LEAKY/${NOPE}", {})
    except MissingProviderCredential as exc:
        message = str(exc)
    assert "LEAKY" not in message


# ---------------------------------------------------------------------------
# Pool construction from the chains row
# ---------------------------------------------------------------------------


def test_slots_are_built_in_the_order_the_chains_row_lists_them() -> None:
    """Rotation order is per-chain config: primaries first, fallback last (TZ 5.6)."""
    chain = make_chain(
        rpc_urls=(
            "https://base-mainnet.g.alchemy.com/v2/A",
            "https://x.base-mainnet.quiknode.pro/B/",
            "https://rpc.ankr.com/base/C",
        )
    )
    slots = build_slots(chain, WatcherSettings(), client_factory=RecordingClient)

    assert [s.name for s in slots] == [
        "base-mainnet.g.alchemy.com",
        "x.base-mainnet.quiknode.pro",
        "rpc.ankr.com",
    ]


def test_the_independent_fallback_gets_a_smaller_budget_than_the_primaries() -> None:
    """Ankr exists to still be answering when the primaries are not.

    Which it will not be if it has been spent at the same rate as them — that is
    what makes it a third primary rather than a fallback.
    """
    chain = make_chain(
        rpc_urls=("https://a.example/1", "https://b.example/2", "https://c.example/3")
    )
    slots = build_slots(chain, WatcherSettings(), client_factory=RecordingClient)

    assert slots[2].budget.limit is not None
    assert slots[2].budget.limit < slots[0].budget.limit


def test_more_providers_than_policies_reuses_the_last_policy() -> None:
    settings = WatcherSettings(
        provider_policies=(ProviderPolicy(requests_per_minute=100),)
    )
    chain = make_chain(rpc_urls=("https://a.example/1", "https://b.example/2"))
    slots = build_slots(chain, settings, client_factory=RecordingClient)
    assert [s.budget.limit for s in slots] == [100, 100]


def test_a_chain_row_with_no_providers_fails_loudly() -> None:
    chain = make_chain(rpc_urls=())
    with pytest.raises(ValueError, match="rpc_urls"):
        build_slots(chain, WatcherSettings(), client_factory=RecordingClient)


def test_pool_carries_the_chain_id_from_the_row() -> None:
    chain = make_chain(chain_id=1, name="ethereum", rpc_urls=("https://a.example/1",))
    pool = build_pool(chain, WatcherSettings(), client_factory=RecordingClient)
    assert pool.chain_id == 1


# ---------------------------------------------------------------------------
# No hardcoded networks (TZ section 2)
# ---------------------------------------------------------------------------


def test_no_chain_id_or_chain_name_is_hardcoded_anywhere_in_the_package() -> None:
    """Base and Ethereum are rows in `chains`, never constants.

    One network lets you hardcode anything; the second is what forces the design
    to be honestly multi-chain (TZ section 2). This test is what stops that
    property from decaying one convenient constant at a time.
    """
    banned_text = re.compile(
        r"mainnet\.g\.alchemy|quiknode\.pro|rpc\.ankr\.com|\bbase-mainnet\b", re.IGNORECASE
    )
    banned_numbers = {8453, 84532, 1, 11155111}  # Base, Base Sepolia, Ethereum, Sepolia

    offenders: list[str] = []
    for path in sorted(WATCHER_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        # Docstrings and comments are prose and may name a network freely — the
        # module docstrings here explain *why* Base is a row rather than a
        # constant, and a grep-based check would flag its own justification.
        # What must not exist is a literal the code can branch on, so only
        # non-docstring constants are examined.
        docstrings = {
            id(node.body[0].value)
            for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        }

        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or id(node) in docstrings:
                continue
            if isinstance(node.value, str) and banned_text.search(node.value):
                offenders.append(f"{path.name}:{node.lineno}: string {node.value!r}")
            elif isinstance(node.value, int) and not isinstance(node.value, bool):
                # `1` is too common to ban outright as a bare integer; it only
                # counts as a chain id when it is assigned to something that
                # calls itself one, which is beyond a literal scan. The wide net
                # here is the multi-digit ids, which have no other meaning.
                if node.value in banned_numbers and node.value != 1:
                    offenders.append(f"{path.name}:{node.lineno}: literal {node.value}")

    assert not offenders, "network identity must come from the `chains` row:\n" + "\n".join(
        offenders
    )


def test_settings_from_env_falls_back_cleanly_on_garbage() -> None:
    """A malformed env var must not take the process down at import time."""
    settings = WatcherSettings.from_env({"WATCHER_BLOCKS_PER_STEP": "not-a-number"})
    assert settings.traversal.max_blocks_per_step == 200


def test_native_transfers_are_off_unless_explicitly_enabled() -> None:
    """TZ 5.2: the native path cannot see contract-initiated transfers.

    Default-on would mean silently accepting an asset whose detection is known
    to be incomplete.
    """
    assert WatcherSettings.from_env({}).traversal.enable_native_transfers is False
    enabled = WatcherSettings.from_env({"WATCHER_ENABLE_NATIVE": "true"})
    assert enabled.traversal.enable_native_transfers is True
