"""ERC-20 `Transfer` decoding (TZ 5.2, TZ section 8 "Обнаружение платежей").

The three cases TZ section 8 names explicitly are here — decoding saved logs, a
payment to an address outside the pool being ignored, and chunking not losing a
payment on a chunk boundary (that one lives in `test_pool.py`, where the
chunking is). The rest of this file covers the traps that make the decoder
non-trivial: the ERC-721 signature collision, retracted logs, and a topic that
is not an address.

Honest note about the fixtures, because TZ section 8 asks for "реальных
сохранённых логах USDC": the payloads in `fixtures/` are shaped exactly as
`eth_getLogs` returns them, field for field, but they were constructed rather
than captured — this suite runs with no network access, and inventing a mainnet
transaction hash and calling it captured would be worse than saying so. What the
fixtures do prove is that the decoder handles the real wire shape (hex strings
everywhere, `removed`, padded topics). Capturing a genuine USDC log range and
committing it is a real TODO, marked at the bottom of this file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.watcher._keccak import KECCAK256_OF_EMPTY, keccak256
from watcher.detect.erc20 import (
    TRANSFER_SIGNATURE,
    TRANSFER_TOPIC0,
    address_to_topic,
    build_log_filter,
    decode_transfer_log,
    decode_transfer_logs,
    topic_to_address,
)
from watcher.models import AssetRef, WatchedAddress

FIXTURES = Path(__file__).parent / "fixtures"

CHAIN_ID = 8453
USDC = "0x1111111111111111111111111111111111110001"
OTHER_TOKEN = "0x1111111111111111111111111111111111110002"

# Checksummed exactly as `receive_addresses.address` stores them. The mixed case
# is the point: everything the decoder matches on is lowercased, and what it
# writes back is this string.
POOL_ADDRESS = "0xAbC0000000000000000000000000000000000001"
STRANGER = "0xdEf0000000000000000000000000000000000002"


@pytest.fixture
def addresses() -> dict[str, WatchedAddress]:
    watched = WatchedAddress(address_id=7, address=POOL_ADDRESS, priority=0)
    return {watched.address_lower: watched}


@pytest.fixture
def assets() -> dict[str, AssetRef]:
    return {
        USDC: AssetRef(
            asset_id=1,
            chain_id=CHAIN_ID,
            contract_lower=USDC,
            symbol="USDC",
            decimals=6,
            is_native=False,
            is_enabled=True,
        ),
        OTHER_TOKEN: AssetRef(
            asset_id=2,
            chain_id=CHAIN_ID,
            contract_lower=OTHER_TOKEN,
            symbol="XYZ",
            decimals=18,
            is_native=False,
            is_enabled=False,
        ),
    }


def load_fixture(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The constant itself
# ---------------------------------------------------------------------------


def test_the_test_keccak_is_itself_correct() -> None:
    """Check the checker before trusting it with the constant.

    A broken keccak that happens to agree with a wrong constant would turn this
    file's most important assertion into a rubber stamp.
    """
    assert keccak256(b"").hex() == KECCAK256_OF_EMPTY


def test_transfer_topic0_matches_the_signature_it_claims_to_hash() -> None:
    """Re-derive `TRANSFER_TOPIC0` from the signature string, independently.

    A hardcoded hash nobody verifies is a hardcoded hash that is wrong, and a
    wrong `topics[0]` means the filter silently matches nothing — a watcher that
    runs clean, reports no errors, and sees no payments at all. Every customer's
    money goes undetected and every dashboard stays green.

    The hashing lives in `tests/watcher/_keccak.py` rather than in a dependency
    precisely so this can never be skipped on the machine where it matters; see
    that module's docstring for why the runtime package has no keccak of its own.
    """
    assert TRANSFER_TOPIC0 == "0x" + keccak256(TRANSFER_SIGNATURE.encode()).hex()


def test_topic_roundtrip_is_lossless_and_lowercase() -> None:
    assert topic_to_address(address_to_topic(POOL_ADDRESS)) == POOL_ADDRESS.lower()


def test_topic_with_dirty_padding_is_rejected_not_truncated() -> None:
    """The upper 12 bytes must be zero.

    Silently truncating them would turn an unrelated 32-byte value into a
    plausible-looking address, and the whole recipient match downstream would be
    matching on garbage.
    """
    dirty = "0x" + "ff" * 12 + POOL_ADDRESS[2:].lower()
    with pytest.raises(ValueError):
        topic_to_address(dirty)


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


def test_decodes_a_saved_usdc_transfer(addresses, assets) -> None:
    logs = load_fixture("usdc_transfer_logs.json")
    events = decode_transfer_logs(
        logs, chain_id=CHAIN_ID, addresses_by_lower=addresses, assets_by_contract=assets
    )

    assert len(events) == 1
    event = events[0]
    assert event.amount_raw == 25_000_000  # 25 USDC at 6 decimals
    assert event.asset_id == 1
    assert event.block_number == 0x1000
    assert event.log_index == 3
    # Written back as stored (checksummed), never as the lowercase form the
    # topic was matched on.
    assert event.to_address == POOL_ADDRESS
    assert event.address_id == 7
    # Hashes normalised to lowercase so they satisfy the CHECK on payments.tx_hash.
    assert event.tx_hash == event.tx_hash.lower()
    assert event.sender == "0x" + "11" * 20


def test_payment_to_an_address_outside_the_pool_is_ignored(addresses, assets) -> None:
    """TZ section 8: "платёж на адрес вне пула игнорируется".

    Note what is being tested: the provider *returned* this log despite the
    filter. That is not hypothetical — TZ 5.8 lists a lying provider as a threat
    — so the decoder re-checks the recipient against our own pool rather than
    trusting the filter to have been honoured.
    """
    from tests.watcher.fakes import make_log

    log = make_log(
        contract=USDC,
        to_address=STRANGER,
        amount=999_000_000,
        block_number=0x1000,
        block_hash="0x" + "ab" * 32,
        tx_hash="0x" + "cd" * 32,
        log_index=1,
    )
    assert (
        decode_transfer_log(
            log, chain_id=CHAIN_ID, addresses_by_lower=addresses, assets_by_contract=assets
        )
        is None
    )


def test_erc721_transfer_with_the_same_topic0_is_not_decoded_as_money(
    addresses, assets
) -> None:
    """Four topics means ERC-721 — the signature hash is identical to ERC-20.

    Sending a worthless NFT to a receive address is a five-second attack. A
    decoder that reads `data` as an amount here would either credit a token id
    as a payment or record a zero. Both are worse than not seeing it.
    """
    from tests.watcher.fakes import make_log

    log = make_log(
        contract=USDC,
        to_address=POOL_ADDRESS,
        amount=42,
        block_number=0x1000,
        block_hash="0x" + "ab" * 32,
        tx_hash="0x" + "ce" * 32,
        log_index=2,
        extra_topic=True,
    )
    assert len(log["topics"]) == 4
    assert (
        decode_transfer_log(
            log, chain_id=CHAIN_ID, addresses_by_lower=addresses, assets_by_contract=assets
        )
        is None
    )


def test_retracted_log_is_dropped(addresses, assets) -> None:
    """`removed: true` — the node already withdrew this log.

    Recording it would create a payment row that has to be reverted moments
    later, which on a money table is pure cost.
    """
    from tests.watcher.fakes import make_log

    log = make_log(
        contract=USDC,
        to_address=POOL_ADDRESS,
        amount=1_000_000,
        block_number=0x1000,
        block_hash="0x" + "ab" * 32,
        tx_hash="0x" + "cf" * 32,
        log_index=0,
        removed=True,
    )
    assert (
        decode_transfer_log(
            log, chain_id=CHAIN_ID, addresses_by_lower=addresses, assets_by_contract=assets
        )
        is None
    )


def test_zero_value_transfer_is_not_a_payment(addresses, assets) -> None:
    """`payments.amount_raw > 0` is a CHECK constraint; a zero would be rejected."""
    from tests.watcher.fakes import make_log

    log = make_log(
        contract=USDC,
        to_address=POOL_ADDRESS,
        amount=0,
        block_number=0x1000,
        block_hash="0x" + "ab" * 32,
        tx_hash="0x" + "d0" * 32,
        log_index=0,
    )
    assert (
        decode_transfer_log(
            log, chain_id=CHAIN_ID, addresses_by_lower=addresses, assets_by_contract=assets
        )
        is None
    )


def test_unknown_token_contract_is_invisible_to_the_watcher(addresses, assets) -> None:
    """A token absent from `assets` cannot be recorded at all.

    `payments.asset_id` is NOT NULL with a composite FK to (assets.id,
    assets.chain_id), so there is no row to write. This is a real blind spot,
    and the test exists to pin it as *known* rather than discovered later:
    `/reconcile` is what surfaces the resulting balance (TZ 3.4).
    """
    from tests.watcher.fakes import make_log

    log = make_log(
        contract="0x9999999999999999999999999999999999999999",
        to_address=POOL_ADDRESS,
        amount=5_000_000,
        block_number=0x1000,
        block_hash="0x" + "ab" * 32,
        tx_hash="0x" + "d1" * 32,
        log_index=0,
    )
    assert (
        decode_transfer_log(
            log, chain_id=CHAIN_ID, addresses_by_lower=addresses, assets_by_contract=assets
        )
        is None
    )


def test_disabled_asset_is_still_decoded(addresses, assets) -> None:
    """A known-but-not-accepted token is `wrong_asset`, and must be recorded.

    Dropping it here would turn a documented anomaly (TZ 5.5) into an invisible
    one. The flagging happens in SQL at insert time, not in the decoder — so the
    decoder's job is to let it through.
    """
    from tests.watcher.fakes import make_log

    log = make_log(
        contract=OTHER_TOKEN,
        to_address=POOL_ADDRESS,
        amount=7,
        block_number=0x1000,
        block_hash="0x" + "ab" * 32,
        tx_hash="0x" + "d2" * 32,
        log_index=0,
    )
    event = decode_transfer_log(
        log, chain_id=CHAIN_ID, addresses_by_lower=addresses, assets_by_contract=assets
    )
    assert event is not None
    assert event.asset_id == 2


# ---------------------------------------------------------------------------
# Filter construction
# ---------------------------------------------------------------------------


def test_filter_matches_the_shape_tz_52_specifies() -> None:
    """`address` = contracts, `topics[0]` = signature, `topics[2]` = our addresses."""
    filter_object = build_log_filter(
        from_block=100, to_block=200, contracts=[USDC], recipients=[POOL_ADDRESS, STRANGER]
    )
    assert filter_object["fromBlock"] == "0x64"
    assert filter_object["toBlock"] == "0xc8"
    assert filter_object["address"] == [USDC]
    topics = filter_object["topics"]
    assert topics[0] == TRANSFER_TOPIC0
    # The sender is unconstrained: money arriving from anywhere is still money.
    assert topics[1] is None
    assert topics[2] == [address_to_topic(POOL_ADDRESS), address_to_topic(STRANGER)]


# TODO(week 4): replace `fixtures/usdc_transfer_logs.json` with a range captured
# from a real Base USDC contract via `eth_getLogs` and committed verbatim, so the
# decoder is pinned against bytes nobody in this repo chose. The current fixture
# proves shape handling, not provenance.
