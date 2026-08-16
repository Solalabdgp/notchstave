"""Native-coin detection, and the class of payments it provably cannot see (TZ 5.2).

Most of this file tests a *limitation*. That is unusual and deliberate: TZ 5.2
takes the position that a documented blind spot beats a pretended completeness,
and a limitation that is only described in a docstring is a limitation nobody
verified. `test_contract_initiated_transfer_is_invisible` is the one that
matters — it pins the exact shape of payment that will not be detected, so that
the README's claim about it is checked by CI rather than by memory.
"""

from __future__ import annotations

import asyncio

import pytest

from tests.watcher.fakes import make_block
from watcher.detect.native import (
    extract_native_transfer_candidates,
    extract_native_transfers,
)
from watcher.models import NATIVE_LOG_INDEX, AssetRef, WatchedAddress

CHAIN_ID = 8453
POOL_ADDRESS = "0xAbC0000000000000000000000000000000000001"
STRANGER = "0xdEf0000000000000000000000000000000000002"


@pytest.fixture
def addresses() -> dict[str, WatchedAddress]:
    watched = WatchedAddress(address_id=7, address=POOL_ADDRESS, priority=0)
    return {watched.address_lower: watched}


@pytest.fixture
def native_asset() -> AssetRef:
    return AssetRef(
        asset_id=9,
        chain_id=CHAIN_ID,
        contract_lower=None,
        symbol="ETH",
        decimals=18,
        is_native=True,
        is_enabled=True,
    )


def tx(to: str | None, value: int, *, tx_hash: str, sender: str = "0x" + "11" * 20) -> dict:
    return {
        "hash": tx_hash,
        "from": sender,
        "to": to,
        "value": hex(value),
    }


def block_with(transactions) -> dict:
    return make_block(
        100,
        block_hash="0x" + "ab" * 32,
        parent_hash="0x" + "aa" * 32,
        transactions=transactions,
    )


# ---------------------------------------------------------------------------
# What it can see
# ---------------------------------------------------------------------------


def test_plain_eoa_transfer_is_found_in_the_block_transaction_list(
    addresses, native_asset
) -> None:
    """The ordinary case: a user paying from MetaMask, Rabby, a phone wallet."""
    block = block_with([tx(POOL_ADDRESS, 10**18, tx_hash="0x" + "cd" * 32)])
    found = extract_native_transfer_candidates(
        block, chain_id=CHAIN_ID, addresses_by_lower=addresses, native_asset=native_asset
    )

    assert len(found) == 1
    event = found[0]
    assert event.amount_raw == 10**18
    assert event.asset_id == 9
    assert event.log_index == NATIVE_LOG_INDEX == -1
    assert event.is_native is True
    assert event.to_address == POOL_ADDRESS


def test_transfers_to_other_addresses_and_zero_value_calls_are_skipped(
    addresses, native_asset
) -> None:
    block = block_with(
        [
            tx(STRANGER, 10**18, tx_hash="0x" + "01" * 32),
            tx(POOL_ADDRESS, 0, tx_hash="0x" + "02" * 32),
            tx(None, 10**18, tx_hash="0x" + "03" * 32),  # contract creation
        ]
    )
    assert (
        extract_native_transfer_candidates(
            block, chain_id=CHAIN_ID, addresses_by_lower=addresses, native_asset=native_asset
        )
        == []
    )


# ---------------------------------------------------------------------------
# The documented blind spot
# ---------------------------------------------------------------------------


def test_contract_initiated_transfer_is_invisible(addresses, native_asset) -> None:
    """The honest failure of TZ 5.2, pinned as a test rather than as prose.

    A withdrawal from an exchange, a multisend, or a smart-contract wallet moves
    value as an *internal* transfer: the top-level transaction is addressed to
    the contract, not to us, and our address appears nowhere in the block's
    transaction list. It exists only in the execution trace, which needs
    `debug_traceBlock` / `trace_block` — not available on free RPC tiers.

    So the money arrives, the chain is right, the amount is right, and no
    payment row is created. `/reconcile` (TZ 3.4) is the net that catches it,
    and `notchstave_reconcile_drift_usd` is what makes it visible.
    """
    router = "0x0000000000000000000000000000000000009999"
    block = block_with([tx(router, 5 * 10**17, tx_hash="0x" + "ee" * 32)])

    found = extract_native_transfer_candidates(
        block, chain_id=CHAIN_ID, addresses_by_lower=addresses, native_asset=native_asset
    )

    assert found == [], (
        "if this ever starts passing, the detector gained trace support and the "
        "README's documented limitation is out of date"
    )


def test_a_header_only_block_raises_instead_of_reporting_no_payments(
    addresses, native_asset
) -> None:
    """`full_transactions=False` returns bare hashes.

    Silently returning `[]` would be indistinguishable from "this block had no
    payments", which is the worst possible way for a configuration mistake to
    present itself on a money path.
    """
    block = block_with(["0x" + "cd" * 32])
    with pytest.raises(ValueError, match="transaction hashes only"):
        extract_native_transfer_candidates(
            block, chain_id=CHAIN_ID, addresses_by_lower=addresses, native_asset=native_asset
        )


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------


def test_a_reverted_transaction_is_not_a_payment(addresses, native_asset) -> None:
    """Unlike an ERC-20 log, presence in the block is not proof of success.

    A reverted transaction still sits in the block with its `value` intact, and
    that value went back to the sender. Crediting it is paying out for money
    that was returned.
    """
    tx_hash = "0x" + "cd" * 32
    block = block_with([tx(POOL_ADDRESS, 10**18, tx_hash=tx_hash)])

    async def failed_receipt(_hash: str):
        return {"status": "0x0"}

    found = asyncio.run(
        extract_native_transfers(
            block,
            chain_id=CHAIN_ID,
            addresses_by_lower=addresses,
            native_asset=native_asset,
            fetch_receipt=failed_receipt,
        )
    )
    assert found == []


def test_a_successful_transaction_survives_the_receipt_check(addresses, native_asset) -> None:
    tx_hash = "0x" + "cd" * 32
    block = block_with([tx(POOL_ADDRESS, 10**18, tx_hash=tx_hash)])

    async def ok_receipt(_hash: str):
        return {"status": "0x1"}

    found = asyncio.run(
        extract_native_transfers(
            block,
            chain_id=CHAIN_ID,
            addresses_by_lower=addresses,
            native_asset=native_asset,
            fetch_receipt=ok_receipt,
        )
    )
    assert len(found) == 1


def test_a_missing_receipt_defers_rather_than_discards(addresses, native_asset) -> None:
    """"The node doesn't have it yet" is not "it failed".

    The next pass asks again and the insert is idempotent, so a payment whose
    receipt lags is recorded late rather than lost.
    """
    block = block_with([tx(POOL_ADDRESS, 10**18, tx_hash="0x" + "cd" * 32)])

    async def no_receipt(_hash: str):
        return None

    found = asyncio.run(
        extract_native_transfers(
            block,
            chain_id=CHAIN_ID,
            addresses_by_lower=addresses,
            native_asset=native_asset,
            fetch_receipt=no_receipt,
        )
    )
    assert found == []
