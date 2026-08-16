"""ERC-20 `Transfer` detection (TZ 5.2).

The filter, in the words of the spec: `address` = the token contract,
`topics[0]` = the `Transfer` signature, `topics[2]` = our receive addresses in
padded form. An array in a topic position means OR, so one request covers a
batch of addresses; the chunking that keeps those requests inside provider
limits lives in `watcher/rpc/pool.py`.

Everything below is a filter in the other sense too — a log that reaches
:func:`decode_transfer_log` has already been chosen by a remote node we do not
control, and TZ 5.8 lists "подложные логи Transfer" from a lying provider as a
threat against the watcher. So the decoder re-checks every property it depends
on instead of trusting the filter to have been honoured:

* `topics[0]` is compared again, locally;
* the recipient is looked up in our own address map, so a log for somebody
  else's address is dropped even if the provider returned it;
* the token contract is looked up in our own `assets` map;
* `removed: true` (a log the node has already retracted) is dropped.

**The four-topic trap.** ERC-721 declares
`Transfer(address indexed from, address indexed to, uint256 indexed tokenId)`,
which produces *the same* `topics[0]` as ERC-20 — the signature text is
identical, only the `indexed` on the third argument differs. An NFT transfer to
a receive address therefore matches the filter, and a decoder that reads
`data` as the amount would read an empty `data` field, or worse, would read a
token id as a token amount. The topic count is the discriminator: three topics
is ERC-20, four is ERC-721, and this is not a hypothetical — sending a
worthless NFT to a payment address is a five-second attack.

**Why no keccak here.** Matching is done on lowercase strings against the pool
loaded from the database, and the *stored* checksummed address is what gets
written back, so the watcher never needs to compute an EIP-55 checksum and
therefore never needs a keccak implementation. That keeps this module free of
`eth_utils`/`web3` and, more importantly, keeps a second address-producing code
path out of the repository: addresses are produced by the deriver, from the
xpub, and by nobody else (TZ 5.8/T1).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from watcher.models import AssetRef, TransferEvent, WatchedAddress

__all__ = [
    "TRANSFER_TOPIC0",
    "TRANSFER_SIGNATURE",
    "address_to_topic",
    "topic_to_address",
    "build_log_filter",
    "decode_transfer_log",
    "decode_transfer_logs",
]

#: The canonical event signature, kept next to its hash so the two can be
#: checked against each other.
TRANSFER_SIGNATURE = "Transfer(address,address,uint256)"

#: keccak256(TRANSFER_SIGNATURE). Hardcoded rather than computed at import time
#: so that this module needs no hashing library — and re-derived from the
#: signature string by `tests/watcher/test_erc20.py`, which fails if the
#: constant is wrong. A constant nobody verifies is a constant that is wrong.
TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

#: 32-byte topic, 20-byte address: 12 bytes (24 hex chars) of zero padding.
_TOPIC_PAD = "0" * 24


def address_to_topic(address: str) -> str:
    """Left-pad a 20-byte address into a 32-byte topic value (lowercase)."""
    cleaned = address.lower()
    if not cleaned.startswith("0x") or len(cleaned) != 42:
        raise ValueError(f"not a 20-byte hex address: {address!r}")
    return "0x" + _TOPIC_PAD + cleaned[2:]


def topic_to_address(topic: str) -> str:
    """Read the low 20 bytes of a topic as an address (lowercase).

    The upper 12 bytes are asserted to be zero. A non-zero prefix means the
    topic is not an address — either a different event squatting on the same
    signature hash, or a provider returning something unrelated. Either way it
    must not be silently truncated into a valid-looking address.
    """
    cleaned = topic.lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 64:
        raise ValueError(f"topic is not 32 bytes: {topic!r}")
    if cleaned[:24] != _TOPIC_PAD:
        raise ValueError(f"topic has a non-zero address padding: {topic!r}")
    return "0x" + cleaned[24:]


def build_log_filter(
    *,
    from_block: int,
    to_block: int,
    contracts: Sequence[str],
    recipients: Sequence[str],
) -> dict[str, Any]:
    """Build one `eth_getLogs` filter object (TZ 5.2).

    `topics[1]` is None — the sender is not constrained; we care about money
    arriving, from anywhere. `topics[2]` is the OR-array of padded recipients.
    """
    filter_object: dict[str, Any] = {
        "fromBlock": hex(from_block),
        "toBlock": hex(to_block),
        "topics": [
            TRANSFER_TOPIC0,
            None,
            [address_to_topic(address) for address in recipients],
        ],
    }
    if contracts:
        filter_object["address"] = [contract.lower() for contract in contracts]
    return filter_object


def _hex_to_int(value: Any) -> int | None:
    """Accept both `"0x1f"` and an already-decoded int; reject anything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16)
        except ValueError:
            return None
    return None


def decode_transfer_log(
    log: Mapping[str, Any],
    *,
    chain_id: int,
    addresses_by_lower: Mapping[str, WatchedAddress],
    assets_by_contract: Mapping[str, AssetRef],
) -> TransferEvent | None:
    """Decode one log into a :class:`TransferEvent`, or None if it is not ours.

    None is returned — rather than an exception raised — for every "this log is
    not a payment to us" case, because those are the normal majority: a chunked
    filter over a busy token returns plenty of logs that are irrelevant by the
    time they are cross-checked locally. Malformed input that *did* match all of
    our own checks is different and raises, because that means either a provider
    is corrupting data or this decoder is wrong, and both need a stack trace.
    """
    if log.get("removed") is True:
        # The node already retracted this log (its block lost a reorg race).
        # Recording it would create a payment row that has to be reverted a
        # moment later, for no benefit.
        return None

    topics = log.get("topics")
    if not isinstance(topics, (list, tuple)):
        return None

    # Three topics: ERC-20. Four: ERC-721 with the same signature hash, see the
    # module docstring. Anything else is not a Transfer we understand.
    if len(topics) != 3:
        return None
    if str(topics[0]).lower() != TRANSFER_TOPIC0:
        return None

    contract = str(log.get("address", "")).lower()
    asset = assets_by_contract.get(contract)
    if asset is None:
        # A token that is not in the `assets` table for this chain. The watcher
        # cannot record it at all: `payments.asset_id` is NOT NULL with a
        # composite FK to (assets.id, assets.chain_id). This is the blind spot
        # that `/reconcile` exists to surface (TZ 3.4) — a balance on a receive
        # address with no payment row behind it.
        return None

    try:
        recipient = topic_to_address(str(topics[2]))
    except ValueError:
        return None

    watched = addresses_by_lower.get(recipient)
    if watched is None:
        return None

    amount = _hex_to_int(log.get("data"))
    if amount is None:
        raise ValueError(f"Transfer log for {recipient} has undecodable data: {log.get('data')!r}")
    if amount <= 0:
        # A zero-value transfer is legal ERC-20 and is not a payment.
        # `payments.amount_raw > 0` is a CHECK constraint, so storing one is not
        # merely pointless, it is impossible.
        return None

    block_number = _hex_to_int(log.get("blockNumber"))
    log_index = _hex_to_int(log.get("logIndex"))
    tx_hash = log.get("transactionHash")
    block_hash = log.get("blockHash")
    if block_number is None or log_index is None or not tx_hash or not block_hash:
        raise ValueError(f"Transfer log is missing position fields: {dict(log)!r}")

    try:
        sender = topic_to_address(str(topics[1]))
    except ValueError:
        sender = None

    return TransferEvent(
        chain_id=chain_id,
        tx_hash=str(tx_hash).lower(),
        log_index=log_index,
        block_number=block_number,
        block_hash=str(block_hash).lower(),
        to_address=watched.address,
        address_id=watched.address_id,
        asset_id=asset.asset_id,
        amount_raw=amount,
        sender=sender,
    )


def decode_transfer_logs(
    logs: Sequence[Mapping[str, Any]],
    *,
    chain_id: int,
    addresses_by_lower: Mapping[str, WatchedAddress],
    assets_by_contract: Mapping[str, AssetRef],
) -> list[TransferEvent]:
    """Decode a batch, dropping everything that is not a payment to us."""
    events: list[TransferEvent] = []
    for log in logs:
        event = decode_transfer_log(
            log,
            chain_id=chain_id,
            addresses_by_lower=addresses_by_lower,
            assets_by_contract=assets_by_contract,
        )
        if event is not None:
            events.append(event)
    return events
