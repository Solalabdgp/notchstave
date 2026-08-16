"""Native-coin (ETH) detection — and the class of payments it cannot see.

**This module is deliberately incomplete, and the incompleteness is documented
rather than fixed.** TZ 5.2 states the position: for ERC-20 there are logs and
the picture is complete; for the native coin there are no logs, and only part of
the picture is reachable on a normal RPC plan.

What is visible here
--------------------
A plain transfer from an externally owned account appears in the block's own
transaction list: `eth_getBlockByNumber(n, true)` returns objects with `to`,
`from` and `value`, and matching `to` against the receive-address pool finds it.
That covers a user paying from MetaMask, Rabby, a phone wallet — the ordinary
case.

What is invisible here, and why
-------------------------------
A transfer *initiated by a contract* does not appear in that list. Withdrawals
from some exchanges, multisend contracts, smart-contract wallets (ERC-4337 and
friends), and anything routed through a proxy move value as an **internal
transfer**: a value-carrying message call made during the execution of some
other transaction. Internal transfers leave no log and no top-level transaction;
they exist only inside the execution trace, which means `debug_traceBlock` or
`trace_block` — methods that are not part of free RPC tiers.

So there is a class of native payments this watcher cannot detect. Concretely:
a user withdraws ETH from an exchange straight to an invoice address, the money
arrives, the chain is correct, the amount is correct, and no payment row is
created.

How that is handled instead of hidden
-------------------------------------
1. Native payments are **off by default** (`enable_native_transfers`). The v1
   payment asset is USDC, where the log-based path is complete.
2. When the flag is on, the limitation is stated to the user at invoice time —
   this module cannot do that, but it is why the flag exists as configuration
   rather than as a constant.
3. The safety net is `/reconcile` (TZ 3.4): it compares the sum of recorded
   payments against the actual on-chain balance of each receive address. Money
   that arrived by a path the detector cannot see shows up there as a
   discrepancy, lands in `/pending`, and is resolved by a human.
4. `notchstave_reconcile_drift_usd` is the metric that makes it visible, and TZ
   section 7 already flags it as the most serious alert in the system.

Writing "here is the class of payments my detector does not see, here is why,
and here is how I catch them anyway" is stronger than pretending the problem is
not there. It is also the honest answer to the question a reviewer will ask.

Receipts
--------
Unlike an ERC-20 log, a transaction in the block list is *not* proof that the
transfer happened: a reverted transaction still sits in the block with its
`value` field intact, and its value is returned to the sender. So each candidate
is confirmed against its receipt (`status == 0x1`) before it becomes a payment.
That is one extra request per candidate, not per transaction, which is why the
`to`-address match comes first.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from watcher.models import NATIVE_LOG_INDEX, AssetRef, TransferEvent, WatchedAddress

__all__ = ["extract_native_transfer_candidates", "extract_native_transfers"]

ReceiptFetcher = Callable[[str], Awaitable[Mapping[str, Any] | None]]


def _hex_to_int(value: Any) -> int | None:
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


def extract_native_transfer_candidates(
    block: Mapping[str, Any],
    *,
    chain_id: int,
    addresses_by_lower: Mapping[str, WatchedAddress],
    native_asset: AssetRef,
) -> list[TransferEvent]:
    """Scan a full-transaction block for value transfers to watched addresses.

    Candidates only — success has not been checked yet. `log_index` is set to
    :data:`watcher.models.NATIVE_LOG_INDEX` (-1), the value the schema reserves
    for transfers that have no log.

    That reservation also settles a uniqueness question worth stating: the key
    is `(chain_id, tx_hash, -1)`, so two native payments in the same transaction
    would collide. They cannot happen — a transaction has exactly one `to` and
    one `value`, and a transaction that pays two addresses is by definition
    doing it through a contract, i.e. through internal transfers this function
    cannot see in the first place.
    """
    transactions = block.get("transactions")
    if not isinstance(transactions, (list, tuple)):
        return []

    block_number = _hex_to_int(block.get("number"))
    block_hash = block.get("hash")
    if block_number is None or not block_hash:
        raise ValueError("block is missing number/hash; cannot position native transfers")

    found: list[TransferEvent] = []
    for tx in transactions:
        if not isinstance(tx, Mapping):
            # `full_transactions=False` returns bare hashes. Detecting native
            # transfers then is impossible, and silently returning nothing would
            # look identical to "no payments in this block".
            raise ValueError(
                "native detection needs eth_getBlockByNumber(..., true); "
                "the block carries transaction hashes only"
            )
        recipient = tx.get("to")
        if not recipient:
            continue  # contract creation
        watched = addresses_by_lower.get(str(recipient).lower())
        if watched is None:
            continue
        value = _hex_to_int(tx.get("value"))
        if not value or value <= 0:
            continue
        tx_hash = tx.get("hash")
        if not tx_hash:
            raise ValueError("transaction in block has no hash")

        sender = tx.get("from")
        found.append(
            TransferEvent(
                chain_id=chain_id,
                tx_hash=str(tx_hash).lower(),
                log_index=NATIVE_LOG_INDEX,
                block_number=block_number,
                block_hash=str(block_hash).lower(),
                to_address=watched.address,
                address_id=watched.address_id,
                asset_id=native_asset.asset_id,
                amount_raw=value,
                sender=str(sender).lower() if sender else None,
            )
        )
    return found


async def extract_native_transfers(
    block: Mapping[str, Any],
    *,
    chain_id: int,
    addresses_by_lower: Mapping[str, WatchedAddress],
    native_asset: AssetRef,
    fetch_receipt: ReceiptFetcher | None = None,
) -> list[TransferEvent]:
    """Candidates, filtered down to the transactions that actually succeeded.

    `fetch_receipt=None` skips the check. That is only appropriate in tests and
    against a trusted archive replay: in production a reverted transaction that
    is credited is money paid out for a payment that was returned to its sender.
    """
    candidates = extract_native_transfer_candidates(
        block,
        chain_id=chain_id,
        addresses_by_lower=addresses_by_lower,
        native_asset=native_asset,
    )
    if fetch_receipt is None or not candidates:
        return candidates

    confirmed: list[TransferEvent] = []
    for candidate in candidates:
        receipt = await fetch_receipt(candidate.tx_hash)
        if receipt is None:
            # The node does not have the receipt yet. Treated as "not proven",
            # not as "failed": the next pass over this block will ask again,
            # and the insert is idempotent, so a delayed payment is recorded
            # late rather than lost.
            continue
        if _hex_to_int(receipt.get("status")) == 1:
            confirmed.append(candidate)
    return confirmed
