"""Turning RPC payloads into :class:`watcher.models.TransferEvent` values.

Two detectors, and they are not equally good — which is the point of keeping
them in separate modules with separate docstrings:

* `erc20.py` — complete. Every ERC-20 transfer emits a `Transfer` log, logs of
  reverted transactions are discarded by the node, and `eth_getLogs` with an
  address array in `topics[2]` retrieves them in batches. The main payment asset
  (USDC) lives entirely inside this path.
* `native.py` — knowingly incomplete. Plain EOA transfers are visible in the
  block's transaction list; transfers initiated by a contract are not visible
  anywhere without `debug_traceBlock`/`trace_block`. TZ 5.2 calls this out as an
  accepted limitation rather than a bug, and the module documents exactly which
  payments it cannot see.

Neither module imports web3, sqlalchemy or `core`: decoding a log is arithmetic
over hex strings, and keeping it dependency-free is what lets the tests replay
saved payloads with nothing installed.
"""

from watcher.detect.erc20 import (
    TRANSFER_TOPIC0,
    address_to_topic,
    decode_transfer_log,
    topic_to_address,
)
from watcher.detect.native import extract_native_transfers

__all__ = [
    "TRANSFER_TOPIC0",
    "address_to_topic",
    "decode_transfer_log",
    "extract_native_transfers",
    "topic_to_address",
]
