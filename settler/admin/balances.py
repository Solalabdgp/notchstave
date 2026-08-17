"""On-chain balances for `/reconcile` and `/sweeplist` (TZ 3.4).

The one place in the settler that talks to a chain, and it does so through the
**watcher's** pool — :class:`watcher.rpc.pool.RpcPool` — rather than through
anything new. TZ 5.6 is explicit that there is one provider pool with one
rotation, one circuit breaker per provider, one backoff policy and one request
budget; a reconciliation sweep that opened its own HTTP client would sit outside
all four and could take the watcher down by exhausting a rate limit the watcher
thought it was managing.

That is why :class:`RpcBalanceSource` is a hundred lines of adapter and not a
client: everything hard was already solved next door.

----

**Why this does not weaken the "no signing" architecture test (TZ section 8).**

Two JSON-RPC methods are used. ``eth_getBalance`` reads a number.
``eth_call`` evaluates a contract function against a throwaway copy of state
inside the node and returns its return value; it takes no signature, produces no
transaction and changes nothing. Neither can move a coin. The property the
architectural test protects is that this repository contains no code path
capable of *signing or broadcasting*, and it still does not: there is no
``eth_sendRawTransaction``, no key material, no signing library anywhere in the
import graph.

Refusing to read balances would not have made the system safer; it would have
made `/reconcile` impossible, and `/reconcile` is the check that catches the
ledger and the chain silently diverging — the single most serious alert in TZ
section 7.

----

**Interface, not implementation, is what the callers depend on.**
:class:`BalanceSource` is a ``Protocol``, so ``reconcile`` and
``generate_sweep_list`` accept any object with one async method. The tests hand
in a scripted one; production hands in :class:`RpcBalanceSource`. TZ section 8 —
"RPC в тестах мокается сохранёнными ответами. Никаких сетевых вызовов в CI" —
is then true by construction rather than by discipline.
"""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from settler.admin.repository import AssetRow

if TYPE_CHECKING:  # pragma: no cover - typing only
    from watcher.rpc.pool import RpcPool

__all__ = [
    "BalanceSource",
    "RpcBalanceSource",
    "StaticBalanceSource",
    "BALANCE_OF_SELECTOR",
    "encode_balance_of",
    "decode_uint256",
]

#: ``keccak256("balanceOf(address)")[:4]``. Written as a constant rather than
#: computed, because computing it would mean importing a keccak implementation
#: into a package that has no other use for one — and this repository keeps
#: exactly one address-producing code path (the deriver), which is easier to
#: argue when no other module can hash anything into an address shape. The value
#: is the most widely quoted four bytes in Ethereum tooling and is asserted
#: against a known-good encoding in the tests.
BALANCE_OF_SELECTOR = "0x70a08231"


def encode_balance_of(address: str) -> str:
    """ABI calldata for ``balanceOf(address)``.

    One 32-byte argument, left-padded with zeros — the ABI encoding of a static
    type. Case is normalised away because an EIP-55 checksummed address and its
    lowercase form are the same twenty bytes, and the node compares bytes.
    """
    cleaned = address.lower().removeprefix("0x")
    if len(cleaned) != 40:
        raise ValueError(f"not a 20-byte address: {address!r}")
    return BALANCE_OF_SELECTOR + cleaned.rjust(64, "0")


def decode_uint256(data: str) -> int:
    """A 32-byte ABI return value -> int.

    An empty answer (``0x``) means the call reached an address with no code —
    a token contract that does not exist on this chain, or a mistyped
    ``contract_address``. That is a configuration error, and it raises rather
    than returning zero: a silent zero here reads downstream as "the money is
    gone", which is the most serious alert in TZ section 7 fired by a typo.
    """
    body = data.removeprefix("0x")
    if not body:
        raise ValueError("empty eth_call result: no contract at that address")
    return int(body, 16)


@runtime_checkable
class BalanceSource(Protocol):
    """Actual on-chain balance of one address for one asset, in base units."""

    async def balance_of(self, *, address: str, asset: AssetRow) -> Decimal:
        ...  # pragma: no cover - protocol declaration


class RpcBalanceSource:
    """Balances read through the watcher's provider pool (TZ 5.6).

    One pool per chain, exactly as the watcher holds them; the caller passes the
    pool for the chain being reconciled. Failover, backoff, the circuit breaker
    and the request budget all come from the pool and none of them are
    reimplemented here.
    """

    def __init__(self, pool: RpcPool, *, block: int | str = "latest") -> None:
        self._pool = pool
        #: Which height the balances are read at. ``latest`` for an interactive
        #: `/reconcile`; a specific height is what makes a reconciliation
        #: *reproducible*, which matters when the answer is "we are short by
        #: four hundred dollars" and someone re-runs it an hour later against a
        #: chain that has moved on. Left as a parameter rather than decided
        #: here — the caller knows whether it wants a snapshot or a live read.
        self._block = block

    @property
    def chain_id(self) -> int:
        return int(self._pool.chain_id)

    async def balance_of(self, *, address: str, asset: AssetRow) -> Decimal:
        if asset.chain_id != self.chain_id:
            raise ValueError(
                f"asset {asset.id} belongs to chain {asset.chain_id}, "
                f"this balance source serves chain {self.chain_id}"
            )
        if asset.is_native:
            return Decimal(await self._pool.get_balance(address, block=self._block))
        if not asset.contract_address:
            # The schema forbids this (``native_has_no_contract`` in 0001), so
            # reaching it means the row was written outside the application —
            # the same class of event as a MAC failure in TZ 5.8/T1.
            raise ValueError(f"asset {asset.id} is not native and has no contract address")
        result = await self._pool.call(
            {"to": asset.contract_address, "data": encode_balance_of(address)},
            block=self._block,
        )
        return Decimal(decode_uint256(result))


class StaticBalanceSource:
    """A balance source backed by a dict. Not a mock — a fixture.

    Lives in the package rather than in the test directory because it is also
    the honest way to re-run a reconciliation offline from a saved snapshot:
    "here is what the chain said at 14:02, reconcile against it again". Keyed by
    ``(asset_id, lowercase address)``; a missing key answers zero, exactly as a
    node does for an address it has never seen.
    """

    def __init__(self, balances: dict[tuple[int, str], Decimal | int]) -> None:
        self._balances = {(a, addr.lower()): Decimal(v) for (a, addr), v in balances.items()}
        self.calls: list[tuple[int, str]] = []

    async def balance_of(self, *, address: str, asset: AssetRow) -> Decimal:
        key = (asset.id, address.lower())
        self.calls.append(key)
        return self._balances.get(key, Decimal(0))
