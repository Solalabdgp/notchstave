"""The EIP-681 payment string. One source of truth for three channels.

TZ 3.2 asks for the QR to be built from this, and TZ 5.8/T1.4 explains why it
must be a *string* the server returns rather than a PNG the server renders::

    QR не рендерится картинкой на сервере: клиенту отдаётся текстовая строка
    EIP-681, QR строится в браузере из неё же, и та же строка показывается
    текстом рядом. Одна точка правды вместо двух — подмена картинки перестаёт
    быть незаметной.

That is the whole design constraint on this module. A buyer cannot build a
derivation proof (no xpub — T4 forbids publishing it), so the check available to
them is that the address is identical in the bot message, in the API response
and inside the QR. A server-rendered image breaks that check silently, because
nobody reads a QR with their eyes. Building the string here, once, and having
the bot and the api both call it is what makes "identical in three channels"
a property of the code rather than a hope about three call sites.

**Two forms, and why the token one is not optional.**

For an ERC-20 the recipient is the *token contract*, and the transfer target is
an argument::

    ethereum:<token>@<chainId>/transfer?address=<recipient>&uint256=<amount>

Sending native ETH to a token contract address would burn it. So the two forms
are not cosmetic variants — picking the wrong one loses the buyer's money, which
is why :func:`eip681_uri` refuses to guess and takes ``is_native`` explicitly
rather than inferring it from ``contract_address is None``.

**Amounts are raw base units, always.** ``uint256=`` and ``value=`` are both
integers in the smallest unit; a wallet that receives ``10.5`` there does
something undefined. The whole schema stores ``NUMERIC(78,0)`` for this reason
(TZ 5.3), and this module refuses anything non-integral instead of rounding it.
"""

from __future__ import annotations

from decimal import Decimal

__all__ = ["eip681_uri", "EIP681_SCHEME"]

EIP681_SCHEME = "ethereum"


def _amount_literal(amount_raw: Decimal | int) -> str:
    """Base units as a plain integer — never ``1E+7``, never a float.

    ``NUMERIC(78,0)`` arrives from psycopg as a ``Decimal`` whose ``str()`` may
    carry an exponent after arithmetic. A wallet parsing ``uint256=1E+7`` either
    rejects the URI or, worse, reads a prefix of it.
    """
    value = Decimal(amount_raw)
    if value != value.to_integral_value():
        raise ValueError(f"amount must be whole base units, got {value!r}")
    if value <= 0:
        raise ValueError(f"amount must be positive, got {value!r}")
    return format(int(value), "d")


def _checked_address(address: str, *, field: str) -> str:
    """Reject anything that is not a 0x-prefixed 20-byte hex address.

    Cheap, and it is the last gate before a string goes into a QR a buyer will
    scan. The database CHECKs the same shape (``EVM_ADDRESS_RE``); repeating it
    here means a value that reached this function from anywhere else — a cache,
    a test fixture, a future admin override — is held to the same standard.
    """
    if not address.startswith("0x") or len(address) != 42:
        raise ValueError(f"{field} must be a 0x-prefixed 20-byte address, got {address!r}")
    try:
        int(address[2:], 16)
    except ValueError:
        raise ValueError(f"{field} is not hexadecimal: {address!r}") from None
    return address


def eip681_uri(
    *,
    chain_id: int,
    recipient: str,
    amount_raw: Decimal | int,
    is_native: bool,
    contract_address: str | None = None,
) -> str:
    """Build the payment URI for one invoice.

    ``recipient`` is always the address the buyer's funds must end up at — i.e.
    the invoice's receive address — in both forms. The ERC-20 form puts it in
    the ``address`` argument and the contract in the authority position; the
    native form puts it in the authority position directly. Callers therefore
    never have to know which slot their address goes in, which is the mistake
    this signature is shaped to prevent.

    The chain id is always present, including for mainnet. EIP-681 makes it
    optional and a wallet defaulting to Ethereum when the invoice is on Base is
    the ``wrong_chain`` anomaly of TZ 5.5 happening by omission.
    """
    if chain_id <= 0:
        raise ValueError(f"chain_id must be positive, got {chain_id!r}")
    target = _checked_address(recipient, field="recipient")
    amount = _amount_literal(amount_raw)

    if is_native:
        if contract_address is not None:
            raise ValueError("a native-asset invoice must not carry a contract address")
        return f"{EIP681_SCHEME}:{target}@{chain_id}?value={amount}"

    if contract_address is None:
        raise ValueError("a token invoice needs the ERC-20 contract address")
    token = _checked_address(contract_address, field="contract_address")
    return (
        f"{EIP681_SCHEME}:{token}@{chain_id}/transfer"
        f"?address={target}&uint256={amount}"
    )
