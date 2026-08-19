"""The EIP-681 string (TZ 3.2, 5.8/T1.4). Pure, no database.

The reason this has its own file and its own tests, rather than being asserted
only through an invoice: the string is the *third* of the buyer's three channels
and the only one they cannot read with their eyes. Everything that makes it
wrong makes it wrong invisibly.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from core.invoicing.eip681 import eip681_uri

RECIPIENT = "0x" + "11" * 20
TOKEN = "0x" + "22" * 20


def test_the_token_form_puts_the_contract_in_the_authority_and_the_buyer_in_the_argument() -> None:
    """The exact shape TZ 3.2 specifies."""
    uri = eip681_uri(
        chain_id=8453,
        recipient=RECIPIENT,
        amount_raw=Decimal(10_000_000),
        is_native=False,
        contract_address=TOKEN,
    )
    assert uri == f"ethereum:{TOKEN}@8453/transfer?address={RECIPIENT}&uint256=10000000"


def test_the_native_form_puts_the_buyer_in_the_authority() -> None:
    """A different shape, because sending ETH to a token contract burns it.

    This is why :func:`eip681_uri` takes ``is_native`` explicitly rather than
    inferring it from ``contract_address is None``: the two forms are not
    variants of a layout, they are two different destinations, and a caller who
    forgot to pass the contract would otherwise get a URI that silently sends
    native coin to the receive address of a token invoice.
    """
    uri = eip681_uri(
        chain_id=1, recipient=RECIPIENT, amount_raw=Decimal(10**18), is_native=True
    )
    assert uri == f"ethereum:{RECIPIENT}@1?value=1000000000000000000"


def test_the_chain_id_is_always_present() -> None:
    """EIP-681 makes it optional; omitting it is the ``wrong_chain`` anomaly of
    TZ 5.5 arriving by default, because a wallet with no chain id picks its own.
    """
    uri = eip681_uri(
        chain_id=1,
        recipient=RECIPIENT,
        amount_raw=Decimal(1),
        is_native=False,
        contract_address=TOKEN,
    )
    assert "@1/" in uri


def test_amounts_are_whole_base_units_and_never_exponent_notation() -> None:
    """``Decimal('1E+7')`` is what ``NUMERIC(78,0)`` returns after arithmetic.

    A wallet parsing ``uint256=1E+7`` either rejects the URI or reads a prefix of
    it, and the second outcome is a payment for one unit instead of ten million.
    """
    uri = eip681_uri(
        chain_id=8453,
        recipient=RECIPIENT,
        amount_raw=Decimal("1E+7"),
        is_native=False,
        contract_address=TOKEN,
    )
    assert "uint256=10000000" in uri

    with pytest.raises(ValueError, match="whole base units"):
        eip681_uri(
            chain_id=8453,
            recipient=RECIPIENT,
            amount_raw=Decimal("1.5"),
            is_native=False,
            contract_address=TOKEN,
        )


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"recipient": "0xdeadbeef"}, "recipient"),
        ({"contract_address": "not-an-address"}, "contract_address"),
        ({"amount_raw": Decimal(0)}, "positive"),
        ({"chain_id": 0}, "chain_id"),
    ],
)
def test_malformed_input_is_refused_rather_than_rendered(
    kwargs: dict[str, object], match: str
) -> None:
    """Last gate before a string becomes a QR code somebody scans."""
    base: dict[str, object] = {
        "chain_id": 8453,
        "recipient": RECIPIENT,
        "amount_raw": Decimal(1),
        "is_native": False,
        "contract_address": TOKEN,
    }
    base.update(kwargs)
    with pytest.raises(ValueError, match=match):
        eip681_uri(**base)  # type: ignore[arg-type]


def test_the_two_forms_refuse_each_others_arguments() -> None:
    """A native invoice with a contract, or a token invoice without one, is a bug."""
    with pytest.raises(ValueError, match="native"):
        eip681_uri(
            chain_id=1,
            recipient=RECIPIENT,
            amount_raw=Decimal(1),
            is_native=True,
            contract_address=TOKEN,
        )
    with pytest.raises(ValueError, match="contract"):
        eip681_uri(chain_id=1, recipient=RECIPIENT, amount_raw=Decimal(1), is_native=False)
