"""Private key material must be refused, and never echoed.

The project's one-line pitch is that a private key cannot exist inside this
system (TZ 1, 5.1). That claim is only as good as the code that enforces it,
and there is a concrete reason it needs enforcing: ``bip_utils`` 2.12.2 accepts
an ``xprv`` in ``Bip44.FromExtendedKey`` without complaint and simply reports
``IsPublicOnly() == False``. Verified against the pinned version — so if the
guard in :mod:`deriver.derivation` were removed, the deriver would happily run
with a spendable key loaded and nothing would look wrong.

The second half of this file is about disclosure (TZ 5.8/T4): whatever is
rejected must not come back out in the exception text. An error message
containing the key ends up in a log, a traceback, a Sentry event or a support
message, and at that point the key is leaked by the code whose job was to
protect it.
"""

from __future__ import annotations

import pytest

from deriver.derivation import (
    NotAnAccountXpub,
    PrivateKeyMaterialRejected,
    account_fingerprint,
    derive_address,
)
from deriver.service import Deriver
from deriver.tests.test_account_addresses import TEST_ACCOUNT_XPUB

#: BIP-32 test vector 1 master private key — published in the specification,
#: corresponds to seed 000102...0f, holds nothing.
SPEC_XPRV = (
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv"
    "NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
)

#: BIP-32 test vector 1 master *public* key: valid, but at depth 0. Accepting a
#: master xpub would expose every account of every coin at once (TZ 5.1 rule 2).
SPEC_MASTER_XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ES"
    "FjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)


def test_a_private_extended_key_is_rejected() -> None:
    with pytest.raises(PrivateKeyMaterialRejected):
        derive_address(SPEC_XPRV, 0)


def test_a_private_extended_key_is_rejected_at_deriver_construction() -> None:
    """Fail at startup, not on the first customer's `/buy`."""
    with pytest.raises(PrivateKeyMaterialRejected):
        Deriver({1: SPEC_XPRV})


def test_the_rejection_message_does_not_contain_the_key() -> None:
    """TZ 5.8/T4: not in logs, not in errors, not in tracebacks."""
    with pytest.raises(PrivateKeyMaterialRejected) as caught:
        derive_address(SPEC_XPRV, 0)

    rendered = f"{caught.value}{caught.value.args!r}"
    assert SPEC_XPRV not in rendered
    assert SPEC_XPRV[4:40] not in rendered


def test_no_exception_chain_leaks_the_key() -> None:
    """`raise ... from None` is deliberate, and this proves it stays that way.

    Several bip_utils exceptions include the offending string. Chaining them
    with `from exc` would put the key into the traceback of every wrapped
    failure, where it would be captured by any error reporter.
    """
    with pytest.raises(PrivateKeyMaterialRejected) as caught:
        derive_address(SPEC_XPRV, 0)

    chained: list[str] = []
    current: BaseException | None = caught.value
    while current is not None:
        chained.append(str(current))
        current = current.__cause__ or current.__context__

    assert not any(SPEC_XPRV in text for text in chained)


def test_a_master_xpub_is_rejected() -> None:
    """Only account level is accepted (TZ 5.1 rule 2, 5.8/T4)."""
    with pytest.raises(NotAnAccountXpub):
        derive_address(SPEC_MASTER_XPUB, 0)


@pytest.mark.parametrize("prefix", ["ypub", "zpub", "tpub", "vpub"])
def test_non_mainnet_extended_key_prefixes_are_rejected(prefix: str) -> None:
    """ypub/zpub are SLIP-132 segwit variants — wrong script type, wrong chain.

    Deriving from one would still produce a syntactically valid Ethereum
    address, which is exactly why it has to be refused explicitly rather than
    left to fail somewhere downstream.
    """
    swapped = prefix + TEST_ACCOUNT_XPUB[4:]

    with pytest.raises(PrivateKeyMaterialRejected):
        derive_address(swapped, 0)


@pytest.mark.parametrize(
    "malformed",
    [
        "",
        "xpub",
        "xpubTOOSHORT",
        "not a key at all",
        "xpub" + "0" * 107,  # '0' is not in the base58 alphabet
    ],
)
def test_malformed_keys_are_rejected(malformed: str) -> None:
    with pytest.raises((PrivateKeyMaterialRejected, NotAnAccountXpub)):
        account_fingerprint(malformed)


def test_a_corrupted_checksum_is_rejected() -> None:
    """base58check is what catches a transcription error in the exported key.

    This is the realistic failure during setup: the owner copies the xpub off a
    hardware wallet screen and drops a character. It must fail loudly, because
    the alternative is deriving addresses nobody can sweep.
    """
    corrupted = TEST_ACCOUNT_XPUB[:-1] + ("a" if TEST_ACCOUNT_XPUB[-1] != "a" else "b")

    with pytest.raises(NotAnAccountXpub):
        derive_address(corrupted, 0)


def test_non_string_input_is_rejected() -> None:
    for junk in (None, 42, b"bytes", ["list"]):
        with pytest.raises(PrivateKeyMaterialRejected):
            derive_address(junk, 0)  # type: ignore[arg-type]


def test_deriver_repr_does_not_leak_the_xpub() -> None:
    """TZ 5.8/T4 asks for an overridden ``__repr__`` specifically.

    A default repr is how a key reaches a log: a config object printed at
    startup, a pytest assertion diff, a debugger frame dump.
    """
    deriver = Deriver({1: TEST_ACCOUNT_XPUB})

    for rendered in (repr(deriver), str(deriver), f"{deriver}"):
        assert TEST_ACCOUNT_XPUB not in rendered
        assert TEST_ACCOUNT_XPUB[4:40] not in rendered
    assert "60b68b69" in repr(deriver)  # fingerprint is safe and useful


def test_deriver_has_no_attribute_exposing_the_xpub() -> None:
    """`__slots__` + name mangling: no `__dict__` to walk, no attribute to grab.

    Not a security boundary against code running in-process — it is defence
    against accidental disclosure by generic machinery (serialisers, `vars()`,
    error reporters) that reflects over objects it was never told about.
    """
    deriver = Deriver({1: TEST_ACCOUNT_XPUB})

    assert not hasattr(deriver, "__dict__")
    exposed = [
        name
        for name in dir(deriver)
        if not name.startswith("_") and isinstance(getattr(deriver, name, None), str)
    ]
    assert exposed == []
