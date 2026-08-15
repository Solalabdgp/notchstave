"""Control check: the first five addresses from a known-throwaway test xpub.

TZ 5.1 requires a control comparison of the first five addresses against an
independently computed result before a single real payment is accepted. In
production that second opinion is the owner's hardware wallet, which cannot be
driven from CI; this file provides the automatable half of that gate, and the
hardware-wallet comparison stays a manual step in the Week 1 checklist.

**Which key.** The BIP-39 canonical test mnemonic — eleven ``abandon`` and one
``about``, the all-zero-entropy vector from the BIP-39 reference test suite
(https://github.com/trezor/python-mnemonic, ``vectors.json``, first entry). It
is the most-published seed phrase in the ecosystem, has no funds anyone sane
would send it, and is the only kind of key that may appear in this repository:
TZ 5.8/T4 forbids a real xpub in git, in the README, or in a screenshot.

Its BIP-39 seed is pinned below and matches the reference vector byte for byte,
which is what makes the account xpub derived from it reproducible by anyone.

**Where the expected addresses come from.** Two independent sources had to
agree before they were written down:

1. ``bip_utils`` 2.12.2 — the production path;
2. the reimplementation in this file, which shares no code with it: base58
   decoding written out longhand, CKDpub over ``coincurve``, and keccak-256
   from ``pycryptodome``. Different libraries, different authors, same numbers.

A third, external confirmation: ``0x9858EfFD232B4033E47d90003D41EC34EcaEda94``
is the widely documented first Ethereum address of this mnemonic at
``m/44'/60'/0'/0/0`` (it appears throughout HD-wallet library documentation and
test fixtures, e.g. hdwallet-io/python-hdwallet and Nethereum's wallet docs).

A single implementation checked against itself proves nothing. That is why the
independent path below is real code and not a copied constant.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod

import pytest
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins
from coincurve import PublicKey
from Crypto.Hash import keccak

from deriver.derivation import account_fingerprint, derive_address, derive_addresses

# --------------------------------------------------------------------------
# Public, deliberately-burned test material. Never a real key (TZ 5.8/T4).
# --------------------------------------------------------------------------

TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

#: BIP-39 reference vector for the mnemonic above (empty passphrase).
TEST_SEED_HEX = (
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)

#: Account-level xpub at m/44'/60'/0' — exactly what the owner's hardware
#: wallet exports and the only key material the deriver ever holds (TZ 5.1).
TEST_ACCOUNT_XPUB = (
    "xpub6DCoCpSuQZB2jawqnGMEPS63ePKWkwWPH4TU45Q7LPXWuNd8TMtVxRrgjtEsh"
    "uqpK3mdhaWHPFsBngh5GFZaM6si3yZdUsT8ddYM3PwnATt"
)

TEST_ACCOUNT_FINGERPRINT = "60b68b69"

#: m/44'/60'/0'/0/0 .. /4, EIP-55 checksummed.
EXPECTED_FIRST_FIVE = [
    "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
    "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
    "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A",
    "0xF3f50213C1d2e255e4B2bAD430F8A38EEF8D718E",
    "0x51cA8ff9f1C0a99f88E86B8112eA3237F55374cA",
]


# --------------------------------------------------------------------------
# Independent reimplementation. Shares no code with deriver.derivation.
# --------------------------------------------------------------------------

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_MAINNET_PUBLIC_VERSION = bytes.fromhex("0488b21e")


def _base58check_decode(value: str) -> bytes:
    number = 0
    for char in value:
        number = number * 58 + _BASE58_ALPHABET.index(char)
    raw = number.to_bytes(82, "big")
    payload, checksum = raw[:-4], raw[-4:]
    assert hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum
    return payload


def _ckd_pub(parent_key: bytes, parent_chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    """CKDpub from BIP-32, written out directly from the specification."""
    assert index < 2**31, "hardened derivation is impossible from a public key"
    digest = hmac_mod.new(
        parent_chain_code, parent_key + index.to_bytes(4, "big"), hashlib.sha512
    ).digest()
    tweak, child_chain_code = digest[:32], digest[32:]
    assert 0 < int.from_bytes(tweak, "big") < _SECP256K1_ORDER
    child_point = PublicKey.from_valid_secret(tweak).combine([PublicKey(parent_key)])
    return child_point.format(compressed=True), child_chain_code


def _to_eip55(address_bytes: bytes) -> str:
    """keccak256(pubkey[1:])[-20:] rendered with EIP-55 checksum casing."""
    lowercase = address_bytes.hex()
    digest = keccak.new(digest_bits=256)
    digest.update(lowercase.encode("ascii"))
    checksum = digest.hexdigest()
    return "0x" + "".join(
        char.upper() if char.isalpha() and int(checksum[i], 16) >= 8 else char
        for i, char in enumerate(lowercase)
    )


def independently_derive(account_xpub: str, count: int) -> list[str]:
    """Full TZ 5.1 pipeline without touching ``deriver`` or ``bip_utils``."""
    payload = _base58check_decode(account_xpub)
    assert payload[:4] == _MAINNET_PUBLIC_VERSION, "not a mainnet xpub"
    assert payload[4] == 3, "account-level key must be at depth 3 (m/44'/60'/0')"
    chain_code, key = payload[13:45], payload[45:78]

    change_key, change_chain_code = _ckd_pub(key, chain_code, 0)

    addresses = []
    for index in range(count):
        child_key, _ = _ckd_pub(change_key, change_chain_code, index)
        uncompressed = PublicKey(child_key).format(compressed=False)
        digest = keccak.new(digest_bits=256)
        digest.update(uncompressed[1:])  # drop the 0x04 prefix byte
        addresses.append(_to_eip55(digest.digest()[-20:]))
    return addresses


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


def test_test_mnemonic_produces_the_published_bip39_seed() -> None:
    """Anchors the whole file to a published vector rather than to our output."""
    seed = Bip39SeedGenerator(TEST_MNEMONIC).Generate()

    assert seed.hex() == TEST_SEED_HEX


def test_account_xpub_is_reproducible_from_the_test_mnemonic() -> None:
    """The pinned xpub really is m/44'/60'/0' of the published test seed.

    Without this, ``TEST_ACCOUNT_XPUB`` would be an unexplained magic string
    and the reader would have to take on trust that it corresponds to a
    throwaway key rather than to something real.
    """
    seed = bytes.fromhex(TEST_SEED_HEX)
    account = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM).Purpose().Coin().Account(0)

    assert account.PublicKey().ToExtended() == TEST_ACCOUNT_XPUB
    assert account.IsPublicOnly() is False  # the seed path does hold a private key...


def test_the_deriver_only_ever_sees_the_public_half() -> None:
    """...but what reaches the deriver is public-only, and it stays that way."""
    context = Bip44.FromExtendedKey(TEST_ACCOUNT_XPUB, Bip44Coins.ETHEREUM)

    assert context.IsPublicOnly() is True


@pytest.mark.parametrize(("index", "expected"), list(enumerate(EXPECTED_FIRST_FIVE)))
def test_first_five_addresses_match_the_control_values(index: int, expected: str) -> None:
    """The Week 1 gate: five addresses, character for character (TZ 5.1)."""
    assert derive_address(TEST_ACCOUNT_XPUB, index) == expected


def test_production_path_agrees_with_the_independent_implementation() -> None:
    """Two implementations sharing no code must produce identical addresses.

    This is the assertion that actually carries weight. The hardcoded constants
    above could in principle have been copied from a buggy run; an independent
    derivation from the same xpub could not reproduce them if they were wrong.
    """
    independent = independently_derive(TEST_ACCOUNT_XPUB, len(EXPECTED_FIRST_FIVE))

    assert independent == EXPECTED_FIRST_FIVE
    assert independent == [derive_address(TEST_ACCOUNT_XPUB, i) for i in range(5)]


def test_batch_derivation_matches_single_derivation() -> None:
    """``derive_addresses`` parses the xpub once; that must not change results."""
    batch = derive_addresses(TEST_ACCOUNT_XPUB, 0, 5)

    assert [item.address for item in batch] == EXPECTED_FIRST_FIVE
    assert [item.derivation_index for item in batch] == [0, 1, 2, 3, 4]
    assert {item.account_fingerprint for item in batch} == {TEST_ACCOUNT_FINGERPRINT}


def test_batch_derivation_from_an_offset() -> None:
    offset = derive_addresses(TEST_ACCOUNT_XPUB, 3, 2)

    assert [item.address for item in offset] == EXPECTED_FIRST_FIVE[3:5]
    assert [item.derivation_index for item in offset] == [3, 4]


def test_addresses_are_eip55_checksummed_not_lowercase() -> None:
    """Mixed case is the checksum (EIP-55), and TZ 3.1 requires it in the UI.

    A lowercase address is not "the same address, formatted differently" — it
    is an address with its typo protection stripped off.
    """
    addresses = [derive_address(TEST_ACCOUNT_XPUB, i) for i in range(5)]

    assert any(char.isupper() for address in addresses for char in address[2:])
    for address in addresses:
        assert address.startswith("0x")
        assert len(address) == 42


def test_account_fingerprint_matches_the_hardware_wallet_value() -> None:
    """Four bytes, lowercase hex — the format `hd_accounts.xpub_fingerprint` holds."""
    fingerprint = account_fingerprint(TEST_ACCOUNT_XPUB)

    assert fingerprint == TEST_ACCOUNT_FINGERPRINT
    assert len(fingerprint) == 8
    assert fingerprint == fingerprint.lower()


def test_derivation_is_deterministic_across_calls() -> None:
    """Same index, same address, forever — otherwise invoices cannot be reissued."""
    assert derive_address(TEST_ACCOUNT_XPUB, 7) == derive_address(TEST_ACCOUNT_XPUB, 7)


def test_distinct_indexes_give_distinct_addresses() -> None:
    """Two invoices must never collide on an address (TZ 5.3 relies on this)."""
    addresses = [derive_address(TEST_ACCOUNT_XPUB, i) for i in range(64)]

    assert len(set(addresses)) == 64
