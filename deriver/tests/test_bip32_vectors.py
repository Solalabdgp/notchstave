"""Official BIP-32 test vectors — key-level correctness of the derivation stack.

TZ 5.1, "Чем реализуем": *"Обязательный тест — сверка по эталонным тестовым
векторам BIP-32"*. This file is that check.

**Source of the expected values.** The BIP-32 specification itself:
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki, section
"Test Vectors", fetched 2026-08-15. The strings below are copied from that
document verbatim; they are not produced by any tool in this repository, which
is the entire point — a vector that our own code generated would only prove
self-consistency.

**What is actually being tested.** Only the non-hardened steps of the published
chains, because those are the only ones reachable from an extended *public*
key — and they are also the only ones Notchstave ever performs (``/0/i`` below
the account level, TZ 5.1). Concretely this exercises CKDpub: HMAC-SHA512 over
the parent chain code, the scalar-to-point addition, and the serialisation of
the resulting extended key. A silent error in any of those is the failure mode
TZ 5.1 warns about — it does not raise, it yields an address whose private key
does not exist.

The hardened steps of the same vectors are used in reverse: they must be
*impossible* from a public key. That impossibility is not an inconvenience, it
is the property the entire custody model rests on (TZ 5.1, 5.8/T4).
"""

from __future__ import annotations

import pytest
from bip_utils import Bip32KeyIndex, Bip32Slip10Secp256k1

# --------------------------------------------------------------------------
# (parent chain, parent ext pub, non-hardened child index, expected child ext pub)
# Verbatim from bip-0032.mediawiki, "Test Vectors".
# --------------------------------------------------------------------------
CKDPUB_VECTORS = [
    pytest.param(
        "vector1: m/0H -> m/0H/1",
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        1,
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        id="v1-m0H-1",
    ),
    pytest.param(
        "vector1: m/0H/1/2H -> m/0H/1/2H/2",
        "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
        2,
        "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
        id="v1-m0H1-2H-2",
    ),
    pytest.param(
        # The largest non-hardened index in the published vectors: 1000000000
        # sits just below the 2**31 hardening boundary, so it also pins down
        # that we are not accidentally setting the hardening bit.
        "vector1: m/0H/1/2H/2 -> m/0H/1/2H/2/1000000000",
        "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
        1000000000,
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
        id="v1-deep-1000000000",
    ),
    pytest.param(
        "vector2: m -> m/0",
        "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        0,
        "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        id="v2-m-0",
    ),
    pytest.param(
        "vector2: m/0/2147483647H -> m/0/2147483647H/1",
        "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
        1,
        "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
        id="v2-m0-2147483647H-1",
    ),
    pytest.param(
        "vector2: m/0/2147483647H/1/2147483646H -> .../2",
        "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        2,
        "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
        id="v2-deep-2",
    ),
]

#: Master extended public keys from vectors 1-4, used for round-trip and
#: hardening-refusal checks.
MASTER_XPUBS = [
    pytest.param(
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        id="vector1",
    ),
    pytest.param(
        "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        id="vector2",
    ),
    pytest.param(
        "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
        id="vector3",
    ),
    pytest.param(
        "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
        id="vector4",
    ),
]


@pytest.mark.parametrize(("label", "parent_xpub", "index", "expected_child_xpub"), CKDPUB_VECTORS)
def test_ckdpub_matches_bip32_specification(
    label: str, parent_xpub: str, index: int, expected_child_xpub: str
) -> None:
    """Non-hardened public derivation reproduces the spec's extended key exactly."""
    parent = Bip32Slip10Secp256k1.FromExtendedKey(parent_xpub)
    assert parent.IsPublicOnly(), f"{label}: parent must be watch-only"

    child = parent.ChildKey(index)

    assert child.PublicKey().ToExtended() == expected_child_xpub, label


@pytest.mark.parametrize(("label", "parent_xpub", "index", "expected_child_xpub"), CKDPUB_VECTORS)
def test_derived_child_is_still_public_only(
    label: str, parent_xpub: str, index: int, expected_child_xpub: str
) -> None:
    """Deriving from a watch-only key can never produce a spendable one.

    Stated as a test rather than assumed, because "the child somehow has a
    private key" is exactly the kind of regression that would invalidate the
    project's central claim without breaking any address.
    """
    child = Bip32Slip10Secp256k1.FromExtendedKey(parent_xpub).ChildKey(index)

    assert child.IsPublicOnly() is True, label
    with pytest.raises(Exception):
        child.PrivateKey()


@pytest.mark.parametrize("master_xpub", MASTER_XPUBS)
def test_hardened_derivation_from_public_key_is_impossible(master_xpub: str) -> None:
    """The property the whole custody model rests on (TZ 5.1, 5.8/T4).

    Hardened derivation needs the parent *private* key by construction. If this
    ever stopped raising, it would mean the library had been handed key
    material it should not have.
    """
    ctx = Bip32Slip10Secp256k1.FromExtendedKey(master_xpub)

    for hardened_index in (0, 1, 2147483647):
        with pytest.raises(Exception):
            ctx.ChildKey(Bip32KeyIndex.HardenIndex(hardened_index))


@pytest.mark.parametrize("master_xpub", MASTER_XPUBS)
def test_extended_key_serialisation_round_trips(master_xpub: str) -> None:
    """Parse -> re-serialise must be the identity.

    Catches a whole class of silent corruption (depth, parent fingerprint or
    chain code lost in translation) that would not show up as an exception but
    would change every address derived afterwards.
    """
    ctx = Bip32Slip10Secp256k1.FromExtendedKey(master_xpub)

    assert ctx.PublicKey().ToExtended() == master_xpub


def test_a_tampered_vector_does_not_pass() -> None:
    """Sanity check on the test itself.

    A comparison that passes no matter what is worse than no comparison. This
    proves the assertions above can actually fail.
    """
    _, parent_xpub, index, expected = (
        CKDPUB_VECTORS[0].values[0],
        CKDPUB_VECTORS[0].values[1],
        CKDPUB_VECTORS[0].values[2],
        CKDPUB_VECTORS[0].values[3],
    )
    child = Bip32Slip10Secp256k1.FromExtendedKey(parent_xpub).ChildKey(index + 1)

    assert child.PublicKey().ToExtended() != expected
