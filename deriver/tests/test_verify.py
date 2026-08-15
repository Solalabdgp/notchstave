"""`Deriver.verify` — countermeasure 1.1 against address substitution (TZ 5.8/T1).

The threat being tested is the one ranked first in the model: an attacker who
reaches the database but not the host runs
``UPDATE invoices SET address = '0xAttacker'``. The user pays, the money is
gone, and the watcher never even notices — it listens on
``receive_addresses``, not on ``invoices``. The invoice simply hangs and the
user blames the bot.

``verify`` removes the possibility of *declaring* an address. After it, an
address can only be *derived*, so a tampered row stops being silent.
"""

from __future__ import annotations

import pytest

from deriver.derivation import DerivationError, IndexOutOfRange, addresses_equal
from deriver.service import Deriver, UnknownHDAccount
from deriver.tests.test_account_addresses import (
    EXPECTED_FIRST_FIVE,
    TEST_ACCOUNT_FINGERPRINT,
    TEST_ACCOUNT_XPUB,
)

HD_ACCOUNT_ID = 1


@pytest.fixture()
def deriver() -> Deriver:
    return Deriver({HD_ACCOUNT_ID: TEST_ACCOUNT_XPUB})


def test_verify_accepts_a_correctly_derived_address(deriver: Deriver) -> None:
    for index, address in enumerate(EXPECTED_FIRST_FIVE):
        assert deriver.verify(address, HD_ACCOUNT_ID, index) is True


def test_verify_rejects_an_attacker_supplied_address(deriver: Deriver) -> None:
    """The T1 vector-1 scenario, reduced to one assertion."""
    attacker_address = "0x00000000000000000000000000000000DeaDBeef"

    assert deriver.verify(attacker_address, HD_ACCOUNT_ID, 0) is False


def test_verify_rejects_a_valid_address_at_the_wrong_index(deriver: Deriver) -> None:
    """Vector 4 of T1: not an attack, a bug — an off-by-one on the index.

    The consequence is identical to the attack (the user pays an address the
    invoice does not watch), so the defence has to be identical too.
    """
    assert deriver.verify(EXPECTED_FIRST_FIVE[1], HD_ACCOUNT_ID, 0) is False
    assert deriver.verify(EXPECTED_FIRST_FIVE[0], HD_ACCOUNT_ID, 1) is False


def test_verify_rejects_a_case_mangled_address(deriver: Deriver) -> None:
    """In EIP-55 the casing is a checksum, so a re-cased address is corrupt.

    Accepting it would mean the comparison silently tolerates exactly the kind
    of mutation a broken serialisation layer introduces.
    """
    correct = EXPECTED_FIRST_FIVE[0]

    assert deriver.verify(correct.lower(), HD_ACCOUNT_ID, 0) is False
    assert deriver.verify("0x" + correct[2:].upper(), HD_ACCOUNT_ID, 0) is False


def test_verify_rejects_a_single_character_change(deriver: Deriver) -> None:
    """A homoglyph-style substitution, the realistic form of a tampered row."""
    correct = EXPECTED_FIRST_FIVE[0]
    tampered = correct[:-1] + ("5" if correct[-1] != "5" else "6")

    assert deriver.verify(tampered, HD_ACCOUNT_ID, 0) is False


@pytest.mark.parametrize("junk", ["", "0x", "not-an-address", "0x123", None, 42, b"bytes"])
def test_verify_rejects_malformed_input_without_raising(deriver: Deriver, junk: object) -> None:
    """Garbage in the address slot is a mismatch, never an exception.

    The caller's contract is "False means suspected compromise". A TypeError
    escaping from here would be caught by some generic handler upstream and
    could turn a substitution attempt into a retry loop.
    """
    assert deriver.verify(junk, HD_ACCOUNT_ID, 0) is False  # type: ignore[arg-type]


def test_verify_raises_on_an_unknown_account(deriver: Deriver) -> None:
    """A malformed *question* must raise, not return False.

    Returning False for "I have no key for that account" would let a caller
    treat a configuration error as a detected attack, and — worse — a future
    caller might read the False as "address is wrong, derive a new one".
    """
    with pytest.raises(UnknownHDAccount):
        deriver.verify(EXPECTED_FIRST_FIVE[0], 999, 0)


def test_verify_raises_on_an_out_of_range_index(deriver: Deriver) -> None:
    with pytest.raises(IndexOutOfRange):
        deriver.verify(EXPECTED_FIRST_FIVE[0], HD_ACCOUNT_ID, 2**31)
    with pytest.raises(IndexOutOfRange):
        deriver.verify(EXPECTED_FIRST_FIVE[0], HD_ACCOUNT_ID, -1)


def test_addresses_equal_is_exact() -> None:
    address = EXPECTED_FIRST_FIVE[0]

    assert addresses_equal(address, address) is True
    assert addresses_equal(address, address.lower()) is False
    assert addresses_equal(address, address + " ") is False
    assert addresses_equal(address, "") is False


def test_deriver_exposes_the_fingerprint_for_the_derivation_proof(deriver: Deriver) -> None:
    assert deriver.fingerprint(HD_ACCOUNT_ID) == TEST_ACCOUNT_FINGERPRINT


def test_derivation_proof_is_reproducible_and_key_free(deriver: Deriver) -> None:
    """TZ 5.8/T1.4: fingerprint + path + address, and nothing that can spend."""
    proof = deriver.derivation_proof(HD_ACCOUNT_ID, 3, "m/44'/60'/0'")

    assert proof == {
        "xpub_fingerprint": TEST_ACCOUNT_FINGERPRINT,
        "derivation_path": "m/44'/60'/0'/0/3",
        "address": EXPECTED_FIRST_FIVE[3],
        "derivation_index": 3,
    }
    assert TEST_ACCOUNT_XPUB not in str(proof)


def test_derivation_proof_accepts_the_sql_escaped_path_prefix(deriver: Deriver) -> None:
    """`hd_accounts.path_prefix` is stored SQL-escaped (core.db.base)."""
    proof = deriver.derivation_proof(HD_ACCOUNT_ID, 0, "m/44''/60''/0''")

    assert proof["derivation_path"] == "m/44'/60'/0'/0/0"


def test_multiple_accounts_do_not_bleed_into_each_other() -> None:
    """Rotation after an xpub leak means two accounts coexist (TZ 5.8/T4).

    Deriving invoice addresses from the wrong one would produce perfectly valid
    addresses that the owner cannot sweep, so the isolation is load-bearing.
    """
    other_xpub = (
        "xpub6C7LtZJgtz3K4yQe1UNyeqZgKm5xnT2xN4CjxCn1qLNhr8XvNFyLKgqBnGH9M"
        "sCUMWzXhMk1M8sNKZvUgvVJpqMxHYPCr4nrqDsPZWNwBQK"
    )
    with pytest.raises(DerivationError):
        # A deliberately invalid second key must be rejected at construction,
        # not silently accepted and used later.
        Deriver({1: TEST_ACCOUNT_XPUB, 2: other_xpub})
