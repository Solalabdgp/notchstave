"""BIP-32/BIP-44 address derivation from an account-level extended PUBLIC key.

This module is the whole technical argument of Notchstave (TZ 5.1). Everything
it can do is: take an account-level xpub at ``m/44'/60'/<account>'`` and produce
the address at ``m/44'/60'/<account>'/0/<index>``. There is deliberately no
function here that signs, that reads a private key, or that could be extended
into one without the reviewer noticing.

The pipeline, straight out of TZ 5.1:

    child public key -> uncompressed form -> keccak256(pubkey[1:])
                     -> last 20 bytes -> EIP-55 checksum

Three properties this module enforces rather than assumes:

1. **Private key material is refused at the door.** ``bip_utils`` will happily
   accept an ``xprv`` in :meth:`Bip44.FromExtendedKey` and hand back an object
   with ``IsPublicOnly() == False`` — verified against 2.12.2, it does not raise.
   So the guard has to be ours: the serialization prefix is checked before the
   string is handed to the library, and ``IsPublicOnly()`` is asserted after.
   A key that is not a watch-only mainnet xpub never reaches derivation code.
2. **Only the account level is accepted.** ``m/44'/60'/0'`` and nothing else —
   a master xpub would expose every account of every coin at once (TZ 5.1 rule 2,
   5.8/T4). ``bip_utils`` happens to reject a public-only master key for BIP-44
   itself, but we assert the level explicitly instead of relying on that.
3. **No key material ever reaches a string.** Every exception raised here is
   built from constants and integers. Nothing formats the xpub into a message,
   a repr, or a traceback (TZ 5.8/T4). :mod:`deriver.redaction` is the second
   line of defence, not the first.

Why ``bip_utils`` and not hand-rolled curve math: TZ 5.1, "свой велосипед на
этом месте писать нельзя категорически" — a bug in point arithmetic does not
raise, it silently yields an address whose private key does not exist, and the
money is gone. The library is pinned in ``deriver/pyproject.toml`` and its
output is checked against the official BIP-32 test vectors in
``tests/test_bip32_vectors.py``.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass

from bip_utils import Bip44, Bip44Changes, Bip44Coins, Bip44Levels

__all__ = [
    "DerivationError",
    "PrivateKeyMaterialRejected",
    "NotAnAccountXpub",
    "IndexOutOfRange",
    "DerivedAddress",
    "derive_address",
    "derive_addresses",
    "account_fingerprint",
    "derivation_path",
    "addresses_equal",
    "EXTERNAL_CHAIN_INDEX",
    "MAX_NON_HARDENED_INDEX",
]

#: BIP-44 external chain. Notchstave never derives the internal/change chain:
#: it has no change to receive, only payments (TZ 5.1).
EXTERNAL_CHAIN_INDEX = 0

#: Non-hardened index space. 2**31 is where hardened derivation starts, and
#: hardened derivation from a public key is impossible by construction — which
#: is precisely the property the whole custody model rests on.
MAX_NON_HARDENED_INDEX = 2**31 - 1

#: Mainnet BIP-32 public serialization (version bytes 0x0488B21E) renders as the
#: ASCII prefix "xpub". ypub/zpub are SLIP-132 variants for segwit Bitcoin and
#: are not valid input here — accepting them would mean silently deriving from a
#: key whose intended script type is not what this code produces.
_XPUB_PREFIX = "xpub"

#: Shape check only — cheap, no crypto, no decoding. Real validation is the
#: library's base58 checksum. A mainnet extended key serializes to 111 or 112
#: base58 characters; the bound is loose on purpose so that a genuine key is
#: never rejected by our own arithmetic.
_XPUB_SHAPE = re.compile(r"\Axpub[1-9A-HJ-NP-Za-km-z]{95,120}\Z")


class DerivationError(Exception):
    """Base class. No subclass ever carries key material in its message."""


class PrivateKeyMaterialRejected(DerivationError):
    """The supplied key was not a watch-only public key.

    This is a security event, not a validation nit: the deriver is the process
    that is supposed to make "a private key cannot exist here" mechanically
    true (TZ 5.1). Something upstream handing it an ``xprv`` means either a
    misconfigured credential or an attempt to weaken the custody model, and
    either way the process must refuse rather than quietly cope.
    """


class NotAnAccountXpub(DerivationError):
    """The key parsed, but is not at account level ``m/44'/60'/<account>'``."""


class IndexOutOfRange(DerivationError):
    """Derivation index outside the non-hardened range."""


@dataclass(frozen=True, slots=True)
class DerivedAddress:
    """One derived receive address plus everything needed to reproduce it.

    This is exactly the payload of the derivation proof in TZ 5.8/T1.4: with
    the fingerprint and the path, the owner can rebuild the address in any
    third-party tool without asking the bot. It carries no key material.
    """

    derivation_index: int
    address: str
    #: 4-byte BIP-32 fingerprint of the ACCOUNT key, lowercase hex — the same
    #: value a hardware wallet displays, and what `hd_accounts.xpub_fingerprint`
    #: stores (matches core.db.base.FINGERPRINT_RE).
    account_fingerprint: str


def _load_account(account_xpub: str) -> Bip44:
    """Parse and validate an account-level xpub. Never echoes its input.

    Order matters. The prefix check happens first so that a private extended
    key is rejected before it is handed to a library that would build a signing
    context out of it.
    """
    if not isinstance(account_xpub, str):
        raise PrivateKeyMaterialRejected(
            "extended key must be a string; refusing to derive from "
            f"{type(account_xpub).__name__}"
        )

    stripped = account_xpub.strip()
    if not stripped.startswith(_XPUB_PREFIX):
        # Deliberately does not quote the offending value. The four leading
        # characters are enough to debug with and cannot reconstruct a key.
        raise PrivateKeyMaterialRejected(
            "extended key does not start with 'xpub' (got prefix "
            f"{stripped[:4]!r}); only mainnet watch-only account keys are accepted"
        )
    if not _XPUB_SHAPE.match(stripped):
        raise NotAnAccountXpub("extended key is not a well-formed base58 xpub string")

    try:
        ctx = Bip44.FromExtendedKey(stripped, Bip44Coins.ETHEREUM)
    except Exception as exc:  # noqa: BLE001 - re-raised without the input
        # bip_utils raises several distinct types (Bip32KeyError, Base58ChecksumError,
        # Bip44DepthError...). Collapsing them keeps the offending string out of
        # any traceback: `raise ... from exc` would chain the original message,
        # which for some of these includes the key. The class name is kept for
        # debuggability.
        raise NotAnAccountXpub(
            f"extended key rejected by bip_utils ({type(exc).__name__})"
        ) from None

    # Belt and braces: bip_utils 2.12.2 accepts an xprv here without raising and
    # simply reports IsPublicOnly() == False. Verified empirically, not assumed.
    if not ctx.IsPublicOnly():
        raise PrivateKeyMaterialRejected(
            "extended key carries private key material; the deriver never "
            "accepts a spendable key (TZ 5.1)"
        )
    if ctx.Level() != Bip44Levels.ACCOUNT:
        raise NotAnAccountXpub(
            "extended key is at level "
            f"{ctx.Level().name}; expected ACCOUNT, i.e. exported at m/44'/60'/<account>'"
        )
    return ctx


def _check_index(derivation_index: int) -> None:
    if isinstance(derivation_index, bool) or not isinstance(derivation_index, int):
        raise IndexOutOfRange(
            f"derivation index must be an int, got {type(derivation_index).__name__}"
        )
    if not 0 <= derivation_index <= MAX_NON_HARDENED_INDEX:
        raise IndexOutOfRange(
            f"derivation index {derivation_index} outside non-hardened range "
            f"0..{MAX_NON_HARDENED_INDEX}"
        )


def derive_address(account_xpub: str, derivation_index: int) -> str:
    """Return the EIP-55 checksummed address at ``<account>/0/<derivation_index>``.

    The single function the rest of the system depends on. Pure: same inputs,
    same output, no I/O, no clock, no database.
    """
    _check_index(derivation_index)
    ctx = _load_account(account_xpub)
    node = ctx.Change(Bip44Changes.CHAIN_EXT).AddressIndex(derivation_index)
    # bip_utils' Ethereum address encoder performs the full TZ 5.1 pipeline —
    # uncompressed point, keccak256 of the 64 body bytes, last 20, EIP-55 —
    # and tests/test_account_addresses.py re-implements it independently to
    # prove that claim rather than trust it.
    return node.PublicKey().ToAddress()


def derive_addresses(account_xpub: str, start_index: int, count: int) -> list[DerivedAddress]:
    """Derive ``count`` consecutive addresses, parsing the xpub only once.

    Used for gap-limit pre-derivation (TZ 5.1, p. 2): the pool is topped up in
    batches so that a hardware wallet restoring the account does not stop at
    20 empty addresses in a row.
    """
    if count < 0:
        raise IndexOutOfRange(f"count must be non-negative, got {count}")
    _check_index(start_index)
    if count:
        _check_index(start_index + count - 1)

    ctx = _load_account(account_xpub)
    fingerprint = _fingerprint_of(ctx)
    chain = ctx.Change(Bip44Changes.CHAIN_EXT)
    return [
        DerivedAddress(
            derivation_index=index,
            address=chain.AddressIndex(index).PublicKey().ToAddress(),
            account_fingerprint=fingerprint,
        )
        for index in range(start_index, start_index + count)
    ]


def _fingerprint_of(ctx: Bip44) -> str:
    return ctx.Bip32Object().PublicKey().FingerPrint().ToHex().lower()


def account_fingerprint(account_xpub: str) -> str:
    """4-byte BIP-32 fingerprint of the account key, lowercase hex.

    Stored in ``hd_accounts.xpub_fingerprint`` and published in the derivation
    proof (TZ 5.8/T1.4). It is a hash prefix, not key material: it cannot be
    used to derive anything, which is why it is safe to show a user while the
    xpub is not.
    """
    return _fingerprint_of(_load_account(account_xpub))


def derivation_path(path_prefix: str, derivation_index: int) -> str:
    """Full BIP-44 path string for the derivation proof, e.g. ``m/44'/60'/0'/0/7``.

    ``path_prefix`` comes from ``hd_accounts.path_prefix``. Note that the CHECK
    constraint in the database stores it SQL-escaped (``m/44''/60''/0''``, see
    ``core.db.base.BIP32_PATH_PREFIX_RE``); a doubled apostrophe is collapsed
    here so callers can pass either form.
    """
    _check_index(derivation_index)
    prefix = path_prefix.replace("''", "'").rstrip("/")
    return f"{prefix}/{EXTERNAL_CHAIN_INDEX}/{derivation_index}"


def addresses_equal(left: str, right: str) -> bool:
    """Byte-for-byte comparison of two EIP-55 addresses (TZ 5.8/T1.1).

    Case-sensitive on purpose. In EIP-55 the letter case *is* a checksum, so
    two strings that differ only in case are not "the same address written
    differently" — at least one of them is corrupt, and a comparison that
    shrugs that off would defeat the point of checksumming.

    Uses :func:`hmac.compare_digest`: address verification runs on the path
    where an attacker controls one side (a tampered ``invoices.address``), so
    there is no reason to leak a match prefix through timing.
    """
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
