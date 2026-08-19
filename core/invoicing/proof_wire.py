"""What a derivation proof *is*: the triple, its MAC, and its wire form.

Split out of :mod:`core.invoicing.proof`, and the split is a boundary rather
than a tidying-up.

**Who imports which half.** The deriver *produces* proofs — it is the only
process holding the account xpub, so it is the only one that can derive an
address rather than declare one (TZ 5.8/T1.4). Its composition root,
:mod:`core.invoicing.issuer`, therefore needs the dataclass, the MAC and the
encoder, and needs nothing at all of the queue client that asks for a proof: the
deriver answers requests, it never makes one. The bot and the api are the
mirror image — they need :class:`~core.invoicing.proof.ProofClient` and get the
definitions below through it.

**Why that is worth a file.** ``ProofClient`` parks a thread on a socket
(``asyncio.to_thread``), so :mod:`core.invoicing.proof` imports ``asyncio``, so
``asyncio`` would be in the import closure of the process that holds the xpub.
TZ 5.8/T4 is the claim that that process has no way to reach a network, and
``deriver/tests/test_isolation.py`` walks the closure from the composition root
and enforces it — including through ``core``, and deliberately without an
exemption list. Its docstring says what to do when a module in the closure
genuinely needs a forbidden import: *keep it out of the closure*. This file is
that, done once, at the seam the two halves already had.

A function-level ``import asyncio`` would have silenced the test's AST walk
while leaving the capability exactly where it was, which is worse than the
problem: the guarantee would then depend on nobody ever calling the function.

Nothing here can reach anything. ``uuid``, ``dataclasses``, and the HMAC helper
from :mod:`core.invoicing.integrity` — no driver, no socket, no event loop.

The MAC's tuple, and why it is not the invoice's
------------------------------------------------

``(invoice_id, xpub_fingerprint, derivation_path, address)`` under the domain
tag ``notchstave/derivation-proof/v1``. A separate tag under the same key, which
is the whole reason :func:`core.invoicing.integrity.framed` takes one: two
claims signed with one key and one encoding are only distinguishable if the
encoding separates them. Without the tag a captured invoice MAC and a captured
proof MAC would live in the same space, and "this address is proven at this
path" could be replayed from "this address is billed for this amount".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from core.invoicing.integrity import IntegrityKey, framed

__all__ = [
    "PROOF_DOMAIN_TAG",
    "PROOF_WIRE_VERSION",
    "DerivationProof",
    "ProofWireError",
    "compute_proof_mac",
    "verify_proof_mac",
    "to_wire",
    "from_wire",
]

#: Domain separation for the proof MAC. The version digit is part of the tag so
#: that changing the tuple later invalidates every proof at once and visibly,
#: rather than letting old and new proofs verify under subtly different rules.
PROOF_DOMAIN_TAG = b"notchstave/derivation-proof/v1"

PROOF_WIRE_VERSION = 1


class ProofWireError(ValueError):
    """A reply that is not this format. Never a partial decode."""


@dataclass(frozen=True, slots=True)
class DerivationProof:
    """The publishable triple of TZ 5.8/T1.4, plus what makes it checkable.

    Contains no key material by construction: a fingerprint is four bytes of a
    hash of a public key, a path is public structure, and the address is already
    on a public ledger. That is exactly why this can be sent over Telegram while
    the xpub it comes from cannot.
    """

    invoice_id: uuid.UUID
    #: Lowercase hex, matching ``hd_accounts.xpub_fingerprint`` and what a
    #: hardware wallet shows on its screen.
    xpub_fingerprint: str
    #: The full path, e.g. ``m/44'/60'/0'/0/17`` — prefix plus the external
    #: chain plus the index, not just the index, so it can be pasted whole.
    derivation_path: str
    derivation_index: int
    #: EIP-55 checksum form, character for character what the buyer was shown.
    address: str
    #: HMAC over the four fields above under :data:`PROOF_DOMAIN_TAG`.
    proof_mac: bytes


def _canonical_payload(
    *, invoice_id: uuid.UUID, xpub_fingerprint: str, derivation_path: str, address: str
) -> bytes:
    """The exact bytes the proof MAC is taken over.

    Keyword-only, and the reason is the one :func:`core.invoicing.integrity
    .canonical_payload` gives: three of the four fields are strings, and a
    positional call site that swapped the path and the address would produce
    MACs that verify perfectly against each other while authenticating nonsense.
    """
    return framed(
        PROOF_DOMAIN_TAG,
        invoice_id.bytes,
        xpub_fingerprint.encode("ascii"),
        derivation_path.encode("ascii"),
        address.encode("utf-8"),
    )


def compute_proof_mac(
    key: IntegrityKey,
    *,
    invoice_id: uuid.UUID,
    xpub_fingerprint: str,
    derivation_path: str,
    address: str,
) -> bytes:
    return key.mac(
        _canonical_payload(
            invoice_id=invoice_id,
            xpub_fingerprint=xpub_fingerprint,
            derivation_path=derivation_path,
            address=address,
        )
    )


def verify_proof_mac(key: IntegrityKey, proof: DerivationProof) -> bool:
    """Recompute and compare in constant time. Never raises on a mismatch."""
    return key.verify(
        _canonical_payload(
            invoice_id=proof.invoice_id,
            xpub_fingerprint=proof.xpub_fingerprint,
            derivation_path=proof.derivation_path,
            address=proof.address,
        ),
        proof.proof_mac,
    )


def to_wire(proof: DerivationProof) -> dict[str, Any]:
    return {
        "v": PROOF_WIRE_VERSION,
        "invoice_id": str(proof.invoice_id),
        "xpub_fingerprint": proof.xpub_fingerprint,
        "derivation_path": proof.derivation_path,
        "derivation_index": proof.derivation_index,
        "address": proof.address,
        "proof_mac": proof.proof_mac.hex(),
    }


def from_wire(payload: dict[str, Any]) -> DerivationProof:
    """Decode a reply. Raises :class:`ProofWireError` rather than guessing."""
    try:
        version = int(payload["v"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProofWireError("reply carries no wire version") from exc
    if version != PROOF_WIRE_VERSION:
        raise ProofWireError(
            f"reply is proof wire v{version}, this build speaks v{PROOF_WIRE_VERSION}"
        )
    try:
        return DerivationProof(
            invoice_id=uuid.UUID(str(payload["invoice_id"])),
            xpub_fingerprint=str(payload["xpub_fingerprint"]),
            derivation_path=str(payload["derivation_path"]),
            derivation_index=int(payload["derivation_index"]),
            address=str(payload["address"]),
            proof_mac=bytes.fromhex(str(payload["proof_mac"])),
        )
    except ProofWireError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ProofWireError(f"malformed proof reply: {exc}") from exc
