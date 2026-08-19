"""What a message that is not a command is probably about.

TZ 3.1 gives the bot seven commands and one support burden: *"что делать, если
отправил не туда, не столько или не тем токеном (важнее, чем кажется: половина
обращений в поддержку — это)"*. The messages that arrive alongside that burden
are not commands. They are a pasted transaction hash, a pasted address, an
invoice id copied out of an earlier message, or a sku typed without the
``/buy``. Answering all four with "unknown command, try /help" is how a payment
question becomes a support ticket.

So the free-text path classifies by shape and routes to the handler the person
almost certainly wanted. It is a convenience and is treated as one: every branch
ends in the same place the corresponding command would, with the same ownership
filter and the same refusals. Nothing here grants anything, and nothing here
is reachable without the classification being *certain* — an ambiguous string
gets the help text rather than a guess, because a guess that runs ``/buy`` on a
mistyped sku costs somebody an invoice out of their quota.

**Why the shapes do not overlap.** An EVM address is exactly 42 characters
starting ``0x``, a transaction hash is exactly 66, and a UUID has hyphens in
fixed places. The three cannot be confused with each other or with a sku, which
is why the classifier can be a regex table and not a scoring function. A sku is
the residual category and is therefore the one that must be checked against the
catalogue before anything happens — which the handler does, rather than this
module, because "is this a real sku" is a database question and this module
takes no arguments it cannot see.
"""

from __future__ import annotations

import enum
import re
import uuid
from dataclasses import dataclass

__all__ = ["InputKind", "Detected", "classify", "parse_invoice_id"]

#: EIP-55 checksummed or not — the case is not part of the shape, and telling a
#: user "that is not a valid address" because they lower-cased it would be
#: pedantry about a value this module only classifies and never uses.
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_TX_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
#: ``products.sku`` is ``String(64)``; the character class is what a sku can
#: contain without needing quoting in a chat message.
_SKU = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class InputKind(enum.StrEnum):
    ADDRESS = "address"
    TX_HASH = "tx_hash"
    INVOICE_ID = "invoice_id"
    SKU = "sku"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Detected:
    kind: InputKind
    #: The cleaned token — trimmed, and for a UUID normalised to its canonical
    #: lowercase hyphenated form so the handler does not have to re-parse it.
    value: str


def classify(text: str) -> Detected:
    """One line of free text to a shape. Never raises, never guesses.

    Order matters only between the two ``0x`` forms, and they are distinguished
    by length rather than by which pattern is tried first — stated as two
    anchored regexes so that neither can shadow the other if this list is ever
    reordered.
    """
    token = text.strip()
    # A single pasted value is the whole case this handles. Two words is a
    # sentence, and a sentence is a support question, not an identifier.
    if not token or len(token.split()) > 1:
        return Detected(InputKind.UNKNOWN, token)

    if _TX_HASH.match(token):
        return Detected(InputKind.TX_HASH, token)
    if _ADDRESS.match(token):
        return Detected(InputKind.ADDRESS, token)
    if _UUID.match(token):
        return Detected(InputKind.INVOICE_ID, str(uuid.UUID(token)))
    if _SKU.match(token):
        return Detected(InputKind.SKU, token)
    return Detected(InputKind.UNKNOWN, token)


def parse_invoice_id(text: str) -> uuid.UUID | None:
    """``None`` rather than a raised ``ValueError`` for a malformed id.

    Every caller is a handler whose next line is "tell the user it is not an
    invoice id", so an exception here would be caught and discarded at every
    call site. Returning ``None`` makes the "not an id" branch the visible one.
    """
    token = text.strip()
    if not _UUID.match(token):
        return None
    return uuid.UUID(token)
