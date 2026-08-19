"""``/verify <invoice_id>``: the derivation proof, and how it crosses the boundary.

TZ 5.8/T1.4 asks for three published values — the parent key's BIP-32
fingerprint, the full derivation path, and the address — so that whoever holds
the xpub can reproduce the address in any third-party tool and stop taking the
bot's word for it. *"Это превращает «поверь боту» в «проверь бота»."*

The limit is stated in the TZ and is restated in the copy the bot sends, because
leaving it out would turn an honest control into an advertisement: **a buyer
cannot build a full derivation proof.** They have no xpub and publishing one is
forbidden (T4). What the buyer gets from this command is the weaker check the TZ
describes — the same address in three independent channels — plus the knowledge
that the value came from the process that can *derive* rather than *declare*.

Why the proof is not assembled by the bot out of its own SELECTs
----------------------------------------------------------------

Everything in the triple is sitting in tables the bot can read:
``hd_accounts.xpub_fingerprint``, ``hd_accounts.path_prefix``,
``receive_addresses.derivation_index``, ``receive_addresses.address``. Printing
those four values would be one query and no new machinery.

It would also be worthless, and specifically worthless against the one attack it
is supposed to answer. Vector 1 of TZ 5.8/T1 is *"компрометация БД без
компрометации хоста"* — the attacker has UPDATE and nothing else. Under that
attacker, a proof built from SELECTs prints the attacker's address under the
heading "here is the cryptographic proof that this address is ours". The command
would have converted a lie into a more convincing lie.

So the proof is produced where the xpub is (:mod:`deriver.service`), through the
queue of migration 0008, and it carries its own MAC on the way back for the same
reason the invoice reply carries one: the transport is a table, the table is the
thing assumed to be compromised, and a bot with no xpub can only check a MAC
(TZ 5.8/T1.3).

What is here and what is next door
----------------------------------

This file is the *asking* half: the queue client, its channel names and its
refusal ladder. The proof itself — the dataclass, the MAC over
``(invoice_id, xpub_fingerprint, derivation_path, address)``, and the wire
encoding — lives in :mod:`core.invoicing.proof_wire`, and is re-exported from
here so that call sites need not care.

The split is not filing. ``ProofClient`` waits on a socket, so this module
imports ``asyncio``; the deriver *produces* proofs and therefore imports the
definitions, and TZ 5.8/T4 says the process holding the xpub has no way to reach
a network. Keeping the two apart is what lets both statements be true, and
``deriver/tests/test_isolation.py`` is what keeps them apart. The reasoning is
written out once, in ``proof_wire``.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg.rows import dict_row

from core.invoicing import errors as E
from core.invoicing.ids import uuid7
from core.invoicing.integrity import IntegrityKey
from core.invoicing.metrics import MAC_FAILURES

# Re-exported below so that every existing `from core.invoicing.proof import
# DerivationProof` keeps working. The definitions live next door because the
# deriver needs them and must not reach this file — see `proof_wire`'s module
# docstring for the isolation argument, which is the whole reason for the split.
from core.invoicing.proof_wire import (
    PROOF_DOMAIN_TAG,
    PROOF_WIRE_VERSION,
    DerivationProof,
    ProofWireError,
    compute_proof_mac,
    from_wire,
    to_wire,
    verify_proof_mac,
)

__all__ = [
    "CHANNEL_PROOFS",
    "PROOF_REPLY_PREFIX",
    "proof_reply_channel",
    "PROOF_DOMAIN_TAG",
    "PROOF_WIRE_VERSION",
    "DerivationProof",
    "ProofWireError",
    "compute_proof_mac",
    "verify_proof_mac",
    "to_wire",
    "from_wire",
    "ProofClient",
]

log = logging.getLogger("notchstave.invoicing.proof")

#: Must equal ``deriver.requests`` and migration 0008. Three copies of one
#: string, asserted equal by a test — see the note on ``CHANNEL_REQUESTS`` in
#: :mod:`core.invoicing.client` for why a drifted channel name is the worst kind
#: of bug: it does not fail, it goes slow.
CHANNEL_PROOFS = "notchstave_proof_requests"
PROOF_REPLY_PREFIX = "nsp_"


def proof_reply_channel(request_id: uuid.UUID) -> str:
    """The channel this proof request's reply will arrive on (migration 0008)."""
    return f"{PROOF_REPLY_PREFIX}{request_id.hex}"


#: Same generous deadline as the invoice round trip, for the same reason: the
#: expected cost is one ``NOTIFY`` hop plus a keccak, so anything near this
#: number means the deriver is down rather than busy.
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_RECHECK_SECONDS = 0.25

SQL_INSERT_REQUEST = """
INSERT INTO derivation_proof_requests (id, user_id, invoice_id)
VALUES (%(id)s, %(user_id)s, %(invoice_id)s)
"""

SQL_READ_REQUEST = """
SELECT status::text AS status, result_json, error_code, error_message
  FROM derivation_proof_requests
 WHERE id = %(id)s
"""

_ERROR_CLASSES: dict[str, type[E.InvoicingError]] = {
    name: cls
    for name in E.__all__
    if isinstance(cls := getattr(E, name), type) and issubclass(cls, E.InvoicingError)
}


@dataclass(frozen=True, slots=True)
class _Reply:
    status: str
    result_json: dict[str, Any] | None
    error_code: str | None
    error_message: str | None


class ProofClient:
    """Ask the deriver to prove one invoice's address. The ``/verify`` half.

    Shaped as a deliberate twin of :class:`core.invoicing.client.InvoiceClient`
    — same LISTEN-before-INSERT ordering, same "verified or raise, no third
    outcome" contract, same ``user_message`` on everything it raises. The twin
    is intentional: two round trips over one transport that behaved differently
    under a timeout or a corrupted reply would be two things to reason about,
    and the second one would be the one nobody re-read.
    """

    __slots__ = ("_dsn", "_key", "_timeout", "_recheck")

    def __init__(
        self,
        dsn: str,
        key: IntegrityKey,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        recheck_interval: float = DEFAULT_RECHECK_SECONDS,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._dsn = dsn
        self._key = key
        self._timeout = timeout
        self._recheck = min(recheck_interval, timeout)

    def request_proof(
        self,
        *,
        user_id: int,
        invoice_id: uuid.UUID,
        timeout: float | None = None,
    ) -> DerivationProof:
        """Ask, wait, verify, return. Blocks the calling thread.

        ``user_id`` is passed through to the deriver rather than being used to
        pre-filter here, and that is the IDOR rule of TZ 5.8/T1.7 landing where
        it can actually be enforced: the deriver loads the invoice with
        ``expected_user_id`` and answers :class:`~core.invoicing.errors
        .InvoiceNotFound` for somebody else's, which is the same answer a
        genuinely unknown id gets. A bot-side filter would be a second copy of
        the rule that a bug could skip.
        """
        deadline = time.monotonic() + (self._timeout if timeout is None else timeout)
        request_id = uuid7(dt.datetime.now(dt.UTC))

        with psycopg.connect(self._dsn, autocommit=True) as conn:
            conn.execute(f"LISTEN {proof_reply_channel(request_id)}")
            self._insert(conn, request_id, user_id, invoice_id)
            reply = self._wait(conn, request_id, deadline)

        return self._interpret(reply, request_id, invoice_id)

    async def arequest_proof(
        self,
        *,
        user_id: int,
        invoice_id: uuid.UUID,
        timeout: float | None = None,
    ) -> DerivationProof:
        """The same call for the aiogram handler and the FastAPI route."""
        return await asyncio.to_thread(
            self.request_proof, user_id=user_id, invoice_id=invoice_id, timeout=timeout
        )

    # -- steps ------------------------------------------------------------

    def _insert(
        self,
        conn: psycopg.Connection[Any],
        request_id: uuid.UUID,
        user_id: int,
        invoice_id: uuid.UUID,
    ) -> None:
        try:
            conn.execute(
                SQL_INSERT_REQUEST,
                {"id": request_id, "user_id": user_id, "invoice_id": invoice_id},
            )
        except psycopg.errors.UniqueViolation as exc:
            raise E.InvoiceRequestInFlight(
                f"user_id={user_id} already has an open derivation proof request"
            ) from exc
        except psycopg.errors.ForeignKeyViolation as exc:
            # `fk_derivation_proof_requests_invoice_id_invoices`. A well-formed
            # UUID for an invoice that does not exist is the ordinary case of a
            # mistyped `/verify`, and it gets the same sentence a *foreign*
            # invoice gets — the constraint answers it a round trip earlier than
            # the deriver would, and must not answer it differently (T1.7).
            raise E.InvoiceNotFound(f"no invoice {invoice_id}") from exc

    def _wait(
        self, conn: psycopg.Connection[Any], request_id: uuid.UUID, deadline: float
    ) -> _Reply:
        while True:
            reply = self._read(conn, request_id)
            if reply.status in ("done", "failed"):
                return reply

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise E.InvoiceRequestTimeout(
                    f"proof request {request_id} still {reply.status} after the deadline",
                    user_message=(
                        "The derivation proof is taking longer than usual. "
                        "Please try /verify again in a moment."
                    ),
                )
            for _ in conn.notifies(timeout=min(remaining, self._recheck), stop_after=1):
                break

    def _read(self, conn: psycopg.Connection[Any], request_id: uuid.UUID) -> _Reply:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(SQL_READ_REQUEST, {"id": request_id})
            row = cur.fetchone()
        if row is None:
            raise E.InvoiceUnavailable(
                f"proof request {request_id} vanished from derivation_proof_requests"
            )
        return _Reply(
            status=row["status"],
            result_json=row["result_json"],
            error_code=row["error_code"],
            error_message=row["error_message"],
        )

    def _interpret(
        self, reply: _Reply, request_id: uuid.UUID, invoice_id: uuid.UUID
    ) -> DerivationProof:
        if reply.status == "failed":
            cls = _ERROR_CLASSES.get(reply.error_code or "", E.InvoiceUnavailable)
            summary = (
                f"deriver refused the proof request: {reply.error_code} "
                f"{reply.error_message or ''}"
            ).strip()
            if issubclass(cls, E.IntegrityFailure):
                raise cls(summary, invoice_id=invoice_id, user_message=reply.error_message)
            if issubclass(cls, E.QuotaExceeded):  # pragma: no cover - not reachable today
                raise cls(summary, limit=0, observed=0, user_message=reply.error_message)
            raise cls(summary, user_message=reply.error_message)

        if reply.result_json is None:  # pragma: no cover - the CHECK forbids it
            raise E.InvoiceUnavailable(f"proof request {request_id} is done with no result")

        try:
            proof = from_wire(reply.result_json)
        except ProofWireError as exc:
            raise E.MacMismatch(
                f"proof request {request_id} carried an unreadable reply: {exc}",
                invoice_id=invoice_id,
            ) from exc

        if proof.invoice_id != invoice_id:
            # A proof for a different invoice is not a decoding problem, it is a
            # substitution: the one shape of attack this whole command exists to
            # make visible, arriving through the reply channel instead of
            # through the address column.
            raise E.MacMismatch(
                f"proof request {request_id} answered about invoice {proof.invoice_id}, "
                f"not {invoice_id}",
                invoice_id=invoice_id,
            )

        if not verify_proof_mac(self._key, proof):
            MAC_FAILURES.inc()
            raise E.MacMismatch(
                f"invoice {invoice_id}: the derivation proof delivered through "
                "derivation_proof_requests does not verify against INVOICE_INTEGRITY_KEY. "
                "The row was changed between the deriver and here (TZ 5.8/T1.3) — "
                "do not display, do not send funds.",
                invoice_id=invoice_id,
            )
        return proof
