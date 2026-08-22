"""The composition root of the deriver process: keys on one side, rules on the other.

    python -m core.invoicing.issuer

This is the module ``notchstave-deriver.service`` runs. It is the *only* place
in the repository where :mod:`deriver` and :mod:`core.invoicing` are joined, and
that concentration is the design rather than an accident of layout.

Why the join has to happen somewhere
------------------------------------

Migration 0006 put invoice issuance behind the ``notchstave_deriver`` role,
because an invoice is a claim that an address derives from our xpub and only the
xpub holder can make that claim honestly. So ``create_invoice`` runs in the
process that holds the key. But ``create_invoice`` lives in ``core``, and
``deriver`` may not import ``core`` — ``deriver/pyproject.toml`` says so in prose
and ``deriver/tests/test_isolation.py`` says so as a build failure.

Dependency inversion resolves it and nothing else does. :mod:`deriver.requests`
defines the port (:class:`~deriver.requests.InvoiceIssuer`); :mod:`deriver.main`
runs the loop against that port; this module supplies the implementation and
starts the process. The arrow points from ``core`` into ``deriver`` and never
back, which is exactly the one-way boundary of TZ 5.8 ("наружу уходят только
адреса и индексы").

What the isolation test does and does not prove, stated plainly
---------------------------------------------------------------

``deriver/tests/test_isolation.py`` proves that the *package* is free of
network-capable imports. This module means the *process* is a composition of two
packages, so that proof needs a companion, and it has one:
``test_the_issuer_process_pulls_in_no_network_capable_repo_module`` walks the
in-repo import closure starting here and applies the same forbidden list. Adding
``httpx`` to ``core.invoicing.rates`` for a live price feed — the realistic way
this erodes — fails that test.

What neither test can prove is the third-party closure: ``prometheus_client``
can serve HTTP and ``sqlalchemy`` can open a connection, and both are reachable
from here. The control for that is not a unit test, it is the unit file:
``notchstave-deriver.service`` runs with ``IPAddressDeny=any`` plus
``RestrictAddressFamilies=AF_UNIX AF_INET`` and reaches Postgres over the local
socket only. Saying so here rather than implying that a green suite covers it is
the difference between a security argument and a security decoration.

Refusals, and why they are values here
--------------------------------------

Every :class:`~core.invoicing.errors.InvoicingError` is caught and returned as a
:class:`~deriver.requests.RefusedInvoice`. Anything else is allowed to escape.
That line *is* the retry policy: a quota, a disabled asset, an exhausted address
ceiling and a failed re-derivation are answers that would come back identical on
a second attempt, while a dropped connection or a deadlock is worth another go.
The queue cannot make that distinction; this module can, because it is the only
one that knows the exception vocabulary.

:class:`~core.invoicing.errors.IntegrityFailure` is caught with the rest, and it
is worth saying why it is not special-cased into an exception that kills the
loop. It is already loud in the two ways that matter — ``ADDRESS_MISMATCH``
moved inside ``create_invoice``, and TZ section 7 alerts on
``address_mismatch_total > 0`` — and the buyer at the other end of that request
is entitled to the sentence :attr:`IntegrityFailure.user_message` carries
("do not send any funds") rather than to a ten-second silence.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
from typing import Any, Protocol

import psycopg
from psycopg.rows import dict_row

from core.invoicing import proof_wire, wire
from core.invoicing.config import DEFAULT_POLICY, InvoicingPolicy
from core.invoicing.errors import InvoicingError, QuotaExceeded
from core.invoicing.integrity import IntegrityKey, load_integrity_key
from core.invoicing.proof_wire import DerivationProof, compute_proof_mac
from core.invoicing.quotas import QuotaCache
from core.invoicing.rates import RateSource
from core.invoicing.service import (
    AddressPool,
    InvoiceView,
    create_invoice,
    verify_invoice_address,
)
from deriver import main as deriver_main
from deriver import pool as deriver_pool
from deriver.requests import (
    DEFAULT_LEASE_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_RETENTION_SECONDS,
    IssuedInvoice,
    ProvenAddress,
    RefusedInvoice,
    RefusedProof,
)

__all__ = ["InvoiceIssuer", "ProofIssuer", "build_issuer", "build_proof_issuer", "main"]

log = logging.getLogger("notchstave.issuer")


class InvoiceIssuer(Protocol):
    """:class:`deriver.requests.InvoiceIssuer`, restated on this side of the seam.

    The same shape, declared again rather than imported, and the reason is a
    build rule rather than a preference: the root ``mypy`` config sets
    ``follow_imports = "skip"`` for ``deriver.*`` (see the note in
    ``pyproject.toml``) so that the deriver is never type-checked under *this*
    environment's dependency set. Everything imported from there is therefore
    ``Any`` to this file, and ``Any`` cannot be used as an annotation.

    Restating the protocol turns that into a feature. The two declarations are
    the contract written down twice, on either side of a boundary that is
    deliberately not type-connected, and the integration test is what proves they
    still agree — which is the honest arrangement for a seam whose whole purpose
    is that the two halves cannot see each other.

    ``deriver`` and ``request`` are ``Any`` because their types live in the
    package this one cannot look into; what they must supply is fixed by
    :class:`core.invoicing.service.AddressDeriver` and by the columns of
    ``invoice_requests``.
    """

    def __call__(
        self, conn: psycopg.Connection[Any], deriver: Any, request: Any
    ) -> Any: ...


class ProofIssuer(Protocol):
    """:class:`deriver.requests.ProofIssuer`, restated on this side of the seam.

    Declared again rather than imported, for the same ``follow_imports = skip``
    reason :class:`InvoiceIssuer` gives above.
    """

    def __call__(
        self, conn: psycopg.Connection[Any], deriver: Any, request: Any
    ) -> Any: ...


#: The external chain of BIP-44: ``m/44'/60'/<account>'/0/<index>``. Change
#: addresses do not exist in this system — every derived address is one an
#: outsider is asked to pay — so this is a constant rather than a column, and
#: naming it once here keeps the path in the published proof identical to the
#: path ``deriver.derivation`` actually derives at.
EXTERNAL_CHAIN = 0

SQL_ACCOUNT_PATH = """
SELECT path_prefix, xpub_fingerprint
  FROM hd_accounts
 WHERE id = %(hd_account_id)s
"""


def _error_detail(exc: InvoicingError) -> str | None:
    """Operator-facing structure for ``invoice_requests.error_detail``.

    Split from ``user_message`` because the two have different readers. The
    buyer gets a sentence; whoever is on call gets the numbers that say whether
    a refusal was one impatient person or the address ceiling. ``retry_at`` is in
    both worlds — the client turns it into "try again at" — so it travels here
    and the bot may use it.
    """
    detail: dict[str, Any] = {"type": type(exc).__name__}
    retry_at = getattr(exc, "retry_at", None)
    if isinstance(retry_at, dt.datetime):
        detail["retry_at"] = retry_at.isoformat()
    if isinstance(exc, QuotaExceeded):
        detail["scope"] = exc.scope
        detail["limit"] = exc.limit
        detail["observed"] = exc.observed
    return json.dumps(detail)


def build_issuer(
    key: IntegrityKey,
    *,
    pool: AddressPool | None = None,
    policy: InvoicingPolicy = DEFAULT_POLICY,
    rates: RateSource | None = None,
    cache: QuotaCache | None = None,
) -> InvoiceIssuer:
    """Close over the issuance configuration and return the port implementation.

    A closure and not a class with a ``__call__``, because there is exactly one
    method and the alternative reads as ceremony. The captured values are the
    ones that must not vary per request: the MAC key, the policy whose version
    lands in every ``invoices`` row, and the pool module that owns the
    reservation SQL.

    ``pool`` defaults to :mod:`deriver.pool` itself — the module satisfies the
    :class:`~core.invoicing.service.AddressPool` protocol, which is what that
    protocol was shaped for. Overridable so a test can watch the calls, never so
    the SQL can be reimplemented.
    """
    address_pool: AddressPool = deriver_pool if pool is None else pool

    def issue(
        conn: psycopg.Connection[Any],
        deriver: Any,
        request: Any,
    ) -> Any:
        try:
            view: InvoiceView = create_invoice(
                conn,
                deriver,
                key,
                user_id=request.user_id,
                product_id=request.product_id,
                chain_id=request.chain_id,
                asset_id=request.asset_id,
                hd_account_id=request.hd_account_id,
                pool=address_pool,
                policy=policy,
                rates=rates,
                cache=cache,
            )
        except InvoicingError as exc:
            # `str(exc)` is the operator detail and stays in the log; only
            # `user_message` crosses back to a human (errors.py draws that line
            # and this is the one place it could be blurred).
            log.warning(
                "request %s refused (%s): %s", request.request_id, type(exc).__name__, exc
            )
            return RefusedInvoice(
                error_code=type(exc).__name__,
                error_message=exc.user_message,
                error_detail=_error_detail(exc),
            )
        return IssuedInvoice(
            invoice_id=view.invoice_id,
            result_json=json.dumps(wire.to_wire(view)),
        )

    return issue


def build_proof_issuer(key: IntegrityKey) -> ProofIssuer:
    """The ``/verify`` port: prove one invoice's address, or refuse (TZ 5.8/T1.4).

    Four steps, and the order is the argument for the command existing at all:

    1. :func:`~core.invoicing.service.verify_invoice_address` with
       ``expected_user_id``. That single call is the ownership filter of T1.7,
       the re-derivation of T1.1 and the invoice MAC check of T1.3 — so a proof
       is never built for an invoice whose address has already failed its own
       checks. Publishing a "proof" of a substituted address would be the worst
       possible outcome of this feature and this line is what forecloses it.
    2. Read ``path_prefix`` from ``hd_accounts``, and compare the row's
       ``xpub_fingerprint`` against the one the *loaded key* produces. The
       fingerprint that goes out is the deriver's, never the row's: publishing
       the row's value would make the proof a restatement of the database, which
       is the thing the reader is trying to check. A disagreement means this
       process is holding a different key from the one the account claims —
       realistically a half-finished rotation (T4) — and it refuses.
    3. Derive the address again through the same object, at the path being
       published, and compare. Step 1 already did this; doing it again against
       the *composed path string* is what makes the published path and the
       published address provably the same fact rather than two adjacent ones.
    4. MAC the triple and hand it to the queue.

    Refusals are values, exceptions are exceptions — the split
    :class:`~deriver.requests.ProofIssuer` needs in order to know whether a
    retry could ever help.
    """

    def prove(conn: psycopg.Connection[Any], deriver: Any, request: Any) -> Any:
        try:
            view: InvoiceView = verify_invoice_address(
                conn,
                deriver,
                key,
                request.invoice_id,
                expected_user_id=request.user_id,
            )
        except InvoicingError as exc:
            log.warning(
                "proof request %s refused (%s): %s",
                request.request_id,
                type(exc).__name__,
                exc,
            )
            return RefusedProof(
                error_code=type(exc).__name__, error_message=exc.user_message
            )

        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(SQL_ACCOUNT_PATH, {"hd_account_id": view.hd_account_id})
            account = cur.fetchone()
        if account is None:  # pragma: no cover - FK on receive_addresses forbids it
            raise RuntimeError(f"hd_account {view.hd_account_id} vanished mid-proof")

        fingerprint = str(deriver.fingerprint(view.hd_account_id))
        if fingerprint != str(account["xpub_fingerprint"]):
            log.error(
                "hd_account %s claims fingerprint %s, the loaded key produces %s",
                view.hd_account_id,
                account["xpub_fingerprint"],
                fingerprint,
            )
            return RefusedProof(
                error_code="AddressMismatch",
                error_message=(
                    "This invoice cannot be proven right now. Do not send any funds "
                    "and please contact support."
                ),
            )

        path = f"{str(account['path_prefix']).rstrip('/')}/{EXTERNAL_CHAIN}/{view.derivation_index}"
        derived = str(deriver.address(view.hd_account_id, view.derivation_index))
        if derived.lower() != view.address.lower():  # pragma: no cover - step 1 covers it
            return RefusedProof(
                error_code="AddressMismatch",
                error_message=(
                    "This invoice failed a security check and cannot be proven. "
                    "Do not send any funds. Please contact support."
                ),
            )

        proof = DerivationProof(
            invoice_id=view.invoice_id,
            xpub_fingerprint=fingerprint,
            derivation_path=path,
            derivation_index=view.derivation_index,
            # The address from the *verified view*, not the freshly derived
            # string: they are equal by the check above, and using the view's
            # keeps the published address byte-identical to the EIP-55 form the
            # buyer was shown, which is the comparison T1.4 asks them to make.
            address=view.address,
            proof_mac=compute_proof_mac(
                key,
                invoice_id=view.invoice_id,
                xpub_fingerprint=fingerprint,
                derivation_path=path,
                address=view.address,
            ),
        )
        return ProvenAddress(result_json=json.dumps(proof_wire.to_wire(proof)))

    return prove


def main(argv: list[str] | None = None) -> int:
    """Start the deriver process: load the keys, then answer invoice requests.

    Fails closed on every startup input. A missing xpub credential, a private key
    where an account xpub should be, a MAC key shorter than 16 bytes or an unset
    ``DERIVER_DATABASE_URL`` all stop the process here — before it can advertise itself
    as ready and start consuming requests it cannot finish.
    """
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(levelname)s %(name)s %(message)s",
    )

    args = [] if argv is None else argv
    credentials_dir = args[0] if args else None

    try:
        deriver = deriver_main.build_deriver(credentials_dir)
        key = load_integrity_key(credentials_dir)
        policy = InvoicingPolicy.from_env()
    except Exception as exc:  # noqa: BLE001 — top level; redaction is already installed
        log.error("issuer failed to start: %s: %s", type(exc).__name__, exc)
        return 1

    log.info("issuer ready, policy=%s", policy.version)
    deriver_main.serve(
        deriver,
        build_issuer(key, policy=policy),
        # Both ports, one loop, one pair of connections. `/verify` is a read and
        # `/buy` is a write, but they need the same two things — the xpub and the
        # ability to answer a queue — so splitting them into two processes would
        # mean two copies of the credential for no isolation gained.
        proof_issuer=build_proof_issuer(key),
        poll_interval=float(
            os.environ.get(
                "DERIVER_POLL_INTERVAL_SECONDS", deriver_main.DEFAULT_POLL_INTERVAL_SECONDS
            )
        ),
        max_attempts=int(os.environ.get("DERIVER_REQUEST_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS)),
        lease_seconds=float(
            os.environ.get("DERIVER_REQUEST_LEASE_SECONDS", DEFAULT_LEASE_SECONDS)
        ),
        retention_seconds=float(
            os.environ.get("DERIVER_REQUEST_RETENTION_SECONDS", DEFAULT_RETENTION_SECONDS)
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
