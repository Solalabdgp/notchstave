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

from core.invoicing import wire
from core.invoicing.config import DEFAULT_POLICY, InvoicingPolicy
from core.invoicing.errors import InvoicingError, QuotaExceeded
from core.invoicing.integrity import IntegrityKey, load_integrity_key
from core.invoicing.quotas import QuotaCache
from core.invoicing.rates import RateSource
from core.invoicing.service import AddressPool, InvoiceView, create_invoice
from deriver import main as deriver_main
from deriver import pool as deriver_pool
from deriver.requests import (
    DEFAULT_LEASE_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_RETENTION_SECONDS,
    IssuedInvoice,
    RefusedInvoice,
)

__all__ = ["InvoiceIssuer", "build_issuer", "main"]

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


def main(argv: list[str] | None = None) -> int:
    """Start the deriver process: load the keys, then answer invoice requests.

    Fails closed on every startup input. A missing xpub credential, a private key
    where an account xpub should be, a MAC key shorter than 16 bytes or an unset
    ``DATABASE_URL`` all stop the process here — before it can advertise itself
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
