"""Ask the deriver for an invoice. The one function ``bot`` and ``api`` call.

    from core.invoicing.client import InvoiceClient

    client = InvoiceClient(dsn=..., key=load_integrity_key())
    view = await client.acreate_invoice(
        user_id=user.id, product_id=product.id,
        chain_id=8453, asset_id=usdc_id, hd_account_id=account_id,
    )
    await message.answer(f"Send {view.amount_due_raw} to {view.address}")

Everything about the transport is behind that call. What a caller has to know is
in three sentences:

1. It returns a fully verified :class:`~core.invoicing.service.InvoiceView`, or
   it raises. There is no third outcome and no ``None``.
2. Everything it raises is a :class:`~core.invoicing.errors.InvoicingError`, and
   every one of those carries a ``user_message`` that can be sent to the buyer
   as-is. Rendering ``str(exc)`` instead would put quota limits and account ids
   in a Telegram message.
3. :class:`~core.invoicing.errors.IntegrityFailure` is the one you must not
   swallow into a friendly retry. It does not inherit from
   ``InvoiceUnavailable`` precisely so a ``except InvoiceUnavailable`` handler
   cannot catch it by accident, and its meaning is "do not show anything to
   anyone, raise the alarm" (TZ 5.8/T1).

----

**Why the reply is checked and not trusted.** The address the buyer will send
money to arrives through a database table. TZ 5.3 says no address reaches a
human without a check, and the check it names — re-derive it from the xpub —
cannot be run here: ``bot`` has no xpub, by construction, and that is the whole
security model. So the second check of TZ 5.8/T1.3 does the work instead. The
deriver computed ``integrity_mac`` over (id, chain, asset, address, amount,
expiry) at issuance; :meth:`InvoiceClient.create_invoice` recomputes it over
what came back before returning. An attacker with UPDATE on ``invoice_requests``
and without ``INVOICE_INTEGRITY_KEY`` can corrupt a reply into a
:class:`~core.invoicing.errors.MacMismatch` and cannot forge one into a payment
to their own address.

**Why it is synchronous underneath.** ``psycopg`` in sync mode, wrapped in
``asyncio.to_thread`` for the async callers — the same reasoning
:mod:`core.invoicing.service` gives for itself. The wait is a blocking
``LISTEN`` on a dedicated connection, which is what makes the round trip a
notification rather than a poll; an async psycopg connection would give the
same behaviour and a second connection-management story for the sake of a
thread that spends its life parked on a socket.

**Why a connection per request.** ``LISTEN`` needs a connection with no open
transaction, and a pooled connection that is sometimes listening and sometimes
mid-query is a source of confusing, load-dependent misses. A connect costs about
a millisecond against a round trip measured in tens, and ``/buy`` is not a hot
path — it is a human pressing a button. If it ever becomes one, the fix is a
dedicated listener connection shared by all waiters, not a pool.
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
from core.invoicing.integrity import IntegrityKey, verify_mac
from core.invoicing.metrics import INVOICE_REQUEST_SECONDS, INVOICE_REQUESTS, MAC_FAILURES
from core.invoicing.service import InvoiceView
from core.invoicing.wire import WireFormatError, from_wire

__all__ = [
    "CHANNEL_REQUESTS",
    "REPLY_CHANNEL_PREFIX",
    "reply_channel",
    "DEFAULT_TIMEOUT_SECONDS",
    "InvoiceClient",
    "active_hd_account_id",
]

log = logging.getLogger("notchstave.invoicing.client")

#: Must equal ``deriver.requests`` and migration 0007. Asserted equal by
#: ``core/invoicing/tests/test_invoice_requests.py`` — three copies of a string
#: that nothing else would notice going out of sync, because the symptom of a
#: mismatch is not an error but a round trip that quietly falls back to polling.
CHANNEL_REQUESTS = "notchstave_invoice_requests"
REPLY_CHANNEL_PREFIX = "nsr_"


def reply_channel(request_id: uuid.UUID) -> str:
    """The channel this request's reply will arrive on (migration 0007)."""
    return f"{REPLY_CHANNEL_PREFIX}{request_id.hex}"

#: When to stop waiting. Generous on purpose: the expected round trip is a
#: single ``NOTIFY`` hop in the tens of milliseconds, so anything approaching
#: this number means the deriver is down rather than busy — and in that world
#: the right answer is a clear message, not a faster one. Kept under Telegram's
#: callback-answer window so a ``/buy`` pressed as an inline button can still be
#: answered rather than left spinning.
DEFAULT_TIMEOUT_SECONDS = 10.0

#: How often the wait re-reads the row even without a notification. This is the
#: safety net for a wakeup lost to a reconnect, not the mechanism — at 250ms it
#: is invisible next to the notification path and cheap enough to leave on.
DEFAULT_RECHECK_SECONDS = 0.25

SQL_INSERT_REQUEST = """
INSERT INTO invoice_requests (id, user_id, product_id, chain_id, asset_id, hd_account_id)
VALUES (%(id)s, %(user_id)s, %(product_id)s, %(chain_id)s, %(asset_id)s, %(hd_account_id)s)
"""

SQL_READ_REQUEST = """
SELECT status::text AS status, invoice_id, result_json,
       error_code, error_message, error_detail
  FROM invoice_requests
 WHERE id = %(id)s
"""

SQL_ACTIVE_ACCOUNT = "SELECT id FROM hd_accounts WHERE is_active ORDER BY id LIMIT 1"

#: Name -> class, built from the module's own ``__all__`` so a refusal added to
#: ``errors.py`` is routable the moment it exists. The deriver writes
#: ``type(exc).__name__``; this reads it back. An unknown name is not a crash —
#: a bot on an older deploy than the deriver must still say something sensible —
#: it degrades to :class:`~core.invoicing.errors.InvoiceUnavailable`.
_ERROR_CLASSES: dict[str, type[E.InvoicingError]] = {
    name: cls
    for name in E.__all__
    if isinstance(cls := getattr(E, name), type) and issubclass(cls, E.InvoicingError)
}


@dataclass(frozen=True, slots=True)
class _Reply:
    status: str
    invoice_id: uuid.UUID | None
    result_json: dict[str, Any] | None
    error_code: str | None
    error_message: str | None
    error_detail: dict[str, Any] | None


def active_hd_account_id(conn: psycopg.Connection[Any]) -> int:
    """The account new invoices are issued from (TZ 5.8/T4 rotation).

    Exposed here because every caller of :meth:`InvoiceClient.create_invoice`
    needs it and the alternative is each of them writing the same query slightly
    differently. ``uq_hd_accounts_single_active`` guarantees there is at most one,
    so ``LIMIT 1`` is a formality rather than a choice between candidates.

    Raises rather than returning ``None``: no active account means mid-rotation
    or a broken install, and issuing against a guessed account produces a valid
    address whose owner cannot spend it.
    """
    with conn.cursor() as cur:
        cur.execute(SQL_ACTIVE_ACCOUNT)
        row = cur.fetchone()
    if row is None:
        raise E.InvoiceUnavailable(
            "no active hd_accounts row: the xpub rotation of TZ 5.8/T4 is mid-flight "
            "or no account has been provisioned",
            user_message="Payments are temporarily paused. Please try again shortly.",
        )
    return int(row[0])


class InvoiceClient:
    """A thin, blocking client for the ``invoice_requests`` round trip.

    Holds no connection between calls. The ``key`` is the same
    ``INVOICE_INTEGRITY_KEY`` the deriver used to sign the invoice; without it
    this class cannot verify a reply and therefore refuses to be built.
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

    # -- the call ---------------------------------------------------------

    def create_invoice(
        self,
        *,
        user_id: int,
        product_id: int,
        chain_id: int,
        asset_id: int,
        hd_account_id: int,
        timeout: float | None = None,
    ) -> InvoiceView:
        """Ask, wait, verify, return. Blocks the calling thread.

        Ordering inside, and the one step that is not obvious: ``LISTEN`` is
        issued **before** the INSERT. The deriver can answer in less time than
        it takes this function to get to its wait loop, and a subscription taken
        out after the reply committed would miss the notification entirely —
        turning a 20ms round trip into a 250ms one on exactly the requests that
        went best. Subscribing first costs nothing and removes the race.
        """
        deadline = time.monotonic() + (self._timeout if timeout is None else timeout)
        request_id = uuid7(dt.datetime.now(dt.UTC))
        started = time.monotonic()

        with psycopg.connect(self._dsn, autocommit=True) as conn:
            conn.execute(f"LISTEN {reply_channel(request_id)}")
            self._insert(conn, request_id, user_id, product_id, chain_id, asset_id, hd_account_id)
            reply = self._wait(conn, request_id, deadline)

        view = self._interpret(reply, request_id)
        INVOICE_REQUEST_SECONDS.observe(time.monotonic() - started)
        INVOICE_REQUESTS.labels(outcome="issued").inc()
        return view

    async def acreate_invoice(
        self,
        *,
        user_id: int,
        product_id: int,
        chain_id: int,
        asset_id: int,
        hd_account_id: int,
        timeout: float | None = None,
    ) -> InvoiceView:
        """The same call for the aiogram handler and the FastAPI route.

        ``to_thread`` and not an async driver: the thread spends its entire life
        parked on a socket waiting for a notification, which is precisely the
        workload a thread is cheap for, and it keeps one implementation of the
        protocol instead of two that can disagree about a corner.
        """
        return await asyncio.to_thread(
            self.create_invoice,
            user_id=user_id,
            product_id=product_id,
            chain_id=chain_id,
            asset_id=asset_id,
            hd_account_id=hd_account_id,
            timeout=timeout,
        )

    # -- steps ------------------------------------------------------------

    def _insert(
        self,
        conn: psycopg.Connection[Any],
        request_id: uuid.UUID,
        user_id: int,
        product_id: int,
        chain_id: int,
        asset_id: int,
        hd_account_id: int,
    ) -> None:
        try:
            conn.execute(
                SQL_INSERT_REQUEST,
                {
                    "id": request_id,
                    "user_id": user_id,
                    "product_id": product_id,
                    "chain_id": chain_id,
                    "asset_id": asset_id,
                    "hd_account_id": hd_account_id,
                },
            )
        except psycopg.errors.UniqueViolation as exc:
            # `uq_invoice_requests_one_open_per_user`. Translated rather than
            # propagated: a psycopg exception reaching an aiogram handler is a
            # 500 in a place where the correct answer is one polite sentence.
            INVOICE_REQUESTS.labels(outcome="in_flight").inc()
            raise E.InvoiceRequestInFlight(
                f"user_id={user_id} already has an open invoice request (TZ 5.8/T5.1)"
            ) from exc

    def _wait(
        self, conn: psycopg.Connection[Any], request_id: uuid.UUID, deadline: float
    ) -> _Reply:
        while True:
            reply = self._read(conn, request_id)
            if reply.status in ("done", "failed"):
                return reply

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                INVOICE_REQUESTS.labels(outcome="timeout").inc()
                raise E.InvoiceRequestTimeout(
                    f"invoice request {request_id} still {reply.status} after the deadline; "
                    "it may yet be answered — the row is not withdrawn"
                )

            # The notification is a wakeup, never the answer: the loop re-reads
            # the row and decides from that. A missed notification therefore
            # costs one recheck interval and cannot cost correctness, which is
            # the same stance settler/main.py takes about its own tick.
            for _ in conn.notifies(timeout=min(remaining, self._recheck), stop_after=1):
                break

    def _read(self, conn: psycopg.Connection[Any], request_id: uuid.UUID) -> _Reply:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(SQL_READ_REQUEST, {"id": request_id})
            row = cur.fetchone()
        if row is None:
            # The prune only touches finished rows past their retention, so this
            # means somebody deleted an in-flight request out of band.
            raise E.InvoiceUnavailable(
                f"invoice request {request_id} vanished from invoice_requests"
            )
        return _Reply(
            status=row["status"],
            invoice_id=row["invoice_id"],
            result_json=row["result_json"],
            error_code=row["error_code"],
            error_message=row["error_message"],
            error_detail=row["error_detail"],
        )

    def _interpret(self, reply: _Reply, request_id: uuid.UUID) -> InvoiceView:
        if reply.status == "failed":
            INVOICE_REQUESTS.labels(outcome="refused").inc()
            raise self._rebuild(reply)

        if reply.result_json is None:  # pragma: no cover - the CHECK forbids it
            raise E.InvoiceUnavailable(f"invoice request {request_id} is done with no result")

        try:
            view = from_wire(reply.result_json)
        except WireFormatError as exc:
            INVOICE_REQUESTS.labels(outcome="tampered").inc()
            raise E.MacMismatch(
                f"invoice request {request_id} carried an unreadable reply: {exc}",
                invoice_id=reply.invoice_id,
            ) from exc

        self._verify(view)
        return view

    def _verify(self, view: InvoiceView) -> None:
        """TZ 5.8/T1.3 on the receiving end. The gate this whole module exists for.

        Not ``deriver.verify`` — that needs the xpub and lives on the other side
        of the boundary, and it already ran at issuance inside the same
        transaction that wrote this invoice. This is the second, independent
        check, and it is the one that covers the transport: it authenticates the
        exact tuple that travelled, under a key the transport never sees.
        """
        if verify_mac(
            self._key,
            view.integrity_mac,
            invoice_id=view.invoice_id,
            chain_id=view.chain_id,
            asset_id=view.asset_id,
            address=view.address,
            amount_due_raw=view.amount_due_raw,
            expires_at=view.expires_at,
        ):
            return

        MAC_FAILURES.inc()
        INVOICE_REQUESTS.labels(outcome="tampered").inc()
        raise E.MacMismatch(
            f"invoice {view.invoice_id}: the reply delivered through invoice_requests does "
            "not verify against INVOICE_INTEGRITY_KEY. The row was changed between the "
            "deriver and here (TZ 5.8/T1.3) — do not display, do not credit.",
            invoice_id=view.invoice_id,
        )

    def _rebuild(self, reply: _Reply) -> E.InvoicingError:
        """Turn ``(error_code, error_message, error_detail)`` back into an exception.

        The class travels by name and the buyer-facing sentence travels with it,
        so a refusal raised in the deriver process is caught by type in the bot
        process. What deliberately does *not* travel is ``str(exc)``: the
        operator detail names limits, counts and account ids and stays in the
        deriver's log, which is the split ``errors.py`` draws and the reason a
        handler can render ``user_message`` without reviewing it first.
        """
        detail = reply.error_detail or {}
        message = reply.error_message or None
        cls = _ERROR_CLASSES.get(reply.error_code or "", E.InvoiceUnavailable)
        summary = f"deriver refused the request: {reply.error_code} {message or ''}".strip()

        if issubclass(cls, E.QuotaExceeded):
            retry_raw = detail.get("retry_at")
            return cls(
                summary,
                limit=int(detail.get("limit", 0)),
                observed=int(detail.get("observed", 0)),
                retry_at=(
                    dt.datetime.fromisoformat(str(retry_raw)) if retry_raw else None
                ),
                user_message=message,
            )
        if issubclass(cls, E.IntegrityFailure):
            return cls(summary, invoice_id=reply.invoice_id, user_message=message)
        return cls(summary, user_message=message)
