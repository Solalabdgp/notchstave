"""The endpoints. Two doors into one invoice, and they are authorized differently.

* ``/i/{public_token}`` and ``/api/invoices/by-token/...`` — the **public page**
  of TZ 3.2. Authorization is possession of the token: 32 bytes of CSPRNG output
  with a TTL of "invoice life + top-up window", which is TZ 5.8/T1.7's answer to
  IDOR (*"Публичная ссылка на страницу инвойса — по отдельному неугадываемому
  токену с TTL"*). No Telegram identity is involved, on purpose — the buyer may
  open the link in any browser, and requiring a session would make the link
  useless in exactly the case it exists for.
* ``/api/me/invoices/{invoice_id}`` — the **authenticated** read, for a Mini App
  that already has a verified ``initData``. Authorization is the ``user_id``
  inside that signature, and the lookup is filtered by it — the other half of
  T1.7: *"Любой запрос статуса фильтруется по user_id из проверенного
  initData/tg_id, а не только по invoice_id."*

Both doors reach the invoice through
:func:`core.invoicing.service.load_invoice_by_public_token` /
:func:`~core.invoicing.service.verify_invoice_address`, and never through a
``SELECT`` of their own. That is not tidiness. Those two functions are the only
code in the repository that returns an address to a caller, and they do it
having run the T1 checks; a hand-written query here would be an address display
path with no gate on it, which is precisely the bug T1 is about.

**Every failure to find anything is 404, and they are indistinguishable.** A
wrong token, an expired token, an invoice belonging to somebody else, and an
invoice that never existed all produce the same response with the same body.
:class:`core.invoicing.errors.InvoiceNotFound` already collapses the four for
the same stated reason — a 403 confirms that an id is real, which is the one bit
an enumeration attempt is buying.

**Integrity failures are not 404 and not 500.** A
:class:`~core.invoicing.errors.IntegrityFailure` means the stored invoice
disagrees with the key material, and TZ 5.8/T1 classifies that as suspected
compromise. The buyer gets an explicit "do not send funds" sentence — the
``user_message`` the exception already carries — because the one outcome that
must not happen is a buyer paying an address the system just failed to verify.
"""

from __future__ import annotations

import datetime as dt
import logging
import string
import uuid
from typing import Annotated, Any
from urllib.parse import quote

import psycopg
from fastapi import APIRouter, Depends, Header, HTTPException, Path, Request
from fastapi.responses import HTMLResponse, JSONResponse

from api import page
from api.deps import ApiDependencies
from api.repository import InvoiceProgress, database_reachable, load_progress
from api.schemas import HealthOut, InvoiceOut, StatusOut
from api.telegram import InitData, InitDataError, verify_init_data
from core.invoicing.errors import IntegrityFailure, InvoiceNotFound
from core.invoicing.service import (
    InvoiceView,
    MacOnly,
    load_invoice_by_public_token,
    verify_invoice_address,
)

__all__ = ["router", "dependencies_of"]

log = logging.getLogger("notchstave.api.routes")

router = APIRouter()

#: ``secrets.token_urlsafe`` output, so base64url plus nothing else.
_TOKEN_ALPHABET = frozenset(string.ascii_letters + string.digits + "-_")

#: The scheme Telegram Mini App clients conventionally use for this header.
_AUTH_SCHEME = "tma"

_NOT_FOUND = "No such invoice, or this link has expired."


def dependencies_of(request: Request) -> ApiDependencies:
    """Pull the composed dependencies off the app.

    Stored on ``app.state`` by :func:`api.main.create_app` rather than in a
    module global, so two apps built in one test session — one with a real
    deriver, one with ``MAC_ONLY`` — cannot see each other's wiring.
    """
    deps: ApiDependencies = request.app.state.deps
    return deps


Deps = Annotated[ApiDependencies, Depends(dependencies_of)]


# ---------------------------------------------------------------------------
# Shared loading
# ---------------------------------------------------------------------------


def _check_token_shape(token: str, deps: ApiDependencies) -> None:
    """Reject what cannot be a token before it reaches the database.

    Not a security control on its own — the lookup is safe either way, it is a
    parameterised query against a unique index — but it keeps a scripted probe
    from converting itself into database load, and it means the logs
    distinguish "nonsense" from "plausible token that missed".
    """
    if not token or len(token) > deps.config.max_token_length:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    if not _TOKEN_ALPHABET.issuperset(token):
        raise HTTPException(status_code=404, detail=_NOT_FOUND)


def _load_by_token(
    conn: psycopg.Connection[Any], deps: ApiDependencies, token: str
) -> tuple[InvoiceView, InvoiceProgress | None]:
    """One connection, one moment: the verified invoice and its progress.

    Both reads happen on the same connection inside one call so the page cannot
    render an address from one instant and a confirmation count from another.
    """
    view = load_invoice_by_public_token(conn, deps.deriver, deps.integrity_key, token)
    return view, load_progress(conn, view.invoice_id)


def _load_by_id(
    conn: psycopg.Connection[Any], deps: ApiDependencies, invoice_id: uuid.UUID, user_id: int
) -> tuple[InvoiceView, InvoiceProgress | None]:
    view = verify_invoice_address(
        conn, deps.deriver, deps.integrity_key, invoice_id, expected_user_id=user_id
    )
    return view, load_progress(conn, view.invoice_id)


def _payload(
    view: InvoiceView, progress: InvoiceProgress | None, *, now: dt.datetime
) -> InvoiceOut:
    if progress is None:
        # The invoice verified a microsecond ago and its row is gone. Not a
        # 404 — that would tell a caller their token is wrong when it is not.
        raise HTTPException(status_code=503, detail="Please try again in a moment.")
    return InvoiceOut.of(view, progress, now=now)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@router.get("/healthz", response_model=HealthOut, tags=["ops"])
async def healthz(deps: Deps) -> HealthOut:
    """Liveness plus the two postures a bad deploy gets wrong.

    Never reports configuration values — TZ 5.1 rules that out for this
    endpoint and ``/metrics`` alike. "mac-only" names a *policy*, not a secret,
    and a probe that could not distinguish a process with a working invoice
    gate from one without would be a probe worth deleting.
    """
    try:
        reachable = await deps.read(database_reachable)
    except psycopg.Error as exc:
        log.warning("healthz: database unreachable: %s", exc)
        reachable = False

    return HealthOut(
        status="ok" if reachable else "degraded",
        database="up" if reachable else "down",
        address_verification="mac-only" if isinstance(deps.deriver, MacOnly) else "derivation",
        telegram_auth="configured" if deps.webapp_secret is not None else "unconfigured",
    )


# ---------------------------------------------------------------------------
# The public page (TZ 3.2)
# ---------------------------------------------------------------------------

#: Deliberately unconstrained at the FastAPI layer, with the length cap enforced
#: by :func:`_check_token_shape` instead. A ``Path(max_length=...)`` here would
#: answer an over-long token with a 422 and a validation body naming the limit,
#: while a merely wrong token gets a 404 — and TZ 5.8/T1.7's whole point is that
#: the ways of not being a valid token are indistinguishable from each other.
#: The request line is already bounded by the ASGI server well below anything
#: that could cost this process work.
TokenPath = Annotated[str, Path()]


@router.get("/i/{public_token}", response_class=HTMLResponse, tags=["page"])
async def invoice_page(public_token: TokenPath, deps: Deps) -> HTMLResponse:
    """The page itself: server-rendered, self-hosted, no external anything.

    The address and the EIP-681 string are rendered into the HTML server-side
    rather than fetched by the script after load. Two reasons, and the second
    is the important one: the page is readable with JavaScript disabled, and
    the address a buyer sees does not depend on a fetch that an injected script
    could have raced. The script's job is the parts that move — the countdown,
    the status poll, and drawing the QR from the string that is already in the
    document.
    """
    _check_token_shape(public_token, deps)

    def work(conn: psycopg.Connection[Any]) -> tuple[InvoiceView, InvoiceProgress | None]:
        return _load_by_token(conn, deps, public_token)

    try:
        view, progress = await deps.read(work)
    except InvoiceNotFound:
        return HTMLResponse(page.render_not_found(), status_code=404)
    except IntegrityFailure as exc:
        # Loud in the log, careful on the page. The metric already moved inside
        # core.invoicing; TZ section 7 alerts on it.
        log.error("integrity failure rendering invoice page: %s", exc)
        return HTMLResponse(page.render_blocked(exc.user_message), status_code=409)

    payload = _payload(view, progress, now=dt.datetime.now(dt.UTC))
    return HTMLResponse(
        page.render_invoice(
            payload,
            poll_seconds=deps.config.status_poll_seconds,
            # The token came in on the path and goes back out on the same path.
            # `quote` is belt and braces — `_check_token_shape` has already
            # restricted it to base64url — but it means the one place a
            # path-shaped value is concatenated into a URL cannot be the place
            # that stops being safe if that alphabet is ever widened.
            status_url=f"/api/invoices/by-token/{quote(public_token, safe='')}/status",
        )
    )


@router.get(
    "/api/invoices/by-token/{public_token}", response_model=InvoiceOut, tags=["invoice"]
)
async def invoice_by_token(public_token: TokenPath, deps: Deps) -> InvoiceOut:
    """The same data as JSON, for a client that would rather not scrape HTML."""
    _check_token_shape(public_token, deps)

    def work(conn: psycopg.Connection[Any]) -> tuple[InvoiceView, InvoiceProgress | None]:
        return _load_by_token(conn, deps, public_token)

    view, progress = await _guarded(deps, work)
    return _payload(view, progress, now=dt.datetime.now(dt.UTC))


@router.get(
    "/api/invoices/by-token/{public_token}/status",
    response_model=StatusOut,
    tags=["invoice"],
)
async def status_by_token(public_token: TokenPath, deps: Deps) -> StatusOut:
    """The polled endpoint. Still goes through the full verification.

    It would be cheaper to resolve the token to an ``invoice_id`` once and then
    poll a plain status query. It is not done, because the token's TTL is
    enforced inside the verified load: skipping it would leave a page that
    keeps updating for as long as it is open, long after the link stopped
    working. The MAC check that comes with it costs one HMAC-SHA256 over six
    fields, which is not a reason to build a second, weaker path to the same
    row.
    """
    _check_token_shape(public_token, deps)

    def work(conn: psycopg.Connection[Any]) -> tuple[InvoiceView, InvoiceProgress | None]:
        return _load_by_token(conn, deps, public_token)

    _, progress = await _guarded(deps, work)
    if progress is None:
        raise HTTPException(status_code=503, detail="Please try again in a moment.")
    return StatusOut.of(progress, now=dt.datetime.now(dt.UTC))


# ---------------------------------------------------------------------------
# The authenticated read (TZ 3.2 initData, 5.8/T1.7)
# ---------------------------------------------------------------------------


def _init_data(deps: ApiDependencies, authorization: str | None) -> InitData:
    """``Authorization: tma <initData>`` -> a verified session, or 401.

    A missing secret is 503 and not 401: the request may be perfectly valid and
    the server is the one that cannot tell. Answering 401 would send a correct
    client into a re-authentication loop against a misconfiguration.
    """
    if deps.webapp_secret is None:
        raise HTTPException(
            status_code=503,
            detail="Telegram authorization is not configured on this server.",
        )
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Telegram session.")

    scheme, _, raw = authorization.partition(" ")
    if scheme.lower() != _AUTH_SCHEME or not raw.strip():
        raise HTTPException(status_code=401, detail="Missing Telegram session.")

    try:
        return verify_init_data(
            raw.strip(),
            deps.webapp_secret,
            max_age_seconds=deps.config.initdata_max_age_seconds,
        )
    except InitDataError as exc:
        # The detail names which of the four checks failed and stays in the log;
        # the caller gets the class's user_message.
        log.info("initData rejected: %s", exc)
        raise HTTPException(status_code=401, detail=exc.user_message) from exc


@router.get("/api/me/invoices/{invoice_id}", response_model=InvoiceOut, tags=["invoice"])
async def my_invoice(
    invoice_id: uuid.UUID,
    deps: Deps,
    authorization: Annotated[str | None, Header()] = None,
) -> InvoiceOut:
    """One of *my* invoices, where "my" is the signature's ``user_id``.

    The filter is applied inside
    :func:`~core.invoicing.service.verify_invoice_address` via
    ``expected_user_id``, which raises
    :class:`~core.invoicing.errors.InvoiceNotFound` on a mismatch — so somebody
    else's invoice id is a 404 with the same body as an id that does not exist.
    """
    session = _init_data(deps, authorization)

    def work(conn: psycopg.Connection[Any]) -> tuple[InvoiceView, InvoiceProgress | None]:
        return _load_by_id(conn, deps, invoice_id, session.user_id)

    view, progress = await _guarded(deps, work)
    return _payload(view, progress, now=dt.datetime.now(dt.UTC))


@router.get(
    "/api/me/invoices/{invoice_id}/status", response_model=StatusOut, tags=["invoice"]
)
async def my_invoice_status(
    invoice_id: uuid.UUID,
    deps: Deps,
    authorization: Annotated[str | None, Header()] = None,
) -> StatusOut:
    session = _init_data(deps, authorization)

    def work(conn: psycopg.Connection[Any]) -> tuple[InvoiceView, InvoiceProgress | None]:
        return _load_by_id(conn, deps, invoice_id, session.user_id)

    _, progress = await _guarded(deps, work)
    if progress is None:
        raise HTTPException(status_code=503, detail="Please try again in a moment.")
    return StatusOut.of(progress, now=dt.datetime.now(dt.UTC))


# ---------------------------------------------------------------------------
# One place that turns invoicing exceptions into responses
# ---------------------------------------------------------------------------


async def _guarded(
    deps: ApiDependencies,
    work: Any,
) -> tuple[InvoiceView, InvoiceProgress | None]:
    """Run a load and translate the two outcomes that are not "it worked".

    Written once and shared by all four JSON endpoints, so a new endpoint cannot
    accidentally let an :class:`IntegrityFailure` fall through to FastAPI's
    default 500 handler — which would render a stack trace's worth of nothing
    to the buyer and, more importantly, would not carry the "do not send funds"
    sentence.
    """
    try:
        result: tuple[InvoiceView, InvoiceProgress | None] = await deps.read(work)
    except InvoiceNotFound as exc:
        raise HTTPException(status_code=404, detail=_NOT_FOUND) from exc
    except IntegrityFailure as exc:
        log.error("integrity failure serving invoice: %s", exc)
        raise HTTPException(status_code=409, detail=exc.user_message) from exc
    return result


def integrity_failure_handler(_: Request, exc: Exception) -> JSONResponse:
    """Last resort for an :class:`IntegrityFailure` raised outside ``_guarded``.

    Registered on the app so that no future route can turn a suspected
    compromise into a 500 by forgetting to use the helper above.
    """
    assert isinstance(exc, IntegrityFailure)
    log.error("integrity failure escaped a route: %s", exc)
    return JSONResponse(status_code=409, content={"detail": exc.user_message})


def not_found_handler(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, InvoiceNotFound)
    return JSONResponse(status_code=404, content={"detail": _NOT_FOUND})
