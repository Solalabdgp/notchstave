"""The app factory and the composition root.

Two functions, and the split between them is the whole design:

* :func:`create_app` takes an :class:`~api.deps.ApiDependencies` and builds the
  application. It reads no environment, opens no connection and loads no secret.
* :func:`build_dependencies` does all three, once, at startup.

That split is what lets the test suite exercise the real application — real
routes, real middleware, real exception handlers, real static files — against a
test database with a deriver of its choosing, instead of monkeypatching module
globals and hoping the result resembles production.

**``debug=False``, always.** The Week 1 note in this file already said so and it
is repeated as code rather than as a comment: a traceback rendered into an HTTP
response by a process holding ``INVOICE_INTEGRITY_KEY`` is a config-and-locals
dump on the page whose entire threat model is address substitution (TZ 5.1).

**No CORS middleware, deliberately.** The page is served from the same origin as
the endpoints it polls, and ``connect-src 'self'`` in the CSP says so. Adding a
permissive ``Access-Control-Allow-Origin`` would let any site read a public
invoice by token from a victim's browser, which is TZ 5.8/T1 vector 5 handed out
for free. If a separate front-end origin is ever needed, it belongs in an
explicit allow-list here, next to this paragraph.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api import routes
from api.config import ApiConfig
from api.deps import ApiDependencies, psycopg_connector
from api.security import SecurityHeadersMiddleware
from api.telegram import load_webapp_secret
from core.invoicing.errors import IntegrityFailure, InvoiceNotFound
from core.invoicing.integrity import load_integrity_key
from core.invoicing.service import MAC_ONLY, AddressDeriver, MacOnly

__all__ = ["create_app", "build_dependencies", "STATIC_DIR"]

log = logging.getLogger("notchstave.api")

#: Self-hosted assets (TZ 5.8/T1.6 — "ассеты self-hosted"). Shipped inside the
#: package so a deployment cannot end up serving a stylesheet from a path that
#: happens to be writable by another process.
STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(deps: ApiDependencies) -> FastAPI:
    """Build the application around an already-resolved set of dependencies."""
    app = FastAPI(
        title="Notchstave invoice API",
        version="0.1.0",
        debug=False,
        # The interactive docs pull Swagger UI from a CDN. On this origin that
        # is a script-src violation and, more to the point, exactly the external
        # dependency TZ 5.8/T1.6 rules out. The schema itself stays available
        # for tooling that wants it; only the HTML viewers are gone.
        docs_url=None,
        redoc_url=None,
    )

    app.state.deps = deps
    app.include_router(routes.router)

    # Registered before the static mount so that a future asset route cannot be
    # served without the policy attached.
    app.add_middleware(SecurityHeadersMiddleware)

    app.add_exception_handler(IntegrityFailure, routes.integrity_failure_handler)
    app.add_exception_handler(InvoiceNotFound, routes.not_found_handler)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


def build_dependencies(
    env: Mapping[str, str] | None = None,
    *,
    deriver: AddressDeriver | MacOnly | None = None,
) -> ApiDependencies:
    """Read the environment and the credentials once.

    ``deriver`` defaults to :data:`~core.invoicing.service.MAC_ONLY` and that
    default is the production answer, not a placeholder: TZ section 9 gives the
    xpub to ``notchstave-deriver.service`` alone, so this process cannot
    re-derive an address and must not pretend otherwise.
    :class:`~core.invoicing.service.MacOnly` carries the full statement of what
    that costs and what still holds.

    The parameter exists so that the moment a deriver-verification channel is
    available — the ``invoice_requests``-shaped round trip of migration 0007,
    extended to answer "does this address verify" — wiring it in is one argument
    here and no change anywhere else.
    """
    source = os.environ if env is None else env
    config = ApiConfig.from_env(source)

    secret = load_webapp_secret(source)
    if secret is None:
        log.warning(
            "no Telegram WebApp secret configured (%s credential or TELEGRAM_BOT_TOKEN); "
            "initData endpoints will answer 503",
            "notchstave-telegram-webapp-secret",
        )

    return ApiDependencies(
        config=config,
        connect=psycopg_connector(config),
        # `env=`, not positional: the first parameter is `credentials_dir`, and
        # passing the environment into it reads plausibly, type-checks under a
        # looser setting than this repo's, and fails at runtime on `Path(...)`
        # of a mapping — inside the one call that loads the key every invoice
        # MAC is checked against. mypy caught it here; the keyword is what keeps
        # it caught.
        integrity_key=load_integrity_key(env=source),
        deriver=MAC_ONLY if deriver is None else deriver,
        webapp_secret=secret,
    )


def app() -> FastAPI:
    """ASGI entry point: ``uvicorn 'api.main:app' --factory``.

    A factory rather than a module-level ``app = create_app(...)`` so that
    importing this module — which the test suite and any tooling does — never
    has the side effect of reading credentials off disk.
    """
    return create_app(build_dependencies())
