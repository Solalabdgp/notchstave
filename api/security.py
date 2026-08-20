"""The response headers, and the argument for each one.

TZ 3.2 and 5.8/T1.6 both ask for the same thing in the same words: ``CSP
default-src 'self'``, ``script-src 'self'``, no CDN, no third-party fonts, no
analytics, assets self-hosted. The reasoning in the TZ is worth restating
because it is what makes this file security-relevant rather than boilerplate:

    Для страницы, единственное содержимое которой — адрес и сумма, любой
    внешний скрипт является каналом подмены.

T1 vector 2 is *"XSS или подмена статики на странице инвойса. Адрес — первое,
что перепишет любой внедрённый скрипт. Особенно уязвим QR: картинку никто
глазами не проверяет."* A single ``<script src="https://cdn...">`` on this page
is a standing permission for a third party to rewrite the address after it has
been verified. So the policy is applied as a **middleware over every response**,
not as a decorator on the page route: a policy that is attached per-route is a
policy that a future route forgets, and the one it forgets will be the one that
returns an address.

Applied everywhere also means applied to ``/healthz`` and to the JSON endpoints,
where it costs nothing and removes the question of which responses are covered.

**The directives that are not in the TZ, and why they are here.**

``object-src 'none'`` and ``base-uri 'none'`` — ``default-src`` does not cover
``base-uri`` at all, and a injected ``<base href>`` re-points every relative
URL on the page, which defeats ``'self'`` without violating it.

``form-action 'none'`` — the page has no forms; saying so means an injected one
cannot post the address anywhere.

``frame-ancestors`` — the Mini App is loaded in an iframe by Telegram Web and in
a webview by the native clients. ``'self'`` would break the former, and ``'*'``
would let any site frame the payment page and overlay it. The allow-list is
Telegram's web origins, which is the narrowest set that keeps the product
working.

``Cache-Control: no-store`` — the page and the JSON both carry a payment address
bound to one buyer. A shared or intermediary cache holding that is both a
privacy leak (T1 vector 5, revenue disclosure) and a way for a stale address to
outlive the invoice that owns it.

``Referrer-Policy: no-referrer`` — the URL contains the ``public_token``, which
is a bearer credential (TZ 5.8/T1.7). Any outbound navigation that leaked it in
a ``Referer`` header would hand over the invoice.

``X-Content-Type-Options: nosniff`` — the static assets are served from this
process; sniffing turns a mislabelled asset into a script.
"""

from __future__ import annotations

from collections.abc import Iterable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__ = [
    "CONTENT_SECURITY_POLICY",
    "SECURITY_HEADERS",
    "TELEGRAM_FRAME_ANCESTORS",
    "SecurityHeadersMiddleware",
]

#: Where a Telegram Mini App may legitimately be framed from. Native clients use
#: a webview and send no ancestor at all, so this list only has to satisfy the
#: web client.
TELEGRAM_FRAME_ANCESTORS: tuple[str, ...] = (
    "https://web.telegram.org",
    "https://telegram.org",
)

#: Built once at import. The ordering is human-readable rather than significant;
#: CSP directives are a set.
CONTENT_SECURITY_POLICY = "; ".join(
    (
        # The line TZ 3.2 and 5.8/T1.6 name verbatim.
        "default-src 'self'",
        "script-src 'self'",
        # Spelled out rather than left to `default-src` so that a future relaxation
        # of one of them is a visible edit to that line and not a side effect.
        "style-src 'self'",
        "img-src 'self'",
        "font-src 'self'",
        # The status poll goes to this origin and nowhere else.
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        f"frame-ancestors {' '.join(TELEGRAM_FRAME_ANCESTORS)}",
    )
)

SECURITY_HEADERS: dict[str, str] = {
    "content-security-policy": CONTENT_SECURITY_POLICY,
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    # No geolocation, camera or microphone on a page that shows an address.
    "permissions-policy": "geolocation=(), camera=(), microphone=(), payment=()",
    "cache-control": "no-store",
}


class SecurityHeadersMiddleware:
    """Stamp :data:`SECURITY_HEADERS` onto every response leaving this app.

    Written as raw ASGI rather than as a ``BaseHTTPMiddleware`` subclass on
    purpose: ``BaseHTTPMiddleware`` wraps the response in a streaming shim that
    changes error propagation and buffering, which is a lot of behaviour to
    inherit for the sake of setting five headers. This form touches
    ``http.response.start`` and nothing else.

    Headers are **set**, not appended: a route that returned its own
    ``cache-control`` must not be able to end up with two conflicting values,
    and for a security header the safe resolution is "the policy wins".
    """

    def __init__(self, app: ASGIApp, headers: Iterable[tuple[str, str]] | None = None) -> None:
        self._app = app
        source = SECURITY_HEADERS.items() if headers is None else headers
        # Encoded once at construction: this runs on every response, and the
        # header names are ASCII constants that cannot change per request.
        self._encoded: list[tuple[bytes, bytes]] = [
            (name.lower().encode("latin-1"), value.encode("latin-1")) for name, value in source
        ]
        self._names = {name for name, _ in self._encoded}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                raw: list[tuple[bytes, bytes]] = [
                    (key, value)
                    for key, value in message.get("headers", [])
                    if key.lower() not in self._names
                ]
                raw.extend(self._encoded)
                message = {**message, "headers": raw}
            await send(message)

        await self._app(scope, receive, send_with_headers)
