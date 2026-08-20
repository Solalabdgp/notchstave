"""The CSP and the headers beside it, asserted on real responses.

TZ 3.2 and 5.8/T1.6 name ``default-src 'self'`` and ``script-src 'self'``
verbatim, and T1 vector 2 gives the reason: *"Адрес — первое, что перепишет
любой внедрённый скрипт. Особенно уязвим QR: картинку никто глазами не
проверяет."*

The tests below check the policy on **every kind of response the app can
produce** — the page, JSON, a 404, a 409, a static asset and ``/healthz`` —
rather than on one happy-path request. That is the whole argument for applying
the policy as middleware instead of per route: a route-level decorator is
something a future route forgets, and the one it forgets will be the one that
returns an address.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import psycopg
import pytest
from fastapi import FastAPI

from api.security import CONTENT_SECURITY_POLICY, SECURITY_HEADERS
from api.tests.conftest import Rig, Seeded


def _directives(header: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for chunk in header.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, _, value = chunk.partition(" ")
        out[name] = value.strip()
    return out


# ---------------------------------------------------------------------------
# The policy itself
# ---------------------------------------------------------------------------


def test_the_two_directives_the_tz_names_are_exactly_self() -> None:
    directives = _directives(CONTENT_SECURITY_POLICY)

    assert directives["default-src"] == "'self'"
    assert directives["script-src"] == "'self'"


def test_the_policy_has_no_unsafe_escape_hatch() -> None:
    """``'unsafe-inline'`` in ``script-src`` would make the rest decorative.

    It is also the tempting fix the first time somebody wants to pass server
    data to the page through a ``<script>`` block — which is why the page uses
    ``data-`` attributes instead. This test is what makes that a decision rather
    than a preference.
    """
    assert "'unsafe-inline'" not in CONTENT_SECURITY_POLICY
    assert "'unsafe-eval'" not in CONTENT_SECURITY_POLICY
    assert "*" not in CONTENT_SECURITY_POLICY
    assert "data:" not in CONTENT_SECURITY_POLICY


def test_the_directives_default_src_cannot_cover_are_present() -> None:
    """``base-uri`` is not covered by ``default-src`` at all.

    An injected ``<base href>`` re-points every relative URL on the page,
    including the script tags, which defeats ``'self'`` without violating it.
    """
    directives = _directives(CONTENT_SECURITY_POLICY)

    assert directives["base-uri"] == "'none'"
    assert directives["object-src"] == "'none'"
    assert directives["form-action"] == "'none'"


def test_framing_is_restricted_to_telegram() -> None:
    """The Mini App is framed by Telegram Web and by nobody else.

    ``'self'`` would break the product; ``*`` would let any site frame the
    payment page and overlay it.
    """
    directives = _directives(CONTENT_SECURITY_POLICY)
    ancestors = directives["frame-ancestors"].split()

    assert ancestors
    assert all(a.startswith("https://") and "telegram.org" in a for a in ancestors)


# ---------------------------------------------------------------------------
# On real responses
# ---------------------------------------------------------------------------


def test_every_response_kind_carries_the_policy(
    rig: Rig,
    seed: Callable[..., Seeded],
    conn: psycopg.Connection[Any],
) -> None:
    """Page, JSON, 404, static asset, health — all of them.

    The 409 is included deliberately: the integrity-failure page is the one a
    buyer is most likely to be looking at while someone is actively attacking
    them, and it is served by a different code path from the happy page.
    """
    seeded = seed()
    responses = {
        "page": rig.client.get(f"/i/{seeded.token}"),
        "json": rig.client.get(f"/api/invoices/by-token/{seeded.token}"),
        "status": rig.client.get(f"/api/invoices/by-token/{seeded.token}/status"),
        "page-404": rig.client.get("/i/" + "q" * 40),
        "json-404": rig.client.get("/api/invoices/by-token/" + "q" * 40),
        "route-404": rig.client.get("/no-such-route"),
        "static": rig.client.get("/static/qr.js"),
        "health": rig.client.get("/healthz"),
        "unauthorized": rig.client.get(f"/api/me/invoices/{seeded.invoice_id}"),
    }

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE receive_addresses SET address = %(a)s WHERE id = %(id)s",
            {"a": "0x" + "cc" * 20, "id": seeded.view.address_id},
        )
    conn.commit()
    responses["blocked"] = rig.client.get(f"/i/{seeded.token}")

    for label, response in responses.items():
        assert (
            response.headers.get("content-security-policy") == CONTENT_SECURITY_POLICY
        ), f"{label} ({response.status_code}) was served without the policy"


@pytest.mark.parametrize("header", sorted(SECURITY_HEADERS))
def test_each_header_reaches_the_page(
    header: str, rig: Rig, seed: Callable[..., Seeded]
) -> None:
    seeded = seed()

    response = rig.client.get(f"/i/{seeded.token}")

    assert response.headers.get(header) == SECURITY_HEADERS[header]


def test_the_page_is_not_cached_anywhere(rig: Rig, seed: Callable[..., Seeded]) -> None:
    """The page carries a payment address bound to one buyer.

    A shared or intermediary cache holding it is both a revenue-disclosure leak
    and a way for a stale address to outlive the invoice that owns it.
    """
    seeded = seed()

    response = rig.client.get(f"/i/{seeded.token}")

    assert response.headers["cache-control"] == "no-store"


def test_the_token_cannot_leak_in_a_referer(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """The URL *is* the credential (TZ 5.8/T1.7), so it must not travel outward."""
    seeded = seed()

    response = rig.client.get(f"/i/{seeded.token}")

    assert response.headers["referrer-policy"] == "no-referrer"
    assert 'name="referrer" content="no-referrer"' in response.text


def test_a_route_cannot_override_the_policy_with_its_own_header(rig: Rig) -> None:
    """Headers are set, not appended.

    A route returning its own ``cache-control`` must not leave the response with
    two conflicting values, and for a security header the safe resolution is
    "the policy wins".
    """
    response = rig.client.get("/static/invoice.css")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    # StaticFiles sets its own; exactly one value must survive.
    assert len(response.headers.get_list("cache-control")) == 1


def test_no_cors_header_is_ever_sent(rig: Rig, seed: Callable[..., Seeded]) -> None:
    """A permissive ACAO would let any site read an invoice from a victim's browser.

    The page is same-origin with the endpoints it polls and ``connect-src 'self'``
    says so; there is no reason for this app to answer a cross-origin read, and
    the absence is asserted rather than assumed.
    """
    seeded = seed()

    response = rig.client.get(
        f"/api/invoices/by-token/{seeded.token}",
        headers={"Origin": "https://evil.example"},
    )

    assert "access-control-allow-origin" not in response.headers


def test_static_assets_cannot_be_sniffed_into_scripts(rig: Rig) -> None:
    response = rig.client.get("/static/invoice.js")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"


def test_debug_is_off_so_a_traceback_never_reaches_a_response(
    build_rig: Callable[..., Rig],
) -> None:
    """A traceback rendered into a response by a process holding the integrity
    key is a config-and-locals dump on the page whose threat model is address
    substitution.
    """
    rig = build_rig()

    # `TestClient.app` is typed as the bare ASGI callable, so the attribute is
    # invisible to mypy even though the object is a FastAPI instance. Asserted
    # into the right type rather than silenced with an ignore: the assertion
    # also fails loudly if `create_app` ever stops returning one.
    app = rig.client.app
    assert isinstance(app, FastAPI)
    assert app.debug is False


def test_the_page_declares_a_viewport(rig: Rig, seed: Callable[..., Seeded]) -> None:
    """The buyer is on a phone; an unscaled page is an unreadable address."""
    seeded = seed()

    assert 'name="viewport"' in rig.client.get(f"/i/{seeded.token}").text
