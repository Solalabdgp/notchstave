"""The public invoice page: what it shows, and what it refuses to show.

TZ 3.2 asks for a page carrying the address, the amount, a QR and a live status,
reachable by an unguessable token. TZ 5.8/T1.7 makes that token the entire
authorization, which puts the weight of this file on the negative cases: a wrong
token, an expired token, and an invoice whose stored MAC no longer verifies must
each produce a response with no address in it.
"""

from __future__ import annotations

import datetime as dt
import re
import uuid
from collections.abc import Callable
from html import escape, unescape
from typing import Any

import psycopg
import pytest

from api.tests.conftest import Rig, Seeded
from core.invoicing.integrity import compute_mac
from core.invoicing.tests.conftest import TEST_INTEGRITY_KEY

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def close_the_window(
    conn: psycopg.Connection[Any], seeded: Seeded, *, margin: dt.timedelta | None = None
) -> None:
    """Age an invoice past the end of its top-up window, and commit.

    The public token's TTL is *"срок жизни инвойса + окно доплаты"* (TZ 6) and
    :func:`core.invoicing.service.load_invoice_by_public_token` enforces it by
    comparing ``now()`` against ``topup_window_until``. So the way to test an
    expired link is to move that column into the past — this project does not
    have, and should not grow, a clock injection point on the HTTP path just so
    a test can pretend it is tomorrow.

    **The whole timeline moves together, and that is not optional.** Three
    CHECK constraints on ``invoices`` (migration 0001) tie these columns to each
    other::

        topup_window_until >= expires_at   -- topup_window_after_expiry
        expires_at         >  created_at   -- expiry_after_creation
        settled_at IS NULL OR settled_at >= created_at

    So dragging ``topup_window_until`` back on its own is rejected, and so is
    dragging it back with ``expires_at`` but without ``created_at``. Each
    constraint is right on its own terms — a top-up window that closes before
    the invoice it extends, or an invoice that expires before it was issued,
    are both meaningless — so the fixture satisfies them instead of working
    around them, by shifting all three by one offset. The gaps between them come
    out unchanged, which is the point: the result is the row an invoice issued a
    day earlier would actually have. ``settled_at`` is left alone; it is NULL on
    an unpaid invoice, and moving ``created_at`` backwards can only make its
    constraint easier to satisfy.

    **The shift is computed from ``now()``, not passed in as a constant.** A
    fixed ``timedelta(days=1)`` is the obvious version and it is wrong: the
    default top-up window is 24 hours (``core.invoicing.config
    .DEFAULT_TOPUP_WINDOW``), so subtracting a day from a window that closes a
    day out lands it back on the present and the token keeps working. Anchoring
    to ``now()`` inside the statement makes the helper independent of however
    the policy is configured — the row ends up with ``topup_window_until`` at
    ``now() - margin``, whatever it started as. Every right-hand side reads the
    *old* row, which is what lets one statement move the three without a
    temporary.

    **The MAC is recomputed, and that is the part worth being deliberate
    about.** ``integrity_mac`` covers ``expires_at`` (TZ 5.8/T1.3), so moving
    the timeline invalidates it. Leaving it stale would technically still pass
    the tests below — ``load_invoice_by_public_token`` checks the TTL before it
    checks the MAC, so the 404 arrives first — but it would pass for the wrong
    reason: the suite would be asserting "expired links 404" against a row that
    is *also* corrupt, and the day someone reorders those two checks the
    response becomes a 409 and the failure reads as a TTL bug. Re-MACing with
    the same key the fixture issued the invoice with keeps the row honest: after
    this call the only thing wrong with the invoice is that it is old.
    """
    slack = dt.timedelta(hours=1) if margin is None else margin
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE invoices
               SET expires_at         = expires_at
                                      - (topup_window_until - now() + %(margin)s),
                   topup_window_until = topup_window_until
                                      - (topup_window_until - now() + %(margin)s),
                   created_at         = created_at
                                      - (topup_window_until - now() + %(margin)s)
             WHERE id = %(id)s
          RETURNING expires_at
            """,
            {"margin": slack, "id": seeded.invoice_id},
        )
        row = cur.fetchone()
        assert row is not None, "the invoice under test was not there to expire"

        cur.execute(
            "UPDATE invoices SET integrity_mac = %(mac)s WHERE id = %(id)s",
            {
                "mac": compute_mac(
                    TEST_INTEGRITY_KEY,
                    invoice_id=seeded.invoice_id,
                    chain_id=seeded.view.chain_id,
                    asset_id=seeded.view.asset_id,
                    address=seeded.view.address,
                    amount_due_raw=seeded.view.amount_due_raw,
                    expires_at=row[0],
                ),
                "id": seeded.invoice_id,
            },
        )
    conn.commit()


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_page_shows_address_amount_and_the_eip681_string(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """All three, and the QR string must be the one the page displays as text.

    That equality is the check TZ 5.8/T1.4 leaves available to a buyer who has
    no xpub: the QR is drawn in the browser from ``data-eip681``, and the same
    value is printed below it. If the two could differ, the visible string would
    stop being evidence about the invisible one.
    """
    seeded = seed()

    response = rig.client.get(f"/i/{seeded.token}")

    assert response.status_code == 200
    body = response.text
    assert seeded.view.address in body
    assert str(int(seeded.view.amount_due_raw)) in body

    expected = seeded.view.eip681()
    # HTML-escaped in both places, and identical in both places. The `&` of
    # `&uint256=` becomes `&amp;` in the source and `&` again in the DOM, which
    # is why the comparison is made against the escaped form rather than the
    # raw one — the browser reads the same string out of the attribute that it
    # renders into the visible block.
    escaped = escape(expected, quote=True)
    assert f'data-eip681="{escaped}"' in body
    assert escaped in body.split('<code id="eip681"', 1)[1]


def test_page_is_served_with_no_external_references(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """TZ 5.8/T1.6: no CDN, no third-party fonts, no analytics.

    Asserted as the absence of any absolute URL rather than as a list of hosts
    that are not present, so a future edit that adds a new external dependency
    fails here regardless of which vendor it is.
    """
    seeded = seed()
    body = rig.client.get(f"/i/{seeded.token}").text

    assert "http://" not in body
    assert "//" not in body.replace("<!doctype", "")
    assert "<script" in body  # the page does have scripts...
    assert 'src="/static/' in body  # ...and all of them are local


def test_the_scripts_and_stylesheet_the_page_asks_for_exist(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """A self-hosted asset that 404s is a page with no QR and no live status.

    Worth its own test because the CSP makes the failure silent: there is no
    fallback to a CDN, so a renamed file just quietly stops the page working.
    """
    seeded = seed()
    body = rig.client.get(f"/i/{seeded.token}").text

    referenced = [
        part.split('"', 1)[0]
        for marker in ('src="', 'href="')
        for part in body.split(marker)[1:]
        if part.startswith("/static/")
    ]
    assert referenced, "the page referenced no static assets at all"

    for path in referenced:
        assert rig.client.get(path).status_code == 200, path


def test_page_renders_without_javascript(rig: Rig, seed: Callable[..., Seeded]) -> None:
    """The address is server-rendered, not fetched.

    A page whose address arrives by ``fetch`` after load is a page where an
    injected script can race the render. It is also a page that shows nothing to
    a buyer with scripting off.
    """
    seeded = seed()
    body = rig.client.get(f"/i/{seeded.token}").text

    before_scripts = body.split("<script", 1)[0]
    assert seeded.view.address in before_scripts
    assert "<noscript>" in body


def test_page_does_not_leak_issuance_volume(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """No ``derivation_index``, no ``hd_account_id``, no MAC (TZ 5.8/T1 vector 5).

    The page has no login, so anything on it is public. ``derivation_index`` in
    particular is a running count of invoices ever issued.
    """
    seeded = seed()
    body = rig.client.get(f"/i/{seeded.token}").text

    assert "derivation_index" not in body
    assert "hd_account" not in body
    assert seeded.view.integrity_mac.hex() not in body

    # Asserted against the JSON contract by *field name* rather than by hunting
    # for the values in the HTML: a small integer id like `1` appears inside a
    # viewport tag and an amount by coincidence, so a substring search here
    # would either fail on innocent pages or have to be loosened until it
    # stopped catching anything.
    payload = rig.client.get(f"/api/invoices/by-token/{seeded.token}").json()
    forbidden = {
        "user_id",
        "product_id",
        "derivation_index",
        "hd_account_id",
        "integrity_mac",
        "public_token",
        "address_id",
    }
    assert forbidden.isdisjoint(payload)
    assert forbidden.isdisjoint(payload["status"])


# ---------------------------------------------------------------------------
# The QR is a string, not a picture
# ---------------------------------------------------------------------------
#
# TZ 3.2: *"Сервер отдаёт не картинку, а текстовую строку EIP-681: QR рисуется в
# браузере из неё же, и та же строка показывается текстом рядом. Одна точка
# правды вместо двух — подменённый QR перестаёт быть незаметным."*
#
# That sentence is a statement about the *server*, and these are the tests for
# it. The symbol itself is drawn by `static/qr.js` in the browser, from the same
# attribute the visible text is rendered from, so there is no second value for
# the two to disagree about — see that file's header on why it is trusted rather
# than decoded here, and why an earlier draft that ran it under Node was the
# wrong shape for this suite.


def _attribute(body: str, name: str) -> str:
    match = re.search(rf'{name}="([^"]*)"', body)
    assert match is not None, f"the page carries no {name} attribute"
    return unescape(match.group(1))


def _code_block(body: str, element_id: str) -> str:
    match = re.search(rf'<code id="{element_id}"[^>]*>(.*?)</code>', body, re.S)
    assert match is not None, f"the page carries no <code id={element_id}> block"
    return unescape(match.group(1).strip())


def test_the_eip681_string_is_the_same_in_all_three_places(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """The attribute the QR is drawn from, the text beside it, and the JSON.

    This is the whole of TZ 5.8/T1.4's "одна точка правды" as far as the server
    can enforce it. A buyer without an xpub cannot re-derive anything; what they
    *can* do is check that the address is identical in the bot message, on the
    page and in the request their wallet shows after scanning. That check is only
    evidence if the page's own three copies cannot drift, so the equality is
    asserted rather than assumed — they are produced by three different pieces of
    code (an f-string attribute, an f-string element, a Pydantic model).
    """
    seeded = seed()
    body = rig.client.get(f"/i/{seeded.token}").text
    payload = rig.client.get(f"/api/invoices/by-token/{seeded.token}").json()

    canonical = seeded.view.eip681()

    assert _attribute(body, "data-eip681") == canonical
    assert _code_block(body, "eip681") == canonical
    assert payload["eip681"] == canonical


def test_the_address_in_the_eip681_string_is_the_address_on_the_page(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """The substitution this arrangement exists to make visible.

    A QR encoding a different recipient from the one printed above it is the
    exact failure of T1 vector 2 — *"Особенно уязвим QR: картинку никто глазами
    не проверяет."* Here the symbol is built from this string, so the assertion
    that the string carries the displayed address is the assertion that the two
    cannot differ.
    """
    seeded = seed()
    body = rig.client.get(f"/i/{seeded.token}").text

    shown = _code_block(body, "address")
    request = _attribute(body, "data-eip681")

    assert shown == seeded.view.address
    assert shown.lower() in request.lower()


def test_the_server_never_renders_the_qr_as_an_image(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """No image endpoint, no embedded bitmap, no second copy of the address.

    A server-rendered PNG would be a second, independent encoding of the payment
    request, and the one nobody can read by eye. TZ 3.2 rules it out, and the
    absence is asserted here rather than left as an architectural intention that
    a future "just add /qr.png for the email" would quietly reverse.
    """
    seeded = seed()
    body = rig.client.get(f"/i/{seeded.token}").text

    assert "data:image" not in body
    assert "<img" not in body
    # The canvas ships empty; the browser fills it from `data-eip681`.
    assert re.search(r"<canvas[^>]*id=\"qr\"[^>]*>\s*</canvas>", body) is not None

    for path in (f"/i/{seeded.token}", f"/api/invoices/by-token/{seeded.token}"):
        content_type = rig.client.get(path).headers.get("content-type", "")
        assert not content_type.startswith("image/"), path


def test_the_encoder_ships_as_a_self_hosted_script(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """`script-src 'self'` means the QR encoder is an asset of this app.

    Worth pinning because the tempting fix for a QR bug is a CDN one-liner, and
    on this page that single tag is a standing permission for a third party to
    rewrite the address (TZ 5.8/T1.6).
    """
    seeded = seed()
    body = rig.client.get(f"/i/{seeded.token}").text
    assert '/static/qr.js' in body

    response = rig.client.get("/static/qr.js")

    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert "encodeToMatrix" in response.text


# ---------------------------------------------------------------------------
# Nothing to show
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        pytest.param("wRoNgToKeNwRoNgToKeNwRoNgToKeN", id="never-existed"),
        pytest.param("x", id="too-short"),
        pytest.param("A" * 200, id="over-the-length-cap"),
        pytest.param("not/a/token", id="outside-the-alphabet"),
        pytest.param("' OR 1=1 --", id="sql-shaped"),
    ],
)
def test_unknown_token_is_404_with_no_data(
    rig: Rig, seed: Callable[..., Seeded], token: str
) -> None:
    """Every way of not being a token lands on the same page.

    Seeded first so the database is not empty — a 404 from an empty table proves
    nothing about whether the lookup is filtered.
    """
    seeded = seed()

    response = rig.client.get(f"/i/{token}")

    assert response.status_code == 404
    assert seeded.view.address not in response.text
    assert seeded.token not in response.text


def test_expired_token_stops_working_and_says_nothing_about_it(
    rig: Rig,
    seed: Callable[..., Seeded],
    conn: psycopg.Connection[Any],
) -> None:
    """TTL is "invoice life + top-up window" (TZ 6), enforced on lookup.

    And an expired link renders the *same* page as a wrong one: saying "expired"
    would confirm to somebody guessing tokens that their guess had once been
    real.
    """
    seeded = seed()
    alive = rig.client.get(f"/i/{seeded.token}")
    assert alive.status_code == 200

    close_the_window(conn, seeded)

    expired = rig.client.get(f"/i/{seeded.token}")
    unknown = rig.client.get("/i/" + "z" * 43)

    assert expired.status_code == 404
    assert seeded.view.address not in expired.text
    assert expired.text == unknown.text


def test_expired_token_also_closes_the_json_and_status_endpoints(
    rig: Rig,
    seed: Callable[..., Seeded],
    conn: psycopg.Connection[Any],
) -> None:
    """The polled endpoint runs the full verified load, so the TTL reaches it.

    It would be cheaper to resolve the token once and then poll a plain status
    query; that shortcut would leave a page updating forever after its link
    died, which is the bug this asserts is absent.
    """
    seeded = seed()
    close_the_window(conn, seeded)

    assert rig.client.get(f"/api/invoices/by-token/{seeded.token}").status_code == 404
    assert (
        rig.client.get(f"/api/invoices/by-token/{seeded.token}/status").status_code == 404
    )


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------


def test_tampered_address_blocks_the_page_instead_of_rendering_it(
    rig: Rig,
    seed: Callable[..., Seeded],
    conn: psycopg.Connection[Any],
) -> None:
    """T1 vector 1: a database write that swaps the address must not be paid.

    The MAC no longer verifies, and the one outcome that must not happen is a
    buyer sending funds to an address the system just failed to check. So the
    response carries a refusal and *neither* address.
    """
    seeded = seed()
    attacker = "0x" + "ff" * 20
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE receive_addresses SET address = %(a)s WHERE id = %(id)s",
            {"a": attacker, "id": seeded.view.address_id},
        )
    conn.commit()

    response = rig.client.get(f"/i/{seeded.token}")

    assert response.status_code == 409
    assert attacker not in response.text
    assert seeded.view.address not in response.text
    assert "do not send" in response.text.lower()


def test_tampered_amount_is_also_caught(
    rig: Rig,
    seed: Callable[..., Seeded],
    conn: psycopg.Connection[Any],
) -> None:
    """The MAC covers the amount too, so raising the price is not a silent edit."""
    seeded = seed()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE invoices SET amount_due_raw = amount_due_raw * 10 WHERE id = %(id)s",
            {"id": seeded.invoice_id},
        )
    conn.commit()

    assert rig.client.get(f"/i/{seeded.token}").status_code == 409


def test_integrity_failure_is_409_on_the_json_endpoints_too(
    rig: Rig,
    seed: Callable[..., Seeded],
    conn: psycopg.Connection[Any],
) -> None:
    """Never a 500: a stack trace carries no "do not send funds" sentence."""
    seeded = seed()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE receive_addresses SET address = %(a)s WHERE id = %(id)s",
            {"a": "0x" + "ee" * 20, "id": seeded.view.address_id},
        )
    conn.commit()

    for path in (
        f"/api/invoices/by-token/{seeded.token}",
        f"/api/invoices/by-token/{seeded.token}/status",
    ):
        response = rig.client.get(path)
        assert response.status_code == 409, path
        assert response.json()["detail"]


def test_mac_only_still_catches_a_tampered_address(
    build_rig: Callable[..., Rig],
    seed: Callable[..., Seeded],
    conn: psycopg.Connection[Any],
) -> None:
    """Production posture: no xpub in this process, and T1.3 still holds.

    ``MAC_ONLY`` drops the re-derivation check and only that one — see
    :class:`core.invoicing.service.MacOnly`. The MAC is computed over the
    address, so a swapped address is still caught by the process that cannot
    re-derive it. This is the test that says the production deployment is not
    running blind.
    """
    from core.invoicing.service import MAC_ONLY

    seeded = seed()
    rig = build_rig(address_deriver=MAC_ONLY)
    assert rig.client.get(f"/i/{seeded.token}").status_code == 200

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE receive_addresses SET address = %(a)s WHERE id = %(id)s",
            {"a": "0x" + "dd" * 20, "id": seeded.view.address_id},
        )
    conn.commit()

    assert rig.client.get(f"/i/{seeded.token}").status_code == 409


# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------


def test_database_content_is_escaped_into_the_page(
    rig: Rig,
    seed: Callable[..., Seeded],
    conn: psycopg.Connection[Any],
) -> None:
    """T1 vector 1 must not upgrade into vector 2.

    An attacker who can write the catalog and gets their content reflected
    unescaped has turned a data tamper into script execution on the page that
    displays the address. The asset symbol is the field a shop operator edits
    most often, so it is the one used here.

    The payload is trimmed to fit ``assets.symbol``, which is ``VARCHAR(16)``.
    That column width is not a defence and must not be mistaken for one — an
    unclosed ``<script>`` tag is still an injection, and there is no length at
    which unescaped output becomes safe — but the test has to write a row
    Postgres will accept, or it fails on the ``INSERT`` without ever reaching
    the renderer it is about.
    """
    seeded = seed()
    payload = "<script>x</b>"  # 13 chars, fits VARCHAR(16)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE assets SET symbol = %(s)s WHERE id = %(id)s AND chain_id = %(c)s",
            {
                "s": payload,
                "id": seeded.view.asset_id,
                "c": seeded.view.chain_id,
            },
        )
    conn.commit()

    body = rig.client.get(f"/i/{seeded.token}").text

    assert payload not in body
    assert "&lt;script&gt;x&lt;/b&gt;" in body


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def test_healthz_reports_posture_without_configuration(rig: Rig) -> None:
    """TZ 5.1: posture, never values. "mac-only" names a policy, not a secret."""
    payload = rig.client.get("/healthz").json()

    assert payload["status"] == "ok"
    assert payload["database"] == "up"
    assert payload["address_verification"] == "derivation"
    assert payload["telegram_auth"] == "configured"


def test_healthz_distinguishes_the_two_postures_a_bad_deploy_gets_wrong(
    build_rig: Callable[..., Rig],
) -> None:
    from core.invoicing.service import MAC_ONLY

    payload = build_rig(address_deriver=MAC_ONLY, telegram=False).client.get("/healthz").json()

    assert payload["address_verification"] == "mac-only"
    assert payload["telegram_auth"] == "unconfigured"
    # Still healthy: neither is an outage, and a probe that took the process out
    # of rotation for running its documented production posture would be wrong.
    assert payload["status"] == "ok"


def test_healthz_reports_a_database_outage_instead_of_crashing(
    build_rig: Callable[..., Rig],
) -> None:
    """The app is built before the database is reached, so an outage is reportable.

    A process that failed to start during a Postgres blip would take the whole
    deployment down with it and report nothing about why.
    """
    from api.config import ApiConfig

    dead = ApiConfig(
        database_url="postgresql+psycopg://nobody:nobody@127.0.0.1:1/nothing"
    )
    payload = build_rig(config=dead).client.get("/healthz").json()

    assert payload["status"] == "degraded"
    assert payload["database"] == "down"


def test_interactive_docs_are_not_served(rig: Rig) -> None:
    """Swagger UI pulls its assets from a CDN, which this page's CSP forbids."""
    assert rig.client.get("/docs").status_code == 404
    assert rig.client.get("/redoc").status_code == 404


def test_uuid_shaped_garbage_on_the_authenticated_route_is_not_a_500(
    rig: Rig,
) -> None:
    """FastAPI's own validation answers 422 before any of our code runs."""
    response = rig.client.get(
        f"/api/me/invoices/{uuid.uuid4()}x", headers={"Authorization": "tma nope"}
    )
    assert response.status_code in (401, 422)
