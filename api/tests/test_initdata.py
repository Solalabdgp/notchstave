"""``initData`` verification — TZ 3.2's "обязательная проверка подписи на бэкенде".

The unit tests here drive :func:`api.telegram.verify_init_data` directly and the
endpoint tests drive it through ``Authorization: tma ...`` on a real route, and
both are needed: the first says the algorithm is Telegram's, the second says the
route actually calls it. A verifier that is correct and unreferenced is the
failure mode this pair exists to catch.

Every signature in this file is produced by :func:`api.tests.conftest
.sign_init_data`, which runs the algorithm forwards in its own code rather than
calling the module under test. If the two ever disagree about the data-check
string, these tests fail instead of agreeing with each other.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
from collections.abc import Callable
from urllib.parse import urlencode

import pytest

from api.telegram import (
    InitDataExpired,
    InitDataMalformed,
    InitDataSignatureInvalid,
    WebAppSecret,
    derive_webapp_secret,
    verify_init_data,
)
from api.tests.conftest import BOT_TOKEN, Rig, Seeded, init_data_fields, sign_init_data, tma


@pytest.fixture
def secret() -> WebAppSecret:
    return derive_webapp_secret(BOT_TOKEN)


def _now() -> int:
    return int(dt.datetime.now(dt.UTC).timestamp())


# ---------------------------------------------------------------------------
# The algorithm
# ---------------------------------------------------------------------------


def test_derivation_is_the_documented_one(secret: WebAppSecret) -> None:
    """``HMAC_SHA256(key="WebAppData", data=<token>)`` — that way round.

    Spelled out as its own test because reversing the two arguments produces a
    validator that is self-consistent and rejects every real Telegram session,
    which is a bug that only shows up against production traffic.
    """
    expected = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    assert secret.raw == expected


def test_valid_signature_yields_the_user_id(secret: WebAppSecret) -> None:
    raw = sign_init_data(secret, init_data_fields(user_id=777_001, auth_date=_now()))

    session = verify_init_data(raw, secret)

    assert session.user_id == 777_001
    assert "hash" not in session.fields


def test_extra_fields_are_covered_by_the_signature(secret: WebAppSecret) -> None:
    """``query_id`` and ``start_param`` survive the round trip and are signed."""
    fields = init_data_fields(
        user_id=42, auth_date=_now(), query_id="AAH1", start_param="prod-7"
    )
    session = verify_init_data(sign_init_data(secret, fields), secret)

    assert session.query_id == "AAH1"
    assert session.start_param == "prod-7"


def test_tampering_with_any_signed_field_is_rejected(secret: WebAppSecret) -> None:
    """The whole point: changing the user id after signing must not verify.

    This is the concrete attack — a buyer editing ``user`` in a captured
    ``initData`` to read somebody else's invoices — and it is why TZ 5.8/T1.7
    filters by the id *inside the verified signature* rather than by an id the
    client sends alongside it.
    """
    fields = init_data_fields(user_id=1, auth_date=_now())
    raw = sign_init_data(secret, fields)

    forged = raw.replace(
        urlencode({"user": fields["user"]}),
        urlencode({"user": json.dumps({"id": 2, "first_name": "Test"})}),
    )

    with pytest.raises(InitDataSignatureInvalid):
        verify_init_data(forged, secret)


def test_signature_from_a_different_bot_is_rejected(secret: WebAppSecret) -> None:
    other = derive_webapp_secret("43:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
    raw = sign_init_data(other, init_data_fields(user_id=5, auth_date=_now()))

    with pytest.raises(InitDataSignatureInvalid):
        verify_init_data(raw, secret)


def test_uppercase_hex_hash_still_verifies(secret: WebAppSecret) -> None:
    """Telegram sends lowercase; a client library that upper-cased it is not forged."""
    fields = init_data_fields(user_id=9, auth_date=_now())
    raw = sign_init_data(secret, fields)
    head, _, digest = raw.rpartition("hash=")

    session = verify_init_data(f"{head}hash={digest.upper()}", secret)

    assert session.user_id == 9


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("", id="empty"),
        pytest.param("user=%7B%22id%22%3A1%7D&auth_date=1", id="no-hash"),
        pytest.param("=&hash=ab", id="no-key"),
    ],
)
def test_unreadable_init_data_is_malformed(raw: str, secret: WebAppSecret) -> None:
    with pytest.raises(InitDataMalformed):
        verify_init_data(raw, secret)


def test_duplicate_field_is_refused_rather_than_guessed(secret: WebAppSecret) -> None:
    """``a=1&a=2`` has two readings and this module must not pick one.

    A parser that kept the last value while a proxy or a client library kept the
    first is a signature that verifies over text the server never saw.
    """
    fields = init_data_fields(user_id=3, auth_date=_now())
    raw = sign_init_data(secret, fields) + "&auth_date=1"

    with pytest.raises(InitDataMalformed):
        verify_init_data(raw, secret)


def test_stale_init_data_is_expired_not_accepted(secret: WebAppSecret) -> None:
    """Freshness is enforced, not merely parsed — see the module docstring.

    Without this, one ``initData`` copied out of a browser console is a
    permanent key to that user's invoices.
    """
    old = _now() - 100_000
    raw = sign_init_data(secret, init_data_fields(user_id=8, auth_date=old))

    with pytest.raises(InitDataExpired):
        verify_init_data(raw, secret, max_age_seconds=86_400)

    # Same string, wider window: genuinely signed, so only the age was wrong.
    assert verify_init_data(raw, secret, max_age_seconds=200_000).user_id == 8


def test_signature_is_checked_before_freshness(secret: WebAppSecret) -> None:
    """Order matters: a forged-and-stale string must not report "expired".

    Reporting expiry first would tell an unauthenticated caller whether a
    timestamp it invented falls inside the window — a small oracle, and a free
    one to close by ordering the checks.
    """
    other = derive_webapp_secret("43:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
    raw = sign_init_data(other, init_data_fields(user_id=8, auth_date=_now() - 100_000))

    with pytest.raises(InitDataSignatureInvalid):
        verify_init_data(raw, secret)


def test_secret_does_not_print_itself(secret: WebAppSecret) -> None:
    """TZ 5.8/T4: key material must not reach a log line or a pytest diff."""
    assert "<redacted>" in repr(secret)
    assert secret.raw.hex() not in repr(secret)
    assert secret.raw.hex() not in str(secret)


# ---------------------------------------------------------------------------
# Through the route
# ---------------------------------------------------------------------------


def test_authenticated_read_returns_the_invoice(rig: Rig, seed: Callable[..., Seeded]) -> None:
    seeded = seed()
    assert rig.deps.webapp_secret is not None
    raw = sign_init_data(
        rig.deps.webapp_secret,
        init_data_fields(user_id=seeded.view.user_id, auth_date=_now()),
    )

    response = rig.client.get(f"/api/me/invoices/{seeded.invoice_id}", headers=tma(raw))

    assert response.status_code == 200
    assert response.json()["address"] == seeded.view.address


def test_bad_signature_is_401_and_reveals_nothing(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    seeded = seed()
    other = derive_webapp_secret("43:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
    raw = sign_init_data(
        other, init_data_fields(user_id=seeded.view.user_id, auth_date=_now())
    )

    response = rig.client.get(f"/api/me/invoices/{seeded.invoice_id}", headers=tma(raw))

    assert response.status_code == 401
    # The operator detail names which check failed and stays in the log; the
    # caller gets the class's user_message and no address.
    assert seeded.view.address not in response.text


def test_missing_header_is_401(rig: Rig, seed: Callable[..., Seeded]) -> None:
    seeded = seed()

    assert rig.client.get(f"/api/me/invoices/{seeded.invoice_id}").status_code == 401


def test_wrong_auth_scheme_is_401(rig: Rig, seed: Callable[..., Seeded]) -> None:
    seeded = seed()
    assert rig.deps.webapp_secret is not None
    raw = sign_init_data(
        rig.deps.webapp_secret,
        init_data_fields(user_id=seeded.view.user_id, auth_date=_now()),
    )

    response = rig.client.get(
        f"/api/me/invoices/{seeded.invoice_id}", headers={"Authorization": f"Bearer {raw}"}
    )

    assert response.status_code == 401


def test_somebody_elses_invoice_is_404_not_403(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """TZ 5.8/T1.7: filtered by the signed ``user_id``, and a miss is a 404.

    A 403 would confirm that the id is real, which is the one bit an enumeration
    attempt is trying to buy. The body must be the same as for an id that never
    existed — asserted against that case here rather than described.
    """
    seeded = seed()
    assert rig.deps.webapp_secret is not None
    intruder = sign_init_data(
        rig.deps.webapp_secret,
        init_data_fields(user_id=seeded.view.user_id + 1, auth_date=_now()),
    )

    theirs = rig.client.get(f"/api/me/invoices/{seeded.invoice_id}", headers=tma(intruder))
    nonexistent = rig.client.get(
        "/api/me/invoices/00000000-0000-7000-8000-000000000000", headers=tma(intruder)
    )

    assert theirs.status_code == 404
    assert nonexistent.status_code == 404
    assert theirs.json() == nonexistent.json()
    assert seeded.view.address not in theirs.text


def test_unconfigured_telegram_is_503_not_401(
    build_rig: Callable[..., Rig], seed: Callable[..., Seeded]
) -> None:
    """A server that cannot check must not tell a correct client it is wrong.

    401 would send a perfectly good Mini App into a re-authentication loop
    against a misconfiguration it cannot fix.
    """
    seeded = seed()
    rig = build_rig(telegram=False)

    response = rig.client.get(
        f"/api/me/invoices/{seeded.invoice_id}", headers=tma("anything")
    )

    assert response.status_code == 503


def test_status_endpoint_applies_the_same_filter(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """The polled endpoint is authorized too, not just the initial read.

    An endpoint that a page hits every two seconds is exactly the one a reviewer
    forgets, and it returns the same invoice.
    """
    seeded = seed()
    assert rig.deps.webapp_secret is not None
    intruder = sign_init_data(
        rig.deps.webapp_secret,
        init_data_fields(user_id=seeded.view.user_id + 1, auth_date=_now()),
    )

    response = rig.client.get(
        f"/api/me/invoices/{seeded.invoice_id}/status", headers=tma(intruder)
    )

    assert response.status_code == 404
