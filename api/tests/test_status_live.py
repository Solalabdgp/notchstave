"""The live status line, read from a real ledger.

TZ 3.2 asks for the four-rung ladder — *"ожидает оплаты -> увидели транзакцию,
N/M подтверждений -> оплачено -> доступ выдан"* — and TZ section 4 says the api
*"только читает то, что settler уже решил"*. Both are testable only against real
rows, so every test here writes ``payments`` / ``invoices`` / ``entitlements``
and then asks the endpoint what it says.

The confirmation count is the one arithmetic the api performs, and it is copied
from the settler rather than invented::

    confirmations = max(0, chains.last_indexed_block - payments.block_number + 1)

A page that says ``3/3`` while the settler still thinks a payment is one short
is a buyer who believes they have been robbed, so the sharpest test in this file
is the one that pins that expression against the head block.
"""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from typing import Any

import psycopg
import pytest

from api.stages import Stage
from api.tests.conftest import Rig, Seeded
from core.db import enums as E


def _status(rig: Rig, seeded: Seeded) -> dict[str, Any]:
    response = rig.client.get(f"/api/invoices/by-token/{seeded.token}/status")
    assert response.status_code == 200, response.text
    payload: dict[str, Any] = response.json()
    return payload


# ---------------------------------------------------------------------------
# The ladder
# ---------------------------------------------------------------------------


def test_a_fresh_invoice_is_awaiting_payment(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    seeded = seed()

    payload = _status(rig, seeded)

    assert payload["stage"] == Stage.AWAITING
    assert payload["confirmations"] is None
    assert payload["payments"] == []
    assert payload["amount_paid_raw"] == "0"
    assert payload["amount_outstanding_raw"] == str(int(seeded.view.amount_due_raw))


def test_a_seen_payment_shows_the_n_of_m_line(
    rig: Rig, seed: Callable[..., Seeded], pay: Callable[..., int]
) -> None:
    """Rung two, and the count is measured against the watcher's head block."""
    seeded = seed(head_block=100)
    pay(seeded=seeded, amount_raw=seeded.view.amount_due_raw, block_number=98)

    payload = _status(rig, seeded)

    assert payload["stage"] == Stage.CONFIRMING
    # 100 - 98 + 1 — the settler's expression, character for character.
    assert payload["confirmations"] == 3
    assert payload["required_confirmations"] >= 1
    assert len(payload["payments"]) == 1
    assert payload["payments"][0]["confirmations"] == 3


def test_the_count_tracks_the_head_block(
    rig: Rig,
    seed: Callable[..., Seeded],
    pay: Callable[..., int],
    conn: psycopg.Connection[Any],
) -> None:
    """Advancing the watcher advances the page, by exactly one per block."""
    seeded = seed(head_block=100)
    pay(seeded=seeded, amount_raw=seeded.view.amount_due_raw, block_number=100)

    assert _status(rig, seeded)["confirmations"] == 1

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE chains SET last_indexed_block = 104 WHERE chain_id = %(c)s",
            {"c": seeded.view.chain_id},
        )
    conn.commit()

    assert _status(rig, seeded)["confirmations"] == 5


def test_the_count_never_runs_ahead_of_the_watcher(
    rig: Rig, seed: Callable[..., Seeded], pay: Callable[..., int]
) -> None:
    """A payment in a block the watcher has not reached is zero, not negative.

    The head is the watcher's head, not the network's, so a lagging watcher
    makes the page show *fewer* confirmations than the chain has. That is the
    conservative direction: a page that ran ahead would promise access the
    settler has not granted.
    """
    seeded = seed(head_block=100)
    pay(seeded=seeded, amount_raw=seeded.view.amount_due_raw, block_number=140)

    assert _status(rig, seeded)["confirmations"] == 0


def test_two_pending_payments_report_the_slower_one(
    rig: Rig, seed: Callable[..., Seeded], pay: Callable[..., int]
) -> None:
    """The minimum, not the maximum.

    With two transfers against one invoice the buyer is waiting on the later
    one; showing the earlier one's count promises a credit that is not coming
    yet.
    """
    seeded = seed(head_block=100)
    half = Decimal(seeded.view.amount_due_raw) / 2
    pay(seeded=seeded, amount_raw=half, block_number=90)
    pay(seeded=seeded, amount_raw=half, block_number=99)

    payload = _status(rig, seeded)

    assert payload["confirmations"] == 2  # 100 - 99 + 1
    assert len(payload["payments"]) == 2


def test_credited_payments_sum_into_amount_paid(
    rig: Rig, seed: Callable[..., Seeded], pay: Callable[..., int]
) -> None:
    """TZ 5.3: the settled total is a SUM over creditable rows, never a counter."""
    seeded = seed()
    third = Decimal(seeded.view.amount_due_raw) / 4
    pay(
        seeded=seeded,
        amount_raw=third,
        block_number=90,
        status=E.PaymentStatus.CREDITED,
    )
    pay(
        seeded=seeded,
        amount_raw=third,
        block_number=91,
        status=E.PaymentStatus.CONFIRMED,
    )

    payload = _status(rig, seeded)

    assert payload["amount_paid_raw"] == str(int(third * 2))
    assert payload["stage"] == Stage.UNDERPAID


def test_underpaid_reports_what_is_still_owed(
    rig: Rig, seed: Callable[..., Seeded], pay: Callable[..., int]
) -> None:
    """TZ 5.5: the same address stays open for a top-up, so the page says so."""
    seeded = seed()
    due = Decimal(seeded.view.amount_due_raw)
    pay(
        seeded=seeded,
        amount_raw=due / 4,
        block_number=95,
        status=E.PaymentStatus.CREDITED,
    )

    payload = _status(rig, seeded)

    assert payload["stage"] == Stage.UNDERPAID
    assert payload["amount_outstanding_raw"] == str(int(due - due / 4))


def test_overpayment_never_reports_a_negative_outstanding(
    rig: Rig, seed: Callable[..., Seeded], pay: Callable[..., int]
) -> None:
    seeded = seed()
    pay(
        seeded=seeded,
        amount_raw=Decimal(seeded.view.amount_due_raw) * 2,
        block_number=95,
        status=E.PaymentStatus.CREDITED,
    )

    assert _status(rig, seeded)["amount_outstanding_raw"] == "0"


def test_paid_comes_from_the_settlers_verdict_not_from_the_sums(
    rig: Rig,
    seed: Callable[..., Seeded],
    pay: Callable[..., int],
    set_invoice_status: Callable[..., None],
) -> None:
    """Rung three. ``invoices.status`` is the settler's, and the api reads it."""
    seeded = seed()
    pay(
        seeded=seeded,
        amount_raw=seeded.view.amount_due_raw,
        block_number=95,
        status=E.PaymentStatus.CREDITED,
    )
    set_invoice_status(seeded.invoice_id, E.InvoiceStatus.PAID)

    payload = _status(rig, seeded)

    assert payload["stage"] == Stage.PAID
    assert payload["invoice_status"] == "paid"
    assert payload["access_granted"] is False


def test_granted_is_the_last_rung(
    rig: Rig,
    seed: Callable[..., Seeded],
    pay: Callable[..., int],
    set_invoice_status: Callable[..., None],
    grant: Callable[..., None],
) -> None:
    """Rung four, and it lives in ``entitlements`` — not in ``invoices.status``."""
    seeded = seed()
    pay(
        seeded=seeded,
        amount_raw=seeded.view.amount_due_raw,
        block_number=95,
        status=E.PaymentStatus.CREDITED,
    )
    set_invoice_status(seeded.invoice_id, E.InvoiceStatus.PAID)
    grant(seeded)

    payload = _status(rig, seeded)

    assert payload["stage"] == Stage.GRANTED
    assert payload["access_granted"] is True


def test_a_revoked_grant_is_not_a_grant(
    rig: Rig,
    seed: Callable[..., Seeded],
    set_invoice_status: Callable[..., None],
    grant: Callable[..., None],
    conn: psycopg.Connection[Any],
) -> None:
    seeded = seed()
    set_invoice_status(seeded.invoice_id, E.InvoiceStatus.PAID)
    grant(seeded)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE entitlements SET revoked_at = now() WHERE invoice_id = %(id)s",
            {"id": seeded.invoice_id},
        )
    conn.commit()

    payload = _status(rig, seeded)

    assert payload["access_granted"] is False
    assert payload["stage"] == Stage.PAID


# ---------------------------------------------------------------------------
# The branches off the ladder
# ---------------------------------------------------------------------------


def test_manual_review_never_shows_a_confirmation_count(
    rig: Rig,
    seed: Callable[..., Seeded],
    pay: Callable[..., int],
    set_invoice_status: Callable[..., None],
) -> None:
    """A count implies an automatic outcome that is no longer coming.

    The invoice has a pending payment, so the count exists — the assertion is
    that the *stage* does not invite the buyer to wait for it.
    """
    seeded = seed()
    pay(
        seeded=seeded,
        amount_raw=seeded.view.amount_due_raw,
        block_number=99,
        anomaly=E.PaymentAnomaly.WRONG_ASSET,
    )
    set_invoice_status(seeded.invoice_id, E.InvoiceStatus.MANUAL_REVIEW)

    assert _status(rig, seeded)["stage"] == Stage.MANUAL_REVIEW


@pytest.mark.parametrize(
    ("status", "stage"),
    [
        (E.InvoiceStatus.CANCELLED, Stage.CANCELLED),
        (E.InvoiceStatus.REVERTED, Stage.REVERTED),
        (E.InvoiceStatus.EXPIRED, Stage.EXPIRED),
    ],
)
def test_terminal_statuses_reach_the_page(
    rig: Rig,
    seed: Callable[..., Seeded],
    set_invoice_status: Callable[..., None],
    status: E.InvoiceStatus,
    stage: Stage,
) -> None:
    seeded = seed()
    set_invoice_status(seeded.invoice_id, status)

    assert _status(rig, seeded)["stage"] == stage


def test_an_expired_invoice_with_money_against_it_is_still_payable(
    rig: Rig,
    seed: Callable[..., Seeded],
    pay: Callable[..., int],
    set_invoice_status: Callable[..., None],
) -> None:
    """TZ 5.5: the top-up window outlives ``expires_at``.

    Telling this buyer "expired" when the system will still credit them is how a
    support conversation starts — and how a partial payment gets abandoned.
    """
    seeded = seed()
    pay(
        seeded=seeded,
        amount_raw=Decimal(seeded.view.amount_due_raw) / 4,
        block_number=95,
        status=E.PaymentStatus.CREDITED,
    )
    set_invoice_status(seeded.invoice_id, E.InvoiceStatus.EXPIRED)

    assert _status(rig, seeded)["stage"] == Stage.UNDERPAID


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------


def test_the_status_payload_carries_no_address(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """The polled channel must not be able to repaint an address.

    The address is rendered once and the page script never rewrites it — the
    browser-side counterpart of TZ 5.8/T1.5. That guarantee is only real if the
    frequently-polled payload has no address in it to rewrite from.
    """
    seeded = seed()

    response = rig.client.get(f"/api/invoices/by-token/{seeded.token}/status")

    assert seeded.view.address not in response.text
    assert "address" not in response.json()


def test_amounts_are_strings_all_the_way_out(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """``NUMERIC(78,0)`` does not survive a JSON number.

    And the buyer's only available check (TZ 5.8/T1.4) is that the amount reads
    identically in the bot message, on the page and in the EIP-681 string — a
    float in one of them makes "identical" ambiguous.
    """
    seeded = seed()
    payload = _status(rig, seeded)

    for field in ("amount_due_raw", "amount_paid_raw", "amount_outstanding_raw"):
        assert isinstance(payload[field], str), field
        assert "E" not in payload[field]  # never `1E+7`
        assert payload[field].isdigit()


def test_a_huge_amount_survives_postgres_and_the_encoder(
    conn: psycopg.Connection[Any],
) -> None:
    """Past 2^53, where a JSON number silently stops being the same number.

    Eighteen decimals of a native asset puts real invoices in this range, so it
    is not hypothetical. Driven through Postgres rather than a hand-made
    ``Decimal`` because the hazard is what psycopg hands back: a ``NUMERIC``
    whose ``str()`` carries an exponent, which would put ``1E+30`` on the page
    beside a QR containing the digits.
    """
    from api.schemas import _raw

    huge = 10**30 + 7
    with conn.cursor() as cur:
        cur.execute("SELECT %(v)s::numeric(78,0)", {"v": huge})
        row = cur.fetchone()
    conn.rollback()

    assert row is not None
    assert _raw(row[0]) == str(huge)


def test_seconds_until_expiry_is_sent_so_the_page_ignores_the_device_clock(
    rig: Rig, seed: Callable[..., Seeded]
) -> None:
    """A phone an hour fast would otherwise show a live invoice as expired."""
    seeded = seed()
    payload = _status(rig, seeded)

    assert isinstance(payload["seconds_until_expiry"], int)
    assert payload["seconds_until_expiry"] >= 0
    assert payload["expires_at"]


def test_the_json_and_the_page_agree_about_the_stage(
    rig: Rig, seed: Callable[..., Seeded], pay: Callable[..., int]
) -> None:
    """The server-rendered sentence and the polled payload are one source.

    They are produced by different code — an f-string in :mod:`api.page` and a
    Pydantic model in :mod:`api.schemas` — so "they agree" is an assertion, not
    a structural fact.
    """
    seeded = seed(head_block=100)
    pay(seeded=seeded, amount_raw=seeded.view.amount_due_raw, block_number=99)

    payload = _status(rig, seeded)
    body = rig.client.get(f"/i/{seeded.token}").text

    assert f'data-stage="{payload["stage"]}"' in body
    assert f"{payload['confirmations']}/{payload['required_confirmations']}" in body
