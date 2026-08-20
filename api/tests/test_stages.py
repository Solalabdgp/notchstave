"""The stage ladder as a pure function, plus the parity the two renderers need.

:func:`api.stages.stage_of` collapses three tables into the one word a buyer
reads. It is tested here without a database because the ladder has more edges
than it looks like it has, and every edge is a sentence someone reads while
deciding whether they have been robbed. The same ladder is exercised end to end
against real rows in ``test_status_live.py``; this file is where the ordering
decisions themselves are pinned.

The last two tests are about a different hazard: the stage sentence is written
twice, once in :mod:`api.page` for the server-rendered first paint and once in
``static/invoice.js`` for the live updates. Two copies of a vocabulary drift, so
both are checked against the enum.
"""

from __future__ import annotations

import datetime as dt
import re
import uuid
from decimal import Decimal
from pathlib import Path

import pytest

from api.repository import InvoiceProgress, PaymentProgress
from api.stages import Stage, stage_of
from core.db import enums as E

REPO_ROOT = Path(__file__).resolve().parents[2]


def progress(
    *,
    status: str = "awaiting",
    due: int = 1000,
    paid: int = 0,
    pending: int = 0,
    payments: tuple[PaymentProgress, ...] = (),
    access_granted: bool = False,
) -> InvoiceProgress:
    now = dt.datetime.now(dt.UTC)
    return InvoiceProgress(
        invoice_id=uuid.uuid4(),
        status=status,
        expires_at=now + dt.timedelta(minutes=10),
        topup_window_until=now + dt.timedelta(hours=24),
        amount_due_raw=Decimal(due),
        amount_paid_raw=Decimal(paid),
        amount_pending_raw=Decimal(pending),
        required_confirmations=3,
        head_block=100,
        payments=payments,
        access_granted=access_granted,
        settled_at=None,
    )


def payment(*, block: int = 99, amount: int = 1000, status: str = "seen") -> PaymentProgress:
    return PaymentProgress(
        tx_hash="0x" + "ab" * 32,
        amount_raw=Decimal(amount),
        status=status,
        block_number=block,
        confirmations=max(0, 100 - block + 1),
        anomaly=None,
    )


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------


def test_nothing_on_chain_is_awaiting() -> None:
    assert stage_of(progress()) is Stage.AWAITING


def test_something_seen_and_nothing_credited_is_confirming() -> None:
    assert stage_of(progress(payments=(payment(),))) is Stage.CONFIRMING


def test_a_live_grant_outranks_everything() -> None:
    """Including a status that a later reorg flipped.

    A revoked grant clears ``access_granted``; a live one means the product was
    delivered, and telling that buyer their payment was reverted would be false.
    """
    assert (
        stage_of(progress(status="reverted", access_granted=True)) is Stage.GRANTED
    )


@pytest.mark.parametrize(
    ("status", "stage"),
    [
        (E.InvoiceStatus.MANUAL_REVIEW, Stage.MANUAL_REVIEW),
        (E.InvoiceStatus.REVERTED, Stage.REVERTED),
        (E.InvoiceStatus.CANCELLED, Stage.CANCELLED),
    ],
)
def test_terminal_statuses_beat_the_arithmetic(
    status: E.InvoiceStatus, stage: Stage
) -> None:
    """An invoice under manual review must never be shown a confirmation count.

    The count implies an automatic outcome that is no longer coming, so these
    are checked before any sum is looked at — asserted here with a pending
    payment present, which is the case where the order is load-bearing.
    """
    assert stage_of(progress(status=str(status), payments=(payment(),))) is stage


@pytest.mark.parametrize("status", [E.InvoiceStatus.PAID, E.InvoiceStatus.OVERPAID])
def test_the_settlers_paid_verdict_is_not_recomputed(status: E.InvoiceStatus) -> None:
    """Even when the sums would say otherwise. TZ section 4: the api reads."""
    assert stage_of(progress(status=str(status), paid=1)) is Stage.PAID


def test_partial_credit_is_underpaid() -> None:
    assert stage_of(progress(paid=400, due=1000)) is Stage.UNDERPAID


def test_expiry_does_not_close_the_topup_window() -> None:
    """TZ 5.5: an expired invoice with money against it is still payable."""
    assert (
        stage_of(progress(status=str(E.InvoiceStatus.EXPIRED), paid=400, due=1000))
        is Stage.UNDERPAID
    )


def test_expired_with_nothing_against_it_is_expired() -> None:
    assert stage_of(progress(status=str(E.InvoiceStatus.EXPIRED))) is Stage.EXPIRED


def test_fully_credited_without_a_settler_verdict_is_not_yet_paid() -> None:
    """The sums reaching the total does not make it paid — the settler does.

    Deliberately *not* ``PAID``: crediting is the settler's write, and a page
    that promoted itself off the arithmetic would show "paid" during the window
    between the last confirmation and the settler's commit.
    """
    assert stage_of(progress(paid=1000, due=1000)) is not Stage.PAID


# ---------------------------------------------------------------------------
# Confirmations
# ---------------------------------------------------------------------------


def test_confirmations_is_none_when_nothing_is_pending() -> None:
    assert progress().confirmations is None
    assert progress(payments=(payment(status="credited"),)).confirmations is None


def test_confirmations_is_the_minimum_across_pending_payments() -> None:
    """The buyer is waiting on the slower transfer, so that is the one shown."""
    two = progress(payments=(payment(block=90), payment(block=99)))

    assert two.confirmations == 2


def test_outstanding_is_never_negative() -> None:
    assert progress(due=1000, paid=2500).amount_outstanding_raw == 0


# ---------------------------------------------------------------------------
# The two renderers must know the same words
# ---------------------------------------------------------------------------


def test_the_server_renders_a_sentence_for_every_stage() -> None:
    """No stage may fall through to the generic "waiting" line by accident."""
    from api.page import _stage_sentence
    from api.schemas import InvoiceOut, StatusOut

    seen: set[str] = set()
    for stage in Stage:
        status = StatusOut(
            stage=stage,
            invoice_status="awaiting",
            amount_due_raw="1000",
            amount_paid_raw="0",
            amount_outstanding_raw="1000",
            confirmations=1,
            required_confirmations=3,
            expires_at=dt.datetime.now(dt.UTC),
            topup_window_until=dt.datetime.now(dt.UTC),
            seconds_until_expiry=60,
            access_granted=False,
        )
        payload = InvoiceOut(
            invoice_id=str(uuid.uuid4()),
            chain_id=1,
            asset_symbol="USDC",
            asset_decimals=6,
            address="0x" + "ab" * 20,
            amount_due_raw="1000",
            amount_due_display="0.001",
            amount_due_usd="10",
            eip681="ethereum:0x",
            status=status,
        )
        sentence = _stage_sentence(payload)
        assert sentence
        seen.add(sentence)

    # `awaiting` shares the default sentence, so one collision is expected and
    # anything more means two stages are being told the same story.
    assert len(seen) >= len(Stage) - 1


def test_the_page_script_knows_every_stage_the_enum_defines() -> None:
    """``invoice.js`` switches on these strings; a new stage must reach it.

    The alternative to this test is a stage added on the server that renders an
    empty status line at a buyer whose page is polling — which nothing else in
    the suite would catch, because the browser is not under test anywhere else.
    """
    script = (REPO_ROOT / "api" / "static" / "invoice.js").read_text(encoding="utf-8")
    cases = set(re.findall(r"case '([a-z_]+)':", script))

    missing = {str(s) for s in Stage} - cases - {str(Stage.AWAITING)}

    assert not missing, f"invoice.js has no branch for {sorted(missing)}"


def test_the_stage_values_are_a_stable_wire_contract() -> None:
    """The browser compares against these strings, so they are lowercase ASCII."""
    for stage in Stage:
        assert re.fullmatch(r"[a-z_]+", str(stage)), stage
