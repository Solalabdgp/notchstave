"""S-C3: the notifier does not trust `payload["address"]` on its own.

The Phase-2 security review's Critical finding: migration 0002 gave
``notchstave_api`` — the one internet-facing process — ``INSERT`` on
``notifications``, which it never legitimately uses. A compromised ``api``
could INSERT an ``invoice_underpaid`` row carrying an attacker's own address,
and until this fix the notifier would render and send it verbatim. Migration
0010 revokes the grant (the necessary fix, exercised by
``settler/tests/test_login_roles.py``'s new ``api``/``notifications`` DENIED
cases); this suite exercises the sufficient one — the notifier independently
checks ``payload["address"]`` against ``invoices.address_id -> receive_
addresses.address`` before sending, regardless of who wrote the row or how.

Two things this suite is careful to prove together, not separately: a forged
address is refused *and* a legitimate one still goes through exactly as
before. A suite that only tested the refusal could pass against a notifier
that refuses to send anything.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncEngine

from core.metrics import address_mismatch_total
from notifier.config import NotifierConfig
from notifier.ratelimit import NullRateLimiter
from notifier.sender import RecordingSender
from notifier.service import Notifier
from notifier.tests.conftest import Outbox, sample_value

CONFIG = NotifierConfig(max_attempts=3, backoff_jitter=0.0)


def build(engine: AsyncEngine, sender: RecordingSender) -> Notifier:
    return Notifier(engine, sender=sender, limiter=NullRateLimiter(), config=CONFIG)


def _underpaid_payload(invoice_id: str, address: str) -> dict[str, object]:
    return {
        "invoice_id": invoice_id,
        "outcome": "partially_paid",
        "address": address,
        "asset": "USDC",
        "decimals": 6,
        "amount_due_raw": "1000000",
        "amount_paid_raw": "500000",
        "missing_raw": "500000",
        "topup_window_until": "2026-08-22T00:00:00+00:00",
        "policy_version": "v1",
    }


async def test_a_forged_address_is_never_sent(engine: AsyncEngine, outbox: Outbox) -> None:
    """The exact S-C3 exploit: a row whose address is not the invoice's own."""
    invoice_id, real_address = await outbox.invoice()
    attacker_address = "0x" + "ba" * 20

    user_id = await outbox.user()
    notification_id = await outbox.enqueue(
        user_id=user_id,
        kind="invoice_underpaid",
        ref_id=invoice_id,
        payload=_underpaid_payload(invoice_id, attacker_address),
    )

    before = sample_value(address_mismatch_total)
    sender = RecordingSender()
    result = await build(engine, sender).run_once()

    assert result.sent == 0
    assert result.dead == 1
    assert sender.sent == [], "the attacker's address must never reach Telegram"

    row = await outbox.row(notification_id)
    assert row["status"] == "dead"
    assert "address_mismatch" in row["last_error"]
    assert real_address != attacker_address, "sanity: the fixture's address must differ"

    assert sample_value(address_mismatch_total) == before + 1.0


async def test_a_forged_address_is_audited_as_suspected_compromise(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    invoice_id, _real_address = await outbox.invoice()
    user_id = await outbox.user()
    await outbox.enqueue(
        user_id=user_id,
        kind="invoice_underpaid",
        ref_id=invoice_id,
        payload=_underpaid_payload(invoice_id, "0x" + "cd" * 20),
    )

    await build(engine, RecordingSender()).run_once()

    # `_retire` writes one `notifier_dlq` audit row for every DLQ entry
    # regardless of reason; the reason itself is inside `args_json`/`last_error`
    # and is what a human reads to tell "address mismatch" apart from
    # "retries exhausted" or "no renderer".
    assert await outbox.audit_count("notifier_dlq") == 1


async def test_a_genuine_address_is_delivered_exactly_as_before(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """Regression: the S-C3 check must not touch the legitimate path."""
    invoice_id, real_address = await outbox.invoice()
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(
        user_id=user_id,
        kind="invoice_underpaid",
        ref_id=invoice_id,
        payload=_underpaid_payload(invoice_id, real_address),
    )

    before = sample_value(address_mismatch_total)
    sender = RecordingSender()
    result = await build(engine, sender).run_once()

    assert result.sent == 1
    assert result.dead == 0
    assert len(sender.sent) == 1
    assert real_address in sender.sent[0].text
    assert await outbox.status(notification_id) == "sent"

    # The legitimate path must not move the T1 alarm.
    assert sample_value(address_mismatch_total) == before


async def test_an_invoice_that_does_not_exist_is_refused_not_guessed(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """No ledger row to check against is treated the same as a proven mismatch.

    TZ 5.3's rule is "no address reaches a human without a check" — "cannot be
    checked" and "checked and wrong" both fail the rule.
    """
    user_id = await outbox.user()
    fake_invoice_id = str(uuid.uuid4())
    notification_id = await outbox.enqueue(
        user_id=user_id,
        kind="invoice_underpaid",
        ref_id=fake_invoice_id,
        payload=_underpaid_payload(fake_invoice_id, "0x" + "11" * 20),
    )

    result = await build(engine, RecordingSender()).run_once()

    assert result.dead == 1
    row = await outbox.row(notification_id)
    assert "address_mismatch" in row["last_error"]


async def test_a_malformed_ref_id_is_refused_not_a_crash(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """`ref_id` is attacker-controlled text (VARCHAR(64)), not trusted to parse."""
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(
        user_id=user_id,
        kind="invoice_underpaid",
        ref_id="not-a-uuid",
        payload=_underpaid_payload("not-a-uuid", "0x" + "22" * 20),
    )

    result = await build(engine, RecordingSender()).run_once()

    assert result.dead == 1
    row = await outbox.row(notification_id)
    assert "address_mismatch" in row["last_error"]


async def test_kinds_that_never_render_an_address_are_not_checked_at_all(
    engine: AsyncEngine, outbox: Outbox
) -> None:
    """The check is scoped to kinds that display an address, not every row.

    ``invoice_settled`` never mentions an address (see ``notifier/render.py``),
    so a `ref_id` that resolves to nothing must not block it — narrowing the
    check to `ADDRESS_SENSITIVE_KINDS` is what keeps this a targeted S-C3 fix
    rather than a change to every notification's behaviour.
    """
    user_id = await outbox.user()
    notification_id = await outbox.enqueue(
        user_id=user_id,
        kind="invoice_settled",
        ref_id="also-not-a-uuid-and-that-is-fine-here",
        payload={"invoice_id": "inv-1", "outcome": "paid"},
    )

    sender = RecordingSender()
    result = await build(engine, sender).run_once()

    assert result.sent == 1
    assert len(sender.sent) == 1
    assert await outbox.status(notification_id) == "sent"
