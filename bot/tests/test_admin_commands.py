"""TZ 3.4 — the four owner commands, and who cannot reach them.

The access control being tested is one integer compared to
:attr:`bot.config.BotConfig.owner_tg_id`, and TZ 5.8/T7 is explicit that this
does nothing about a *captured* owner account. What it does do is keep everyone
else out, and there are three ways that goes wrong quietly:

1. The check is written on three of four commands. Hence a parametrised test
   over the literal command list rather than four hand-written ones — adding a
   fifth command without a check makes the list wrong in a visible way.
2. The refusal *differs* from the unknown-command answer, which confirms to
   whoever is probing that ``/resolve`` exists and therefore that there is an
   owner account worth phishing.
3. The denial happens after the service call rather than before it. Every test
   here asserts on :attr:`FakeAdminOps.calls` being empty, because a check that
   runs but does not stop anything is the worst of both.

The money behind these commands is not retested here — ``settler/tests``
covers the two-step threshold, the CAS on ``resolved_at``, the entitlement
insert and the audit row against a real database. What the bot owes is argument
parsing and the boundary, and that is what is below.
"""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from bot import texts
from bot.tests.conftest import (
    BUYER_TG_ID,
    OWNER_TG_ID,
    Harness,
    Shop,
    make_invoice,
    make_user,
)
from settler.admin.errors import (
    ConfirmationRequired,
    InvalidConfirmationCode,
    ReviewAlreadyResolved,
    ReviewNotFound,
)
from settler.admin.reconcile import AddressDrift, ReconcileReport
from settler.admin.reviews import PendingCase, ResolutionOutcome, ResolutionResult
from settler.admin.sweeplist import SweepExport

#: Exactly the commands of TZ 3.4. Written out so that the "denied" tests below
#: are a statement about the section, not about whatever happens to be
#: registered.
ADMIN_COMMANDS = [
    "/pending",
    "/resolve 1 credit",
    "/sweeplist",
    "/reconcile",
]


def a_pending_case(review_id: int = 1, invoice_id: uuid.UUID | None = None) -> PendingCase:
    return PendingCase(
        review_id=review_id,
        kind="underpaid",
        invoice_id=invoice_id or uuid.uuid4(),
        payment_id=None,
        opened_at=dt.datetime.now(dt.UTC),
        note="short by 4 USDC",
        policy_version="test-policy",
        invoice_status="manual_review",
        user_id=1,
        asset_symbol="USDC",
        asset_decimals=6,
        amount_due_raw=Decimal(10_000_000),
        amount_due_usd=Decimal("10"),
        received_raw=Decimal(6_000_000),
    )


def a_resolution(review_id: int = 1, **kw: object) -> ResolutionResult:
    base: dict[str, object] = {
        "review_id": review_id,
        "resolution": "credit",
        "outcome": ResolutionOutcome.CREDITED,
        "invoice_id": uuid.uuid4(),
        "operator_id": OWNER_TG_ID,
        "amount_usd": Decimal("10"),
        "policy_version": "test-policy",
        "audit_id": 7,
        "entitlement_id": 3,
        "invoice_status_after": "paid",
    }
    base.update(kw)
    return ResolutionResult(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The boundary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", ADMIN_COMMANDS)
async def test_a_non_owner_is_denied_and_the_service_is_never_called(
    harness: Harness, command: str
) -> None:
    reply = await harness.send(command, tg_id=BUYER_TG_ID)

    assert harness.admin.calls == [], f"{command} reached AdminOps for a non-owner"
    assert reply == texts.admin_denied()


@pytest.mark.parametrize("command", ADMIN_COMMANDS)
async def test_the_denial_is_indistinguishable_from_an_unknown_command(
    harness: Harness, command: str
) -> None:
    """TZ 5.8/T7 — do not confirm that an owner account exists.

    ``/help`` does not list these commands either, which the buyer suite checks;
    together the two mean a prober learns nothing from trying.
    """
    denied = await harness.send(command, tg_id=BUYER_TG_ID)
    unknown = await harness.send("/definitely-not-a-command", tg_id=BUYER_TG_ID)

    assert denied == unknown


@pytest.mark.parametrize("command", ADMIN_COMMANDS)
async def test_an_unconfigured_owner_disables_the_commands_for_everyone(
    ownerless: Harness, command: str
) -> None:
    """``BOT_OWNER_TG_ID`` unset is the fresh-checkout state and fails closed.

    The failure this forecloses is a deployment where the variable was
    forgotten and ``/resolve credit`` therefore answered to the first person who
    tried it.
    """
    denied = await ownerless.send(command, tg_id=OWNER_TG_ID)

    assert ownerless.admin.calls == []
    assert denied == texts.admin_denied()


# ---------------------------------------------------------------------------
# /pending
# ---------------------------------------------------------------------------


async def test_pending_lists_the_open_cases_for_the_owner(harness: Harness) -> None:
    invoice_id = uuid.uuid4()
    harness.admin.pending_cases = (a_pending_case(invoice_id=invoice_id),)

    reply = await harness.send("/pending", tg_id=OWNER_TG_ID)

    assert harness.admin.calls == [("pending", {"limit": 200})]
    assert "#1" in reply
    assert "underpaid" in reply
    assert str(invoice_id) in reply
    # Human and exact both, never rounded (see bot/admin_texts.py).
    assert "due 10 USDC, received 6 USDC" in reply


async def test_pending_with_nothing_open(harness: Harness) -> None:
    reply = await harness.send("/pending", tg_id=OWNER_TG_ID)
    assert reply == "No open cases."


# ---------------------------------------------------------------------------
# /resolve
# ---------------------------------------------------------------------------


async def test_resolve_by_case_number_forwards_verb_operator_and_comment(
    harness: Harness,
) -> None:
    harness.admin.resolution = a_resolution(review_id=42)

    reply = await harness.send(
        "/resolve 42 credit paid by hand after support call", tg_id=OWNER_TG_ID
    )

    assert harness.admin.calls == [
        (
            "resolve",
            {
                "review_id": 42,
                "resolution": "credit",
                # The *configured* owner id, not anything parsed from the text.
                "operator_id": OWNER_TG_ID,
                "comment": "paid by hand after support call",
                "confirmation_code": None,
            },
        )
    ]
    assert "Case #42" in reply
    assert "Entitlement granted: 3" in reply


async def test_resolve_by_invoice_id_looks_up_the_single_open_case(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """TZ 3.4 spells the command with an invoice id; AdminOps takes a case id."""
    import sqlalchemy as sa

    user_id = await make_user(engine, BUYER_TG_ID)
    invoice_id, _ = await make_invoice(
        engine, shop, user_id=user_id, index=31, status="manual_review"
    )
    async with engine.begin() as conn:
        review_id = int(
            (
                await conn.execute(
                    sa.text(
                        """
                        INSERT INTO manual_reviews (invoice_id, kind, opened_at, policy_version)
                        VALUES (:invoice_id, CAST('underpaid' AS manual_review_kind),
                                now(), 'test-policy')
                        RETURNING id
                        """
                    ),
                    {"invoice_id": invoice_id},
                )
            ).scalar_one()
        )
    harness.admin.resolution = a_resolution(review_id=review_id)

    await harness.send(f"/resolve {invoice_id} reject", tg_id=OWNER_TG_ID)

    assert harness.admin.calls[0][1]["review_id"] == review_id
    assert harness.admin.calls[0][1]["resolution"] == "reject"


async def test_resolve_refuses_when_one_invoice_has_two_open_cases(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """Picking for the owner would close a decision nobody made (TZ 3.4)."""
    import sqlalchemy as sa

    user_id = await make_user(engine, BUYER_TG_ID)
    invoice_id, _ = await make_invoice(
        engine, shop, user_id=user_id, index=32, status="manual_review"
    )
    async with engine.begin() as conn:
        for kind in ("underpaid", "wrong_asset"):
            await conn.execute(
                sa.text(
                    """
                    INSERT INTO manual_reviews (invoice_id, kind, opened_at, policy_version)
                    VALUES (:invoice_id, CAST(:kind AS manual_review_kind), now(), 'p')
                    """
                ),
                {"invoice_id": invoice_id, "kind": kind},
            )

    reply = await harness.send(f"/resolve {invoice_id} credit", tg_id=OWNER_TG_ID)

    assert harness.admin.calls == []
    assert "2 open cases" in reply
    assert "underpaid" in reply and "wrong_asset" in reply


async def test_resolve_on_an_invoice_with_no_open_case(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    user_id = await make_user(engine, BUYER_TG_ID)
    invoice_id, _ = await make_invoice(engine, shop, user_id=user_id, index=33)

    reply = await harness.send(f"/resolve {invoice_id} credit", tg_id=OWNER_TG_ID)

    assert harness.admin.calls == []
    assert "No open case" in reply


@pytest.mark.parametrize(
    "args",
    ["", "42", "42 approve", "not-a-uuid credit", "42 CREDITS"],
    ids=["empty", "no-verb", "bad-verb", "bad-target", "typo-verb"],
)
async def test_resolve_with_unusable_arguments_shows_usage_and_calls_nothing(
    harness: Harness, args: str
) -> None:
    reply = await harness.send(f"/resolve {args}".strip(), tg_id=OWNER_TG_ID)

    assert harness.admin.calls == []
    assert "Usage" in reply


async def test_resolve_extracts_a_named_confirmation_code_and_strips_it_from_the_comment(
    harness: Harness,
) -> None:
    """``code=`` is a named token, not a positional one.

    Positional would make a one-word comment indistinguishable from a code,
    which is how an owner credits two hundred dollars by writing "urgent".
    """
    harness.admin.resolution = a_resolution(review_id=5)

    await harness.send(
        "/resolve 5 credit urgent code=ABCD1234 refund promised", tg_id=OWNER_TG_ID
    )

    call = harness.admin.calls[0][1]
    assert call["confirmation_code"] == "ABCD1234"
    # No gap left where the code was: the comment is written to `audit_log.note`
    # and a double space there is a permanent marker of a redacted token.
    assert call["comment"] == "urgent refund promised"


async def test_a_one_word_comment_is_not_mistaken_for_a_confirmation_code(
    harness: Harness,
) -> None:
    harness.admin.resolution = a_resolution(review_id=5)

    await harness.send("/resolve 5 credit urgent", tg_id=OWNER_TG_ID)

    call = harness.admin.calls[0][1]
    assert call["confirmation_code"] is None
    assert call["comment"] == "urgent"


async def test_confirmation_required_renders_the_code_and_says_nothing_happened(
    harness: Harness,
) -> None:
    """TZ 5.8/T7's two-step, second half.

    The exception is raised *after* the commit that recorded the attempt, so
    this message is a control and not a dead end — and it has to say that
    nothing was credited, because an owner who assumes otherwise re-sends.
    """
    harness.admin.resolve_error = ConfirmationRequired(
        review_id=9,
        code="ZZZZ9999",
        amount_usd=Decimal("240"),
        limit_usd=Decimal("100"),
        ttl_seconds=300,
    )

    reply = await harness.send("/resolve 9 credit", tg_id=OWNER_TG_ID)

    assert "ZZZZ9999" in reply
    assert "$240.00" in reply
    assert "$100.00" in reply
    assert "Nothing has been credited yet" in reply


async def test_a_stale_confirmation_code_is_refused_without_a_second_chance_message(
    harness: Harness,
) -> None:
    harness.admin.resolve_error = InvalidConfirmationCode("code does not match")

    reply = await harness.send("/resolve 9 credit code=WRONG123", tg_id=OWNER_TG_ID)

    assert "does not belong to this decision" in reply


async def test_an_already_resolved_case_says_the_decision_did_not_take_effect(
    harness: Harness,
) -> None:
    """The CAS on ``resolved_at`` lost. Silence here would read as success."""
    harness.admin.resolve_error = ReviewAlreadyResolved("already resolved")

    reply = await harness.send("/resolve 9 credit", tg_id=OWNER_TG_ID)

    assert "did <b>not</b> take effect" in reply


async def test_a_missing_case_number_is_reported_as_such(harness: Harness) -> None:
    harness.admin.resolve_error = ReviewNotFound("no review 9999")

    reply = await harness.send("/resolve 9999 credit", tg_id=OWNER_TG_ID)

    assert "No open case" in reply


async def test_a_refund_resolution_says_plainly_that_nothing_was_sent(
    harness: Harness,
) -> None:
    """TZ 12 — this repository cannot build, sign or broadcast a transaction."""
    harness.admin.resolution = a_resolution(
        review_id=11,
        resolution="refund",
        outcome=ResolutionOutcome.REFUND_REQUESTED,
        entitlement_id=None,
        refund_id=4,
    )

    reply = await harness.send("/resolve 11 refund wrong network", tg_id=OWNER_TG_ID)

    assert "Nothing has been sent" in reply
    assert "cannot send funds" in reply


# ---------------------------------------------------------------------------
# /sweeplist and /reconcile
# ---------------------------------------------------------------------------


async def test_sweeplist_sends_the_csv_as_a_document(
    harness: Harness, shop: Shop
) -> None:
    """TZ 3.4: *"Это всё, что бот делает для вывода средств."*"""
    harness.admin.sweep_result = SweepExport(
        export_id=3,
        generated_at=dt.datetime.now(dt.UTC),
        chain_id=shop.chain_id,
        asset_id=shop.asset_id,
        asset_symbol="USDC",
        file_ref="sweep.csv",
        rows=(),
        candidates_checked=5,
        total_raw=Decimal(25_000_000),
        total_usd=Decimal("25"),
        csv_text="address,balance_raw\n",
        audit_id=8,
        policy_version="test-policy",
    )

    caption = await harness.send("/sweeplist", tg_id=OWNER_TG_ID)

    documents = harness.session.documents
    assert len(documents) == 1
    call = harness.admin.calls[0]
    assert call[0] == "sweeplist"
    assert call[1]["chain_id"] == shop.chain_id
    assert call[1]["asset_id"] == shop.asset_id
    assert call[1]["operator_id"] == OWNER_TG_ID
    # The filename recorded in `sweep_exports` is the one attached, decided
    # before the send because the export row commits before Telegram is asked.
    assert call[1]["file_ref"] == documents[0].document.filename  # type: ignore[union-attr]
    assert "no key here" in caption


async def test_sweeplist_without_a_balance_source_says_so_instead_of_reporting_zero(
    harness: Harness,
) -> None:
    """Reconciling against nothing reads as "the money is gone" (TZ section 7)."""
    object.__setattr__(harness.services, "balances", None)

    reply = await harness.send("/sweeplist", tg_id=OWNER_TG_ID)

    assert harness.admin.calls == []
    assert "not available to this process" in reply


async def test_reconcile_reports_a_clean_ledger(harness: Harness, shop: Shop) -> None:
    harness.admin.reconcile_result = ReconcileReport(
        chain_id=shop.chain_id,
        asset_id=shop.asset_id,
        asset_symbol="USDC",
        checked=(
            AddressDrift(
                address_id=1,
                address="0x" + "aa" * 20,
                derivation_index=0,
                expected_raw=Decimal(10_000_000),
                actual_raw=Decimal(10_000_000),
                address_status="funded",
                swept_at=None,
            ),
        ),
        total_expected_raw=Decimal(10_000_000),
        total_actual_raw=Decimal(10_000_000),
        threshold_usd=Decimal("20"),
    )

    reply = await harness.send("/reconcile", tg_id=OWNER_TG_ID)

    assert harness.admin.calls[0][0] == "reconcile"
    assert "No drift" in reply


async def test_reconcile_names_a_drift_as_a_bug_signal(
    harness: Harness, shop: Shop
) -> None:
    """TZ 3.4: *"расхождение — сигнал бага, а не повод подправить цифру руками"*.

    The sentence is in the message rather than only in the runbook, because the
    wrong instinct on reading a drift is to correct the ledger and the person
    reading it at three in the morning is the one who can.
    """
    harness.admin.reconcile_result = ReconcileReport(
        chain_id=shop.chain_id,
        asset_id=shop.asset_id,
        asset_symbol="USDC",
        checked=(
            AddressDrift(
                address_id=1,
                address="0x" + "bb" * 20,
                derivation_index=4,
                expected_raw=Decimal(10_000_000),
                actual_raw=Decimal(2_000_000),
                address_status="funded",
                swept_at=None,
            ),
        ),
        total_expected_raw=Decimal(10_000_000),
        total_actual_raw=Decimal(2_000_000),
        absolute_drift_raw=Decimal(8_000_000),
        drift_usd=Decimal("8"),
        rate_source="latest_invoice_snapshot",
        threshold_usd=Decimal("5"),
        manual_review_ids=(12,),
    )

    reply = await harness.send("/reconcile", tg_id=OWNER_TG_ID)

    assert "Drift on 1 address(es)" in reply
    assert "bug signal, not a number" in reply
    assert "#12" in reply


async def test_reconcile_that_cannot_price_the_drift_reports_that_it_failed(
    harness: Harness,
) -> None:
    """Defaulting to a rate of 1 or 0 would invent an alert or silence one."""
    harness.admin.reconcile_error = RuntimeError("no usable rate snapshot")

    reply = await harness.send("/reconcile", tg_id=OWNER_TG_ID)

    assert "could not complete" in reply
    assert "no usable rate snapshot" in reply
