"""`/pending` and `/resolve` — the three doors out of a manual review (TZ 3.4, 5.5, 5.8/T7, T8).

Every case here is built by running the **real** settler over a real underpayment
until it parks the invoice in ``manual_review``, rather than by inserting a
``manual_reviews`` row directly. That costs three lines per test and buys the
thing that matters: the case under resolution is shaped exactly as production
shapes it, including the opening note, the opening ``policy_version`` and the
invoice status the settler chose. A hand-written case would let a resolution
pass against a case that cannot occur.
"""

from __future__ import annotations

import datetime as dt
from decimal import Decimal
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from core.db import enums as E
from settler.admin.errors import (
    ConfirmationRequired,
    ConfirmationUnavailable,
    InvalidConfirmationCode,
    ResolutionNotApplicable,
    ReviewAlreadyResolved,
    ReviewNotFound,
)
from settler.admin.ops import AdminOps
from settler.admin.policy import AdminPolicy
from settler.admin.reviews import ResolutionOutcome, list_pending, resolve_manual_review
from settler.admin.twostep import ConfirmationKey
from settler.policy import Outcome
from settler.service import settle_invoice
from settler.tests.conftest import (
    Scenario,
    World,
    count,
    invoice_status,
    payment_status,
    sample_value,
)

USDC = 1_000_000
OPERATOR = 770_001

#: A key that exists only in this file. TZ section 9 puts the real one in
#: systemd credentials for the settler unit alone.
KEY = ConfirmationKey(b"test-confirmation-key")

#: Deadlines that put an invoice past its top-up window without sleeping.
#: ``dict[str, Any]`` rather than ``dict[str, timedelta]``: mypy checks a ``**``
#: expansion against *every* parameter of the callee, so a precisely-typed
#: mapping is rejected by the parameters it does not supply.
CLOSED_WINDOW: dict[str, Any] = {
    "age": dt.timedelta(minutes=30),
    "expires_in": dt.timedelta(minutes=15),
    "topup_window": dt.timedelta(0),
}


async def _underpaid_case(
    conn: AsyncConnection,
    world: World,
    *,
    due_raw: int = 10 * USDC,
    paid_raw: int = 4 * USDC,
    amount_due_usd: str = "10",
) -> tuple[Scenario, int]:
    """An invoice short of its bill with the top-up window closed (TZ 5.5.3).

    Returns the scenario and the id of the case the settler opened. "Автоматиче-
    ски не зачитывается никогда" — so the only way out is `/resolve`, which is
    what every test below then takes.
    """
    scenario = await world.scenario(
        amount_due_raw=due_raw, amount_due_usd=amount_due_usd, **CLOSED_WINDOW
    )
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=paid_raw,
        block_number=90,
    )
    result = await settle_invoice(conn, scenario.invoice_id)
    assert result.outcome is Outcome.UNDERPAID_MANUAL_REVIEW
    assert result.manual_review_ids, "the settler must open a case it refuses to decide"
    return scenario, result.manual_review_ids[0]


# ---------------------------------------------------------------------------
# credit
# ---------------------------------------------------------------------------


async def test_credit_hands_over_the_product_and_closes_the_case(
    conn: AsyncConnection, world: World
) -> None:
    scenario, review_id = await _underpaid_case(conn, world)

    result = await resolve_manual_review(
        conn, review_id, "credit", OPERATOR, "goodwill, exchange ate the fee"
    )

    assert result.outcome is ResolutionOutcome.CREDITED
    assert result.entitlement_id is not None
    assert await invoice_status(conn, scenario.invoice_id) == str(E.InvoiceStatus.PAID)
    assert await count(conn, "entitlements", "revoked_at IS NULL") == 1
    assert await count(conn, "manual_reviews", "resolved_at IS NOT NULL") == 1
    # The buyer is told, through the same outbox the automatic path uses.
    assert await count(conn, "notifications", "kind = 'invoice_manual_credit'") == 1
    # And the money on the invoice is marked credited, so the ledger and the
    # decision agree — which is what `/reconcile` will later check.
    assert await count(conn, "payments", "status = 'credited'") == 1


async def test_credit_leaves_a_foreign_token_in_its_own_case(
    conn: AsyncConnection, world: World
) -> None:
    """Crediting an invoice decides about *that invoice*, not about everything near it.

    A stray USDT transfer to the same address is a separate row of the TZ 5.5
    anomaly table with its own open case. Sweeping it into a `/resolve credit` on
    the invoice would close a case nobody decided — and would mark as credited a
    payment in an asset the invoice was never denominated in.
    """
    from settler.service import review_anomalous_payments

    scenario, review_id = await _underpaid_case(conn, world)
    usdt_id = await world.asset(scenario.chain_id, symbol="USDT", decimals=6)
    stray = await world.payment(
        chain_id=scenario.chain_id,
        asset_id=usdt_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=50 * USDC,
        block_number=90,
        anomaly=E.PaymentAnomaly.WRONG_ASSET,
    )
    await review_anomalous_payments(conn)

    result = await resolve_manual_review(conn, review_id, "credit", OPERATOR)

    assert result.outcome is ResolutionOutcome.CREDITED
    assert stray not in result.credited_payment_ids
    assert await payment_status(conn, stray) == str(E.PaymentStatus.SEEN)
    still_open = await count(
        conn, "manual_reviews", "resolved_at IS NULL AND payment_id = :p", p=stray
    )
    assert still_open == 1


# ---------------------------------------------------------------------------
# refund
# ---------------------------------------------------------------------------


async def test_refund_records_an_obligation_and_sends_nothing(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 12 in one assertion: a row appears, and no transfer exists to make.

    ``to_address`` staying NULL is not an omission — TZ 5.5 says the sender
    address is not a refund address ("если деньги пришли с биржевого адреса,
    возврат на него в лучшем случае потеряется, в худшем — уйдёт чужому
    человеку"), so the destination is asked from the buyer and the
    ``executed_requires_details`` CHECK makes it impossible to mark the refund
    executed without one.
    """
    scenario, review_id = await _underpaid_case(conn, world, paid_raw=4 * USDC)

    result = await resolve_manual_review(
        conn, review_id, "refund", OPERATOR, "buyer asked to cancel"
    )

    assert result.outcome is ResolutionOutcome.REFUND_REQUESTED
    assert result.refund_id is not None
    row = (
        await conn.execute(
            sa.text(
                "SELECT amount_raw, status::text AS status, to_address, asset_id "
                "FROM refunds WHERE id = :id"
            ),
            {"id": result.refund_id},
        )
    ).mappings().one()
    assert Decimal(row["amount_raw"]) == Decimal(4 * USDC)
    assert row["status"] == str(E.RefundStatus.PENDING)
    assert row["to_address"] is None
    assert row["asset_id"] == scenario.asset_id

    assert await invoice_status(conn, scenario.invoice_id) == str(E.InvoiceStatus.CANCELLED)
    assert await count(conn, "entitlements") == 0
    assert await count(conn, "notifications", "kind = 'refund_requested'") == 1


async def test_refunding_an_invoice_that_received_nothing_is_refused(
    conn: AsyncConnection, world: World
) -> None:
    """There is nothing to give back, and ``amount_raw > 0`` is a CHECK.

    Raised rather than written as a zero-amount row: an owner who typed
    ``refund`` on an empty invoice meant ``reject``, and a refund obligation for
    nothing is a line in the operational checklist that wastes somebody's
    afternoon.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC, **CLOSED_WINDOW)
    stray = await world.payment(
        chain_id=scenario.chain_id,
        asset_id=await world.asset(scenario.chain_id, symbol="USDT", decimals=6),
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=USDC,
        block_number=90,
        anomaly=E.PaymentAnomaly.WRONG_ASSET,
    )
    result = await settle_invoice(conn, scenario.invoice_id)
    review_id = next(iter(result.manual_review_ids))
    assert stray > 0

    with pytest.raises(ResolutionNotApplicable):
        await resolve_manual_review(conn, review_id, "refund", OPERATOR)


# ---------------------------------------------------------------------------
# reject
# ---------------------------------------------------------------------------


async def test_reject_closes_the_case_with_nothing_granted_and_nothing_owed(
    conn: AsyncConnection, world: World
) -> None:
    scenario, review_id = await _underpaid_case(conn, world)

    result = await resolve_manual_review(conn, review_id, "reject", OPERATOR, "no response")

    assert result.outcome is ResolutionOutcome.REJECTED
    assert await invoice_status(conn, scenario.invoice_id) == str(E.InvoiceStatus.CANCELLED)
    assert await count(conn, "entitlements") == 0
    assert await count(conn, "refunds") == 0
    assert await count(conn, "manual_reviews", "resolved_at IS NULL") == 0
    # The money is left exactly where the watcher put it. A rejection is a
    # decision about the product, not a licence to edit the ledger.
    assert await count(conn, "payments", "status = 'confirmed'") == 1


async def test_a_case_with_no_invoice_can_only_be_rejected(
    conn: AsyncConnection, world: World
) -> None:
    """``unassigned_payment``: money on a known address nobody was billing.

    There is no invoice to credit and ``refunds.invoice_id`` is ``NOT NULL``, so
    two of the three doors are not doors at all. Saying so explicitly beats
    letting the command fail later on a foreign key.
    """
    from settler.service import review_anomalous_payments

    chain_id = await world.chain()
    asset_id = await world.asset(chain_id)
    hd_id = await world.hd_account()
    address_id, _address = await world.address(hd_id, index=41)
    await world.payment(
        chain_id=chain_id,
        asset_id=asset_id,
        address_id=address_id,
        invoice_id=None,
        amount_raw=3 * USDC,
        block_number=90,
        anomaly=E.PaymentAnomaly.UNASSIGNED_PAYMENT,
    )
    (review_id,) = await review_anomalous_payments(conn)

    with pytest.raises(ResolutionNotApplicable):
        await resolve_manual_review(conn, review_id, "credit", OPERATOR)
    with pytest.raises(ResolutionNotApplicable):
        await resolve_manual_review(conn, review_id, "refund", OPERATOR)

    result = await resolve_manual_review(conn, review_id, "reject", OPERATOR, "swept by hand")
    assert result.outcome is ResolutionOutcome.REJECTED
    assert result.invoice_id is None
    assert await count(conn, "manual_reviews", "resolved_at IS NULL") == 0


# ---------------------------------------------------------------------------
# TZ 5.8/T7 — the threshold on a manual credit
# ---------------------------------------------------------------------------


async def test_a_large_credit_needs_a_second_call_with_the_code(
    conn: AsyncConnection, world: World
) -> None:
    """"``/resolve credit`` выше ``manual_credit_limit_usd`` требует подтверждения."

    The first call decides nothing: the case is still open, no entitlement
    exists, the invoice has not moved. That is the property the control depends
    on — a scripted burst from a captured session must not be able to leave
    anything half-applied.
    """
    scenario, review_id = await _underpaid_case(
        conn, world, due_raw=240 * USDC, paid_raw=100 * USDC, amount_due_usd="240"
    )
    policy = AdminPolicy(manual_credit_limit_usd=Decimal("50"))

    first = await resolve_manual_review(
        conn, review_id, "credit", OPERATOR, confirmation_key=KEY, admin_policy=policy
    )

    assert first.outcome is ResolutionOutcome.CONFIRMATION_REQUIRED
    assert first.needs_confirmation
    assert first.confirmation_code
    assert first.entitlement_id is None
    assert await count(conn, "entitlements") == 0
    assert await count(conn, "manual_reviews", "resolved_at IS NULL") == 1
    assert await invoice_status(conn, scenario.invoice_id) == str(E.InvoiceStatus.MANUAL_REVIEW)
    # The attempt is on the record even though nothing happened (TZ 5.8/T7).
    assert await count(conn, "audit_log", "action = 'admin.credit_confirmation_requested'") == 1

    second = await resolve_manual_review(
        conn,
        review_id,
        "credit",
        OPERATOR,
        "confirmed by owner",
        confirmation_code=first.confirmation_code,
        confirmation_key=KEY,
        admin_policy=policy,
    )

    assert second.outcome is ResolutionOutcome.CREDITED
    assert second.entitlement_id is not None
    assert await invoice_status(conn, scenario.invoice_id) == str(E.InvoiceStatus.PAID)


async def test_a_credit_below_the_limit_needs_no_confirmation(
    conn: AsyncConnection, world: World
) -> None:
    scenario, review_id = await _underpaid_case(conn, world, amount_due_usd="10")

    result = await resolve_manual_review(
        conn,
        review_id,
        "credit",
        OPERATOR,
        confirmation_key=KEY,
        admin_policy=AdminPolicy(manual_credit_limit_usd=Decimal("50")),
    )

    assert result.outcome is ResolutionOutcome.CREDITED
    assert await invoice_status(conn, scenario.invoice_id) == str(E.InvoiceStatus.PAID)


async def test_a_code_issued_for_one_case_does_not_confirm_another(
    conn: AsyncConnection, world: World
) -> None:
    """The code is bound to the decision, not merely to the moment.

    This is the attack a captured session would actually run: obtain one
    legitimate code, then replay it against the largest open case. A stored
    nonce keyed on time alone would let that through; an HMAC over
    ``(review, resolution, invoice, amount, operator)`` does not.
    """
    policy = AdminPolicy(manual_credit_limit_usd=Decimal("50"))
    _first_scenario, first_review = await _underpaid_case(
        conn, world, due_raw=240 * USDC, paid_raw=100 * USDC, amount_due_usd="240"
    )
    _second_scenario, second_review = await _underpaid_case(
        conn, world, due_raw=900 * USDC, paid_raw=100 * USDC, amount_due_usd="900"
    )

    issued = await resolve_manual_review(
        conn, first_review, "credit", OPERATOR, confirmation_key=KEY, admin_policy=policy
    )
    assert issued.confirmation_code

    with pytest.raises(InvalidConfirmationCode):
        await resolve_manual_review(
            conn,
            second_review,
            "credit",
            OPERATOR,
            confirmation_code=issued.confirmation_code,
            confirmation_key=KEY,
            admin_policy=policy,
        )
    assert await count(conn, "entitlements") == 0


async def test_a_wrong_code_confirms_nothing(conn: AsyncConnection, world: World) -> None:
    policy = AdminPolicy(manual_credit_limit_usd=Decimal("50"))
    _scenario, review_id = await _underpaid_case(
        conn, world, due_raw=240 * USDC, paid_raw=100 * USDC, amount_due_usd="240"
    )

    with pytest.raises(InvalidConfirmationCode):
        await resolve_manual_review(
            conn,
            review_id,
            "credit",
            OPERATOR,
            confirmation_code="AAAAAAAA",
            confirmation_key=KEY,
            admin_policy=policy,
        )
    assert await count(conn, "entitlements") == 0
    assert await count(conn, "manual_reviews", "resolved_at IS NULL") == 1


async def test_a_missing_key_makes_a_large_credit_impossible_not_unconfirmed(
    conn: AsyncConnection, world: World
) -> None:
    """Fail closed. A control that switches itself off when misconfigured is not a control."""
    _scenario, review_id = await _underpaid_case(
        conn, world, due_raw=240 * USDC, paid_raw=100 * USDC, amount_due_usd="240"
    )

    with pytest.raises(ConfirmationUnavailable):
        await resolve_manual_review(
            conn,
            review_id,
            "credit",
            OPERATOR,
            confirmation_key=None,
            admin_policy=AdminPolicy(manual_credit_limit_usd=Decimal("50")),
        )
    assert await count(conn, "entitlements") == 0


async def test_the_facade_commits_the_refused_attempt_before_raising(
    engine: AsyncEngine,
) -> None:
    """Commit, then raise — both halves, checked from outside the transaction.

    ``AsyncEngine.begin()`` rolls back on an exception, so a naive
    "raise ConfirmationRequired from inside the transaction" would erase the
    audit row that records the attempt. :class:`AdminOps` exists to get the
    ordering right, and this test reads the row back on a *separate* connection
    to prove it is really committed rather than merely visible to the writer.

    Deliberately does not use the ``conn`` / ``world`` fixtures: they share one
    long transaction, and a test about what survives a commit cannot be written
    inside somebody else's uncommitted one.
    """
    async with engine.begin() as setup:
        _scenario, review_id = await _underpaid_case(
            setup, World(setup), due_raw=240 * USDC, paid_raw=100 * USDC, amount_due_usd="240"
        )

    ops = AdminOps(
        engine,
        policy=AdminPolicy(manual_credit_limit_usd=Decimal("50")),
        confirmation_key=KEY,
    )
    with pytest.raises(ConfirmationRequired) as caught:
        await ops.resolve(review_id, "credit", OPERATOR)
    assert caught.value.code

    async with engine.connect() as other:
        attempts = (
            await other.execute(
                sa.text(
                    "SELECT count(*) FROM audit_log "
                    " WHERE action = 'admin.credit_confirmation_requested'"
                )
            )
        ).scalar_one()
        granted = (await other.execute(sa.text("SELECT count(*) FROM entitlements"))).scalar_one()
    assert attempts == 1, "the refused attempt must outlive the refusal"
    assert granted == 0


# ---------------------------------------------------------------------------
# TZ 5.8/T7, T8 — the trail every decision leaves
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verb", ["credit", "refund", "reject"])
async def test_every_resolution_records_actor_before_after_and_policy(
    conn: AsyncConnection, world: World, verb: str
) -> None:
    """TZ 5.8/T7 and T8 together, once per door.

    T7 wants actor, arguments and prior state on every admin action. T8 wants the
    policy version that governed the decision to be *in the decision*, not
    inferred from today's configuration — "иначе через месяц ответ звучит как
    «наверное, тогда допуск был другой»".
    """
    _scenario, review_id = await _underpaid_case(conn, world)
    policy = AdminPolicy(version="test-admin-9", manual_credit_limit_usd=Decimal("1000"))

    result = await resolve_manual_review(
        conn, review_id, verb, OPERATOR, "because", admin_policy=policy, confirmation_key=KEY
    )

    row = (
        await conn.execute(
            sa.text(
                """
                SELECT actor_kind::text AS actor_kind, actor_id, action,
                       target_kind, target_id, before_state, after_state,
                       args_json, policy_version
                  FROM audit_log
                 WHERE id = :id
                """
            ),
            {"id": result.audit_id},
        )
    ).mappings().one()

    assert row["actor_kind"] == str(E.ActorKind.OWNER)
    assert row["actor_id"] == str(OPERATOR)
    assert row["action"] == f"admin.resolve.{verb}"
    assert row["target_kind"] == "manual_review"
    assert row["target_id"] == str(review_id)
    assert row["policy_version"] == "test-admin-9"
    assert row["before_state"]["resolved_at"] is None
    # The policy the case was *opened* under survives next to the one it was
    # closed under. Two versions, two questions, both answerable.
    assert row["before_state"]["opened_policy_version"] is not None
    assert row["after_state"]["operator_id"] == OPERATOR
    assert row["args_json"]["comment"] == "because"

    case = (
        await conn.execute(
            sa.text(
                "SELECT operator_id, resolution::text AS resolution, note, policy_version "
                "  FROM manual_reviews WHERE id = :id"
            ),
            {"id": review_id},
        )
    ).mappings().one()
    assert case["operator_id"] == OPERATOR
    assert case["resolution"] == verb
    assert case["policy_version"] == "test-admin-9"
    # The settler's reason for opening the case is not overwritten by the
    # owner's reason for closing it.
    assert "underpaid by" in (case["note"] or "")
    assert "because" in (case["note"] or "")


async def test_the_owner_gets_a_copy_of_every_admin_action(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 5.8/T7 — "захвативший аккаунт не сможет действовать незаметно"."""
    scenario, review_id = await _underpaid_case(conn, world)

    await resolve_manual_review(
        conn, review_id, "credit", OPERATOR, owner_user_id=scenario.user_id
    )

    assert await count(conn, "notifications", "kind = 'admin_action'") == 1


async def test_a_case_cannot_be_resolved_twice(conn: AsyncConnection, world: World) -> None:
    _scenario, review_id = await _underpaid_case(conn, world)
    await resolve_manual_review(conn, review_id, "reject", OPERATOR)

    with pytest.raises(ReviewAlreadyResolved):
        await resolve_manual_review(conn, review_id, "credit", OPERATOR)
    assert await count(conn, "entitlements") == 0


async def test_resolving_a_case_that_does_not_exist_is_an_error(conn: AsyncConnection) -> None:
    with pytest.raises(ReviewNotFound):
        await resolve_manual_review(conn, 999_999, "reject", OPERATOR)


def test_the_confirmation_key_cannot_be_printed() -> None:
    """TZ 5.8/T4 discipline applied to the second secret in the system.

    A config object with a generated ``repr`` is the standard way a key reaches
    a log line — through an exception message, a ``logging.exception``
    traceback, or a debug dump of settings. The dataclass is declared
    ``repr=False`` *and* overrides both hooks, because the generated repr would
    print the only field this object has.
    """
    secret = ConfirmationKey(b"super-secret-material")

    assert "super-secret" not in repr(secret)
    assert "super-secret" not in str(secret)
    assert "super-secret" not in f"{secret}"
    assert "super-secret" not in f"{secret!r}"
    assert "super-secret" not in str({"key": secret})


async def test_admin_actions_are_counted(conn: AsyncConnection, world: World) -> None:
    """TZ 5.8/T7 — ``notchstave_admin_actions_total{action}``."""
    from settler import metrics

    _scenario, review_id = await _underpaid_case(conn, world)
    before = sample_value(metrics.ADMIN_ACTIONS, "_total", action="resolve.reject")

    await resolve_manual_review(conn, review_id, "reject", OPERATOR)

    after = sample_value(metrics.ADMIN_ACTIONS, "_total", action="resolve.reject")
    assert after == before + 1


# ---------------------------------------------------------------------------
# `/pending`
# ---------------------------------------------------------------------------


async def test_pending_lists_the_open_cases_with_what_is_missing(
    conn: AsyncConnection, world: World
) -> None:
    scenario, review_id = await _underpaid_case(conn, world, due_raw=10 * USDC, paid_raw=4 * USDC)

    cases = await list_pending(conn)

    assert [c.review_id for c in cases] == [review_id]
    case = cases[0]
    assert case.kind == str(E.ManualReviewKind.UNDERPAID)
    assert case.invoice_id == scenario.invoice_id
    assert case.received_raw == Decimal(4 * USDC)
    assert case.shortfall_raw == Decimal(6 * USDC)
    assert case.asset_symbol == "USDC"


async def test_a_resolved_case_leaves_pending(conn: AsyncConnection, world: World) -> None:
    _scenario, review_id = await _underpaid_case(conn, world)
    assert len(await list_pending(conn)) == 1

    await resolve_manual_review(conn, review_id, "reject", OPERATOR)

    assert await list_pending(conn) == ()


async def test_pending_shows_payment_level_cases_with_no_invoice(
    conn: AsyncConnection, world: World
) -> None:
    """The kind of case an invoice-status listing would miss entirely.

    Money on a known address with nothing billed against it moves no invoice, so
    a `/pending` driven by ``invoices.status`` would show an empty screen while
    the funds sit there. Driven by ``manual_reviews`` it shows up, which is the
    reason for that choice in :data:`settler.admin.repository.SQL_PENDING_CASES`.
    """
    from settler.service import review_anomalous_payments

    chain_id = await world.chain()
    asset_id = await world.asset(chain_id)
    hd_id = await world.hd_account()
    address_id, _address = await world.address(hd_id, index=77)
    await world.payment(
        chain_id=chain_id,
        asset_id=asset_id,
        address_id=address_id,
        invoice_id=None,
        amount_raw=3 * USDC,
        block_number=90,
        anomaly=E.PaymentAnomaly.UNASSIGNED_PAYMENT,
    )
    await review_anomalous_payments(conn)

    cases = await list_pending(conn)

    assert len(cases) == 1
    assert cases[0].invoice_id is None
    assert cases[0].kind == str(E.ManualReviewKind.UNASSIGNED_PAYMENT)
    assert cases[0].shortfall_raw is None
