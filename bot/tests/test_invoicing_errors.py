"""Every class :mod:`core.invoicing.errors` can raise, through a real handler.

Two properties are checked for all of them, and they are the two ways this code
can go wrong quietly.

**The buyer sees ``user_message``, never ``str(exc)``.** The operator detail
names quota limits, observed counts, account ids and — for an integrity failure
— which check failed. Rendering it would hand the shape of the rate limiter to
whoever is probing it, and the split exists in ``errors.py`` precisely so that a
handler can get this wrong. So every test below asserts the buyer-facing
sentence *and* asserts the detail string is absent.

**The ladder does not collapse.** :class:`~core.invoicing.errors.IntegrityFailure`
deliberately does not inherit from
:class:`~core.invoicing.errors.InvoiceUnavailable`, so that an ``except
InvoiceUnavailable`` written to be friendly about quotas cannot swallow a
suspected address substitution into "please try again later". A test for each
branch is what stops a later refactor from replacing the ladder with one
``except InvoicingError`` and losing the distinction with no visible symptom.
"""

from __future__ import annotations

import logging
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from bot.tests.conftest import BUYER_TG_ID, Harness, Shop, an_invoice_view, make_user
from core.invoicing import errors as E

#: The operator-facing detail every error below is constructed with. Never
#: allowed to reach a message.
DETAIL = "internal-detail-user_id=7-limit=3-observed=9"


def _errors() -> list[tuple[str, E.InvoicingError]]:
    """One instance of every class ``/buy`` and ``/verify`` can meet."""
    return [
        ("UnknownProduct", E.UnknownProduct(DETAIL)),
        ("UnknownAsset", E.UnknownAsset(DETAIL)),
        ("RateUnavailable", E.RateUnavailable(DETAIL)),
        (
            "TooManyActiveInvoices",
            E.TooManyActiveInvoices(DETAIL, limit=3, observed=4),
        ),
        ("HourlyQuotaExceeded", E.HourlyQuotaExceeded(DETAIL, limit=10, observed=11)),
        ("BehaviouralCooldown", E.BehaviouralCooldown(DETAIL, limit=5, observed=6)),
        ("AddressCapacityExhausted", E.AddressCapacityExhausted(DETAIL)),
        ("InvoiceRequestInFlight", E.InvoiceRequestInFlight(DETAIL)),
        ("InvoiceRequestTimeout", E.InvoiceRequestTimeout(DETAIL)),
        ("InvoiceRequestAbandoned", E.InvoiceRequestAbandoned(DETAIL)),
        ("InvoiceUnavailable", E.InvoiceUnavailable(DETAIL)),
        (
            "AddressMismatch",
            E.AddressMismatch(DETAIL, invoice_id=uuid.uuid4()),
        ),
        ("MacMismatch", E.MacMismatch(DETAIL, invoice_id=uuid.uuid4())),
    ]


@pytest.mark.parametrize("name,error", _errors(), ids=[n for n, _ in _errors()])
async def test_buy_renders_the_buyer_sentence_and_never_the_detail(
    harness: Harness, shop: Shop, engine: AsyncEngine, name: str, error: E.InvoicingError
) -> None:
    await make_user(engine, BUYER_TG_ID)
    harness.invoices.error = error

    reply = await harness.send(f"/buy {shop.product_sku}")

    assert reply == error.user_message, f"{name} rendered the wrong sentence"
    assert DETAIL not in reply, f"{name} leaked the operator detail to the buyer"
    # One message. A refusal that also sent the usage text would train buyers to
    # retry immediately, which is the opposite of what a quota wants.
    assert len(harness.texts) == 1


async def test_an_integrity_failure_is_logged_at_critical_not_swallowed_as_a_retry(
    harness: Harness,
    shop: Shop,
    engine: AsyncEngine,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """TZ 5.8/T1.1 and T1.3: the correct response is to stop taking payments.

    ``AddressMismatch`` means the address in the row did not re-derive, which is
    the exact event this whole product is built around. It must not be reported
    at the same severity as a quota, and the log line must carry the buyer so an
    operator can see who was looking at it.
    """
    await make_user(engine, BUYER_TG_ID)
    invoice_id = uuid.uuid4()
    harness.invoices.error = E.AddressMismatch(DETAIL, invoice_id=invoice_id)

    with caplog.at_level(logging.INFO, logger="notchstave.bot.buyer"):
        reply = await harness.send(f"/buy {shop.product_sku}")

    critical = [r for r in caplog.records if r.levelno >= logging.CRITICAL]
    assert critical, "an integrity failure was not logged at critical"
    assert "AddressMismatch" in critical[0].getMessage()
    # The buyer is told to stop, not to try again.
    assert "try again" not in reply.lower()


async def test_a_quota_refusal_is_not_logged_at_critical(
    harness: Harness,
    shop: Shop,
    engine: AsyncEngine,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The other half of the same property: ordinary refusals stay ordinary.

    A quota that paged somebody would make the page meaningless within a day,
    which is how a real incident gets ignored.
    """
    await make_user(engine, BUYER_TG_ID)
    harness.invoices.error = E.TooManyActiveInvoices(DETAIL, limit=3, observed=4)

    with caplog.at_level(logging.INFO, logger="notchstave.bot.buyer"):
        await harness.send(f"/buy {shop.product_sku}")

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


async def test_a_timed_out_request_points_at_status_and_not_at_a_retry(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """The request row stands and the deriver may still answer it.

    Telling the buyer to press ``/buy`` again would burn a second slot of the
    T5.1 active-invoice quota on a duplicate of an invoice that is about to
    exist.
    """
    await make_user(engine, BUYER_TG_ID)
    harness.invoices.error = E.InvoiceRequestTimeout(DETAIL)

    reply = await harness.send(f"/buy {shop.product_sku}")

    assert "/status" in reply or "/my" in reply


@pytest.mark.parametrize(
    "error",
    [
        E.InvoiceUnavailable(DETAIL),
        E.MacMismatch(DETAIL, invoice_id=uuid.uuid4()),
        E.InvoiceRequestTimeout(DETAIL),
    ],
    ids=["unavailable", "mac-mismatch", "timeout"],
)
async def test_verify_renders_the_buyer_sentence_for_every_refusal(
    harness: Harness, engine: AsyncEngine, error: E.InvoicingError
) -> None:
    await make_user(engine, BUYER_TG_ID)
    harness.proofs.error = error

    reply = await harness.send(f"/verify {uuid.uuid4()}")

    assert reply == error.user_message
    assert DETAIL not in reply


async def test_verify_on_an_unknown_invoice_gives_the_same_answer_as_a_foreign_one(
    harness: Harness, engine: AsyncEngine
) -> None:
    """TZ 5.8/T1.7. ``InvoiceNotFound`` is mapped to the ``/status`` sentence.

    Both cases have to be indistinguishable, and this is the assertion that
    makes them so: the not-found copy is one function, and ``/verify`` calls
    exactly it rather than a paraphrase of it.
    """
    from bot import texts

    await make_user(engine, BUYER_TG_ID)
    harness.proofs.error = E.InvoiceNotFound(DETAIL)

    reply = await harness.send(f"/verify {uuid.uuid4()}")

    assert reply == texts.status_not_found()


async def test_a_successful_buy_after_a_refusal_still_works(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """No sticky state: a refusal is not a circuit breaker in this process."""
    user_id = await make_user(engine, BUYER_TG_ID)
    harness.invoices.error = E.TooManyActiveInvoices(DETAIL, limit=3, observed=4)
    await harness.send(f"/buy {shop.product_sku}")

    harness.invoices.error = None
    harness.invoices.view = an_invoice_view(shop, user_id=user_id)
    reply = await harness.send(f"/buy {shop.product_sku}")

    assert "Invoice created" in reply
