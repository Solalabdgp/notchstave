"""TZ 5.8/T1.7 — an invoice id is not a capability.

The threat is the cheap one: invoice ids are handed to buyers, get pasted into
support chats and screenshots, and a bot that answered ``/status`` for any id it
was shown would turn every leaked id into somebody else's payment history. The
answer in this system is that the *identity* comes from Telegram's verified
``from_user.id`` and the id comes from the message, and the two are joined in
the WHERE clause.

Three things are asserted, and the third is the one that is easy to lose:

1. A foreign invoice is not readable.
2. It answers with the *same* sentence an entirely unknown id gets — anything
   else confirms the id exists, which is the single bit an enumeration attempt
   is buying.
3. The filter is in the query, not applied to its result. Asserted by going
   through :class:`~bot.repository.BotRepository` directly against a real
   Postgres, so that a refactor which drops the predicate and keeps a Python-side
   check would still have to face a test that never looks at Python.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncEngine

from bot import texts
from bot.tests.conftest import (
    BUYER_TG_ID,
    OTHER_TG_ID,
    OWNER_TG_ID,
    Harness,
    Shop,
    a_proof,
    make_invoice,
    make_user,
)


async def test_status_refuses_someone_elses_invoice(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    owner_of_invoice = await make_user(engine, OTHER_TG_ID)
    invoice_id, _ = await make_invoice(
        engine, shop, user_id=owner_of_invoice, index=11
    )

    reply = await harness.send(f"/status {invoice_id}", tg_id=BUYER_TG_ID)

    assert reply == texts.status_not_found()


async def test_status_gives_a_foreign_invoice_and_a_fictional_one_the_same_answer(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """The indistinguishability property, asserted as an equality."""
    owner_of_invoice = await make_user(engine, OTHER_TG_ID)
    real_but_foreign, _ = await make_invoice(
        engine, shop, user_id=owner_of_invoice, index=12
    )

    foreign = await harness.send(f"/status {real_but_foreign}", tg_id=BUYER_TG_ID)
    fictional = await harness.send(f"/status {uuid.uuid4()}", tg_id=BUYER_TG_ID)

    assert foreign == fictional


async def test_the_owner_gets_no_special_read_on_a_buyers_invoice(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """``/status`` has no admin mode, and TZ 3.4's commands are the ones that do.

    An owner who could read any invoice through the ordinary command would make
    T7's "compromised owner account" strictly worse for no operational gain —
    ``/pending`` already surfaces everything that needs a decision.
    """
    buyer_id = await make_user(engine, BUYER_TG_ID)
    invoice_id, _ = await make_invoice(engine, shop, user_id=buyer_id, index=13)

    reply = await harness.send(f"/status {invoice_id}", tg_id=OWNER_TG_ID)

    assert reply == texts.status_not_found()


async def test_the_ownership_filter_lives_in_the_sql(
    shop: Shop, engine: AsyncEngine
) -> None:
    """Straight at the repository, past every handler.

    If the predicate were applied in Python after the query, this would still
    pass — so the assertion is paired with the one below, which reads the
    statement itself.
    """
    from bot.repository import BotRepository

    mine = await make_user(engine, BUYER_TG_ID)
    theirs = await make_user(engine, OTHER_TG_ID)
    invoice_id, _ = await make_invoice(engine, shop, user_id=theirs, index=14)

    repo = BotRepository(engine)
    assert await repo.invoice_status(user_id=mine, invoice_id=invoice_id) is None
    assert await repo.invoice_status(user_id=theirs, invoice_id=invoice_id) is not None


def test_the_status_statement_requires_a_user_id_parameter() -> None:
    """A caller cannot forget the filter — the statement will not run without it.

    This is the structural half of the property. ``:user_id`` being a bound
    parameter of the statement means a refactor that drops the caller's argument
    fails with a missing-parameter error rather than by returning a row.
    """
    from bot.repository import SQL_INVOICE_STATUS

    text = str(SQL_INVOICE_STATUS)
    assert "i.user_id = :user_id" in text


async def test_verify_forwards_the_callers_user_id_and_never_the_typed_one(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """The ``/verify`` half of T1.7.

    The bot deliberately does *not* pre-filter: it passes the caller's
    ``users.id`` to the deriver, which loads the invoice with
    ``expected_user_id`` and answers ``InvoiceNotFound`` for a foreign one. What
    the bot owes is that the id it sends is the *sender's*, resolved from the
    Telegram identity, and never anything taken from the message. So the
    assertion is on the argument, which is the only thing the bot controls.
    """
    buyer_id = await make_user(engine, BUYER_TG_ID)
    other_id = await make_user(engine, OTHER_TG_ID)
    invoice_id, _ = await make_invoice(engine, shop, user_id=other_id, index=15)
    harness.proofs.proof = a_proof(invoice_id)

    await harness.send(f"/verify {invoice_id}", tg_id=BUYER_TG_ID)

    assert harness.proofs.calls[0]["user_id"] == buyer_id
    assert harness.proofs.calls[0]["user_id"] != other_id


async def test_verify_refuses_a_foreign_invoice_the_way_the_deriver_answers_it(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """End to end with the deriver's real answer to a foreign id.

    ``InvoiceNotFound`` is what :func:`core.invoicing.service
    .verify_invoice_address` raises when ``expected_user_id`` does not match, and
    it is the same class a genuinely missing invoice produces — so the bot's
    rendering of it has to be the not-found sentence and nothing more specific.
    """
    from core.invoicing import errors as E

    other_id = await make_user(engine, OTHER_TG_ID)
    invoice_id, _ = await make_invoice(engine, shop, user_id=other_id, index=16)
    harness.proofs.error = E.InvoiceNotFound(f"invoice {invoice_id} is not this user's")

    reply = await harness.send(f"/verify {invoice_id}", tg_id=BUYER_TG_ID)

    assert reply == texts.status_not_found()
    assert str(invoice_id) not in reply


async def test_my_lists_only_the_callers_invoices(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    mine = await make_user(engine, BUYER_TG_ID)
    theirs = await make_user(engine, OTHER_TG_ID)
    my_invoice, _ = await make_invoice(engine, shop, user_id=mine, index=17)
    their_invoice, _ = await make_invoice(engine, shop, user_id=theirs, index=18)

    reply = await harness.send("/my", tg_id=BUYER_TG_ID)

    assert str(my_invoice) in reply
    assert str(their_invoice) not in reply


async def test_a_pasted_foreign_invoice_id_takes_the_same_filtered_path(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """The free-text convenience must not be a way around the filter.

    ``bot.handlers.freeform`` routes a bare UUID into
    :func:`bot.handlers.buyer.show_status` rather than re-implementing the read,
    and this is the test that would fail if somebody ever wrote the second copy.
    """
    theirs = await make_user(engine, OTHER_TG_ID)
    invoice_id, _ = await make_invoice(engine, shop, user_id=theirs, index=19)

    reply = await harness.send(str(invoice_id), tg_id=BUYER_TG_ID)

    assert reply == texts.status_not_found()
