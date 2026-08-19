"""Messages that are not commands — TZ 3.1's other half of support.

The claim :mod:`bot.handlers.freeform` makes is that its convenience paths reach
*the same code* the corresponding command would, not similar code. That is a
claim about ownership filters and refusal ladders, so the tests below check the
consequences rather than the call graph: a pasted invoice id has to be as
unreadable to a stranger as ``/status`` makes it (in ``test_ownership.py``), and
a bare sku has to meet every quota answer ``/buy`` would.

The second property under test is that nothing here acts on a guess. A sentence
is a support question, an unknown word is an unknown word, and neither may cost
somebody an invoice out of the T5.1 quota.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from bot import texts
from bot.detect import Detected, InputKind, classify, parse_invoice_id
from bot.tests.conftest import (
    BUYER_TG_ID,
    CHECKSUMMED_ADDRESS,
    Harness,
    Shop,
    an_invoice_view,
    make_invoice,
    make_user,
)

TX_HASH = "0x" + "ab" * 32


# ---------------------------------------------------------------------------
# The classifier
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,kind",
    [
        (CHECKSUMMED_ADDRESS, InputKind.ADDRESS),
        (CHECKSUMMED_ADDRESS.lower(), InputKind.ADDRESS),
        (TX_HASH, InputKind.TX_HASH),
        ("  " + TX_HASH + "  ", InputKind.TX_HASH),
        ("3f8b0d5e-1c2a-4b6d-9e0f-1a2b3c4d5e6f", InputKind.INVOICE_ID),
        ("monthly-pro", InputKind.SKU),
        ("SKU_1", InputKind.SKU),
        ("", InputKind.UNKNOWN),
        ("where is my money", InputKind.UNKNOWN),
        # Right prefix, wrong length. Falls through to the residual category,
        # which is safe precisely because SKU is residual: the handler checks it
        # against `products` before acting, so a truncated address can only ever
        # buy something if a product is literally called `0xdeadbeef`.
        ("0xdeadbeef", InputKind.SKU),
        ("0x" + "ab" * 33, InputKind.UNKNOWN),  # past both the hash and sku lengths
        ("!!!", InputKind.UNKNOWN),
    ],
)
def test_shapes_do_not_overlap(text: str, kind: InputKind) -> None:
    """Length and anchoring, never a scoring function.

    An address is 42 characters, a hash is 66, a UUID has hyphens in fixed
    places. Because the three cannot be confused, the classifier can be a regex
    table — and because the table is anchored, reordering it cannot change an
    answer.
    """
    assert classify(text).kind is kind


def test_a_uuid_is_normalised_so_the_handler_does_not_reparse_it() -> None:
    upper = "3F8B0D5E-1C2A-4B6D-9E0F-1A2B3C4D5E6F"
    detected = classify(upper)
    assert detected == Detected(InputKind.INVOICE_ID, upper.lower())


@pytest.mark.parametrize("text", ["", "nope", "3f8b0d5e1c2a4b6d9e0f1a2b3c4d5e6f"])
def test_parse_invoice_id_returns_none_rather_than_raising(text: str) -> None:
    """Every caller's next line is "tell the user that is not an id"."""
    assert parse_invoice_id(text) is None


def test_parse_invoice_id_rejects_the_unhyphenated_form() -> None:
    """A 32-hex string is what ``public_token`` looks like, not an invoice id.

    ``uuid.UUID()`` would happily accept it, which is why the regex is anchored
    on the hyphenated form: silently treating a page token as an invoice id
    would answer ``/status`` for a value that reaches a *different* ownership
    rule.
    """
    assert parse_invoice_id(uuid.uuid4().hex) is None


# ---------------------------------------------------------------------------
# The routing
# ---------------------------------------------------------------------------


async def test_a_pasted_invoice_id_answers_as_status_would(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    user_id = await make_user(engine, BUYER_TG_ID)
    invoice_id, _ = await make_invoice(engine, shop, user_id=user_id, index=41)

    pasted = await harness.send(str(invoice_id))
    commanded = await harness.send(f"/status {invoice_id}")

    assert pasted == commanded
    assert shop.product_title in pasted


async def test_a_bare_sku_issues_an_invoice_through_the_same_path_as_buy(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    user_id = await make_user(engine, BUYER_TG_ID)
    harness.invoices.view = an_invoice_view(shop, user_id=user_id)

    reply = await harness.send(shop.product_sku)

    assert harness.invoices.calls == [
        {
            "user_id": user_id,
            "product_id": shop.product_id,
            "chain_id": shop.chain_id,
            "asset_id": shop.asset_id,
            "hd_account_id": shop.hd_account_id,
            "timeout": 1.0,
        }
    ]
    assert "Invoice created" in reply


async def test_a_bare_sku_meets_the_same_refusals_as_buy(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """The refusal ladder is shared code, and this is what proves it.

    A convenience path that re-implemented ``/buy`` would be the copy nobody
    re-reads, and the quota answers are exactly the thing it would get wrong.
    """
    from core.invoicing import errors as E

    await make_user(engine, BUYER_TG_ID)
    harness.invoices.error = E.TooManyActiveInvoices("detail", limit=3, observed=4)

    reply = await harness.send(shop.product_sku)

    assert reply == E.TooManyActiveInvoices.user_message


async def test_an_unknown_word_never_creates_an_invoice(harness: Harness) -> None:
    """The catalogue lookup happens before anything is acted on."""
    reply = await harness.send("hello")

    assert harness.invoices.calls == []
    assert reply == texts.free_text_unknown()


async def test_a_sentence_is_a_support_question_not_an_identifier(
    harness: Harness,
) -> None:
    reply = await harness.send("my payment has not arrived, what do I do")

    assert harness.invoices.calls == []
    assert reply == texts.free_text_unknown()


async def test_an_unclaimed_command_is_not_treated_as_a_sku(
    harness: Harness, shop: Shop
) -> None:
    """Otherwise anyone typing ``/pending`` would try to buy "/pending"."""
    reply = await harness.send("/nonexistent")

    assert harness.invoices.calls == []
    assert reply == texts.free_text_unknown()


async def test_a_pasted_tx_hash_gets_the_explorer_link_and_the_right_advice(
    harness: Harness,
) -> None:
    reply = await harness.send(TX_HASH)

    assert TX_HASH in reply
    assert f"https://explorer.example/tx/{TX_HASH}" in reply
    # Payments are matched by receiving address, never by a hash a user sends.
    assert "by receiving address" in reply


async def test_a_pasted_address_is_answered_without_confirming_anything_about_it(
    harness: Harness,
) -> None:
    """The bot must not become an address lookup service.

    Answering "yes that is one of ours" for an arbitrary address would leak the
    pool address by address to anyone willing to guess, which is the enumeration
    T1.7 closes on invoice ids.
    """
    reply = await harness.send(CHECKSUMMED_ADDRESS)

    assert "wallet address" in reply
    assert "only the address in the invoice message is valid" in reply
    # No claim either way about whether this address belongs to the system.
    assert "ours" not in reply.replace("really is ours", "")


async def test_the_freeform_router_runs_last(harness: Harness, shop: Shop) -> None:
    """Registration order is a priority statement (bot/handlers/__init__.py).

    ``F.text`` matches every text message, so a router registered after it would
    never be reached. The assertion is that a real command still reaches its own
    handler rather than the catch-all — which is only true because ``freeform``
    is third.
    """
    reply = await harness.send("/shop")
    assert reply != texts.free_text_unknown()
    assert shop.product_sku in reply
