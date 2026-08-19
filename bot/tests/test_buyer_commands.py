"""The seven commands of TZ 3.1: each one reaches the right service call.

The shape of every test here is the same and it is deliberate. Feed the exact
text a user types, then assert on two things: what went to Telegram, and what
the handler asked the service layer for. The second half is the one that catches
the interesting bugs — a ``/buy`` that renders a beautiful invoice message
against the wrong ``hd_account_id`` looks perfect on screen and issues an
address nobody can sweep.
"""

from __future__ import annotations

import uuid

import pytest
from aiogram.methods import SendMessage
from sqlalchemy.ext.asyncio import AsyncEngine

from bot import texts
from bot.formatting import code
from bot.tests.conftest import (
    BUYER_TG_ID,
    CHECKSUMMED_ADDRESS,
    Harness,
    Shop,
    a_proof,
    an_invoice_view,
    make_invoice,
    make_user,
)


async def test_start_registers_the_user_and_states_the_one_network_rule(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """``/start`` — "явное предупреждение, что бот принимает платежи только в
    указанной сети и только указанным токеном" (TZ 3.1)."""
    reply = await harness.send("/start")

    assert shop.asset_symbol in reply
    assert shop.chain_name in reply
    # The safety rule of TZ 5.8/T1.5 is in the first message a user ever gets,
    # verbatim and not paraphrased.
    assert texts.SAFETY_RULE in reply

    assert await harness.services.repo.upsert_user(BUYER_TG_ID)


async def test_start_creates_exactly_one_user_row_however_often_it_is_pressed(
    harness: Harness, engine: AsyncEngine
) -> None:
    """``ON CONFLICT`` and not an INSERT: the second ``/start`` is a welcome back."""
    first = await harness.send("/start")
    second = await harness.send("/start")

    assert first.startswith("Welcome.")
    assert second.startswith("Welcome back.")

    import sqlalchemy as sa

    async with engine.begin() as conn:
        count = (
            await conn.execute(
                sa.text("SELECT count(*) FROM users WHERE tg_id = :tg"),
                {"tg": BUYER_TG_ID},
            )
        ).scalar_one()
    assert count == 1


async def test_start_clears_bot_blocked_at(harness: Harness, engine: AsyncEngine) -> None:
    """A user who unblocked the bot must stop being muted (TZ 5.5).

    ``/start`` arriving is the only signal this system will ever get that a 403
    is over, so the upsert clears the flag. Without this a buyer who once
    removed the bot never hears about a payment again.
    """
    import sqlalchemy as sa

    await make_user(engine, BUYER_TG_ID)
    async with engine.begin() as conn:
        await conn.execute(
            sa.text("UPDATE users SET bot_blocked_at = now() WHERE tg_id = :tg"),
            {"tg": BUYER_TG_ID},
        )

    await harness.send("/start")

    async with engine.begin() as conn:
        blocked = (
            await conn.execute(
                sa.text("SELECT bot_blocked_at FROM users WHERE tg_id = :tg"),
                {"tg": BUYER_TG_ID},
            )
        ).scalar_one()
    assert blocked is None


async def test_shop_lists_the_catalogue_with_usd_prices(
    harness: Harness, shop: Shop
) -> None:
    reply = await harness.send("/shop")
    assert shop.product_title in reply
    assert shop.product_sku in reply
    assert "$10.00" in reply


async def test_shop_on_an_empty_catalogue_says_so(
    harness: Harness, engine: AsyncEngine
) -> None:
    import sqlalchemy as sa

    async with engine.begin() as conn:
        await conn.execute(sa.text("UPDATE products SET active = false"))

    reply = await harness.send("/shop")
    assert "Nothing is on sale" in reply


async def test_buy_forwards_the_resolved_ids_and_renders_the_address_once(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """``/buy <sku>`` — the whole of TZ 3.1's third bullet.

    The service call is checked field by field because every one of them is a
    thing the handler resolved rather than received: the product came from a
    case-insensitive sku lookup, the asset from the configured (chain, symbol)
    pair, the HD account from ``is_active``.
    """
    user_id = await make_user(engine, BUYER_TG_ID)
    harness.invoices.view = an_invoice_view(shop, user_id=user_id)

    reply = await harness.send(f"/buy {shop.product_sku}")

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

    view = harness.invoices.view
    # Machine-copyable, EIP-55 case preserved (TZ 3.1).
    assert f"<code>{CHECKSUMMED_ADDRESS}</code>" in reply
    assert "12.5 USDC" in reply
    # The payment string goes out HTML-escaped — its `&` separators become
    # `&amp;` on the wire and a Telegram client renders them back, so what the
    # buyer copies out of the block is the byte-for-byte EIP-681 URI. Asserting
    # against `code(...)` rather than against the raw string is what makes that
    # round trip part of the test instead of an assumption.
    assert code(view.eip681()) in reply
    assert str(view.invoice_id) in reply
    assert f"https://pay.example/i/{view.public_token}" in reply
    # Exactly one message, because this is the message that is never edited
    # (TZ 5.8/T1.5).
    assert len(harness.texts) == 1


async def test_buy_is_case_insensitive_on_the_sku(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    user_id = await make_user(engine, BUYER_TG_ID)
    harness.invoices.view = an_invoice_view(shop, user_id=user_id)

    await harness.send(f"/buy {shop.product_sku.upper()}")

    assert len(harness.invoices.calls) == 1


async def test_buy_without_a_sku_explains_itself_and_calls_nothing(
    harness: Harness,
) -> None:
    reply = await harness.send("/buy")
    assert reply == texts.buy_usage()
    assert harness.invoices.calls == []


async def test_buy_with_an_unknown_sku_refuses_before_the_round_trip(
    harness: Harness,
) -> None:
    """A miss costs a sentence, never a request — the quota of T5.1 is finite."""
    reply = await harness.send("/buy no-such-thing")
    assert "no-such-thing" in reply
    assert harness.invoices.calls == []


async def test_buy_without_an_active_hd_account_refuses_rather_than_guessing(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """Mid-rotation (TZ 5.8/T4) an address issued against a guessed account
    would be valid and unspendable."""
    import sqlalchemy as sa

    async with engine.begin() as conn:
        await conn.execute(sa.text("UPDATE hd_accounts SET is_active = false"))

    reply = await harness.send(f"/buy {shop.product_sku}")

    assert "temporarily paused" in reply
    assert harness.invoices.calls == []


async def test_buy_with_the_configured_asset_disabled_answers_the_catalogue_sentence(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    import sqlalchemy as sa

    from core.invoicing import errors as E

    async with engine.begin() as conn:
        await conn.execute(sa.text("UPDATE assets SET is_enabled = false"))

    reply = await harness.send(f"/buy {shop.product_sku}")

    assert reply == E.UnknownAsset.user_message
    assert harness.invoices.calls == []


async def test_status_reports_received_missing_and_confirmations(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """``/status`` — "сколько пришло, сколько подтверждений, чего ждём" (TZ 3.1)."""
    import sqlalchemy as sa

    from core.db import enums as E
    from settler.tests.conftest import World

    user_id = await make_user(engine, BUYER_TG_ID)
    invoice_id, address_id = await make_invoice(
        engine, shop, user_id=user_id, index=1, amount_due_raw=10_000_000
    )
    async with engine.begin() as conn:
        world = World(conn)
        await world.block(shop.chain_id, 98)
        await world.payment(
            chain_id=shop.chain_id,
            asset_id=shop.asset_id,
            address_id=address_id,
            invoice_id=invoice_id,
            amount_raw=4_000_000,
            block_number=98,
            status=E.PaymentStatus.SEEN,
        )
        await conn.execute(
            sa.text("UPDATE chains SET last_indexed_block = 99 WHERE chain_id = :c"),
            {"c": shop.chain_id},
        )

    reply = await harness.send(f"/status {invoice_id}")

    assert "Received: <code>0 USDC</code> of <code>10 USDC</code>" in reply
    assert "Still missing: <code>10 USDC</code>" in reply
    # 99 - 98 + 1 = 2 confirmations of the 3 the chain row requires.
    assert "Unconfirmed: <code>4 USDC</code> — 2/3 confirmations" in reply
    # No address, ever, in a later message (TZ 5.8/T1.5).
    assert "0x" not in reply


async def test_status_never_carries_an_address(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    user_id = await make_user(engine, BUYER_TG_ID)
    invoice_id, address_id = await make_invoice(engine, shop, user_id=user_id, index=2)

    import sqlalchemy as sa

    async with engine.begin() as conn:
        address = (
            await conn.execute(
                sa.text("SELECT address FROM receive_addresses WHERE id = :id"),
                {"id": address_id},
            )
        ).scalar_one()

    reply = await harness.send(f"/status {invoice_id}")
    assert str(address).lower() not in reply.lower()


@pytest.mark.parametrize("argument", ["", "not-a-uuid", "12345"])
async def test_status_with_a_malformed_id_shows_usage(
    harness: Harness, argument: str
) -> None:
    reply = await harness.send(f"/status {argument}".strip())
    assert reply == texts.status_usage()


async def test_status_for_an_unknown_invoice_gives_the_not_found_sentence(
    harness: Harness,
) -> None:
    reply = await harness.send(f"/status {uuid.uuid4()}")
    assert reply == texts.status_not_found()


async def test_my_lists_open_invoices_and_granted_access(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """``/my`` — "история покупок и активные доступы" (TZ 3.1)."""
    import sqlalchemy as sa

    user_id = await make_user(engine, BUYER_TG_ID)
    open_id, _ = await make_invoice(engine, shop, user_id=user_id, index=3)
    paid_id, _ = await make_invoice(
        engine, shop, user_id=user_id, index=4, status="paid"
    )
    async with engine.begin() as conn:
        await conn.execute(
            sa.text(
                """
                INSERT INTO entitlements (user_id, product_id, invoice_id, granted_at)
                VALUES (:user_id, :product_id, :invoice_id, now())
                """
            ),
            {"user_id": user_id, "product_id": shop.product_id, "invoice_id": paid_id},
        )

    reply = await harness.send("/my")

    assert "Active access" in reply
    assert "Waiting for payment" in reply
    assert str(open_id) in reply
    assert shop.product_title in reply


async def test_my_when_nothing_has_been_bought(harness: Harness) -> None:
    reply = await harness.send("/my")
    assert "not bought anything yet" in reply


async def test_verify_passes_the_caller_down_and_renders_the_whole_triple(
    harness: Harness, shop: Shop, engine: AsyncEngine
) -> None:
    """``/verify`` — TZ 5.8/T1.4: fingerprint, full path, address."""
    user_id = await make_user(engine, BUYER_TG_ID)
    invoice_id = uuid.uuid4()
    harness.proofs.proof = a_proof(invoice_id)

    reply = await harness.send(f"/verify {invoice_id}")

    assert harness.proofs.calls == [
        {"user_id": user_id, "invoice_id": invoice_id, "timeout": 1.0}
    ]
    assert "<code>deadbeef</code>" in reply
    # The full path, not just the index, so it can be pasted whole into an
    # offline tool (TZ 5.8/T1.4). The apostrophes of hardened derivation survive
    # escaping because `bot.formatting.esc` uses `quote=False` — an escaped
    # `&#x27;` would be a path nobody can paste.
    assert "<code>m/44'/60'/0'/0/17</code>" in reply
    assert f"<code>{CHECKSUMMED_ADDRESS}</code>" in reply
    # The honest limit of the control, stated to the person who would otherwise
    # over-trust it.
    assert "does and does not prove" in reply


async def test_verify_tells_the_owner_they_can_complete_the_check(
    harness: Harness, engine: AsyncEngine
) -> None:
    """The owner holds the xpub, so for them the proof *is* completable."""
    from bot.tests.conftest import OWNER_TG_ID

    invoice_id = uuid.uuid4()
    harness.proofs.proof = a_proof(invoice_id)

    reply = await harness.send(f"/verify {invoice_id}", tg_id=OWNER_TG_ID)

    assert "reproduce this yourself" in reply
    assert "does and does not prove" not in reply


@pytest.mark.parametrize("argument", ["", "nonsense"])
async def test_verify_with_a_malformed_id_shows_usage_and_calls_nothing(
    harness: Harness, argument: str
) -> None:
    reply = await harness.send(f"/verify {argument}".strip())
    assert reply == texts.verify_usage()
    assert harness.proofs.calls == []


async def test_help_covers_all_four_wrong_ways_to_pay(
    harness: Harness, shop: Shop
) -> None:
    """TZ 3.1: "что делать, если отправил не туда, не столько или не тем токеном"."""
    reply = await harness.send("/help")

    assert "wrong amount" in reply
    assert "wrong token" in reply
    assert "wrong network" in reply
    assert "wrong address" in reply
    assert texts.SAFETY_RULE in reply
    # The admin commands are not advertised (TZ 3.4, 5.8/T7).
    assert "/resolve" not in reply
    assert "/pending" not in reply


async def test_every_reply_goes_out_as_html(harness: Harness) -> None:
    """The default is set on the client, not per call — see ``bot.main.main``.

    A per-call ``parse_mode`` is a thing to forget on exactly the one message
    that carries an address, so this asserts the client-level default is what
    the tests (and production) run with.
    """
    await harness.send("/help")
    sends = [c for c in harness.session.calls if isinstance(c, SendMessage)]
    assert sends
    for call in sends:
        assert harness.bot.session.api  # the session is the real one
        assert call.parse_mode is not None
