"""The happy path of TZ 3.1 ``/buy <sku>``, and the shape of what it produces."""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import ROUND_CEILING, Decimal
from typing import Any

import psycopg
import pytest

from core.invoicing import errors
from core.invoicing.config import InvoicingPolicy
from core.invoicing.integrity import IntegrityKey
from core.invoicing.rates import StaticRates
from core.invoicing.service import InvoiceView, create_invoice
from core.invoicing.tests.conftest import (
    FakeDeriver,
    Shop,
    World,
    address_row,
    buy,
    count_rows,
    invoice_row,
    next_index,
    pool,
    scalar,
)


def _buy(
    conn: psycopg.Connection[Any],
    deriver: FakeDeriver,
    key: IntegrityKey,
    shop: Shop,
    **kwargs: Any,
) -> InvoiceView:
    return buy(conn, deriver, key, shop, **kwargs)


def test_buy_from_an_empty_pool_derives_reserves_and_issues_in_one_transaction(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """The case migration 0006 exists for.

    With no free address in the pool, the address row and the invoice row have
    to be created in the same transaction, each referencing the other. Before
    0006 this was impossible in any order — the deferred foreign key is what
    makes the two INSERTs one unit of work, and this test is what proves the
    deferral actually shipped rather than being described in a docstring.
    """
    shop = world.shop()

    view = _buy(conn, deriver, key, shop)

    assert view.newly_derived is True
    assert next_index(conn, shop.hd_account_id) == 1

    address = address_row(conn, view.address_id)
    assert address["status"] == "reserved"
    assert address["current_invoice_id"] == view.invoice_id
    assert address["reserved_from_block"] == shop.head_block
    assert address["address"] == view.address

    invoice = invoice_row(conn, view.invoice_id)
    assert invoice["address_id"] == view.address_id
    assert invoice["status"] == "awaiting"
    assert invoice["policy_version"] == view.policy_version

    # Both foreign keys are satisfiable at COMMIT — the whole point.
    conn.commit()
    assert count_rows(conn, "invoices") == 1


def test_the_pool_is_used_before_next_index_moves(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 5.1 p. 3 ordering, seen from the caller's side."""
    shop = world.shop(pooled_addresses=3, deriver=deriver)
    assert next_index(conn, shop.hd_account_id) == 3

    view = _buy(conn, deriver, key, shop)

    assert view.newly_derived is False
    assert view.derivation_index == 0, "the lowest free index goes first"
    assert next_index(conn, shop.hd_account_id) == 3, "reusing must not consume index space"


def test_the_amount_is_the_catalog_price_rounded_up_to_a_whole_base_unit(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """Rounding direction is a money decision, not a formatting one.

    $10.00 of an asset quoted at $3.00 is 3.333... whole tokens. Rounded down at
    six decimals the bill becomes payable for one base unit less than the price,
    and — worse — anyone paying the true price overpays, routing an ordinary
    purchase through the overpayment branch of TZ 5.5.
    """
    shop = world.shop(price_usd="10.00", symbol="ETH", decimals=18)
    rates = StaticRates({"ETH": Decimal("3")})

    view = _buy(conn, deriver, key, shop, rates=rates)

    exact = (Decimal("10.00") / Decimal(3)) * (Decimal(10) ** 18)
    assert view.amount_due_raw == exact.to_integral_value(rounding=ROUND_CEILING)
    assert view.amount_due_raw * 3 >= Decimal("10.00") * (Decimal(10) ** 18)
    assert view.rate_snapshot == Decimal(3)


def test_the_invoice_id_is_a_uuidv7_and_the_public_token_is_not_derived_from_it(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 6 and 5.8/T1.7 — not serial, and the page key is separate from the id."""
    shop = world.shop(pooled_addresses=2, deriver=deriver)

    first = _buy(conn, deriver, key, shop)
    second = _buy(conn, deriver, key, shop)

    for view in (first, second):
        assert view.invoice_id.version == 7
        assert view.invoice_id.variant == uuid.RFC_4122

    # Time-ordered, so the index stays local — the reason RFC 9562 defines v7.
    assert first.invoice_id.bytes[:6] <= second.invoice_id.bytes[:6]
    # And unguessable-in-the-tail, which is what stops enumeration.
    assert first.invoice_id.bytes[8:] != second.invoice_id.bytes[8:]

    assert first.public_token != second.public_token
    assert first.invoice_id.hex not in first.public_token
    assert len(first.public_token) <= 64, "must fit invoices.public_token"


def test_deadlines_follow_the_policy_and_satisfy_the_schema_checks(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 5.5 / 5.8-T5.4: fifteen minutes of invoice, a day of top-up window."""
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    moment = dt.datetime(2026, 8, 19, 12, 0, tzinfo=dt.UTC)
    policy = InvoicingPolicy(
        invoice_ttl=dt.timedelta(minutes=15),
        rate_lock_ttl=dt.timedelta(minutes=15),
        topup_window=dt.timedelta(hours=24),
    )

    view = _buy(conn, deriver, key, shop, policy=policy, now=moment)

    assert view.expires_at == moment + dt.timedelta(minutes=15)
    assert view.rate_locked_until == moment + dt.timedelta(minutes=15)
    assert view.topup_window_until == view.expires_at + dt.timedelta(hours=24)
    # `topup_window_after_expiry` and `expiry_after_creation` from migration 0001
    # would have refused the INSERT; getting here means both hold.
    assert view.created_at < view.expires_at <= view.topup_window_until


def test_the_public_token_ttl_is_the_invoice_life_plus_the_topup_window() -> None:
    """TZ 6, stated as a derived property rather than a separate knob."""
    policy = InvoicingPolicy(
        invoice_ttl=dt.timedelta(minutes=15), topup_window=dt.timedelta(hours=24)
    )
    assert policy.public_token_ttl == dt.timedelta(minutes=15, hours=24)


def test_a_refusal_leaves_no_trace_at_all(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """Everything that can refuse does so before anything is consumed.

    An inactive product is the cheapest refusal there is, and the assertion that
    matters is not the exception type — it is that ``next_index`` did not move
    and no address changed state. Issuance either happens completely or not at
    all, which is what lets the caller treat any exception as "roll back".
    """
    shop = world.shop(pooled_addresses=2, deriver=deriver)
    dead_product = world.product(active=False)

    with pytest.raises(errors.UnknownProduct):
        create_invoice(
            conn,
            deriver,
            key,
            user_id=shop.user_id,
            product_id=dead_product,
            chain_id=shop.chain_id,
            asset_id=shop.asset_id,
            hd_account_id=shop.hd_account_id,
            pool=pool,
        )

    assert next_index(conn, shop.hd_account_id) == 2
    assert count_rows(conn, "invoices") == 0
    assert count_rows(conn, "receive_addresses", "status <> 'free'") == 0


def test_a_disabled_asset_is_refused_without_saying_which_check_failed(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 12 — the accepted set is an allow-list, and probing it must be useless."""
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    disabled_id, _ = world.asset(shop.chain_id, symbol="SHADY", is_enabled=False)

    with pytest.raises(errors.UnknownAsset) as disabled:
        create_invoice(
            conn,
            deriver,
            key,
            user_id=shop.user_id,
            product_id=shop.product_id,
            chain_id=shop.chain_id,
            asset_id=disabled_id,
            hd_account_id=shop.hd_account_id,
            pool=pool,
        )

    with pytest.raises(errors.UnknownAsset) as absent:
        create_invoice(
            conn,
            deriver,
            key,
            user_id=shop.user_id,
            product_id=shop.product_id,
            chain_id=shop.chain_id,
            asset_id=999_999,
            hd_account_id=shop.hd_account_id,
            pool=pool,
        )

    assert disabled.value.user_message == absent.value.user_message


def test_an_unpriceable_asset_fails_before_an_address_is_spent(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 5.7 — no price feed means no invoice, not an invoice at a guessed price."""
    shop = world.shop(symbol="WETH", decimals=18)

    with pytest.raises(errors.RateUnavailable):
        _buy(conn, deriver, key, shop)

    assert next_index(conn, shop.hd_account_id) == 0


def test_issuance_writes_one_audit_row_and_no_secrets_into_it(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 5.8/T8 — every money decision keeps the policy version that made it.

    The negative half is the interesting one: ``audit_log`` is SELECT-able by
    every application role, so the public token — a bearer credential for the
    invoice page — must not be in it.
    """
    shop = world.shop(pooled_addresses=1, deriver=deriver)

    view = _buy(conn, deriver, key, shop)

    assert count_rows(conn, "audit_log", "action = 'invoice_created'") == 1
    row = scalar(
        conn,
        "SELECT after_state::text || args_json::text FROM audit_log "
        "WHERE target_id = %(id)s",
        id=str(view.invoice_id),
    )
    assert view.public_token not in row
    assert view.address not in row
    assert str(view.address_id) in row
    assert (
        scalar(
            conn,
            "SELECT policy_version FROM audit_log WHERE target_id = %(id)s",
            id=str(view.invoice_id),
        )
        == view.policy_version
    )
