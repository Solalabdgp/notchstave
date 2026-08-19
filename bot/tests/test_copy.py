"""The copy layer, without a dispatcher: exact amounts, escaping, safety rules.

:mod:`bot.texts` and :mod:`bot.formatting` are pure ``data -> str``, which is
why the copy for a product that takes money can be read and tested on its own.
Three properties are load-bearing rather than cosmetic:

**Amounts are exact.** Every amount in this system is ``NUMERIC(78,0)`` base
units and the human form needs the asset's ``decimals``. A float in that
conversion puts a rounded number in front of somebody about to type it into a
wallet, and the payment that follows is short by an amount nobody can explain.

**Everything from outside is escaped.** A product title with an ``&`` in it is a
Tuesday, and an unescaped one silently truncates the whole message at the
client — including, on the invoice message, the address below it.

**The safety rule is a countermeasure, not copy.** TZ 5.8/T1.5: the address
changes only with a new invoice, the bot never asks for a seed phrase, messages
carrying an address are never edited. It is asserted to be identical in
``/start`` and ``/help`` because a user who compares the two must not find a
difference to interpret.
"""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal

import pytest

from bot import texts
from bot.formatting import (
    code,
    esc,
    format_amount,
    format_deadline,
    format_usd,
    humanise_duration,
    whole_units,
)
from bot.repository import InvoiceStatusRow, OpenInvoiceRow, ProductRow, PurchaseRow

# ---------------------------------------------------------------------------
# Amounts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,decimals,expected",
    [
        (12_500_000, 6, "12.5 USDC"),
        (10_000_000, 6, "10 USDC"),
        (1, 6, "0.000001 USDC"),
        (0, 6, "0 USDC"),
        (1_000_000_000_000_000_000, 18, "1 USDC"),
        # 78 digits is what the column holds. Nothing here may round it.
        (10**30 + 1, 18, "1000000000000.000000000000000001 USDC"),
    ],
)
def test_amounts_are_exact_at_every_scale(raw: int, decimals: int, expected: str) -> None:
    assert format_amount(Decimal(raw), decimals, "USDC") == expected


def test_whole_units_shifts_rather_than_divides() -> None:
    """``scaleb`` is an exact decimal shift; ``/ 10**decimals`` goes through the
    context's precision and can round a value the database stored exactly."""
    huge = Decimal(10) ** 40 + 7
    assert whole_units(huge, 18) * Decimal(10) ** 18 == huge


def test_usd_always_has_two_places() -> None:
    assert format_usd(Decimal("10")) == "$10.00"
    assert format_usd(Decimal("9.5")) == "$9.50"


# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------


def test_escaping_covers_the_characters_that_break_a_message() -> None:
    assert esc("Tom & Jerry <b>") == "Tom &amp; Jerry &lt;b&gt;"


def test_escaping_leaves_apostrophes_alone_so_a_derivation_path_stays_pasteable() -> None:
    """``quote=False``, deliberately.

    ``m/44'/60'/0'/0/17`` is the value TZ 5.8/T1.4 asks a reader to paste into an
    offline tool. Escaping the hardening marks to ``&#x27;`` would produce a
    path that renders correctly and cannot be used.
    """
    assert esc("m/44'/60'/0'/0/17") == "m/44'/60'/0'/0/17"


def test_a_hostile_product_title_cannot_inject_markup() -> None:
    products = [
        ProductRow(
            id=1,
            sku="evil",
            title="<b>Free</b> & <script>alert(1)</script>",
            price_usd=Decimal("10"),
            kind="one_off",
            subscription_days=None,
        )
    ]
    rendered = texts.shop(products)
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_code_blocks_are_what_makes_a_value_tap_to_copy() -> None:
    """TZ 3.1: "сумма и адрес выводятся ... в машинно-копируемом виде"."""
    assert code("0xAbC") == "<code>0xAbC</code>"


# ---------------------------------------------------------------------------
# Deadlines
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "seconds,expected",
    [
        (-1, "expired"),
        (0, "expired"),
        (30, "less than a minute"),
        (60, "1 minute"),
        (120, "2 minutes"),
        (3600, "1 hour"),
        (3900, "1 hour 5 minutes"),
        (7200, "2 hours"),
    ],
)
def test_durations_stop_at_minutes(seconds: int, expected: str) -> None:
    """No seconds. An invoice lives fifteen minutes and the message is never
    edited (TZ 5.8/T1.5, T5.4), so a ticking countdown would be wrong the moment
    it was read."""
    assert humanise_duration(dt.timedelta(seconds=seconds)) == expected


def test_a_deadline_carries_both_the_absolute_time_and_the_relative_one() -> None:
    """Neither half is redundant in a message that is never edited.

    The absolute time survives being read an hour later; the relative one is
    what a person acts on now. UTC is named rather than converted, because this
    process does not know the reader's zone and rendering a server's local time
    as though it were theirs is how a deadline is missed by an hour.
    """
    now = dt.datetime(2026, 8, 19, 14, 20, tzinfo=dt.UTC)
    rendered = format_deadline(now + dt.timedelta(minutes=12), now=now)
    assert rendered == "14:32 UTC (in 12 minutes)"


# ---------------------------------------------------------------------------
# The safety rule
# ---------------------------------------------------------------------------


def test_the_safety_rule_is_one_string_in_both_places() -> None:
    """TZ 5.8/T1.5 and TZ 12.

    An attacker who wants to normalise "sometimes the address changes" has to
    contradict the same sentence twice, and a user who compares ``/start``
    against ``/help`` must not find a paraphrase to interpret.
    """
    start = texts.start(is_new=True, chain_name="Base", asset_symbol="USDC")
    helped = texts.help_text(chain_name="Base", asset_symbol="USDC")

    assert texts.SAFETY_RULE in start
    assert texts.SAFETY_RULE in helped


@pytest.mark.parametrize(
    "phrase",
    [
        "changes <b>only</b> together with a new invoice",
        "never</b> ask for your private key",
        "never edited",
    ],
)
def test_the_safety_rule_names_all_three_attacks(phrase: str) -> None:
    assert phrase in texts.SAFETY_RULE


# ---------------------------------------------------------------------------
# Status rendering
# ---------------------------------------------------------------------------


def _status_row(**kw: object) -> InvoiceStatusRow:
    now = dt.datetime.now(dt.UTC)
    base: dict[str, object] = {
        "invoice_id": uuid.uuid4(),
        "status": "awaiting",
        "product_title": "Product 1",
        "product_sku": "sku-1",
        "amount_due_raw": Decimal(10_000_000),
        "amount_due_usd": Decimal("10"),
        "asset_symbol": "USDC",
        "asset_decimals": 6,
        "chain_name": "Base",
        "min_confirmations": 3,
        "expires_at": now + dt.timedelta(minutes=10),
        "topup_window_until": now + dt.timedelta(hours=24),
        "created_at": now,
        "public_token": "tok",
        "received_raw": Decimal(0),
        "pending_count": 0,
        "pending_raw": Decimal(0),
        "least_confirmations": None,
    }
    base.update(kw)
    return InvoiceStatusRow(**base)  # type: ignore[arg-type]


def test_missing_never_goes_negative_on_an_overpayment() -> None:
    row = _status_row(received_raw=Decimal(15_000_000), status="overpaid")
    assert row.missing_raw == 0
    assert "Still missing" not in texts.status(row)


@pytest.mark.parametrize(
    "status",
    [
        "awaiting",
        "seen",
        "partially_paid",
        "paid",
        "overpaid",
        "expired",
        "manual_review",
        "cancelled",
        "reverted",
    ],
)
def test_every_invoice_status_has_a_sentence(status: str) -> None:
    """A raw enum value in front of a buyer is a bug report they cannot file."""
    rendered = texts.status(_status_row(status=status))
    assert f"State: {status}" not in rendered


def test_status_shows_the_topup_window_only_once_the_deadline_has_passed() -> None:
    """Before the deadline it is noise; after it, it is the only useful number."""
    now = dt.datetime.now(dt.UTC)
    live = _status_row(expires_at=now + dt.timedelta(minutes=5))
    lapsed = _status_row(
        expires_at=now - dt.timedelta(minutes=5),
        created_at=now - dt.timedelta(minutes=20),
    )

    assert "Top-up window" not in texts.status(live, now=now)
    assert "Top-up window" in texts.status(lapsed, now=now)


# ---------------------------------------------------------------------------
# /my
# ---------------------------------------------------------------------------


def _purchase(**kw: object) -> PurchaseRow:
    base: dict[str, object] = {
        "product_title": "Product 1",
        "product_sku": "sku-1",
        "kind": "subscription",
        "invoice_id": uuid.uuid4(),
        "granted_at": dt.datetime.now(dt.UTC) - dt.timedelta(days=40),
        "expires_at": None,
        "revoked_at": None,
        "content_ref": "https://files.example/1",
    }
    base.update(kw)
    return PurchaseRow(**base)  # type: ignore[arg-type]


def test_a_revoked_grant_is_never_active_however_far_its_expiry_is(
) -> None:
    """A reorg revokes a grant (TZ 5.4) and the expiry does not move with it."""
    now = dt.datetime.now(dt.UTC)
    revoked = _purchase(
        expires_at=now + dt.timedelta(days=365), revoked_at=now - dt.timedelta(days=1)
    )
    assert revoked.is_active(now) is False


def test_a_perpetual_grant_stays_active(
) -> None:
    assert _purchase(expires_at=None).is_active(dt.datetime.now(dt.UTC)) is True


def test_my_separates_active_access_from_what_is_only_ordered() -> None:
    now = dt.datetime.now(dt.UTC)
    rendered = texts.my(
        [_purchase()],
        [
            OpenInvoiceRow(
                invoice_id=uuid.uuid4(),
                product_title="Product 2",
                status="awaiting",
                amount_due_usd=Decimal("25"),
                expires_at=now + dt.timedelta(minutes=10),
            )
        ],
        now=now,
    )
    assert rendered.index("Active access") < rendered.index("Waiting for payment")
    assert "$25.00" in rendered


# ---------------------------------------------------------------------------
# /verify
# ---------------------------------------------------------------------------


def test_the_verify_disclaimer_states_the_limit_of_the_control() -> None:
    """TZ 5.8/T1.4 — saying what a proof does not prove is what separates a
    countermeasure from an advertisement.

    A buyer cannot reproduce the address: that needs the account xpub, and
    publishing it is what T4 forbids. What the buyer *can* do is compare one
    address across three channels, and the message says exactly that.
    """
    from core.invoicing.proof import DerivationProof

    proof = DerivationProof(
        invoice_id=uuid.uuid4(),
        xpub_fingerprint="deadbeef",
        derivation_path="m/44'/60'/0'/0/17",
        derivation_index=17,
        address="0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        proof_mac=b"\x00" * 32,
    )
    rendered = texts.verify_proof(proof)

    assert "requires the account extended public key, which we do not publish" in (
        rendered.replace("\n", " ").replace("  ", " ")
    )
    assert "invoice message" in rendered
    assert "payment link" in rendered
    assert "invoice page" in rendered


def test_the_denial_text_is_literally_the_unknown_command_text() -> None:
    """TZ 5.8/T7 — do not confirm that an owner account exists.

    Equality rather than similarity, because two sentences that merely look
    alike drift apart the first time one of them is edited.
    """
    assert texts.admin_denied() == texts.free_text_unknown()
