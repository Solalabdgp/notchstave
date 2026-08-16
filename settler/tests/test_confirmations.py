"""TZ 5.4 — how deep a payment must be buried before it buys anything.

Pure arithmetic, so it is tested as arithmetic. The database half of TZ 5.4
(a large payment actually waiting, a reorg actually revoking) lives in
``test_settlement.py`` and ``test_reorg.py``.

The property under test is not "the maths is right" — it is that the two
regimes of TZ 5.4 are chosen by the *amount*, and that the expensive regime
fails closed. A finality check that waves payments through when the chain has
not reported a finalized block is worse than no finality check at all, because
it looks like one.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from settler.confirmations import ConfirmationRule, creditable_cutoff_height, required_rule

DECIMALS = 6
RATE = Decimal(1)
THRESHOLD = Decimal(20)


def rule_for(amount_raw: int, *, min_confirmations: int = 3) -> ConfirmationRule:
    return required_rule(
        amount_raw=Decimal(amount_raw),
        decimals=DECIMALS,
        rate=RATE,
        min_confirmations=min_confirmations,
        credit_threshold_usd=THRESHOLD,
    )


# ---------------------------------------------------------------------------
# Which regime applies
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("amount_raw", "usd", "needs_finality"),
    [
        (3_000_000, "3", False),
        (19_999_999, "19.999999", False),
        # "до credit_threshold_usd ... выше — только по финализированному":
        # exactly on the threshold takes the cheap path, one unit above does not.
        (20_000_000, "20", False),
        (20_000_001, "20.000001", True),
        (300_000_000, "300", True),
    ],
)
def test_regime_is_chosen_by_amount(amount_raw: int, usd: str, needs_finality: bool) -> None:
    rule = rule_for(amount_raw)
    assert rule.amount_usd == Decimal(usd)
    assert rule.needs_finality is needs_finality


def test_regime_follows_the_invoice_rate() -> None:
    """The same quantity of a different asset is a different amount of money.

    0.01 ETH is under the threshold at 1000 USD/ETH and over it at 4000, and
    the regime has to follow the money rather than the token count.
    """
    hundredth_eth = Decimal(10) ** 16

    cheap = required_rule(
        amount_raw=hundredth_eth,
        decimals=18,
        rate=Decimal(1000),
        min_confirmations=3,
        credit_threshold_usd=THRESHOLD,
    )
    dear = required_rule(
        amount_raw=hundredth_eth,
        decimals=18,
        rate=Decimal(4000),
        min_confirmations=3,
        credit_threshold_usd=THRESHOLD,
    )

    assert cheap.amount_usd == Decimal(10)
    assert cheap.needs_finality is False
    assert dear.amount_usd == Decimal(40)
    assert dear.needs_finality is True


def test_label_names_the_regime_for_the_audit_log() -> None:
    assert rule_for(3_000_000).label == ">=3conf"
    assert rule_for(300_000_000).label == "finalized"


# ---------------------------------------------------------------------------
# The cutoff height
# ---------------------------------------------------------------------------


def test_small_payment_is_credited_by_confirmation_count() -> None:
    """head 100 with 3 required confirmations makes block 98 the deepest new one.

    98, 99, 100 is three blocks inclusive — the off-by-one that would credit a
    payment one block too early lives exactly here.
    """
    rule = rule_for(3_000_000, min_confirmations=3)
    assert creditable_cutoff_height(head_block=100, rule=rule, finalized_head=95) == 98


def test_small_payment_ignores_finality_entirely() -> None:
    """Below the threshold, a chain that has finalized nothing is not a problem."""
    rule = rule_for(3_000_000, min_confirmations=3)
    assert creditable_cutoff_height(head_block=100, rule=rule, finalized_head=None) == 98
    assert creditable_cutoff_height(head_block=100, rule=rule, finalized_head=10) == 98


def test_large_payment_is_capped_by_the_finalized_head() -> None:
    """"Тридцать подтверждений на секвенсере не значат ничего" (TZ 5.4).

    Above the threshold the confirmation count stops being evidence: the cutoff
    is the finalized head even though 98 blocks are technically deep enough.
    """
    rule = rule_for(300_000_000, min_confirmations=3)
    assert creditable_cutoff_height(head_block=100, rule=rule, finalized_head=95) == 95


def test_large_payment_still_respects_the_confirmation_count() -> None:
    """Finality is an additional condition, not a replacement for depth.

    A chain reporting a finalized head *ahead* of the indexed head (a lagging
    watcher, a provider returning an optimistic tag) must not let a payment
    from the last two blocks through.
    """
    rule = rule_for(300_000_000, min_confirmations=3)
    assert creditable_cutoff_height(head_block=100, rule=rule, finalized_head=200) == 98


def test_large_payment_fails_closed_when_nothing_is_finalized() -> None:
    """No finalized block means no large credit — not "credit anyway" (TZ 5.4).

    ``-1`` rather than ``0`` because block 0 is a real height: a genesis-block
    payment must not slip through the one gap a zero would leave.
    """
    rule = rule_for(300_000_000, min_confirmations=3)
    assert creditable_cutoff_height(head_block=100, rule=rule, finalized_head=None) == -1


def test_nothing_qualifies_on_a_chain_shallower_than_its_own_policy() -> None:
    """A fresh chain at height 1 with 3 required confirmations credits nothing."""
    rule = rule_for(3_000_000, min_confirmations=3)
    assert creditable_cutoff_height(head_block=1, rule=rule, finalized_head=None) == -1
