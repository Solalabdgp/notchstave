"""The money policy table of TZ 5.5, as a pure function.

> "Счастливый путь пишется за день, а вот эта таблица — за неделю, и именно
> она отличает продукт от демо." (TZ 5.5)

Everything in this module is deliberately free of I/O. :func:`classify` takes
numbers and a clock reading and returns a decision; the database work of
*applying* that decision lives in :mod:`settler.service`. The split exists so
that the table below can be tested exhaustively, cell by cell, without a
database — and so that a reviewer can read the whole policy on one screen
instead of reconstructing it from UPDATE statements.

The full table, with the TZ paragraph each row comes from:

| shortfall / excess                          | outcome                     | TZ    |
|---------------------------------------------|-----------------------------|-------|
| nothing creditable arrived yet              | `no_funds`                  | 5.3   |
| short by <= tolerance                       | `underpaid_tolerated`       | 5.5.1 |
| short by > tolerance, top-up window open    | `partially_paid`            | 5.5.2 |
| short by > tolerance, top-up window closed  | `underpaid_manual_review`   | 5.5.3 |
| exact, or over by <= tolerance              | `paid` / `overpaid_credited`| 5.5   |
| over by > tolerance                         | `overpaid_refund_pending`   | 5.5.2 |

Two asymmetries in that table are the whole point of it and must not be
"simplified" later:

* the underpayment tolerance is the **smaller** of a percentage and an absolute
  cap ("0.5% и не более 1 USD в абсолюте, что меньше"), because it exists to
  absorb an exchange withdrawal fee, not to discount the product;
* the overpayment tolerance is the **larger** of the two ("5% или 5 USD, что
  больше"), because it exists to avoid opening a refund case over dust.

And one rule with no exceptions: an underpayment beyond tolerance is never
auto-credited, in any state, ever. "Это дыра, через которую платят 1% от цены
и получают товар."
"""

from __future__ import annotations

import datetime as dt
import enum
import os
from dataclasses import dataclass
from decimal import ROUND_FLOOR, Decimal

from settler.amounts import usd_to_raw

__all__ = [
    "Outcome",
    "MoneyPolicy",
    "AmountDecision",
    "DEFAULT_POLICY",
    "classify",
    "SETTLED_OUTCOMES",
    "GRANTING_OUTCOMES",
]


class Outcome(enum.StrEnum):
    """What the settler decided about an invoice.

    These values are user-visible in three places — the ``outcome`` label of
    ``notchstave_invoices_settled_total`` (TZ 7), the ``audit_log`` entry of the
    decision, and the notification payload — so they are a stable vocabulary,
    not an implementation detail.
    """

    #: No creditable payment yet, or not enough confirmations for the amount.
    NO_FUNDS = "no_funds"
    AWAITING_CONFIRMATIONS = "awaiting_confirmations"

    #: Settled outcomes. Product is delivered in all three.
    PAID = "paid"
    UNDERPAID_TOLERATED = "underpaid_tolerated"
    OVERPAID_CREDITED = "overpaid_credited"
    OVERPAID_REFUND_PENDING = "overpaid_refund_pending"

    #: Not settled: the buyer still owes money and can still send it.
    PARTIALLY_PAID = "partially_paid"

    #: Not settled and never auto-settled. A human decides (TZ 3.4 `/resolve`).
    UNDERPAID_MANUAL_REVIEW = "underpaid_manual_review"
    ANOMALY_MANUAL_REVIEW = "anomaly_manual_review"

    #: Someone else already did this work — the CAS in TZ 5.8/T2.2 lost.
    ALREADY_SETTLED = "already_settled"

    #: No decision was taken at all: another worker holds the advisory Redis
    #: lock (TZ 5.8/T2.4). Distinct from ALREADY_SETTLED on purpose — nothing is
    #: known about the invoice here, and the next scan will look again.
    SKIPPED_BUSY = "skipped_busy"

    #: The invoice is not in a state where money decisions apply at all
    #: (cancelled, expired, reverted, already in manual review).
    NOT_LIVE = "not_live"

    #: ``integrity_mac`` did not verify (TZ 5.8/T1.3). Not a money decision and
    #: deliberately not one of the states above: nothing about the amount was
    #: decided, because the amount is one of the fields that failed to
    #: authenticate. The invoice is taken out of the live set and a human is
    #: called; see :func:`settler.service.settle_invoice`.
    INTEGRITY_FAILED = "integrity_failed"


#: Outcomes after which the invoice is closed and the product is owed.
SETTLED_OUTCOMES = frozenset(
    {
        Outcome.PAID,
        Outcome.UNDERPAID_TOLERATED,
        Outcome.OVERPAID_CREDITED,
        Outcome.OVERPAID_REFUND_PENDING,
    }
)

#: Outcomes that grant an entitlement. Identical to the set above by design:
#: TZ 5.5 is explicit that an overpayment above tolerance still delivers the
#: product ("товар выдаётся (обязательство перед покупателем выполнено)") and
#: only *then* opens a refund obligation.
GRANTING_OUTCOMES = SETTLED_OUTCOMES


#: The default table, as module constants rather than only as dataclass field
#: defaults — and that is not a style choice.
#:
#: ``MoneyPolicy`` is ``slots=True``, and on a slotted dataclass the class
#: attribute is the slot *descriptor*, not the default value: ``MoneyPolicy
#: .underpay_tolerance_pct`` evaluates to ``<member '...' of 'MoneyPolicy'
#: objects>``. Reading a default off the class inside :meth:`MoneyPolicy
#: .from_env` therefore builds a policy whose thresholds are descriptor objects,
#: which either raises on the first multiplication or writes a repr into
#: ``policy_version`` — a settler that fails at start-up in the lucky case and
#: silently records nonsense in the audit trail in the unlucky one.
#:
#: Naming the defaults once, here, is what makes both the dataclass and the
#: environment reader refer to the same value with no way to diverge.
DEFAULT_POLICY_VERSION = "2026-08-15.settler-1"

#: TZ 5.5.1 — "не больше 0.5% и не более 1 USD в абсолюте, что меньше".
DEFAULT_UNDERPAY_TOLERANCE_PCT = Decimal("0.005")
DEFAULT_UNDERPAY_TOLERANCE_CAP_USD = Decimal("1")

#: TZ 5.5 overpayment — "5% или 5 USD, что больше".
DEFAULT_OVERPAY_TOLERANCE_PCT = Decimal("0.05")
DEFAULT_OVERPAY_TOLERANCE_FLOOR_USD = Decimal("5")


@dataclass(frozen=True, slots=True)
class MoneyPolicy:
    """Configurable thresholds of TZ 5.5. "Все пороги — конфиг."

    ``version`` is written into ``invoices.policy_version``,
    ``manual_reviews.policy_version`` and every ``audit_log`` row the settler
    writes, so that a decision taken months ago can still be explained by the
    numbers that were in force at the time (TZ 5.8/T8). Change a threshold →
    change the version; the two are one edit.
    """

    version: str = DEFAULT_POLICY_VERSION

    underpay_tolerance_pct: Decimal = DEFAULT_UNDERPAY_TOLERANCE_PCT
    underpay_tolerance_cap_usd: Decimal = DEFAULT_UNDERPAY_TOLERANCE_CAP_USD

    overpay_tolerance_pct: Decimal = DEFAULT_OVERPAY_TOLERANCE_PCT
    overpay_tolerance_floor_usd: Decimal = DEFAULT_OVERPAY_TOLERANCE_FLOOR_USD

    def underpay_tolerance_raw(self, due_raw: Decimal, decimals: int, rate: Decimal) -> Decimal:
        """Largest shortfall still counted as paid, in base units."""
        pct_part = (due_raw * self.underpay_tolerance_pct).to_integral_value(rounding=ROUND_FLOOR)
        cap_part = usd_to_raw(self.underpay_tolerance_cap_usd, decimals, rate)
        return min(pct_part, cap_part)

    def overpay_tolerance_raw(self, due_raw: Decimal, decimals: int, rate: Decimal) -> Decimal:
        """Largest excess absorbed as internal balance instead of a refund case."""
        pct_part = (due_raw * self.overpay_tolerance_pct).to_integral_value(rounding=ROUND_FLOOR)
        floor_part = usd_to_raw(self.overpay_tolerance_floor_usd, decimals, rate)
        return max(pct_part, floor_part)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> MoneyPolicy:
        """Read the thresholds from the environment, keeping the defaults above.

        Deliberately not pydantic-Settings: this object is passed explicitly
        into every decision so that a test can hand in a different table, and a
        global settings singleton would quietly make that impossible.
        """
        src = os.environ if env is None else env

        def _dec(key: str, default: Decimal) -> Decimal:
            raw = src.get(key)
            return default if raw is None or raw == "" else Decimal(raw)

        return cls(
            version=src.get("SETTLER_POLICY_VERSION", DEFAULT_POLICY_VERSION),
            underpay_tolerance_pct=_dec(
                "SETTLER_UNDERPAY_TOLERANCE_PCT", DEFAULT_UNDERPAY_TOLERANCE_PCT
            ),
            underpay_tolerance_cap_usd=_dec(
                "SETTLER_UNDERPAY_TOLERANCE_CAP_USD", DEFAULT_UNDERPAY_TOLERANCE_CAP_USD
            ),
            overpay_tolerance_pct=_dec(
                "SETTLER_OVERPAY_TOLERANCE_PCT", DEFAULT_OVERPAY_TOLERANCE_PCT
            ),
            overpay_tolerance_floor_usd=_dec(
                "SETTLER_OVERPAY_TOLERANCE_FLOOR_USD", DEFAULT_OVERPAY_TOLERANCE_FLOOR_USD
            ),
        )


DEFAULT_POLICY = MoneyPolicy()


@dataclass(frozen=True, slots=True)
class AmountDecision:
    """Outcome plus the numbers that justify it.

    ``delta_raw`` is signed and always ``total - due``: negative is a shortfall
    the buyer still owes, positive is an excess we owe back or credit. Callers
    put it straight into the message to the user, which is why it is part of
    the decision and not recomputed downstream — two places computing "how much
    is missing" is one place too many.
    """

    outcome: Outcome
    due_raw: Decimal
    total_raw: Decimal
    delta_raw: Decimal
    tolerance_raw: Decimal

    @property
    def shortfall_raw(self) -> Decimal:
        """How much is still owed (0 when covered)."""
        return -self.delta_raw if self.delta_raw < 0 else Decimal(0)

    @property
    def excess_raw(self) -> Decimal:
        """How much arrived beyond the bill (0 when not overpaid)."""
        return self.delta_raw if self.delta_raw > 0 else Decimal(0)


def classify(
    *,
    due_raw: Decimal,
    total_raw: Decimal,
    decimals: int,
    rate: Decimal,
    now: dt.datetime,
    topup_window_until: dt.datetime,
    policy: MoneyPolicy = DEFAULT_POLICY,
) -> AmountDecision:
    """Apply the TZ 5.5 table. No I/O, no clock of its own, no surprises.

    ``now`` is passed in rather than read from the system clock so that the
    "top-up window closed" branch is testable without sleeping, and so that the
    caller can use the *database* clock — the only clock that is the same for
    every worker.
    """
    delta = total_raw - due_raw

    if total_raw <= 0:
        return AmountDecision(Outcome.NO_FUNDS, due_raw, total_raw, delta, Decimal(0))

    if delta < 0:
        tolerance = policy.underpay_tolerance_raw(due_raw, decimals, rate)
        if -delta <= tolerance:
            # 5.5.1 — an exchange withdrawal fee, not a haggle. Close it.
            return AmountDecision(Outcome.UNDERPAID_TOLERATED, due_raw, total_raw, delta, tolerance)
        if now <= topup_window_until:
            # 5.5.2 — the window outlives the invoice on purpose: someone who
            # already sent money is in a different position from someone who
            # simply did not pay.
            return AmountDecision(Outcome.PARTIALLY_PAID, due_raw, total_raw, delta, tolerance)
        # 5.5.3 — never auto-credited. `/resolve` decides.
        return AmountDecision(
            Outcome.UNDERPAID_MANUAL_REVIEW, due_raw, total_raw, delta, tolerance
        )

    tolerance = policy.overpay_tolerance_raw(due_raw, decimals, rate)
    if delta == 0:
        return AmountDecision(Outcome.PAID, due_raw, total_raw, delta, tolerance)
    if delta <= tolerance:
        # Credited to the user's internal balance and stated in plain words.
        # "Тихо оставлять себе чужие деньги нельзя."
        return AmountDecision(Outcome.OVERPAID_CREDITED, due_raw, total_raw, delta, tolerance)
    # Product is delivered; the excess becomes a refund obligation that a human
    # executes offline. The bot never sends an outgoing transfer (TZ 12).
    return AmountDecision(Outcome.OVERPAID_REFUND_PENDING, due_raw, total_raw, delta, tolerance)
