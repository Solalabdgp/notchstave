"""Notchstave settler — the only package allowed to make a money decision.

Reading order for anyone new to this code:

1. :mod:`settler.policy` — the TZ 5.5 table as a pure function. Start here;
   everything else exists to apply what this module decides.
2. :mod:`settler.confirmations` — when a payment is safe to credit (TZ 5.4).
3. :mod:`settler.repository` — every SQL statement, including the literal
   compare-and-set shapes that TZ 5.8/T2.2 requires.
4. :mod:`settler.service` — the orchestration, plus the module docstring listing
   the known gaps.
5. :mod:`settler.locks` — why the Redis lock is allowed to be wrong.

The package never opens a network connection to a chain. Its entire view of the
blockchain is what the watcher has written to PostgreSQL (TZ section 4).
"""

from __future__ import annotations

from settler.errors import InconsistentInvoice, InvoiceNotFound, SettlerError
from settler.policy import DEFAULT_POLICY, AmountDecision, MoneyPolicy, Outcome, classify
from settler.service import (
    ReorgResult,
    SettlementResult,
    Settler,
    handle_reorg,
    review_anomalous_payments,
    settle_invoice,
    sweep_expired_invoices,
)

__all__ = [
    "AmountDecision",
    "DEFAULT_POLICY",
    "InconsistentInvoice",
    "InvoiceNotFound",
    "MoneyPolicy",
    "Outcome",
    "ReorgResult",
    "SettlementResult",
    "Settler",
    "SettlerError",
    "classify",
    "handle_reorg",
    "review_anomalous_payments",
    "settle_invoice",
    "sweep_expired_invoices",
]
