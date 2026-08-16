"""Failure modes of the settler.

There are deliberately very few of these. Almost every unusual situation in
money handling is a *decision*, not an exception — an underpayment, a late
top-up or a lost race are all normal outcomes with a recorded policy behind
them (see :class:`settler.policy.Outcome`). Raising for those would push the
decision into a stack trace, where nobody can audit it.

What remains here is the small set of situations where continuing would mean
guessing about money.
"""

from __future__ import annotations

__all__ = [
    "SettlerError",
    "InvoiceNotFound",
    "InconsistentInvoice",
]


class SettlerError(Exception):
    """Base class for settler failures."""


class InvoiceNotFound(SettlerError):
    """No ``invoices`` row with this id.

    Not the same thing as "nothing to do": a settle request for an id that does
    not exist means the caller (queue, admin command, retry) is working from a
    stale or forged reference, and swallowing it would hide that.
    """


class InconsistentInvoice(SettlerError):
    """The invoice row contradicts the rows it depends on.

    Example: ``invoices.asset_id`` points at an asset belonging to a different
    chain. The schema forbids this through a composite foreign key
    (``fk_invoices_asset_id_chain_id_assets``), so reaching this exception means
    the database was modified outside the application — the same class of event
    as a MAC failure in TZ 5.8/T1. Refuse to credit, alert, let a human look.
    """
