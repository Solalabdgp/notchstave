"""What both ends of the admin queue have to agree on (migration 0012).

The bot enqueues an owner command and the settler executes it, so exactly three
things must mean the same in two processes: the channel names, the set of
operations, and which value object each operation answers with. They live here
rather than in :mod:`settler.admin.queue` (the settler half) or
:mod:`settler.admin.client` (the bot half) so that neither half owns the
contract and neither can change it alone.

This module deliberately imports only the value objects and the errors — no
:class:`~settler.admin.ops.AdminOps`, no
:class:`~settler.admin.balances.BalanceSource`, nothing that reaches RPC. The
bot process should be able to speak this protocol without having the code that
executes it, which is the whole point of moving the execution out.

**The error vocabulary travels by class name**, the same technique
:mod:`core.invoicing.client` uses: the settler writes ``type(exc).__name__`` and
the bot looks it up here. A name this table does not know degrades to
:class:`~settler.admin.errors.AdminActionFailed` rather than crashing, because a
bot on an older deploy than the settler must still be able to say something true
about a refusal it has never heard of.
"""

from __future__ import annotations

import uuid

from settler.admin import errors as E
from settler.admin.reconcile import ReconcileReport
from settler.admin.reviews import PendingCase, ResolutionResult
from settler.admin.sweeplist import SweepExport

__all__ = [
    "CHANNEL_ADMIN_REQUESTS",
    "REPLY_CHANNEL_PREFIX",
    "reply_channel",
    "OPS",
    "OP_PENDING",
    "OP_RESOLVE",
    "OP_SWEEPLIST",
    "OP_RECONCILE",
    "ERROR_CLASSES",
    "PendingCase",
    "ResolutionResult",
    "SweepExport",
    "ReconcileReport",
]

#: Must equal migration 0012's ``CHANNEL_ADMIN_REQUESTS``. Asserted equal by
#: ``settler/tests/test_admin_queue.py`` — three copies of a string whose
#: divergence produces no error, only a round trip that quietly falls back to the
#: settler's poll interval.
CHANNEL_ADMIN_REQUESTS = "notchstave_admin_requests"
REPLY_CHANNEL_PREFIX = "nsa_"


def reply_channel(request_id: uuid.UUID) -> str:
    """The channel this request's answer will arrive on (migration 0012)."""
    return f"{REPLY_CHANNEL_PREFIX}{request_id.hex}"


OP_PENDING = "pending"
OP_RESOLVE = "resolve"
OP_SWEEPLIST = "sweeplist"
OP_RECONCILE = "reconcile"

#: Must equal migration 0012's ``OPS`` enum, in the same order.
OPS: tuple[str, ...] = (OP_PENDING, OP_RESOLVE, OP_SWEEPLIST, OP_RECONCILE)

#: Name -> class, built from :mod:`settler.admin.errors`'s own ``__all__`` so a
#: refusal added there is routable the moment it exists.
ERROR_CLASSES: dict[str, type[E.AdminError]] = {
    name: cls
    for name in E.__all__
    if isinstance(cls := getattr(E, name), type) and issubclass(cls, E.AdminError)
}
