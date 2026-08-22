"""Owner-facing money operations — the four commands of TZ 3.4.

``/pending``, ``/resolve``, ``/sweeplist``, ``/reconcile``. What lives here is
the *decision*, not the chat: nothing in this package imports aiogram, formats a
Telegram message or knows what a chat id is. The bot (Week 5) parses the command,
checks the fixed ``tg_id``, and calls one function from here.

That split is not tidiness. Three consequences follow from it, and each one is
the reason a reviewer should look at this package before looking at the bot.

**1. The bot never gains the privilege to grant.** TZ 5.8/T2 rests on there
being exactly one code path that writes ``entitlements``, guarded by
``entitlements_active_uniq``. ``/resolve credit`` grants a product, so it runs
under the settler's role, and migration 0003 revokes ``INSERT`` on
``entitlements`` from every other role in writing. A compromised bot process
(T7's premise) can therefore issue commands but cannot itself hand out anything.

**2. The threshold on a manual credit is testable.** TZ 5.8/T7 asks for a second
message carrying a code from the first. Implemented as
:mod:`settler.admin.twostep` — a function that takes a ``confirmation_code`` —
so the property under test is "the second call must present a code bound to this
exact decision", not "a Telegram conversation happened".

**3. Reading the chain and deciding about money stay separate.**
``/reconcile`` and ``/sweeplist`` need on-chain balances, and
:mod:`settler.service` states as an invariant that it holds no RPC client. That
invariant is intact: RPC lives in :mod:`settler.admin.balances`, behind a
:class:`~settler.admin.balances.BalanceSource` protocol, and it reuses the
watcher's :class:`~watcher.rpc.pool.RpcPool` — one rotation, one circuit
breaker, one request budget (TZ 5.6). There is no second pool in this
repository and there must not be one.

----

**What none of this does, by construction (TZ 12).** ``/resolve refund`` writes
a row in ``refunds`` with status ``pending`` and stops. ``/sweeplist`` writes a
CSV and stops. Neither this package nor any other in the repository can build,
sign or broadcast a transaction. "Компрометация самого привилегированного
аккаунта системы не приводит к потере средств" is a claim the code has to keep
true, and the way it keeps it true is by not containing the capability.
"""

from settler.admin.client import AdminClient
from settler.admin.errors import (
    AdminActionFailed,
    AdminError,
    AdminUnavailable,
    BalancesUnavailable,
    ConfirmationRequired,
    InvalidConfirmationCode,
    ResolutionNotApplicable,
    ReviewAlreadyResolved,
    ReviewNotFound,
)
from settler.admin.ops import AdminOps
from settler.admin.policy import DEFAULT_ADMIN_POLICY, AdminPolicy
from settler.admin.queue import AdminWorker
from settler.admin.reconcile import AddressDrift, ReconcileReport, reconcile
from settler.admin.reviews import (
    PendingCase,
    ResolutionOutcome,
    ResolutionResult,
    list_pending,
    resolve_manual_review,
)
from settler.admin.sweeplist import SweepExport, SweepRow, generate_sweep_list

__all__ = [
    "AddressDrift",
    "AdminActionFailed",
    "AdminClient",
    "AdminError",
    "AdminOps",
    "AdminPolicy",
    "AdminUnavailable",
    "AdminWorker",
    "BalancesUnavailable",
    "ConfirmationRequired",
    "DEFAULT_ADMIN_POLICY",
    "InvalidConfirmationCode",
    "PendingCase",
    "ReconcileReport",
    "ResolutionNotApplicable",
    "ResolutionOutcome",
    "ResolutionResult",
    "ReviewAlreadyResolved",
    "ReviewNotFound",
    "SweepExport",
    "SweepRow",
    "generate_sweep_list",
    "list_pending",
    "reconcile",
    "resolve_manual_review",
]
