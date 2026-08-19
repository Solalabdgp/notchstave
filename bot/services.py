"""What a handler is allowed to reach for, in one object.

Handlers receive this through aiogram's dependency injection (``dp["services"]``
becomes a ``services`` argument on every handler that names one), which is the
whole reason it exists: the alternative is module-level singletons built at
import time, and those cannot be swapped for a test without mutating the
importing module.

The membership of this class is deliberately a *narrow* list rather than "the
world". Four collaborators, and each one is the only route to a capability:

* :class:`~bot.repository.BotRepository` — reads, plus the one write this
  process is allowed to originate (``users``, from ``/start``).
* :class:`~core.invoicing.client.InvoiceClient` — the only way to create an
  invoice. It is a client for the deriver's queue, not a function, because the
  bot's role has no INSERT on ``invoices`` (migration 0006).
* :class:`~core.invoicing.proof.ProofClient` — the only way to obtain an address
  the bot may display outside the message that created it (TZ 5.3, 5.8/T1.4).
* :class:`~settler.admin.AdminOps` — the only way to act on money, and it runs
  under the *settler's* role, not this one. TZ 5.8/T7's premise is a captured
  owner account; the answer is that even the owner's commands cannot write
  ``entitlements`` from this process.

``admin`` and ``balances`` are optional and default to ``None``, which is the
fail-closed state: an unconfigured deployment answers the admin commands as
though they do not exist, rather than answering them without the checks.
"""

from __future__ import annotations

from dataclasses import dataclass

from bot.config import BotConfig
from bot.repository import BotRepository
from core.invoicing.client import InvoiceClient
from core.invoicing.proof import ProofClient
from settler.admin.balances import BalanceSource
from settler.admin.ops import AdminOps

__all__ = ["BotServices"]


@dataclass(frozen=True, slots=True)
class BotServices:
    config: BotConfig
    repo: BotRepository
    invoices: InvoiceClient
    proofs: ProofClient
    #: ``None`` when no owner is configured — see :class:`bot.config.BotConfig`.
    admin: AdminOps | None = None
    #: On-chain balances for ``/reconcile`` and ``/sweeplist``. ``None`` when the
    #: process could not build an RPC pool, in which case those two commands say
    #: so instead of reporting a reconciliation against zero — which would read
    #: as "everything is missing" and is the single most alarming wrong answer
    #: this system can produce.
    balances: BalanceSource | None = None
