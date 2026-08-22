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
* :class:`~settler.admin.client.AdminClient` — the only way to act on money, and
  it does not act: it *asks* the settler to, over the queue of migration 0012, so
  the decision executes under the settler's role and not this one. TZ 5.8/T7's
  premise is a captured owner account; the answer is that even the owner's
  commands cannot write ``entitlements`` from this process.

``admin`` is optional and defaults to ``None``, which is the fail-closed state:
an unconfigured deployment answers the admin commands as though they do not
exist, rather than answering them without the checks.

There is no ``balances`` member any more, and its absence is the visible half of
migration 0012. On-chain balances for `/reconcile` and `/sweeplist` are now read
in the process that executes those commands; this one no longer builds an RPC
pool, and with it no longer carries ``web3``, a provider rotation or a circuit
breaker in order to run two commands whose results it is not allowed to write.
"""

from __future__ import annotations

from dataclasses import dataclass

from bot.config import BotConfig
from bot.repository import BotRepository
from core.invoicing.client import InvoiceClient
from core.invoicing.proof import ProofClient
from settler.admin.client import AdminClient

__all__ = ["BotServices"]


@dataclass(frozen=True, slots=True)
class BotServices:
    config: BotConfig
    repo: BotRepository
    invoices: InvoiceClient
    proofs: ProofClient
    #: ``None`` when no owner is configured — see :class:`bot.config.BotConfig`.
    admin: AdminClient | None = None
