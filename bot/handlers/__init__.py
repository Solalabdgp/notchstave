"""Router assembly. The order of the three routers is the whole content here.

aiogram walks routers in registration order and stops at the first handler that
matches, so this list is a priority statement:

1. ``admin`` — before the buyer commands, because ``/resolve`` and friends must
   be reached by their own handlers even though nothing in the buyer router
   would have claimed them. Registering it first also means the owner check is
   the first thing that runs on those words, rather than the second.
2. ``buyer`` — the seven commands of TZ 3.1.
3. ``freeform`` — last, and it must stay last. It matches *any* text message, so
   a router registered after it would never be reached.

There is deliberately no fourth router for callbacks. TZ 3.1 lists inline
buttons (open the invoice page, view the transaction in an explorer), and every
one of them is a URL button — a link the client opens itself, with no callback
coming back to this process. That is not an omission: a callback that could act
on an invoice would be a second, un-audited path into the money commands, and
the buttons named in the TZ need nothing of the sort.
"""

from __future__ import annotations

from aiogram import Router

from bot.handlers import admin, buyer, freeform

__all__ = ["build_router"]


def build_router() -> Router:
    """One root router with the three children attached in priority order.

    Everything here is built fresh on every call, children included. aiogram
    refuses to attach a router that already has a parent, so a module-level
    router object can be included exactly once in the lifetime of the process —
    which is invisible in production, where :func:`bot.main.main` builds one
    dispatcher, and immediately fatal for a suite that builds one per test. The
    per-module factories keep "how many bots can this process run" from being a
    question the answer to which is "one, by accident".
    """
    root = Router(name="notchstave")
    root.include_router(admin.build_router())
    root.include_router(buyer.build_router())
    root.include_router(freeform.build_router())
    return root
