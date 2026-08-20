"""What the app is built out of, gathered in one object it is handed.

:func:`api.main.create_app` takes an :class:`ApiDependencies` and never reads
the environment, opens a connection, or loads a secret itself. That is what
makes the test suite able to build the real application — real routes, real
middleware, real handlers — against a test database and a
:class:`~core.invoicing.service.AddressDeriver` of its choosing, without
monkeypatching a module global.

**Connections are per-request and synchronous.** ``core.invoicing`` is
synchronous psycopg for the reasons its own module docstring sets out, and the
handlers reach it through ``asyncio.to_thread``. A pool would be the right
answer under load; a connect-per-request is the right answer for a page a human
opens, and it removes an entire class of "which transaction is this connection
in" bugs from a process whose job is to read. The note stays here rather than in
a TODO because it is a deliberate trade and not an omission — see
``core.invoicing.client`` making the same call for the same reason.

**Autocommit is on.** Every statement this process runs is a read. An implicit
transaction held open across a page render would pin a snapshot and make the
status endpoint report a confirmation count from whenever the connection was
opened.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import psycopg

from api.config import ApiConfig
from api.telegram import WebAppSecret
from core.invoicing.integrity import IntegrityKey
from core.invoicing.service import AddressDeriver, MacOnly

__all__ = ["ApiDependencies", "Connect", "psycopg_connector"]

#: A callable that hands back a fresh, open connection. A callable rather than a
#: connection so the app can be built before the database is up — which is what
#: lets ``/healthz`` report a database outage instead of the process failing to
#: start during one.
Connect = Callable[[], psycopg.Connection[Any]]


def psycopg_connector(config: ApiConfig) -> Connect:
    """The production :data:`Connect`. Autocommit, one per request."""

    def connect() -> psycopg.Connection[Any]:
        return psycopg.connect(config.psycopg_dsn, autocommit=True)

    return connect


@dataclass(frozen=True, slots=True)
class ApiDependencies:
    """Everything the routes need, resolved once at startup."""

    config: ApiConfig
    connect: Connect

    #: ``INVOICE_INTEGRITY_KEY``. TZ section 9 scopes it to settler/api/bot, so
    #: this process legitimately has it, and every invoice read goes through a
    #: MAC check against it (TZ 5.8/T1.3).
    integrity_key: IntegrityKey

    #: A real deriver, or :data:`core.invoicing.service.MAC_ONLY`. In production
    #: this is ``MAC_ONLY`` — TZ section 9 gives the xpub to
    #: ``notchstave-deriver.service`` and to no one else, and :class:`MacOnly`
    #: documents precisely what that costs and what still holds. Tests inject a
    #: real one to exercise the full T1.1 + T1.3 path.
    deriver: AddressDeriver | MacOnly

    #: ``None`` when no Telegram credential is configured. The public invoice
    #: page does not need it (TZ 5.8/T1.7 makes that page token-authorized);
    #: the ``initData`` endpoints answer 503 rather than pretending, and
    #: ``/healthz`` says so.
    webapp_secret: WebAppSecret | None

    async def read[T](self, work: Callable[[psycopg.Connection[Any]], T]) -> T:
        """Run one synchronous read on a fresh connection, off the event loop.

        The connection is closed on the way out whatever happens, including on
        an exception raised inside ``work`` — this is the only place in the
        package that opens one, so the guarantee is made once instead of at
        every call site.
        """

        def run() -> T:
            with self.connect() as conn:
                return work(conn)

        return await asyncio.to_thread(run)
