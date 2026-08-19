"""Invoice issuance and address-integrity checks (TZ 3.1, 5.3, 5.8/T1, T5).

The service layer behind ``/buy``. It is a library, not a process: the bot, the
api and anything else that has to put an address in front of a person call into
here, and there is no second implementation of any of it anywhere.

**Which half you are in decides which door you use.** Since migration 0006 only
``notchstave_deriver`` may mint an invoice, and since ``create_invoice`` needs a
live xpub for ``deriver.verify``, issuance happens in the deriver process and
nowhere else:

* ``bot`` / ``api`` — :class:`core.invoicing.client.InvoiceClient`. It asks the
  deriver over ``invoice_requests`` (migration 0007), verifies the reply's MAC
  and hands back the same :class:`~core.invoicing.service.InvoiceView` a direct
  call would have. Calling :func:`~core.invoicing.service.create_invoice`
  directly from those processes fails on a missing INSERT grant, which is the
  system telling you the truth rather than an obstacle to work around.
* the deriver process — :mod:`core.invoicing.issuer`, its composition root and
  entry point, which is what actually calls ``create_invoice``.

``client`` is deliberately **not** re-exported from this package. It imports
``asyncio`` for its async wrapper, and this ``__init__`` is inside the import
closure of the process that holds the xpub — where ``asyncio`` is a forbidden
import (``deriver/tests/test_isolation.py``). Importing the client here would
put it there transitively and fail that test, which is the mechanism working
rather than an inconvenience.

Two things every caller must know, and nothing else:

**Never render an address you did not get from this package.** Both
:func:`~core.invoicing.service.create_invoice` and
:func:`~core.invoicing.service.verify_invoice_address` return an
:class:`~core.invoicing.service.InvoiceView` only after re-deriving the address
from the xpub *and* re-checking the invoice's HMAC, and both raise rather than
returning a flag. Reading ``invoices.address`` with your own SELECT skips the
countermeasures of TZ 5.8/T1 entirely.

**The transaction is yours.** Nothing here commits. Open a transaction, call
:func:`~core.invoicing.service.create_invoice`, commit on success, roll back on
any exception — every refusal is then also a complete undo, including the
address it had already taken out of the pool.

Wiring from ``bot`` / ``api``, in full::

    from core.invoicing import load_integrity_key
    from core.invoicing.client import InvoiceClient, active_hd_account_id

    client = InvoiceClient(dsn, load_integrity_key())   # once, at startup
    view = await client.acreate_invoice(
        user_id=..., product_id=..., chain_id=..., asset_id=...,
        hd_account_id=...,
    )
    await bot.send_message(chat_id, render(view.address, view.eip681()))

Wiring inside the deriver process, in full — this is what
:mod:`core.invoicing.issuer` does and the only place it is done::

    import deriver.pool
    from core.invoicing import create_invoice, load_integrity_key

    key = load_integrity_key()          # systemd credential, cached at startup
    with conn.transaction():
        view = create_invoice(
            conn, deriver, key,
            user_id=..., product_id=..., chain_id=..., asset_id=...,
            hd_account_id=..., pool=deriver.pool,
        )
"""

from __future__ import annotations

from core.invoicing.config import DEFAULT_POLICY, InvoicingPolicy
from core.invoicing.eip681 import eip681_uri
from core.invoicing.errors import (
    AddressCapacityExhausted,
    AddressMismatch,
    BehaviouralCooldown,
    CatalogError,
    HourlyQuotaExceeded,
    IntegrityFailure,
    InvoiceNotFound,
    InvoiceRequestAbandoned,
    InvoiceRequestInFlight,
    InvoiceRequestTimeout,
    InvoiceUnavailable,
    InvoicingError,
    MacMismatch,
    QuotaExceeded,
    RateUnavailable,
    TooManyActiveInvoices,
    UnknownAsset,
    UnknownProduct,
)
from core.invoicing.ids import public_token, uuid7
from core.invoicing.integrity import (
    IntegrityKey,
    canonical_payload,
    compute_mac,
    load_integrity_key,
    verify_mac,
)
from core.invoicing.quotas import NullQuotaCache, QuotaCache, RedisQuotaCache
from core.invoicing.rates import PeggedRates, RateSource, StaticRates, price_to_raw
from core.invoicing.service import (
    MAC_ONLY,
    AddressDeriver,
    AddressPool,
    InvoiceView,
    MacOnly,
    create_invoice,
    load_invoice_by_public_token,
    verify_invoice_address,
)

__all__ = [
    # entry points
    "create_invoice",
    "verify_invoice_address",
    "load_invoice_by_public_token",
    "InvoiceView",
    # seams
    "AddressDeriver",
    "AddressPool",
    "MacOnly",
    "MAC_ONLY",
    "RateSource",
    "QuotaCache",
    # configuration
    "InvoicingPolicy",
    "DEFAULT_POLICY",
    "PeggedRates",
    "StaticRates",
    "NullQuotaCache",
    "RedisQuotaCache",
    "price_to_raw",
    # integrity
    "IntegrityKey",
    "load_integrity_key",
    "compute_mac",
    "verify_mac",
    "canonical_payload",
    "eip681_uri",
    "uuid7",
    "public_token",
    # errors
    "InvoicingError",
    "InvoiceUnavailable",
    "CatalogError",
    "UnknownProduct",
    "UnknownAsset",
    "RateUnavailable",
    "QuotaExceeded",
    "TooManyActiveInvoices",
    "HourlyQuotaExceeded",
    "BehaviouralCooldown",
    "AddressCapacityExhausted",
    "InvoiceRequestInFlight",
    "InvoiceRequestTimeout",
    "InvoiceRequestAbandoned",
    "InvoiceNotFound",
    "IntegrityFailure",
    "AddressMismatch",
    "MacMismatch",
]
