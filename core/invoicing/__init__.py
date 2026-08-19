"""Invoice issuance and address-integrity checks (TZ 3.1, 5.3, 5.8/T1, T5).

The service layer behind ``/buy``. It is a library, not a process: the bot, the
api and anything else that has to put an address in front of a person call into
here, and there is no second implementation of any of it anywhere.

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

Wiring, in full::

    import deriver.pool
    from core.invoicing import create_invoice, load_integrity_key

    key = load_integrity_key()          # systemd credential, cached at startup
    with conn.transaction():
        view = create_invoice(
            conn, deriver, key,
            user_id=..., product_id=..., chain_id=..., asset_id=...,
            hd_account_id=..., pool=deriver.pool,
        )
    await bot.send_message(chat_id, render(view.address, view.eip681()))
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
    AddressDeriver,
    AddressPool,
    InvoiceView,
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
    "InvoiceNotFound",
    "IntegrityFailure",
    "AddressMismatch",
    "MacMismatch",
]
