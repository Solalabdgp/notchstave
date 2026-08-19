"""Invoice issuance and the gate every address display has to pass.

Two public entry points, and the second one is not optional decoration on the
first:

* :func:`create_invoice` — TZ 3.1 ``/buy <sku>``: a unique address, an exact
  amount, a deadline, and the EIP-681 string a QR is drawn from.
* :func:`verify_invoice_address` — TZ 5.3 "Целостность адреса на пути к
  пользователю" and 5.8/T1: **before any address reaches a human**, re-derive it
  from the xpub and re-check the invoice's HMAC. Both fail closed.

----

**The transaction.** Everything in :func:`create_invoice` happens in one
transaction owned by the caller — quota lock, quota counts, address reservation,
the invoice INSERT, the ``rate_limits`` mirror, the audit row. Nothing here
commits. That is what makes the failure modes boring: a refusal, a crash, or a
verify that comes back False all leave the database exactly as it was, with the
address still in the free pool and no half-invoice for the settler to trip over.

Migration 0006 is what allows it to be one transaction; its docstring carries
the argument, and the short version is that the address must be reserved to an
invoice id that does not exist yet, so
``fk_receive_addresses_current_invoice_id_invoices`` is now DEFERRABLE INITIALLY
DEFERRED and both halves are checked at COMMIT.

**Why this module is synchronous.** ``deriver.pool`` is synchronous psycopg, and
the reservation SQL of TZ 5.1 p. 3 lives there — it is the money-critical
statement of the address pool and there is exactly one copy of it. Reaching it
from an async engine would mean either a second copy of that SQL or a second
connection in a second transaction, and both are worse than asking an async
caller for ``await asyncio.to_thread(create_invoice, ...)``. The deriver is
synchronous for its own reasons (no network library may enter that package) and
this function is short; the thread hop costs microseconds against a transaction
that does five round trips anyway.

**Ordering inside the transaction**, and why it is this order:

1. advisory lock on ``user_id`` — before any read, or the counts are stale by
   the time they are used (TZ 5.8/T5.1);
2. catalog and pricing — everything that can refuse *without* consuming
   anything happens before anything is consumed;
3. quotas — same reason, and the last gate before an address is spent;
4. reserve the address (fused pool pickup, TZ 5.1 p. 3);
5. ``deriver.verify`` on what came back — countermeasure T1.1 applied at
   issuance, not only at display;
6. MAC over the real address, then the INSERT;
7. bookkeeping: ``rate_limits``, ``audit_log``, metrics.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Protocol

import psycopg
from psycopg.rows import dict_row

from core.db import enums as E
from core.invoicing import quotas
from core.invoicing.config import DEFAULT_POLICY, InvoicingPolicy
from core.invoicing.eip681 import eip681_uri
from core.invoicing.errors import (
    AddressCapacityExhausted,
    AddressMismatch,
    InvoiceNotFound,
    MacMismatch,
    UnknownAsset,
    UnknownProduct,
)
from core.invoicing.ids import public_token, uuid7
from core.invoicing.integrity import IntegrityKey, compute_mac, verify_mac
from core.invoicing.metrics import (
    ACTIVE_RESERVED_ADDRESSES,
    ADDRESS_MISMATCH,
    INVOICES_CREATED,
    MAC_FAILURES,
    RATELIMIT_HITS,
)
from core.invoicing.quotas import NullQuotaCache, QuotaCache
from core.invoicing.rates import PeggedRates, RateSource, price_to_raw

__all__ = [
    "InvoiceView",
    "AddressPool",
    "AddressDeriver",
    "MacOnly",
    "MAC_ONLY",
    "create_invoice",
    "verify_invoice_address",
    "load_invoice_by_public_token",
    "ACTOR_ID",
]

#: ``audit_log.actor_id`` for rows this module writes on behalf of a buyer. The
#: actor kind is ``user`` — the person pressed ``/buy`` — but the actor id names
#: the component, so a row can be traced to the code that wrote it (TZ 5.8/T8).
ACTOR_ID = "core.invoicing"

_LIVE = tuple(str(s) for s in E.LIVE_INVOICE_STATUSES)


# ---------------------------------------------------------------------------
# Seams
# ---------------------------------------------------------------------------


class AddressDeriver(Protocol):
    """What this module needs from :class:`deriver.service.Deriver`.

    Structural rather than an import, for the reason stated in
    ``deriver/pyproject.toml``: the deriver is a separately installable package
    with its own dependency allow-list, and ``core`` must not acquire a hard
    import edge into it. The production wiring passes the real object.
    """

    def address(self, hd_account_id: int, derivation_index: int) -> str: ...

    def verify(self, address: str, hd_account_id: int, derivation_index: int) -> bool: ...


class AddressPool(Protocol):
    """The one function this module calls from :mod:`deriver.pool`.

    Typed as a callable-holder rather than taking the function directly so the
    production wiring reads ``create_invoice(..., pool=deriver.pool, ...)`` —
    the module itself satisfies this protocol, which is the point. The address
    pool's SQL is not reimplemented anywhere in ``core``.
    """

    def reserve_address_for_invoice(
        self,
        conn: psycopg.Connection[Any],
        deriver: Any,
        hd_account_id: int,
        invoice_id: uuid.UUID,
        reserved_from_block: int,
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class MacOnly:
    """"I hold the HMAC key and structurally cannot hold the xpub." One sentinel.

    Passed in place of an :class:`AddressDeriver` by a process that is not
    allowed to re-derive, and there is exactly one of those: ``api``. TZ section
    9 gives ``LoadCredential=`` with the xpub to ``notchstave-deriver.service``
    and to no other unit, and ``hd_accounts`` deliberately stores only the
    4-byte fingerprint (see its model docstring), so there is no third place an
    ``api`` process could obtain one. ``INVOICE_INTEGRITY_KEY``, by contrast, is
    scoped to settler/api/bot by the same section.

    **What is given up, stated exactly**, because a countermeasure described
    without its boundary is advertising (the TZ's own standard for T1.3). With
    this sentinel the T1.1 derivation check does not run at display time; the
    T1.3 MAC check does, over the full significant tuple including the address.
    What still holds:

    * the address was re-derived and compared by the deriver at issuance —
      :func:`create_invoice` step 5, in the same transaction that wrote the row;
    * ``receive_addresses`` is writable only by ``notchstave_deriver``
      (migration 0002, TZ 5.8/T1.2), so an address cannot be *declared* into the
      pool by a compromised ``api``;
    * the MAC binds ``(invoice_id, chain_id, asset_id, address, amount_due_raw,
      expires_at)`` under a key that is not in the database, so the DB-only
      compromise of T1 vector 1 — leaked replica, stolen backup, forgotten port
      forward — still cannot rewrite the displayed address into a verifying row.

    What is lost is the case where the attacker holds the database *and*
    ``INVOICE_INTEGRITY_KEY``. That key lives on the ``api`` host, so this is
    the full-host compromise the TZ already excludes from the HMAC's promise.

    The stronger arrangement is an ``api`` that asks the deriver process to
    verify over the ``invoice_requests``-style channel of migration 0007, and
    then passes a real :class:`AddressDeriver` here instead. Nothing in this
    module needs to change for that — which is the point of the sentinel being a
    distinct type rather than ``None``: it is greppable, it cannot be arrived at
    by forgetting an argument, and the day the RPC lands the call sites that
    still say ``MAC_ONLY`` are the exact list of what is left to move.
    """


#: The one instance. See :class:`MacOnly`.
MAC_ONLY = MacOnly()


# ---------------------------------------------------------------------------
# What a caller gets back
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InvoiceView:
    """Everything the bot and the api need to render one invoice, verified.

    A view is only ever produced by code that has already run
    :func:`verify_invoice_address`'s two checks — at creation by
    :func:`create_invoice`, on every later read by
    :func:`verify_invoice_address` itself. That is why there is no
    ``verified: bool`` field: an unverified :class:`InvoiceView` does not exist,
    and a flag would invite a caller to render one that says ``False``.
    """

    invoice_id: uuid.UUID
    public_token: str
    user_id: int
    product_id: int
    chain_id: int
    asset_id: int
    address_id: int
    address: str
    hd_account_id: int
    derivation_index: int
    amount_due_raw: Decimal
    amount_due_usd: Decimal
    rate_snapshot: Decimal
    rate_locked_until: dt.datetime
    status: str
    expires_at: dt.datetime
    topup_window_until: dt.datetime
    created_at: dt.datetime
    integrity_mac: bytes
    policy_version: str
    asset_symbol: str
    asset_decimals: int
    asset_contract: str | None
    asset_is_native: bool
    #: True when the pool was empty and ``next_index`` had to move. Feeds the
    #: ``address_index_gap`` conversation of TZ 5.1 p. 2 / 5.8-T5.3 — under
    #: normal load this is False almost always, and a run of True values means
    #: peak concurrency, not traffic.
    newly_derived: bool = False

    def eip681(self) -> str:
        """The payment string for the QR and for the text beside it (TZ 3.2).

        Computed rather than stored so the bot message, the API response and the
        QR are provably one value (TZ 5.8/T1.4): there is one function, it takes
        its address from this verified view, and there is no second place where
        an address could enter the string.
        """
        return eip681_uri(
            chain_id=self.chain_id,
            recipient=self.address,
            amount_raw=self.amount_due_raw,
            is_native=self.asset_is_native,
            contract_address=self.asset_contract,
        )

    @property
    def is_live(self) -> bool:
        return self.status in _LIVE


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

SQL_LOAD_PRODUCT = """
SELECT id, sku, title, price_usd, active
  FROM products
 WHERE id = %(product_id)s
"""

#: Asset and chain in one round trip, because they are one question: "may this
#: (chain, asset) pair be billed right now". ``last_indexed_block`` comes along
#: because it is the reservation height (see :func:`create_invoice`).
SQL_LOAD_ASSET = """
SELECT a.id                AS asset_id,
       a.chain_id          AS chain_id,
       a.contract_address  AS contract_address,
       a.symbol            AS symbol,
       a.decimals          AS decimals,
       a.is_native         AS is_native,
       a.is_enabled        AS asset_enabled,
       c.is_enabled        AS chain_enabled,
       c.last_indexed_block AS last_indexed_block
  FROM assets a
  JOIN chains c ON c.chain_id = a.chain_id
 WHERE a.id = %(asset_id)s
   AND a.chain_id = %(chain_id)s
"""

SQL_INSERT_INVOICE = """
INSERT INTO invoices (id, user_id, product_id, chain_id, asset_id, address_id,
                      amount_due_raw, amount_due_usd, rate_snapshot, rate_locked_until,
                      status, expires_at, topup_window_until, created_at,
                      integrity_mac, public_token, policy_version)
VALUES (%(id)s, %(user_id)s, %(product_id)s, %(chain_id)s, %(asset_id)s, %(address_id)s,
        %(amount_due_raw)s, %(amount_due_usd)s, %(rate_snapshot)s, %(rate_locked_until)s,
        'awaiting', %(expires_at)s, %(topup_window_until)s, %(created_at)s,
        %(integrity_mac)s, %(public_token)s, %(policy_version)s)
RETURNING created_at
"""

#: One row shape for both lookup paths, so the verification code below has a
#: single input and cannot verify one set of columns on one path and another set
#: on the other. ``receive_addresses`` is joined through ``invoices.address_id``
#: — the invoice names its address, and the pool row is what the watcher builds
#: its filter from, so checking the pool row is checking what actually receives.
_SQL_INVOICE_SELECT = """
SELECT i.id                 AS invoice_id,
       i.public_token       AS public_token,
       i.user_id            AS user_id,
       i.product_id         AS product_id,
       i.chain_id           AS chain_id,
       i.asset_id           AS asset_id,
       i.address_id         AS address_id,
       i.amount_due_raw     AS amount_due_raw,
       i.amount_due_usd     AS amount_due_usd,
       i.rate_snapshot      AS rate_snapshot,
       i.rate_locked_until  AS rate_locked_until,
       i.status::text       AS status,
       i.expires_at         AS expires_at,
       i.topup_window_until AS topup_window_until,
       i.created_at         AS created_at,
       i.integrity_mac      AS integrity_mac,
       i.policy_version     AS policy_version,
       ra.address           AS address,
       ra.hd_account_id     AS hd_account_id,
       ra.derivation_index  AS derivation_index,
       a.symbol             AS asset_symbol,
       a.decimals           AS asset_decimals,
       a.contract_address   AS asset_contract,
       a.is_native          AS asset_is_native
  FROM invoices i
  JOIN receive_addresses ra ON ra.id = i.address_id
  JOIN assets a ON a.id = i.asset_id AND a.chain_id = i.chain_id
"""

SQL_LOAD_INVOICE_BY_ID = _SQL_INVOICE_SELECT + " WHERE i.id = %(invoice_id)s"

SQL_LOAD_INVOICE_BY_TOKEN = _SQL_INVOICE_SELECT + " WHERE i.public_token = %(public_token)s"

SQL_COUNT_RESERVED_ON_CHAIN = """
SELECT count(*) AS n
  FROM invoices
 WHERE chain_id = %(chain_id)s
   AND status = ANY(%(live)s::invoice_status[])
"""

SQL_AUDIT = """
INSERT INTO audit_log (actor_kind, actor_id, action, target_kind, target_id,
                       after_state, args_json, policy_version)
VALUES ('user', %(actor_id)s, %(action)s, 'invoice', %(target_id)s,
        %(after_state)s, %(args_json)s, %(policy_version)s)
"""


# ---------------------------------------------------------------------------
# Verification — the gate
# ---------------------------------------------------------------------------


def _view_from_row(row: dict[str, Any], *, newly_derived: bool = False) -> InvoiceView:
    return InvoiceView(
        invoice_id=row["invoice_id"],
        public_token=row["public_token"],
        user_id=int(row["user_id"]),
        product_id=int(row["product_id"]),
        chain_id=int(row["chain_id"]),
        asset_id=int(row["asset_id"]),
        address_id=int(row["address_id"]),
        address=row["address"],
        hd_account_id=int(row["hd_account_id"]),
        derivation_index=int(row["derivation_index"]),
        amount_due_raw=Decimal(row["amount_due_raw"]),
        amount_due_usd=Decimal(row["amount_due_usd"]),
        rate_snapshot=Decimal(row["rate_snapshot"]),
        rate_locked_until=row["rate_locked_until"],
        status=row["status"],
        expires_at=row["expires_at"],
        topup_window_until=row["topup_window_until"],
        created_at=row["created_at"],
        integrity_mac=bytes(row["integrity_mac"]),
        policy_version=row["policy_version"],
        asset_symbol=row["asset_symbol"],
        asset_decimals=int(row["asset_decimals"]),
        asset_contract=row["asset_contract"],
        asset_is_native=bool(row["asset_is_native"]),
        newly_derived=newly_derived,
    )


def _check_integrity(
    view: InvoiceView,
    deriver: AddressDeriver | MacOnly,
    key: IntegrityKey,
) -> None:
    """The two T1 checks, in the order that makes the alert legible.

    Derivation first. A failure there means the address itself is wrong, which
    is the vector that takes the buyer's money (TZ 5.8/T1, vector 1); a MAC
    failure on top of it would add nothing to the diagnosis. A MAC failure
    *alone* is the narrower finding — the address is genuinely ours and
    something else in the tuple was edited — and reporting it as its own
    exception is what makes ``invoice_mac_failures_total`` mean what its help
    text says.

    Both raise. Neither returns a boolean, because a boolean is a value a caller
    can forget to look at, and "forgot to check" must not be a way to show an
    unverified address.

    :data:`MAC_ONLY` skips the first check and only the first check — see
    :class:`MacOnly` for which process passes it and exactly what that costs.
    """
    if isinstance(deriver, MacOnly):
        pass
    elif not deriver.verify(view.address, view.hd_account_id, view.derivation_index):
        ADDRESS_MISMATCH.inc()
        raise AddressMismatch(
            f"invoice {view.invoice_id}: address {view.address} does not re-derive from "
            f"hd_account_id={view.hd_account_id} index={view.derivation_index}. "
            "Suspected database compromise (TZ 5.8/T1.1) — do not display, do not credit.",
            invoice_id=view.invoice_id,
        )

    if not verify_mac(
        key,
        view.integrity_mac,
        invoice_id=view.invoice_id,
        chain_id=view.chain_id,
        asset_id=view.asset_id,
        address=view.address,
        amount_due_raw=view.amount_due_raw,
        expires_at=view.expires_at,
    ):
        MAC_FAILURES.inc()
        raise MacMismatch(
            f"invoice {view.invoice_id}: integrity_mac does not verify over "
            "(id, chain_id, asset_id, address, amount_due_raw, expires_at). "
            "The row was changed outside the application (TZ 5.8/T1.3).",
            invoice_id=view.invoice_id,
        )


def verify_invoice_address(
    conn: psycopg.Connection[Any],
    deriver: AddressDeriver | MacOnly,
    key: IntegrityKey,
    invoice_id: uuid.UUID,
    *,
    expected_user_id: int | None = None,
) -> InvoiceView:
    """Load one invoice and prove it before anyone sees the address.

    Call this before rendering the address in a bot message, in an API
    response, or into an EIP-681 string — TZ 5.3: *"Перед показом любого адреса
    ``api``/``bot`` вызывают ``deriver.verify``... Дополнительно строка инвойса
    защищена HMAC."*

    ``expected_user_id`` is the IDOR guard of TZ 5.8/T1.7: *"Любой запрос
    статуса фильтруется по ``user_id`` из проверенного ``initData``/``tg_id``, а
    не только по ``invoice_id``."* A mismatch raises :class:`InvoiceNotFound`
    and not a permission error, on purpose — a 403 confirms the id exists, which
    is the one bit an enumeration attempt is trying to buy.

    Raises :class:`~core.invoicing.errors.AddressMismatch` or
    :class:`~core.invoicing.errors.MacMismatch` on failure; never returns an
    unverified view.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SQL_LOAD_INVOICE_BY_ID, {"invoice_id": invoice_id})
        row = cur.fetchone()

    if row is None:
        raise InvoiceNotFound(f"no invoice {invoice_id}")

    view = _view_from_row(row)
    if expected_user_id is not None and view.user_id != expected_user_id:
        raise InvoiceNotFound(
            f"invoice {invoice_id} belongs to user {view.user_id}, "
            f"not {expected_user_id} (TZ 5.8/T1.7)"
        )

    _check_integrity(view, deriver, key)
    return view


def load_invoice_by_public_token(
    conn: psycopg.Connection[Any],
    deriver: AddressDeriver | MacOnly,
    key: IntegrityKey,
    token: str,
    *,
    now: dt.datetime | None = None,
) -> InvoiceView:
    """Same guarantees, keyed by the public page token (TZ 5.8/T1.7).

    ``deriver`` may be :data:`MAC_ONLY` when the calling process cannot hold an
    xpub; :class:`MacOnly` documents which guarantee that drops and which
    survive. Every other guarantee below is unchanged by that choice — in
    particular the TTL, which is enforced here and not in the token.

    The token's TTL is *"срок жизни инвойса + окно доплаты"* (TZ 6) and is
    enforced here as a lookup against ``topup_window_until`` rather than encoded
    in the token. A structured token would still need this query — a cancelled
    invoice's link has to stop working before its nominal deadline — so the
    structure would buy nothing and add a second thing to keep in sync.

    An expired token is :class:`InvoiceNotFound`, the same as a wrong one. The
    page has no reason to distinguish them and distinguishing them tells a
    guesser that their guess was once real.
    """
    moment = dt.datetime.now(dt.UTC) if now is None else now
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SQL_LOAD_INVOICE_BY_TOKEN, {"public_token": token})
        row = cur.fetchone()

    if row is None:
        raise InvoiceNotFound("no invoice for that token")

    view = _view_from_row(row)
    if moment > view.topup_window_until:
        raise InvoiceNotFound(
            f"public token for invoice {view.invoice_id} expired at "
            f"{view.topup_window_until.isoformat()}"
        )

    _check_integrity(view, deriver, key)
    return view


# ---------------------------------------------------------------------------
# Issuance
# ---------------------------------------------------------------------------


def _load_catalog(
    conn: psycopg.Connection[Any], *, product_id: int, chain_id: int, asset_id: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SQL_LOAD_PRODUCT, {"product_id": product_id})
        product = cur.fetchone()
        if product is None or not product["active"]:
            raise UnknownProduct(f"product_id={product_id} is missing or not for sale")

        cur.execute(SQL_LOAD_ASSET, {"asset_id": asset_id, "chain_id": chain_id})
        asset = cur.fetchone()

    # One message for "no such asset", "asset disabled", "chain disabled" and
    # "asset belongs to another chain". TZ 12 makes the accepted set an
    # allow-list, and telling a caller which of the four it was maps the
    # allow-list for free.
    if asset is None or not asset["asset_enabled"] or not asset["chain_enabled"]:
        raise UnknownAsset(f"asset_id={asset_id} on chain_id={chain_id} is not accepted")

    return product, asset


def _publish_reserved_gauge(conn: psycopg.Connection[Any], chain_id: int) -> None:
    """Set ``notchstave_active_reserved_addresses{chain}`` from the ledger.

    Counted rather than incremented. A counter kept in process memory drifts the
    moment an invoice expires in the settler or a second issuing process starts,
    and this gauge carries the T5 alert at 80% of the ceiling — a drifting value
    there either cries wolf or, worse, stays quiet during the burst it exists to
    catch. One cheap indexed count per issuance is the right price for a number
    an alert depends on.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SQL_COUNT_RESERVED_ON_CHAIN, {"chain_id": chain_id, "live": list(_LIVE)})
        row = cur.fetchone()
    if row is not None:
        ACTIVE_RESERVED_ADDRESSES.labels(chain=str(chain_id)).set(float(row["n"]))


def create_invoice(
    conn: psycopg.Connection[Any],
    deriver: AddressDeriver,
    key: IntegrityKey,
    *,
    user_id: int,
    product_id: int,
    chain_id: int,
    asset_id: int,
    hd_account_id: int,
    pool: AddressPool,
    policy: InvoicingPolicy = DEFAULT_POLICY,
    rates: RateSource | None = None,
    cache: QuotaCache | None = None,
    now: dt.datetime | None = None,
    reserved_from_block: int | None = None,
) -> InvoiceView:
    """TZ 3.1 ``/buy <sku>``: one address, one amount, one deadline, one QR string.

    Runs entirely inside the caller's transaction and commits nothing. The
    caller commits on a returned view and rolls back on any exception; every
    refusal in this function is therefore also a full undo of everything it did
    before the refusal, including the address it may have taken out of the pool.

    Raises, all of them subclasses of :class:`~core.invoicing.errors
    .InvoicingError` and all of them carrying a buyer-safe ``user_message``:

    * :class:`~core.invoicing.errors.UnknownProduct` /
      :class:`~core.invoicing.errors.UnknownAsset` — catalog;
    * :class:`~core.invoicing.errors.RateUnavailable` — no price snapshot;
    * :class:`~core.invoicing.errors.QuotaExceeded` subclasses — TZ 5.8/T5.1,
      T5.5;
    * :class:`~core.invoicing.errors.AddressCapacityExhausted` — TZ 5.8/T5.2,
      the ceiling, answered honestly rather than as a 500;
    * :class:`~core.invoicing.errors.AddressMismatch` — the address that came
      out of the pool does not re-derive. Nothing is issued.
    """
    moment = dt.datetime.now(dt.UTC) if now is None else now
    rate_source = PeggedRates() if rates is None else rates
    quota_cache = NullQuotaCache() if cache is None else cache

    # 1. Serialise this user's quota decision before reading any of its inputs.
    quotas.lock_user(conn, user_id)

    # 2. Everything that can refuse without consuming anything.
    product, asset = _load_catalog(
        conn, product_id=product_id, chain_id=chain_id, asset_id=asset_id
    )
    rate = rate_source.quote(symbol=asset["symbol"], chain_id=chain_id)
    amount_due_usd = Decimal(product["price_usd"])
    amount_due_raw = price_to_raw(
        amount_due_usd, decimals=int(asset["decimals"]), rate=rate
    )

    # 3. Quotas. Last gate before an address is spent.
    snap = quotas.snapshot(conn, user_id, policy=policy, now=moment)
    quotas.enforce(conn, snap, policy=policy, now=moment)

    # 4. Reserve. The invoice id is minted first because the fused pool
    #    statement writes it into `receive_addresses.current_invoice_id` — legal
    #    in one transaction only because migration 0006 deferred that FK.
    invoice_id = uuid7(moment)
    head_block = (
        int(asset["last_indexed_block"]) if reserved_from_block is None else reserved_from_block
    )
    try:
        reserved = pool.reserve_address_for_invoice(
            conn, deriver, hd_account_id, invoice_id, head_block
        )
    except Exception as exc:  # noqa: BLE001 — narrowed immediately below
        # `deriver.pool.AddressPoolExhausted` is caught by name rather than by
        # import: importing it would give `core` the hard edge into the deriver
        # package that `AddressDeriver` exists to avoid. The class name is part
        # of the pool's public API (it is in its `__all__`) and the alternative
        # — letting a ceiling hit surface as a 500 — is the exact outcome TZ
        # 5.8/T5.2 rules out.
        if type(exc).__name__ == "AddressPoolExhausted":
            RATELIMIT_HITS.labels(scope="addresses").inc()
            raise AddressCapacityExhausted(
                f"hd_account_id={hd_account_id} is at its max_active_addresses ceiling "
                f"(TZ 5.8/T5.2): {exc}"
            ) from exc
        raise

    # 5. T1.1 at issuance. The pool row could have been written by something
    #    other than the deriver in the window since it was derived; an address
    #    that does not re-derive must not become an invoice.
    if not deriver.verify(reserved.address, reserved.hd_account_id, reserved.derivation_index):
        ADDRESS_MISMATCH.inc()
        raise AddressMismatch(
            f"pooled address {reserved.address} (id={reserved.address_id}) does not re-derive "
            f"from hd_account_id={reserved.hd_account_id} index={reserved.derivation_index}. "
            "Refusing to issue an invoice against it (TZ 5.8/T1.1).",
            invoice_id=invoice_id,
        )

    # 6. Deadlines, MAC, insert. The MAC is computed over the address that came
    #    back from the pool and was just verified — not over anything a caller
    #    passed in.
    expires_at = moment + policy.invoice_ttl
    rate_locked_until = moment + policy.rate_lock_ttl
    topup_window_until = expires_at + policy.topup_window
    integrity_mac = compute_mac(
        key,
        invoice_id=invoice_id,
        chain_id=chain_id,
        asset_id=asset_id,
        address=reserved.address,
        amount_due_raw=amount_due_raw,
        expires_at=expires_at,
    )
    token = public_token(policy.public_token_bytes)

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            SQL_INSERT_INVOICE,
            {
                "id": invoice_id,
                "user_id": user_id,
                "product_id": product_id,
                "chain_id": chain_id,
                "asset_id": asset_id,
                "address_id": reserved.address_id,
                "amount_due_raw": amount_due_raw,
                "amount_due_usd": amount_due_usd,
                "rate_snapshot": rate,
                "rate_locked_until": rate_locked_until,
                "expires_at": expires_at,
                "topup_window_until": topup_window_until,
                "created_at": moment,
                "integrity_mac": integrity_mac,
                "public_token": token,
                "policy_version": policy.version,
            },
        )

    # 7. Bookkeeping, all in the same transaction as the invoice.
    hourly_count = quotas.record_issued(
        conn, user_id, now=moment, expired_streak=snap.expired_streak
    )
    quota_cache.note_issued(
        user_id,
        ttl_seconds=int(policy.quota_window.total_seconds()),
        limit=policy.max_invoices_per_hour,
    )
    _ = hourly_count  # kept explicit: the cache is advisory, the count is the record

    with conn.cursor() as cur:
        cur.execute(
            SQL_AUDIT,
            {
                "actor_id": ACTOR_ID,
                "action": "invoice_created",
                "target_id": str(invoice_id),
                # No address and no token in the audit row. The row proves *that*
                # an invoice was issued under a named policy version; the address
                # already lives in two tables and the public token is a bearer
                # credential that has no business in an append-only log every
                # role can SELECT.
                "after_state": json.dumps(
                    {
                        "chain_id": chain_id,
                        "asset_id": asset_id,
                        "address_id": reserved.address_id,
                        "derivation_index": reserved.derivation_index,
                        "amount_due_raw": str(amount_due_raw),
                        "amount_due_usd": str(amount_due_usd),
                        "expires_at": expires_at.isoformat(),
                    }
                ),
                "args_json": json.dumps(
                    {
                        "user_id": user_id,
                        "product_id": product_id,
                        "newly_derived": reserved.newly_derived,
                        "active_invoices_before": snap.active_invoices,
                        "invoices_in_window_before": snap.invoices_in_window,
                    }
                ),
                "policy_version": policy.version,
            },
        )

    INVOICES_CREATED.labels(chain=str(chain_id), asset=asset["symbol"]).inc()
    _publish_reserved_gauge(conn, chain_id)

    return InvoiceView(
        invoice_id=invoice_id,
        public_token=token,
        user_id=user_id,
        product_id=product_id,
        chain_id=chain_id,
        asset_id=asset_id,
        address_id=reserved.address_id,
        address=reserved.address,
        hd_account_id=reserved.hd_account_id,
        derivation_index=reserved.derivation_index,
        amount_due_raw=amount_due_raw,
        amount_due_usd=amount_due_usd,
        rate_snapshot=rate,
        rate_locked_until=rate_locked_until,
        status=str(E.InvoiceStatus.AWAITING),
        expires_at=expires_at,
        topup_window_until=topup_window_until,
        created_at=moment,
        integrity_mac=integrity_mac,
        policy_version=policy.version,
        asset_symbol=asset["symbol"],
        asset_decimals=int(asset["decimals"]),
        asset_contract=asset["contract_address"],
        asset_is_native=bool(asset["is_native"]),
        newly_derived=bool(reserved.newly_derived),
    )
