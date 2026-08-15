"""Domain enums.

Every one of these becomes a native PostgreSQL ENUM type (created explicitly in
migration 0001). Native types are used on purpose: a typo in a status string
must fail at the database boundary, not silently write garbage into a money
table.

Values are what reaches the database; `StrEnum` keeps `str(x)` equal to that
value so a stray f-string cannot write `InvoiceStatus.PAID` into a money column.
"""

from __future__ import annotations

import enum

__all__ = [
    "BlockStatus",
    "AddressStatus",
    "InvoiceStatus",
    "PaymentStatus",
    "PaymentAnomaly",
    "ProductKind",
    "RefundStatus",
    "ManualReviewKind",
    "ManualReviewResolution",
    "NotificationStatus",
    "ActorKind",
    "ENUM_TYPE_NAMES",
]


class BlockStatus(enum.StrEnum):
    """`blocks.status` — chain-of-blocks bookkeeping for reorg handling (TZ 5.4)."""

    PENDING = "pending"
    CONFIRMED = "confirmed"
    ORPHANED = "orphaned"


class AddressStatus(enum.StrEnum):
    """`receive_addresses.status` (TZ 5.1, gap-limit / reuse pool).

    free     — in the pool, may be handed to the next invoice
    reserved — bound to a live invoice
    funded   — money has arrived; NEVER returns to `free`
    swept    — moved to cold storage offline; NEVER returns to `free`
    """

    FREE = "free"
    RESERVED = "reserved"
    FUNDED = "funded"
    SWEPT = "swept"


class InvoiceStatus(enum.StrEnum):
    """`invoices.status` — the payment state machine (TZ 6)."""

    AWAITING = "awaiting"
    SEEN = "seen"
    PARTIALLY_PAID = "partially_paid"
    PAID = "paid"
    OVERPAID = "overpaid"
    EXPIRED = "expired"
    MANUAL_REVIEW = "manual_review"
    CANCELLED = "cancelled"
    REVERTED = "reverted"


#: Statuses in which an invoice still owns its receive address exclusively.
#: Mirrors the predicate of the partial unique index
#: `uq_invoices_active_address` — keep the two in sync.
LIVE_INVOICE_STATUSES = (
    InvoiceStatus.AWAITING,
    InvoiceStatus.SEEN,
    InvoiceStatus.PARTIALLY_PAID,
)

#: Statuses whose payments count towards the settled amount (TZ 5.3:
#: `SUM(amount_raw)` over confirmed/credited, never an incremental counter).
CREDITABLE_PAYMENT_STATUSES = ("confirmed", "credited")


class PaymentStatus(enum.StrEnum):
    """`payments.status` (TZ 6)."""

    SEEN = "seen"
    CONFIRMED = "confirmed"
    CREDITED = "credited"
    REVERTED = "reverted"
    IGNORED_DUST = "ignored_dust"


class PaymentAnomaly(enum.StrEnum):
    """`payments.anomaly` — NULL means "nothing unusual" (TZ 5.5)."""

    WRONG_ASSET = "wrong_asset"
    WRONG_CHAIN = "wrong_chain"
    LATE = "late"
    DUST = "dust"
    ORPHAN_PAYMENT = "orphan_payment"
    UNASSIGNED_PAYMENT = "unassigned_payment"


class ProductKind(enum.StrEnum):
    ONE_OFF = "one_off"
    SUBSCRIPTION = "subscription"


class RefundStatus(enum.StrEnum):
    """`refunds.status`.

    A refund row is an accounting obligation, not an instruction to send money.
    Nothing in this codebase can execute it — see TZ 12.
    """

    PENDING = "pending"
    EXECUTED = "executed"
    DECLINED = "declined"


class ManualReviewKind(enum.StrEnum):
    """Why a human was pulled in (TZ 5.5 anomaly table + 5.8/T1, T3)."""

    UNDERPAID = "underpaid"
    OVERPAID = "overpaid"
    WRONG_ASSET = "wrong_asset"
    WRONG_CHAIN = "wrong_chain"
    LATE_PAYMENT = "late_payment"
    ORPHAN_PAYMENT = "orphan_payment"
    UNASSIGNED_PAYMENT = "unassigned_payment"
    ADDRESS_MISMATCH = "address_mismatch"
    MAC_FAILURE = "mac_failure"
    RECONCILE_DRIFT = "reconcile_drift"


class ManualReviewResolution(enum.StrEnum):
    """Outcome of `/resolve <invoice_id> <credit|refund|reject>` (TZ 3.4)."""

    CREDIT = "credit"
    REFUND = "refund"
    REJECT = "reject"


class NotificationStatus(enum.StrEnum):
    """Transactional-outbox row state (TZ 5.7 / 5.8-T2.5)."""

    QUEUED = "queued"
    SENT = "sent"
    FAILED = "failed"
    DEAD = "dead"  # exhausted retries -> DLQ, needs a human


class ActorKind(enum.StrEnum):
    """`audit_log.actor_kind` (TZ 5.8/T7, T8)."""

    OWNER = "owner"
    USER = "user"
    SYSTEM = "system"


#: Order matters only for readability; migration 0001 creates them all up-front.
ENUM_TYPE_NAMES = (
    "block_status",
    "address_status",
    "invoice_status",
    "payment_status",
    "payment_anomaly",
    "product_kind",
    "refund_status",
    "manual_review_kind",
    "manual_review_resolution",
    "notification_status",
    "actor_kind",
)
