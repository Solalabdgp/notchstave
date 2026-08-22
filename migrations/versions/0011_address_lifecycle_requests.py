"""address_lifecycle_requests: the queue the settler uses to hand an address back

The finding this closes, stated plainly: **the address pool never refilled.**

``deriver/pool.py`` shipped the whole return path in Week 1 — ``schedule_release``
(condition 2 of TZ 5.1's three reuse rules), ``release_due_addresses`` (all three
in one WHERE clause) and ``mark_address_funded`` (the ``ever_funded`` latch of
condition 1). All three were exported, tested, and called by nothing outside
their own test file. ``create_invoice`` takes an address out of the pool as
``reserved`` and no code path anywhere put one back, so
``hd_accounts.max_active_addresses`` — documented as a ceiling on *simultaneously*
reserved addresses — behaved as a **lifetime issuance cap**. The performance
review measured the consequence: one quota-compliant user exhausts the default
500 in about two days of ordinary, entirely successful traffic, after which
every ``/buy`` is refused with ``AddressCapacityExhausted`` and nothing recovers
without a human writing UPDATEs by hand.

Why the settler is the one that has to ask
------------------------------------------

The three conditions in TZ 5.1 are questions about *money and time*:

1. has this address ever held funds (``ever_funded`` — forever, one-way);
2. has the top-up window plus a cooldown passed;
3. is the invoice that reserved it finally done with it.

Every one of those is answered from ``payments`` and ``invoices``, and the
settler is the process that owns both (TZ section 4). It is also the only place
an invoice reaches ``expired`` / ``manual_review`` / a settled status, which is
the moment the questions become answerable.

But the settler holds **SELECT and nothing else** on ``receive_addresses``
(migration 0002, TZ 5.8/T1.2: an address is derived, never declared, and the
deriver is the only writer). 0002's own comment already named the intended
mechanism — *"the settler asks the deriver to perform that transition instead of
doing it itself"* — and that ask was never built. This table is it.

Why a third queue rather than a discriminator on ``invoice_requests``
---------------------------------------------------------------------

Same argument migration 0008 made for the proof queue and it has held twice
already: the row shapes have nothing in common (this one has no user, no
product, no chain, no quota), the failure vocabularies have nothing in common,
and a listener woken by another queue's traffic is a listener that scales with
somebody else's load. Two short literal statement sets are cheaper to read than
one parameterised over a table name — which would also mean string-built SQL in
the package whose entire remit is to be boring about the database.

**No reply channel, and that is the difference from 0007/0008.** Nobody waits
for this. The settler enqueues and moves on; the buyer is not blocked on it and
no interactive path depends on the answer. So the trigger fires on INSERT only,
to wake the deriver, and there is no per-request reply channel and no client
that blocks on one. A failure surfaces as ``status='failed'`` plus a log line in
the deriver, and the settler's next pass re-derives the same candidate from the
ledger anyway — the sweep is a function of database state, exactly like every
other settler pass, so a lost request costs one poll interval and nothing else.

Idempotency
-----------

``uq_address_lifecycle_open_per_action`` allows one open request per (address,
action). The settler's sweep re-computes its candidate list from
``receive_addresses`` every pass, and between the enqueue and the deriver acting
on it the same address still matches; the index is what turns that from a
growing pile into a no-op. Once the deriver has acted the row stops matching the
sweep's predicates altogether — ``cooldown_until`` is no longer NULL, or
``ever_funded`` is true — so the queue drains to empty on its own.

Revision ID: 0011
Revises: 0010
Create Date: 2026-08-22

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DERIVER = "notchstave_deriver"
SETTLER = "notchstave_settler"

TS = sa.DateTime(timezone=True)

#: One channel, INSERT only. Mirrored as a module constant in
#: ``deriver/requests.py`` and ``settler/repository.py``; a drifted name is a
#: wakeup that never arrives, which is indistinguishable from a slow deriver, so
#: a test asserts the copies are the same string.
CHANNEL_ADDRESS_LIFECYCLE = "notchstave_address_lifecycle"

ACTION_ENUM = "address_lifecycle_action"
ACTIONS = ("release", "mark_funded")

STATUS_ENUM = "address_request_status"
STATUSES = ("pending", "processing", "done", "failed")

NOTIFY_FUNCTION = "notchstave_address_lifecycle_notify"

NOTIFY_FUNCTION_SQL = f"""
CREATE OR REPLACE FUNCTION {NOTIFY_FUNCTION}() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('{CHANNEL_ADDRESS_LIFECYCLE}', NEW.id::text);
    RETURN NULL;
END
$fn$;
"""


def _if_role_exists(role: str, statement: str) -> None:
    """Same degradation as 0002-0010: no role, no grant, no failed deploy."""
    op.execute(
        f"""
        DO $g$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                EXECUTE '{statement}';
            END IF;
        END
        $g$;
        """
    )


def upgrade() -> None:
    op.execute(f"CREATE TYPE {ACTION_ENUM} AS ENUM ({', '.join(repr(a) for a in ACTIONS)})")
    op.execute(f"CREATE TYPE {STATUS_ENUM} AS ENUM ({', '.join(repr(s) for s in STATUSES)})")

    op.create_table(
        "address_lifecycle_requests",
        # UUIDv7, minted by the settler. Not a bigserial: the settler holds
        # INSERT here and nothing else, and an id it chose itself is one it can
        # log before the commit.
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("address_id", sa.BigInteger(), nullable=False),
        # Context, not a key. Which invoice's tenancy ended is the first thing
        # anyone asks when reading one of these rows six weeks later, and it is
        # nullable because `mark_funded` can be provoked by an
        # `unassigned_payment` — money on an address with no live invoice
        # behind it (TZ 5.5), which is precisely a case where the address must
        # never be reused and there is no invoice to name.
        sa.Column("invoice_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "action",
            postgresql.ENUM(*ACTIONS, name=ACTION_ENUM, create_type=False),
            nullable=False,
        ),
        # Only `release` carries one; see the CHECK. The settler computes it in
        # SQL from `invoices.topup_window_until` and `now()` so that the two
        # halves of "top-up window plus cooldown" are read off one clock — the
        # database's — rather than off whichever host the settler happens to run
        # on.
        sa.Column("cooldown_until", TS, nullable=True),
        sa.Column(
            "status",
            postgresql.ENUM(*STATUSES, name=STATUS_ENUM, create_type=False),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column("attempts", sa.SmallInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("requested_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.Column("claimed_at", TS, nullable=True),
        sa.Column("completed_at", TS, nullable=True),
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.CheckConstraint("attempts >= 0", name="attempts_non_negative"),
        # A release with no moment to release at would free the address on the
        # next sweep, which is condition 2 of TZ 5.1 deleted rather than
        # implemented — a late top-up would then land on an address that already
        # belongs to somebody else.
        sa.CheckConstraint(
            "action <> 'release' OR cooldown_until IS NOT NULL",
            name="release_has_a_cooldown",
        ),
        sa.CheckConstraint(
            "action <> 'mark_funded' OR cooldown_until IS NULL",
            name="mark_funded_has_no_cooldown",
        ),
        sa.CheckConstraint(
            "status <> 'failed' OR (error_code IS NOT NULL AND completed_at IS NOT NULL)",
            name="failed_has_a_reason",
        ),
        sa.CheckConstraint(
            "status IN ('done', 'failed') OR (completed_at IS NULL AND error_code IS NULL)",
            name="open_request_has_no_outcome",
        ),
        sa.ForeignKeyConstraint(
            ["address_id"],
            ["receive_addresses.id"],
            name="fk_address_lifecycle_requests_address_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["invoices.id"],
            name="fk_address_lifecycle_requests_invoice_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_address_lifecycle_requests"),
        comment=(
            "Ask-the-deriver queue for receive_addresses lifecycle transitions. "
            "The settler asks (it holds SELECT only, TZ 5.8/T1.2), "
            "notchstave_deriver answers (TZ 5.1 p. 2)."
        ),
    )

    op.create_index(
        "ix_address_lifecycle_pending",
        "address_lifecycle_requests",
        ["requested_at"],
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "ix_address_lifecycle_inflight",
        "address_lifecycle_requests",
        ["claimed_at"],
        postgresql_where=sa.text("status = 'processing'"),
    )
    op.create_index(
        "ix_address_lifecycle_completed",
        "address_lifecycle_requests",
        ["completed_at"],
        postgresql_where=sa.text("status IN ('done', 'failed')"),
    )
    # The idempotency guarantee the settler's sweep leans on. See the module
    # docstring: the sweep re-derives its candidates from the ledger every pass
    # and this index is what makes a repeat a no-op rather than a pile.
    op.create_index(
        "uq_address_lifecycle_open_per_action",
        "address_lifecycle_requests",
        ["address_id", "action"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'processing')"),
    )

    op.execute(NOTIFY_FUNCTION_SQL)
    op.execute(
        f"""
        CREATE TRIGGER address_lifecycle_requests_notify
        AFTER INSERT ON address_lifecycle_requests
        FOR EACH ROW EXECUTE FUNCTION {NOTIFY_FUNCTION}()
        """
    )

    # ------------------------------------------------------------- grants
    #
    # The mirror image of 0007's asymmetry. The settler may ask and read back;
    # it may not answer, because an UPDATE here is not a write to
    # `receive_addresses` but it is the *decision* that one happens, and a
    # settler that could mark its own request done would be releasing addresses
    # by writing to a queue instead of by asking the one role allowed to move
    # them. The deriver may answer and prune; it may not ask, because the three
    # conditions of TZ 5.1 are read from `payments` and `invoices`, and the
    # deriver has no grant on `payments` at all.
    _if_role_exists(
        SETTLER,
        f"GRANT SELECT, INSERT ON TABLE address_lifecycle_requests TO {SETTLER}",
    )
    _if_role_exists(
        DERIVER,
        f"GRANT SELECT, UPDATE, DELETE ON TABLE address_lifecycle_requests TO {DERIVER}",
    )


def downgrade() -> None:
    for role in (SETTLER, DERIVER):
        _if_role_exists(role, f"REVOKE ALL ON TABLE address_lifecycle_requests FROM {role}")

    op.execute(
        "DROP TRIGGER IF EXISTS address_lifecycle_requests_notify "
        "ON address_lifecycle_requests"
    )
    op.execute(f"DROP FUNCTION IF EXISTS {NOTIFY_FUNCTION}()")
    op.drop_table("address_lifecycle_requests")
    op.execute(f"DROP TYPE IF EXISTS {STATUS_ENUM}")
    op.execute(f"DROP TYPE IF EXISTS {ACTION_ENUM}")
