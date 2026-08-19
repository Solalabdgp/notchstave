"""invoice_requests: the queue bot/api use to ask the deriver for an invoice

This revision answers the question migration 0006 created and could not itself
close: **if only ``notchstave_deriver`` may mint an invoice, how does a ``/buy``
press in the bot reach the process that holds that role?**

The knot, restated
------------------

``core.invoicing.service.create_invoice`` needs three things at once, in one
transaction: a live :class:`deriver.service.Deriver` (the xpub, for
``deriver.verify`` and for deriving a new index when the pool is empty), the
``notchstave_deriver`` role (0006), and the business rules in ``core.invoicing``.
The first two exist only in the deriver process. The third is a library. So the
invoice is issued *there*, and ``bot``/``api`` can only ask.

They cannot ask over a socket: the deriver is the one process in this system
that must not carry a network stack (TZ 5.8/T4), and ``deriver/tests/
test_isolation.py`` fails the build if it grows one. And they should not ask
over a *new* transport at all — every other link in this system is already
Postgres. The watcher writes ``payments`` and the settler reads them; the settler
writes ``notifications`` and the notifier reads them. No process in this repo
runs a server, and that is not an accident: it is what makes "process X is down"
degrade into latency instead of into an error path per caller.

So this table is that pattern applied one more time, to the one direction that
runs the other way — from the user-facing processes inward.

Why a table and not a unix socket
---------------------------------

The obvious objection is latency: ``/buy`` is interactive, and a poll loop with
a five-second tick would put five seconds in front of a human. That objection is
answered by ``NOTIFY``, not by giving up the transport. The triggers below fire
``pg_notify`` on the *commit* of the request row and again on the commit of its
reply, so both sides are woken by the database at the moment the row becomes
visible — typically single-digit milliseconds — and the poll interval stops
being the response time and becomes only the recovery time for a missed wakeup
(a reconnect, a restart mid-flight).

What the table buys that a socket cannot:

* **Durability.** A request in flight through a socket dies with either end. A
  row does not: a deriver restart resumes from ``processing``, and a bot restart
  can still read the answer to a question it asked before it died.
* **Idempotency and back-pressure for free.** ``uq_invoice_requests_one_open_
  per_user`` is a T5.1 quota expressed as a unique index — a script pressing
  ``/buy`` in a loop gets a constraint violation before it gets an advisory lock,
  never mind an address.
* **No second authorisation model.** Who may ask, and who may answer, is the
  grant matrix below. A socket would need file permissions doing the same job in
  a different vocabulary, and the two would drift.
* **It is inspectable.** "Why did that ``/buy`` fail" is a SELECT.

What it costs, stated rather than buried: two commits per invoice instead of
one, a table that needs pruning (the deriver does it, see the DELETE grant), and
a request that times out on the client while still succeeding on the server —
which is why a timeout is not an error the buyer can act on, and why the client
in ``core.invoicing.client`` says so.

The reply is tamper-evident, and that matters here
--------------------------------------------------

``result_json`` carries the whole verified invoice, including the address the
buyer will be shown. That address travels through a table, and TZ 5.3 requires
that *no* address reach a human without a check. The bot cannot re-derive it —
it has no xpub, by construction. So the reply carries ``integrity_mac`` and the
client recomputes it (TZ 5.8/T1.3) before handing the view to the renderer: an
attacker with UPDATE on this table and no access to ``INVOICE_INTEGRITY_KEY``
can corrupt a reply and cannot forge one. The MAC check is the reason this
transport is allowed to carry an address at all.

``NOTIFY`` payloads are deliberately *only* the request id. Channel names are
not privilege-controlled objects in PostgreSQL — any role that can connect can
``LISTEN`` on any channel — so nothing that is not already readable by the
listener may travel in a payload.

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-19

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DERIVER = "notchstave_deriver"
API = "notchstave_api"
BOT = "notchstave_bot"

TS = sa.DateTime(timezone=True)

#: Both halves of the round trip. Names are module constants in
#: ``deriver/requests.py`` and ``core/invoicing/client.py`` too; a channel name
#: that drifts is a request nobody wakes up for, which looks exactly like a slow
#: deriver — so the string lives in three files and is asserted equal by a test.
CHANNEL_REQUESTS = "notchstave_invoice_requests"

#: Replies go to a channel named after the request instead of to one shared
#: channel, and the reason is fan-out. With a single reply channel every waiting
#: bot handler wakes on every other buyer's answer and re-reads its own row —
#: n wakeups per reply, n² queries per burst, at exactly the moment the system
#: is busiest. ``nsr_`` plus 32 hex characters is 36, comfortably inside
#: PostgreSQL's 63-byte identifier limit, so each waiter can subscribe to
#: precisely the one event it cares about.
REPLY_CHANNEL_PREFIX = "nsr_"

STATUS_ENUM = "invoice_request_status"
STATUSES = ("pending", "processing", "done", "failed")

NOTIFY_FUNCTION = "notchstave_invoice_request_notify"

#: One trigger function, two channels, chosen by what changed. Written as a
#: trigger rather than as a ``NOTIFY`` statement next to each INSERT/UPDATE so
#: that the wakeup is a property of the row transition and not of the code path
#: that caused it — a future admin ``UPDATE`` that fails a stuck request still
#: wakes the client that is waiting for it.
NOTIFY_FUNCTION_SQL = f"""
CREATE OR REPLACE FUNCTION {NOTIFY_FUNCTION}() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM pg_notify('{CHANNEL_REQUESTS}', NEW.id::text);
    ELSIF NEW.status IN ('done', 'failed') AND NEW.status IS DISTINCT FROM OLD.status THEN
        PERFORM pg_notify(
            '{REPLY_CHANNEL_PREFIX}' || replace(NEW.id::text, '-', ''),
            NEW.status::text
        );
    END IF;
    RETURN NULL;
END;
$fn$;
"""


def _if_role_exists(role: str, statement: str) -> None:
    """Same degradation as 0002-0006: no role, no grant, no failed deploy."""
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
    rendered = ", ".join(f"'{v}'" for v in STATUSES)
    op.execute(f"CREATE TYPE {STATUS_ENUM} AS ENUM ({rendered})")

    op.create_table(
        "invoice_requests",
        # Minted by the *client*, as a UUIDv7, before the INSERT. That ordering
        # is what lets the client LISTEN for its own reply before the request
        # exists, which is what closes the lost-wakeup window: a reply that
        # commits between the INSERT and a later LISTEN would otherwise be
        # invisible until the next poll tick.
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column("chain_id", sa.BigInteger(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("hd_account_id", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(*STATUSES, name=STATUS_ENUM, create_type=False),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        # Bumped by the claim, not by the completion, so a request that kills
        # the process it is being served by still counts against its own budget.
        # Without that, a poison request is an infinite crash loop.
        sa.Column("attempts", sa.SmallInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("requested_at", TS, server_default=sa.text("now()"), nullable=False),
        # The lease. `claimed_at` plus the deriver's lease window is when another
        # pass may take this row back off a process that is no longer running —
        # the same mechanism `notifications.next_attempt_at` uses (0004).
        sa.Column("claimed_at", TS, nullable=True),
        sa.Column("completed_at", TS, nullable=True),
        sa.Column("invoice_id", postgresql.UUID(as_uuid=True), nullable=True),
        # The verified InvoiceView, as wire JSON. See core/invoicing/wire.py for
        # the encoding and for why every number in it is a string.
        sa.Column("result_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        # The exception class name from core.invoicing.errors. Deliberately the
        # class name and not a made-up code: the client raises that class back at
        # its caller, so a new refusal in the service is a new refusal at the bot
        # without a lookup table in between that somebody has to remember.
        sa.Column("error_code", sa.Text(), nullable=True),
        # `InvoicingError.user_message` — buyer-safe, rendered as-is.
        sa.Column("error_message", sa.Text(), nullable=True),
        # Structured operator detail: quota limits, observed counts, retry_at.
        # Split from `error_message` because one is shown to a human who pressed
        # a button and the other is read by whoever is on call.
        sa.Column("error_detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.CheckConstraint("attempts >= 0", name="attempts_non_negative"),
        sa.CheckConstraint(
            "status <> 'done' OR (invoice_id IS NOT NULL AND result_json IS NOT NULL "
            "AND completed_at IS NOT NULL)",
            name="done_has_a_result",
        ),
        sa.CheckConstraint(
            "status <> 'failed' OR (error_code IS NOT NULL AND completed_at IS NOT NULL)",
            name="failed_has_a_reason",
        ),
        # An open request carries no outcome. Stated as a constraint rather than
        # left to the writer because the client's wait loop branches on `status`
        # alone, and a row that is `pending` with a `result_json` from a previous
        # attempt would be an answer to a question that is still being asked.
        sa.CheckConstraint(
            "status IN ('done', 'failed') OR (invoice_id IS NULL AND result_json IS NULL "
            "AND error_code IS NULL AND completed_at IS NULL)",
            name="open_request_has_no_outcome",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_invoice_requests_user_id_users", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["products.id"],
            name="fk_invoice_requests_product_id_products",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["chain_id"],
            ["chains.chain_id"],
            name="fk_invoice_requests_chain_id_chains",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name="fk_invoice_requests_asset_id_assets",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["hd_account_id"],
            ["hd_accounts.id"],
            name="fk_invoice_requests_hd_account_id_hd_accounts",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["invoices.id"],
            name="fk_invoice_requests_invoice_id_invoices",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_invoice_requests"),
        comment=(
            "Ask-the-deriver queue for invoice issuance. bot/api INSERT, "
            "notchstave_deriver answers (0006, TZ 5.1 p. 3)."
        ),
    )

    # The claim scan. Partial on `pending` because that is the only status the
    # claim looks at, and the table is dominated by finished rows between prunes.
    op.create_index(
        "ix_invoice_requests_pending",
        "invoice_requests",
        ["requested_at"],
        postgresql_where=sa.text("status = 'pending'"),
    )
    # The lease sweep.
    op.create_index(
        "ix_invoice_requests_inflight",
        "invoice_requests",
        ["claimed_at"],
        postgresql_where=sa.text("status = 'processing'"),
    )
    # The prune.
    op.create_index(
        "ix_invoice_requests_completed",
        "invoice_requests",
        ["completed_at"],
        postgresql_where=sa.text("status IN ('done', 'failed')"),
    )
    # TZ 5.8/T5.1 at the door instead of at the desk. `create_invoice` already
    # refuses a fourth simultaneous invoice — but it refuses it *after* taking
    # an advisory lock and reading three counts, per press. This index refuses a
    # second simultaneous *request* at INSERT time, for the cost of a unique
    # check, and it is the only thing standing between a script and an unbounded
    # queue depth. Its cost is one real behaviour the bot must render: a buyer
    # who double-taps `/buy` gets "one at a time", not two invoices.
    op.create_index(
        "uq_invoice_requests_one_open_per_user",
        "invoice_requests",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'processing')"),
    )

    op.execute(NOTIFY_FUNCTION_SQL)
    op.execute(
        f"""
        CREATE TRIGGER invoice_requests_notify
        AFTER INSERT OR UPDATE OF status ON invoice_requests
        FOR EACH ROW EXECUTE FUNCTION {NOTIFY_FUNCTION}()
        """
    )

    # ------------------------------------------------------------- grants
    #
    # The asymmetry is the point. bot/api may ask and read; they may not answer,
    # because an UPDATE here is a forged invoice reply and 0006 exists precisely
    # to stop them minting one. The deriver may answer and prune; it may not
    # ask, because a process that can enqueue its own work can bypass the quota
    # that lives on the way in.
    _if_role_exists(DERIVER, f"GRANT SELECT, UPDATE, DELETE ON TABLE invoice_requests TO {DERIVER}")
    for role in (API, BOT):
        _if_role_exists(role, f"GRANT SELECT, INSERT ON TABLE invoice_requests TO {role}")


def downgrade() -> None:
    for role in (DERIVER, API, BOT):
        _if_role_exists(role, f"REVOKE ALL ON TABLE invoice_requests FROM {role}")

    op.execute("DROP TRIGGER IF EXISTS invoice_requests_notify ON invoice_requests")
    op.execute(f"DROP FUNCTION IF EXISTS {NOTIFY_FUNCTION}()")
    op.drop_table("invoice_requests")
    op.execute(f"DROP TYPE IF EXISTS {STATUS_ENUM}")
