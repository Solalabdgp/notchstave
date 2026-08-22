"""admin_action_requests: the queue the bot uses to ask the settler to act

This revision closes the hole migration 0003 opened and described but did not
wire. 0003's own docstring states the split in one sentence — *"the bot parses
the command and shows the result; the settler executes the decision under its
own role"* — and then revokes ``INSERT`` on ``entitlements`` from every role but
the settler's to make the first half enforceable. The second half was never
built. ``bot/main.py`` constructed :class:`settler.admin.AdminOps` on the *bot's*
engine, so every one of the TZ 3.4 commands ran under ``notchstave_bot``.

While every process still connected as the schema owner that was invisible: an
owner connection is never denied anything on its own tables, so the code read as
though the split existed. Migration 0009 gave each process its own LOGIN role and
turned the discrepancy into a production failure: ``/resolve credit`` reaches
``INSERT INTO entitlements`` as ``notchstave_bot_login`` and gets ``permission
denied``. Tracked as review finding H1.

Moving the call is not enough, because ``AdminOps`` needs a connection under the
settler's role and the bot process has none and must not have one — handing the
bot the settler's credentials would delete the control rather than satisfy it.
So the bot asks, exactly as it already asks the deriver for an invoice (0007),
and this table is that request.

Why this is the third queue and not a shared one
------------------------------------------------

0007 (bot/api -> deriver) and 0011 (settler -> deriver) already exist and this is
deliberately a third table rather than a fourth ``kind`` column on one of them.
The three queues differ in every property that matters to their storage:

* **Who may write which column.** The grant matrix is per table, and it is the
  entire security argument in all three cases. A shared queue would have to
  express "the bot may insert admin actions but not invoice requests, and may
  not answer either" in application code, which is where 0002's comment about
  ``receive_addresses`` says such rules go to die.
* **What a row references.** An invoice request points at a product and an
  hd_account; an address request points at ``receive_addresses``; this one
  points at nothing, because its arguments are a command line. The foreign keys
  that make the first two readable would all be nullable here.
* **Whether anybody waits.** 0011 has no reply channel because the settler does
  not care when the deriver acts. Here a human is watching a Telegram client, so
  the reply half of 0007's trigger comes back.

Why the arguments are JSONB and the results are JSONB
-----------------------------------------------------

The four commands take four different argument lists and return four different
value objects (``PendingCase``, ``ResolutionResult``, ``SweepExport``,
``ReconcileReport``), and the last of those contains a nested tuple of
``AddressDrift`` rows. Columns for the union of all of that would be forty
nullable fields whose CHECK constraints encode which command is which — a
schema that describes :mod:`settler.admin` rather than storing it, and one that
needs a migration every time a report gains a field.

``settler/admin/wire.py`` is the one place the encoding exists, in both
directions, for the same reason ``core/invoicing/wire.py`` is: an encoder and a
decoder written in two files drift, and here they would drift on an amount.

**Nothing in this table is trusted with money.** The MAC that guards 0007's
reply has no counterpart here and needs none: ``result_json`` is a *report* on
decisions already committed by the settler under its own role. An attacker with
UPDATE on this table can lie to the owner about what happened — a real and
logged offence, since ``audit_log`` is append-only and disagrees — and cannot
cause a grant, a refund or a sweep, because the rows that do those things were
written on the other side of this queue by a role the attacker does not hold.

Why ``requested_by`` is recorded and not checked
------------------------------------------------

The bot writes the owner's ``tg_id`` into every request. The settler does not
use it to authorise anything: TZ 5.8/T7's premise is that the owner's account is
captured, so a caller claiming to be the owner proves nothing, and the control
that actually holds is the one 0003 describes — the bot cannot write
``entitlements`` no matter what it says. The column is there so that
``audit_log`` and this queue can be read side by side afterwards, which is what
"кто и когда трогал деньги" needs.

Revision ID: 0012
Revises: 0011
Create Date: 2026-08-23

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BOT = "notchstave_bot"
SETTLER = "notchstave_settler"

TS = sa.DateTime(timezone=True)

#: Mirrored as module constants in ``settler/admin/queue.py`` and
#: ``settler/admin/client.py``. Same hazard as 0007 and 0011: a drifted name is a
#: wakeup that never arrives, which looks exactly like a slow settler rather than
#: like a bug, so a test asserts the copies are the same string.
CHANNEL_ADMIN_REQUESTS = "notchstave_admin_requests"

#: Replies go to a channel named after the request, not to one shared channel —
#: 0007's fan-out argument, which applies here even though the expected number of
#: simultaneous waiters is one: the property that each waiter wakes only for its
#: own answer should not depend on how many owners a deployment has.
#: ``nsa_`` plus 32 hex characters is 36, inside PostgreSQL's 63-byte limit.
REPLY_CHANNEL_PREFIX = "nsa_"

OP_ENUM = "admin_action_op"
#: One value per method on :class:`settler.admin.AdminOps`. An enum rather than
#: free text because the settler dispatches on this column: an unknown op must be
#: impossible to insert, not something the worker discovers and has to decide
#: what to do about.
OPS = ("pending", "resolve", "sweeplist", "reconcile")

STATUS_ENUM = "admin_request_status"
STATUSES = ("pending", "processing", "done", "failed")

NOTIFY_FUNCTION = "notchstave_admin_request_notify"

#: 0007's trigger, unchanged in shape: the request channel on INSERT, the
#: per-request reply channel when the row reaches a terminal status. Written as a
#: trigger rather than as a ``NOTIFY`` next to each statement so the wakeup is a
#: property of the transition and not of the code path that caused it — an
#: operator who fails a stuck request by hand still wakes whoever is waiting.
NOTIFY_FUNCTION_SQL = f"""
CREATE OR REPLACE FUNCTION {NOTIFY_FUNCTION}() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM pg_notify('{CHANNEL_ADMIN_REQUESTS}', NEW.id::text);
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
    """Same degradation as 0002-0011: no role, no grant, no failed deploy."""
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
    op.execute(f"CREATE TYPE {OP_ENUM} AS ENUM ({', '.join(repr(o) for o in OPS)})")
    op.execute(f"CREATE TYPE {STATUS_ENUM} AS ENUM ({', '.join(repr(s) for s in STATUSES)})")

    op.create_table(
        "admin_action_requests",
        # UUIDv7, minted by the bot before the INSERT — 0007's ordering, and for
        # 0007's reason: the client can LISTEN for its own reply before the
        # request exists, which closes the window where a fast answer commits
        # between the INSERT and a later subscription.
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "op",
            postgresql.ENUM(*OPS, name=OP_ENUM, create_type=False),
            nullable=False,
        ),
        # The command line, decoded by `settler.admin.wire`. Never SQL, never
        # anything the settler passes through to a query as text: every consumer
        # reads named keys out of this object and binds them as parameters.
        sa.Column(
            "args_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        # The owner's Telegram id as the bot saw it. Recorded, not trusted — see
        # the module docstring.
        sa.Column("requested_by", sa.BigInteger(), nullable=True),
        sa.Column(
            "status",
            postgresql.ENUM(*STATUSES, name=STATUS_ENUM, create_type=False),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        # Bumped by the claim rather than by the completion, so a request that
        # kills the process serving it still counts against its own budget. 0007
        # explains why: without that, a poison request is a crash loop.
        sa.Column("attempts", sa.SmallInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("requested_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.Column("claimed_at", TS, nullable=True),
        sa.Column("completed_at", TS, nullable=True),
        sa.Column("result_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        # The exception class name from `settler.admin.errors`, so the bot can
        # re-raise the same class it used to catch when the call was in-process.
        # A code table in between is a thing somebody has to remember to update.
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        # Structured detail for the exceptions that carry data:
        # `ConfirmationRequired` travels with the code the owner must send back.
        sa.Column("error_detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.CheckConstraint("attempts >= 0", name="attempts_non_negative"),
        sa.CheckConstraint(
            "status <> 'done' OR (result_json IS NOT NULL AND completed_at IS NOT NULL)",
            name="done_has_a_result",
        ),
        sa.CheckConstraint(
            "status <> 'failed' OR (error_code IS NOT NULL AND completed_at IS NOT NULL)",
            name="failed_has_a_reason",
        ),
        # An open request carries no outcome. Stated as a constraint because the
        # client's wait loop branches on `status` alone: a `pending` row holding
        # a `result_json` from a previous attempt is an answer to a question that
        # is still being asked.
        sa.CheckConstraint(
            "status IN ('done', 'failed') OR (result_json IS NULL "
            "AND error_code IS NULL AND completed_at IS NULL)",
            name="open_request_has_no_outcome",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_admin_action_requests"),
        comment=(
            "Ask-the-settler queue for the TZ 3.4 owner commands. The bot asks, "
            "notchstave_settler executes under its own role (0003, TZ 5.8/T7)."
        ),
    )

    op.create_index(
        "ix_admin_action_requests_pending",
        "admin_action_requests",
        ["requested_at"],
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "ix_admin_action_requests_inflight",
        "admin_action_requests",
        ["claimed_at"],
        postgresql_where=sa.text("status = 'processing'"),
    )
    op.create_index(
        "ix_admin_action_requests_completed",
        "admin_action_requests",
        ["completed_at"],
        postgresql_where=sa.text("status IN ('done', 'failed')"),
    )

    # No `uq_..._one_open_per_owner`, and the omission is a decision rather than
    # an oversight. 0007 has one because `/buy` is pressed by the public and an
    # unbounded queue depth is the attack. Here the writer is one person whose
    # commands legitimately overlap — `/pending` while a `/reconcile` walks a few
    # hundred addresses over RPC is normal use — and refusing the second one
    # would turn a slow command into an outage of the other three. Back-pressure
    # instead comes from the bot: `settler.admin.client` holds one request open
    # per call and gives up on a deadline.

    op.execute(NOTIFY_FUNCTION_SQL)
    op.execute(
        f"""
        CREATE TRIGGER admin_action_requests_notify
        AFTER INSERT OR UPDATE OF status ON admin_action_requests
        FOR EACH ROW EXECUTE FUNCTION {NOTIFY_FUNCTION}()
        """
    )

    # ------------------------------------------------------------- grants
    #
    # 0007's asymmetry, pointing the other way. The bot may ask and read back the
    # answer; it may not answer, because an UPDATE here is a forged report of a
    # decision the settler never took — and the whole reason this table exists is
    # that the bot's claims about money are not authority. The settler may answer
    # and prune; it may not ask, because a process that can enqueue its own admin
    # actions is a process that can credit an entitlement without an owner, which
    # is the one thing 0003's single-writer rule buys.
    _if_role_exists(BOT, f"GRANT SELECT, INSERT ON TABLE admin_action_requests TO {BOT}")
    _if_role_exists(
        SETTLER,
        f"GRANT SELECT, UPDATE, DELETE ON TABLE admin_action_requests TO {SETTLER}",
    )


def downgrade() -> None:
    for role in (BOT, SETTLER):
        _if_role_exists(role, f"REVOKE ALL ON TABLE admin_action_requests FROM {role}")

    op.execute("DROP TRIGGER IF EXISTS admin_action_requests_notify ON admin_action_requests")
    op.execute(f"DROP FUNCTION IF EXISTS {NOTIFY_FUNCTION}()")
    op.drop_table("admin_action_requests")
    op.execute(f"DROP TYPE IF EXISTS {STATUS_ENUM}")
    op.execute(f"DROP TYPE IF EXISTS {OP_ENUM}")
