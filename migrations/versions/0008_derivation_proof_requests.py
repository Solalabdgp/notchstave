"""derivation_proof_requests: the queue /verify uses to ask the deriver for a proof

Migration 0007 answered "how does a ``/buy`` reach the process that holds the
xpub". This one answers the question ``/verify`` asks, which is nearly the same
question turned around: **how does the bot show an address it is allowed to show?**

The rule it has to satisfy
--------------------------

TZ 5.3 and 5.8/T1.1: *"Перед любым показом адреса пользователю ... `api`/`bot`/
`settler` дёргают `deriver.verify(address, hd_account_id, derivation_index)`"*.
And TZ 5.8/T1.4: ``/verify <invoice_id>`` publishes ``xpub_fingerprint``, the
full derivation path, and the address, so the owner can reproduce the address in
a third-party tool without trusting the bot.

Both halves need the xpub. The bot does not have one and must never have one
(T4), so it cannot run either. ``/buy`` gets around this because issuance
already happens inside the deriver process — the address on a ``/buy`` message
was verified at issuance and re-checked by its MAC on arrival (0007). ``/verify``
has no such ride: it is a question asked about an invoice that was issued
minutes or hours ago, and answering it out of the bot's own SELECT would print
whatever the ``invoices`` row currently says. That is precisely vector 1 of T1
— *"компрометация БД без компрометации хоста"* — and printing the tampered
address under the heading "derivation proof" would be worse than not offering
the command at all.

So ``/verify`` asks the deriver, over the transport this repository already
uses for exactly this shape of question.

Why a second table rather than a ``kind`` column on ``invoice_requests``
-----------------------------------------------------------------------

The temptation is one queue with a discriminator. Three concrete things stop it,
and all three are in 0007's own DDL:

* ``product_id``, ``chain_id``, ``asset_id`` and ``hd_account_id`` are ``NOT
  NULL`` there. A proof request has none of them — it names an invoice. Making
  four columns nullable to fit a second shape gives up the constraint that makes
  the first shape checkable.
* ``uq_invoice_requests_one_open_per_user`` is a *quota on issuance* (T5.1). A
  shared table would make ``/verify`` consume that quota, so a buyer with a
  ``/buy`` in flight could not ask whether the address they are looking at is
  real — the exact moment they most want to.
* ``fk_invoice_requests_invoice_id_invoices`` is ``ON DELETE RESTRICT``, because
  a reply that names an issued invoice must not outlive it silently. Here the
  invoice is the *input*, so the correct rule is the opposite one (``CASCADE``):
  the question disappears with the thing it was about.

Two tables cost one more trigger and a second drain in the deriver loop. One
table would cost a constraint set that means nothing for either shape, which is
the more expensive of the two.

The reply is MAC'd, and here that is the entire point
-----------------------------------------------------

``result_json`` carries an address, so it travels under the same rule 0007
established: the client recomputes an HMAC over the reply before showing it
(TZ 5.8/T1.3). The tuple is different — ``(invoice_id, xpub_fingerprint,
derivation_path, address)`` under its own domain tag, see
``core/invoicing/proof.py`` — because a proof is a different claim from an
invoice and a MAC that verified for both would let one be replayed as the other.

Without that check this table would be a *new* place to substitute an address,
which would make ``/verify`` a downgrade rather than a countermeasure. With it,
an attacker holding UPDATE on this table and not ``INVOICE_INTEGRITY_KEY`` can
corrupt a proof into a visible failure and cannot forge one.

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-19

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DERIVER = "notchstave_deriver"
API = "notchstave_api"
BOT = "notchstave_bot"

TS = sa.DateTime(timezone=True)

#: Mirrors of the two constants in ``deriver/requests.py`` and
#: ``core/invoicing/proof.py``. Asserted equal by a test, for the reason 0007
#: gives: a drifted channel name is a wakeup that never arrives, and that looks
#: exactly like a slow deriver rather than like a bug.
CHANNEL_PROOFS = "notchstave_proof_requests"

#: ``nsp_`` + 32 hex characters = 36, inside PostgreSQL's 63-byte identifier
#: limit. A channel per request, for 0007's fan-out reason.
PROOF_REPLY_PREFIX = "nsp_"

#: Reused from 0007 rather than redeclared. The two queues genuinely have the
#: same four states, and a second enum with the same members would be a second
#: thing to migrate in step every time either one gains a state.
STATUS_ENUM = "invoice_request_status"

NOTIFY_FUNCTION = "notchstave_proof_request_notify"

NOTIFY_FUNCTION_SQL = f"""
CREATE OR REPLACE FUNCTION {NOTIFY_FUNCTION}() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM pg_notify('{CHANNEL_PROOFS}', NEW.id::text);
    ELSIF NEW.status IN ('done', 'failed') AND NEW.status IS DISTINCT FROM OLD.status THEN
        PERFORM pg_notify(
            '{PROOF_REPLY_PREFIX}' || replace(NEW.id::text, '-', ''),
            NEW.status::text
        );
    END IF;
    RETURN NULL;
END;
$fn$;
"""


def _if_role_exists(role: str, statement: str) -> None:
    """Same degradation as 0002-0007: no role, no grant, no failed deploy."""
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
    op.create_table(
        "derivation_proof_requests",
        # Client-minted UUIDv7, before the INSERT, so the caller can LISTEN for
        # its own reply before the request exists (0007's lost-wakeup argument).
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        # The asker. Present so the *deriver* enforces the IDOR rule of TZ
        # 5.8/T1.7 rather than trusting the bot to have filtered: the issuer
        # passes this straight into `verify_invoice_address(expected_user_id=)`,
        # which answers "no such invoice" for somebody else's id.
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("invoice_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(name=STATUS_ENUM, create_type=False),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column("attempts", sa.SmallInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("requested_at", TS, server_default=sa.text("now()"), nullable=False),
        sa.Column("claimed_at", TS, nullable=True),
        sa.Column("completed_at", TS, nullable=True),
        # The proof triple plus its MAC, as wire JSON. See core/invoicing/proof.py.
        sa.Column("result_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        # An exception class name from core.invoicing.errors, same convention as
        # invoice_requests.error_code — so `InvoiceNotFound` raised in the
        # deriver is `InvoiceNotFound` caught in the bot, with no lookup table.
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.CheckConstraint("attempts >= 0", name="attempts_non_negative"),
        sa.CheckConstraint(
            "status <> 'done' OR (result_json IS NOT NULL AND completed_at IS NOT NULL)",
            name="done_has_a_proof",
        ),
        sa.CheckConstraint(
            "status <> 'failed' OR (error_code IS NOT NULL AND completed_at IS NOT NULL)",
            name="failed_has_a_reason",
        ),
        sa.CheckConstraint(
            "status IN ('done', 'failed') OR (result_json IS NULL AND error_code IS NULL "
            "AND completed_at IS NULL)",
            name="open_request_has_no_outcome",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_derivation_proof_requests_user_id_users",
            ondelete="CASCADE",
        ),
        # CASCADE, unlike 0007's RESTRICT on the same column name, and the
        # direction is what differs: there the invoice is the *product* of the
        # request, here it is the *subject*. A question about a deleted invoice
        # has no answer worth keeping.
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["invoices.id"],
            name="fk_derivation_proof_requests_invoice_id_invoices",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_derivation_proof_requests"),
        comment=(
            "Ask-the-deriver queue for derivation proofs. bot/api INSERT, "
            "notchstave_deriver answers (TZ 5.8/T1.1, T1.4)."
        ),
    )

    op.create_index(
        "ix_derivation_proof_requests_pending",
        "derivation_proof_requests",
        ["requested_at"],
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "ix_derivation_proof_requests_inflight",
        "derivation_proof_requests",
        ["claimed_at"],
        postgresql_where=sa.text("status = 'processing'"),
    )
    op.create_index(
        "ix_derivation_proof_requests_completed",
        "derivation_proof_requests",
        ["completed_at"],
        postgresql_where=sa.text("status IN ('done', 'failed')"),
    )
    # Back-pressure, not a quota. `/verify` consumes no address and no rate
    # limit, so there is nothing here to ration — but a script that can enqueue
    # unboundedly is a script that can fill a table, and one open question per
    # user is all any human interaction needs. The bot renders the resulting
    # unique violation as "one moment", exactly as it does for `/buy`.
    op.create_index(
        "uq_derivation_proof_requests_open_per_user",
        "derivation_proof_requests",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'processing')"),
    )

    op.execute(NOTIFY_FUNCTION_SQL)
    op.execute(
        f"""
        CREATE TRIGGER derivation_proof_requests_notify
        AFTER INSERT OR UPDATE OF status ON derivation_proof_requests
        FOR EACH ROW EXECUTE FUNCTION {NOTIFY_FUNCTION}()
        """
    )

    # ------------------------------------------------------------- grants
    #
    # The same asymmetry as 0007, and here it carries more weight than there. A
    # bot with UPDATE on this table could answer its own question — that is,
    # declare an address proven. The whole value of `/verify` is that the answer
    # comes from the one process that can derive rather than declare, so the
    # grant matrix has to say so.
    _if_role_exists(
        DERIVER,
        f"GRANT SELECT, UPDATE, DELETE ON TABLE derivation_proof_requests TO {DERIVER}",
    )
    for role in (API, BOT):
        _if_role_exists(
            role, f"GRANT SELECT, INSERT ON TABLE derivation_proof_requests TO {role}"
        )


def downgrade() -> None:
    for role in (DERIVER, API, BOT):
        _if_role_exists(role, f"REVOKE ALL ON TABLE derivation_proof_requests FROM {role}")

    op.execute(
        "DROP TRIGGER IF EXISTS derivation_proof_requests_notify ON derivation_proof_requests"
    )
    op.execute(f"DROP FUNCTION IF EXISTS {NOTIFY_FUNCTION}()")
    op.drop_table("derivation_proof_requests")
