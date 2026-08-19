"""deferrable address<->invoice cycle, and invoice issuance as a deriver privilege

This revision exists to answer one question migration 0001 left open and
``deriver/pool.py`` wrote down without deciding: **in what order does a brand
new invoice and its brand new address come into existence?**

The knot, restated
------------------

``invoices.address_id`` is NOT NULL and references ``receive_addresses.id``.
``receive_addresses.current_invoice_id`` references ``invoices.id``, and the
CHECK ``reserved_state_bound`` forbids ``status='reserved'`` with a NULL value
there. Neither foreign key was DEFERRABLE. So each row needs the other to exist
first, and the fused reservation statement TZ 5.1 p. 3 actually specifies —

    UPDATE receive_addresses SET status='reserved', current_invoice_id=$invoice
     WHERE id = (SELECT id FROM receive_addresses
                  WHERE ... AND status='free'
                  ORDER BY derivation_index FOR UPDATE SKIP LOCKED LIMIT 1)

— cannot run, because ``$invoice`` does not exist yet.

``deriver/pool.py`` shipped both ways out and deliberately did not pick one:
the fused statement above (correct, race-free, one shot, currently illegal) and
a two-phase ``allocate_free_address`` → insert invoice → ``bind_address_to_
invoice`` protocol that is legal against the schema as it stands. Week 5 has to
choose, because Week 5 is the code that actually creates invoices.

Why the two-phase protocol was rejected
---------------------------------------

Not because it is ugly. Because it cannot be one transaction, and the gap is
made of money.

The two phases belong to two different PostgreSQL roles — only
``notchstave_deriver`` may write ``receive_addresses`` (0002, TZ 5.8/T1.2),
only an invoice-issuing role may write ``invoices``. One transaction has one
role. So the protocol is: commit a free address, commit an invoice pointing at
it, commit the binding. Between the second and third commits there exists an
invoice, visible and payable, whose address is still ``free``: no
``reserved_from_block``, no ``current_invoice_id``, not in the watcher's filter.
A buyer paying in that window pays a correct address whose money the system
classifies as ``unassigned_payment`` — a manual review for a customer who did
everything right. And if the third commit never happens (process death, lost
race, an address funded meanwhile), the compensating action is a *fourth*
transaction under the *first* role again.

Holding the row lock across the gap does not rescue it, and the reason is
specific: inserting the invoice takes ``FOR KEY SHARE`` on the referenced
``receive_addresses`` row, which conflicts with the ``FOR UPDATE`` the deriver
would be holding. The two phases would deadlock rather than interleave.

What this revision does instead
-------------------------------

1. ``fk_receive_addresses_current_invoice_id_invoices`` becomes ``DEFERRABLE
   INITIALLY DEFERRED``. Now one transaction can reserve an address to an
   invoice id that does not exist yet, insert that invoice a few statements
   later, and let the constraint check both at COMMIT. Every intermediate state
   is invisible to every other transaction, which is precisely the property the
   two-phase protocol could not have.

   Only *this* direction is deferred. ``fk_invoices_address_id_receive_
   addresses`` stays IMMEDIATE: an invoice must never be insertable against an
   address row that is not there, and nothing in the flow needs it to be.

   The cost, stated rather than buried: a deferred constraint reports its
   violation at COMMIT, where the failing statement is no longer in the
   traceback. That is a debuggability tax on a code path that has exactly one
   caller (``core.invoicing.service.create_invoice``), paid once, in exchange
   for removing a window in which a buyer's money goes to manual review.

2. ``notchstave_deriver`` gains INSERT on ``invoices`` and the reads and writes
   the issuance transaction needs, and ``notchstave_api`` / ``notchstave_bot``
   lose INSERT on ``invoices``.

   This is the part worth arguing with, so here is the argument. An invoice is a
   promise that an address is ours and derives from our xpub. The component that
   can make that promise truthfully is the one holding the xpub; every other
   component can only copy an address from somewhere and assert it. Splitting
   "reserve the address" from "issue the invoice that names it" across two
   privilege domains does not divide the capability, it duplicates it — the
   issuer still decides which address the buyer sees. Folding issuance into the
   deriver's role means a compromised ``api`` or ``bot`` can cancel invoices and
   read them, and cannot mint one pointing anywhere it likes. T1.2 gets wider in
   letter (one more table for the deriver) and narrower in effect (one fewer
   process able to put an address in front of a buyer).

   What did NOT change: nobody gained UPDATE or DELETE on ``audit_log``, nobody
   but the deriver gained anything on ``receive_addresses``, and the deriver
   still has no UPDATE on ``invoices`` — it can issue one and never rewrite one.
   Settlement stays with the settler.

3. ``ix_invoices_user_created_at_recent`` — the hourly quota of TZ 5.8/T5.1 is
   answered by counting this user's invoices inside a rolling window, and that
   count runs under an advisory lock on every ``/buy``. ``ix_invoices_user_id_
   created_at`` from 0001 already covers it; this revision only adds the
   ``rate_limits`` lookup index, since that table had none for the hot path.

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-19

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FK_NAME = "fk_receive_addresses_current_invoice_id_invoices"

DERIVER = "notchstave_deriver"
API = "notchstave_api"
BOT = "notchstave_bot"

#: Everything the single issuance transaction touches, and nothing else.
#:
#: ``products`` / ``users`` / ``chains`` / ``assets`` are read to price the
#: invoice and to reject a disabled asset before an address is spent on it.
#: ``rate_limits`` is written because the quota decision and the invoice are one
#: unit of work — a quota counter that commits separately from the thing it
#: counts is a quota that can be walked past by crashing at the right moment.
#: ``notifications`` is NOT here: issuance sends nothing.
ISSUANCE_GRANTS: tuple[tuple[str, str], ...] = (
    ("invoices", "SELECT, INSERT"),
    ("products", "SELECT"),
    ("users", "SELECT"),
    ("rate_limits", "SELECT, INSERT, UPDATE"),
)


def _if_role_exists(role: str, statement: str) -> str:
    """Wrap DDL so a cluster without the roles (0002 had no CREATEROLE) still migrates."""
    return f"""
        DO $g$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                EXECUTE '{statement}';
            END IF;
        END
        $g$;
        """


def upgrade() -> None:
    # 1. The cycle. DROP + ADD rather than ALTER: PostgreSQL has no
    #    `ALTER CONSTRAINT ... DEFERRABLE` for foreign keys that were created
    #    NOT DEFERRABLE, only for changing the initial deferral mode of one that
    #    already is.
    op.execute(f"ALTER TABLE receive_addresses DROP CONSTRAINT {FK_NAME}")
    op.execute(
        f"""
        ALTER TABLE receive_addresses
            ADD CONSTRAINT {FK_NAME}
            FOREIGN KEY (current_invoice_id) REFERENCES invoices (id)
            ON DELETE RESTRICT
            DEFERRABLE INITIALLY DEFERRED
        """
    )

    # 2. Issuance moves to the role that can derive.
    for table, privileges in ISSUANCE_GRANTS:
        op.execute(_if_role_exists(DERIVER, f"GRANT {privileges} ON TABLE {table} TO {DERIVER}"))

    for role in (API, BOT):
        # Spelled as a REVOKE of INSERT alone, leaving SELECT and UPDATE intact:
        # the bot still cancels an invoice (TZ 3.1, inline "отменить счёт") and
        # the api still reads one. Only minting is withdrawn.
        op.execute(_if_role_exists(role, f"REVOKE INSERT ON TABLE invoices FROM {role}"))

    # 3. The quota lookup. `rate_limits` is keyed (user_id, window_start) and the
    #    hot query is "this user's row for the current window", which the primary
    #    key already serves — but the cooldown sweep and any future eviction want
    #    a user-only path that does not scan. Cheap index, one table, no data.
    op.create_index(
        "ix_rate_limits_user_id_cooldown_until",
        "rate_limits",
        ["user_id", "cooldown_until"],
        postgresql_where=None,
    )


def downgrade() -> None:
    op.drop_index("ix_rate_limits_user_id_cooldown_until", table_name="rate_limits")

    for role in (API, BOT):
        op.execute(_if_role_exists(role, f"GRANT INSERT ON TABLE invoices TO {role}"))

    for table, _privileges in ISSUANCE_GRANTS:
        # Back to 0002's matrix: deriver had SELECT on invoices and nothing at
        # all on products / users / rate_limits.
        if table == "invoices":
            op.execute(_if_role_exists(DERIVER, f"REVOKE INSERT ON TABLE {table} FROM {DERIVER}"))
        else:
            op.execute(_if_role_exists(DERIVER, f"REVOKE ALL ON TABLE {table} FROM {DERIVER}"))

    op.execute(f"ALTER TABLE receive_addresses DROP CONSTRAINT {FK_NAME}")
    op.execute(
        f"""
        ALTER TABLE receive_addresses
            ADD CONSTRAINT {FK_NAME}
            FOREIGN KEY (current_invoice_id) REFERENCES invoices (id)
            ON DELETE RESTRICT
        """
    )
