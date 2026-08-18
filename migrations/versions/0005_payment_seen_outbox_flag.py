"""payments.seen_notified_at: the flag that makes payment_seen an outbox event

TZ 3.5, first bullet: «увидели ваш перевод» — сразу после появления транзакции в
блоке, до подтверждений. The renderer for it has existed since Week 4
(``notifier/render.py::_payment_seen``) and nothing ever wrote the row it
renders, so the first message a buyer got was «оплачено» — after the
confirmation wait, which on Ethereum mainnet above the finality threshold is
minutes of silence with money already sent.

**Why the settler writes it and not the watcher.** The watcher is the process
that first sees the transfer, and it is the obvious author — but migration 0002
gives ``notchstave_watcher`` no privilege at all on ``notifications``, and that
is not an oversight to patch here. The watcher is the process holding RPC
connections to third-party nodes; TZ section 4 scopes it to "блоки → платежи"
and the privilege matrix is what makes that scoping real. Granting it INSERT on
the outbox would let a compromised watcher send arbitrary text to every user of
the bot. The settler already owns the transactional-outbox pattern (TZ 5.8/T2.5)
and already holds ``SELECT, INSERT`` on ``notifications`` and ``SELECT, UPDATE``
on ``payments``, so it needs no new privilege — the whole change fits inside
grants that already exist.

**Why a column and not just the dedup index.** ``UNIQUE (kind, ref_id,
dedup_key)`` on ``notifications`` already makes a second insert of the same
``payment_seen`` a no-op, so correctness does not need this column. Load does.
The settler is a poll loop (``settler/main.py``, five seconds by default), and
without a flag every pass would re-attempt an INSERT for every payment it has
ever seen — a constraint violation absorbed by ``ON CONFLICT DO NOTHING``, but
still a write attempt, a dead tuple, and an index probe per payment per five
seconds, forever. A NULL timestamp answers "does this payment still owe a
message" from a partial index instead.

The column is also the claim: the settler stamps it with ``UPDATE ... WHERE id
= $1 AND seen_notified_at IS NULL`` in the same transaction as the outbox
insert, which is the compare-and-set shape of TZ 5.8/T2.2. Two settler workers
racing on the same payment produce exactly one message, and a rollback takes the
stamp and the message together — there is no state in which the flag says "told
them" and the outbox is empty.

**Cost accepted, stated rather than hidden.** The partial index keeps every
payment that will never be notified — ``reverted``, ``ignored_dust``, and the
``wrong_asset`` / ``wrong_chain`` anomalies the settler deliberately stays quiet
about (telling somebody "we see your transfer, waiting for confirmations" about
money that will never be credited is worse than saying nothing). Those rows are
filtered by the query, never stamped, and so sit in the index permanently. That
is a small and slowly-growing set against the alternative — stamping a
timestamp named ``seen_notified_at`` on a payment nobody was notified about,
which would make the column lie to the next person who reads it.

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-19

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column(
        "payments",
        sa.Column(
            "seen_notified_at",
            TS,
            nullable=True,
            comment="When the settler enqueued the payment_seen outbox row (TZ 3.5).",
        ),
    )

    # NULL on every existing row, which is the honest answer: nothing has ever
    # written a `payment_seen` notification, so no payment has been notified.
    # The practical effect is that the first pass after this migration sends one
    # «увидели ваш перевод» per open payment. That is deliberate — those buyers
    # are owed the message — and it is bounded by the same LIMIT every other
    # settler sweep uses. Backfilling `now()` to suppress it would silence a
    # message TZ 3.5 requires for the sake of a quieter deploy.

    # The scan predicate, verbatim: rows that still owe a message. `invoice_id IS
    # NOT NULL` is in the index rather than only in the query because an
    # `unassigned_payment` has nobody to send to — there is no invoice, so no
    # user — and those rows would otherwise be the bulk of what this index holds
    # on a system under address-reuse pressure.
    op.create_index(
        "ix_payments_seen_unnotified",
        "payments",
        ["id"],
        postgresql_where=sa.text("seen_notified_at IS NULL AND invoice_id IS NOT NULL"),
    )

    # No GRANT statements here on purpose, and it is worth being explicit about
    # why a migration that adds a settler-written column changes no privileges:
    # migration 0002 gives `notchstave_settler` table-level `SELECT, UPDATE` on
    # `payments`, so the new column is already covered. This is the opposite case
    # from 0003/0004, where the grant had to be narrowed to a single column
    # because the column in question was money.


def downgrade() -> None:
    op.drop_index("ix_payments_seen_unnotified", table_name="payments")
    op.drop_column("payments", "seen_notified_at")
