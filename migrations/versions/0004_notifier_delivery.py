"""notifier delivery state: retry schedule + column-scoped user grant

Week 4 (TZ section 11 — "надёжность: ... backoff, DLQ, метрики"). Two changes,
both of them things the notifier cannot do correctly without the database.

**1. ``notifications.next_attempt_at``.**

TZ 5.5 asks for "ретраи с backoff, после N неудач — DLQ". Backoff is a *time*,
and there was nowhere to put it: the table carried ``attempts`` and
``last_error`` but no schedule. Keeping the schedule in process memory looks
adequate while the process is up and is wrong the moment it is not — a
notifier that crash-loops re-reads every failed row on every start and hammers
the Telegram API precisely when something is already broken. The column also
does the second job the process needs from it: it is the claim **lease**. A row
picked up for delivery gets ``next_attempt_at = now() + lease``, so a second
instance (or the same instance after a restart) will not pick up a message that
may still be in flight.

NULL means "eligible now" — that is what every existing queued row means, and
backfilling ``now()`` into rows written before this migration would have delayed
them for no reason.

**2. Column-scoped UPDATE on ``users`` for the notifier.**

Migration 0002 gave ``notchstave_notifier`` table-level ``SELECT, UPDATE`` on
``users`` for one purpose: setting ``bot_blocked_at`` when Telegram answers 403
(TZ 5.5, 5.7). Table-level UPDATE also let it rewrite
``internal_balance_usd`` — the overpayment credit of TZ 5.5 — which is real
money, in the one process whose whole job is to talk to a third-party API. That
is the same hole 0003 closed for the settler, and it is closed here the same
way and for the same reason: the REVOKE first, so the result is provable rather
than assumed.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-19

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NOTIFIER = "notchstave_notifier"

TS = sa.DateTime(timezone=True)


def _if_role_exists(role: str, statement: str) -> None:
    """Same degradation as 0002/0003: no role, no grant, no failed deploy."""
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
    op.add_column(
        "notifications",
        sa.Column(
            "next_attempt_at",
            TS,
            nullable=True,
            comment="Earliest next delivery attempt; also the in-flight lease (TZ 5.5).",
        ),
    )

    # The retry scan, mirroring `ix_notifications_queue` for the other half of
    # the claim predicate. Partial on `failed` because that is the only status a
    # retry can be in — `queued` rows are always eligible and are already served
    # by the existing index, and `sent`/`dead` are terminal.
    op.create_index(
        "ix_notifications_retry",
        "notifications",
        ["next_attempt_at"],
        postgresql_where=sa.text("status = 'failed'"),
    )

    # A dead row is a row a human has to look at (TZ 5.5 "DLQ с ручным
    # разбором") and `notchstave_dlq_size` counts them on every pass (TZ 7).
    # Without this the gauge is a sequential scan over the whole outbox.
    op.create_index(
        "ix_notifications_dead",
        "notifications",
        ["created_at"],
        postgresql_where=sa.text("status = 'dead'"),
    )

    _if_role_exists(NOTIFIER, f"REVOKE UPDATE ON TABLE users FROM {NOTIFIER}")
    _if_role_exists(NOTIFIER, f"GRANT UPDATE (bot_blocked_at) ON TABLE users TO {NOTIFIER}")


def downgrade() -> None:
    op.drop_index("ix_notifications_dead", table_name="notifications")
    op.drop_index("ix_notifications_retry", table_name="notifications")
    op.drop_column("notifications", "next_attempt_at")

    # The column grant is deliberately NOT widened back to table level. A
    # downgrade that hands out privileges is a downgrade nobody can safely run
    # (0003 states the same rule for the same reason).
    _if_role_exists(NOTIFIER, f"REVOKE UPDATE (bot_blocked_at) ON TABLE users FROM {NOTIFIER}")
