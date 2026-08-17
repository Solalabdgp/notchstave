"""week 3 money grants: internal balance credit and sweep export bookkeeping

Two privileges the Week 2 settler needed and did not have, plus one it must
never gain. All three are grants; there is no DDL in this revision, and that is
the point — the Week 3 features are new *code paths through the existing
schema*, not new tables.

----

**1. `UPDATE (internal_balance_usd)` on `users` for the settler.**

TZ 5.5 says a tolerated overpayment "уходит на внутренний баланс пользователя в
счёт следующих покупок", and migration 0002 gave the settler only `SELECT` on
`users` — so nothing in the system physically performed that credit. The Week 2
settler flagged it rather than papering over it
(``TODO(week3, grants)`` in ``settler/service.py``), which left exactly two
honest ways to close it:

*Widen the grant to the whole table.* Rejected. `users` also holds `tg_id`,
`lang`, `settings_json` and `bot_blocked_at`. A settler with table-level UPDATE
could rewrite a Telegram id — i.e. move a purchase to a different human — and
nothing in the schema would notice. The privilege needed is one column wide;
granting nine columns to get one is the exact shape of the hole 0002 closed on
``receive_addresses``.

*Column-level grant.* Chosen. ``GRANT UPDATE (internal_balance_usd) ON users``
is enforced by PostgreSQL itself: ``UPDATE users SET lang = 'ru'`` under this
role fails with *permission denied for table users* no matter what the
application code says. The privilege is exactly as wide as the requirement, and
``settler/tests/test_grants.py`` asserts both halves — that the credit succeeds
and that every other column is still refused.

*A `SECURITY DEFINER` function was also considered and rejected.* It would add
one more guarantee (the settler could only *add* to a balance, never set it) at
the cost of a function whose owner holds full UPDATE on `users`, a `search_path`
that must be pinned or the function becomes a privilege-escalation primitive,
and a second role for the migration to create on a database where 0002 already
degrades to a NOTICE for lack of CREATEROLE. The additive-only property is
instead held by the *statement* — ``SET internal_balance_usd =
internal_balance_usd + :delta`` with a positive-delta guard in
``settler.repository.credit_internal_balance`` — and by the ``CHECK
(internal_balance_usd >= 0)`` that shipped in 0001. Enforcement in the schema
where it is cheap, in the statement where it is not, and no new privileged
object to audit.

----

**2. `SELECT, INSERT` on `sweep_exports` for the settler.**

`/sweeplist` (TZ 3.4) records the fact that an export was generated. 0002 gave
that table to the bot, on the assumption that the bot both builds and sends the
file. It does not: the bot is the *surface* of the admin commands, the settler
is what executes them (see point 3). `INSERT` and `SELECT` only — an export is a
historical record of what the owner was told to sweep, and editing one after the
fact would defeat the weekly spot-check of three addresses from `/sweeplist`
against an independent derivation that TZ section 9 asks for.

----

**3. The bot does *not* get `INSERT` on `entitlements`, and here it is in writing.**

`/resolve credit` (TZ 3.4) hands a product to a buyer who did not fully pay, and
the obvious implementation is to let the bot process do it, since that is where
the Telegram command arrives. Refused, for one reason: TZ 5.8/T2 rests entirely
on there being **exactly one** code path that creates an entitlement, guarded by
``entitlements_active_uniq``. A second writer is a second place for the "grant
twice" bug to live, in the process with the largest attack surface and the one
T7 assumes can be compromised.

So the split is: the bot parses the command and shows the result; the settler
executes the decision under its own role. The REVOKE below is not redundant with
0002 — it is the thing that makes a future one-line edit to the 0002 GRANTS dict
visibly wrong rather than quietly effective, the same technique 0002 itself uses
for ``receive_addresses``.

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-17

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SETTLER = "notchstave_settler"
API = "notchstave_api"
BOT = "notchstave_bot"
NOTIFIER = "notchstave_notifier"
WATCHER = "notchstave_watcher"
DERIVER = "notchstave_deriver"


def _if_role_exists(role: str, statement: str) -> None:
    """Run `statement` only where `role` was actually created.

    Same degradation as 0002: on a managed database where the migrating user has
    no CREATEROLE the roles do not exist, the deploy must not fail, and the DBA
    applies the grants out of band.
    """
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
    # 1. The overpayment credit of TZ 5.5, one column wide.
    #
    # The REVOKE first is what makes the result provable rather than assumed: a
    # table-level UPDATE left over from an earlier hand-applied grant would make
    # the column-level GRANT look like it was doing something it was not.
    _if_role_exists(SETTLER, f"REVOKE UPDATE ON TABLE users FROM {SETTLER}")
    _if_role_exists(SETTLER, f"GRANT UPDATE (internal_balance_usd) ON TABLE users TO {SETTLER}")

    # 2. `/sweeplist` bookkeeping (TZ 3.4). Append-only in practice: no UPDATE.
    _if_role_exists(SETTLER, f"GRANT SELECT, INSERT ON TABLE sweep_exports TO {SETTLER}")
    _if_role_exists(SETTLER, f"REVOKE UPDATE, DELETE, TRUNCATE ON TABLE sweep_exports FROM {SETTLER}")

    # 3. One writer for entitlements, forever (TZ 5.8/T2).
    for role in (API, BOT, NOTIFIER, WATCHER, DERIVER):
        _if_role_exists(role, f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE entitlements FROM {role}")

    # Belt and braces on the audit trail, restated for the same reason 0002
    # restates it: `/resolve` is about to become the largest producer of rows in
    # this table (TZ 5.8/T7), and a decision that can be edited afterwards is not
    # a decision that was recorded.
    for role in (SETTLER, API, BOT, NOTIFIER, WATCHER, DERIVER):
        _if_role_exists(role, f"REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_log FROM {role}")


def downgrade() -> None:
    _if_role_exists(SETTLER, f"REVOKE UPDATE (internal_balance_usd) ON TABLE users FROM {SETTLER}")
    _if_role_exists(SETTLER, f"REVOKE SELECT, INSERT ON TABLE sweep_exports FROM {SETTLER}")
    # The entitlements and audit_log REVOKEs are deliberately not undone: 0002 is
    # the revision that decides who may write those, and re-granting here would
    # mean a downgrade *widens* privileges. A migration that hands out access on
    # the way down is a migration nobody can safely run.
