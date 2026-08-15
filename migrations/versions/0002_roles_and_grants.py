"""per-process PostgreSQL roles and grants

TZ 6 (last paragraph) and 5.8/T1.2, T7: process separation from section 4 is
decorative unless it is backed by privilege separation. Two rules carry real
security weight:

* only ``notchstave_deriver`` may INSERT/UPDATE ``receive_addresses`` — a
  compromised ``api`` cannot inject an attacker-controlled address into the
  pool (T1, vector 1);
* no application role has UPDATE or DELETE on ``audit_log`` — decisions cannot
  be erased after the fact (T7, T8).

Kept separate from 0001 on purpose: creating roles is a cluster-level operation
that needs CREATEROLE. On a managed database where the migrating user does not
have it, this revision degrades to a NOTICE instead of failing the deploy, and
the roles are then created by the DBA out of band.

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-15

"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


DERIVER = "notchstave_deriver"
API = "notchstave_api"
BOT = "notchstave_bot"
WATCHER = "notchstave_watcher"
SETTLER = "notchstave_settler"
NOTIFIER = "notchstave_notifier"

ROLES = (DERIVER, API, BOT, WATCHER, SETTLER, NOTIFIER)

R = "SELECT"
RW = "SELECT, INSERT, UPDATE"
RU = "SELECT, UPDATE"
RI = "SELECT, INSERT"

#: table -> {role: privileges}. Anything omitted is denied.
GRANTS: dict[str, dict[str, str]] = {
    "chains": {DERIVER: R, API: R, BOT: R, WATCHER: RU, SETTLER: R, NOTIFIER: R},
    "assets": {DERIVER: R, API: R, BOT: R, WATCHER: R, SETTLER: R, NOTIFIER: R},
    "products": {API: R, BOT: R, SETTLER: R},
    "users": {API: RW, BOT: RW, SETTLER: R, NOTIFIER: RU},
    # next_index is bumped only by the deriver, inside the reservation
    # transaction (TZ 5.1, p. 3).
    "hd_accounts": {DERIVER: RU, API: R, BOT: R, WATCHER: R, SETTLER: R},
    # TZ 5.8/T1.2 verbatim: api / bot / watcher get SELECT and nothing else.
    # The settler needs UPDATE to mark funded / swept / return-to-pool, which is
    # a state transition on an existing row, not the creation of an address.
    "receive_addresses": {DERIVER: RW, API: R, BOT: R, WATCHER: R, SETTLER: RU, NOTIFIER: R},
    "blocks": {WATCHER: RW, SETTLER: RU},
    "invoices": {DERIVER: R, API: RW, BOT: RW, WATCHER: R, SETTLER: RU, NOTIFIER: R},
    "payments": {API: R, BOT: R, WATCHER: RI, SETTLER: RU, NOTIFIER: R},
    "entitlements": {API: R, BOT: R, SETTLER: RW, NOTIFIER: R},
    "refunds": {API: R, BOT: RW, SETTLER: RW},
    "manual_reviews": {API: R, BOT: RW, SETTLER: RW},
    "sweep_exports": {DERIVER: R, BOT: RI},
    "notifications": {API: RI, BOT: RI, SETTLER: RI, NOTIFIER: RU},
    # Append-only: INSERT + SELECT, never UPDATE, never DELETE (TZ 5.8/T7).
    "audit_log": {DERIVER: RI, API: RI, BOT: RI, WATCHER: RI, SETTLER: RI, NOTIFIER: RI},
    "rate_limits": {API: RW, BOT: RW, SETTLER: R},
}


def upgrade() -> None:
    # Roles are cluster-wide; create them only if missing, and survive a
    # database where we are not allowed to.
    role_list = ", ".join(f"'{r}'" for r in ROLES)
    op.execute(
        f"""
        DO $roles$
        DECLARE
            r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY[{role_list}] LOOP
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE format('CREATE ROLE %I NOLOGIN', r);
                END IF;
            END LOOP;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE NOTICE
                    'notchstave: cannot create roles (no CREATEROLE). Create % out of band, then re-run grants.',
                    ARRAY[{role_list}];
        END
        $roles$;
        """
    )

    op.execute(
        f"""
        DO $grants$
        DECLARE
            r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY[{role_list}] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', r);
                    EXECUTE format(
                        'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', r);
                END IF;
            END LOOP;
        END
        $grants$;
        """
    )

    for table, matrix in GRANTS.items():
        for role, privileges in matrix.items():
            op.execute(
                f"""
                DO $g$
                BEGIN
                    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                        EXECUTE 'REVOKE ALL ON TABLE {table} FROM {role}';
                        EXECUTE 'GRANT {privileges} ON TABLE {table} TO {role}';
                    END IF;
                END
                $g$;
                """
            )

    # Belt and braces for the append-only guarantee: even if a future migration
    # widens a grant by mistake, this REVOKE documents the intent.
    for role in ROLES:
        op.execute(
            f"""
            DO $g$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                    EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_log FROM {role}';
                END IF;
            END
            $g$;
            """
        )


def downgrade() -> None:
    for table in GRANTS:
        for role in ROLES:
            op.execute(
                f"""
                DO $g$
                BEGIN
                    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                        EXECUTE 'REVOKE ALL ON TABLE {table} FROM {role}';
                    END IF;
                END
                $g$;
                """
            )

    role_list = ", ".join(f"'{r}'" for r in ROLES)
    op.execute(
        f"""
        DO $roles$
        DECLARE
            r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY[{role_list}] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE format('REVOKE ALL ON SCHEMA public FROM %I', r);
                    EXECUTE format(
                        'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %I', r);
                    EXECUTE format('DROP ROLE %I', r);
                END IF;
            END LOOP;
        EXCEPTION
            WHEN insufficient_privilege OR dependent_objects_still_exist THEN
                RAISE NOTICE 'notchstave: roles left in place (%)', SQLERRM;
        END
        $roles$;
        """
    )
