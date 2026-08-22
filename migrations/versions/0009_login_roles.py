"""per-process LOGIN roles for the 0002 grant matrix

Migration 0002 built a grant matrix onto six ``NOLOGIN`` roles and 0003/0006/
0007/0008 amended it. Nothing ever logged in as any of them. All six processes
connected with one ``DATABASE_URL`` belonging to the user that owns the tables,
and a table owner is never denied anything on its own tables — so PostgreSQL
never evaluated a single one of those GRANTs or REVOKEs outside the test suite
(which reached them with ``SET ROLE``). Every TZ 5.8 claim of the shape "role X
cannot do Y" — T1.2, T7, T8, 0006's issuance monopoly, 0003's one-column grant on
``users`` — was true of the schema and false of the deployment.

This revision adds the missing half, in the standard two-tier shape:

* the six existing roles stay exactly as they are — ``NOLOGIN`` *permission*
  roles holding the grants, renamed by nothing, referenced by every earlier
  migration;
* six new ``LOGIN`` roles, ``notchstave_<process>_login``, each a member of
  exactly one permission role and of nothing else, owning nothing.

Membership is ``INHERIT`` (PostgreSQL's default) so the privileges apply to the
session as soon as it connects. The alternative, ``NOINHERIT`` plus an explicit
``SET ROLE`` after connecting, moves the enforcement back into application code
that has to remember to run it on every connection — including the ones opened
by a library, and including the reconnect after a dropped socket. The whole
finding this revision closes is what happens when enforcement depends on
application code remembering.

**No passwords here, deliberately.** The roles are created with ``PASSWORD
NULL``, which refuses every password-authenticated connection. Three arguments,
in order of weight:

1. A migration is a file in git. A password in it is a password in every clone,
   every CI artifact and every fork, forever, and rotating it means editing
   history rather than running a command.
2. A migration is replayed. Anything it sets, it re-sets — so a password written
   here would silently revert a rotation performed correctly out of band, at the
   next deploy, with no error.
3. ``PASSWORD NULL`` fails closed. A login role that cannot authenticate is a
   process that will not start; a login role created with a default password is
   a process that starts and a credential everybody knows.

Setting them is an operational step, run once after ``alembic upgrade head`` by
whoever holds the secrets:

    python -m core.db.roles      # reads NOTCHSTAVE_<PROCESS>_DB_PASSWORD

That command is idempotent, so it is also the rotation procedure. See
``core/db/roles.py`` for the per-process URL lookup on the other side of it, and
``docker-compose.test.yml`` for the CI wiring with deterministic test passwords.

**Degrades rather than fails**, same as 0002: creating roles is a cluster-level
operation, and on a managed database where the migrating user has no CREATEROLE
this revision raises a NOTICE and leaves the login roles to the DBA. It also
survives the case where the *permission* roles were themselves created out of
band and the migrating user therefore has no ADMIN OPTION on them.

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-22

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


PROCESSES = ("deriver", "watcher", "settler", "notifier", "bot", "api")

#: (permission role, login role) — the permission names are 0002's, unchanged.
PAIRS: tuple[tuple[str, str], ...] = tuple(
    (f"notchstave_{p}", f"notchstave_{p}_login") for p in PROCESSES
)


def upgrade() -> None:
    pair_list = ", ".join(f"('{perm}','{login}')" for perm, login in PAIRS)

    op.execute(
        f"""
        DO $login_roles$
        DECLARE
            pair record;
        BEGIN
            FOR pair IN SELECT * FROM (VALUES {pair_list}) AS t(perm, login) LOOP
                -- The permission role is the thing that carries the grants. If
                -- 0002 could not create it, creating a login role that is a
                -- member of nothing would produce a process that connects
                -- successfully and is denied its first statement, which is a
                -- worse diagnostic than not existing at all.
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = pair.perm) THEN
                    RAISE NOTICE
                        'notchstave: % missing - skipping %, create both out of band',
                        pair.perm, pair.login;
                    CONTINUE;
                END IF;

                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = pair.login) THEN
                    -- PASSWORD NULL is explicit rather than implied: it is the
                    -- fail-closed property this revision depends on, and a
                    -- reader has to be able to see it without knowing the
                    -- default.
                    EXECUTE format(
                        'CREATE ROLE %I LOGIN INHERIT PASSWORD NULL '
                        'NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                        pair.login);
                END IF;

                -- Explicit, though it matches the default: a login role that
                -- resolved unqualified names through a schema of its own would
                -- be a way around a table-level grant, and this repo's SQL is
                -- unqualified throughout.
                EXECUTE format('ALTER ROLE %I SET search_path TO public', pair.login);

                -- The membership is the entire point of the pair. INHERIT above
                -- is what makes it apply without SET ROLE.
                EXECUTE format('GRANT %I TO %I', pair.perm, pair.login);
            END LOOP;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE NOTICE
                    'notchstave: no privilege to create/grant login roles (%) - '
                    'create them out of band: CREATE ROLE notchstave_<p>_login LOGIN; '
                    'GRANT notchstave_<p> TO notchstave_<p>_login;', SQLERRM;
        END
        $login_roles$;
        """
    )


def downgrade() -> None:
    login_list = ", ".join(f"'{login}'" for _perm, login in PAIRS)

    op.execute(
        f"""
        DO $login_roles$
        DECLARE
            r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY[{login_list}] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE format('DROP ROLE %I', r);
                END IF;
            END LOOP;
        EXCEPTION
            WHEN insufficient_privilege OR dependent_objects_still_exist THEN
                RAISE NOTICE 'notchstave: login roles left in place (%)', SQLERRM;
        END
        $login_roles$;
        """
    )
