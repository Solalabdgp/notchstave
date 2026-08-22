"""Six real logins, six real denials — the proof that the grant matrix is live.

This file is the answer to a specific finding: migrations 0002/0003/0006/0007/
0008 write a careful per-process grant matrix onto six ``NOLOGIN`` roles, and
until migration 0009 nothing ever logged in as any of them. Every process
connected with one ``DATABASE_URL`` belonging to the user that owns the tables,
and **a table owner is never denied anything on its own tables** — so PostgreSQL
never evaluated a single one of those GRANTs or REVOKEs outside a test.

The three ``test_grants.py`` files in this repo did exercise the matrix, with
``SET ROLE`` on an owner connection. That is a genuine check of the matrix and
*not* a check of the deployment: ``SET ROLE`` proves what the roles are allowed
to do if anything ever assumed them. They are kept — they are fast, they need no
credentials, and they cover the *sufficiency* half (a complete settlement, a
complete `/buy`) in far more depth than anything here. This file covers the half
they structurally cannot: that a process starting up today, with the environment
this repo ships, arrives at the database as a constrained identity.

So every assertion below runs over a **separate connection, authenticated with a
password, as the login role itself**. Nothing here calls ``SET ROLE``. If the
per-process URLs were quietly pointed back at the owner tomorrow, the
``current_user`` assertions in :func:`test_each_process_authenticates_as_its_own_role`
and every ``permission denied`` below would fail — which is exactly the
regression that went unnoticed for the whole of weeks 1-5.

Why the denials need no fixture data: PostgreSQL checks table privileges when the
statement is planned, before any row is touched. ``UPDATE receive_addresses SET
status = 'funded'`` on an empty table is a privilege error, not a no-op. That
keeps this file independent of the ``World`` builders and therefore honest — it
cannot pass because a scenario happened not to produce a matching row.

It lives in ``settler/tests`` because that directory owns the real-Postgres rig
(``conftest.py``'s session ``_schema`` fixture runs the migrations), not because
the settler is its subject: all six roles are.

**Skips when the passwords are absent**, the same way the ``SET ROLE`` suites skip
when migration 0002 had no CREATEROLE. Migration 0009 creates the login roles
with ``PASSWORD NULL`` on purpose — a migration in git cannot carry a credential —
so ``python -m core.db.roles`` is a separate operational step, and
``docker-compose.test.yml`` runs it between ``alembic upgrade head`` and pytest.
A bare ``pytest`` against a database where that step was skipped reports the
truth: these roles cannot log in yet.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
from sqlalchemy.engine import make_url

from core.db.roles import PROCESSES, login_role, password_var, permission_role, psycopg_dsn
from settler.tests.conftest import database_url

#: One statement per role that its grants must refuse, with the rule it encodes.
#: Deliberately overlapping between roles: the append-only guarantee (TZ 5.8/T7,
#: T8) and the address-pool monopoly (T1.2) are properties of the *matrix*, not of
#: any one role, and a REVOKE that was dropped for one role only is exactly the
#: kind of edit a per-role list catches and a shared one does not.
DENIED: tuple[tuple[str, str, str], ...] = (
    # --- the address pool belongs to the deriver (0002, TZ 5.8/T1.2) ---------
    ("watcher", "UPDATE receive_addresses SET status = 'funded'", "T1.2"),
    ("settler", "UPDATE receive_addresses SET status = 'funded'", "T1.2"),
    ("notifier", "UPDATE receive_addresses SET status = 'funded'", "T1.2"),
    ("bot", "UPDATE receive_addresses SET status = 'funded'", "T1.2"),
    (
        "api",
        "INSERT INTO receive_addresses (hd_account_id, derivation_index, address) "
        "VALUES (1, 999, '0x1111111111111111111111111111111111111111')",
        "T1.2 — an address is derived, never declared, and least of all by the "
        "one process on a public interface",
    ),
    # --- audit_log is append-only for everyone (0002/0003, TZ 5.8/T7, T8) ----
    ("deriver", "DELETE FROM audit_log", "T7"),
    ("watcher", "DELETE FROM audit_log", "T7"),
    ("settler", "UPDATE audit_log SET action = 'nothing happened'", "T8"),
    ("notifier", "DELETE FROM audit_log", "T7"),
    ("bot", "UPDATE audit_log SET action = 'nothing happened'", "T8"),
    ("api", "DELETE FROM audit_log", "T7"),
    # --- only the deriver mints an invoice (0006) ----------------------------
    #
    # One column and nothing else, which is enough and is not laziness: PostgreSQL
    # checks table privileges at executor start, before a tuple is built, so a
    # NOT NULL column left out never gets as far as complaining. Spelling out a
    # plausible-looking row would only add columns whose types this file would
    # then have to keep in step with the migrations for no gain — and would make
    # the test fail for the wrong reason the first time one of them changes.
    (
        "api",
        "INSERT INTO invoices (id) VALUES ('00000000-0000-0000-0000-000000000001')",
        "0006 — issuance moved to the deriver and the INSERT was revoked here",
    ),
    (
        "bot",
        "INSERT INTO invoices (id) VALUES ('00000000-0000-0000-0000-000000000002')",
        "0006 — the bot asks for an invoice, it does not write one",
    ),
    # --- the queues are asymmetric on purpose (0007, 0008) -------------------
    (
        "bot",
        "UPDATE invoice_requests SET status = 'done'",
        "0007 — a bot that could answer its own request would be minting "
        "invoices through the queue instead of around it",
    ),
    (
        "api",
        "UPDATE derivation_proof_requests SET status = 'done'",
        "0008 — the value of /verify is that the answer comes from the process "
        "that can derive rather than declare",
    ),
    # --- entitlements have exactly one writer (0003) -------------------------
    ("api", "UPDATE entitlements SET revoked_at = now()", "0003"),
    ("bot", "INSERT INTO entitlements (user_id, product_id) VALUES (1, 1)", "0003"),
    ("deriver", "INSERT INTO entitlements (user_id, product_id) VALUES (1, 1)", "0003"),
    ("notifier", "UPDATE entitlements SET revoked_at = now()", "0003"),
    # --- and the tables a role has no business reading at all ----------------
    (
        "watcher",
        "SELECT * FROM entitlements",
        "a chain observer has no reason to know who owns what",
    ),
    (
        "deriver",
        "SELECT * FROM notifications",
        "the process holding the xpub does not read the outbox",
    ),
    (
        "notifier",
        "SELECT * FROM sweep_exports",
        "0003 disowned this table from everyone but the settler",
    ),
    # --- the settler's one-column grant on users (0003) ----------------------
    (
        "settler",
        "UPDATE users SET tg_id = 1",
        "0003 grants UPDATE (internal_balance_usd) and one column means one "
        "column — a settler able to rewrite tg_id could move a purchase to "
        "another person without touching entitlements",
    ),
    ("deriver", "UPDATE users SET lang = 'ru'", "0006 grants the deriver SELECT, not UPDATE"),
    # --- api holds nothing it does not use (0010, S-C3 / Phase-1 M1) ---------
    #
    # api performs zero writes in its own process (api.deps.ApiDependencies
    # exposes only .read()); 0002 nonetheless gave it INSERT/UPDATE on four
    # tables it never touches. The most consequential of the four is
    # `notifications`: an api INSERT there is an attacker-controlled outbox row
    # that the notifier would render and send as a legitimate system message —
    # S-C3, live under a fully-enforced role matrix and independent of C1.
    (
        "api",
        "INSERT INTO notifications (user_id, kind, ref_id, dedup_key, payload_json) "
        "VALUES (1, 'invoice_underpaid', 'x', 'x', '{}'::jsonb)",
        "0010 / S-C3 — the outbox belongs to whoever made the money decision, "
        "and api makes none",
    ),
    ("api", "SELECT * FROM notifications", "0010 — api never reads the outbox either"),
    (
        "api",
        "INSERT INTO users (tg_id) VALUES (999999999)",
        "0010 / Phase-1 M1 — api never creates a user; the bot does, on /start",
    ),
    ("api", "UPDATE users SET lang = 'ru'", "0010 / Phase-1 M1 — api never touches users"),
    (
        "api",
        "INSERT INTO rate_limits (user_id, window_start) VALUES (1, now())",
        "0010 / Phase-1 M1 — no quota-display feature reads or writes this "
        "table from api",
    ),
    (
        "api",
        "INSERT INTO audit_log (actor_kind, actor_id, action, target_kind, target_id) "
        "VALUES ('system', 'api', 'x', 'x', 'x')",
        "0010 / Phase-1 M1 — api logs failures through logging, not audit_log",
    ),
)

#: One read per role that its grants must allow. Sufficiency in depth belongs to
#: the ``SET ROLE`` suites (a whole settlement, a whole `/buy`); this is the
#: narrower claim that the login role reaches the schema at all — that USAGE ON
#: SCHEMA public and the table grant both arrived through the membership, without
#: the process issuing ``SET ROLE``.
ALLOWED: tuple[tuple[str, str], ...] = (
    ("deriver", "SELECT count(*) FROM receive_addresses"),
    ("watcher", "SELECT count(*) FROM blocks"),
    ("settler", "SELECT count(*) FROM invoices"),
    ("notifier", "SELECT count(*) FROM notifications"),
    ("bot", "SELECT count(*) FROM products"),
    ("api", "SELECT count(*) FROM invoices"),
)


def login_dsn(process: str) -> str | None:
    """This process's libpq DSN, built from the owner URL with a swapped identity.

    Host, port and database come from ``DATABASE_URL`` so that the test rig has
    one place that says where the database is; only the credentials change. The
    password comes from the same environment variable
    ``python -m core.db.roles`` reads, which is what keeps the provisioning step
    and this file from drifting into disagreement about what the password is.
    """
    password = os.environ.get(password_var(process))
    if not password:
        return None
    url = make_url(database_url()).set(username=login_role(process), password=password)
    return psycopg_dsn(url.render_as_string(hide_password=False))


@pytest.fixture(scope="module")
def owner() -> Iterator[psycopg.Connection[Any]]:
    """A plain synchronous owner connection, for reading the catalogs."""
    with psycopg.connect(psycopg_dsn(database_url()), autocommit=True) as conn:
        yield conn


@pytest.fixture(autouse=True)
def _require_login_roles(owner: psycopg.Connection[Any]) -> None:
    """Skip where 0009 could not create the roles or their passwords are unset.

    Two separate reasons, reported separately, because the operator's next move
    differs: a missing role means the migration ran without CREATEROLE, a missing
    password means ``python -m core.db.roles`` has not been run.
    """
    with owner.cursor() as cur:
        cur.execute(
            "SELECT rolname FROM pg_roles WHERE rolname = ANY(%(names)s)",
            {"names": [login_role(p) for p in PROCESSES]},
        )
        present = {row[0] for row in cur.fetchall()}
    missing = [login_role(p) for p in PROCESSES if login_role(p) not in present]
    if missing:
        pytest.skip(f"login roles missing ({', '.join(missing)}); 0009 had no CREATEROLE")

    without_password = [password_var(p) for p in PROCESSES if not os.environ.get(password_var(p))]
    if without_password:
        pytest.skip(
            "no login password for: "
            + ", ".join(without_password)
            + " — run `python -m core.db.roles` (docker-compose.test.yml does)"
        )


# ---------------------------------------------------------------------------
# The shape of the two-tier model
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("process", PROCESSES)
def test_the_permission_role_stays_nologin(
    owner: psycopg.Connection[Any], process: str
) -> None:
    """The grants live on a role nothing can connect as.

    Pinned rather than assumed, because the tempting one-line "fix" for the
    original finding is to give the permission role LOGIN and hand out its
    password. That collapses the two tiers into one: the role holding the grants
    becomes an account, so every future ``GRANT ... TO notchstave_settler`` is
    also a change to what a live session may do, and there is no longer any layer
    at which membership can be revoked without rewriting the matrix.
    """
    with owner.cursor() as cur:
        cur.execute(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = %(r)s",
            {"r": permission_role(process)},
        )
        row = cur.fetchone()
    assert row is not None, f"{permission_role(process)} does not exist"
    assert row[0] is False


@pytest.mark.parametrize("process", PROCESSES)
def test_the_login_role_is_a_member_of_exactly_its_permission_role(
    owner: psycopg.Connection[Any], process: str
) -> None:
    """One membership, and it is the right one.

    "Exactly" is the assertion that matters. A login role that had picked up a
    second membership — the owner's, another process's, a convenience group
    someone added during an incident — would hold privileges this repo's
    migrations never granted it, and no GRANTS dict anywhere would show that.
    """
    with owner.cursor() as cur:
        cur.execute(
            """
            SELECT g.rolname
              FROM pg_auth_members m
              JOIN pg_roles r ON r.oid = m.member
              JOIN pg_roles g ON g.oid = m.roleid
             WHERE r.rolname = %(login)s
             ORDER BY g.rolname
            """,
            {"login": login_role(process)},
        )
        memberships = [row[0] for row in cur.fetchall()]
    assert memberships == [permission_role(process)]


@pytest.mark.parametrize("process", PROCESSES)
def test_the_login_role_is_powerless_by_itself(
    owner: psycopg.Connection[Any], process: str
) -> None:
    """No superuser, no role/db creation, no RLS bypass, and owns nothing.

    Ownership is the one worth spelling out: the whole finding this file answers
    is that an owner is never denied anything on its own tables. A login role that
    ended up owning a single table would have an unconstrained hole in the matrix
    at exactly that table, and it would not show up as a GRANT anywhere.
    """
    with owner.cursor() as cur:
        cur.execute(
            """
            SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolcanlogin
              FROM pg_roles WHERE rolname = %(r)s
            """,
            {"r": login_role(process)},
        )
        attributes = cur.fetchone()
        cur.execute(
            """
            SELECT count(*) FROM pg_class c
              JOIN pg_roles r ON r.oid = c.relowner
             WHERE r.rolname = %(r)s
            """,
            {"r": login_role(process)},
        )
        owned = cur.fetchone()

    assert attributes is not None
    superuser, createrole, createdb, bypassrls, canlogin = attributes
    assert (superuser, createrole, createdb, bypassrls) == (False, False, False, False)
    assert canlogin is True
    assert owned is not None and owned[0] == 0


# ---------------------------------------------------------------------------
# Real connections
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("process", PROCESSES)
def test_each_process_authenticates_as_its_own_role(process: str) -> None:
    """The one assertion the ``SET ROLE`` suites cannot make.

    ``session_user`` and not just ``current_user``: ``SET ROLE`` changes the
    latter and leaves the former as whoever logged in. Checking both is what
    distinguishes "a session that assumed the role" from "a session that *is* the
    role", and the difference between those two is the entire finding.
    """
    dsn = login_dsn(process)
    assert dsn is not None
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT session_user, current_user, "
            "       pg_has_role(current_user, %(perm)s, 'USAGE'), "
            "       current_setting('is_superuser')",
            {"perm": permission_role(process)},
        )
        row = cur.fetchone()

    assert row is not None
    session, current, inherits_permission_role, is_superuser = row
    assert session == login_role(process)
    assert current == login_role(process)
    # INHERIT, so the grants apply without the application issuing SET ROLE —
    # which it would eventually forget to do on one connection out of six.
    assert inherits_permission_role is True
    assert is_superuser == "off"


def test_no_process_connects_as_the_schema_owner() -> None:
    """The finding itself, stated as an assertion.

    Six distinct logins, none of them the identity that owns the tables. Written
    as one test over the whole set rather than six, because "they are all
    different from each other and from the owner" is the property; six separate
    inequalities would still pass if two processes shared a role.
    """
    owner_name = make_url(database_url()).username
    identities = set()
    for process in PROCESSES:
        dsn = login_dsn(process)
        assert dsn is not None
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("SELECT session_user")
            row = cur.fetchone()
        assert row is not None
        identities.add(row[0])

    assert len(identities) == len(PROCESSES)
    assert owner_name not in identities


@pytest.mark.parametrize(("process", "statement"), ALLOWED)
def test_the_login_role_can_read_what_its_grants_allow(process: str, statement: str) -> None:
    dsn = login_dsn(process)
    assert dsn is not None
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(statement)
        assert cur.fetchone() is not None


@pytest.mark.parametrize(
    ("process", "statement", "why"),
    DENIED,
    ids=[f"{p}-{s.split()[0].lower()}-{i}" for i, (p, s, _) in enumerate(DENIED)],
)
def test_the_login_role_is_refused_what_its_grants_forbid(
    process: str, statement: str, why: str
) -> None:
    """Each of these was already REVOKEd. None of them was ever enforced.

    Rolled back rather than committed, though nothing here can succeed: if a
    future edit widens a grant, the failure should be this assertion and not a
    mutated database that the next test in the session then reads.
    """
    dsn = login_dsn(process)
    assert dsn is not None
    with psycopg.connect(dsn, autocommit=False) as conn:
        try:
            with pytest.raises(psycopg.errors.InsufficientPrivilege), conn.cursor() as cur:
                cur.execute(statement)
        finally:
            conn.rollback()


@pytest.mark.parametrize(
    ("process", "statement", "why"),
    DENIED,
    ids=[f"{p}-{s.split()[0].lower()}-{i}" for i, (p, s, _) in enumerate(DENIED)],
)
def test_each_denial_is_a_denial_and_not_a_typo(
    process: str, statement: str, why: str
) -> None:
    """Every statement above is well formed — so the refusal proves a privilege.

    Without this, the suite above is worth much less than it looks. A statement
    naming a column that no longer exists, or an enum label that was renamed,
    raises before PostgreSQL ever consults an ACL — and ``pytest.raises`` would
    have caught it just the same if the class it expected happened to be the
    parent of both. That is not hypothetical: two of these cases were written
    with a plausible-looking enum label that the schema does not have, and they
    "passed" against the wrong error until this test existed.

    So each statement is run once as the **owner**, which is denied nothing, and
    the only thing asserted is what did *not* happen: no class-42 error (syntax,
    undefined column/table/object, and — since the owner is running it —
    insufficient privilege) and no 22P02 (an unparseable literal, which is how a
    stale enum label shows up). Anything else is fine and expected: a NOT NULL
    or foreign-key violation means the statement got past planning and into
    execution, which is exactly the far side of the ACL check.

    Rolled back unconditionally: as the owner these statements can genuinely
    modify data.
    """
    masking = ""
    with psycopg.connect(psycopg_dsn(database_url()), autocommit=False) as conn:
        try:
            with conn.cursor() as cur:
                cur.execute(statement)
        except psycopg.Error as exc:
            state = exc.sqlstate or ""
            if state.startswith("42") or state == "22P02":
                masking = f"{state} {exc}"
        finally:
            conn.rollback()

    assert not masking, (
        f"the {process} case ({why}) is malformed, not merely denied: {masking}. "
        "Fix the statement — as written it can never reach a privilege check."
    )
