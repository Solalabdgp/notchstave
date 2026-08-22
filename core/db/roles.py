"""Which PostgreSQL identity each process logs in as, and how it gets there.

Migration 0002 (with 0003/0006/0007/0008 amending it) writes a grant matrix onto
six roles — ``notchstave_deriver``, ``notchstave_watcher``, ``notchstave_settler``,
``notchstave_notifier``, ``notchstave_bot``, ``notchstave_api``. Every guarantee in
TZ 5.8 that is phrased "role X cannot do Y" is that matrix and nothing else:
T1.2 (only the deriver writes ``receive_addresses``), T7/T8 (``audit_log`` is
append-only), 0006 (only the deriver mints an invoice), 0003 (one writer for
``entitlements``, one *column* of ``users`` for the settler).

Until this module existed the matrix was inert. Those six roles are ``NOLOGIN``
— they are permission roles, not accounts — and all six processes connected with
one ``DATABASE_URL`` belonging to the user that owns the tables. A table owner is
never denied anything on its own tables, so PostgreSQL never consulted a single
GRANT or REVOKE in production; the whole matrix was documentation with a test
suite (``*/tests/test_grants.py`` reached it via ``SET ROLE``, which is the only
reason it was ever exercised at all).

**The model, in the standard two-tier shape.**

* A *permission role* per process (``notchstave_settler``) — ``NOLOGIN``, owns no
  tables, holds the grants. Unchanged: migrations 0002-0008 keep writing to
  exactly these names, and nothing here renames them.
* A *login role* per process (``notchstave_settler_login``) — ``LOGIN``, granted
  membership in its one permission role and in nothing else, owns nothing. This
  is what a process authenticates as. Membership is ``INHERIT`` (the default), so
  the privileges apply without the process having to issue ``SET ROLE`` — an
  application that had to remember to do that would forget on one code path.

Migration ``0009_login_roles`` creates the login roles. It does **not** set their
passwords: see that migration's docstring for the argument, in short a password
in a file under version control is not a password. :func:`main` here is the
operational step that sets them.

**One URL per process, no shared fallback.** Each process reads its own variable
(``SETTLER_DATABASE_URL``, ``WATCHER_DATABASE_URL``, ...) and raises if it is
missing. There is deliberately no "fall back to ``DATABASE_URL``": that fallback
is precisely the bug this module exists to close, and a fallback with a warning
would be the same bug with a log line in front of it. ``DATABASE_URL`` keeps its
meaning — the *owner* connection — and is now used by exactly two things that
legitimately need to own the schema: Alembic, and the provisioning CLI below.

**Production delivery.** The per-process URL carries a password, so in production
it arrives as a systemd credential (``LoadCredential=`` writing
``notchstave-<process>-database-url`` into ``$CREDENTIALS_DIRECTORY``) and not as
an environment variable, which is readable from ``docker inspect``,
``/proc/<pid>/environ`` and a core dump. Same rule and same precedence as
``INVOICE_INTEGRITY_KEY``: the credential file wins whenever it is present, so a
stray env var cannot downgrade a correctly configured unit. The environment path
exists for local dev, and ``.env.example`` says so.

Note for ``deriver/``: that package cannot import ``core`` (see
``deriver/pyproject.toml`` — the isolation is enforced by dependency resolution
and asserted by ``deriver/tests/test_isolation.py``), so
``deriver.main.database_dsn`` carries its own copy of the lookup below. The
duplication is deliberate and already the established convention there.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    import psycopg

__all__ = [
    "PROCESSES",
    "credential_name",
    "login_role",
    "password_var",
    "permission_role",
    "process_database_url",
    "psycopg_dsn",
    "url_var",
]

#: The six process boundaries of TZ section 4, in the order migration 0002 lists
#: them. A seventh name here without a matching row in that migration's GRANTS
#: dict would be a login with no privileges, which fails loudly on first query.
PROCESSES: tuple[str, ...] = ("deriver", "watcher", "settler", "notifier", "bot", "api")


def _check(process: str) -> str:
    if process not in PROCESSES:
        raise ValueError(f"unknown process {process!r}; expected one of {', '.join(PROCESSES)}")
    return process


def permission_role(process: str) -> str:
    """The ``NOLOGIN`` role holding the grants (migrations 0002-0008)."""
    return f"notchstave_{_check(process)}"


def login_role(process: str) -> str:
    """The ``LOGIN`` role the process authenticates as (migration 0009)."""
    return f"notchstave_{_check(process)}_login"


def url_var(process: str) -> str:
    """Environment variable holding this process's own connection URL."""
    return f"{_check(process).upper()}_DATABASE_URL"


def credential_name(process: str) -> str:
    """File name under ``$CREDENTIALS_DIRECTORY`` holding the same URL."""
    return f"notchstave-{_check(process)}-database-url"


def password_var(process: str) -> str:
    """Environment variable read by :func:`main` when setting a login password.

    Only the provisioning step reads this. A running process never sees a bare
    password — it gets a complete URL, and only its own.
    """
    return f"NOTCHSTAVE_{_check(process).upper()}_DB_PASSWORD"


def password_credential_name(process: str) -> str:
    """File name under ``$CREDENTIALS_DIRECTORY`` holding the same password."""
    return f"notchstave-{_check(process)}-db-password"


def _read_credential(name: str, env: Mapping[str, str], override: str | None) -> str | None:
    raw_dir = override or env.get("CREDENTIALS_DIRECTORY")
    if not raw_dir:
        return None
    candidate = Path(raw_dir) / name
    if not candidate.is_file():
        return None
    # `.rstrip` and not `.strip`: leading whitespace in a credential file is
    # content, a trailing newline is an editor artefact. Same call as
    # `core.invoicing.integrity.load_integrity_key`, for the same reason.
    return candidate.read_text(encoding="utf-8").rstrip("\r\n") or None


def process_database_url(
    process: str,
    *,
    env: Mapping[str, str] | None = None,
    credentials_dir: str | None = None,
) -> str:
    """This process's own SQLAlchemy-form URL, or raise.

    Credential file first, environment second, nothing third. The absence of a
    third option is the point: a process that cannot find its own credentials
    must not silently connect as somebody with more privileges, and the only
    identity lying around to fall back to is the schema owner.
    """
    src = os.environ if env is None else env
    _check(process)

    from_file = _read_credential(credential_name(process), src, credentials_dir)
    if from_file:
        return from_file

    from_env = src.get(url_var(process))
    if from_env and from_env.strip():
        return from_env.strip()

    raise RuntimeError(
        f"{url_var(process)} is not set. Each process connects as its own "
        f"PostgreSQL login role ({login_role(process)}, a member of "
        f"{permission_role(process)}) so that the grant matrix in migrations "
        f"0002-0008 is enforced by the database rather than merely documented. "
        f"There is no fallback to DATABASE_URL: that variable is the schema "
        f"OWNER, and an owner is never denied anything on its own tables. "
        f"Production delivers this URL as the systemd credential "
        f"{credential_name(process)}; local dev sets {url_var(process)} in .env "
        f"(see .env.example)."
    )


def psycopg_dsn(url: str) -> str:
    """``postgresql+psycopg://`` -> ``postgresql://``.

    The repo standardises on SQLAlchemy's form (``.env.example``, ``alembic.ini``,
    ``migrations/env.py``); psycopg does not understand the ``+driver`` suffix,
    and several processes need both faces of the same URL. Converting at the
    point of use rather than carrying a second environment variable is what stops
    the two drifting apart.
    """
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


# ---------------------------------------------------------------------------
# Operational step: set the login passwords
# ---------------------------------------------------------------------------
#
# Run once after `alembic upgrade head`, as the owner/superuser, from a shell
# that has the six passwords:
#
#     python -m core.db.roles
#
# Idempotent — ALTER ROLE ... PASSWORD overwrites, so this is also the rotation
# procedure. Roles whose password is not supplied are left exactly as they are,
# which for a freshly created login role means PASSWORD NULL, which means every
# password-authenticated connection attempt is refused. Failing closed is the
# whole reason the migration does not invent a default.


def _password_for(
    process: str, env: Mapping[str, str], credentials_dir: str | None
) -> str | None:
    from_file = _read_credential(password_credential_name(process), env, credentials_dir)
    if from_file:
        return from_file
    raw = env.get(password_var(process))
    return raw.strip() if raw and raw.strip() else None


def provision(
    conn: psycopg.Connection[Any],
    *,
    env: Mapping[str, str] | None = None,
    credentials_dir: str | None = None,
) -> list[str]:
    """``ALTER ROLE <login> WITH LOGIN PASSWORD ...`` for every supplied password.

    ``conn`` is a live connection owned by the caller — the transaction and the
    commit belong to whoever opened it. Returns the login roles that were
    changed, in :data:`PROCESSES` order.

    The password is passed through ``psycopg.sql.Literal`` rather than string
    formatting. ``ALTER ROLE`` takes no bind parameters, so a password containing
    a quote would otherwise be a syntax error at best and a statement boundary at
    worst — in a function whose entire job is handing out credentials.
    """
    from psycopg import sql

    src = os.environ if env is None else env
    changed: list[str] = []
    for process in PROCESSES:
        password = _password_for(process, src, credentials_dir)
        if password is None:
            continue
        role = login_role(process)
        statement = sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {}").format(
            sql.Identifier(role), sql.Literal(password)
        )
        with conn.cursor() as cur:
            cur.execute(statement)
        changed.append(role)
    return changed


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Connects with ``DATABASE_URL`` — the owner connection."""
    import psycopg

    args = list(sys.argv[1:] if argv is None else argv)
    owner_url = os.environ.get("DATABASE_URL")
    if not owner_url:
        print(
            "DATABASE_URL is not set. This step runs as the schema owner "
            "(the same identity that runs `alembic upgrade head`), not as any "
            "of the per-process login roles it is about to configure.",
            file=sys.stderr,
        )
        return 2

    missing = [password_var(p) for p in PROCESSES if _password_for(p, os.environ, None) is None]
    if missing and "--partial" not in args:
        print(
            "no password supplied for: "
            + ", ".join(missing)
            + "\nEach login role needs one, or it cannot authenticate at all "
            "(PASSWORD NULL refuses every password-authenticated connection). "
            "Pass --partial to configure only the roles you do have passwords "
            "for — useful when rotating one credential, wrong as a deploy step.",
            file=sys.stderr,
        )
        return 2

    with psycopg.connect(psycopg_dsn(owner_url), autocommit=False) as conn:
        changed = provision(conn)
        conn.commit()

    if not changed:
        print("nothing to do: no passwords supplied", file=sys.stderr)
        return 1
    print("configured: " + ", ".join(changed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
