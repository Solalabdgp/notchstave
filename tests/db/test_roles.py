"""The lookup that decides which identity a process connects as. No database.

``settler/tests/test_login_roles.py`` proves the roles behave correctly once a
process has reached the database. This file proves the step before that: which
URL each process picks up, and — the part that matters — which URL it refuses to
pick up.

The finding these two files answer was not that the grant matrix was wrong. It
was that every process connected with the schema owner's ``DATABASE_URL``, so the
matrix was never consulted. The single most important assertion in this file is
:func:`test_there_is_no_fallback_to_the_owner_url`: with ``DATABASE_URL`` set and
the per-process variable absent, the lookup must raise. A fallback here — even a
loud, logged, "development only" one — would restore the original bug in the one
configuration where it is hardest to notice, which is a deployment that half
works.

No database, no network, no install: this suite runs from a bare checkout.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.db import roles


def test_the_six_processes_are_the_six_of_tz_section_4() -> None:
    assert set(roles.PROCESSES) == {
        "deriver",
        "watcher",
        "settler",
        "notifier",
        "bot",
        "api",
    }


@pytest.mark.parametrize("process", roles.PROCESSES)
def test_the_role_names_match_the_migrations_that_grant_to_them(process: str) -> None:
    """A rename here without a rename there is a role with no privileges.

    Read from the migration text rather than imported: ``migrations/versions`` is
    not an importable package (Alembic loads those files by path), and the point
    of the check is the literal string the SQL grants to.
    """
    versions = Path(__file__).resolve().parents[2] / "migrations" / "versions"
    grants = (versions / "0002_roles_and_grants.py").read_text(encoding="utf-8")
    logins = (versions / "0009_login_roles.py").read_text(encoding="utf-8")

    assert roles.permission_role(process) in grants
    # 0009 builds the names from the same process list, so what this pins is the
    # shape: the login role is the permission role plus a suffix, and neither
    # file can change that convention alone.
    assert roles.login_role(process) == f"{roles.permission_role(process)}_login"
    assert f'"{process}"' in logins or f"'{process}'" in logins


def test_an_unknown_process_is_a_programming_error_not_a_default() -> None:
    for call in (roles.permission_role, roles.login_role, roles.url_var, roles.password_var):
        with pytest.raises(ValueError, match="unknown process"):
            call("scheduler")


@pytest.mark.parametrize("process", roles.PROCESSES)
def test_each_process_reads_its_own_variable(process: str) -> None:
    env = {roles.url_var(p): f"postgresql+psycopg://{p}@db/x" for p in roles.PROCESSES}
    assert roles.process_database_url(process, env=env) == f"postgresql+psycopg://{process}@db/x"


def test_there_is_no_fallback_to_the_owner_url() -> None:
    """The finding, as a unit test.

    ``DATABASE_URL`` is present and points at a working database. That is exactly
    the configuration every deployment had, and it must now be a startup failure
    rather than a silent owner connection.
    """
    env = {"DATABASE_URL": "postgresql+psycopg://notchstave:pw@db/notchstave"}
    with pytest.raises(RuntimeError) as caught:
        roles.process_database_url("settler", env=env)

    message = str(caught.value)
    assert "SETTLER_DATABASE_URL" in message
    # The message has to say why, not just what: an operator who is told a
    # variable is missing and can see DATABASE_URL sitting right there will set
    # the new name to the same value unless the reason is in front of them.
    assert "owner" in message.lower()


def test_blank_is_treated_as_absent() -> None:
    """``FOO=`` in a .env is a variable that exists and says nothing."""
    with pytest.raises(RuntimeError):
        roles.process_database_url("api", env={"API_DATABASE_URL": "   "})


def test_a_credential_file_wins_over_the_environment(tmp_path: Path) -> None:
    """Same precedence as the integrity key, for the same reason.

    Production hands this over as a systemd credential because the URL carries a
    password and an environment variable is readable from ``docker inspect``,
    ``/proc/<pid>/environ`` and a core dump. The file winning is what stops a
    stray env var downgrading a correctly configured unit.
    """
    (tmp_path / roles.credential_name("bot")).write_text(
        "postgresql+psycopg://notchstave_bot_login:filepw@db/notchstave\n", encoding="utf-8"
    )
    resolved = roles.process_database_url(
        "bot",
        env={"BOT_DATABASE_URL": "postgresql+psycopg://notchstave_bot_login:envpw@db/notchstave"},
        credentials_dir=str(tmp_path),
    )
    assert resolved.endswith("filepw@db/notchstave")


def test_an_empty_credential_file_falls_through_rather_than_connecting_as_nobody(
    tmp_path: Path,
) -> None:
    (tmp_path / roles.credential_name("bot")).write_text("\n", encoding="utf-8")
    env = {"BOT_DATABASE_URL": "postgresql+psycopg://notchstave_bot_login:envpw@db/notchstave"}
    assert roles.process_database_url("bot", env=env, credentials_dir=str(tmp_path)).endswith(
        "envpw@db/notchstave"
    )


def test_the_dsn_conversion_only_touches_the_driver_suffix() -> None:
    assert (
        roles.psycopg_dsn("postgresql+psycopg://u:p@h:5432/d")
        == "postgresql://u:p@h:5432/d"
    )
    # A password containing the literal scheme text must not be rewritten: the
    # replacement is bounded to one occurrence, at the front.
    unchanged = "postgresql://u:p@h/d"
    assert roles.psycopg_dsn(unchanged) == unchanged


@pytest.mark.parametrize("process", roles.PROCESSES)
def test_the_password_variable_is_never_the_url_variable(process: str) -> None:
    """A running process gets a URL, and only its own; passwords go to one place.

    ``python -m core.db.roles`` is the only reader of the password variables. The
    separation is what keeps the operator's provisioning shell — the one place all
    six credentials exist at once — from being every process's environment.
    """
    assert roles.password_var(process) != roles.url_var(process)
    assert roles.password_var(process).startswith("NOTCHSTAVE_")
