"""The notifier under its own PostgreSQL role (migrations 0002 and 0004).

Same argument as ``settler/tests/test_grants.py``: the process separation of TZ
section 4 is decorative unless the grants back it, and grants drift quietly. Two
directions, both necessary.

**Sufficient** — one complete delivery cycle runs as ``notchstave_notifier`` and
succeeds. This is the failure mode nobody notices until deploy: a privilege the
code needs and the matrix forgot.

**Necessary** — the writes this process must never have are attempted and must
fail. The notifier is the one component in the system whose job is to talk to a
third-party API over the internet, which makes it the most plausible thing here
to be compromised, and what it can reach on that day is decided entirely by
these grants. Three matter most:

* no INSERT on ``notifications`` — a notifier able to enqueue is a notifier able
  to deliver a message about a grant that never happened (TZ 5.7);
* no write of any kind on ``entitlements`` — one writer, forever (migration
  0003, TZ 5.8/T2). This is what makes TZ 5.7's ordering structural rather than
  conventional: delivery cannot affect access, so "message after the grant" is
  the only arrangement the privileges permit;
* no UPDATE of ``users.internal_balance_usd`` — migration 0002 gave the notifier
  table-level UPDATE on ``users`` for the single purpose of setting
  ``bot_blocked_at``, which also handed it the overpayment credit of TZ 5.5.
  Migration 0004 narrows it to one column, and the parametrised cases below are
  what stop it being widened back.

``SET LOCAL ROLE`` rather than six logins: the roles are ``NOLOGIN`` on purpose,
and a test needing passwords for all of them is a test nobody runs.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from notifier import repository
from notifier.tests.conftest import Outbox

NOTIFIER_ROLE = "notchstave_notifier"


@pytest.fixture
async def as_notifier(engine: AsyncEngine) -> AsyncGenerator[AsyncConnection, None]:
    """A connection that has dropped to the notifier's privileges.

    Skips rather than fails where migration 0002 could not create the roles —
    that is a cluster-level operation and 0002 degrades to a NOTICE on a managed
    database, where a red suite would be reporting the wrong problem.
    """
    async with engine.begin() as conn:
        exists = (
            await conn.execute(
                sa.text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": NOTIFIER_ROLE}
            )
        ).scalar_one_or_none()
        if not exists:
            pytest.skip(f"{NOTIFIER_ROLE} does not exist; migration 0002 had no CREATEROLE")
        await conn.execute(sa.text(f"SET LOCAL ROLE {NOTIFIER_ROLE}"))
        try:
            yield conn
        finally:
            await conn.execute(sa.text("RESET ROLE"))


async def test_a_full_delivery_cycle_fits_inside_the_grants(
    outbox: Outbox, as_notifier: AsyncConnection
) -> None:
    """Sufficient: claim, complete, retry, retire, audit and read back.

    One pass over every statement in :mod:`notifier.repository` that the happy
    path and both failure paths use, under the real role. Add a column or a
    joined table to any of them and the missing GRANT surfaces here, in CI,
    rather than on the server.
    """
    user_id = await outbox.user()
    first = await outbox.enqueue(user_id=user_id, ref_id="inv-1", dedup_key="a")
    second = await outbox.enqueue(user_id=user_id, ref_id="inv-1", dedup_key="b")
    third = await outbox.enqueue(user_id=user_id, ref_id="inv-1", dedup_key="c")

    claimed = await repository.claim_batch(as_notifier, limit=10, lease_seconds=60)
    assert {c.id for c in claimed} == {first, second, third}
    by_id = {c.id: c for c in claimed}

    assert await repository.mark_sent(
        as_notifier, notification_id=first, attempts=by_id[first].attempts, message_id=1
    )
    assert await repository.schedule_retry(
        as_notifier,
        notification_id=second,
        attempts=by_id[second].attempts,
        delay_seconds=30,
        last_error="telegram 502",
    )
    assert await repository.mark_dead(
        as_notifier, notification_id=third, last_error="retries_exhausted"
    )
    await repository.record_audit(
        as_notifier, action="notifier_dlq", target_id=str(third), args={"kind": "test"}
    )

    assert await repository.dlq_size(as_notifier) == 1
    assert (
        await repository.find_message_id(
            as_notifier, user_id=user_id, kind="invoice_settled", ref_id="inv-1"
        )
        == 1
    )


async def test_the_notifier_may_mark_a_user_blocked_and_retire_their_queue(
    outbox: Outbox, as_notifier: AsyncConnection
) -> None:
    """Both halves of TZ 5.5's "помечаем и прекращаем слать", under the real role.

    The column-scoped grant of migration 0004 has to be wide enough to do the
    job it was narrowed for; a REVOKE that also broke the feature would be
    caught here rather than the first time a buyer blocks the bot.
    """
    user_id = await outbox.user()
    await outbox.enqueue(user_id=user_id, dedup_key="a")
    await outbox.enqueue(user_id=user_id, dedup_key="b")

    assert await repository.block_user(as_notifier, user_id=user_id) is True
    assert await repository.retire_blocked_user(as_notifier, user_id=user_id) == 2
    # Idempotent: the second call finds the flag already set and keeps the
    # original timestamp.
    assert await repository.block_user(as_notifier, user_id=user_id) is False


@pytest.mark.parametrize(
    ("statement", "why"),
    [
        (
            "INSERT INTO notifications (user_id, kind, ref_id, dedup_key, status) "
            "VALUES (1, 'invented', 'x', 'y', 'queued')",
            "TZ 5.7 — the notifier drains the outbox, it does not write it",
        ),
        (
            "DELETE FROM notifications",
            "a message never sent must still be there tomorrow; so must one that was",
        ),
        (
            "UPDATE users SET internal_balance_usd = 999",
            "migration 0004 — the overpayment credit of TZ 5.5 is real money",
        ),
        (
            "UPDATE users SET tg_id = 1",
            "reassigning an account would redirect every future receipt",
        ),
        (
            "UPDATE users SET lang = 'ru'",
            "0004 grants one column, not the table",
        ),
        (
            "UPDATE entitlements SET revoked_at = now()",
            "TZ 5.8/T2 — one writer for access, and delivery is not it",
        ),
        (
            "DELETE FROM entitlements",
            "a grant is revoked, never deleted, and never by this process",
        ),
        (
            "UPDATE invoices SET status = 'paid'",
            "TZ section 4 — the notifier takes no decisions about money",
        ),
        (
            "UPDATE payments SET amount_raw = 1",
            "same rule, on the table where the money actually is",
        ),
        (
            "UPDATE audit_log SET action = 'nothing happened'",
            "TZ 5.8/T7, T8 — decisions cannot be edited after the fact",
        ),
        ("DELETE FROM audit_log", "append-only means append-only"),
        (
            "SELECT sku FROM products",
            "no grant at all: renderers use payload_json, which is why the "
            "settler writes user-facing facts into the outbox row",
        ),
        (
            "UPDATE receive_addresses SET status = 'free'",
            "TZ 5.8/T1.2 — only the deriver writes the address pool",
        ),
        (
            "SELECT count(*) FROM manual_reviews",
            "open cases are the owner's view, not the delivery process's",
        ),
    ],
)
async def test_the_notifier_role_is_refused_what_it_must_not_have(
    outbox: Outbox, as_notifier: AsyncConnection, statement: str, why: str
) -> None:
    await outbox.user()

    with pytest.raises(sa.exc.ProgrammingError) as caught:
        async with as_notifier.begin_nested():
            await as_notifier.execute(sa.text(statement))
    assert "permission denied" in str(caught.value).lower(), why
