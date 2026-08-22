"""TZ 5.8/T1.3 at the settlement checkpoint: a tampered row is never credited.

The attack this file exists to make impossible, in three statements against a
real Postgres:

    UPDATE invoices SET amount_due_raw = 1 WHERE id = ...;   -- attacker
    INSERT INTO payments (... amount_raw = 1 ...);            -- attacker pays
    settle_invoice(...)                                       -- product granted?

Before the check landed, the answer was yes. The two Week-5 checkpoints — the
bot before it shows an address, the api before it renders the invoice page —
cannot see this at all: neither of them is in the flow. The attacker is not the
paying buyer and never opens the page. The settler is the only process that
compares "what is owed" with "what arrived", so the settler is the only place
this comparison can be defended.

Every invoice these tests use carries a **real** MAC, computed by
``World.invoice`` under ``settler.tests.conftest.TEST_INTEGRITY_KEY``. That is
the load-bearing half of the fixture change that came with this file: while the
builder wrote 32 bytes of ``0xab``, no test in this suite could have caught a
settler that skipped the check, because there was no invoice in the suite whose
MAC would have verified either way.
"""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

from core.db import enums as E
from core.invoicing.integrity import compute_mac
from settler import metrics
from settler.policy import Outcome
from settler.service import settle_invoice
from settler.tests.conftest import TEST_INTEGRITY_KEY, World


def counter_value(metric: object) -> float:
    """Current value of an unlabelled Prometheus counter, read through ``collect()``.

    Deltas only. The collectors are process-global and this suite shares an
    interpreter with four others, so an absolute assertion would depend on test
    ordering.
    """
    for family in metric.collect():  # type: ignore[attr-defined]
        for sample in family.samples:
            if sample.name.endswith("_total") and not sample.labels:
                return float(sample.value)
    return 0.0


async def _reviews(conn: AsyncConnection, invoice_id: uuid.UUID) -> list[str]:
    rows = await conn.execute(
        sa.text(
            "SELECT kind::text FROM manual_reviews "
            " WHERE invoice_id = :id ORDER BY id"
        ),
        {"id": invoice_id},
    )
    return [r[0] for r in rows.all()]


async def _audit_actions(conn: AsyncConnection, invoice_id: uuid.UUID) -> list[str]:
    rows = await conn.execute(
        sa.text(
            "SELECT action FROM audit_log "
            " WHERE target_kind = 'invoice' AND target_id = :id ORDER BY id"
        ),
        {"id": str(invoice_id)},
    )
    return [r[0] for r in rows.all()]


async def _invoice_status(conn: AsyncConnection, invoice_id: uuid.UUID) -> str:
    return str(
        (
            await conn.execute(
                sa.text("SELECT status::text FROM invoices WHERE id = :id"),
                {"id": invoice_id},
            )
        ).scalar_one()
    )


async def _entitlement_count(conn: AsyncConnection, invoice_id: uuid.UUID) -> int:
    return int(
        (
            await conn.execute(
                sa.text("SELECT count(*) FROM entitlements WHERE invoice_id = :id"),
                {"id": invoice_id},
            )
        ).scalar_one()
    )


# ---------------------------------------------------------------------------
# The attack
# ---------------------------------------------------------------------------


async def test_rewriting_amount_due_in_the_database_does_not_buy_the_product(
    conn: AsyncConnection, world: World
) -> None:
    """S-C2, the whole finding in one test.

    The bill is 10 USDC. The attacker rewrites it to one base unit, pays one
    base unit, and asks for the goods. The settler must refuse — and refuse for
    the *right* reason: not "underpaid" (which a top-up could later satisfy) but
    "this row does not authenticate".
    """
    s = await world.scenario(amount_due_raw=10_000_000)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=1,
        block_number=90,
    )

    await conn.execute(
        sa.text("UPDATE invoices SET amount_due_raw = 1 WHERE id = :id"),
        {"id": s.invoice_id},
    )

    before = counter_value(metrics.MAC_FAILURES)
    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.INTEGRITY_FAILED
    assert not result.granted
    assert await _entitlement_count(conn, s.invoice_id) == 0
    # Not `paid`, and equally not left `awaiting` for the next pass to try again.
    assert await _invoice_status(conn, s.invoice_id) == str(E.InvoiceStatus.MANUAL_REVIEW)
    assert str(E.ManualReviewKind.MAC_FAILURE) in await _reviews(conn, s.invoice_id)
    assert "settle.integrity_mac_failed" in await _audit_actions(conn, s.invoice_id)
    assert counter_value(metrics.MAC_FAILURES) - before == 1


async def test_the_same_invoice_untouched_still_settles(
    conn: AsyncConnection, world: World
) -> None:
    """The control. Without it the test above passes on a settler that refuses
    everything, which is not the property anybody wants."""
    s = await world.scenario(amount_due_raw=10_000_000)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10_000_000,
        block_number=90,
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.PAID
    assert result.granted
    assert await _reviews(conn, s.invoice_id) == []


async def test_rewriting_the_receive_address_is_caught_too(
    conn: AsyncConnection, world: World
) -> None:
    """The address is under the MAC as well (TZ 5.8/T1.3).

    The settler cannot re-derive it — no xpub, by construction, the same
    position ``core.invoicing.service.MacOnly`` describes for the api. So the
    MAC is the entire defence here, and it covers the case where an attacker
    repoints a live invoice at an address they control in the hope that the
    watcher starts crediting payments to it.
    """
    s = await world.scenario(amount_due_raw=10_000_000)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10_000_000,
        block_number=90,
    )
    await conn.execute(
        sa.text("UPDATE receive_addresses SET address = :address WHERE id = :id"),
        {"address": "0x" + "ab" * 20, "id": s.address_id},
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.INTEGRITY_FAILED
    assert await _entitlement_count(conn, s.invoice_id) == 0


async def test_moving_the_deadline_is_caught_too(
    conn: AsyncConnection, world: World
) -> None:
    """``expires_at`` is the sixth field of the tuple.

    Not a money field at first glance, and exactly why it is in the MAC: moving
    it forward turns an invoice that should have expired into one that is still
    live, which is how a stale quote gets paid at a price the market has left
    behind (TZ 5.5, rate table).
    """
    s = await world.scenario(amount_due_raw=10_000_000)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10_000_000,
        block_number=90,
    )
    await conn.execute(
        sa.text(
            "UPDATE invoices "
            "   SET expires_at = expires_at + interval '1 hour', "
            "       topup_window_until = topup_window_until + interval '1 hour' "
            " WHERE id = :id"
        ),
        {"id": s.invoice_id},
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.INTEGRITY_FAILED


async def test_an_attacker_who_also_rewrites_the_mac_still_fails(
    conn: AsyncConnection, world: World
) -> None:
    """The key is not in the database, so a matching MAC cannot be produced.

    This is the sentence the whole countermeasure rests on and it deserves an
    executable version rather than a docstring: the attacker recomputes the MAC
    with a key of their own over the amount they want, writes both, and the
    settler still refuses.
    """
    s = await world.scenario(amount_due_raw=10_000_000)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=1,
        block_number=90,
    )

    expires_at = (
        await conn.execute(
            sa.text("SELECT expires_at FROM invoices WHERE id = :id"), {"id": s.invoice_id}
        )
    ).scalar_one()
    from core.invoicing.integrity import IntegrityKey

    forged = compute_mac(
        IntegrityKey("an-attacker-key-that-is-long-enough"),
        invoice_id=s.invoice_id,
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address=s.address,
        amount_due_raw=Decimal(1),
        expires_at=expires_at,
    )
    await conn.execute(
        sa.text(
            "UPDATE invoices SET amount_due_raw = 1, integrity_mac = :mac WHERE id = :id"
        ),
        {"mac": forged, "id": s.invoice_id},
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.INTEGRITY_FAILED
    assert await _entitlement_count(conn, s.invoice_id) == 0


# ---------------------------------------------------------------------------
# Behaviour around the refusal
# ---------------------------------------------------------------------------


async def test_a_tampered_invoice_is_not_re_reviewed_on_every_pass(
    conn: AsyncConnection, world: World
) -> None:
    """One case per invoice, not one per settler tick.

    The settler polls. A refusal that opened a fresh manual review each time
    would bury the operator under copies of one incident within a minute of it
    happening, which is a denial of service against the person who has to answer
    it.
    """
    s = await world.scenario(amount_due_raw=10_000_000)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=1,
        block_number=90,
    )
    await conn.execute(
        sa.text("UPDATE invoices SET amount_due_raw = 1 WHERE id = :id"), {"id": s.invoice_id}
    )

    first = await settle_invoice(conn, s.invoice_id)
    second = await settle_invoice(conn, s.invoice_id)

    assert first.outcome is second.outcome is Outcome.INTEGRITY_FAILED
    assert await _reviews(conn, s.invoice_id) == [str(E.ManualReviewKind.MAC_FAILURE)]


async def test_editing_an_already_settled_invoice_is_reported_and_changes_nothing(
    conn: AsyncConnection, world: World
) -> None:
    """A terminal invoice keeps its status; the incident is still recorded.

    Revoking a grant that was correct when it was made, on the strength of a row
    that has just been shown to be untrustworthy, would be a second money
    decision taken from the same bad data. The case and the audit row are what a
    human acts on.
    """
    s = await world.scenario(amount_due_raw=10_000_000)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10_000_000,
        block_number=90,
    )
    settled = await settle_invoice(conn, s.invoice_id)
    assert settled.granted

    await conn.execute(
        sa.text("UPDATE invoices SET amount_due_raw = 1 WHERE id = :id"), {"id": s.invoice_id}
    )
    after = await settle_invoice(conn, s.invoice_id)

    assert after.outcome is Outcome.INTEGRITY_FAILED
    assert await _invoice_status(conn, s.invoice_id) == str(E.InvoiceStatus.PAID)
    assert await _entitlement_count(conn, s.invoice_id) == 1
    assert str(E.ManualReviewKind.MAC_FAILURE) in await _reviews(conn, s.invoice_id)


async def test_an_invoice_with_a_late_expiry_edit_is_refused_before_the_amount_is_read(
    conn: AsyncConnection, world: World
) -> None:
    """Ordering: the MAC check runs before the "already settled" shortcut.

    An invoice in a settled status returns early in the normal path. If the MAC
    check sat behind that return, the one class of tamper worth the most —
    editing a row after the money moved — would be the class the check never
    saw.
    """
    s = await world.scenario(amount_due_raw=10_000_000)
    await conn.execute(
        sa.text(
            "UPDATE invoices SET status = 'paid', settled_at = now() WHERE id = :id"
        ),
        {"id": s.invoice_id},
    )
    await conn.execute(
        sa.text("UPDATE invoices SET amount_due_raw = 42 WHERE id = :id"),
        {"id": s.invoice_id},
    )

    result = await settle_invoice(conn, s.invoice_id)

    assert result.outcome is Outcome.INTEGRITY_FAILED


async def test_a_key_that_is_not_the_issuing_key_refuses_everything(
    conn: AsyncConnection, world: World
) -> None:
    """The failure mode of a mis-rotated key, made explicit.

    Handing the settler the wrong key does not degrade quietly into "MAC checks
    are off": it refuses every invoice and fills ``/pending`` with mac_failure
    cases. That is loud, and loud is correct — the alternative is a deployment
    where the key was wrong for a week and nobody found out.
    """
    from core.invoicing.integrity import IntegrityKey

    s = await world.scenario(amount_due_raw=10_000_000)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10_000_000,
        block_number=90,
    )

    result = await settle_invoice(
        conn, s.invoice_id, integrity_key=IntegrityKey("a-different-key-entirely-here")
    )

    assert result.outcome is Outcome.INTEGRITY_FAILED
    assert await _entitlement_count(conn, s.invoice_id) == 0


async def test_the_fixture_key_verifies_what_the_fixture_writes(
    conn: AsyncConnection, world: World
) -> None:
    """A guard on the rig itself.

    If ``World.invoice`` ever goes back to writing a placeholder MAC, every test
    in this file would still pass — they would all be asserting INTEGRITY_FAILED
    for the wrong reason — and the control above would be the only failure. This
    asserts the fixture's own invariant directly so the diagnosis is one line
    instead of a bisect.
    """
    s = await world.scenario(amount_due_raw=7_500_000)
    row = (
        await conn.execute(
            sa.text(
                "SELECT integrity_mac, expires_at FROM invoices WHERE id = :id"
            ),
            {"id": s.invoice_id},
        )
    ).mappings().one()

    expected = compute_mac(
        TEST_INTEGRITY_KEY,
        invoice_id=s.invoice_id,
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address=s.address,
        amount_due_raw=s.amount_due_raw,
        expires_at=row["expires_at"],
    )
    assert bytes(row["integrity_mac"]) == expected
    assert isinstance(row["expires_at"], dt.datetime)
