"""TZ 3.5, first bullet — «увидели ваш перевод», and the flag that keeps it once.

The renderer for ``payment_seen`` shipped in Week 4 and nothing wrote the row it
renders, so the message did not exist: the first thing a buyer heard after
sending money was «оплачено», minutes later. These tests pin the two halves of
the fix.

**The message is written at all**, for every payment that has arrived and
belongs to somebody — including the payment that is detected and credited inside
one settler transaction, which never exists in the ``seen`` status for anything
outside that transaction to observe. That case is not exotic; it is the normal
path for a small payment on a chain whose confirmation requirement is already
satisfied at detection, and a naive implementation keyed on ``status = 'seen'``
drops the message for exactly the buyers whose payment went best.

**And it is written once.** The settler is a five-second poll loop. The dedup
index on ``notifications`` would already absorb a second insert, so the property
under test here is stronger than "no duplicate row": it is that the second pass
does not *attempt* the insert — ``test_a_second_pass_does_not_even_try`` asserts
on the query result, not on the row count, because a suite that only counts rows
passes just as green against an implementation that fires a constraint violation
per payment per five seconds forever.

Real Postgres, real migrations, no mocks: the claim is a compare-and-set rowcount
and a partial index predicate, and neither exists anywhere else.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from core.db import enums as E
from notifier.render import render
from settler import repository as repo
from settler.policy import Outcome
from settler.service import (
    ANNOUNCEABLE_PAYMENT_STATUSES,
    CREDITABLE_ANOMALIES,
    Settler,
    handle_reorg,
    notify_seen_payments,
    settle_invoice,
)
from settler.tests.conftest import World, count, payment_status

USDC = 1_000_000


async def _notifications(conn: AsyncConnection, kind: str = "payment_seen") -> list[Any]:
    rows = await conn.execute(
        sa.text(
            """
            SELECT id, user_id, kind, ref_id, dedup_key, payload_json, status
              FROM notifications
             WHERE kind = :kind
             ORDER BY id
            """
        ),
        {"kind": kind},
    )
    return [dict(r) for r in rows.mappings().all()]


async def _seen_notified_at(conn: AsyncConnection, payment_id: int) -> dt.datetime | None:
    row = await conn.execute(
        sa.text("SELECT seen_notified_at FROM payments WHERE id = :id"), {"id": payment_id}
    )
    value = row.scalar_one()
    return None if value is None else value


async def _outstanding(conn: AsyncConnection) -> list[repo.SeenPaymentRow]:
    """What the settler's next pass would even consider announcing."""
    return await repo.unnotified_seen_payments(
        conn,
        statuses=ANNOUNCEABLE_PAYMENT_STATUSES,
        notifiable_anomalies=CREDITABLE_ANOMALIES,
    )


# ---------------------------------------------------------------------------
# The message exists
# ---------------------------------------------------------------------------


async def test_a_new_payment_earns_exactly_one_payment_seen(
    conn: AsyncConnection, world: World
) -> None:
    """"«увидели ваш перевод» — сразу после появления транзакции в блоке" (TZ 3.5).

    Before confirmations, before any money decision: the payment is ``seen``,
    nothing has been settled, and the buyer is already being told.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    payment_id = await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        # Above the creditable cutoff (head 100, three confirmations), so this
        # payment is emphatically *not* settleable yet. The announcement does not
        # wait for it to become so.
        block_number=100,
    )

    notified = await notify_seen_payments(conn)

    assert len(notified) == 1
    rows = await _notifications(conn)
    assert len(rows) == 1
    row = rows[0]
    assert row["user_id"] == s.user_id
    assert row["ref_id"] == str(s.invoice_id)
    assert row["dedup_key"] == str(payment_id)
    assert row["status"] == str(E.NotificationStatus.QUEUED)
    # Nothing was settled. The message is about arrival, not about a decision.
    assert await count(conn, "entitlements") == 0
    assert await count(conn, "invoices", "status = 'awaiting'") == 1


async def test_the_payload_is_what_the_notifier_can_render(
    conn: AsyncConnection, world: World
) -> None:
    """The outbox contract, checked against the real renderer rather than described.

    :mod:`notifier.render` treats a missing payload key as a permanent failure
    that lands the row in the DLQ — deliberately, because a message about money
    with a blank in it is worse than no message. So the only honest test of "the
    settler writes what the notifier needs" is to hand the row to the notifier.
    The two packages share an interpreter in this suite precisely so a
    disagreement about the outbox fails in one run.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    payment_id = await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=4 * USDC,
        block_number=97,
    )

    await notify_seen_payments(conn)

    payload = (await _notifications(conn))[0]["payload_json"]
    assert payload["invoice_id"] == str(s.invoice_id)
    assert payload["payment_id"] == payment_id
    assert payload["asset"] == "USDC"
    assert payload["decimals"] == 6
    assert payload["amount_raw"] == str(4 * USDC)
    assert payload["block_number"] == 97

    rendered = render("payment_seen", payload)
    assert str(s.invoice_id) in rendered.text
    # Not a correction of an earlier message — this is the first thing the buyer
    # hears, so there is nothing on screen to edit.
    assert rendered.edits_kind is None


async def test_a_payment_credited_on_sight_is_still_announced(
    conn: AsyncConnection, world: World
) -> None:
    """The rare-but-real case: zero wait between detection and credit.

    ``min_confirmations = 1`` with the payment already at the head, and a value
    below ``credit_threshold_usd`` so finality is not required — the payment goes
    ``seen -> confirmed -> credited`` inside :func:`settle_invoice`'s single
    transaction and is never observable as ``seen`` by any other reader. TZ 3.5
    still owes this buyer «увидели ваш перевод»; an implementation keyed on
    ``status = 'seen'`` would find nothing here and send only «оплачено».

    Announcing after the fact is the worst ordering this can produce, and it is
    the ordering this test deliberately creates by settling first. In production
    :func:`settler.main.run_once` runs the announcement pass ahead of settlement
    so both land in the outbox in reading order; that the message survives even
    the reversed order is what makes the flag, not the status, the right key.
    """
    s = await world.scenario(
        amount_due_raw=10 * USDC, min_confirmations=1, credit_threshold_usd=1000
    )
    payment_id = await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=s.head_block,
    )

    settlement = await settle_invoice(conn, s.invoice_id)
    assert settlement.outcome is Outcome.PAID
    assert settlement.granted
    # The premise of the test: this payment was never `seen` to anyone else.
    assert await payment_status(conn, payment_id) == str(E.PaymentStatus.CREDITED)

    notified = await notify_seen_payments(conn)

    assert len(notified) == 1
    assert (await _notifications(conn))[0]["dedup_key"] == str(payment_id)


async def test_each_transfer_of_a_split_payment_is_announced_separately(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 5.3 — "пользователь может отправить двумя переводами".

    Two transfers, two arrivals, two messages. ``dedup_key`` is the payment id
    rather than the invoice id for this reason: keying on the invoice would
    silence every announcement after the first, and the buyer who tops up after
    an underpayment would send money into silence.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    first = await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=6 * USDC,
        block_number=99,
    )

    assert len(await notify_seen_payments(conn)) == 1

    second = await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=4 * USDC,
        block_number=100,
    )

    assert len(await notify_seen_payments(conn)) == 1

    rows = await _notifications(conn)
    assert [r["dedup_key"] for r in rows] == [str(first), str(second)]
    assert {r["ref_id"] for r in rows} == {str(s.invoice_id)}


# ---------------------------------------------------------------------------
# And it is written once
# ---------------------------------------------------------------------------


async def test_a_second_pass_does_not_even_try(conn: AsyncConnection, world: World) -> None:
    """The reason migration 0005 adds a column instead of trusting the index.

    ``UNIQUE (kind, ref_id, dedup_key)`` would already keep the outbox clean, so
    counting rows proves nothing about the property that matters: a five-second
    poll loop must not re-attempt an insert per payment per pass for the life of
    the system. The assertion is therefore on the *candidate query* — after the
    first pass the payment is not selected at all, which is the only version of
    "does not duplicate" that also means "does no work".
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    payment_id = await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=99,
    )

    assert len(await _outstanding(conn)) == 1
    assert len(await notify_seen_payments(conn)) == 1

    stamped = await _seen_notified_at(conn, payment_id)
    assert stamped is not None

    # Four more passes, the way the loop would run them.
    for _ in range(4):
        assert await _outstanding(conn) == []
        assert await notify_seen_payments(conn) == ()

    assert await count(conn, "notifications", "kind = 'payment_seen'") == 1
    # The claim is stamped once and never re-stamped: the CAS in
    # `SQL_MARK_PAYMENT_SEEN_NOTIFIED` refuses a row that already has a value,
    # so the timestamp still records the first announcement.
    assert await _seen_notified_at(conn, payment_id) == stamped


async def test_the_promotion_to_confirmed_does_not_re_announce(
    conn: AsyncConnection, world: World
) -> None:
    """A payment moving ``seen -> confirmed -> credited`` is still one arrival.

    The status changes three times on the way to a grant and the announcement is
    keyed on none of them. Without the flag, a query over "seen, confirmed,
    credited" would announce the same transfer again at every promotion.
    """
    s = await world.scenario(amount_due_raw=10 * USDC, min_confirmations=1)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    assert len(await notify_seen_payments(conn)) == 1

    settlement = await settle_invoice(conn, s.invoice_id)
    assert settlement.granted

    assert await notify_seen_payments(conn) == ()
    assert await count(conn, "notifications", "kind = 'payment_seen'") == 1
    assert await count(conn, "notifications", "kind = 'invoice_settled'") == 1


async def test_two_workers_on_one_payment_announce_once(engine: AsyncEngine) -> None:
    """TZ 5.8/T2.2 through the announcement path.

    Two settler processes on separate connections, same unannounced payment. The
    CAS on ``seen_notified_at`` is what decides: the loser's UPDATE reports zero
    affected rows after blocking on the winner's row lock, and it exits without
    enqueuing. Committed setup for the same reason
    ``test_concurrency.py::a_fully_paid_invoice`` commits its own — a second
    connection cannot see an open transaction's rows.
    """
    async with engine.begin() as conn:
        world = World(conn)
        s = await world.scenario(amount_due_raw=10 * USDC)
        payment_id = await world.payment(
            chain_id=s.chain_id,
            asset_id=s.asset_id,
            address_id=s.address_id,
            invoice_id=s.invoice_id,
            amount_raw=10 * USDC,
            block_number=99,
        )

    settler = Settler(engine)
    results = await asyncio.gather(settler.notify_seen(), settler.notify_seen())

    assert sorted(len(r) for r in results) == [0, 1]
    async with engine.connect() as conn:
        assert await count(conn, "notifications", "kind = 'payment_seen'") == 1
        assert await count(
            conn, "notifications", "dedup_key = :key", key=str(payment_id)
        ) == 1


# ---------------------------------------------------------------------------
# What is deliberately not announced
# ---------------------------------------------------------------------------


async def test_money_that_will_never_be_credited_is_not_announced(
    conn: AsyncConnection, world: World
) -> None:
    """A ``wrong_asset`` transfer gets a human, not a reassurance (TZ 5.5).

    "We can see your transfer and are waiting for it to confirm" is a promise
    that the money is on its way to buying something. For an anomaly that is
    never summed into the bill it is a promise the settler is about to break,
    and the buyer would learn the truth only from the manual-review outcome.
    Silence here is not an omission; it is the correct message being sent by a
    different path.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    other_asset = await world.asset(s.chain_id, symbol="USDT", decimals=6)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=other_asset,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=99,
        anomaly=E.PaymentAnomaly.WRONG_ASSET,
    )

    assert await notify_seen_payments(conn) == ()
    assert await count(conn, "notifications", "kind = 'payment_seen'") == 0


async def test_a_late_payment_is_announced(conn: AsyncConnection, world: World) -> None:
    """The one creditable anomaly (TZ 5.5, "Платёж пришёл после истечения инвойса").

    A late transfer inside the top-up window still counts towards the bill, so
    the buyer is owed the same acknowledgement as an on-time one. The anomaly
    filter is an allow-list of exactly this case rather than a blanket "no
    anomalies", which would have swept it up with the others.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=99,
        anomaly=E.PaymentAnomaly.LATE,
    )

    assert len(await notify_seen_payments(conn)) == 1


async def test_dust_is_not_announced(conn: AsyncConnection, world: World) -> None:
    """``ignored_dust`` has nothing to confirm and nothing to wait for."""
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=1,
        block_number=99,
        status=E.PaymentStatus.IGNORED_DUST,
        anomaly=E.PaymentAnomaly.DUST,
    )

    assert await notify_seen_payments(conn) == ()


async def test_a_payment_reorged_out_before_the_pass_is_never_announced(
    conn: AsyncConnection, world: World
) -> None:
    """Ordering inside :func:`settler.main.run_once`, asserted rather than assumed.

    The reorg pass runs first, so by the time the announcement pass looks, a
    payment whose block was orphaned is already ``reverted`` — and telling
    somebody "we can see your transfer" about money that no longer exists is the
    one message this feature must never send.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.block(s.chain_id, 90, status=E.BlockStatus.CONFIRMED)
    payment_id = await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )
    await world.orphan_block(s.chain_id, 90)

    reorg = await handle_reorg(conn, s.chain_id)
    assert payment_id in reorg.reverted_payment_ids

    assert await notify_seen_payments(conn) == ()
    assert await count(conn, "notifications", "kind = 'payment_seen'") == 0
    assert await _seen_notified_at(conn, payment_id) is None


async def test_an_unassigned_payment_has_nobody_to_tell(
    conn: AsyncConnection, world: World
) -> None:
    """Money on one of our addresses with no invoice behind it (TZ 5.5).

    There is no ``user_id`` to address a message to — that is what "unassigned"
    means — so this goes to the owner through ``review_anomalous_payments``. The
    ``invoice_id IS NOT NULL`` predicate is in the index as well as the query so
    these rows do not accumulate in the announcement scan set.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=None,
        amount_raw=3 * USDC,
        block_number=99,
        anomaly=E.PaymentAnomaly.UNASSIGNED_PAYMENT,
    )

    assert await notify_seen_payments(conn) == ()


# ---------------------------------------------------------------------------
# Regression guard on the outbox as a whole
# ---------------------------------------------------------------------------


async def test_the_announcement_does_not_disturb_the_settlement_outbox(
    conn: AsyncConnection, world: World
) -> None:
    """A full happy path: one arrival message, one settlement message, in order.

    The settlement notifications carry their own dedup keys (the entitlement id)
    and the announcement carries the payment id, so the two cannot collide even
    though they share ``ref_id``. Asserted because they do share it: ``ref_id``
    is the invoice for every user-facing message, which is what lets the notifier
    find an earlier message to edit (TZ 5.5).
    """
    s = await world.scenario(amount_due_raw=10 * USDC, min_confirmations=1)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=95,
    )

    await notify_seen_payments(conn)
    await settle_invoice(conn, s.invoice_id)

    rows = await conn.execute(
        sa.text("SELECT kind FROM notifications WHERE ref_id = :ref ORDER BY id"),
        {"ref": str(s.invoice_id)},
    )
    assert [r[0] for r in rows.all()] == ["payment_seen", "invoice_settled"]


async def test_an_invoice_with_no_payments_produces_nothing(
    conn: AsyncConnection, world: World
) -> None:
    """The empty case, so a green suite is not an artefact of always having a row."""
    await world.scenario(amount_due_raw=10 * USDC)
    assert await notify_seen_payments(conn) == ()
    assert await count(conn, "notifications") == 0


async def test_the_limit_is_honoured(conn: AsyncConnection, world: World) -> None:
    """Same shape as every other sweep: a bounded batch, the rest next pass.

    An unbounded pass over a backlog — which is exactly what the first pass after
    migration 0005 is, since every existing payment starts unannounced — would
    hold one transaction open across the whole table.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    for block in range(90, 95):
        await world.payment(
            chain_id=s.chain_id,
            asset_id=s.asset_id,
            address_id=s.address_id,
            invoice_id=s.invoice_id,
            amount_raw=USDC,
            block_number=block,
        )

    assert len(await notify_seen_payments(conn, limit=2)) == 2
    assert len(await notify_seen_payments(conn, limit=2)) == 2
    assert len(await notify_seen_payments(conn, limit=2)) == 1
    assert await notify_seen_payments(conn, limit=2) == ()


async def test_a_missing_invoice_cannot_produce_a_message(
    conn: AsyncConnection, world: World
) -> None:
    """The join is inner, and the failure mode it rules out is worth naming.

    ``invoices.user_id`` is NOT NULL behind a RESTRICT foreign key, so a payment
    with an ``invoice_id`` always has a user. An outer join would turn a broken
    key into a NULL recipient instead of no row — a message queued to nobody,
    discovered in the DLQ. There is no way to build the broken state through the
    schema, which is the point; this asserts the query does not invent one.
    """
    s = await world.scenario(amount_due_raw=10 * USDC)
    await world.payment(
        chain_id=s.chain_id,
        asset_id=s.asset_id,
        address_id=s.address_id,
        invoice_id=s.invoice_id,
        amount_raw=10 * USDC,
        block_number=99,
    )

    rows = await _outstanding(conn)
    assert len(rows) == 1
    assert rows[0].user_id == s.user_id
    assert isinstance(rows[0].invoice_id, uuid.UUID)
