"""TZ 5.8/T3 — можно ли зачесть один и тот же платёж дважды.

The scenario people usually propose — "two invoices for the same amount, the
handler mixed up the events" — is impossible here by construction, and the
reason is worth a test of its own: **the amount takes no part in matching.** The
key is the address. Two invoices for the same price do not intersect anywhere.

What remains are the four real replay channels of T3, and each gets a test that
tries to perform the replay and is stopped by the database rather than by an
`if` statement:

* **3.1** the same log delivered twice — ``UNIQUE (chain_id, tx_hash,
  log_index)``, plus the ``confirmed -> credited`` compare-and-set;
* **3.2** rebinding a payment to another invoice — the ``BEFORE UPDATE``
  trigger, which no code path in this repository can talk its way past;
* **3.3** a reused address paying its previous tenant's invoice — covered in
  ``test_settlement.py`` where the orphan payment is excluded from the SUM;
* **3.4** cross-chain — the same ``tx_hash`` in another network is a different
  payment, and cannot be summed into an invoice pinned to one chain.

The file closes with the invariant TZ 5.8/T3 says `/reconcile` checks.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

from core.db import enums as E
from settler import repository as repo
from settler.policy import Outcome
from settler.service import settle_invoice
from settler.tests.conftest import World, count, payment_status

USDC = 1_000_000


# ---------------------------------------------------------------------------
# T3.2 — the binding is immutable, and the database is what says so
# ---------------------------------------------------------------------------


async def test_the_database_refuses_to_rebind_a_payment(
    conn: AsyncConnection, world: World
) -> None:
    """"Попытка изменить payments.invoice_id отклоняется триггером БД." (TZ 5.8/T3)

    Note what is being tested: not that the settler declines to rebind — it has
    no function that could — but that a direct UPDATE from a psql prompt is
    refused. "В кодовой базе нет функции, меняющей привязку" is a promise about
    this codebase; the trigger is a promise about the data.
    """
    first = await world.scenario(amount_due_raw=10 * USDC)
    second = await world.scenario(amount_due_raw=10 * USDC)
    payment_id = await world.payment(
        chain_id=first.chain_id,
        asset_id=first.asset_id,
        address_id=first.address_id,
        invoice_id=first.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    with pytest.raises(sa.exc.IntegrityError, match="immutable"):
        async with conn.begin_nested():
            await conn.execute(
                sa.text("UPDATE payments SET invoice_id = :new WHERE id = :id"),
                {"new": second.invoice_id, "id": payment_id},
            )

    bound_to = (
        await conn.execute(
            sa.text("SELECT invoice_id FROM payments WHERE id = :id"), {"id": payment_id}
        )
    ).scalar_one()
    assert bound_to == first.invoice_id


async def test_unbinding_a_payment_is_refused_too(
    conn: AsyncConnection, world: World
) -> None:
    """Setting the column to NULL is a rebind with extra steps.

    Worth its own test because ``IS DISTINCT FROM`` is what makes it fail, and a
    naive ``!=`` in the trigger would let NULL through — leaving a payment that
    can then be bound to anything at all.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    payment_id = await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    with pytest.raises(sa.exc.IntegrityError, match="immutable"):
        async with conn.begin_nested():
            await conn.execute(
                sa.text("UPDATE payments SET invoice_id = NULL WHERE id = :id"),
                {"id": payment_id},
            )


async def test_binding_a_payment_that_had_no_invoice_is_allowed(
    conn: AsyncConnection, world: World
) -> None:
    """The trigger guards a *change*, not the first write.

    An ``unassigned_payment`` that a human later attaches to the right invoice
    must remain possible — the rule is "written once", not "never written".
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    payment_id = await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=None,
        amount_raw=10 * USDC,
        block_number=90,
        anomaly=E.PaymentAnomaly.UNASSIGNED_PAYMENT,
    )

    await conn.execute(
        sa.text("UPDATE payments SET invoice_id = :id WHERE id = :pid"),
        {"id": scenario.invoice_id, "pid": payment_id},
    )

    bound = (
        await conn.execute(
            sa.text("SELECT invoice_id FROM payments WHERE id = :id"), {"id": payment_id}
        )
    ).scalar_one()
    assert bound == scenario.invoice_id

    # ...and now it is frozen like any other bound payment.
    with pytest.raises(sa.exc.IntegrityError, match="immutable"):
        async with conn.begin_nested():
            await conn.execute(
                sa.text("UPDATE payments SET invoice_id = NULL WHERE id = :id"),
                {"id": payment_id},
            )


async def test_updating_other_columns_is_unaffected(
    conn: AsyncConnection, world: World
) -> None:
    """``BEFORE UPDATE OF invoice_id`` — the settler still has to move statuses."""
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    payment_id = await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    assert await repo.promote_payment_to_confirmed(conn, payment_id) is True
    assert await payment_status(conn, payment_id) == "confirmed"


# ---------------------------------------------------------------------------
# T3.1 — the same log twice
# ---------------------------------------------------------------------------


async def test_the_same_log_cannot_be_recorded_twice(
    conn: AsyncConnection, world: World
) -> None:
    """``UNIQUE (chain_id, tx_hash, log_index)`` (TZ 5.5, 5.8/T3.1).

    A redelivered log is stopped before the settler ever sees it, which is why
    nothing downstream needs a deduplication step of its own.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    tx = "0x" + "ab" * 32
    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
        tx_hash=tx,
        log_index=0,
    )

    with pytest.raises(sa.exc.IntegrityError, match="uq_payments_chain_tx_log"):
        async with conn.begin_nested():
            await world.payment(
                chain_id=scenario.chain_id,
                asset_id=scenario.asset_id,
                address_id=scenario.address_id,
                invoice_id=scenario.invoice_id,
                amount_raw=10 * USDC,
                block_number=90,
                tx_hash=tx,
                log_index=0,
            )

    assert await count(conn, "payments") == 1


async def test_a_confirmed_payment_cannot_be_credited_twice(
    conn: AsyncConnection, world: World
) -> None:
    """"Переход confirmed -> credited идёт тем же CAS-паттерном" (TZ 5.8/T3.1).

    Even if the same event were delivered twice and both deliveries reached the
    credit step, the second finds zero rows in ``confirmed`` and does nothing.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    payment_id = await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
        status=E.PaymentStatus.CONFIRMED,
    )

    assert await repo.credit_payment(conn, payment_id, 11) is True
    assert await repo.credit_payment(conn, payment_id, 99) is False

    row = (
        await conn.execute(
            sa.text(
                "SELECT status::text AS s, confirmations_at_credit FROM payments WHERE id = :id"
            ),
            {"id": payment_id},
        )
    ).mappings().one()
    assert row["s"] == "credited"
    assert row["confirmations_at_credit"] == 11, "the second attempt must not overwrite"


# ---------------------------------------------------------------------------
# T3.4 — cross-chain
# ---------------------------------------------------------------------------


async def test_the_same_tx_hash_in_another_network_is_a_different_payment(
    conn: AsyncConnection, world: World
) -> None:
    """"payments уникален с учётом chain_id именно поэтому" (TZ 5.8/T3.4).

    Both rows exist — the uniqueness is per chain — and only the one on the
    invoice's own chain is summed into it.
    """
    scenario = await world.scenario(amount_due_raw=10 * USDC)
    other_chain = await world.chain(chain_id=1, last_indexed_block=100)
    other_asset = await world.asset(other_chain, symbol="USDC", decimals=6)
    tx = "0x" + "cd" * 32

    await world.payment(
        chain_id=scenario.chain_id,
        asset_id=scenario.asset_id,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
        tx_hash=tx,
        log_index=0,
    )
    await world.payment(
        chain_id=other_chain,
        asset_id=other_asset,
        address_id=scenario.address_id,
        invoice_id=scenario.invoice_id,
        amount_raw=500 * USDC,
        block_number=90,
        tx_hash=tx,
        log_index=0,
        anomaly=E.PaymentAnomaly.WRONG_CHAIN,
    )

    assert await count(conn, "payments") == 2

    result = await settle_invoice(conn, scenario.invoice_id)

    assert result.outcome is Outcome.PAID
    assert result.decision is not None
    assert result.decision.total_raw == Decimal(10 * USDC), "the other chain must not be summed"


# ---------------------------------------------------------------------------
# Matching is by address, never by amount
# ---------------------------------------------------------------------------


async def test_two_invoices_for_the_same_price_are_kept_apart(
    conn: AsyncConnection, world: World
) -> None:
    """"Сумма вообще не участвует в сопоставлении. Ключ — адрес." (TZ 5.8/T3)

    Two buyers, the same product, the same price to the base unit, at the same
    moment. One pays. The other invoice is untouched — there is no code that
    could confuse them, because nothing anywhere searches by amount.
    """
    alice = await world.scenario(amount_due_raw=10 * USDC)
    bob = await world.scenario(amount_due_raw=10 * USDC)

    assert alice.address != bob.address
    assert alice.amount_due_raw == bob.amount_due_raw

    await world.payment(
        chain_id=alice.chain_id,
        asset_id=alice.asset_id,
        address_id=alice.address_id,
        invoice_id=alice.invoice_id,
        amount_raw=10 * USDC,
        block_number=90,
    )

    assert (await settle_invoice(conn, alice.invoice_id)).outcome is Outcome.PAID
    assert (await settle_invoice(conn, bob.invoice_id)).outcome is Outcome.NO_FUNDS

    assert (
        await count(conn, "entitlements", "invoice_id = :id", id=alice.invoice_id)
    ) == 1
    assert (await count(conn, "entitlements", "invoice_id = :id", id=bob.invoice_id)) == 0


# ---------------------------------------------------------------------------
# The /reconcile invariant
# ---------------------------------------------------------------------------


async def test_the_reconcile_invariant_holds_after_a_mixed_workload(
    conn: AsyncConnection, world: World
) -> None:
    """"Для каждого payments.id существует ровно ноль или один entitlements." (T3)

    Run one of each outcome through the settler and then check the two halves of
    the invariant `/reconcile` checks: no invoice holds more than one active
    grant, and no invoice holds a grant it was not paid for. A drift here is
    ``reconcile_drift_usd``, the most serious alert in the system (TZ 7).
    """
    paid = await world.scenario(amount_due_raw=10 * USDC)
    short = await world.scenario(amount_due_raw=10 * USDC)
    over = await world.scenario(amount_due_raw=10 * USDC)
    empty = await world.scenario(amount_due_raw=10 * USDC)

    for scenario, amount in ((paid, 10), (short, 3), (over, 16)):
        await world.payment(
            chain_id=scenario.chain_id,
            asset_id=scenario.asset_id,
            address_id=scenario.address_id,
            invoice_id=scenario.invoice_id,
            amount_raw=amount * USDC,
            block_number=90,
        )

    for scenario in (paid, short, over, empty):
        for _ in range(3):  # redelivery, retries, a second worker
            await settle_invoice(conn, scenario.invoice_id)

    doubles = (
        await conn.execute(
            sa.text(
                """
                SELECT invoice_id FROM entitlements
                 WHERE revoked_at IS NULL
                 GROUP BY invoice_id HAVING count(*) > 1
                """
            )
        )
    ).all()
    assert doubles == [], "an invoice with two active grants is a double delivery"

    unpaid_grants = (
        await conn.execute(
            sa.text(
                """
                SELECT e.invoice_id
                  FROM entitlements e
                  JOIN invoices i ON i.id = e.invoice_id
                 WHERE e.revoked_at IS NULL
                   AND COALESCE((
                         SELECT SUM(p.amount_raw) FROM payments p
                          WHERE p.invoice_id = i.id
                            AND p.status IN ('confirmed', 'credited')
                            AND p.asset_id = i.asset_id
                            AND p.chain_id = i.chain_id
                       ), 0) < i.amount_due_raw
                """
            )
        )
    ).all()
    assert unpaid_grants == [], "access granted for money that is not in the ledger"

    assert await count(conn, "entitlements", "revoked_at IS NULL") == 2  # paid + over
    assert await count(conn, "entitlements", "invoice_id = :id", id=short.invoice_id) == 0
    assert await count(conn, "entitlements", "invoice_id = :id", id=empty.invoice_id) == 0
