"""Exercises the watcher's real classification SQL for TZ 5.5 `wrong_chain`.

Placed in ``settler/tests`` rather than ``tests/watcher`` on purpose: the
watcher's own unit tests (``tests/watcher/``) run against ``fakes.py``, an
in-memory double, precisely so the detection/reorg logic can be tested without
a database. That is the right call for those tests, but it means
``SQL_INSERT_PAYMENT`` — the one statement in the whole system that classifies
`wrong_asset` / `unassigned_payment` / `wrong_chain` / `orphan_payment`
(``watcher/store/postgres.py``) — is never run against a real Postgres
anywhere in the suite. ``settler/tests`` already has the real-migrations,
real-Postgres rig this needs (``docker-compose.test.yml``), so this file
borrows it rather than standing up a second one.

**Why this specific scenario needed its own test.** TZ 2 states the same key
derives the same address on every EVM network, and TZ 5.5 names the resulting
case `wrong_chain`: money physically on one of our addresses that arrived on a
different chain than the invoice reserving that address. The only existing
coverage of this classification
(``test_settlement.py::test_the_right_token_on_the_wrong_chain_is_not_summed``)
inserts a `payments` row with ``anomaly=WRONG_CHAIN`` already set by hand — it
proves the *settler* handles an already-classified anomaly correctly, not that
the *watcher's SQL* produces that classification from a raw cross-chain
transfer on a reused address. This file closes that gap by calling the exact
``sa.text(...)`` object `watcher.store.postgres.PostgresWatcherStore
.insert_payments` executes in production, with the same address reserved for
an invoice on one chain and the transfer arriving on another.

**Why a shared ``conn`` instead of ``PostgresWatcherStore`` on its own
engine.** ``PostgresWatcherStore`` opens its own connection per call
(``self._engine.begin()``), which is correct for production (short
transactions, TZ 4) but would start a second Postgres session that cannot see
the ``chains``/``assets``/``invoices``/``receive_addresses`` rows the
``world`` fixture just wrote through the still-open ``conn`` transaction
(``settler/tests/conftest.py`` commits at fixture teardown, not mid-test).
Executing ``SQL_INSERT_PAYMENT`` through the same ``conn`` avoids that
isolation mismatch while testing the identical SQL object the store runs —
same import, same constant, not a re-typed copy.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

from settler.tests.conftest import World, _address, _hash
from watcher.store.postgres import SQL_INSERT_PAYMENT

USDC = 1_000_000  # one whole token in base units, 6 decimals


async def _insert_transfer(
    conn: AsyncConnection,
    *,
    chain_id: int,
    address_id: int,
    asset_id: int,
    block_number: int,
    amount_raw: int,
    asset_enabled: bool = True,
) -> sa.engine.Row:
    """Runs the production classification SQL, unmodified, and returns its row.

    Mirrors exactly what ``PostgresWatcherStore.insert_payments`` binds — see
    ``watcher/store/postgres.py`` — so a change to the CASE logic there is
    caught here without this file needing to duplicate it.
    """
    result = await conn.execute(
        sa.text(SQL_INSERT_PAYMENT),
        {
            "chain_id": chain_id,
            "tx_hash": _hash(f"tx-{chain_id}-{address_id}-{block_number}"),
            "log_index": 0,
            "block_number": block_number,
            "address_id": address_id,
            "asset_id": asset_id,
            "asset_enabled": asset_enabled,
            "amount_raw": str(amount_raw),
            "sender": _address(f"sender-{chain_id}-{address_id}"),
        },
    )
    row = result.first()
    assert row is not None, "ON CONFLICT DO NOTHING fired — tx_hash/log_index collided"
    return row


async def test_a_transfer_on_another_evm_network_to_a_reused_address_is_wrong_chain(
    conn: AsyncConnection, world: World
) -> None:
    """TZ 2 + 5.5 — "прислали в другой EVM-сети на тот же адрес".

    The receive address is chain-agnostic (``core.db.models.ReceiveAddress``
    has no ``chain_id`` column at all — that is the mechanism, not an
    accident). An invoice reserves it on Base (8453); the transfer arrives on
    Ethereum mainnet (1) with a *different* asset row, because assets are
    scoped per chain. `SQL_INSERT_PAYMENT` has to notice the chain mismatch
    before it ever looks at the asset, and does: the CASE checks
    ``i.chain_id <> :chain_id`` ahead of the asset predicate.
    """
    base_chain_id = await world.chain(chain_id=8453)
    eth_chain_id = await world.chain(chain_id=1)
    hd_account_id = await world.hd_account()
    address_id, _address_str = await world.address(hd_account_id, index=0)
    base_asset_id = await world.asset(base_chain_id, symbol="USDC")
    eth_asset_id = await world.asset(eth_chain_id, symbol="USDC")
    product_id = await world.product()
    user_id = await world.user()

    invoice_id = await world.invoice(
        user_id=user_id,
        product_id=product_id,
        chain_id=base_chain_id,
        asset_id=base_asset_id,
        address_id=address_id,
        amount_due_raw=10 * USDC,
    )

    row = await _insert_transfer(
        conn,
        chain_id=eth_chain_id,
        address_id=address_id,
        asset_id=eth_asset_id,
        block_number=10,
        amount_raw=10 * USDC,
    )

    assert row.anomaly == "wrong_chain"
    # Never attached to the Base invoice: a mis-bound cross-chain row is what
    # `test_the_right_token_on_the_wrong_chain_is_not_summed` protects against
    # at the settler layer, but the watcher itself never creates that state —
    # `invoice_id` stays NULL here, by the same CASE that set the anomaly.
    assert row.invoice_id is None

    persisted = (
        await conn.execute(
            sa.text(
                "SELECT anomaly::text AS anomaly, invoice_id FROM payments WHERE id = :id"
            ),
            {"id": row.id},
        )
    ).mappings().one()
    assert persisted["anomaly"] == "wrong_chain"
    assert persisted["invoice_id"] is None
    assert invoice_id is not None  # the Base invoice itself is untouched


async def test_the_same_address_on_its_own_chain_is_not_wrong_chain(
    conn: AsyncConnection, world: World
) -> None:
    """Control case for the test above.

    Same address, same reservation, but the transfer arrives on the chain that
    actually reserved it. Without this, a bug that always tags cross-chain
    lookups as `wrong_chain` (e.g. an accidental ``<>`` where the address
    lookup itself should have failed) would pass the test above for the wrong
    reason.
    """
    base_chain_id = await world.chain(chain_id=8453)
    hd_account_id = await world.hd_account()
    address_id, _address_str = await world.address(hd_account_id, index=1)
    base_asset_id = await world.asset(base_chain_id, symbol="USDC")
    product_id = await world.product()
    user_id = await world.user()

    invoice_id = await world.invoice(
        user_id=user_id,
        product_id=product_id,
        chain_id=base_chain_id,
        asset_id=base_asset_id,
        address_id=address_id,
        amount_due_raw=10 * USDC,
    )

    row = await _insert_transfer(
        conn,
        chain_id=base_chain_id,
        address_id=address_id,
        asset_id=base_asset_id,
        block_number=10,
        amount_raw=10 * USDC,
    )

    assert row.anomaly is None
    assert row.invoice_id == invoice_id


async def test_a_transfer_on_another_chain_to_an_unreserved_address_is_unassigned_not_wrong_chain(
    conn: AsyncConnection, world: World
) -> None:
    """The chain predicate only fires once an invoice is found at all.

    A free (never-reserved) address has no ``current_invoice_id``, so
    ``i.id IS NULL`` short-circuits the CASE to `unassigned_payment` before the
    chain comparison is reached, on any chain. This is the boundary between the
    two anomalies the settler otherwise never has to reason about.
    """
    eth_chain_id = await world.chain(chain_id=1)
    hd_account_id = await world.hd_account()
    address_id, _address_str = await world.address(hd_account_id, index=2)
    eth_asset_id = await world.asset(eth_chain_id, symbol="USDC")

    row = await _insert_transfer(
        conn,
        chain_id=eth_chain_id,
        address_id=address_id,
        asset_id=eth_asset_id,
        block_number=10,
        amount_raw=10 * USDC,
    )

    assert row.anomaly == "unassigned_payment"
    assert row.invoice_id is None
