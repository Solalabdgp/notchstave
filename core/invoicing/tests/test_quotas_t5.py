"""TZ 5.8/T5 — DoS through address generation, and the four things that stop it.

The tests named in TZ section 8 under T5 are, verbatim:

* сто попыток ``/buy`` подряд от одного пользователя дают три активных инвойса и
  ``ratelimit_hits``, а не сто адресов;
* ``next_index`` не растёт, пока в пуле есть свободные адреса;
* при достижении потолка активных адресов создание инвойса отклоняется
  корректным сообщением, а не 500-й ошибкой.

All three are here, plus the behavioural cooldown of T5.5 and the concurrency
case the advisory lock exists for.
"""

from __future__ import annotations

import datetime as dt
import threading
from typing import Any

import psycopg
import pytest

from core.invoicing import errors
from core.invoicing.config import InvoicingPolicy
from core.invoicing.integrity import IntegrityKey
from core.invoicing.metrics import RATELIMIT_HITS
from core.invoicing.tests.conftest import (
    FakeDeriver,
    Shop,
    World,
    buy,
    count_rows,
    next_index,
    psycopg_dsn,
    sample_value,
    scalar,
)


def test_a_hundred_buys_give_three_invoices_and_ninety_seven_ratelimit_hits(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ section 8, T5, first bullet — "а не сто адресов".

    The number that matters is not the three. It is that ``receive_addresses``
    holds three rows and ``next_index`` sits at three: the attack's payload is
    consumed index space and filter size, and a quota that let ninety-seven
    addresses be derived before refusing the ninety-eighth invoice would have
    passed a naive count-the-invoices assertion while doing nothing at all.
    """
    shop = world.shop()
    before = sample_value(RATELIMIT_HITS, "_total", scope="active_invoices")

    refusals = 0
    for _ in range(100):
        try:
            buy(conn, deriver, key, shop)
        except errors.TooManyActiveInvoices:
            refusals += 1

    assert count_rows(conn, "invoices") == 3
    assert refusals == 97

    assert count_rows(conn, "receive_addresses") == 3
    assert next_index(conn, shop.hd_account_id) == 3

    after = sample_value(RATELIMIT_HITS, "_total", scope="active_invoices")
    assert after - before == 97


def test_a_refused_buy_is_an_answer_and_not_an_exception_the_bot_cannot_render(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """Every quota refusal carries a sentence a buyer can be shown as-is.

    TZ 5.8/T5.2 says this explicitly for the address ceiling, and the same rule
    is applied to all of them: an operator-facing ``str(exc)`` naming counts and
    limits, and a separate ``user_message`` that names neither.
    """
    shop = world.shop()
    for _ in range(3):
        buy(conn, deriver, key, shop)

    with pytest.raises(errors.TooManyActiveInvoices) as caught:
        buy(conn, deriver, key, shop)

    error = caught.value
    assert error.scope == "active_invoices"
    assert error.limit == 3
    assert error.observed == 3
    assert "limit is 3" in str(error)
    # The buyer-facing half leaks no counts and reads as a sentence.
    assert "3" not in error.user_message
    assert error.user_message.endswith(".")


def test_next_index_does_not_move_while_the_pool_has_stock(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ section 8, T5, second bullet — countermeasure 5.3.

    This is the only measure that makes the gap-limit half of the attack
    structurally impossible rather than merely expensive: consumed index space
    becomes a function of peak concurrency, not of total button presses.
    """
    shop = world.shop(pooled_addresses=5, deriver=deriver)
    policy = InvoicingPolicy(max_active_invoices_per_user=5, max_invoices_per_hour=50)

    for _ in range(5):
        buy(conn, deriver, key, shop, policy=policy)

    assert count_rows(conn, "invoices") == 5
    assert next_index(conn, shop.hd_account_id) == 5, "the pool covered all five"
    assert count_rows(conn, "receive_addresses") == 5, "no address was derived"


def test_the_address_ceiling_refuses_honestly_instead_of_raising_a_five_hundred(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ section 8, T5, third bullet — "корректным сообщением, а не 500-й ошибкой".

    The ceiling is a system-wide condition and not this buyer's fault, so it
    gets its own exception type with its own sentence, and it moves the same
    ``ratelimit_hits`` family under a distinct ``scope`` so the dashboard can
    tell "one user is hammering us" apart from "we are out of address space".
    """
    shop = world.shop(max_active_addresses=2)
    policy = InvoicingPolicy(max_active_invoices_per_user=10, max_invoices_per_hour=50)
    before = sample_value(RATELIMIT_HITS, "_total", scope="addresses")

    buy(conn, deriver, key, shop, policy=policy)
    buy(conn, deriver, key, shop, policy=policy)

    with pytest.raises(errors.AddressCapacityExhausted) as caught:
        buy(conn, deriver, key, shop, policy=policy)

    assert isinstance(caught.value, errors.InvoiceUnavailable)
    assert "try again" in caught.value.user_message.lower()
    assert sample_value(RATELIMIT_HITS, "_total", scope="addresses") - before == 1

    # And the refusal did not consume the thing it was refusing about.
    assert next_index(conn, shop.hd_account_id) == 2


def test_the_hourly_quota_counts_invoices_and_not_live_ones(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 5.8/T5.1 — "не более 10 за час", regardless of what happened to them.

    Cancelling nine invoices frees nine addresses and does not buy nine more
    presses: the active-invoice quota protects the filter size, the hourly quota
    protects the rate of address churn, and only counting live invoices would
    collapse the second into the first.
    """
    shop = world.shop(pooled_addresses=12, deriver=deriver)
    policy = InvoicingPolicy(max_active_invoices_per_user=100, max_invoices_per_hour=10)

    for _ in range(10):
        view = buy(conn, deriver, key, shop, policy=policy)
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE invoices SET status = 'cancelled' WHERE id = %(id)s",
                {"id": view.invoice_id},
            )

    with pytest.raises(errors.HourlyQuotaExceeded) as caught:
        buy(conn, deriver, key, shop, policy=policy)

    assert caught.value.observed == 10
    assert caught.value.retry_at is not None, "an hourly quota knows when it lifts"


def test_the_quota_decision_survives_a_wiped_rate_limits_table(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """The authority is ``invoices``, not the counter — and not Redis.

    TZ 5.8/T5.1: "сброс или перезапуск Redis не должен открывать шлюз". The same
    argument applies one layer down. ``rate_limits`` is a mirror kept for audit
    and for the cooldown deadline; if it were the authority, anything able to
    write it could reset the gate. Deleting every row in it must change nothing.
    """
    shop = world.shop()
    for _ in range(3):
        buy(conn, deriver, key, shop)

    with conn.cursor() as cur:
        cur.execute("DELETE FROM rate_limits")

    with pytest.raises(errors.TooManyActiveInvoices):
        buy(conn, deriver, key, shop)


def test_five_consecutive_expired_invoices_put_the_user_in_a_one_hour_cooldown(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 5.8/T5.5 — "мягкая и обратимая" .

    The streak is read off ``invoices`` rather than kept as a counter, so the
    settler expiring an invoice does not have to remember to increment anything
    (and does not have the grant to). The cooldown deadline is the one piece of
    state that is not derivable, so it — and only it — is written down.
    """
    shop = world.shop(pooled_addresses=8, deriver=deriver)
    policy = InvoicingPolicy(
        max_active_invoices_per_user=10,
        max_invoices_per_hour=50,
        expired_streak_limit=5,
        cooldown=dt.timedelta(hours=1),
    )

    for _ in range(5):
        view = buy(conn, deriver, key, shop, policy=policy)
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE invoices SET status = 'expired' WHERE id = %(id)s",
                {"id": view.invoice_id},
            )

    with pytest.raises(errors.BehaviouralCooldown) as caught:
        buy(conn, deriver, key, shop, policy=policy)

    assert caught.value.observed == 5
    stored = scalar(
        conn,
        "SELECT max(cooldown_until) FROM rate_limits WHERE user_id = %(u)s",
        u=shop.user_id,
    )
    assert stored is not None
    assert stored > dt.datetime.now(dt.UTC) + dt.timedelta(minutes=55)

    # The cooldown is then honoured on the next attempt without recomputing the
    # streak — which is what makes it survive the invoices ageing out.
    with pytest.raises(errors.BehaviouralCooldown) as again:
        buy(conn, deriver, key, shop, policy=policy)
    assert again.value.retry_at == stored


def test_one_payment_in_the_streak_stops_the_cooldown(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """"Обычный покупатель в неё не упирается, скрипт упирается сразу."

    A buyer whose invoice expired four times and then paid once is not the
    attacker this measure is aimed at, and the streak resetting on any
    non-expired outcome is what keeps the measure from punishing them.
    """
    shop = world.shop(pooled_addresses=8, deriver=deriver)
    policy = InvoicingPolicy(
        max_active_invoices_per_user=10, max_invoices_per_hour=50, expired_streak_limit=5
    )

    for n in range(5):
        view = buy(conn, deriver, key, shop, policy=policy)
        status = "paid" if n == 2 else "expired"
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE invoices SET status = %(s)s WHERE id = %(id)s",
                {"s": status, "id": view.invoice_id},
            )

    # Two expired at the head of the list, not five. No cooldown.
    buy(conn, deriver, key, shop, policy=policy)


# `test_the_reserved_address_gauge_tracks_the_ledger` used to live here and was
# deleted rather than repaired. It asserted that `create_invoice` set
# `notchstave_active_reserved_addresses`, which it did — from a count of live
# *invoices*, which is not the quantity the TZ 5.8/T5.2 alert reads, and inside
# the deriver process, which serves no `/metrics` at all, so the value it
# asserted on was never visible to Prometheus in production. The test passed and
# the metric was blind, which is the worst arrangement of the two.
#
# The gauge now has one writer, in the settler, counting rows in
# `receive_addresses`. Its test moved with it:
# `settler/tests/test_address_pool.py::test_the_reserved_gauge_counts_addresses
# _and_comes_back_down`.


# ---------------------------------------------------------------------------
# Concurrency — what the advisory lock is for
# ---------------------------------------------------------------------------


def _buy_in_own_connection(
    shop: Shop, deriver: FakeDeriver, key: IntegrityKey, results: list[str], index: int
) -> None:
    """One thread, one connection, one transaction — as in production.

    Real threads and real connections rather than coroutines: the property under
    test is that PostgreSQL serialises the quota check, and twenty coroutines on
    one connection would be serialised by the client library instead, which
    proves nothing.
    """
    connection = psycopg.connect(psycopg_dsn(), autocommit=False)
    try:
        buy(connection, deriver, key, shop)
        connection.commit()
        results[index] = "issued"
    except errors.QuotaExceeded as exc:
        connection.rollback()
        results[index] = exc.scope
    except Exception as exc:  # noqa: BLE001 — recorded so a failure names itself
        connection.rollback()
        results[index] = f"error:{type(exc).__name__}:{exc}"
    finally:
        connection.close()


def test_twenty_simultaneous_buys_from_one_user_still_give_exactly_three(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 5.8/T5.1 — "иначе параллельные /buy пролезают мимо счётчика".

    Without ``pg_advisory_xact_lock`` every one of these twenty transactions
    reads "0 active invoices" before any of them writes one, and all twenty
    succeed. The count cannot be defended by a unique index the way the double
    grant in T2 can — "at most three" is not a property of any single row — so
    serialising the check-and-insert is the mechanism rather than an
    optimisation.

    The uncommitted setup has to be committed first: the worker threads are
    separate transactions and cannot see rows this one has not published.
    """
    shop = world.shop(pooled_addresses=25, deriver=deriver)
    conn.commit()

    results: list[str] = [""] * 20
    threads = [
        threading.Thread(target=_buy_in_own_connection, args=(shop, deriver, key, results, i))
        for i in range(20)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert all(not t.is_alive() for t in threads), "a thread deadlocked on the advisory lock"

    unexpected = [r for r in results if r.startswith("error:")]
    assert not unexpected, unexpected

    assert results.count("issued") == 3
    assert results.count("active_invoices") == 17

    assert count_rows(conn, "invoices") == 3
    # Seventeen rolled-back reservations left no address behind.
    assert count_rows(conn, "receive_addresses", "status = 'reserved'") == 3
    assert next_index(conn, shop.hd_account_id) == 25, "the pool absorbed all of it"
