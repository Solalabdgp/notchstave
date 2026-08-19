"""The ask-the-deriver round trip, end to end against a real Postgres.

Migration 0007 put a table and two triggers between ``/buy`` and
``create_invoice``. What this file is here to prove is that nothing was lost in
the crossing:

* a request reaches the deriver and comes back as a **verified** invoice;
* a refusal comes back as **the same exception class** the service raised, with
  its buyer-safe sentence intact — a quota is still a quota on the other side;
* an integrity failure comes back as an integrity failure, and specifically not
  as something an ``except InvoiceUnavailable`` handler can swallow;
* a **corrupted reply** is caught by the MAC, because that is the only check
  ``bot`` can run on an address and this transport carries addresses;
* the queue's own failure modes — a lost client, a crashing issuer, a dead
  claim — end in an answer rather than in a hang.

**Real Postgres, real triggers, real ``LISTEN``.** The notification path is the
entire latency argument for choosing a table over a socket, and it is made of
``pg_notify`` inside a trigger. Nothing about that can be faked: a mock that
returns "you were notified" tests the mock. The deriver loop runs in a thread,
against its own connections, exactly as it does in production.

**The issuer is the real one** (:func:`core.invoicing.issuer.build_issuer`),
wired to the real :mod:`deriver.pool`, with only the curve replaced by
``FakeDeriver`` — the same trade the rest of this suite makes and for the same
reason (see ``conftest.py``).
"""

from __future__ import annotations

import datetime as dt
import json
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
import pytest
from psycopg.rows import dict_row

import deriver.main as deriver_main
import deriver.requests as deriver_requests
from core.invoicing import client as client_module
from core.invoicing import errors as E
from core.invoicing.client import InvoiceClient, active_hd_account_id
from core.invoicing.config import InvoicingPolicy
from core.invoicing.integrity import IntegrityKey
from core.invoicing.issuer import build_issuer
from core.invoicing.service import InvoiceView
from core.invoicing.tests.conftest import (
    REPO_ROOT,
    TEST_INTEGRITY_KEY,
    FakeDeriver,
    Shop,
    World,
    psycopg_dsn,
    scalar,
)
from core.invoicing.wire import from_wire, to_wire

# ---------------------------------------------------------------------------
# A deriver process, in a thread
# ---------------------------------------------------------------------------


@contextmanager
def running_deriver(
    deriver: FakeDeriver,
    key: IntegrityKey = TEST_INTEGRITY_KEY,
    *,
    policy: InvoicingPolicy | None = None,
    wrap: Callable[[Any], Any] | None = None,
) -> Iterator[None]:
    """Run :func:`deriver.main.serve` for the duration of the block.

    ``poll_interval`` is short so that a test which somehow misses a
    notification still finishes; it is deliberately *not* short enough to hide a
    broken trigger, because every assertion below about latency would then pass
    for the wrong reason.

    ``wrap`` lets a test sit between the issuer and the queue — used to forge a
    tampered reply, which is the one thing this transport must survive.
    """
    issuer = build_issuer(key, policy=policy or InvoicingPolicy())
    stop = threading.Event()
    failure: list[BaseException] = []

    def run() -> None:
        try:
            deriver_main.serve(
                deriver,
                issuer if wrap is None else wrap(issuer),
                dsn=psycopg_dsn(),
                poll_interval=0.2,
                should_stop=stop.is_set,
            )
        except BaseException as exc:  # pragma: no cover - surfaced below
            failure.append(exc)

    thread = threading.Thread(target=run, name="test-deriver", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=10)
    assert not failure, f"the deriver loop died: {failure[0]!r}"


def serve_pending(deriver: FakeDeriver, issuer: Any, *, max_attempts: int = 3) -> list[str]:
    """One synchronous drain, for the tests that want to step the loop by hand."""
    with psycopg.connect(psycopg_dsn(), autocommit=False) as conn:
        # `list(...)` rather than a bare return: `deriver.main` is type-checked
        # under its own environment (root pyproject sets `follow_imports = skip`
        # for `deriver.*`), so everything it returns is `Any` here.
        outcomes: list[str] = list(
            deriver_main.run_once(conn, deriver, issuer, max_attempts=max_attempts)
        )
    return outcomes


@pytest.fixture
def shop(conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver) -> Shop:
    """A committed catalog.

    Committed, unlike everywhere else in this suite, and that is the whole
    difference this file makes: the deriver is another *connection*, so anything
    still sitting in this test's transaction does not exist as far as it is
    concerned.
    """
    built = world.shop(pooled_addresses=4, deriver=deriver)
    conn.commit()
    return built


@pytest.fixture
def buyer(key: IntegrityKey) -> InvoiceClient:
    return InvoiceClient(psycopg_dsn(), key, timeout=10.0, recheck_interval=0.1)


def ask(buyer: InvoiceClient, shop: Shop, **kwargs: Any) -> InvoiceView:
    return buyer.create_invoice(
        user_id=shop.user_id,
        product_id=shop.product_id,
        chain_id=shop.chain_id,
        asset_id=shop.asset_id,
        hd_account_id=shop.hd_account_id,
        **kwargs,
    )


def request_row(conn: psycopg.Connection[Any], request_id: uuid.UUID) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM invoice_requests WHERE id = %(id)s", {"id": request_id})
        row = cur.fetchone()
    assert row is not None
    return row


def only_request(conn: psycopg.Connection[Any]) -> dict[str, Any]:
    conn.rollback()  # see the freshest committed state, not this test's snapshot
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM invoice_requests")
        rows = cur.fetchall()
    assert len(rows) == 1, f"expected exactly one request row, found {len(rows)}"
    return rows[0]


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_buy_reaches_the_deriver_and_comes_back_verified(
    conn: psycopg.Connection[Any], shop: Shop, deriver: FakeDeriver, buyer: InvoiceClient
) -> None:
    """The whole point, in one test.

    The address that arrives at the bot must be the address the deriver derived,
    and it must arrive with a MAC that verifies — because the MAC check inside
    :class:`InvoiceClient` is what stands in for ``deriver.verify`` on a process
    that has no xpub.
    """
    with running_deriver(deriver):
        view = ask(buyer, shop)

    assert view.address == deriver.address(view.hd_account_id, view.derivation_index)
    assert view.status == "awaiting"
    assert view.eip681().startswith("ethereum:")

    row = only_request(conn)
    assert row["status"] == "done"
    assert row["invoice_id"] == view.invoice_id
    assert row["error_code"] is None
    # The invoice and the answer are one transaction: there is no reply pointing
    # at an invoice that is not there.
    assert scalar(conn, "SELECT count(*) FROM invoices WHERE id = %(id)s", id=view.invoice_id) == 1


def test_the_reply_carries_the_pooled_address_and_not_a_new_index(
    conn: psycopg.Connection[Any], shop: Shop, deriver: FakeDeriver, buyer: InvoiceClient
) -> None:
    """TZ 5.1 p. 3 survives the round trip.

    Worth pinning down separately: the transport must not quietly change which
    reservation path runs. Four addresses were pre-filled, so ``next_index`` must
    not move and ``newly_derived`` must be False on the way back.
    """
    sql = "SELECT next_index FROM hd_accounts WHERE id = %(i)s"
    before = scalar(conn, sql, i=shop.hd_account_id)

    with running_deriver(deriver):
        view = ask(buyer, shop)

    conn.rollback()
    after = scalar(conn, sql, i=shop.hd_account_id)
    assert after == before
    assert view.newly_derived is False


def test_three_buys_in_a_row_each_get_their_own_address(
    conn: psycopg.Connection[Any], shop: Shop, deriver: FakeDeriver, buyer: InvoiceClient
) -> None:
    """The one-open-per-user index must not stop a user buying again, only twice at once."""
    with running_deriver(deriver):
        views = [ask(buyer, shop) for _ in range(3)]

    assert len({v.address for v in views}) == 3
    assert len({v.invoice_id for v in views}) == 3
    conn.rollback()
    assert scalar(conn, "SELECT count(*) FROM invoice_requests WHERE status = 'done'") == 3


# ---------------------------------------------------------------------------
# Refusals come back as themselves
# ---------------------------------------------------------------------------


def test_a_quota_refusal_arrives_as_the_same_exception_class(
    conn: psycopg.Connection[Any], shop: Shop, deriver: FakeDeriver, buyer: InvoiceClient
) -> None:
    """TZ 5.8/T5.1 across a process boundary.

    The class, the buyer-safe sentence and the numbers all have to survive, or
    the bot ends up rendering "something went wrong" for a condition the TZ
    writes a specific message for.
    """
    tight = InvoicingPolicy(max_active_invoices_per_user=1)
    with running_deriver(deriver, policy=tight):
        ask(buyer, shop)
        with pytest.raises(E.TooManyActiveInvoices) as caught:
            ask(buyer, shop)

    exc = caught.value
    assert exc.user_message == E.TooManyActiveInvoices.user_message
    assert exc.limit == 1
    assert exc.observed >= 1
    assert exc.scope == "active_invoices"
    # `InvoiceUnavailable` is the umbrella a friendly handler catches; a quota
    # must still be under it after the trip.
    assert isinstance(exc, E.InvoiceUnavailable)


def test_the_address_ceiling_arrives_as_address_capacity_exhausted(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, buyer: InvoiceClient
) -> None:
    """TZ 5.8/T5.2 — "сейчас нельзя, попробуйте позже", not a 500.

    Exactly one address in the pool, so the second ``/buy`` is the one that has
    to derive — which is where the ceiling lives. The pool pickup deliberately
    does not check it (an address already derived costs no new index), so a test
    with two pooled addresses would pass without ever reaching the code it names.
    """
    built = world.shop(max_active_addresses=1, pooled_addresses=1, deriver=deriver)
    conn.commit()

    with running_deriver(deriver):
        ask(buyer, built)
        with pytest.raises(E.AddressCapacityExhausted) as caught:
            ask(buyer, built)

    assert "try again" in caught.value.user_message.lower()


def test_an_unknown_product_arrives_as_unknown_product(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, buyer: InvoiceClient
) -> None:
    built = world.shop(pooled_addresses=1, deriver=deriver)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE products SET active = false WHERE id = %(id)s",
            {"id": built.product_id},
        )
    conn.commit()

    with running_deriver(deriver), pytest.raises(E.UnknownProduct):
        ask(buyer, built)


def test_an_integrity_failure_is_not_catchable_as_invoice_unavailable(
    conn: psycopg.Connection[Any], shop: Shop, buyer: InvoiceClient
) -> None:
    """TZ 5.8/T1.1 keeps its species across the boundary.

    ``errors.py`` puts :class:`IntegrityFailure` deliberately outside
    :class:`InvoiceUnavailable` so a handler written to be friendly about quotas
    cannot swallow a suspected compromise. That property is worth nothing if the
    transport flattens it, so this is the test that says it did not.
    """

    class NeverVerifies(FakeDeriver):
        def verify(self, address: str, hd_account_id: int, derivation_index: int) -> bool:
            return False

    with running_deriver(NeverVerifies()), pytest.raises(E.AddressMismatch) as caught:
        ask(buyer, shop)

    assert not isinstance(caught.value, E.InvoiceUnavailable)
    assert "do not send any funds" in caught.value.user_message.lower()
    # And nothing was issued: the refusal path rolls the work transaction back.
    conn.rollback()
    assert scalar(conn, "SELECT count(*) FROM invoices") == 0


def test_a_refusal_leaves_the_address_pool_exactly_as_it_was(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, buyer: InvoiceClient
) -> None:
    """The rollback in ``serve_one`` is real, not a comment.

    ``create_invoice`` may take an address out of the pool before it refuses on
    a later gate. The queue rolls that back before writing the refusal, and the
    only way to see the difference is to count reserved addresses afterwards.
    """
    built = world.shop(pooled_addresses=2, deriver=deriver)
    conn.commit()

    tight = InvoicingPolicy(max_active_invoices_per_user=1)
    with running_deriver(deriver, policy=tight):
        ask(buyer, built)
        with pytest.raises(E.TooManyActiveInvoices):
            ask(buyer, built)

    conn.rollback()
    assert scalar(conn, "SELECT count(*) FROM receive_addresses WHERE status = 'reserved'") == 1
    assert scalar(conn, "SELECT count(*) FROM receive_addresses WHERE status = 'free'") == 1


# ---------------------------------------------------------------------------
# The reply is checked, not trusted
# ---------------------------------------------------------------------------


def test_a_tampered_reply_is_caught_by_the_mac(
    conn: psycopg.Connection[Any], shop: Shop, deriver: FakeDeriver, buyer: InvoiceClient
) -> None:
    """The attack this transport has to survive (TZ 5.8/T1.3).

    Someone with write access to ``invoice_requests`` — a leaked replica, a
    forgotten port forward, a contractor's SQL session — swaps the address in a
    reply for one of their own. They cannot recompute ``integrity_mac`` without
    ``INVOICE_INTEGRITY_KEY``, which never goes near this table. Simulated by
    rewriting the payload between the issuer and the queue, which is the same
    bytes arriving at the client either way.
    """
    attacker_address = "0x" + "ab" * 20

    def tamper(issuer: Any) -> Any:
        def wrapped(conn_: Any, deriver_: Any, request: Any) -> Any:
            outcome = issuer(conn_, deriver_, request)
            payload = json.loads(outcome.result_json)
            payload["address"] = attacker_address
            return deriver_requests.IssuedInvoice(
                invoice_id=outcome.invoice_id, result_json=json.dumps(payload)
            )

        return wrapped

    with running_deriver(deriver, wrap=tamper), pytest.raises(E.MacMismatch) as caught:
        ask(buyer, shop)

    assert not isinstance(caught.value, E.InvoiceUnavailable)
    assert "do not send any funds" in caught.value.user_message.lower()


def test_an_unreadable_reply_is_a_mac_mismatch_and_not_a_crash(
    shop: Shop, deriver: FakeDeriver, buyer: InvoiceClient
) -> None:
    """A truncated or re-versioned payload must not reach a renderer half-decoded."""

    def truncate(issuer: Any) -> Any:
        def wrapped(conn_: Any, deriver_: Any, request: Any) -> Any:
            outcome = issuer(conn_, deriver_, request)
            payload = json.loads(outcome.result_json)
            payload.pop("address")
            return deriver_requests.IssuedInvoice(
                invoice_id=outcome.invoice_id, result_json=json.dumps(payload)
            )

        return wrapped

    with running_deriver(deriver, wrap=truncate), pytest.raises(E.MacMismatch):
        ask(buyer, shop)


def test_the_wire_round_trip_is_exact(
    conn: psycopg.Connection[Any], shop: Shop, deriver: FakeDeriver, buyer: InvoiceClient
) -> None:
    """Every field, byte for byte, through JSON.

    The two that would break quietly are the decimals (``NUMERIC(78,0)`` past
    2^53) and the microseconds in ``expires_at`` (one of the six fields under the
    MAC). Comparing the whole dataclass catches both without a test per field.
    """
    with running_deriver(deriver):
        view = ask(buyer, shop)

    assert from_wire(json.loads(json.dumps(to_wire(view)))) == view


# ---------------------------------------------------------------------------
# The queue's own failure modes
# ---------------------------------------------------------------------------


def test_a_second_simultaneous_request_is_refused_at_the_door(
    conn: psycopg.Connection[Any], shop: Shop, buyer: InvoiceClient
) -> None:
    """TZ 5.8/T5.1, enforced by ``uq_invoice_requests_one_open_per_user``.

    No deriver is running, so the first request stays pending — which is exactly
    the window the index exists to cover.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO invoice_requests (id, user_id, product_id, chain_id, asset_id,
                                          hd_account_id)
            VALUES (gen_random_uuid(), %(u)s, %(p)s, %(c)s, %(a)s, %(h)s)
            """,
            {
                "u": shop.user_id,
                "p": shop.product_id,
                "c": shop.chain_id,
                "a": shop.asset_id,
                "h": shop.hd_account_id,
            },
        )
    conn.commit()

    with pytest.raises(E.InvoiceRequestInFlight) as caught:
        ask(buyer, shop, timeout=1.0)

    assert isinstance(caught.value, E.InvoiceUnavailable)


def test_a_client_that_gives_up_leaves_the_request_standing(
    conn: psycopg.Connection[Any], shop: Shop, buyer: InvoiceClient
) -> None:
    """A timeout says "we do not know", and the row proves it is not a lie.

    The request is not withdrawn on the way out. That is the honest behaviour
    and it is why :class:`InvoiceRequestTimeout`'s message points the buyer at
    ``/status`` instead of telling them it failed.
    """
    with pytest.raises(E.InvoiceRequestTimeout):
        ask(buyer, shop, timeout=0.5)

    row = only_request(conn)
    assert row["status"] == "pending"
    assert row["invoice_id"] is None


def test_an_issuer_that_keeps_crashing_is_retried_then_answered(
    conn: psycopg.Connection[Any], shop: Shop, deriver: FakeDeriver, buyer: InvoiceClient
) -> None:
    """A poison request must not be an infinite crash loop.

    ``attempts`` is incremented by the *claim*, so a request that kills its
    server still spends budget — which is the difference between three failed
    attempts and an outage. After the budget the queue answers it itself.
    """

    def explode(conn_: Any, deriver_: Any, request: Any) -> Any:
        raise RuntimeError("the database went away")

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO invoice_requests (id, user_id, product_id, chain_id, asset_id,
                                          hd_account_id)
            VALUES (gen_random_uuid(), %(u)s, %(p)s, %(c)s, %(a)s, %(h)s)
            """,
            {
                "u": shop.user_id,
                "p": shop.product_id,
                "c": shop.chain_id,
                "a": shop.asset_id,
                "h": shop.hd_account_id,
            },
        )
    conn.commit()

    outcomes = [serve_pending(deriver, explode, max_attempts=3) for _ in range(3)]
    assert [o[0] for o in outcomes] == ["retry", "retry", "abandoned"]

    row = only_request(conn)
    assert row["status"] == "failed"
    assert row["error_code"] == deriver_requests.ABANDONED_ERROR_CODE
    assert row["attempts"] == 3
    # And the class name the deriver wrote is one the client can raise.
    assert row["error_code"] == E.InvoiceRequestAbandoned.__name__


def test_a_claim_abandoned_by_a_dead_process_is_reclaimed(
    conn: psycopg.Connection[Any], shop: Shop
) -> None:
    """The lease, without which a crash between claim and work is a stuck buyer."""
    request_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO invoice_requests (id, user_id, product_id, chain_id, asset_id,
                                          hd_account_id, status, attempts, claimed_at)
            VALUES (%(id)s, %(u)s, %(p)s, %(c)s, %(a)s, %(h)s, 'processing', 1,
                    now() - interval '10 minutes')
            """,
            {
                "id": request_id,
                "u": shop.user_id,
                "p": shop.product_id,
                "c": shop.chain_id,
                "a": shop.asset_id,
                "h": shop.hd_account_id,
            },
        )
    conn.commit()

    with psycopg.connect(psycopg_dsn(), autocommit=False) as work:
        requeued, abandoned, _pruned = deriver_main.housekeeping(work, lease_seconds=30.0)

    assert (requeued, abandoned) == (1, 0)
    conn.rollback()
    assert request_row(conn, request_id)["status"] == "pending"


def test_a_stale_claim_out_of_attempts_is_answered_rather_than_left(
    conn: psycopg.Connection[Any], shop: Shop
) -> None:
    request_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO invoice_requests (id, user_id, product_id, chain_id, asset_id,
                                          hd_account_id, status, attempts, claimed_at)
            VALUES (%(id)s, %(u)s, %(p)s, %(c)s, %(a)s, %(h)s, 'processing', 3,
                    now() - interval '10 minutes')
            """,
            {
                "id": request_id,
                "u": shop.user_id,
                "p": shop.product_id,
                "c": shop.chain_id,
                "a": shop.asset_id,
                "h": shop.hd_account_id,
            },
        )
    conn.commit()

    with psycopg.connect(psycopg_dsn(), autocommit=False) as work:
        requeued, abandoned, _pruned = deriver_main.housekeeping(work, lease_seconds=30.0)

    assert (requeued, abandoned) == (0, 1)
    conn.rollback()
    row = request_row(conn, request_id)
    assert row["status"] == "failed"
    assert row["error_code"] == E.InvoiceRequestAbandoned.__name__


def test_finished_requests_are_pruned_and_the_invoice_is_not(
    conn: psycopg.Connection[Any], shop: Shop, deriver: FakeDeriver, buyer: InvoiceClient
) -> None:
    """The queue is a queue, not a log — and pruning it must not touch money."""
    with running_deriver(deriver):
        view = ask(buyer, shop)

    with conn.cursor() as cur:
        cur.execute("UPDATE invoice_requests SET completed_at = now() - interval '2 hours'")
    conn.commit()

    with psycopg.connect(psycopg_dsn(), autocommit=False) as work:
        _requeued, _abandoned, pruned = deriver_main.housekeeping(work, retention_seconds=3600.0)

    assert pruned == 1
    conn.rollback()
    assert scalar(conn, "SELECT count(*) FROM invoice_requests") == 0
    assert scalar(conn, "SELECT count(*) FROM invoices WHERE id = %(i)s", i=view.invoice_id) == 1


# ---------------------------------------------------------------------------
# The three copies of the protocol agree
# ---------------------------------------------------------------------------


def test_the_channel_names_agree_across_all_three_copies() -> None:
    """A drifted channel name degrades silently into polling. This is the tripwire.

    The name exists in the deriver package, in the client, and inside a PL/pgSQL
    trigger — three places, none of which can import the other two. Nothing at
    runtime would complain about a mismatch: the request would still be served,
    just a quarter of a second later, which is exactly the kind of regression
    that ships.
    """
    migration = (REPO_ROOT / "migrations" / "versions" / "0007_invoice_requests.py").read_text(
        encoding="utf-8"
    )
    assert f'CHANNEL_REQUESTS = "{deriver_requests.CHANNEL_REQUESTS}"' in migration
    assert f'REPLY_CHANNEL_PREFIX = "{deriver_requests.REPLY_CHANNEL_PREFIX}"' in migration

    assert deriver_requests.CHANNEL_REQUESTS == client_module.CHANNEL_REQUESTS
    assert deriver_requests.REPLY_CHANNEL_PREFIX == client_module.REPLY_CHANNEL_PREFIX
    sample = uuid.uuid4()
    assert deriver_requests.reply_channel(sample) == client_module.reply_channel(sample)
    assert len(client_module.reply_channel(sample)) <= 63  # PostgreSQL identifier limit


def test_the_active_account_helper_finds_the_one_account(
    conn: psycopg.Connection[Any], shop: Shop
) -> None:
    assert active_hd_account_id(conn) == shop.hd_account_id


def test_no_active_account_is_a_refusal_and_not_a_none(
    conn: psycopg.Connection[Any], shop: Shop
) -> None:
    with conn.cursor() as cur:
        cur.execute("UPDATE hd_accounts SET is_active = false")
    with pytest.raises(E.InvoiceUnavailable):
        active_hd_account_id(conn)
    conn.rollback()


def test_a_reply_decodes_to_the_same_view_the_service_returned(
    conn: psycopg.Connection[Any], shop: Shop, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """The issuer's own encoding, checked without the queue in the way.

    Keeps the failure legible: if this passes and the end-to-end test does not,
    the problem is the transport; if this fails, it is the encoding.
    """
    issuer = build_issuer(key)
    request = deriver_requests.InvoiceRequest(
        request_id=uuid.uuid4(),
        user_id=shop.user_id,
        product_id=shop.product_id,
        chain_id=shop.chain_id,
        asset_id=shop.asset_id,
        hd_account_id=shop.hd_account_id,
        attempts=1,
        requested_at=dt.datetime.now(dt.UTC),
    )
    outcome = issuer(conn, deriver, request)
    conn.rollback()

    assert isinstance(outcome, deriver_requests.IssuedInvoice)
    decoded = from_wire(json.loads(outcome.result_json))
    assert decoded.invoice_id == outcome.invoice_id
    assert decoded.address == deriver.address(decoded.hd_account_id, decoded.derivation_index)
