"""TZ 5.8/T1 — address substitution, and the two checks that make it loud.

TZ section 8 lists four T1 tests. Three of them are the invoicing service's:

* подмена ``address`` в БД мимо deriver ловится на ``deriver.verify`` — инвойс не
  выдаётся, метрика растёт;
* правка ``amount_due_raw`` в БД ломает ``integrity_mac`` и блокирует;
* адрес совпадает символ в символ в трёх каналах — сообщение бота, ответ API,
  строка EIP-681 в QR;
* ``/status`` по чужому идентификатору не отдаёт чужие данные.

The fourth belongs to the api's HTTP layer; what this module can prove — and
does, below — is that the service never hands out a view for an invoice the
caller does not own, which is the half a route handler cannot get wrong later.
"""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal
from typing import Any

import psycopg
import pytest

from core.invoicing import errors
from core.invoicing.config import InvoicingPolicy
from core.invoicing.integrity import IntegrityKey, canonical_payload, compute_mac
from core.invoicing.metrics import ADDRESS_MISMATCH, MAC_FAILURES
from core.invoicing.service import (
    load_invoice_by_public_token,
    verify_invoice_address,
)
from core.invoicing.tests.conftest import (
    FakeDeriver,
    World,
    buy,
    counter_value,
    scalar,
)

ATTACKER = "0x" + "ba" * 20


def test_a_verified_invoice_round_trips(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """The control case: an untouched invoice passes both checks."""
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    created = buy(conn, deriver, key, shop)

    loaded = verify_invoice_address(conn, deriver, key, created.invoice_id)

    assert loaded.address == created.address
    assert loaded.amount_due_raw == created.amount_due_raw
    assert loaded.integrity_mac == created.integrity_mac
    assert loaded.eip681() == created.eip681()


def test_editing_the_address_in_the_database_blocks_the_invoice(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 5.8/T1, vector 1 — the compromised replica.

    This is the attack the whole countermeasure set is ordered around: an
    attacker with SQL write access runs ``UPDATE ... SET address = '0xАтакующий'``
    and the buyer pays them, while the watcher — which listens to
    ``receive_addresses`` — never sees a thing. Re-deriving is what turns a
    silent theft into a refusal, because after ``verify`` an address can no
    longer be *declared*, only *derived*.
    """
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    view = buy(conn, deriver, key, shop)
    before = counter_value(ADDRESS_MISMATCH)

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE receive_addresses SET address = %(a)s WHERE id = %(id)s",
            {"a": ATTACKER, "id": view.address_id},
        )

    with pytest.raises(errors.AddressMismatch) as caught:
        verify_invoice_address(conn, deriver, key, view.invoice_id)

    assert caught.value.invoice_id == view.invoice_id
    assert counter_value(ADDRESS_MISMATCH) - before == 1
    # The buyer is told not to pay, and is not shown the address that failed.
    assert "do not send" in caught.value.user_message.lower()
    assert ATTACKER not in caught.value.user_message


def test_a_tampered_address_is_caught_at_issuance_too_not_only_at_display(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """T1.1 applies to the pool row an invoice is about to be built on.

    The display-time check protects invoices that already exist. This one covers
    the window before that: a pool row written by something other than the
    deriver must not become an invoice in the first place, or the refusal
    arrives one message too late.
    """
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    with conn.cursor() as cur:
        cur.execute("UPDATE receive_addresses SET address = %(a)s", {"a": ATTACKER})
    before = counter_value(ADDRESS_MISMATCH)

    with pytest.raises(errors.AddressMismatch):
        buy(conn, deriver, key, shop)

    assert counter_value(ADDRESS_MISMATCH) - before == 1
    conn.rollback()
    assert scalar(conn, "SELECT count(*) FROM invoices") == 0


def test_editing_amount_due_raw_breaks_the_mac(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ section 8, T1, second bullet.

    The address still derives perfectly here — that is the point. Re-derivation
    says nothing about the amount, the chain, the asset or the deadline, and an
    attacker who can write the database can profitably edit any of them. The MAC
    is the cover for the rest of the significant tuple, which is why the two
    checks are both mandatory rather than redundant.
    """
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    view = buy(conn, deriver, key, shop)
    before = counter_value(MAC_FAILURES)

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE invoices SET amount_due_raw = amount_due_raw + 1 WHERE id = %(id)s",
            {"id": view.invoice_id},
        )

    with pytest.raises(errors.MacMismatch):
        verify_invoice_address(conn, deriver, key, view.invoice_id)

    assert counter_value(MAC_FAILURES) - before == 1
    # Derivation was fine; only the MAC moved. The two counters are not
    # interchangeable and the dashboard reads them differently.
    assert deriver.verify(view.address, view.hd_account_id, view.derivation_index)


def test_editing_the_deadline_also_breaks_the_mac(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """``expires_at`` is in the tuple for a reason worth having a test for.

    Extending a deadline in the database turns an expired invoice back into a
    payable one at a rate that is no longer honoured (TZ 5.5) — a quiet edit
    with a real cash value, and invisible to a check that only looked at the
    address.
    """
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    view = buy(conn, deriver, key, shop)

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE invoices SET expires_at = expires_at + interval '1 hour', "
            "topup_window_until = topup_window_until + interval '1 hour' "
            "WHERE id = %(id)s",
            {"id": view.invoice_id},
        )

    with pytest.raises(errors.MacMismatch):
        verify_invoice_address(conn, deriver, key, view.invoice_id)


def test_the_address_is_identical_in_all_three_channels(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ section 8, T1, third bullet — "символ в символ".

    This is the only integrity check a *buyer* can perform: they have no xpub
    and cannot build a derivation proof (T4 forbids publishing the key), so what
    is left to them is that the bot message, the API response and the EIP-681
    string inside the QR agree. That check only works if all three come from one
    value, which is what :meth:`InvoiceView.eip681` guarantees by construction.
    """
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    created = buy(conn, deriver, key, shop)
    reloaded = verify_invoice_address(conn, deriver, key, created.invoice_id)

    stored = scalar(
        conn,
        "SELECT ra.address FROM invoices i JOIN receive_addresses ra ON ra.id = i.address_id "
        "WHERE i.id = %(id)s",
        id=created.invoice_id,
    )

    bot_channel = created.address
    api_channel = reloaded.address
    qr_channel = reloaded.eip681()

    assert bot_channel == api_channel == stored
    assert f"address={bot_channel}" in qr_channel
    assert f"uint256={created.amount_due_raw}" in qr_channel
    assert f"@{created.chain_id}/transfer" in qr_channel
    assert qr_channel.startswith(f"ethereum:{shop.asset_contract}")


def test_status_for_someone_elses_invoice_is_not_found_and_not_forbidden(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 5.8/T1.7 — the IDOR guard, and why the status code matters.

    A 403 confirms that the id exists, which is the single bit an enumeration
    attempt is trying to buy. So an invoice belonging to somebody else is
    reported exactly as an invoice that never existed.
    """
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    view = buy(conn, deriver, key, shop)
    stranger = world.user()

    with pytest.raises(errors.InvoiceNotFound) as theirs:
        verify_invoice_address(conn, deriver, key, view.invoice_id, expected_user_id=stranger)

    with pytest.raises(errors.InvoiceNotFound) as nobodys:
        verify_invoice_address(conn, deriver, key, uuid.uuid4(), expected_user_id=stranger)

    assert theirs.value.user_message == nobodys.value.user_message

    # And the owner still gets it.
    assert (
        verify_invoice_address(
            conn, deriver, key, view.invoice_id, expected_user_id=shop.user_id
        ).address
        == view.address
    )


def test_the_public_token_opens_the_page_and_stops_working_after_the_topup_window(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 6 — "TTL = срок жизни инвойса + окно доплаты"."""
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    policy = InvoicingPolicy(
        invoice_ttl=dt.timedelta(minutes=15), topup_window=dt.timedelta(hours=24)
    )
    view = buy(conn, deriver, key, shop, policy=policy)

    inside = load_invoice_by_public_token(conn, deriver, key, view.public_token)
    assert inside.invoice_id == view.invoice_id

    with pytest.raises(errors.InvoiceNotFound):
        load_invoice_by_public_token(
            conn,
            deriver,
            key,
            view.public_token,
            now=view.topup_window_until + dt.timedelta(seconds=1),
        )

    with pytest.raises(errors.InvoiceNotFound):
        load_invoice_by_public_token(conn, deriver, key, "not-a-real-token")


def test_the_public_page_runs_the_same_two_checks_as_the_bot(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """TZ 5.8/T1.3 names three verification points; two of them are here.

    A token-keyed lookup that skipped the checks would be a hole with a public
    URL in front of it, so both entry points funnel through one private
    function rather than each doing its own version.
    """
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    view = buy(conn, deriver, key, shop)

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE receive_addresses SET address = %(a)s WHERE id = %(id)s",
            {"a": ATTACKER, "id": view.address_id},
        )

    with pytest.raises(errors.AddressMismatch):
        load_invoice_by_public_token(conn, deriver, key, view.public_token)


def test_an_integrity_failure_is_not_catchable_as_a_temporary_problem(
    conn: psycopg.Connection[Any], world: World, deriver: FakeDeriver, key: IntegrityKey
) -> None:
    """The hierarchy is load-bearing.

    A route handler that catches :class:`InvoiceUnavailable` to say "try again
    later" must not accidentally catch a suspected compromise and tell the buyer
    to retry into it.
    """
    shop = world.shop(pooled_addresses=1, deriver=deriver)
    view = buy(conn, deriver, key, shop)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE receive_addresses SET address = %(a)s WHERE id = %(id)s",
            {"a": ATTACKER, "id": view.address_id},
        )

    with pytest.raises(errors.IntegrityFailure):
        try:
            verify_invoice_address(conn, deriver, key, view.invoice_id)
        except errors.InvoiceUnavailable:  # pragma: no cover - must not happen
            pytest.fail("an integrity failure was swallowed by the 'try again later' handler")


# ---------------------------------------------------------------------------
# The MAC itself
# ---------------------------------------------------------------------------


def test_the_canonical_payload_cannot_be_confused_between_fields(
    key: IntegrityKey,
) -> None:
    """Length-prefixing, and the reason it is not decoration.

    Plain concatenation makes ``chain_id=1, asset_id=23`` and ``chain_id=12,
    asset_id=3`` the same bytes, so one MAC authenticates both — an attacker who
    can move a digit across a field boundary keeps a valid signature. The four
    bytes per field that stop it are the cheapest fix in this codebase.
    """
    invoice_id = uuid.uuid4()
    expires = dt.datetime(2026, 8, 19, 12, 0, tzinfo=dt.UTC)
    common: dict[str, Any] = {
        "invoice_id": invoice_id,
        "address": "0x" + "ab" * 20,
        "amount_due_raw": Decimal(10),
        "expires_at": expires,
    }

    first = canonical_payload(chain_id=1, asset_id=23, **common)
    second = canonical_payload(chain_id=12, asset_id=3, **common)

    assert first != second
    assert key.mac(first) != key.mac(second)


def test_the_mac_survives_the_representations_postgres_hands_back(
    key: IntegrityKey,
) -> None:
    """Normalisation, tested at the two places it silently bites.

    ``NUMERIC(78,0)`` can come back as ``Decimal('1E+7')`` after arithmetic and
    ``timestamptz`` renders in the session's time zone. Both name the same value
    as their canonical form and must produce the same MAC, or an invoice would
    start failing its own integrity check depending on how it was read.
    """
    invoice_id = uuid.uuid4()
    args: dict[str, Any] = {
        "invoice_id": invoice_id,
        "chain_id": 8453,
        "asset_id": 1,
        "address": "0x" + "cd" * 20,
    }

    plain = compute_mac(
        key,
        amount_due_raw=Decimal("10000000"),
        expires_at=dt.datetime(2026, 8, 19, 12, 0, tzinfo=dt.UTC),
        **args,
    )
    exponent_and_other_zone = compute_mac(
        key,
        amount_due_raw=Decimal("1E+7"),
        expires_at=dt.datetime(
            2026, 8, 19, 15, 0, tzinfo=dt.timezone(dt.timedelta(hours=3))
        ),
        **args,
    )
    assert plain == exponent_and_other_zone


def test_a_different_key_does_not_verify(key: IntegrityKey) -> None:
    """The obvious property, stated because the whole measure rests on it."""
    other = IntegrityKey(b"a-completely-different-integrity-key")
    payload = canonical_payload(
        invoice_id=uuid.uuid4(),
        chain_id=8453,
        asset_id=1,
        address="0x" + "ef" * 20,
        amount_due_raw=Decimal(1),
        expires_at=dt.datetime(2026, 8, 19, 12, 0, tzinfo=dt.UTC),
    )
    assert not other.verify(payload, key.mac(payload))


def test_the_key_never_prints_itself() -> None:
    """TZ 5.8/T4 — the concrete failure is a key in an assertion diff."""
    secret = b"super-secret-integrity-key-value"
    loaded = IntegrityKey(secret)
    assert secret.decode() not in repr(loaded)
    assert secret.decode() not in str(loaded)
    assert secret.decode() not in f"{loaded}"
