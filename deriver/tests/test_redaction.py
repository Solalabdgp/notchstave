"""The logging filter from TZ 5.8/T4 — nothing shaped like an xpub reaches a log.

The pattern is prescribed by the TZ: ``(xpub|ypub|zpub)[1-9A-HJ-NP-Za-km-z]{100,}``.
These tests drive it through the actual ``logging`` machinery rather than
calling the regex directly, because the failure mode that matters is a record
that slips past by taking a route the filter does not cover — lazy ``%s``
arguments, a captured traceback, a child logger propagating to a root handler.
"""

from __future__ import annotations

import io
import logging

import pytest

from deriver.redaction import (
    EXTENDED_KEY_RE,
    REDACTION_PLACEHOLDER,
    ExtendedKeyFilter,
    install,
    redact,
)
from deriver.tests.test_account_addresses import TEST_ACCOUNT_XPUB


@pytest.fixture()
def captured() -> tuple[logging.Logger, io.StringIO]:
    """A logger with the filter installed, writing into a buffer."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))

    logger = logging.getLogger("deriver.tests.redaction")
    logger.handlers.clear()
    logger.filters.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    install(logger)

    yield logger, stream

    logger.handlers.clear()
    logger.filters.clear()


def test_the_pattern_matches_a_real_extended_key() -> None:
    assert EXTENDED_KEY_RE.search(TEST_ACCOUNT_XPUB)


def test_the_pattern_leaves_ordinary_prose_alone() -> None:
    """"xpub" as a word must survive — the filter runs on every record.

    A filter that mangles documentation strings and log messages about the
    concept would get switched off by whoever is debugging at 3am, which is a
    worse outcome than the redaction it provides.
    """
    prose = "loading the account xpub from systemd credentials"

    assert redact(prose) == prose


def test_a_key_in_the_message_is_redacted(captured) -> None:
    logger, stream = captured

    logger.info("about to derive from %s", TEST_ACCOUNT_XPUB)

    output = stream.getvalue()
    assert TEST_ACCOUNT_XPUB not in output
    assert REDACTION_PLACEHOLDER in output


def test_a_key_passed_as_a_lazy_argument_is_redacted(captured) -> None:
    """`record.args` is the route a naive filter misses.

    `logger.info("%s", key)` never puts the key in `record.msg`; it stays in
    `record.args` until the handler formats it.
    """
    logger, stream = captured

    logger.warning("%s", TEST_ACCOUNT_XPUB)

    assert TEST_ACCOUNT_XPUB not in stream.getvalue()


def test_a_key_inside_a_traceback_is_redacted(captured) -> None:
    """The realistic leak: a third-party library echoing its input.

    Nothing in this package puts a key into an exception, but the deriver calls
    code that does not share that discipline.
    """
    logger, stream = captured

    try:
        raise ValueError(f"bad key: {TEST_ACCOUNT_XPUB}")
    except ValueError:
        logger.exception("derivation failed")

    assert TEST_ACCOUNT_XPUB not in stream.getvalue()


def test_a_key_inside_a_container_argument_is_redacted(captured) -> None:
    """Structured payloads: dicts and lists get walked, not stringified blindly."""
    logger, stream = captured

    logger.info("config dump: %s", {"account": 1, "xpub": TEST_ACCOUNT_XPUB, "nested": [
        TEST_ACCOUNT_XPUB
    ]})

    assert TEST_ACCOUNT_XPUB not in stream.getvalue()


def test_a_key_inside_an_object_repr_is_redacted(captured) -> None:
    """A dataclass-style config object with a default repr is the classic case."""

    class LeakyConfig:
        def __repr__(self) -> str:
            return f"LeakyConfig(xpub={TEST_ACCOUNT_XPUB!r})"

    logger, stream = captured

    logger.info("settings: %s", LeakyConfig())

    assert TEST_ACCOUNT_XPUB not in stream.getvalue()


def test_ypub_and_zpub_are_covered(captured) -> None:
    """The TZ names all three prefixes; the deriver rejects the latter two as
    input, but they must still never be logged if one arrives."""
    logger, stream = captured

    for prefix in ("ypub", "zpub"):
        logger.info("key: %s", prefix + TEST_ACCOUNT_XPUB[4:])

    output = stream.getvalue()
    assert TEST_ACCOUNT_XPUB[4:] not in output
    assert output.count(REDACTION_PLACEHOLDER) == 2


def test_records_are_never_dropped(captured) -> None:
    """The filter redacts; it must not swallow the log line itself."""
    logger, stream = captured

    logger.info("plain message with no secrets")

    assert "plain message with no secrets" in stream.getvalue()


def test_the_filter_never_raises() -> None:
    """A logging filter that throws turns a diagnostic into an outage."""

    class Exploding:
        def __str__(self) -> str:
            raise RuntimeError("boom")

        __repr__ = __str__

    record = logging.LogRecord(
        name="x", level=logging.INFO, pathname=__file__, lineno=1,
        msg="%s", args=(Exploding(),), exc_info=None,
    )

    assert ExtendedKeyFilter().filter(record) is True


def test_install_is_idempotent() -> None:
    """Called from several entry points; must not stack duplicate filters."""
    logger = logging.getLogger("deriver.tests.redaction.idempotent")
    logger.filters.clear()

    install(logger)
    install(logger)
    install(logger)

    assert sum(isinstance(f, ExtendedKeyFilter) for f in logger.filters) == 1


def test_redaction_survives_a_key_embedded_in_surrounding_text() -> None:
    """Keys rarely appear alone; they appear inside a sentence or a URL."""
    text = f"GET /debug?key={TEST_ACCOUNT_XPUB}&index=0 failed"

    redacted = redact(text)

    assert TEST_ACCOUNT_XPUB not in redacted
    assert redacted.startswith("GET /debug?key=")
    assert redacted.endswith("&index=0 failed")
