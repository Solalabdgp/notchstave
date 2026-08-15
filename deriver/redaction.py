"""Global logging filter that strips extended keys from anything logged.

TZ 5.8/T4 asks for exactly this, and specifies the pattern:
``(xpub|ypub|zpub)[1-9A-HJ-NP-Za-km-z]{100,}``.

The primary defence is that no code in this package puts an xpub into a string
in the first place (see :mod:`deriver.derivation`). This module is the backstop
for what nobody controls directly: a third-party library echoing its input in
an exception, a ``logging.exception`` call capturing that traceback, a config
dump during debugging.

Design notes:

* The filter rewrites ``record.msg``, ``record.args`` and any pre-rendered
  ``exc_text``. Rewriting only the final formatted string would be too late for
  handlers that re-format the record themselves.
* Tracebacks need care. At filter time ``record.exc_text`` is normally empty —
  ``logging.Formatter`` renders ``exc_info`` into it *after* filters have run,
  so redacting only the existing ``exc_text`` misses every traceback, which is
  the single most likely place for a third-party library to echo a key back.
  The filter therefore renders the traceback itself, redacts it, and stores the
  result; ``Formatter.format`` then reuses that cached text instead of
  rendering the raw exception again.
* It never raises. A logging filter that can throw turns a diagnostic into an
  outage, and this one runs on every record in the process.
* It is installed at handler level *and* at logger level, because a record can
  reach a handler without passing a logger filter when it propagates from a
  child logger.
"""

from __future__ import annotations

import logging
import re
import traceback
from typing import Any

__all__ = ["EXTENDED_KEY_RE", "REDACTION_PLACEHOLDER", "redact", "ExtendedKeyFilter", "install"]

#: Verbatim from TZ 5.8/T4. The character class is the Base58 alphabet (no
#: 0, O, I, l). A mainnet extended key is 111-112 characters, so the {100,}
#: bound matches a whole key while being long enough that ordinary prose
#: containing the word "xpub" is left alone.
EXTENDED_KEY_RE = re.compile(r"(?:xpub|ypub|zpub)[1-9A-HJ-NP-Za-km-z]{100,}")

REDACTION_PLACEHOLDER = "<redacted:extended-key>"


def redact(value: Any) -> Any:
    """Replace every extended key inside ``value`` with a placeholder.

    Recurses into the containers that realistically show up in ``record.args``
    and in structured log payloads. Anything else is converted only if its
    ``str()`` actually contains a key, so ordinary objects keep their identity
    (and are not stringified for no reason).
    """
    if isinstance(value, str):
        return EXTENDED_KEY_RE.sub(REDACTION_PLACEHOLDER, value)
    if isinstance(value, bytes):
        try:
            decoded = value.decode("ascii")
        except UnicodeDecodeError:
            return value
        redacted = EXTENDED_KEY_RE.sub(REDACTION_PLACEHOLDER, decoded)
        return redacted.encode("ascii") if redacted != decoded else value
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {redact(k): redact(v) for k, v in value.items()}

    # Fall-through: an arbitrary object whose repr leaks a key (a config object
    # with a default dataclass repr is the realistic case). Only substitute when
    # there is something to substitute, so normal objects are not flattened.
    try:
        text = str(value)
    except Exception:  # noqa: BLE001 - a broken __str__ must not break logging
        return value
    if EXTENDED_KEY_RE.search(text):
        return EXTENDED_KEY_RE.sub(REDACTION_PLACEHOLDER, text)
    return value


class ExtendedKeyFilter(logging.Filter):
    """Rewrites records in place; never drops them and never raises."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(record.msg)
            if record.args:
                record.args = redact(record.args)

            # Render the traceback here, redacted, and let the formatter reuse
            # it. See the module docstring: waiting for `exc_text` to be
            # populated means never redacting a traceback at all.
            if record.exc_info and not record.exc_text:
                record.exc_text = redact("".join(traceback.format_exception(*record.exc_info)))
            elif record.exc_text:
                record.exc_text = redact(record.exc_text)
            if getattr(record, "stack_info", None):
                record.stack_info = redact(record.stack_info)
        except Exception:  # noqa: BLE001 - see module docstring
            pass
        return True


def install(logger: logging.Logger | None = None) -> ExtendedKeyFilter:
    """Attach the filter to ``logger`` (root by default) and to its handlers.

    Idempotent: calling it twice does not stack duplicate filters.
    """
    target = logger if logger is not None else logging.getLogger()

    for existing in target.filters:
        if isinstance(existing, ExtendedKeyFilter):
            key_filter = existing
            break
    else:
        key_filter = ExtendedKeyFilter()
        target.addFilter(key_filter)

    for handler in target.handlers:
        if not any(isinstance(f, ExtendedKeyFilter) for f in handler.filters):
            handler.addFilter(key_filter)

    return key_filter
