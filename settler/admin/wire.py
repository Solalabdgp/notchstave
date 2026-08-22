"""The on-the-wire form of the TZ 3.4 admin arguments and results.

The bot parses an owner command and the settler executes it (migration 0012), so
both halves of every admin call cross a process boundary as JSON in
``admin_action_requests``. This module is the only place that encoding exists, in
both directions, for the reason :mod:`core.invoicing.wire` gives for itself: an
encoder and a decoder written in two files drift, and the field they drift on
will be an amount.

**Every decimal is a string, every timestamp is ISO-8601 with an offset.** Same
two rules and the same two arguments as ``core/invoicing/wire.py``. Amounts here
are ``NUMERIC(78,0)`` balances and USD figures whose scale is part of their
meaning; ``json.dumps(Decimal('10.00'))`` is not legal without an encoder that
would have to make this choice anyway, and a float round trip through a
reconciliation report is how a drift alert acquires a rounding error. Ordinary
integers stay integers: review ids, audit ids, derivation indexes and Telegram
user ids are all far inside the 2^53 where JSON numbers are exact.

Why this codec is reflective and ``core/invoicing/wire.py`` is not
------------------------------------------------------------------

That module encodes one class with seven fields and spells every one of them
out, which is right: :class:`~core.invoicing.service.InvoiceView` carries the
address a buyer will pay and the MAC that authenticates it, so the reader of
that file should be able to see the whole tuple at once.

This module encodes four value objects with fifty fields between them, two of
which nest tuples of further value objects, and none of which authenticate
anything — ``result_json`` is a *report* on decisions the settler already
committed under its own role (migration 0012's docstring makes that argument in
full). Fifty hand-written pairs of encode/decode lines would be fifty
opportunities for the two directions to disagree about one field, and the
disagreement would be silent: a field dropped from the encoder decodes as its
dataclass default. Driving both directions off ``dataclasses.fields`` makes a
missing field a ``KeyError`` at decode time instead, and makes a field *added*
to :class:`~settler.admin.reviews.ResolutionResult` next month travel without
anybody editing this file.

The price is that the closed set of field types below is load-bearing.
:func:`encode` refuses a value it does not recognise rather than falling back to
``str()``, so a new field of an unhandled type fails in the settler's own tests
rather than arriving in the bot as the repr of an object.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import enum
import types
import typing
import uuid
from decimal import Decimal, InvalidOperation
from typing import Any, Union, cast

__all__ = ["AdminWireError", "encode", "decode", "WIRE_VERSION"]

#: Bumped when a change to this file stops old rows from decoding. It is not
#: bumped for an added field: a bot on an older deploy than the settler ignores
#: what it does not know, and a settler on an older deploy than the bot fails the
#: decode loudly at the one place that can still answer the owner.
WIRE_VERSION = 1


class AdminWireError(Exception):
    """A payload that is not the shape this module writes.

    Distinct from :class:`~settler.admin.errors.AdminError`: that hierarchy is
    about *decisions* and every member of it is something the owner can act on.
    This is a transport fault, and the bot renders it as such.
    """


# ---------------------------------------------------------------------------
# encode
# ---------------------------------------------------------------------------


def encode(value: object) -> Any:
    """One value object, or one field of one, as JSON-able Python.

    Recursive on the *value* rather than on the annotation, which is the
    asymmetry with :func:`decode` and is deliberate: at encode time the object is
    in hand and its runtime type is the truth, while at decode time all that
    survives is a dict and the annotation is the only thing left to reconstruct
    from.
    """
    if value is None:
        return None
    # Before int, and this order is the whole reason the branch exists: `bool` is
    # a subclass of `int`, and `lost_grant_race` reaching the bot as `0` would
    # still be falsy, still render correctly, and still be wrong in a way nobody
    # would find.
    if isinstance(value, bool):
        return value
    # `StrEnum` members are `str`, so `ResolutionOutcome.CREDITED` lands here and
    # travels as `"credited"` — the value the enum was declared with, which is
    # what `decode` feeds back to the class.
    if isinstance(value, str):
        return str(value)
    if isinstance(value, int):
        return value
    if isinstance(value, Decimal):
        # `str`, not `float`. See the module docstring.
        return str(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, (tuple, list)):
        return [encode(item) for item in value]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: encode(getattr(value, f.name)) for f in dataclasses.fields(value)}
    raise AdminWireError(
        f"{type(value).__name__} has no wire form. Add one here rather than "
        "letting it travel as a repr — see the module docstring."
    )


# ---------------------------------------------------------------------------
# decode
# ---------------------------------------------------------------------------


def decode[T](cls: type[T], payload: object) -> T:
    """Rebuild one dataclass from what :func:`encode` wrote.

    Every field the class declares must be present. A payload missing one is an
    error and not a default: the defaults on
    :class:`~settler.admin.reconcile.ReconcileReport` mean "nothing was found",
    and silently reading them out of a truncated reply would report a clean
    reconciliation of a chain nobody managed to read.
    """
    if not dataclasses.is_dataclass(cls):
        raise AdminWireError(f"{cls.__name__} is not a dataclass")
    if not isinstance(payload, dict):
        raise AdminWireError(f"{cls.__name__} expects an object, got {type(payload).__name__}")

    hints = typing.get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for field in dataclasses.fields(cls):
        if field.name not in payload:
            raise AdminWireError(f"{cls.__name__}.{field.name} is missing from the payload")
        kwargs[field.name] = _decode_field(
            hints[field.name], payload[field.name], f"{cls.__name__}.{field.name}"
        )
    return cast(T, cls(**kwargs))


def _decode_field(annotation: Any, value: Any, where: str) -> Any:
    origin = typing.get_origin(annotation)

    # `X | None` from PEP 604 and `Optional[X]` from `typing` are different
    # objects at runtime and `get_type_hints` can produce either depending on how
    # the field was written, so both are matched rather than one being assumed.
    if origin is Union or origin is types.UnionType:
        members = [a for a in typing.get_args(annotation) if a is not type(None)]
        if value is None:
            return None
        if len(members) != 1:
            raise AdminWireError(f"{where}: only `X | None` unions have a wire form")
        return _decode_field(members[0], value, where)

    if origin is tuple:
        args = typing.get_args(annotation)
        if len(args) != 2 or args[1] is not Ellipsis:
            raise AdminWireError(f"{where}: only homogeneous `tuple[X, ...]` has a wire form")
        if not isinstance(value, list):
            raise AdminWireError(f"{where}: expected a list, got {type(value).__name__}")
        return tuple(_decode_field(args[0], item, where) for item in value)

    if value is None:
        raise AdminWireError(f"{where}: null for a field that is not optional")

    # Before `str`: a `StrEnum` member is a `str` and must come back as the
    # member, or `ResolutionResult.outcome is ResolutionOutcome.CREDITED` — which
    # `bot.admin_texts` branches on — is False against an equal string.
    if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
        try:
            return annotation(value)
        except ValueError as exc:
            raise AdminWireError(f"{where}: {value!r} is not a {annotation.__name__}") from exc

    if annotation is bool:
        if not isinstance(value, bool):
            raise AdminWireError(f"{where}: expected a bool, got {type(value).__name__}")
        return value
    if annotation is str:
        if not isinstance(value, str):
            raise AdminWireError(f"{where}: expected a string, got {type(value).__name__}")
        return value
    if annotation is int:
        # `isinstance(True, int)` is True, so bools are excluded explicitly; a
        # JSON `true` arriving in `review_id` should be an error and not a 1.
        if isinstance(value, bool) or not isinstance(value, int):
            raise AdminWireError(f"{where}: expected an integer, got {type(value).__name__}")
        return value
    if annotation is Decimal:
        try:
            return Decimal(str(value))
        except InvalidOperation as exc:
            raise AdminWireError(f"{where}: {value!r} is not a decimal") from exc
    if annotation is uuid.UUID:
        try:
            return uuid.UUID(str(value))
        except ValueError as exc:
            raise AdminWireError(f"{where}: {value!r} is not a uuid") from exc
    if annotation is dt.datetime:
        try:
            return dt.datetime.fromisoformat(str(value))
        except ValueError as exc:
            raise AdminWireError(f"{where}: {value!r} is not an ISO-8601 timestamp") from exc

    if dataclasses.is_dataclass(annotation):
        return decode(cast(type[Any], annotation), value)

    raise AdminWireError(f"{where}: {annotation!r} has no wire form")
