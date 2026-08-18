"""When to try again, and when to stop trying.

Two decisions, one function each, both pure. They are here rather than inline in
:mod:`notifier.service` because "after N failures the row goes to the DLQ" is a
policy sentence out of TZ 5.5 and deserves to be readable and testable as one —
the same split :mod:`settler.policy` makes between deciding and applying.
"""

from __future__ import annotations

import random

from notifier.config import NotifierConfig

__all__ = ["next_delay_seconds", "is_exhausted"]


def next_delay_seconds(
    attempts: int,
    config: NotifierConfig,
    *,
    retry_after: float | None = None,
    rng: random.Random | None = None,
) -> float:
    """Seconds to wait before attempt ``attempts + 1``.

    ``attempts`` is the count *already consumed*, so the first failure computes
    the delay for the second try with ``attempts == 1``.

    ``retry_after`` — Telegram's own 429 answer — wins outright over the curve.
    Not ``max(curve, retry_after)``: the server has told us exactly how long the
    limit lasts, and stretching that with an exponential guess delays a message
    about money for no reason. Not ``min`` either, obviously — undercutting it
    is how a temporary limit gets extended.

    Jitter is multiplicative and one-sided-symmetric around the curve value.
    Every notification produced during one Telegram outage was queued within
    seconds of every other, so an unjittered curve retries the whole batch at
    the same instants for as long as the outage lasts.
    """
    if retry_after is not None:
        return max(0.0, retry_after)

    exponent = max(0, attempts - 1)
    # Cap the exponent before the shift, not the result after it: 2 ** 4000 is
    # a real computation that finishes, slowly, and produces an integer nobody
    # wants. `attempts` comes from a database column that a human with
    # `/dlq requeue` can set.
    exponent = min(exponent, 32)
    raw = min(config.backoff_base_seconds * (2.0**exponent), config.backoff_max_seconds)
    if config.backoff_jitter <= 0.0:
        return raw
    source = rng or random
    factor = 1.0 + source.uniform(-config.backoff_jitter, config.backoff_jitter)
    return max(0.0, raw * factor)


def is_exhausted(attempts: int, config: NotifierConfig) -> bool:
    """Has the retry budget run out? (TZ 5.5 "после N неудач — DLQ".)

    ``>=`` and not ``>``: ``attempts`` is incremented at claim time, so by the
    moment a failure is being recorded the attempt in hand is already counted.
    With ``max_attempts = 6`` the message is tried six times and then retired.
    """
    return attempts >= config.max_attempts
