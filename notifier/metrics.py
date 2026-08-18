"""Prometheus families owned by the notifier (TZ section 7).

One metric in this file is named in the TZ — ``notchstave_dlq_size`` — and the
rest exist because a DLQ gauge on its own answers "is delivery broken" and
nothing about why.

The one-owner rule that :mod:`core.metrics` documents applies here too: nothing
below is declared anywhere else in the repo, and ``notchstave_dlq_size`` in
particular must stay a notifier metric. The settler writes the outbox rows and
could count them, but it is the notifier that knows a row is undeliverable, and
a family declared in two processes reads differently depending on which one
scraped last.

**Why the DLQ is a Gauge and not a Counter.** A counter would answer "how many
messages have ever died", which is the wrong question in both directions: it
resets to zero when this process restarts, and it keeps climbing after an
operator has drained the queue, so the alert stays red once it has been red
once. The size of the dead-letter queue is a *current* quantity that human
action reduces — the same argument :data:`settler.metrics.RECONCILE_DRIFT_USD`
makes for being a gauge, for the same reason. It is set from ``SELECT count(*)``
on every pass, including passes that find zero: writing an explicit zero is what
separates "nothing is stuck" from "the notifier has not run since the last
restart", which look identical on a gauge that is only touched when something is
wrong.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

__all__ = [
    "DLQ_SIZE",
    "NOTIFICATIONS_SENT",
    "NOTIFICATIONS_DEAD",
    "DELIVERY_ATTEMPTS",
    "DELIVERY_SECONDS",
    "RATE_LIMIT_WAIT_SECONDS",
    "USERS_BLOCKED",
]

#: TZ section 7, named there verbatim. Rows in ``notifications`` with
#: ``status = 'dead'``: retries exhausted, or permanently undeliverable. Every
#: one of them is a message about somebody's money that never arrived.
DLQ_SIZE = Gauge(
    "notchstave_dlq_size",
    "Notifications in the dead-letter queue, awaiting manual triage (TZ 5.5, 7).",
)

NOTIFICATIONS_SENT = Counter(
    "notchstave_notifications_sent_total",
    "Messages delivered to Telegram, by outbox kind.",
    ["kind"],
)

#: Split by reason because the two populations need different responses and
#: would otherwise be one indistinguishable number under ``dlq_size``:
#: ``retries_exhausted`` is an outage or a bug, ``bot_blocked`` is a buyer who
#: will not receive their receipt, ``no_renderer`` is a kind the settler
#: enqueues that this process does not know how to say.
NOTIFICATIONS_DEAD = Counter(
    "notchstave_notifications_dead_total",
    "Notifications retired into the DLQ, by reason.",
    ["reason"],
)

DELIVERY_ATTEMPTS = Counter(
    "notchstave_notification_attempts_total",
    "Delivery attempts, by result (sent / transient / permanent).",
    ["result"],
)

#: The delivery half of TZ section 7's latency story — ``payment_detect_seconds``
#: and ``payment_credit_seconds`` belong to the watcher and the settler, and this
#: is what happens after them. Measured from ``notifications.created_at``, i.e.
#: from the commit of the money decision, not from the claim: the queue wait is
#: the part worth seeing.
DELIVERY_SECONDS = Histogram(
    "notchstave_notification_delivery_seconds",
    "Seconds from the outbox row being committed to the message being delivered.",
    buckets=(0.5, 1, 2, 5, 15, 30, 60, 300, 900, 3600),
)

#: How much of the delivery latency above is the process obeying Telegram rather
#: than waiting on it. A rising value is not a fault — it is the rate limiter
#: working, and the signal that one bot token has become the bottleneck.
RATE_LIMIT_WAIT_SECONDS = Histogram(
    "notchstave_notification_rate_limit_wait_seconds",
    "Seconds spent waiting on the Telegram rate limiter before a send (TZ 5.5).",
    buckets=(0.001, 0.01, 0.05, 0.1, 0.5, 1, 2, 5, 30),
)

USERS_BLOCKED = Counter(
    "notchstave_users_bot_blocked_total",
    "Users newly marked as having blocked the bot (TZ 5.5).",
)
