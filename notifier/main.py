# TODO: Week 1 — drain core.db.models.Notification (status='queued') via
# Celery and deliver through the bot's Telegram session for the single
# testnet happy path. Per TZ section 11 Week 1 scope: simplest delivery only,
# no retry policy yet.
#
# Later weeks: retries with backoff, dead-letter queue for exhausted attempts
# (status='dead'), Telegram rate-limit handling, circuit breaker alongside the
# RPC pool work (Week 4).
#
# Hard rule for every week: notifier makes zero money decisions — it only
# delivers what settler already decided and recorded (TZ section 4).
