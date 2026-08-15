"""Notchstave notifier — delivery, retries, DLQ, Telegram rate limits.

Reads from the transactional outbox (core.db.models.Notification) written by
settler in the same transaction as the money decision — never decides
anything about money itself (TZ section 4, 5.7).
"""
