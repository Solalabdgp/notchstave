"""Notchstave notifier — delivery, retries, DLQ, Telegram rate limits.

Reads from the transactional outbox (``core.db.models.Notification``) written by
settler in the same transaction as the money decision — never decides anything
about money itself (TZ sections 4, 5.7).

Week 4 scope (TZ section 11 — "надёжность"): the outbox drain, the retry curve,
the dead-letter queue behind ``notchstave_dlq_size``, and the two Telegram rate
limits of TZ 5.5. The Telegram transport itself is a
:class:`notifier.sender.MessageSender` protocol with test doubles behind it; the
aiogram implementation arrives in Week 5 along with the message copy, and lands
without changing anything in this package but one factory function.
"""
