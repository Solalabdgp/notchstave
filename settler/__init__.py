"""Notchstave settler — matches transfers to invoices, confirmations, reorgs,
grants/revokes access.

All money logic lives only here (TZ section 4). bot/api/watcher/deriver/notifier
must never make a money decision themselves.
"""
