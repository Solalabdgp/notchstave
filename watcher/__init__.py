"""Notchstave watcher — one process per chain, walks blocks, extracts Transfer
logs, writes raw incoming transfers.

No business logic and no money decisions live here (TZ section 4) — that is
settler's job, working only from what's already in the database.
"""
