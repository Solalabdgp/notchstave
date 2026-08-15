"""Notchstave deriver — holds the account-level xpub in memory, derives
BIP-32/44 addresses by index. Nothing else.

Architecturally isolated on purpose (TZ 4, 5.8/T4 — the core threat model of
this project): this package MUST NOT depend on any network library (no
httpx/aiohttp/web3/redis-client/celery imports) and MUST NOT import from
bot/api/watcher/settler/notifier or share a module with them. It only ever
emits addresses and derivation indexes outward; nothing calls back in except
in-process. See deriver/pyproject.toml for the enforced, minimal dependency
set (bip-utils, coincurve, pydantic — nothing else).

In production the xpub arrives via systemd `LoadCredential=` on
notchstave-deriver.service only; no other unit gets it.
"""
