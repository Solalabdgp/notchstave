# Notchstave

Telegram bot for accepting crypto payments that never holds a private key on the server — portfolio project.

## Where the private key lives

It doesn't. The server only ever holds an account-level BIP-32 extended **public** key (`xpub`). Every invoice gets its own receive address, derived deterministically from that xpub — the bot can generate an unlimited number of addresses and watch them for payments without ever being able to spend a cent from any of them. Sweeping funds to cold storage is a manual, offline step: the bot exports a CSV of addresses and balances, the owner signs the sweep transaction on a hardware wallet, and there is no automated path back from that offline perimeter into the bot. There is no seed phrase, no spending key, and no automatic outgoing transfer anywhere in this codebase — see the full architecture and threat-model spec for the reasoning (`crypto-portfolio-specs/notchstave-tz.md`, sections 4, 5.1, and 5.8/T4).

## Status

**Week 1 — skeleton only. Work in progress.** This commit is structure and configuration: six process boundaries (`bot`, `api`, `deriver`, `watcher`, `settler`, `notifier`), a shared `core/` package for the database schema, Alembic scaffolding, Docker Compose for local Postgres/Redis, and dependency pins. There is no business logic yet — every `main.py` is a stub with a `TODO` pointing at what belongs there and when.

Planned:
- **Week 2 — correctness**: confirmations, finalization, reorg handling, idempotency, access revocation.
- **Week 3 — money edge cases**: underpayment, overpayment, expiry, anomalies, manual review, refund requests, admin commands.
- **Week 4 — reliability**: RPC provider pool, circuit breaker, backoff, dead-letter queue, metrics, dashboard, alerts, second chain.
- **Week 5 — product**: invoice page with QR (EIP-681), live status, purchase history, subscriptions, derivation proof (`/verify`).
- **Week 6 — packaging**: full README (architecture diagram, threat-model table, trade-offs), deployment to Hetzner, real small-value payments on both chains.

## Git history

This repository's git history starts at this commit. There is no earlier history to import or reference — nothing here is backdated.

## Architecture (brief)

Six independently-deployable process boundaries, described in full in `crypto-portfolio-specs/notchstave-tz.md` (section 4):

| Package | Responsibility |
|---|---|
| `bot/` | Telegram I/O (aiogram). No money decisions. |
| `api/` | Invoice page / status / QR (FastAPI). No money decisions. |
| `deriver/` | Holds the account xpub in memory, derives addresses. No network access, isolated dependency set. |
| `watcher/` | One process per chain; walks blocks, extracts transfers. No money decisions. |
| `settler/` | Matches transfers to invoices, confirmations, reorgs, grants/revokes access. All money logic lives only here. |
| `notifier/` | Delivery, retries, dead-letter queue, Telegram rate limits. |
| `core/` | Shared database models and config, used by everything except `deriver`. |

## Local setup (Week 1 skeleton — nothing runs end-to-end yet)

```bash
cp .env.example .env   # fill in placeholder values; never commit .env
docker compose up -d   # Postgres + Redis
```
