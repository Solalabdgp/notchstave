# Notchstave

A Telegram bot that accepts on-chain crypto payments (USDC on Base, EVM-mainnet-compatible) and grants access to digital products after confirmation — without ever holding a spending key on the server.

**Status: portfolio / demonstration project, not a live payment service.** See [What's not in this project, and why](#whats-not-in-this-project-and-why) — no KYC/AML, no custody beyond the time it takes to confirm and sweep a payment, no automated outgoing transfers of any kind.

**Screenshot:** TODO — a walkthrough of `/buy` → invoice page → confirmation has not been captured yet.

**Live bot:** not deployed yet. Weeks 1–5 of the build (skeleton, correctness, money handling, reliability, product surface) are in this repository; deployment, a live small-value payment run on both chains, and the operational history that Grafana would show are Week 6 work and have not happened. This README describes what the code does today, not what a running deployment would show.

---

## Where the private key lives

It doesn't. Nowhere in this codebase does a private key, a seed phrase, or anything capable of signing a transaction exist.

The server holds exactly one secret of consequence: an account-level BIP-32 extended **public** key (`xpub`), exported once, offline, from a hardware wallet at the non-hardened path `m/44'/60'/0'`. Everything downstream of that key is address generation, not spending. `deriver/derivation.py` is the only module that touches this key, and it does one thing: turn `xpub` + an index into `m/44'/60'/0'/0/i` → an EVM address, the same computation any watch-only wallet does. The module actively refuses to accept a private key or a master-level key if one is handed to it — see `deriver/derivation.py`'s `PrivateKeyMaterialRejected` and `NotAnAccountXpub` checks — and no exception it raises is allowed to carry key material into a log line or a traceback.

Every invoice gets its own address this way. The bot can issue an effectively unlimited number of receive addresses and watch every one of them for incoming transfers, and there is no code path — anywhere in `bot/`, `api/`, `watcher/`, or `settler/` — capable of spending from any of them. That isn't a policy; it's an absence. `deriver/tests/test_isolation.py` asserts, mechanically, that the process holding the xpub has no network-capable import in its dependency closure, and in production that process (`notchstave-deriver.service`) is additionally sandboxed at the systemd level with `IPAddressDeny=any`.

Getting funds out is a manual, offline act: the owner runs `/sweeplist`, gets a CSV of derivation indices and balances, and signs a sweep transaction on the hardware wallet. Nothing in this repository automates that step, and section 12 below explains why that's a permanent constraint, not a v1 shortcut.

```
                    ┌────────────────┐
   Telegram ───────►│  bot           │  aiogram — user I/O only
                    └───────┬────────┘
                            │
   Browser ───────►┌───────┴────────┐
   (invoice page)   │  api           │  FastAPI — invoice page, status, QR
                    └───────┬────────┘
                            │
      ┌─────────────────────┼─────────────────────┬──────────────────┐
      │                     │                     │                  │
┌─────┴───────┐   ┌─────────┴────────┐  ┌─────────┴───────┐  ┌───────┴──────┐
│  deriver    │   │  watcher         │  │  settler        │  │  notifier    │
│  xpub → addr│   │  blocks →        │  │  money → fact:   │  │  delivery,   │
│  ONLY holds │   │  transfers, one  │  │  confirmations,  │  │  retries,    │
│  the pubkey │   │  process/chain   │  │  reorgs, grants  │  │  DLQ         │
└─────┬───────┘   └─────────┬────────┘  └─────────┬───────┘  └───────┬──────┘
      │                     │                     │                  │
      └─────────────────────┴──────────┬──────────┴──────────────────┘
                                       │
                        ┌──────────────┴──────────────┐
                        │   PostgreSQL   +   Redis     │
                        └───────────────────────────────┘

           ┌───────────────────────────────────────────────────┐
           │  OFFLINE, OUTSIDE THE SYSTEM PERIMETER              │
           │  owner's hardware wallet, private key,              │
           │  sweep transaction signed here                      │
           └───────────────────────────────────────────────────┘
                    ▲
                    │  CSV from /sweeplist only, one direction,
                    │  no channel back in
```

---

## Architecture

Six independently deployable processes, each with a role narrow enough to state in one sentence, and each running under its own PostgreSQL role with the minimum grants that role needs (migration `0002_roles_and_grants.py`):

| Process | Job | Makes money decisions? | Holds the xpub? |
|---|---|---|---|
| `bot/` | Telegram I/O — the seven buyer commands, four owner commands | No | No |
| `api/` | Invoice page, live status, QR, Telegram Mini App auth | No | No |
| `deriver/` | Derives addresses from the xpub; answers invoice-issuance and derivation-proof requests | No (issues addresses; the settler decides what's paid) | Yes — the only one |
| `watcher/` | One process per chain; walks blocks, extracts `Transfer` logs, detects reorgs | No | No |
| `settler/` | Matches payments to invoices, applies the money policy table, grants/revokes access | Yes — the only one | No |
| `notifier/` | Delivers messages from an outbox: retries, backoff, DLQ, Telegram rate limits | No | No |

`deriver` cannot import `core` (enforced by `deriver/pyproject.toml`'s own dependency set, not just convention), so the business logic that decides *whether* to issue an invoice — quotas, pricing, the integrity MAC — is injected into it from `core.invoicing` at process start. The seam exists so the one process holding key material stays, mechanically, unable to import anything that knows what a purchase is.

---

## Technical decisions

One paragraph per TZ §5 topic, and why it's built this way rather than the obvious alternative.

**HD derivation without a private key (§5.1).** Covered above and in `deriver/derivation.py`. The one thing worth adding here: the library choice is deliberate. Address derivation is implemented on top of `bip_utils` (pinned in `deriver/pyproject.toml`) rather than hand-rolled elliptic-curve arithmetic, because a bug in point arithmetic doesn't raise an exception — it silently produces a valid-looking address whose private key doesn't exist, and any payment sent to it is gone. The derivation is checked against the official BIP-32 test vectors in `deriver/tests/`.

**Payment detection (§5.2).** `watcher/` walks blocks from a checkpoint to the head, verifying each block's `parent_hash` against the one already stored before writing it (`watcher/traversal.py`). For ERC-20 transfers this means `eth_getLogs` filtered on the token contract and `Transfer`'s topic, with the recipient addresses batched into the topic array — one request covers many addresses at once, chunked by block range and address-group size because every provider caps both. Native-asset transfers are the harder case: a transfer initiated by a contract (an exchange withdrawal, a smart-contract wallet) never appears in a block's transaction list — only in an internal trace, which needs `debug_traceBlock` and isn't available on free RPC tiers. USDC is the default asset specifically because it sidesteps this: every USDC transfer is a logged `Transfer` event, full stop.

**Invoice matching (§5.3).** Because every invoice has its own address, matching is a lookup, not a heuristic — `to` on a log resolves to an address row, which resolves to an invoice, with no ambiguity between two invoices that happen to share an amount. What isn't trivial is keeping that link from being edited after the fact: `payments.invoice_id` is written once, at insert, and a trigger rejects any later `UPDATE` on a non-null value (see `migrations/versions/0001_initial.py`) — there is no function anywhere in this codebase that reassigns a payment to a different invoice. A disputed payment becomes a `manual_reviews` row and a separate, explicit credit, never a rewritten link.

*The alternative that was rejected: one shared address plus a unique micro-amount.* A common way to avoid per-invoice derivation is a single receive address, where the invoice amount's trailing digits (e.g. `10.004217`) act as an identifier. It was considered and set aside for four concrete reasons: it needs a lock and an exclusivity window to avoid two simultaneous invoices colliding on the same tail digits, where a unique address gives 2³² identifiers for free; an exchange withdrawal that rounds the amount or deducts a fee destroys the identifying digits and turns the payment into an unmatched one; every buyer's payment lands on the same address, so anyone can read the project's total revenue off-chain; and two same-amount payments landing in one block need a tie-breaking heuristic, which is exactly the kind of ambiguity money logic shouldn't have. A third option — a receiving smart contract that takes an invoice ID in calldata — avoids the collision problem but needs a contract deployment, raises gas for the buyer, and breaks entirely for a withdrawal from an exchange, which can't attach calldata. Per-invoice HD derivation costs one thing in exchange for avoiding all four problems: doing address derivation correctly — which is the one thing this whole project is built to demonstrate anyway.

**Confirmations and reorgs (§5.4).** `blocks.status` moves `pending → confirmed` only after `chains.min_confirmations`, and a reorg is detected the same way any chain-following process detects one: walking backwards until a stored block's hash matches the provider's hash at that height, then marking every block above the common ancestor `orphaned`. What's specific to a payment system rather than a tracker: confirmation depth depends on the amount. Below `credit_threshold_usd` (default $20) a payment settles at `min_confirmations`; above it, the settler waits for the chain's `finalized` tag rather than counting blocks — a block count on an OP-stack sequencer like Base means little until the batch actually reaches L1 (`settler/confirmations.py`). If a payment is credited and access already granted, and the block it depended on turns out to be orphaned, the entitlement is revoked — `entitlements.revoked_at` — and the buyer gets a correction message. There's an honest gap here, recorded as a `TODO` in `watcher/traversal.py` and `settler/confirmations.py` rather than hidden: the schema has no column for "the height the chain considers finalized," so a `finalized`-tag chain is read as `blocks.status = 'confirmed'` meaning *the watcher asserts this block is final* — correct, but it means a reader can't later distinguish "buried under N blocks" from "actually finalized on L1." A dedicated `chains.last_finalized_block` column is the right fix and is scheduled, not shipped.

**Underpayment, overpayment, and the rest (§5.5).** The full policy is a pure function — `settler/policy.py`'s `classify()` — deliberately free of any database access, so the whole table can be read and tested on one screen instead of reconstructed from `UPDATE` statements. See the table below. The two tolerances are asymmetric on purpose: underpayment tolerance is the *smaller* of a percentage and a dollar cap, because it exists to absorb an exchange withdrawal fee, not to discount the product; overpayment tolerance is the *larger* of the two, because it exists to avoid opening a refund case over a rounding error. An underpayment beyond tolerance is never auto-credited, in any state — that's a one-line rule in the code and a hard one in the argument: auto-crediting it is the gap someone pays 1% of the price through and gets the product anyway.

**RPC provider pool (§5.6).** Three providers per chain in a fixed rotation (`watcher/rpc/pool.py`), each behind its own in-process circuit breaker (`watcher/rpc/breaker.py`): closed → open on N consecutive failures → half-open trial → closed or open-longer. Backoff between retries uses full jitter (`sleep(random(0, 2^n · base))`), not a deterministic delay — with three providers and every watcher retrying on the same schedule, a deterministic backoff resynchronizes every retry onto the same instant, which is exactly when a provider that just had a blip is least able to answer. A filter that's too wide for one provider is too wide for the next one too, so `range_too_large` triggers a split (block range first, then address-group size if a single block still overflows), never a failover — failing over would spend three requests to learn one fact a split learns in one. For payments above the credit threshold, the pool additionally asks a second provider whether the block in question exists at all; disagreement is recorded as a metric and the decision to withhold credit on it belongs to the settler, because it's a money decision, not an RPC one.

**Rates and delivery (§5.7).** An invoice's exchange rate is a snapshot taken at creation and never re-read — re-pricing a tolerance against a live rate would make the same payment settled or not depending on when the settler happened to run. USDC invoices don't touch a rate API at all. Delivery runs through a transactional outbox: the settler writes an `entitlements` row and a `notifications` row in the same transaction that grants access, so the message that arrives is a consequence of a committed decision, never a decision on its own. `UNIQUE (kind, ref_id, dedup_key)` on `notifications` is what makes redelivery impossible, and it's enforced on the write side, at insert — the notifier adds no second, Python-side "have I sent this" cache, because that cache could disagree with the database and the constraint can't.

---

## Money policy

From `settler/policy.py`, the table the settler's `classify()` function implements exactly:

| Situation | Outcome | Notes |
|---|---|---|
| Nothing creditable has arrived yet | `no_funds` | — |
| Short by ≤ tolerance (min of 0.5% / $1) | `underpaid_tolerated` | Invoice closes as paid; the shortfall is logged, not chased |
| Short by > tolerance, top-up window still open | `partially_paid` | Buyer is told the exact missing amount and given the *same* address; the top-up window outlives the invoice (default 24h) |
| Short by > tolerance, top-up window closed | `underpaid_manual_review` | Never auto-credited. Owner resolves with `/resolve credit\|refund\|reject` |
| Exact, or over by ≤ tolerance (max of 5% / $5) | `paid` / `overpaid_credited` | Overpayment excess is credited to the buyer's internal balance for future purchases, and they're told exactly how much and where |
| Over by > tolerance | `overpaid_refund_pending` | Access is granted (the obligation was met); the excess becomes a `refunds` row with `status='pending'` — the bot never sends the refund itself, an operator executes it manually alongside the next sweep |
| Wrong token, wrong chain, payment after expiry with the top-up window closed, dust below `dust_threshold` | `manual_review` (or ignored, for dust) | Funds are technically sweepable — the address is ours — but crediting is a human decision |

---

## Threat model

Condensed from an internal STRIDE pass. Full reasoning is in code comments at each cited location; this is the map, not the territory.

| Threat | What closes it | Where |
|---|---|---|
| **T1 — address substitution.** DB tampering, XSS, a stolen bot token silently editing an old message, a plain code bug — all have the same effect: the buyer sends money to the wrong address. | Every address is re-derived and compared, never trusted from a column; every invoice is signed with an HMAC covering `(id, chain, asset, address, amount, expiry)` under a key that never touches the database; the address the buyer sees is identical, byte for byte, in the bot message, the API response, and the EIP-681 string inside the QR — one string, three surfaces; the invoice message is never edited after it's sent; `invoice_id` is a UUIDv7, not a serial, and every status lookup is filtered by the caller's verified identity. | `deriver/derivation.py::addresses_equal`, `core/invoicing/client.py::_verify` (MAC re-check on the receiving side), `api/static/qr.js` + `api/page.py` (one EIP-681 string, three render points), `api/tests/test_public_page.py` (asserts they match) |
| **T2 — double grant from a race.** Two settler passes, or a retried event, both try to credit the same invoice. | `entitlements_active_uniq` is a *partial* unique index on `invoice_id WHERE revoked_at IS NULL` — partial, not plain, because a reorg-revoked entitlement must be re-grantable. State transitions are compare-and-set (`UPDATE ... WHERE status='confirmed'`), never read-modify-write in Python. Redis, where used, only saves work; it's never the source of correctness — the same guarantee holds with Redis switched off entirely. | `migrations/versions/0001_initial.py` (the partial index), `settler/locks.py`, `notifier/tests/test_no_redis.py` |
| **T3 — replay / re-crediting a used payment.** Same log processed twice; a payment lands on a *reused* address after it's already been handed to a new invoice. | `UNIQUE (chain_id, tx_hash, log_index)` plus `ON CONFLICT DO NOTHING` stops the first case outright. The second is closed by three joint rules on address reuse: an address only returns to the free pool if it never received funds; it returns only after the top-up window plus a cooldown, not at invoice expiry; and every reservation records `reserved_from_block`, so a payment landing in an earlier block belongs to the *previous* owner of that address and is routed to `orphan_payment` / manual review, never auto-credited to the new invoice. | `deriver/pool.py`, `migrations/versions/0001_initial.py` (uniqueness + the `invoice_id` immutability trigger) |
| **T4 — xpub leakage.** Whoever holds the xpub can read the full revenue history and predict every future address — bad, but it cannot spend anything on its own. | The xpub lives only in `deriver`'s memory, delivered via a systemd credential scoped to that one unit; it is never an environment variable (visible in `docker inspect` and `/proc/<pid>/environ`), never logged (a regex filter strips anything matching an extended-key prefix), and no exception path in `deriver/derivation.py` can format it into a message. Only account-level export (`m/44'/60'/0'`) is ever used — never the master key, which would expose every account. | `deriver/derivation.py` (guards + `__all__` surface), `deriver/redaction.py`, `.env.example`'s xpub section (delivery-mechanism documentation) |
| **T5 — DoS via address generation.** `/buy` is free and unauthenticated by payment; a script calling it in a loop drives up the number of watched addresses, which drives up the size of `watcher`'s `eth_getLogs` filter and degrades detection for everyone. | Per-user quotas on active and hourly invoice creation, enforced under a PostgreSQL advisory lock in the same transaction as the insert (so a Redis outage can only reject early, never permit); a hard ceiling on active addresses per HD account; the free-address pool as the primary brake on index growth, since a new index is only minted when the pool is empty; a short invoice TTL; and a behavioral cooldown after repeated unpaid expiries. | `core/invoicing/quotas.py`, `.env.example`'s `INVOICING_MAX_*` settings, `deriver/pool.py` |
| **T7 — owner-account compromise.** The owner's Telegram session, not the server, is what's captured. | The owner's privileges are structurally incapable of moving funds: `/resolve refund` can only write a `refunds` row (`status='pending'`) because nothing in the codebase can build, sign, or broadcast a transaction. `/resolve credit` above a threshold requires a second-message confirmation code. Every admin action is append-only in `audit_log`, and no application role — including the settler's — has `UPDATE` or `DELETE` on that table (`migrations/versions/0002_roles_and_grants.py`). A denied admin command answers with the same sentence an unknown command gets, so probing `/resolve` doesn't confirm an owner account exists to phish. | `bot/handlers/admin.py`, `migrations/versions/0002_roles_and_grants.py`, `migrations/versions/0003_admin_money_grants.py` |

**MEV and front-running (T6) — deliberately not a concern here, and here's the reasoning rather than a bare assertion.** MEV is extracted where transaction *order* changes a transaction's *outcome*: a sandwich needs a price and slippage to move, a liquidation needs a position, an arbitrage needs a quote gap. The only transaction this system depends on is a fixed-amount ERC-20 `transfer` to a specific EOA. It has no price, no slippage, and no contract state to front-run — copying it just sends the copier's own money to the project's address, which is a donation, not an attack. What people sometimes conflate with MEV and *is* real here is reorg risk, and that's a §5.4 problem, closed by confirmation depth and finality, not a §5.8/T6 one — `watcher` never reads the mempool, only confirmed blocks, specifically so that "saw it pending" can never become "credited it."

**Residual risks — accepted, not closed:**
- Full host compromise exposes the HMAC key and allows real-time address substitution. Nothing closes this except the custody model itself: funds already swept can't be taken, and the ceiling on loss is the unswept balance times the time-to-detection.
- Hardware-wallet or seed-phrase compromise is total loss, and is outside this system's perimeter by construction — it's a physical-security problem for the owner, not a code problem.
- A lying or colluding RPC provider set is mitigated by cross-provider agreement checks on large payments, not eliminated — a majority-colluding provider set isn't detectable this way.
- A reorg deeper than the configured depth, below the credit threshold, is an accepted economic trade-off (the cost of the attack is meant to exceed the amount it could steal), not a closed hole.
- Sweeping funds to cold storage combines every invoice's address into one transaction, which makes the link between them public. That's a known privacy cost of the per-invoice-address model, not an oversight.

---

## Running it

Infrastructure first, then each process. There is no single "start everything" command by design — the six processes are meant to be deployed, restarted, and observed independently (`docker-compose.yml`'s header comment has the full reasoning), and in production each one is its own `systemd` unit.

```bash
cp .env.example .env               # fill in real values; a real .env is never committed
docker compose up -d               # Postgres, Redis, Prometheus, Grafana
alembic upgrade head                # apply all migrations (0001 through 0008)
```

Then, one terminal per process (each reads `.env` on its own):

```bash
python -m core.invoicing.issuer               # deriver: answers invoice + derivation-proof requests
python -m watcher.main --chain-id 8453         # watcher: Base
python -m settler.main                          # settler
python -m notifier.main                         # notifier
python -m bot.main                              # bot
uvicorn 'api.main:app' --factory                # api / invoice page
```

A second chain (Ethereum mainnet) is wired but not enabled by default — turning it on is a single documented `INSERT` into `chains` plus a second `watcher.main --chain-id 1` process; see the runbook in `.env.example`.

---

## What's not in this project, and why

Deliberate scope limits, not gaps waiting to be filled:

- **No private or spending keys, ever** — not in an environment variable, not in the database, not in memory, not "temporarily." The bot works exclusively with a public extended key. There is nothing on the server worth stealing that could move funds.
- **No automated outgoing transfers** — no automated sweep, no automated refund, no payout. Every outbound movement of funds is initiated and signed by a human, offline. An automated refund looks convenient right up until you notice it needs a key on the server, at which point the rest of this design stops meaning anything.
- **No custody beyond confirmation-to-sweep** — this isn't a wallet. It doesn't hold balances, doesn't offer withdrawal, doesn't promise safekeeping. Funds sit on receive addresses only until the next scheduled offline sweep; `unswept_balance_usd` exists as a metric specifically so that window doesn't quietly stretch.
- **No key or seed generation on the bot's side** — key material is created by the owner on a hardware wallet; the bot only ever receives a derived public key from it.
- **No self-run node** — RPC access is through official providers, within their published rate limits and terms of use.
- **No scraping of explorers or working around API limits** — every data source is an official, rate-limited RPC endpoint with its own API key.
- **No exchange, conversion, or trading** — the rate is fixed once, at invoice creation, and used for nothing else.
- **No arbitrary tokens** — only an explicit allow-list; anything else is a manual review.
- **No non-EVM chains in this version.**
- **No multisig, no split payouts to multiple recipients.**
- **No KYC/AML** — which is precisely why this stays a demonstration project rather than a payment service for third parties. It runs on its own small sums; licensing and financial compliance are out of scope, and it isn't described as anything other than what it is.

---

## Trade-offs, and what I'd do differently

Four real ones, from actual points in the build where a first approach didn't hold up:

**The `invoices` ↔ `receive_addresses` foreign-key cycle, and why it's `DEFERRABLE` rather than two-phase.** Reserving an address for a brand-new invoice is a chicken-and-egg problem: `receive_addresses.current_invoice_id` needs an invoice row that doesn't exist yet, and `invoices.address_id` needs an address row already reserved. The first version of this (migration through `0005`) split it into two statements — reserve the address, then insert the invoice, then bind — which works, but leaves a window where the address is `reserved` and pointed at nothing, and a crash in that window needs its own cleanup path. Migration `0006` instead made the address→invoice foreign key `DEFERRABLE INITIALLY DEFERRED`, so a single transaction can write both halves in either order and Postgres checks the cycle only at `COMMIT`. It's a smaller, less obvious fix than the two-phase version, and I'd think harder up front about deferrable constraints before writing the two-phase protocol that migration `0006` then had to unwind — the two-phase code still exists in `deriver/pool.py` as a documented fallback, which is one more code path than the schema needs to carry.

**`LISTEN`/`NOTIFY` over Postgres as the transport between `bot`/`api` and `deriver`, instead of a socket or a message queue.** Because `deriver` can't hold a network-capable dependency, `bot` and `api` can't call it directly — they write a row to `invoice_requests`, `deriver` picks it up and writes the answer, and the caller is woken by a Postgres `NOTIFY` rather than polling. It works, and the code is honest about the corner it lives in: subscribing is issued *before* the insert specifically to avoid a race where a fast reply fires before the listener exists, and a 250ms poll runs alongside the notification anyway as a safety net for a missed wakeup after a reconnect. I'd reconsider this if `/buy` ever became a high-frequency path rather than "a human pressing a button" — a table-based queue is the right choice for the traffic this system actually has, and the wrong one to reach for by default.

**QR rendered in the browser from the same string shown as text, instead of a server-rendered image.** An earlier instinct here would have been the obvious one: generate a QR image server-side and serve it as a `<img>`. It was rejected on a T1 argument — a QR is the one part of a payment page nobody reads with their eyes, so a server-rendered PNG can be silently swapped for a different one and the substitution is invisible. Instead `api/static/qr.js` is a self-hosted, dependency-free encoder that draws the code from the exact `data-eip681` attribute already rendered as visible text on the same page — one string, two representations, and a test that asserts they're character-for-character identical. The cost is real: it's about 500 lines of hand-written QR encoding logic, self-hosted specifically because the CSP forbids a CDN. If I were doing this again outside a portfolio context, I'd still keep the "one string, no second fetch" constraint, but I'd look harder for an audited, zero-dependency library that meets it before writing an encoder by hand.

**The third reorg case that only gets a comment, not code, right now.** `watcher/traversal.py` documents three ways a reorg can re-include a transaction, and handles two of them cleanly through `ON CONFLICT DO NOTHING` on `(chain_id, tx_hash, log_index)`. The third — a payment that lands at a *different height* but the *same* log position as before — means the original row's `block_number` now points at an orphaned block, the watcher has no `UPDATE` grant on `payments` to fix it, and every query that filters on canonical blocks will silently skip a real, canonical payment. The watcher logs the re-observation to `audit_log`, which it can write, and the settler is meant to consume that entry and treat the payment as "back, at this height" — but that consumer isn't built yet; it's a tracked `TODO` in the module, not a debugged edge case. I'd rather ship a README that names an open gap accurately than one that implies every corner of reorg handling is finished, because the alternative is someone finding out the hard way that it wasn't.

---

*Русская версия: [`README.ru.md`](README.ru.md).*
