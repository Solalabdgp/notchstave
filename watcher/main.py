# TODO: Week 1 — one process for Base testnet. Walk blocks from the stored
# checkpoint (core.db.models.Chain.last_indexed_block) to head via web3.py,
# pull ERC-20 Transfer logs for the pooled receive addresses, write raw rows
# into core.db.models.Payment. Per TZ section 11 Week 1 scope: single network,
# single asset (USDC), end-to-end path only — no reorg handling yet.
#
# Later weeks: confirmations/finalization/reorg rollback via core.db.models.Block
# (Week 2); RPC provider pool (Alchemy/QuickNode primary, Ankr fallback),
# circuit breaker, backoff, second chain added by config not rewrite (Week 4).
#
# Hard rule for every week: watcher makes zero business/money decisions. It
# only writes what it observed on-chain (TZ section 4).
