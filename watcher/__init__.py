"""Notchstave watcher: chain -> raw payment rows. One process per network.

What this package is allowed to do (TZ section 4, verbatim in intent): walk
blocks from the stored checkpoint to the head, pull `Transfer` logs for the
addresses in the pool, and write what it observed. Nothing here decides
anything about money — no confirmations policy, no tolerance arithmetic, no
crediting, no access grants. Those live in `settler/` and only there.

The privilege matrix in migration 0002 is what makes that boundary real rather
than aspirational, and it is worth reading before changing anything here:

    chains              SELECT, UPDATE      (only `last_indexed_block`)
    blocks              SELECT, INSERT, UPDATE
    payments            SELECT, INSERT      <- no UPDATE, deliberately
    receive_addresses   SELECT
    invoices            SELECT
    assets              SELECT
    audit_log           SELECT, INSERT

Two consequences follow from that table and shape most of this package:

* The watcher cannot mark a payment `reverted`. On a reorg it flips the
  abandoned *blocks* to `orphaned` and stops there; turning that into a money
  decision (revert the payment, revoke the entitlement) is the settler's job.
  See `watcher/traversal.py` for the full handoff, including the one case where
  a re-observed payment needs an explicit signal because `ON CONFLICT DO
  NOTHING` leaves a stale `block_number` behind.
* The watcher cannot write `receive_addresses`. It reads the pool, builds its
  `eth_getLogs` filter from it, and maps a detected address back to the exact
  stored string — it never invents an address row (TZ 5.8/T1.2).

Module map:

    config.py      env + `chains` row -> runtime settings; no hardcoded network
    metrics.py     TZ section 7 metric names, no-op when prometheus is absent
    models.py      plain dataclasses shared by the layers below
    rpc/           provider pool: circuit breaker, backoff, budget, chunking
    detect/        ERC-20 log decoding and the honest native-ETH degradation
    store/         the persistence protocol and its PostgreSQL implementation
    traversal.py   checkpoint -> head walk, parent_hash check, reorg rollback
    main.py        the loop that wires the above together
"""
