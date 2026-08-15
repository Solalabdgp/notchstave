# TODO: Week 1 — match rows in core.db.models.Payment to their invoice via
# receive_addresses.current_invoice_id, and on a confirmed testnet payment
# insert a core.db.models.Entitlement. Per TZ section 11 Week 1 scope: single
# network, single asset (USDC), the simplest possible happy path only.
#
# Later weeks — the two most valuable weeks per TZ section 11, do not shortcut
# them: confirmations, finalization, reorg rollback, idempotency, revocation,
# plus the T2/T3 countermeasures (partial unique index on entitlements, CAS
# status transitions, FOR UPDATE on invoice, payments.invoice_id immutability
# trigger, reserved_from_block) (Week 2); underpayment/overpayment/late top-up/
# expiry/rate anomalies/manual review/refund requests, /reconcile, /sweeplist
# (Week 3).
#
# Hard rule for every week: settler is the only package allowed to make a
# money decision (TZ section 4). It never talks to an RPC directly — only to
# what watcher already wrote to the database.
