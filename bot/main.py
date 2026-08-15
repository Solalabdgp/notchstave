# TODO: Week 1 — aiogram 3 Dispatcher entrypoint. /start, /shop, /buy (creates an
# invoice through the shared core.db models), /status <invoice_id>. Single
# testnet network (Base) and single asset (USDC) only, per TZ section 11 Week 1
# scope: "one network, one asset, end-to-end path works".
#
# Later weeks: /verify derivation proof + "I sent it to the wrong place" help
# copy and the full invoice-page handoff (Week 5); /reconcile and /sweeplist
# owner-only admin commands (Week 3).
#
# Hard rule for every week: bot makes zero money decisions. It only displays
# what settler already decided and forwards user input for api/settler to act
# on (TZ section 4).
