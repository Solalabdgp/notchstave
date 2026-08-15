# TODO: Week 1 — FastAPI app factory. GET /invoices/{invoice_id}/status, minimal
# invoice page (no QR yet), testnet Base/USDC only, per TZ section 11 Week 1
# scope: "one network, one asset, end-to-end path works".
#
# Later weeks: QR code per EIP-681 + Content-Security-Policy: default-src 'self'
# (no CDN, no external fonts/analytics — TZ 5.8/T1, section 9), live status,
# purchase history, /verify derivation proof endpoint, HMAC integrity check on
# every invoice read, request quotas against T5 (Week 5).
#
# Hard rule for every week: api makes zero money decisions. It only reads what
# settler already decided (TZ section 4). debug=False always; /metrics and
# /healthz must never leak config or the xpub (TZ 5.1).
