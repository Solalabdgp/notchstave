"""Notchstave api — FastAPI, invoice page / status / QR endpoint.

No money decisions live here: this process reads/exposes what `settler`
already decided and never writes invoice/payment state itself (TZ section 4).
"""
