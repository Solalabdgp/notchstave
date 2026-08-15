# TODO: Week 1 — load the account-level xpub via systemd LoadCredential (local
# dev: ACCOUNT_XPUB from .env, dev-only, see .env.example warning) into memory,
# hold it for the process lifetime, and derive m/44'/60'/0'/0/i addresses on
# request using bip_utils (BIP-32/44) on top of coincurve for the curve math
# (TZ 5.1 — "свой велосипед на этом месте писать нельзя категорически").
#
# Before accepting a single real payment: verify against the official BIP-32
# test vectors AND the first five addresses shown by the owner's hardware
# wallet at the same path. Mismatch on either check means stop, not proceed
# (TZ 5.1, section 11 Week 1 gate).
#
# Non-negotiable isolation, re-stated here as code-adjacent as possible: no
# import of httpx/aiohttp/web3/redis/celery/aiogram/fastapi, ever, in this
# package. See deriver/__init__.py and deriver/pyproject.toml.
