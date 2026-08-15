"""Deriver process entry point.

Wires together the three pieces of this package and nothing else:

    redaction filter  ->  installed before anything else runs
    xpub credentials  ->  loaded from systemd LoadCredential=
    Deriver           ->  held for the process lifetime

The order matters. The logging filter goes in first, before any code that
touches a key, so that a failure during credential loading cannot be the thing
that prints one (TZ 5.8/T4).

**What this module deliberately does not do.** It does not open a listening
socket and it does not poll the database in a loop. How other processes reach
the deriver is a Week 2 decision (TZ 4 shows the boundary but not the
transport), and picking one here would mean importing a server framework into
the one package whose whole value is that it cannot reach the network — see
``deriver/pyproject.toml`` and ``tests/test_isolation.py``, which fail the
build if that happens.

Until then this file is usable in two ways that need no transport at all:
importing :func:`build_deriver` in-process, and running the module directly as
a startup self-check.
"""

from __future__ import annotations

import logging
import sys

from deriver.redaction import install as install_redaction
from deriver.service import Deriver, load_accounts_from_credentials

logger = logging.getLogger("notchstave.deriver")


def build_deriver(credentials_dir: str | None = None) -> Deriver:
    """Load every account xpub from systemd credentials and validate it.

    Every key is parsed at construction, so a wrong, private or non-account key
    fails here — at startup, loudly — rather than on the first customer's
    ``/buy``. Nothing is logged except fingerprints.
    """
    install_redaction()
    accounts = load_accounts_from_credentials(credentials_dir)
    deriver = Deriver(accounts)
    logger.info("deriver ready: %s", deriver)  # repr is fingerprints only
    return deriver


def main(argv: list[str] | None = None) -> int:
    """Startup self-check: load the keys, print the fingerprints, exit.

    Meant to be run once on the server after installing the credential, so the
    operator can compare the printed fingerprint against what the hardware
    wallet displays before any invoice is issued (TZ 5.1: until the control
    values match, not a single real payment may be accepted).
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    install_redaction()

    args = sys.argv[1:] if argv is None else argv
    credentials_dir = args[0] if args else None

    try:
        deriver = build_deriver(credentials_dir)
    except Exception as exc:  # noqa: BLE001 - top level, message is already key-free
        logger.error("deriver failed to start: %s: %s", type(exc).__name__, exc)
        return 1

    for hd_account_id in deriver.hd_account_ids:
        # Fingerprint plus the first address: the two values an operator can
        # compare against the hardware wallet screen without any tooling.
        logger.info(
            "hd_account_id=%s fingerprint=%s first_address=%s",
            hd_account_id,
            deriver.fingerprint(hd_account_id),
            deriver.address(hd_account_id, 0),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
