"""Where the Telegram bot token comes from. Shared by ``bot`` and ``notifier``.

Two processes hold a session on the same token — ``bot`` (which reads updates)
and ``notifier`` (which drains the outbox) — because TZ section 4 makes them
separate systemd units and a shared ``Bot`` object would mean a shared process.
Two units mean two credential loads, and this is the one function that does it,
in ``core`` rather than in either package: a loader living in ``bot`` and
imported by ``notifier`` would be a dependency edge pointing the wrong way
between two peers.

**Not an environment variable in production.** TZ section 9 delivers secrets
through systemd ``LoadCredential=``, and TZ 5.8/T1 vector 3 is *"компрометация
токена бота"* — a leaked token lets an attacker send as the bot and edit messages
it already sent, which is the quiet version of address substitution. ``ENV`` is
readable in ``docker inspect``, in ``/proc/<pid>/environ`` and in a core dump; a
credential file is mode 0400 on a tmpfs that is in no backup and no image.

The order is credentials-then-environment, the same way :func:`core.invoicing
.integrity.load_integrity_key` does it, and for the same reason: a correctly
configured production unit must not be downgradable by a stray variable in the
environment, while a laptop with no systemd must still be able to run the thing.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["TOKEN_CREDENTIAL_NAME", "load_bot_token"]

#: ``LoadCredential=notchstave-bot-token:/etc/notchstave/bot-token`` on both
#: ``notchstave-bot.service`` and ``notchstave-notifier.service``.
TOKEN_CREDENTIAL_NAME = "notchstave-bot-token"


def load_bot_token(
    credentials_dir: str | os.PathLike[str] | None = None,
    *,
    env: dict[str, str] | None = None,
) -> str:
    """Credential file first, environment second, refuse third.

    Refuses rather than returning an empty string. A client built with a blank
    token fails on its first API call with a message about authorisation, at
    which point the actual fault — nobody installed the credential — is three
    layers away from what the operator is looking at.
    """
    src = os.environ if env is None else env
    raw_dir = credentials_dir or src.get("CREDENTIALS_DIRECTORY")

    if raw_dir:
        candidate = Path(raw_dir) / TOKEN_CREDENTIAL_NAME
        if candidate.is_file():
            # `.strip()` and not `.rstrip`: a bot token has no leading or
            # trailing whitespace that could be content, unlike a raw key.
            return candidate.read_text(encoding="ascii").strip()

    from_env = src.get("BOT_TOKEN")
    if from_env:
        return from_env

    raise RuntimeError(
        f"no Telegram token: expected {TOKEN_CREDENTIAL_NAME} in $CREDENTIALS_DIRECTORY "
        "(production, TZ section 9) or BOT_TOKEN in the environment (local dev only)."
    )
