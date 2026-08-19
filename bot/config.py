"""Everything the bot process needs to be told, read once at startup.

Same shape as :class:`notifier.config.NotifierConfig` and
:class:`settler.policy.MoneyPolicy`: a frozen dataclass, one ``from_env``, and
nothing below this module reading ``os.environ``. A handler that reaches for a
variable is a handler a test cannot configure.

Two fields are not ordinary configuration and are worth reading the reasoning
for.

**The token is not here at all.** It is loaded by :func:`core.telegram
.load_bot_token`, re-exported from this module for the call sites that expect to
find it beside the rest of the bot's configuration. It lives in ``core`` because
the notifier needs the identical loader and a copy in ``bot`` imported from
``notifier`` would be a dependency edge between two peer processes. The reasons
for reading it from a credential file rather than the environment are in that
module's docstring, and they are about TZ 5.8/T1 vector 3 rather than about
tidiness.

**``owner_tg_id`` is a single integer and is required for the admin commands.**
TZ 3.4: *"Отдельные команды, доступные только владельцу по фиксированному
``tg_id``"*. Unset means the admin commands answer as if they do not exist,
which is the fail-closed direction: a misconfigured deployment must not end up
with ``/resolve credit`` available to everyone, and "no owner configured" is a
state that occurs on every fresh checkout.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from core.telegram import TOKEN_CREDENTIAL_NAME, load_bot_token

__all__ = ["BotConfig", "TOKEN_CREDENTIAL_NAME", "load_bot_token"]

#: v1 is one chain and one asset (TZ section 2, "Сети и активы первой версии").
#: Both are configuration rather than constants because the testnet/mainnet
#: switch is a chain id change and nothing else.
DEFAULT_CHAIN_ID = 8453
DEFAULT_ASSET_SYMBOL = "USDC"

#: How long ``/buy`` and ``/verify`` wait for the deriver before telling the
#: user to check back. Matches ``core.invoicing.client.DEFAULT_TIMEOUT_SECONDS``
#: and is kept configurable only so a slow test rig does not have to sleep.
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10.0


def _int_or_none(name: str, env: dict[str, str]) -> int | None:
    raw = env.get(name)
    return int(raw) if raw and raw.strip() else None


def _float(name: str, default: float, env: dict[str, str]) -> float:
    raw = env.get(name)
    return default if raw is None or not raw.strip() else float(raw)


@dataclass(frozen=True, slots=True)
class BotConfig:
    """Startup configuration. Holds no secrets — the token is passed separately."""

    #: ``users.tg_id`` of the one principal allowed to run the TZ 3.4 commands.
    #: ``None`` disables them entirely; see the module docstring.
    owner_tg_id: int | None = None

    chain_id: int = DEFAULT_CHAIN_ID
    asset_symbol: str = DEFAULT_ASSET_SYMBOL

    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS

    #: Base of the invoice page (TZ 3.2). Empty means the "open the page" button
    #: is omitted rather than pointing at a URL that does not resolve.
    invoice_page_base_url: str = ""

    #: Block-explorer address/tx prefix, for the "look at it yourself" links of
    #: TZ 3.1. Empty omits the links.
    explorer_base_url: str = ""

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> BotConfig:
        src = dict(os.environ) if env is None else env
        return cls(
            owner_tg_id=_int_or_none("BOT_OWNER_TG_ID", src),
            chain_id=int(src.get("BOT_CHAIN_ID") or DEFAULT_CHAIN_ID),
            asset_symbol=src.get("BOT_ASSET_SYMBOL") or DEFAULT_ASSET_SYMBOL,
            request_timeout_seconds=_float(
                "BOT_REQUEST_TIMEOUT_SECONDS", DEFAULT_REQUEST_TIMEOUT_SECONDS, src
            ),
            invoice_page_base_url=(src.get("INVOICE_PAGE_BASE_URL") or "").rstrip("/"),
            explorer_base_url=(src.get("BOT_EXPLORER_BASE_URL") or "").rstrip("/"),
        )

    def is_owner(self, tg_id: int | None) -> bool:
        """The whole of TZ 3.4's access control, in one place.

        A method rather than a comparison at four call sites, and ``None`` on
        either side is False rather than an error: an update with no ``from_user``
        (a channel post) and an unconfigured owner are both "not the owner", and
        neither should be able to raise its way past a check.
        """
        return self.owner_tg_id is not None and tg_id == self.owner_tg_id
