"""The in-process deriver: holds account xpubs, answers with addresses.

One object, three jobs (TZ 4, "deriver"):

* keep account-level xpubs in memory for the process lifetime;
* derive an address for ``(hd_account_id, derivation_index)``;
* :meth:`Deriver.verify` — re-derive and compare, which is contermeasure
  1.1 against address substitution (TZ 5.8/T1).

The xpub is keyed by ``hd_accounts.id`` rather than being a single value,
because xpub rotation after a leak (TZ 5.8/T4) means a second account row at
``m/44'/60'/1'`` coexisting with the first: new invoices are issued from the
new account while the old addresses stay watch-only until the final sweep.
A single-key design would force a restart-with-downtime at exactly the moment
an incident is in progress.

**Loading the secret.** ``LoadCredential=`` in
``notchstave-deriver.service``, read through ``$CREDENTIALS_DIRECTORY``, and
nothing else. TZ 5.8/T4 rules out environment variables explicitly: ``ENV`` is
visible in ``docker inspect``, in ``/proc/<pid>/environ`` and in core dumps.
:func:`load_accounts_from_credentials` therefore reads files, and the local-dev
escape hatch is also a file path — never the key itself in a variable.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from pathlib import Path

from deriver.derivation import (
    DerivedAddress,
    DerivationError,
    addresses_equal,
    account_fingerprint,
    derive_address,
    derive_addresses,
    derivation_path,
)

__all__ = [
    "UnknownHDAccount",
    "Deriver",
    "load_accounts_from_credentials",
    "CREDENTIAL_PREFIX",
]

#: systemd credential names are `notchstave-xpub-<hd_account_id>`, so one unit
#: can carry several accounts across a rotation without a config change.
CREDENTIAL_PREFIX = "notchstave-xpub-"


class UnknownHDAccount(DerivationError):
    """No xpub loaded for this ``hd_accounts.id``.

    Never falls back to "some other account" — deriving from the wrong account
    would produce a perfectly valid address that the owner cannot spend.
    """


class Deriver:
    """Holds account xpubs and derives from them. Not thread-affine, no I/O.

    The xpub is stored in a name-mangled attribute and deliberately excluded
    from :meth:`__repr__`. That is not security by obscurity — it is the
    concrete measure TZ 5.8/T4 asks for ("переопределённый ``__repr__`` у
    объекта конфигурации, чтобы ключ не всплыл при печати настроек"), and it
    is what keeps a key out of a pytest assertion diff or a debugger dump.
    """

    __slots__ = ("__accounts",)

    def __init__(self, accounts: Mapping[int, str]) -> None:
        if not accounts:
            raise ValueError("Deriver requires at least one account xpub")
        # Validate every key up front: a bad or private key must fail at
        # startup, not on the first customer's /buy.
        validated: dict[int, str] = {}
        for hd_account_id, xpub in accounts.items():
            if not isinstance(hd_account_id, int) or isinstance(hd_account_id, bool):
                raise TypeError("hd_account_id must be an int")
            account_fingerprint(xpub)  # raises on private / non-account keys
            validated[hd_account_id] = xpub.strip()
        self.__accounts = validated

    # -- introspection that is safe to print ------------------------------

    def __repr__(self) -> str:
        # Fingerprints only. Enough to answer "is the deriver using the key I
        # think it is" — which is the only question a log line should ask.
        pairs = ", ".join(
            f"{acc_id}:{account_fingerprint(xpub)}" for acc_id, xpub in sorted(self.__accounts.items())
        )
        return f"<Deriver accounts=[{pairs}]>"

    __str__ = __repr__

    @property
    def hd_account_ids(self) -> tuple[int, ...]:
        return tuple(sorted(self.__accounts))

    def fingerprint(self, hd_account_id: int) -> str:
        """Lowercase hex BIP-32 fingerprint, matching ``hd_accounts.xpub_fingerprint``."""
        return account_fingerprint(self.__xpub(hd_account_id))

    # -- derivation --------------------------------------------------------

    def __xpub(self, hd_account_id: int) -> str:
        try:
            return self.__accounts[hd_account_id]
        except KeyError:
            raise UnknownHDAccount(
                f"no xpub loaded for hd_account_id={hd_account_id}; "
                f"loaded accounts: {list(self.hd_account_ids)}"
            ) from None

    def address(self, hd_account_id: int, derivation_index: int) -> str:
        """EIP-55 address at ``m/44'/60'/<account>'/0/<derivation_index>``."""
        return derive_address(self.__xpub(hd_account_id), derivation_index)

    def addresses(self, hd_account_id: int, start_index: int, count: int) -> list[DerivedAddress]:
        """Batch derivation for gap-limit pre-fill (TZ 5.1, p. 2)."""
        return derive_addresses(self.__xpub(hd_account_id), start_index, count)

    def verify(self, address: str, hd_account_id: int, derivation_index: int) -> bool:
        """Re-derive the address from the xpub and compare byte for byte.

        Countermeasure 1.1 of TZ 5.8/T1, verbatim. Cheap — one point addition
        and one keccak — and it closes the two most realistic substitution
        vectors at once: a database compromised without the host (``UPDATE
        invoices SET address = ...``) and a plain bug that reads the wrong row.

        The point is epistemic: after this call an address can no longer be
        *declared*, only *derived*. Callers must treat ``False`` as a suspected
        compromise — block the invoice, bump
        ``notchstave_address_mismatch_total``, alert immediately (TZ 5.5) —
        and not as a display glitch to retry.

        Returns ``False`` rather than raising for a mismatch, and raises only
        when the question itself is malformed (unknown account, bad index), so
        that a caller cannot accidentally treat an error path as a pass.
        """
        expected = self.address(hd_account_id, derivation_index)
        return addresses_equal(address, expected)

    def derivation_proof(
        self, hd_account_id: int, derivation_index: int, path_prefix: str
    ) -> dict[str, str | int]:
        """Publishable triple for ``/verify <invoice_id>`` (TZ 5.8/T1.4).

        Fingerprint + full path + address lets the owner reproduce the address
        in any third-party tool without trusting the bot. It contains no key
        material, so it is safe to send over Telegram — unlike the xpub, which
        is exactly why the buyer-facing proof is the weaker three-channel check
        described in T1.4 rather than this one.
        """
        return {
            "xpub_fingerprint": self.fingerprint(hd_account_id),
            "derivation_path": derivation_path(path_prefix, derivation_index),
            "address": self.address(hd_account_id, derivation_index),
            "derivation_index": derivation_index,
        }


def load_accounts_from_credentials(
    credentials_dir: str | os.PathLike[str] | None = None,
    *,
    expected_account_ids: Iterable[int] | None = None,
) -> dict[int, str]:
    """Read ``notchstave-xpub-<id>`` files from the systemd credentials directory.

    systemd sets ``$CREDENTIALS_DIRECTORY`` for a unit that declares
    ``LoadCredential=``; the files are mode 0400, owned by the service user,
    and live on a tmpfs that is not part of any backup or image. That is the
    storage model TZ 5.8/T4 prescribes, and the reason this function takes a
    directory rather than a value: there is no code path in this package that
    accepts an xpub from the environment.
    """
    raw_dir = credentials_dir or os.environ.get("CREDENTIALS_DIRECTORY")
    if not raw_dir:
        raise RuntimeError(
            "CREDENTIALS_DIRECTORY is not set: the deriver expects its xpub via "
            "systemd LoadCredential=, never via an environment variable (TZ 5.8/T4)"
        )

    directory = Path(raw_dir)
    if not directory.is_dir():
        raise RuntimeError(f"credentials directory {directory} does not exist")

    accounts: dict[int, str] = {}
    for entry in sorted(directory.iterdir()):
        if not entry.is_file() or not entry.name.startswith(CREDENTIAL_PREFIX):
            continue
        suffix = entry.name[len(CREDENTIAL_PREFIX) :]
        if not suffix.isdigit():
            continue
        # `.strip()` handles the trailing newline that any sane editor adds;
        # the value is never logged, echoed, or put in an exception.
        accounts[int(suffix)] = entry.read_text(encoding="ascii").strip()

    if not accounts:
        raise RuntimeError(
            f"no {CREDENTIAL_PREFIX}<id> credential found in {directory}; "
            "check LoadCredential= in notchstave-deriver.service"
        )

    if expected_account_ids is not None:
        missing = sorted(set(expected_account_ids) - accounts.keys())
        if missing:
            raise RuntimeError(f"missing xpub credentials for hd_account_id(s): {missing}")

    return accounts
