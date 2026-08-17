"""`/sweeplist` — the CSV, and the whole of what this bot does about withdrawals.

> "`/sweeplist` — экспорт CSV: индекс деривации, адрес, актив, баланс. Это
> **всё**, что бот делает для вывода средств. Файл уходит владельцу, подпись и
> отправка — офлайн, вручную, вне бота (см. 5.1)"

That emphasis is the TZ's, and it is the reason this module is thirty lines of
logic and a long comment. Everything a custodial system would do next — build a
transaction, pick a fee, sign, broadcast — does not exist here and cannot be
added without contradicting TZ 12 and the project's one real selling point:
there is no key on the server, so there is nothing on the server to steal.

What the module does, then:

1. list the addresses that may still be holding funds (:data:`settler.admin
   .repository.SQL_SWEEP_CANDIDATES`);
2. read each balance through the watcher's provider pool — the **same** read
   `/reconcile` performs, through the same
   :class:`~settler.admin.balances.BalanceSource`, because two sources of truth
   for "how much is on this address" is one more than a payment system may have;
3. render a CSV;
4. record the fact of the export in ``sweep_exports``;
5. stop.

**Read-only on the address pool.** Nothing here sets ``swept_at`` or moves an
address to ``swept``: writing ``receive_addresses`` belongs to the deriver alone
(TZ 5.8/T1.2, migration 0002), and in any case the export is a statement about
what the owner is *about to* do offline, not evidence that they did it. The
addresses stay on the next export until the offline transaction confirms and the
deriver marks them.

**Why the row in ``sweep_exports`` matters more than it looks.** TZ section 9
asks for a weekly spot-check of three addresses from `/sweeplist` against an
independent derivation. That check needs to know which file was checked, when it
was generated and what it claimed — which is exactly ``(generated_at,
address_count, total_raw, asset_id, file_ref)``. Migration 0003 gives the settler
``SELECT, INSERT`` and no ``UPDATE`` on that table for the same reason
``audit_log`` has none: a record of what you were told to sweep is worth nothing
if it can be revised afterwards.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
from dataclasses import dataclass
from decimal import Decimal

from sqlalchemy.ext.asyncio import AsyncConnection

from core.db import enums as E
from settler import metrics
from settler import repository as repo
from settler.admin import repository as admin_repo
from settler.admin.balances import BalanceSource
from settler.admin.policy import DEFAULT_ADMIN_POLICY, AdminPolicy
from settler.amounts import raw_to_usd, sum_raw, whole_units

__all__ = ["SweepRow", "SweepExport", "generate_sweep_list", "CSV_HEADER"]

#: TZ 3.4 names four columns — "индекс деривации, адрес, актив, баланс". The
#: balance appears twice: once in base units, which is what a signing tool needs
#: and the only exact form, and once in whole tokens, which is what a human
#: sanity-checks against a block explorer before signing. Emitting only the
#: second would put a rounded number in front of the one operation in this
#: project that moves real money.
CSV_HEADER = ("derivation_index", "address", "asset", "balance_raw", "balance")


@dataclass(frozen=True, slots=True)
class SweepRow:
    """One address worth sweeping."""

    derivation_index: int
    address: str
    asset_symbol: str
    balance_raw: Decimal
    decimals: int

    @property
    def balance(self) -> Decimal:
        return whole_units(self.balance_raw, self.decimals)


@dataclass(frozen=True, slots=True)
class SweepExport:
    """The file, and the record that it was produced."""

    export_id: int
    generated_at: dt.datetime
    chain_id: int
    asset_id: int
    asset_symbol: str
    file_ref: str
    rows: tuple[SweepRow, ...]
    #: Addresses whose balance was read. Larger than ``len(rows)`` whenever some
    #: candidates turned out to hold nothing.
    candidates_checked: int
    total_raw: Decimal
    total_usd: Decimal
    csv_text: str
    audit_id: int
    policy_version: str

    @property
    def address_count(self) -> int:
        return len(self.rows)


async def generate_sweep_list(
    conn: AsyncConnection,
    *,
    chain_id: int,
    asset_id: int,
    balances: BalanceSource,
    file_ref: str,
    operator_id: int | None = None,
    admin_policy: AdminPolicy = DEFAULT_ADMIN_POLICY,
    rate: Decimal | None = None,
) -> SweepExport:
    """Build the sweep CSV for one asset and record the export (TZ 3.4).

    Args:
        file_ref: how the file will be identified afterwards — a Telegram
            ``file_id``, a path, a content hash. Supplied by the caller rather
            than invented here, because this function does not decide how the
            file is delivered and a reference to a delivery that never happened
            is worse than none.
        rate: USD per whole token, for ``notchstave_unswept_balance_usd`` only.
            Omitted → the most recent ``invoices.rate_snapshot``; unavailable →
            the gauge is left untouched rather than set to a made-up figure.

    Only addresses with a **positive** balance reach the CSV. A candidate that
    turns out to hold nothing is counted in ``candidates_checked`` and dropped
    from the file: the CSV exists to be worked through by hand, and padding it
    with rows that need no action is how the row that does need action gets
    missed.

    Raises:
        LookupError: no such asset.
    """
    asset = await admin_repo.load_asset(conn, asset_id)
    if asset is None:
        raise LookupError(f"asset {asset_id} does not exist")
    if asset.chain_id != chain_id:
        raise ValueError(f"asset {asset_id} belongs to chain {asset.chain_id}, not {chain_id}")

    candidates = await admin_repo.sweep_candidates(conn, chain_id=chain_id, asset_id=asset_id)

    rows: list[SweepRow] = []
    for candidate in candidates:
        balance_raw = Decimal(await balances.balance_of(address=candidate.address, asset=asset))
        if balance_raw <= 0:
            continue
        rows.append(
            SweepRow(
                derivation_index=candidate.derivation_index,
                address=candidate.address,
                asset_symbol=asset.symbol,
                balance_raw=balance_raw,
                decimals=asset.decimals,
            )
        )

    total_raw = sum_raw(r.balance_raw for r in rows)
    csv_text = render_csv(rows)

    export_id, generated_at = await admin_repo.record_sweep_export(
        conn,
        address_count=len(rows),
        total_raw=total_raw,
        asset_id=asset_id,
        file_ref=file_ref,
        operator_id=operator_id,
    )

    effective_rate = rate if rate is not None else await admin_repo.latest_rate_for_asset(
        conn, asset_id
    )
    total_usd = (
        raw_to_usd(total_raw, asset.decimals, effective_rate)
        if effective_rate is not None and effective_rate > 0
        else Decimal(0)
    )
    if effective_rate is not None and effective_rate > 0:
        # TZ section 7 — "на горячих адресах скопилось слишком много. Пора
        # свипать офлайн." Set only when the figure means something; a gauge
        # forced to zero because no rate was available would read as "nothing is
        # unswept", which is the opposite of what an unpriced balance implies.
        metrics.UNSWEPT_BALANCE_USD.labels(chain=str(chain_id)).set(float(total_usd))
    metrics.ADMIN_ACTIONS.labels(action="sweeplist").inc()

    audit_id = await repo.write_audit(
        conn,
        actor_kind=str(E.ActorKind.SYSTEM) if operator_id is None else str(E.ActorKind.OWNER),
        actor_id="settler" if operator_id is None else str(operator_id),
        action="admin.sweeplist",
        target_kind="sweep_export",
        target_id=str(export_id),
        before_state=None,
        after_state={
            "address_count": len(rows),
            "total_raw": str(total_raw),
            "file_ref": file_ref,
        },
        args={
            "chain_id": chain_id,
            "asset_id": asset_id,
            "asset_symbol": asset.symbol,
            "candidates_checked": len(candidates),
            "total_usd": str(total_usd),
            "derivation_indexes": [r.derivation_index for r in rows],
        },
        policy_version=admin_policy.version,
    )

    return SweepExport(
        export_id=export_id,
        generated_at=generated_at,
        chain_id=chain_id,
        asset_id=asset_id,
        asset_symbol=asset.symbol,
        file_ref=file_ref,
        rows=tuple(rows),
        candidates_checked=len(candidates),
        total_raw=total_raw,
        total_usd=total_usd,
        csv_text=csv_text,
        audit_id=audit_id,
        policy_version=admin_policy.version,
    )


def render_csv(rows: list[SweepRow]) -> str:
    """Rows -> CSV text.

    ``lineterminator="\\n"`` explicitly: :mod:`csv` defaults to ``\\r\\n``, and a
    file whose bytes depend on which machine generated it cannot be
    content-addressed, diffed against last week's export, or checked against a
    hash the owner wrote down. For a file that precedes a manual signing
    operation, byte-for-byte reproducibility is worth one keyword argument.

    ``balance_raw`` is written as an integer string rather than through
    ``float``: these are ``NUMERIC(78, 0)`` values, a uint256 does not fit in a
    double, and silently losing precision in the file the owner signs from would
    be the single most expensive rounding error the project could make.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_HEADER)
    for row in rows:
        writer.writerow(
            [
                row.derivation_index,
                row.address,
                row.asset_symbol,
                format(row.balance_raw, "f"),
                format(row.balance.normalize(), "f"),
            ]
        )
    return buffer.getvalue()
