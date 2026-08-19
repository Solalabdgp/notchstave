"""Owner-facing copy for the four commands of TZ 3.4.

Kept apart from :mod:`bot.texts` because the two have different readers and
different rules. Buyer copy explains and reassures; owner copy is a report about
money and its job is to be unambiguous — every number that a decision depends on
appears in full, and nothing is rounded into a friendlier shape.

Two conventions worth stating:

**Raw base units are printed alongside human units, never instead of them.** A
sweep list is worked through by hand against a block explorer, and a rounded
balance in front of the one operation in this project that moves real money is
how a mistake gets signed.

**Nothing here decides anything.** These functions take the value objects
:mod:`settler.admin` already returned. If a report says "no drift", it is
because :class:`~settler.admin.reconcile.ReconcileReport` said so — this module
has no arithmetic in it that could disagree.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence

from bot.formatting import code, esc, format_amount, format_usd
from bot.repository import OpenCaseRow
from settler.admin.errors import ConfirmationRequired
from settler.admin.reconcile import ReconcileReport
from settler.admin.reviews import PendingCase, ResolutionResult
from settler.admin.sweeplist import SweepExport

__all__ = [
    "pending",
    "resolve_usage",
    "no_open_case",
    "ambiguous_cases",
    "resolution",
    "confirmation_required",
    "sweeplist_caption",
    "reconcile_report",
    "balances_unavailable",
    "admin_unconfigured",
]


def pending(cases: Sequence[PendingCase]) -> str:
    """``/pending`` — "счета, зависшие в неоднозначных состояниях" (TZ 3.4)."""
    if not cases:
        return "No open cases."
    lines = [f"<b>Open cases: {len(cases)}</b>", ""]
    for case in cases:
        lines.append(
            f"#{case.review_id} <b>{esc(case.kind)}</b> "
            f"({case.opened_at.astimezone(dt.UTC):%Y-%m-%d %H:%M} UTC)"
        )
        if case.invoice_id is not None:
            lines.append(f"  invoice {code(case.invoice_id)}")
        if case.amount_due_raw is not None and case.asset_decimals is not None:
            due = format_amount(case.amount_due_raw, case.asset_decimals, case.asset_symbol or "")
            got = format_amount(case.received_raw, case.asset_decimals, case.asset_symbol or "")
            lines.append(f"  due {esc(due)}, received {esc(got)}")
        if case.amount_due_usd is not None:
            lines.append(f"  value {format_usd(case.amount_due_usd)}")
        if case.note:
            lines.append(f"  {esc(case.note)}")
        lines.append("")
    lines.append(
        "Resolve with <code>/resolve &lt;invoice_id&gt; &lt;credit|refund|reject&gt; "
        "[comment]</code>, or with the case number when one invoice has several."
    )
    return "\n".join(lines)


def resolve_usage() -> str:
    return (
        "Usage: <code>/resolve &lt;invoice_id|case_id&gt; &lt;credit|refund|reject&gt; "
        "[comment]</code>\n"
        "Add <code>code=XXXXXXXX</code> to confirm a credit above the manual limit.\n"
        "/pending lists what is open."
    )


def no_open_case(invoice_id: object) -> str:
    return (
        f"No open case for invoice {code(invoice_id)}.\n"
        "Either it was already resolved, or nothing about it needs a decision."
    )


def ambiguous_cases(invoice_id: object, cases: Sequence[OpenCaseRow]) -> str:
    """One invoice, several open cases — refuse rather than pick.

    TZ 3.4 spells the command with an invoice id, and :func:`settler.admin
    .resolve_manual_review` takes a case id precisely because one invoice can
    carry an underpayment *and* a stray token at once. Choosing for the owner
    would credit an invoice on the strength of the wrong anomaly.
    """
    listed = "\n".join(f"• #{c.review_id} {esc(c.kind)}" for c in cases)
    return (
        f"Invoice {code(invoice_id)} has {len(cases)} open cases:\n"
        f"{listed}\n\n"
        "Name the case number instead of the invoice id — resolving the wrong "
        "anomaly would close a decision nobody made."
    )


def resolution(result: ResolutionResult) -> str:
    lines = [
        f"<b>Case #{result.review_id} → {esc(result.resolution)}</b>",
        f"Outcome: {esc(result.outcome)}",
        f"Value: {format_usd(result.amount_usd)}",
        f"Audit entry: {result.audit_id} (policy {esc(result.policy_version)})",
    ]
    if result.invoice_id is not None:
        lines.append(f"Invoice: {code(result.invoice_id)}")
    if result.invoice_status_after:
        lines.append(f"Invoice status now: {esc(result.invoice_status_after)}")
    if result.entitlement_id is not None:
        lines.append(f"Entitlement granted: {result.entitlement_id}")
    if result.lost_grant_race:
        lines.append(
            "The buyer already had this product — nothing was granted twice "
            "(entitlements_active_uniq)."
        )
    if result.refund_id is not None:
        lines.append(
            f"Refund #{result.refund_id} recorded as <b>pending</b>. "
            "Nothing has been sent: this system cannot send funds, and the "
            "destination is still blank because a sending address is not a "
            "refund address. Ask the buyer where it should go."
        )
    return "\n".join(lines)


def confirmation_required(exc: ConfirmationRequired) -> str:
    """TZ 5.8/T7 — the second message with the code from the first."""
    return (
        f"<b>Confirmation needed.</b>\n"
        f"Crediting {format_usd(exc.amount_usd)} on case #{exc.review_id} is above "
        f"the manual limit of {format_usd(exc.limit_usd)}.\n\n"
        f"Re-send the same command within {exc.ttl_seconds} seconds with:\n"
        f"{code('code=' + exc.code)}\n\n"
        "Nothing has been credited yet. The attempt is already in the audit log."
    )


def sweeplist_caption(export: SweepExport) -> str:
    """``/sweeplist`` — and a reminder of what the file is not.

    TZ 3.4: *"Это **всё**, что бот делает для вывода средств."* The caption says
    so, because the moment somebody expects the bot to also send the transaction
    is the moment somebody asks for a signing key on the server, which is the
    one thing this whole design exists to avoid (TZ 12).
    """
    lines = [
        f"<b>Sweep list — {esc(export.asset_symbol)} on chain {export.chain_id}</b>",
        f"Addresses with a balance: {export.address_count} "
        f"(checked {export.candidates_checked})",
        f"Total: {code(export.total_raw)} base units ≈ {format_usd(export.total_usd)}",
        f"Export #{export.export_id}, audit entry {export.audit_id}",
        "",
        "This file is the whole of what this system does for withdrawals. "
        "Signing and broadcasting happen offline, from the hardware wallet — "
        "there is no key here and no code path that could use one.",
    ]
    return "\n".join(lines)


def reconcile_report(report: ReconcileReport) -> str:
    """``/reconcile`` — "расхождение — сигнал бага, а не повод подправить цифру"."""
    lines = [
        f"<b>Reconcile — {esc(report.asset_symbol)} on chain {report.chain_id}</b>",
        f"Addresses checked: {len(report.checked)}"
        + (f" (+{len(report.skipped_swept)} already swept)" if report.skipped_swept else ""),
        f"Ledger says: {code(report.total_expected_raw)} base units",
        f"Chain says:  {code(report.total_actual_raw)} base units",
    ]
    if not report.drifting:
        lines += ["", "No drift. Ledger and chain agree address by address."]
        return "\n".join(lines)

    lines += [
        "",
        f"<b>Drift on {len(report.drifting)} address(es)</b>: "
        f"{code(report.absolute_drift_raw)} base units ≈ {format_usd(report.drift_usd)} "
        f"(rate from {esc(report.rate_source)})",
        f"Threshold: {format_usd(report.threshold_usd)}",
    ]
    for drift in report.drifting[:10]:
        lines.append(
            f"• index {drift.derivation_index} {code(drift.address)}: "
            f"expected {drift.expected_raw}, actual {drift.actual_raw}"
        )
    if len(report.drifting) > 10:
        lines.append(f"… and {len(report.drifting) - 10} more")
    if report.alert:
        lines += [
            "",
            "<b>This is above the threshold.</b> It is a bug signal, not a number "
            "to adjust by hand. Cases have been opened: "
            + ", ".join(f"#{i}" for i in report.manual_review_ids),
        ]
    return "\n".join(lines)


def balances_unavailable() -> str:
    """Said plainly instead of reconciling against nothing.

    A balance source that silently answered zero would report the entire ledger
    as missing — the most alarming wrong answer this system can produce, and one
    that would be produced by a configuration mistake rather than by a problem.
    """
    return (
        "On-chain balances are not available to this process, so this command "
        "cannot run. It needs an RPC provider list on the chain row and reachable "
        "endpoints; without them a reconcile would compare the ledger against "
        "zero and report everything as missing."
    )


def admin_unconfigured() -> str:
    return (
        "Admin commands are not configured on this deployment "
        "(no owner tg_id, or no settler engine)."
    )
