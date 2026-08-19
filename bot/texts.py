"""Every string the bot sends, as pure functions of already-fetched data.

TZ section 11 puts "тексты сообщений" in Week 5, and this is that file. It is
separate from the handlers for one practical reason and one structural one: the
copy for a product that takes money is worth reading on its own without a
dispatcher around it, and a pure ``data -> str`` function is testable without a
Telegram client, a database, or an event loop.

English, matching the README and :mod:`notifier.render`. ``users.lang`` exists in
the schema for the day this grows a second language; nothing here reads it yet,
and pretending otherwise with a one-language lookup table would be scaffolding
for a decision nobody has made.

Two pieces of copy are not copy — they are countermeasures, and editing them
without reading the threat model is a security change:

* the ``/start`` and ``/help`` safety rule (TZ 5.8/T1.5, TZ section 12): *the
  address changes only together with a new invoice; the bot never asks you to
  send funds to a different address, and never asks for a private key or seed
  phrase*. It is stated in the first message a user ever gets, so that the
  attack it describes — a compromised bot token quietly editing an old message,
  or a message arriving "afterwards" with a new address — contradicts something
  the user was already told.
* the ``/verify`` disclaimer (TZ 5.8/T1.4): a buyer **cannot** build a full
  derivation proof, because that needs the xpub and publishing the xpub is
  forbidden. Saying what the proof does not prove is the difference between a
  control and an advertisement.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence

from bot.formatting import code, esc, format_amount, format_deadline, format_usd
from bot.repository import (
    InvoiceStatusRow,
    OpenInvoiceRow,
    ProductRow,
    PurchaseRow,
)
from core.invoicing.proof import DerivationProof
from core.invoicing.service import InvoiceView

__all__ = [
    "SAFETY_RULE",
    "start",
    "shop",
    "buy_usage",
    "unknown_sku",
    "invoice_issued",
    "status",
    "status_not_found",
    "my",
    "verify_usage",
    "verify_proof",
    "help_text",
    "free_text_address",
    "free_text_tx_hash",
    "free_text_unknown",
    "admin_denied",
]

#: Repeated verbatim in `/start` and `/help`. One string rather than two
#: paraphrases: a user who compares the two must not find a difference to
#: interpret, and an attacker who wants to normalise "sometimes the address
#: changes" has to contradict the same sentence twice.
SAFETY_RULE = (
    "<b>Safety rules — please read once.</b>\n"
    "• The payment address changes <b>only</b> together with a new invoice. "
    "If a message ever asks you to send funds to a different address for an "
    "invoice you already have, it is not from us.\n"
    "• We will <b>never</b> ask for your private key, your seed phrase, or your "
    "wallet password. Nobody who needs them is legitimate.\n"
    "• Messages carrying an address are never edited. Status updates always "
    "arrive as new messages."
)


def start(*, is_new: bool, chain_name: str, asset_symbol: str) -> str:
    """``/start`` — registration, onboarding, and the explicit warning of TZ 3.1."""
    greeting = (
        "Welcome. This bot sells digital goods for crypto."
        if is_new
        else "Welcome back."
    )
    return (
        f"{greeting}\n\n"
        f"<b>We accept one network and one token:</b> {esc(asset_symbol)} on "
        f"{esc(chain_name)}. Anything sent on another network, or in another "
        "token, does not settle automatically and has to be sorted out by hand — "
        "see /help before you send anything unusual.\n\n"
        "How it works:\n"
        "1. /shop — see what is for sale\n"
        "2. /buy &lt;sku&gt; — get a payment address, an exact amount and a deadline\n"
        "3. pay from any wallet, then /status &lt;invoice_id&gt; to watch it land\n"
        "4. /my — what you own\n"
        "5. /verify &lt;invoice_id&gt; — check that the address really is ours\n\n"
        f"{SAFETY_RULE}"
    )


def shop(products: Sequence[ProductRow]) -> str:
    """``/shop`` — the catalogue with prices in USD (TZ 3.1)."""
    if not products:
        return "Nothing is on sale right now. Please check back later."
    lines = ["<b>On sale</b>", ""]
    for product in products:
        suffix = ""
        if product.kind == "subscription" and product.subscription_days:
            suffix = f" — {product.subscription_days} days"
        lines.append(
            f"• <b>{esc(product.title)}</b>{esc(suffix)} — "
            f"{format_usd(product.price_usd)}\n  {code(product.sku)}"
        )
    lines.append("")
    lines.append("Buy with <code>/buy &lt;sku&gt;</code>, e.g. /buy " + esc(products[0].sku))
    return "\n".join(lines)


def buy_usage() -> str:
    return (
        "Usage: <code>/buy &lt;sku&gt;</code>\n"
        "The sku is the monospaced code next to each item in /shop."
    )


def unknown_sku(sku: str) -> str:
    return (
        f"No item with the code {code(sku)} is on sale.\n"
        "Check /shop for the current list."
    )


def invoice_issued(
    view: InvoiceView, *, chain_name: str, page_url: str | None, now: dt.datetime | None = None
) -> str:
    """The one message in this bot that carries an address (TZ 3.1, 5.8/T1.5).

    Everything a wallet needs is in it and nothing that would need correcting
    later, because this message is never edited: the deadline is absolute as
    well as relative, and the status updates that follow arrive as new messages.

    The address appears twice on purpose — once on its own for a human to
    compare, once inside the EIP-681 string a wallet consumes. That repetition
    is the buyer-side check of TZ 5.8/T1.4: the same address in the message, in
    the payment string and on the invoice page, or something is wrong.
    """
    amount = format_amount(view.amount_due_raw, view.asset_decimals, view.asset_symbol)
    lines = [
        "<b>Invoice created.</b> Send the exact amount to the address below.",
        "",
        f"Amount: {code(amount)}",
        f"Network: {esc(chain_name)} (chain id {view.chain_id})",
        f"Token: {esc(view.asset_symbol)}",
        "",
        "Address:",
        code(view.address),
        "",
        "Or scan/paste this payment link in your wallet:",
        code(view.eip681()),
        "",
        f"Pay by {esc(format_deadline(view.expires_at, now=now))}. "
        "After that the quoted rate no longer applies and you will need a new invoice.",
        "",
        f"Invoice id: {code(view.invoice_id)}",
        f"Track it with /status {esc(view.invoice_id)}",
        f"Check the address is really ours: /verify {esc(view.invoice_id)}",
    ]
    if page_url:
        lines += ["", f"Invoice page: {esc(page_url)}"]
    lines += [
        "",
        "The address above will not change. Any message asking you to send "
        "funds somewhere else is not from us.",
    ]
    return "\n".join(lines)


_STATUS_SENTENCES = {
    "awaiting": "Waiting for your payment.",
    "seen": "We can see your transfer on-chain and are waiting for confirmations.",
    "partially_paid": "Part of the amount has arrived.",
    "paid": "Paid in full — your access is active.",
    "overpaid": "Paid, and you sent more than the total. The difference is being handled.",
    "expired": "This invoice expired. Nothing was charged; start a new order for a fresh quote.",
    "manual_review": (
        "This payment needs a manual check. Nothing is lost — we will come back to you."
    ),
    "cancelled": "This invoice was cancelled.",
    "reverted": "The payment for this invoice was rolled back by a chain reorganisation.",
}


def status(row: InvoiceStatusRow, *, now: dt.datetime | None = None) -> str:
    """``/status`` — "сколько пришло, сколько подтверждений, чего ждём" (TZ 3.1).

    No address. This process cannot run ``deriver.verify`` (TZ 5.3) and the
    address is already on screen in a message that is never edited, so repeating
    it here would be both unverified and the exact pattern TZ 5.8/T1.5 rules
    out — a later message carrying an address.
    """
    instant = dt.datetime.now(dt.UTC) if now is None else now
    received = format_amount(row.received_raw, row.asset_decimals, row.asset_symbol)
    due = format_amount(row.amount_due_raw, row.asset_decimals, row.asset_symbol)

    lines = [
        f"<b>{esc(row.product_title)}</b>",
        _STATUS_SENTENCES.get(row.status, f"State: {esc(row.status)}"),
        "",
        f"Received: {code(received)} of {code(due)}",
    ]
    if row.missing_raw > 0:
        missing = format_amount(row.missing_raw, row.asset_decimals, row.asset_symbol)
        lines.append(f"Still missing: {code(missing)}")
    if row.pending_count:
        pending = format_amount(row.pending_raw, row.asset_decimals, row.asset_symbol)
        seen = row.least_confirmations if row.least_confirmations is not None else 0
        lines.append(
            f"Unconfirmed: {code(pending)} — {seen}/{row.min_confirmations} confirmations"
        )
    if row.status in ("awaiting", "seen", "partially_paid"):
        lines += ["", f"Deadline: {esc(format_deadline(row.expires_at, now=instant))}"]
        if row.missing_raw > 0 and row.expires_at <= instant:
            lines.append(
                "Top-up window: "
                + esc(format_deadline(row.topup_window_until, now=instant))
            )
    lines += ["", f"Invoice id: {code(row.invoice_id)}"]
    return "\n".join(lines)


def status_not_found() -> str:
    """One answer for "no such invoice" and "not yours" (TZ 5.8/T1.7).

    A separate "that is not yours" would confirm the id exists, which is the one
    bit an enumeration attempt is buying.
    """
    return (
        "No such invoice.\n"
        "Check the id — it is the long code in the message that created the invoice, "
        "and /my lists your recent ones."
    )


def status_usage() -> str:
    return (
        "Usage: <code>/status &lt;invoice_id&gt;</code>\n"
        "The invoice id is the long code in the message that created the invoice. "
        "/my lists your recent ones."
    )


def my(
    purchases: Sequence[PurchaseRow],
    open_invoices: Sequence[OpenInvoiceRow],
    *,
    now: dt.datetime | None = None,
) -> str:
    """``/my`` — "история покупок и активные доступы" (TZ 3.1)."""
    instant = dt.datetime.now(dt.UTC) if now is None else now
    if not purchases and not open_invoices:
        return "You have not bought anything yet. /shop shows what is available."

    lines: list[str] = []
    active = [p for p in purchases if p.is_active(instant)]
    past = [p for p in purchases if not p.is_active(instant)]

    if active:
        lines.append("<b>Active access</b>")
        for item in active:
            until = (
                "no expiry"
                if item.expires_at is None
                else f"until {item.expires_at.astimezone(dt.UTC):%Y-%m-%d %H:%M} UTC"
            )
            lines.append(f"• {esc(item.product_title)} — {esc(until)}")
            lines.append(f"  {esc(item.content_ref)}")
        lines.append("")

    if open_invoices:
        lines.append("<b>Waiting for payment</b>")
        for invoice in open_invoices:
            lines.append(
                f"• {esc(invoice.product_title)} — {format_usd(invoice.amount_due_usd)}, "
                f"{esc(_STATUS_SENTENCES.get(invoice.status, invoice.status))}"
            )
            lines.append(f"  /status {esc(invoice.invoice_id)}")
        lines.append("")

    if past:
        lines.append("<b>Earlier purchases</b>")
        for item in past:
            note = "revoked" if item.revoked_at is not None else "expired"
            lines.append(
                f"• {esc(item.product_title)} — {esc(note)} "
                f"({item.granted_at.astimezone(dt.UTC):%Y-%m-%d})"
            )

    return "\n".join(lines).strip()


def verify_usage() -> str:
    return (
        "Usage: <code>/verify &lt;invoice_id&gt;</code>\n"
        "This shows where the payment address for that invoice comes from."
    )


def verify_proof(proof: DerivationProof, *, asked_by_owner: bool = False) -> str:
    """``/verify`` — the derivation proof of TZ 5.8/T1.4, limits included.

    The limit is in the message rather than only in the docs, because the person
    reading it is the one who would otherwise over-trust it. A buyer cannot
    complete this check: it needs the account xpub, and publishing the xpub is
    what T4 forbids. What a buyer *can* do is compare one address across three
    independent channels, and the message says so instead of implying more.
    """
    lines = [
        "<b>Derivation proof</b>",
        "",
        f"Invoice: {code(proof.invoice_id)}",
        f"Parent key fingerprint: {code(proof.xpub_fingerprint)}",
        f"Derivation path: {code(proof.derivation_path)}",
        "Address:",
        code(proof.address),
        "",
        "These values came from the process that holds the extended public key, "
        "not from the invoice row — the address above was derived again just now "
        "and compared before this message was built.",
        "",
    ]
    if asked_by_owner:
        lines.append(
            "As the key holder you can reproduce this yourself: derive the path "
            "above from the account xpub with the matching fingerprint in any "
            "offline tool and compare the address character for character."
        )
    else:
        lines.append(
            "<b>What this does and does not prove.</b> Reproducing the address "
            "from the path requires the account extended public key, which we do "
            "not publish — so this is a proof the operator can complete and you "
            "cannot. What you can check without trusting us: the same address "
            "appears in the invoice message, in the payment link, and on the "
            "invoice page, and it never changes for the life of the invoice. If "
            "those three ever disagree, stop and contact support."
        )
    return "\n".join(lines)


def help_text(*, chain_name: str, asset_symbol: str) -> str:
    """``/help`` — TZ 3.1's half of support, written down once."""
    return (
        "<b>Something went wrong with a payment?</b>\n\n"
        "<b>I sent the wrong amount.</b>\n"
        "Too little: send the rest to the <i>same</i> address. The top-up window "
        "stays open for a day after the invoice deadline, and /status shows "
        "exactly how much is still missing.\n"
        "Too much: your access is released as normal and the difference is either "
        "credited to your balance or refunded by hand — we will message you.\n\n"
        "<b>I sent the wrong token.</b>\n"
        f"We settle {esc(asset_symbol)} only. Another token on {esc(chain_name)} is "
        "seen but not credited automatically; it becomes a manual case and we will "
        "contact you.\n\n"
        "<b>I sent on the wrong network.</b>\n"
        f"The address exists on other EVM chains too, but only {esc(chain_name)} is "
        "watched. Funds sent elsewhere are not lost and are not automatic either — "
        "message us with the transaction hash.\n\n"
        "<b>I sent to the wrong address entirely.</b>\n"
        "We cannot recover that: we never hold the keys to an address we did not "
        "generate, and the ones we do generate cannot be spent from this server "
        "at all.\n\n"
        "<b>My payment does not show up.</b>\n"
        "Paste the transaction hash here. Confirmations take a few minutes; "
        "/status &lt;invoice_id&gt; shows how many are in.\n\n"
        f"{SAFETY_RULE}\n\n"
        "Commands: /start /shop /buy /status /my /verify /help"
    )


def free_text_address(address: str) -> str:
    return (
        f"That looks like a wallet address ({code(address)}).\n\n"
        "If it is the address from one of your invoices, /status "
        "&lt;invoice_id&gt; is the way to check on it — we look payments up by "
        "invoice, not by address.\n"
        "If you are asking where to send funds: only the address in the invoice "
        "message is valid, and it never changes. See /help."
    )


def free_text_tx_hash(tx_hash: str, *, explorer_url: str | None) -> str:
    lines = [
        f"That looks like a transaction hash ({code(tx_hash)}).",
        "",
        "We match payments by receiving address, not by hash, so you do not need "
        "to send it to us for a normal payment — /status &lt;invoice_id&gt; will "
        "show it as soon as it is in a block.",
    ]
    if explorer_url:
        lines += ["", f"Look it up yourself: {esc(explorer_url)}"]
    lines += [
        "",
        "If it has been confirmed for a while and /status still shows nothing, "
        "keep this hash — that is exactly what we need to sort it out.",
    ]
    return "\n".join(lines)


def free_text_unknown() -> str:
    return (
        "I did not recognise that.\n"
        "/shop to browse, /buy &lt;sku&gt; to order, /status &lt;invoice_id&gt; to "
        "check a payment, /help if something went wrong with one."
    )


def admin_denied() -> str:
    """What a non-owner gets for an admin command (TZ 3.4, 5.8/T7).

    The same sentence an unknown command gets, and that is the point: confirming
    that ``/resolve`` exists tells whoever is probing that there is an owner
    worth phishing, and the command list in /help does not mention it.
    """
    return free_text_unknown()
