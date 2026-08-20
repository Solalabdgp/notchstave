"""The invoice page's HTML, assembled in Python with no template engine.

Three constraints shape every decision in this file, and all three come from the
threat model rather than from taste.

**No inline script, because the CSP says ``script-src 'self'`` (TZ 5.8/T1.6).**
That rules out the usual way of handing server data to a page — a
``<script>window.__DATA__ = {...}</script>`` block — since it would need
``'unsafe-inline'``, which is the single directive that would make the rest of
the policy decorative. Data therefore travels on ``data-`` attributes and the
external script reads them out of the DOM. This is not a workaround; it is the
arrangement the policy is designed to force.

**No template engine, because there is no template engine.** Jinja2 is not a
dependency of this project and adding one to render a single page — on the one
page in the system whose entire content is an address — would be a new
transitive dependency inside T1's blast radius. The page is built from f-strings
over values that are individually escaped by :func:`_esc`.

**Everything interpolated is escaped, and the escaping is not optional.** The
values here come from the database. The threat model's T1 vector 1 is a database
compromise; an attacker who can write ``invoices`` and gets their content
reflected unescaped into this page has upgraded a data tamper into script
execution on the page that displays the address (T1 vector 2). So there is one
escape function, every hole goes through it, and the test suite asserts an
address containing markup comes back inert.

----

**Why the address is server-rendered rather than fetched.** The page works with
JavaScript disabled, and the address a buyer reads does not depend on a fetch
that an injected script could have intercepted or raced. The script only touches
what moves: the countdown, the polled status, and the QR — which it draws from
the EIP-681 string already present in the document, never from a second fetch.
That is the browser-side expression of TZ 5.8/T1.4's "one point of truth".
"""

from __future__ import annotations

from html import escape

from api.schemas import InvoiceOut

__all__ = ["render_invoice", "render_not_found", "render_blocked"]


def _esc(value: object) -> str:
    """The only way a value reaches the document. ``quote=True`` covers attributes."""
    return escape(str(value), quote=True)


_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{title}</title>
<link rel="stylesheet" href="/static/invoice.css">
</head>
<body>
"""

_FOOT = """</body>
</html>
"""


def _shell(title: str, body: str, *, scripts: tuple[str, ...] = ()) -> str:
    tags = "".join(f'<script src="{_esc(src)}" defer></script>\n' for src in scripts)
    return _HEAD.format(title=_esc(title)) + body + tags + _FOOT


def render_invoice(payload: InvoiceOut, *, poll_seconds: float, status_url: str) -> str:
    """The page of TZ 3.2: address, amount, QR string, live status, countdown.

    The ``data-`` attributes on ``#invoice`` are the contract with
    ``/static/invoice.js``. ``data-eip681`` in particular is the *same string*
    that is rendered visibly in the ``<code>`` block below — the script reads
    the attribute, draws the QR from it, and never receives an address by any
    other route. A buyer comparing the visible string against what their wallet
    shows after scanning is performing the check TZ 5.8/T1.4 leaves available to
    someone without an xpub.

    ``status_url`` is passed in rather than built here from ``payload``, because
    the only key that opens the status endpoint is the ``public_token`` and
    :class:`~api.schemas.InvoiceOut` deliberately does not carry it — see that
    module on what the public payload is scoped to. The caller in
    :mod:`api.routes` has the token from the path it was routed on.
    """
    status = payload.status
    confirmations = "" if status.confirmations is None else str(status.confirmations)

    body = f"""<main id="invoice"
  data-status-url="{_esc(status_url)}"
  data-poll-seconds="{_esc(poll_seconds)}"
  data-eip681="{_esc(payload.eip681)}"
  data-seconds-until-expiry="{_esc(status.seconds_until_expiry)}"
  data-stage="{_esc(status.stage)}"
  data-confirmations="{_esc(confirmations)}"
  data-required-confirmations="{_esc(status.required_confirmations)}">

  <h1>Send {_esc(payload.amount_due_display)} {_esc(payload.asset_symbol)}</h1>
  <p class="usd">${_esc(payload.amount_due_usd)} &middot; chain {_esc(payload.chain_id)}</p>

  <section class="qr" aria-label="Payment QR code">
    <canvas id="qr" width="264" height="264"
            role="img"
            aria-label="QR code encoding the payment request"></canvas>
    <p id="qr-fallback" class="fallback">
      Scan with a wallet, or copy the address below.
    </p>
  </section>

  <section class="field">
    <h2>Address</h2>
    <code id="address" class="mono selectable">{_esc(payload.address)}</code>
  </section>

  <section class="field">
    <h2>Exact amount (base units)</h2>
    <code class="mono selectable">{_esc(payload.amount_due_raw)}</code>
  </section>

  <section class="field">
    <h2>Payment request</h2>
    <p class="hint">
      The QR above encodes exactly this text. If your wallet shows a different
      address, stop and do not send anything.
    </p>
    <code id="eip681" class="mono selectable wrap">{_esc(payload.eip681)}</code>
  </section>

  <section class="status" aria-live="polite">
    <h2>Status</h2>
    <p id="stage-line">{_esc(_stage_sentence(payload))}</p>
    <p id="timer" class="timer"></p>
    <noscript>
      <p class="hint">
        Live updates need JavaScript. Reload this page to refresh the status.
      </p>
    </noscript>
  </section>
</main>
"""
    return _shell(
        f"Invoice — {payload.amount_due_display} {payload.asset_symbol}",
        body,
        scripts=("/static/qr.js", "/static/invoice.js"),
    )


def _stage_sentence(payload: InvoiceOut) -> str:
    """The server-rendered first draft of the line the script then keeps current.

    Rendered here as well as in JavaScript so the page says something true with
    scripting disabled. The two must agree, which is why the wording lives in
    one table here and is mirrored by ``invoice.js`` — the test suite asserts
    the stage vocabulary matches the :class:`api.stages.Stage` enum so a new
    stage cannot be added without both sides being updated.
    """
    status = payload.status
    stage = str(status.stage)

    if stage == "granted":
        return "Paid. Access granted."
    if stage == "paid":
        return "Paid. Delivering access..."
    if stage == "confirming":
        seen = status.confirmations
        if seen is None:
            return "Transaction seen. Waiting for confirmations."
        return (
            f"Transaction seen — {seen}/{status.required_confirmations} confirmations."
        )
    if stage == "underpaid":
        return (
            f"Received part of the amount. Send {status.amount_outstanding_raw} more "
            "base units to the same address."
        )
    if stage == "expired":
        return "This invoice expired without payment."
    if stage == "manual_review":
        return "This payment needs a manual check. Support has been notified."
    if stage == "reverted":
        return "A confirmed payment was rolled back by a chain reorganisation."
    if stage == "cancelled":
        return "This invoice was cancelled."
    return "Waiting for payment."


def render_not_found() -> str:
    """404 for a wrong or expired token — one page for both (TZ 5.8/T1.7).

    Carries no hint about which it was. A page that said "expired" would confirm
    to somebody guessing tokens that their guess had once been real.
    """
    body = """<main class="notice">
  <h1>Nothing here</h1>
  <p>This payment link is not valid, or it has expired.</p>
  <p class="hint">If you were sent here by the bot, open the invoice again from your chat.</p>
</main>
"""
    return _shell("Invoice not found", body)


def render_blocked(message: str) -> str:
    """The integrity-failure page. Its whole job is to stop a payment.

    Deliberately loud and deliberately without an address, an amount or a retry
    link: TZ 5.8/T1 classifies a failed check as suspected compromise, and the
    only correct outcome is that the buyer sends nothing.
    """
    body = f"""<main class="notice danger">
  <h1>Do not send funds</h1>
  <p>{_esc(message)}</p>
</main>
"""
    return _shell("Invoice blocked", body)
