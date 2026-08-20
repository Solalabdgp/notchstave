/* The invoice page's only moving parts: the QR, the countdown, the status poll.
 *
 * Loaded with `defer` from the same origin, because `script-src 'self'` (TZ
 * 3.2, 5.8/T1.6). It reads its configuration out of `data-` attributes on
 * `#invoice` rather than from an inline `<script>` block, since an inline block
 * would need `'unsafe-inline'` — the one directive that would make the rest of
 * the policy decorative.
 *
 * THE RULE THIS FILE IS WRITTEN AROUND: it never writes an address.
 *
 * The address, the amount and the EIP-681 string are server-rendered into the
 * document and this script does not have a code path that replaces them. The
 * QR is drawn from the `data-eip681` attribute, which is the same string the
 * page displays as text below it, so a buyer comparing what their wallet shows
 * against what the page says is comparing against the thing that was actually
 * encoded (TZ 5.8/T1.4). The poll deliberately reads the *status* endpoint,
 * whose payload contains no address at all (see api/schemas.py), so there is no
 * response this script could receive that would let it repaint one.
 *
 * That is the browser-side counterpart of TZ 5.8/T1.5, where the bot never
 * edits a message that contains an address.
 */
'use strict';

(function () {
  var root = document.getElementById('invoice');
  if (!root) return;

  // --- QR ---------------------------------------------------------------

  /* Error-correction level M, chosen and then left alone.
   *
   * The payload is an EIP-681 URI: ~110-140 bytes for every chain and asset in
   * TZ 2, which is version 7-9 at this level. L would shave one version off and
   * buy nothing a buyer would notice; H would add three versions and make the
   * modules small enough on a phone screen that scanning gets harder, which is
   * the failure this page cannot afford. M restores ~15% of codewords, which
   * covers a thumb over the corner.
   */
  var ECL = 'M';

  function drawQr(text) {
    var canvas = document.getElementById('qr');
    if (!canvas || !canvas.getContext || typeof NotchstaveQR === 'undefined') return;

    var result;
    try {
      result = NotchstaveQR.encodeToMatrix(text, ECL);
    } catch (e) {
      // A QR that cannot be produced must not become a QR that is wrong. Leave
      // the canvas blank and let the text fallback below carry the payment.
      canvas.remove();
      return;
    }

    // A four-module quiet zone is required by the spec, and scanners really do
    // fail without it when the page background runs to the edge of the symbol.
    var quiet = 4;
    var modules = result.size + quiet * 2;
    var ctx = canvas.getContext('2d');

    // Integer scale, then size the canvas to the exact multiple. A fractional
    // module width makes neighbouring modules land on different pixel
    // boundaries, which is how a QR turns into a symbol that scans on one phone
    // and not on another.
    var target = canvas.width || 264;
    var scale = Math.max(1, Math.floor(target / modules));
    var side = modules * scale;
    canvas.width = side;
    canvas.height = side;
    canvas.style.width = '100%';
    canvas.style.maxWidth = side + 'px';

    // Painted rather than inherited: a dark-mode stylesheet that flipped the
    // page background under a transparent symbol would inverse the QR, and an
    // inverted QR does not scan on most readers.
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, side, side);
    ctx.fillStyle = '#000000';
    for (var y = 0; y < result.size; y++) {
      for (var x = 0; x < result.size; x++) {
        if (result.modules[y][x]) {
          ctx.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale);
        }
      }
    }
  }

  drawQr(root.getAttribute('data-eip681') || '');

  // --- Countdown --------------------------------------------------------

  /* Driven from the server's `seconds_until_expiry` and a monotonic clock, not
   * from `Date.now()` against the server's `expires_at`. A phone whose clock is
   * an hour fast would otherwise show a live invoice as expired — and a buyer
   * who is told their invoice is dead does not send the payment.
   */
  var timerEl = document.getElementById('timer');
  var remaining = parseInt(root.getAttribute('data-seconds-until-expiry') || '0', 10);
  var startedAt = (window.performance && performance.now) ? performance.now() : null;
  var initialRemaining = remaining;

  function plural(n, word) {
    return n + ' ' + word + (n === 1 ? '' : 's');
  }

  function renderTimer() {
    if (!timerEl) return;
    var left = remaining;
    if (startedAt !== null) {
      left = initialRemaining - Math.floor((performance.now() - startedAt) / 1000);
    }
    if (left <= 0) {
      timerEl.textContent = 'This invoice has passed its deadline.';
      return;
    }
    var minutes = Math.floor(left / 60);
    var seconds = left % 60;
    timerEl.textContent =
      minutes > 0
        ? 'Time left: ' + plural(minutes, 'minute') + ' ' + plural(seconds, 'second')
        : 'Time left: ' + plural(seconds, 'second');
  }

  renderTimer();
  setInterval(renderTimer, 1000);

  // --- Status poll ------------------------------------------------------

  var stageEl = document.getElementById('stage-line');
  var statusUrl = root.getAttribute('data-status-url');
  var pollMs = Math.max(1000, (parseFloat(root.getAttribute('data-poll-seconds')) || 2) * 1000);

  /* The same wording as `api/page.py::_stage_sentence`, in the same order.
   * `api/tests/test_stages.py` asserts the two vocabularies match the `Stage`
   * enum, so a stage added on the server without a sentence here fails the
   * suite rather than rendering an empty line at a buyer.
   */
  function sentence(status) {
    switch (status.stage) {
      case 'granted':
        return 'Paid. Access granted.';
      case 'paid':
        return 'Paid. Delivering access...';
      case 'confirming':
        return status.confirmations === null || status.confirmations === undefined
          ? 'Transaction seen. Waiting for confirmations.'
          : 'Transaction seen — ' + status.confirmations + '/' +
            status.required_confirmations + ' confirmations.';
      case 'underpaid':
        return 'Received part of the amount. Send ' + status.amount_outstanding_raw +
          ' more base units to the same address.';
      case 'expired':
        return 'This invoice expired without payment.';
      case 'manual_review':
        return 'This payment needs a manual check. Support has been notified.';
      case 'reverted':
        return 'A confirmed payment was rolled back by a chain reorganisation.';
      case 'cancelled':
        return 'This invoice was cancelled.';
      default:
        return 'Waiting for payment.';
    }
  }

  var stopped = false;

  function apply(status) {
    // `textContent`, never `innerHTML`. Everything in `status` came off the
    // wire, and the one page in this system whose content is an address is not
    // the place to parse server output as markup (TZ 5.8/T1 vector 2).
    if (stageEl) stageEl.textContent = sentence(status);

    root.setAttribute('data-stage', status.stage);
    if (typeof status.seconds_until_expiry === 'number') {
      // Re-anchor the countdown on every poll, so a page left open for an hour
      // does not drift away from the server's view of the deadline.
      initialRemaining = status.seconds_until_expiry;
      remaining = status.seconds_until_expiry;
      startedAt = (window.performance && performance.now) ? performance.now() : null;
    }

    // Stop polling once nothing can change. `granted` is the end of the ladder;
    // the other three are terminal states a poll cannot move. Leaving the
    // interval running would keep a tab hitting a verified read every two
    // seconds for as long as it is open.
    if (
      status.stage === 'granted' ||
      status.stage === 'expired' ||
      status.stage === 'cancelled' ||
      status.stage === 'reverted'
    ) {
      stopped = true;
    }
  }

  function poll() {
    if (stopped || !statusUrl) return;
    fetch(statusUrl, { credentials: 'omit', headers: { accept: 'application/json' } })
      .then(function (r) {
        // 404 means the token stopped resolving — expired, or cancelled out
        // from under the page. Stop rather than retry: the endpoint will not
        // start answering again, and a page that hammers it is a page that
        // turns one dead link into sustained load.
        if (r.status === 404 || r.status === 409) {
          stopped = true;
          return null;
        }
        return r.ok ? r.json() : null;
      })
      .then(function (status) {
        if (status) apply(status);
      })
      .catch(function () {
        // A dropped request is normal on a phone changing networks. Say nothing
        // and let the next tick try again — an error banner over a payment page
        // reads as "something is wrong with my money".
      });
  }

  setInterval(poll, pollMs);
})();
