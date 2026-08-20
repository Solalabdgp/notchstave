/* QR Code encoder — ISO/IEC 18004, byte mode. Self-hosted, no dependencies.
 *
 * WHY THIS FILE EXISTS AT ALL, given that a hundred QR libraries do this:
 * TZ 5.8/T1.6 requires `script-src 'self'` with no CDN and no third-party
 * assets, because the invoice page's entire content is an address and any
 * external script is a channel for substituting it. So the encoder ships with
 * the page. TZ 5.8/T1.4 additionally forbids rendering the QR server-side as an
 * image: the buyer's only available check without an xpub is that the address
 * is identical in the bot message, in the page text and inside the QR, and a
 * server-rendered PNG breaks that check silently because nobody reads a QR with
 * their eyes. The QR is therefore drawn in the browser from the same EIP-681
 * string that is displayed as text beside it.
 *
 * WHAT THIS FILE IS TRUSTED FOR, AND WHAT IT IS NOT — the honest version,
 * because the alternative is a comment that oversells a hand-written encoder on
 * a payment page:
 *
 * This symbol is a *convenience*. It is not the payment request and it is not
 * what the buyer is asked to verify. The payment request is the EIP-681 string,
 * which is server-rendered into the document, displayed as text beside this
 * canvas, and returned verbatim in the JSON — one value, three places, and
 * `api/tests/test_public_page.py` asserts the three are character-for-character
 * identical. That string is the artifact TZ 5.8/T1.4 makes authoritative, and
 * it is the one a buyer can actually read.
 *
 * So the failure mode this arrangement is built against is not "the encoder has
 * a bug". It is "the QR and the text disagree, and nobody can see it". They
 * cannot disagree, because there is only one string: `drawQr` in invoice.js
 * reads `data-eip681` — the same attribute the visible `<code>` block is
 * rendered from — and `encodeToMatrix` is a pure function of it. If a constant
 * table below is mistyped, the symbol fails to scan or scans to garbage; it
 * cannot scan to a *different valid address*, because no other address is
 * anywhere in this file's input. A wallet that shows something other than the
 * text on the page is the stop condition the page tells the buyer about in so
 * many words.
 *
 * That is also why the Python suite does not decode this. An earlier draft ran
 * the file under Node and read the symbol back with a decoder built from
 * `segno`'s spec tables. It worked, and it was the wrong shape: it put a
 * JavaScript runtime, a QR library and ~500 lines of decoder into the test
 * dependencies of a process whose contribution to the QR is a string. Server-
 * side QR verification is verification of something the server does not emit.
 *
 * If this encoder ever needs proving rather than trusting, the place for that
 * is a browser test that scans the rendered canvas — same layer as the code
 * under test — not a Python one.
 *
 * Scope: byte mode only. The input is an EIP-681 URI — mixed case, `:@/?=&`,
 * hex — so alphanumeric mode never applies, and a mode chooser that could never
 * pick the other branch would be untested code on a payment path.
 */
'use strict';

var NotchstaveQR = (function () {
  // --- Constants from ISO/IEC 18004, indexed [ecl][version], version 1..40. ---
  // Index 0 is a placeholder so the version number indexes directly.
  var ECC_CODEWORDS_PER_BLOCK = {
    L: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28,
        28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    M: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26,
        26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
    Q: [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26,
        30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    H: [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26,
        28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]
  };

  var NUM_ERROR_CORRECTION_BLOCKS = {
    L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7,
        8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14,
        16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
    Q: [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21,
        20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
    H: [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25,
        25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81]
  };

  // Format-information bits are XORed with this before placement (spec 8.9).
  var FORMAT_MASK = 0x5412;
  var ECL_BITS = { L: 1, M: 0, Q: 3, H: 2 };
  var MIN_VERSION = 1;
  var MAX_VERSION = 40;

  // --- GF(256) arithmetic, primitive polynomial 0x11D (spec Annex B). ---

  function gfMultiply(x, y) {
    var z = 0;
    for (var i = 7; i >= 0; i--) {
      // Russian-peasant multiplication with reduction folded in, so no
      // log/antilog tables are needed and there is no table to mistype.
      z = ((z << 1) ^ ((z >>> 7) * 0x11d)) & 0xff;
      z ^= ((y >>> i) & 1) * x;
    }
    return z & 0xff;
  }

  function reedSolomonDivisor(degree) {
    // Product of (x - r^i) for i in [0, degree), coefficients high-to-low with
    // the leading 1 left implicit.
    var result = [];
    for (var i = 0; i < degree - 1; i++) result.push(0);
    result.push(1);

    var root = 1;
    for (var d = 0; d < degree; d++) {
      for (var j = 0; j < result.length; j++) {
        result[j] = gfMultiply(result[j], root);
        if (j + 1 < result.length) result[j] ^= result[j + 1];
      }
      root = gfMultiply(root, 0x02);
    }
    return result;
  }

  function reedSolomonRemainder(data, divisor) {
    var result = [];
    var i;
    for (i = 0; i < divisor.length; i++) result.push(0);

    for (i = 0; i < data.length; i++) {
      var factor = data[i] ^ result.shift();
      result.push(0);
      for (var j = 0; j < divisor.length; j++) {
        result[j] ^= gfMultiply(divisor[j], factor);
      }
    }
    return result;
  }

  // --- Capacity arithmetic (spec 7.4.10 / Annex). ---

  function numRawDataModules(version) {
    var result = (16 * version + 128) * version + 64;
    if (version >= 2) {
      var numAlign = Math.floor(version / 7) + 2;
      result -= (25 * numAlign - 10) * numAlign - 55;
      if (version >= 7) result -= 36;
    }
    return result;
  }

  function numDataCodewords(version, ecl) {
    return (
      Math.floor(numRawDataModules(version) / 8) -
      ECC_CODEWORDS_PER_BLOCK[ecl][version] * NUM_ERROR_CORRECTION_BLOCKS[ecl][version]
    );
  }

  function alignmentPatternPositions(version) {
    if (version === 1) return [];
    var numAlign = Math.floor(version / 7) + 2;
    var size = version * 4 + 17;
    var step = version === 32
      ? 26
      : Math.ceil((size - 13) / (numAlign * 2 - 2)) * 2;
    var result = [6];
    for (var pos = size - 7; result.length < numAlign; pos -= step) {
      result.splice(1, 0, pos);
    }
    return result;
  }

  // --- Bit buffer ---

  function BitBuffer() {
    this.bits = [];
  }
  BitBuffer.prototype.append = function (value, length) {
    for (var i = length - 1; i >= 0; i--) {
      this.bits.push((value >>> i) & 1);
    }
  };

  // --- Data encoding (byte mode) ---

  function toUtf8(text) {
    // `unescape(encodeURIComponent(...))` is the classic trick; TextEncoder is
    // cleaner and is available in every browser that runs a Telegram Mini App.
    return Array.prototype.slice.call(new TextEncoder().encode(text));
  }

  function charCountBits(version) {
    // Byte mode: 8 bits for versions 1-9, 16 bits for 10-40 (spec table 3).
    return version <= 9 ? 8 : 16;
  }

  function chooseVersion(byteLength, ecl) {
    for (var version = MIN_VERSION; version <= MAX_VERSION; version++) {
      var capacityBits = numDataCodewords(version, ecl) * 8;
      var needed = 4 + charCountBits(version) + byteLength * 8;
      if (needed <= capacityBits) return version;
    }
    throw new Error('data too long for a QR code at error-correction level ' + ecl);
  }

  function buildCodewords(bytes, version, ecl) {
    var capacityBits = numDataCodewords(version, ecl) * 8;
    var bb = new BitBuffer();
    bb.append(0x4, 4); // byte-mode indicator
    bb.append(bytes.length, charCountBits(version));
    for (var i = 0; i < bytes.length; i++) bb.append(bytes[i], 8);

    // Terminator: up to four zero bits, then zero-pad to a byte boundary.
    bb.append(0, Math.min(4, capacityBits - bb.bits.length));
    bb.append(0, (8 - (bb.bits.length % 8)) % 8);

    // Alternating pad codewords until full (spec 7.4.10).
    for (var pad = 0xec; bb.bits.length < capacityBits; pad ^= 0xec ^ 0x11) {
      bb.append(pad, 8);
    }

    var codewords = [];
    for (var k = 0; k < bb.bits.length; k += 8) {
      var byteVal = 0;
      for (var b = 0; b < 8; b++) byteVal = (byteVal << 1) | bb.bits[k + b];
      codewords.push(byteVal);
    }
    return codewords;
  }

  function interleave(data, version, ecl) {
    var numBlocks = NUM_ERROR_CORRECTION_BLOCKS[ecl][version];
    var eccLen = ECC_CODEWORDS_PER_BLOCK[ecl][version];
    var rawCodewords = Math.floor(numRawDataModules(version) / 8);
    var numShortBlocks = numBlocks - (rawCodewords % numBlocks);
    var shortBlockLen = Math.floor(rawCodewords / numBlocks);

    var blocks = [];
    var divisor = reedSolomonDivisor(eccLen);
    var i, j;
    var taken = 0;
    for (i = 0; i < numBlocks; i++) {
      var dataLen = shortBlockLen - eccLen + (i < numShortBlocks ? 0 : 1);
      var dat = data.slice(taken, taken + dataLen);
      taken += dataLen;
      blocks.push({ data: dat, ecc: reedSolomonRemainder(dat, divisor) });
    }

    // Column-major over data, then over ECC. The shorter blocks have no module
    // in the final data column, which is what `i < numShortBlocks` skips.
    var result = [];
    for (i = 0; i < shortBlockLen - eccLen + 1; i++) {
      for (j = 0; j < blocks.length; j++) {
        if (i < blocks[j].data.length) result.push(blocks[j].data[i]);
      }
    }
    for (i = 0; i < eccLen; i++) {
      for (j = 0; j < blocks.length; j++) result.push(blocks[j].ecc[i]);
    }
    return result;
  }

  // --- Module placement ---

  function Matrix(size) {
    this.size = size;
    this.modules = [];
    this.reserved = [];
    for (var y = 0; y < size; y++) {
      var row = [];
      var res = [];
      for (var x = 0; x < size; x++) {
        row.push(false);
        res.push(false);
      }
      this.modules.push(row);
      this.reserved.push(res);
    }
  }

  Matrix.prototype.set = function (x, y, dark, reserve) {
    this.modules[y][x] = dark;
    if (reserve) this.reserved[y][x] = true;
  };

  function drawFunctionPatterns(m, version, ecl) {
    var size = m.size;
    var i, j;

    // Timing patterns.
    for (i = 0; i < size; i++) {
      m.set(6, i, i % 2 === 0, true);
      m.set(i, 6, i % 2 === 0, true);
    }

    // Three finder patterns with their separators.
    drawFinder(m, 3, 3);
    drawFinder(m, size - 4, 3);
    drawFinder(m, 3, size - 4);

    // Alignment patterns, skipping the three that collide with finders.
    var positions = alignmentPatternPositions(version);
    var n = positions.length;
    for (i = 0; i < n; i++) {
      for (j = 0; j < n; j++) {
        var skip =
          (i === 0 && j === 0) ||
          (i === 0 && j === n - 1) ||
          (i === n - 1 && j === 0);
        if (!skip) drawAlignment(m, positions[i], positions[j]);
      }
    }

    // Reserve the format-information areas by drawing a dummy copy of them.
    // Reserving with a hand-written coordinate loop instead is how (8,6) and
    // (6,8) — which belong to the timing patterns, not to the format field —
    // get quietly overwritten with light modules; the format field skips index
    // 6 in both directions precisely because the timing pattern owns it. Using
    // the real writer here means the reserved set and the written set cannot
    // disagree, because they are the same code.
    drawFormatBits(m, ecl, 0);

    // Version information for version >= 7 (spec 8.10).
    if (version >= 7) {
      var rem = version;
      for (i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
      var bits = ((version << 12) | rem) >>> 0;
      for (i = 0; i < 18; i++) {
        var dark = ((bits >>> i) & 1) !== 0;
        var a = size - 11 + (i % 3);
        var b = Math.floor(i / 3);
        m.set(a, b, dark, true);
        m.set(b, a, dark, true);
      }
    }
  }

  function drawFinder(m, cx, cy) {
    for (var dy = -4; dy <= 4; dy++) {
      for (var dx = -4; dx <= 4; dx++) {
        var dist = Math.max(Math.abs(dx), Math.abs(dy));
        var x = cx + dx;
        var y = cy + dy;
        if (x >= 0 && x < m.size && y >= 0 && y < m.size) {
          m.set(x, y, dist !== 2 && dist !== 4, true);
        }
      }
    }
  }

  function drawAlignment(m, cx, cy) {
    for (var dy = -2; dy <= 2; dy++) {
      for (var dx = -2; dx <= 2; dx++) {
        m.set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1, true);
      }
    }
  }

  function drawCodewords(m, codewords) {
    var size = m.size;
    var i = 0; // bit index into codewords

    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5; // the vertical timing pattern column
      for (var vert = 0; vert < size; vert++) {
        for (var k = 0; k < 2; k++) {
          var x = right - k;
          var upward = ((right + 1) & 2) === 0;
          var y = upward ? size - 1 - vert : vert;
          if (!m.reserved[y][x] && i < codewords.length * 8) {
            m.modules[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0;
            i++;
          }
          // Remaining modules past the data stay light, per spec 7.7.3.
        }
      }
    }
  }

  function maskCondition(mask, x, y) {
    switch (mask) {
      case 0: return (x + y) % 2 === 0;
      case 1: return y % 2 === 0;
      case 2: return x % 3 === 0;
      case 3: return (x + y) % 3 === 0;
      case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
      case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
      case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
      case 7: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
      default: throw new Error('bad mask ' + mask);
    }
  }

  function applyMask(m, mask) {
    for (var y = 0; y < m.size; y++) {
      for (var x = 0; x < m.size; x++) {
        if (!m.reserved[y][x] && maskCondition(mask, x, y)) {
          m.modules[y][x] = !m.modules[y][x];
        }
      }
    }
  }

  function drawFormatBits(m, ecl, mask) {
    var data = (ECL_BITS[ecl] << 3) | mask;
    var rem = data;
    for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    var bits = ((data << 10) | rem) ^ FORMAT_MASK;

    var size = m.size;
    var j;
    // Copy 1 — around the top-left finder.
    for (j = 0; j <= 5; j++) m.set(8, j, ((bits >>> j) & 1) !== 0, true);
    m.set(8, 7, ((bits >>> 6) & 1) !== 0, true);
    m.set(8, 8, ((bits >>> 7) & 1) !== 0, true);
    m.set(7, 8, ((bits >>> 8) & 1) !== 0, true);
    for (j = 9; j < 15; j++) m.set(14 - j, 8, ((bits >>> j) & 1) !== 0, true);

    // Copy 2 — split between the other two finders.
    for (j = 0; j < 8; j++) m.set(size - 1 - j, 8, ((bits >>> j) & 1) !== 0, true);
    for (j = 8; j < 15; j++) m.set(8, size - 15 + j, ((bits >>> j) & 1) !== 0, true);
    m.set(8, size - 8, true, true);
  }

  // --- Penalty scoring (spec 7.8.3), used to pick the mask. ---

  function penalty(m) {
    var size = m.size;
    var score = 0;
    var x, y, i;

    // Rule 1: runs of five or more same-coloured modules in a line.
    for (y = 0; y < size; y++) {
      score += lineRuns(m, size, y, true);
    }
    for (x = 0; x < size; x++) {
      score += lineRuns(m, size, x, false);
    }

    // Rule 2: 2x2 blocks of one colour.
    for (y = 0; y < size - 1; y++) {
      for (x = 0; x < size - 1; x++) {
        var c = m.modules[y][x];
        if (
          c === m.modules[y][x + 1] &&
          c === m.modules[y + 1][x] &&
          c === m.modules[y + 1][x + 1]
        ) {
          score += 3;
        }
      }
    }

    // Rule 3: the 1:1:3:1:1 finder-like pattern with four light modules beside it.
    var patternA = [true, false, true, true, true, false, true, false, false, false, false];
    var patternB = [false, false, false, false, true, false, true, true, true, false, true];
    for (y = 0; y < size; y++) {
      for (x = 0; x + 11 <= size; x++) {
        if (matches(m, x, y, patternA, true) || matches(m, x, y, patternB, true)) score += 40;
      }
    }
    for (x = 0; x < size; x++) {
      for (y = 0; y + 11 <= size; y++) {
        if (matches(m, x, y, patternA, false) || matches(m, x, y, patternB, false)) score += 40;
      }
    }

    // Rule 4: deviation of the dark-module proportion from 50%.
    var dark = 0;
    for (y = 0; y < size; y++) {
      for (x = 0; x < size; x++) if (m.modules[y][x]) dark++;
    }
    var total = size * size;
    var k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
    score += k * 10;

    return score;
  }

  function lineRuns(m, size, index, horizontal) {
    var score = 0;
    var runLength = 0;
    var runColor = false;
    for (var i = 0; i < size; i++) {
      var c = horizontal ? m.modules[index][i] : m.modules[i][index];
      if (c === runColor) {
        runLength++;
        if (runLength === 5) score += 3;
        else if (runLength > 5) score += 1;
      } else {
        runColor = c;
        runLength = 1;
      }
    }
    return score;
  }

  function matches(m, x, y, pattern, horizontal) {
    for (var i = 0; i < pattern.length; i++) {
      var c = horizontal ? m.modules[y][x + i] : m.modules[y + i][x];
      if (c !== pattern[i]) return false;
    }
    return true;
  }

  // --- Public entry point ---

  /**
   * Encode `text` and return a square array of booleans (true = dark module).
   * The caller decides how to paint it; this function knows nothing about a
   * canvas, so the drawing code in invoice.js can own the quiet zone and the
   * integer module scale without this file having an opinion about pixels.
   */
  function encodeToMatrix(text, ecl) {
    ecl = ecl || 'M';
    if (!ECC_CODEWORDS_PER_BLOCK[ecl]) throw new Error('unknown ECC level ' + ecl);

    var bytes = toUtf8(text);
    var version = chooseVersion(bytes.length, ecl);
    var codewords = interleave(buildCodewords(bytes, version, ecl), version, ecl);

    var m = new Matrix(version * 4 + 17);
    drawFunctionPatterns(m, version, ecl);
    drawCodewords(m, codewords);

    // Try all eight masks, keep the lowest penalty (spec 7.8.3). Deterministic:
    // ties go to the lower mask number, so the same text always yields the same
    // symbol — which matters for a page a buyer may reload and compare.
    var best = -1;
    var bestScore = Infinity;
    var snapshot = [];
    var y;
    for (y = 0; y < m.size; y++) snapshot.push(m.modules[y].slice());

    for (var mask = 0; mask < 8; mask++) {
      for (y = 0; y < m.size; y++) m.modules[y] = snapshot[y].slice();
      applyMask(m, mask);
      drawFormatBits(m, ecl, mask);
      var score = penalty(m);
      if (score < bestScore) {
        bestScore = score;
        best = mask;
      }
    }

    for (y = 0; y < m.size; y++) m.modules[y] = snapshot[y].slice();
    applyMask(m, best);
    drawFormatBits(m, ecl, best);

    return { size: m.size, version: version, mask: best, modules: m.modules };
  }

  return { encodeToMatrix: encodeToMatrix };
})();

// The browser uses the global. The CommonJS export is kept so the file can be
// loaded by a future browser-layer test runner without being edited first — it
// costs two lines and is inert under a `<script>` tag.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = NotchstaveQR;
}
