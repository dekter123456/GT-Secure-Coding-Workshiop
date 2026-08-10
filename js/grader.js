/* ============================================================================
 * js/grader.js — window.Grader
 *
 * Static, pattern-based grading (see.
 *   Grader.stripComments(code)            -> string
 *   Grader.runChecks(code, checks, traps) -> Result
 *
 * แนวคิด (concept):
 *   1. ตัด comment ออกก่อน (line, block, #, XML) โดย "คงเนื้อหาในสตริงไว้"
 *      เพื่อไม่ให้ผู้เรียนผ่านได้ด้วยการ comment บรรทัดที่มีช่องโหว่ทิ้ง
 *      และไม่ให้ comment ที่ไม่เกี่ยวข้องทำให้ตรวจไม่ผ่าน
 *   2. ตรวจโค้ดที่ตัด comment แล้วกับกติกา:
 *        - mustMatch    = "ต้องมี" pattern ที่ปลอดภัย   (kind: 'require')
 *        - mustNotMatch = "ต้องไม่มี" pattern อันตราย   (kind: 'forbid')
 *   3. traps = "การแก้ที่ดูเหมือนถูกแต่จริง ๆ ไม่ปลอดภัย" — ไม่บล็อกการผ่าน
 *      แต่รายงานเป็นคำเตือนแยกต่างหาก
 *
 * Pure + side-effect free + never throws. ทำงานทั้งบนเบราว์เซอร์และ Node.
 * ==========================================================================*/
(function (global) {
  'use strict';

  /**
   * ตัด comment ออกจากโค้ดโดยคงสตริงไว้ครบถ้วน
   *
   * Removes:
   *   - "//" line comments (JS / Java)
   *   - block comments "/*" ... "*\/" (JS / Java / CSS)
   *   - "#" line comments (YAML / properties / shell snippets)
   *   - XML/HTML comments "<!--" ... "-->"
   * Preserves string literals: "…", '…', `…` (with backslash escapes), so a
   * "//" inside "http://example.com" or a "#" inside '#anchor' is untouched.
   *
   * Design choice for "#" (documented on purpose): a "#" OUTSIDE a string is
   * treated as a line comment. In YAML/properties files that is exactly
   * right; in JS/Java source a bare "#" outside a string literal is rare
   * enough (the exercises target ES2017-era samples — no "#private" class
   * fields) that stripping it is an acceptable trade-off, while a "#" inside
   * a string literal is always preserved.
   *
   * Known, accepted limitation: JS regex *literals* are not tracked, so a
   * pathological literal like a character class containing two adjacent
   * slashes would be clipped. Exercise code samples avoid this
   * (see escaping notes).
   *
   * Newlines inside stripped comments are preserved so line numbering stays
   * roughly stable; a single space replaces each block/XML comment so that
   * "a" + blockcomment + "b" cannot fuse into the single token "ab".
   */
  function stripComments(code) {
    const src = String(code == null ? '' : code);
    let out = '';
    let i = 0;
    const n = src.length;
    let inString = null; // holds the opening quote char: "  '  `

    while (i < n) {
      const c = src[i];
      const next = i + 1 < n ? src[i + 1] : '';

      if (inString) {
        out += c;
        if (c === '\\') {
          // escape: copy the escaped char verbatim (covers \" \' \\ etc.)
          if (i + 1 < n) out += src[i + 1];
          i += 2;
          continue;
        }
        if (c === inString) inString = null;
        i++;
        continue;
      }

      // --- not inside a string ---
      if (c === '"' || c === "'" || c === '`') {
        inString = c;
        out += c;
        i++;
        continue;
      }

      // "//" line comment — keep the newline (do not consume it)
      if (c === '/' && next === '/') {
        while (i < n && src[i] !== '\n') i++;
        continue;
      }

      // block comment — replace with one space, keep inner newlines
      if (c === '/' && next === '*') {
        i += 2;
        while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
          if (src[i] === '\n') out += '\n';
          i++;
        }
        i += 2; // past the closing marker (or harmlessly past EOF if unterminated)
        out += ' ';
        continue;
      }

      // "#" line comment (YAML / properties) — see the design note above
      if (c === '#') {
        while (i < n && src[i] !== '\n') i++;
        continue;
      }

      // XML/HTML comment — replace with one space, keep inner newlines
      if (c === '<' && src.substr(i, 4) === '<!--') {
        i += 4;
        while (i < n && src.substr(i, 3) !== '-->') {
          if (src[i] === '\n') out += '\n';
          i++;
        }
        i += 3; // past "-->" (or past EOF if unterminated)
        out += ' ';
        continue;
      }

      out += c;
      i++;
    }
    return out;
  }

  /** Clone a regex so g/y statefulness (lastIndex) can never leak between
   *  runs and the exercise data's own RegExp objects are never mutated. */
  function cloneRegex(re) {
    return new RegExp(re.source, re.flags);
  }

  /** Test `re` against `text` safely.
   *  Returns true/false, or null when `re` is not a usable RegExp. */
  function safeTest(re, text) {
    if (!(re instanceof RegExp)) return null;
    try {
      return cloneRegex(re).test(text);
    } catch (e) {
      return null;
    }
  }

  /**
   * ตรวจโค้ดกับกติกา (checks) และกับดัก (traps)
   * @param {string} code    learner code
   * @param {Array}  checks  [{ id, label, hint, weight, mustMatch|mustNotMatch }]
   * @param {Array}  traps   [{ id, match, message }]
   * @returns Result — see
   */
  function runChecks(code, checks, traps) {
    const src = String(code == null ? '' : code);

    // Fewer than 10 non-whitespace characters → the localisable KEY
    // 'too-short' (app.js translates it; we never return a sentence here).
    if (src.replace(/\s/g, '').length < 10) {
      return {
        passed: false,
        error: 'too-short',
        score: 0,
        maxScore: 0,
        results: [],
        traps: []
      };
    }

    const checkList = Array.isArray(checks) ? checks : [];
    const trapList = Array.isArray(traps) ? traps : [];
    const stripped = stripComments(src);

    let score = 0;
    let maxScore = 0;

    const results = checkList.map(function (chk) {
      const c = chk && typeof chk === 'object' ? chk : {};
      const hasMust = c.mustMatch !== undefined && c.mustMatch !== null;
      const hasNot = c.mustNotMatch !== undefined && c.mustNotMatch !== null;

      // weight: positive integer, default 1 (contract: 1..3)
      let weight = 1;
      if (typeof c.weight === 'number' && isFinite(c.weight) && c.weight >= 1) {
        weight = Math.floor(c.weight);
      }
      maxScore += weight;

      const kind = hasNot && !hasMust ? 'forbid' : 'require';
      let passed = false;

      if (hasMust && !hasNot) {
        passed = safeTest(c.mustMatch, stripped) === true; // malformed regex → failed
      } else if (hasNot && !hasMust) {
        passed = safeTest(c.mustNotMatch, stripped) === false; // must NOT match; malformed → failed
      } else {
        // Malformed check: neither or both patterns present.
        // Reported as failed rather than throwing (the grader never crashes).
        passed = false;
      }

      if (passed) score += weight;

      return {
        id: c.id !== undefined ? c.id : null,
        label: c.label !== undefined ? c.label : null,
        hint: c.hint !== undefined ? c.hint : null,
        kind: kind,
        weight: weight,
        passed: passed
      };
    });

    const matchedTraps = [];
    trapList.forEach(function (trap) {
      if (!trap || typeof trap !== 'object') return;
      if (safeTest(trap.match, stripped) === true) {
        matchedTraps.push({
          id: trap.id !== undefined ? trap.id : null,
          message: trap.message !== undefined ? trap.message : null
        });
      }
    });

    return {
      passed: results.length > 0 && results.every(function (r) { return r.passed; }),
      error: null,
      score: score,
      maxScore: maxScore,
      results: results,
      traps: matchedTraps
    };
  }

  const api = { stripComments: stripComments, runChecks: runChecks };
  global.Grader = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
