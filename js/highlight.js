/* ============================================================================
 * highlight.js — window.Highlighter
 * ไฮไลต์ซินแท็กซ์แบบสแกนทีละตัวอักษร (single pass, O(n)) เพราะต้องรัน
 * ทุก keystroke ใต้ live editor overlay — ห้ามใช้ regex ที่ backtrack ได้
 * กติกาเหล็ก: ถอด <span> ทั้งหมดออกแล้ว unescape entity ต้องได้โค้ด
 * ต้นฉบับกลับมาแบบ byte-for-byte (ห้ามอักขระหาย/เกินแม้แต่ตัวเดียว)
 * ภาษา: java, js, xml, json, yaml, generic (ไม่รู้จัก → generic)
 * ==========================================================================*/
(function (global) {
  'use strict';

  function makeSet(words) {
    const s = {};
    const list = words.split(' ');
    for (let i = 0; i < list.length; i++) s[list[i]] = true;
    return s;
  }

  // แยกชุด keyword ของ Java กับ JS ออกจากกัน (generic ใช้รวมทั้งสอง)
  const JAVA_WORDS = 'abstract assert boolean break byte case catch char class ' +
    'const continue default do double else enum extends final finally float ' +
    'for goto if implements import instanceof int interface long native new ' +
    'package private protected public record return sealed short static ' +
    'strictfp super switch synchronized this throw throws transient try var ' +
    'void volatile while yield';
  const JS_WORDS = 'async await break case catch class const continue debugger ' +
    'default delete do else export extends finally for from function get if ' +
    'import in instanceof let new of return set static super switch this ' +
    'throw try typeof var void while with yield';

  const JAVA_KEYWORDS = makeSet(JAVA_WORDS);
  const JS_KEYWORDS = makeSet(JS_WORDS);
  const GENERIC_KEYWORDS = makeSet(JAVA_WORDS + ' ' + JS_WORDS);
  const BOOLS = makeSet('true false null undefined');

  const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

  function escText(s) {
    s = s == null ? '' : String(s);
    return s.replace(/[&<>"']/g, function (ch) { return ESC_MAP[ch]; });
  }

  function span(cls, text) {
    return '<span class="' + cls + '">' + escText(text) + '</span>';
  }

  function isDigit(c) { return c >= '0' && c <= '9'; }
  function isWordStart(c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_' || c === '$';
  }
  function isWordChar(c) { return isWordStart(c) || isDigit(c); }
  function peek(code, i, n) { return i + 1 < n ? code[i + 1] : ''; }

  const PUNCT = '{}()[];,.<>=+-*/%&|^!~?:';
  function isPunct(c) { return PUNCT.indexOf(c) !== -1; }

  // อักขระที่ "เริ่ม token" ได้ในภาษาตระกูล C — ใช้ตัดช่วง plain text เป็นก้อน
  function startsClikeToken(c) {
    return c === '"' || c === "'" || c === '`' || c === '/' || c === '@' ||
      isDigit(c) || isWordStart(c) || isPunct(c);
  }

  /* ---------------------------------------------------------------- C-like */

  function scanClike(code, keywords, isJava) {
    let out = '';
    let i = 0;
    const n = code.length;

    while (i < n) {
      const c = code[i];
      const nx = peek(code, i, n);

      // // line comment
      if (c === '/' && nx === '/') {
        let j = i + 2;
        while (j < n && code[j] !== '\n') j++;
        out += span('tok-com', code.slice(i, j));
        i = j;
        continue;
      }
      // /* block comment */ (รวมกรณีไม่ปิดจนจบไฟล์)
      if (c === '/' && nx === '*') {
        let j = code.indexOf('*/', i + 2);
        j = j === -1 ? n : j + 2;
        out += span('tok-com', code.slice(i, j));
        i = j;
        continue;
      }
      // string: " ' ` — รองรับ escape และสตริงไม่ปิด (" และ ' หยุดที่ปลายบรรทัด)
      if (c === '"' || c === "'" || c === '`') {
        let j = i + 1;
        while (j < n) {
          const d = code[j];
          if (d === '\\') { j += 2; continue; }
          if (d === c) { j++; break; }
          if (d === '\n' && c !== '`') break;
          j++;
        }
        if (j > n) j = n;
        out += span('tok-str', code.slice(i, j));
        i = j;
        continue;
      }
      // @Annotation
      if (c === '@' && isWordStart(nx)) {
        let j = i + 1;
        while (j < n && isWordChar(code[j])) j++;
        out += span('tok-ann', code.slice(i, j));
        i = j;
        continue;
      }
      // ตัวเลข (0x1F, 1_000, 1.5e9, 100L)
      if (isDigit(c)) {
        let j = i;
        while (j < n) {
          const d = code[j];
          if (isWordChar(d)) { j++; continue; }
          if (d === '.' && j + 1 < n && isDigit(code[j + 1])) { j++; continue; }
          break;
        }
        out += span('tok-num', code.slice(i, j));
        i = j;
        continue;
      }
      // identifier / keyword / bool / Java type / function call
      if (isWordStart(c)) {
        let j = i;
        while (j < n && isWordChar(code[j])) j++;
        const word = code.slice(i, j);
        let k = j;
        while (k < n && (code[k] === ' ' || code[k] === '\t')) k++;
        if (BOOLS[word] === true) out += span('tok-bool', word);
        else if (keywords[word] === true) out += span('tok-key', word);
        else if (isJava && word[0] >= 'A' && word[0] <= 'Z') out += span('tok-type', word);
        else if (code[k] === '(') out += span('tok-fn', word);
        else out += escText(word);
        i = j;
        continue;
      }
      // เครื่องหมายวรรคตอน — เก็บเป็นก้อน แต่หยุดก่อน / ที่ขึ้นต้น comment
      if (isPunct(c)) {
        let j = i;
        while (j < n && isPunct(code[j])) {
          if (code[j] === '/' && (code[j + 1] === '/' || code[j + 1] === '*')) break;
          j++;
        }
        if (j === i) j = i + 1;
        out += span('tok-punct', code.slice(i, j));
        i = j;
        continue;
      }
      // plain run: ช่องว่าง, ขึ้นบรรทัด, อักษรไทย ฯลฯ
      let j = i + 1;
      while (j < n && !startsClikeToken(code[j])) j++;
      out += escText(code.slice(i, j));
      i = j;
    }
    return out;
  }

  /* -------------------------------------------------------------------- XML */

  function isTagChar(c) {
    return isWordChar(c) || c === '-' || c === '.' || c === ':';
  }

  function scanXml(code) {
    let out = '';
    let i = 0;
    const n = code.length;

    while (i < n) {
      if (code[i] === '<') {
        // <!-- comment --> (รวมกรณีไม่ปิด)
        if (code.slice(i, i + 4) === '<!--') {
          let j = code.indexOf('-->', i + 4);
          j = j === -1 ? n : j + 3;
          out += span('tok-com', code.slice(i, j));
          i = j;
          continue;
        }
        // เปิด tag: < </ <! <?
        let j = i + 1;
        while (j < n && (code[j] === '/' || code[j] === '!' || code[j] === '?')) j++;
        out += span('tok-punct', code.slice(i, j));
        i = j;
        // ชื่อ tag
        let k = i;
        while (k < n && isTagChar(code[k])) k++;
        if (k > i) { out += span('tok-tag', code.slice(i, k)); i = k; }
        // ภายใน tag: attribute / string / = จนถึง >
        while (i < n) {
          const d = code[i];
          if (d === '>') { out += span('tok-punct', '>'); i++; break; }
          if (d === '<') break; // markup พัง — ปล่อยกลับ loop นอก
          if (d === '/' || d === '?' || d === '=') {
            out += span('tok-punct', d);
            i++;
            continue;
          }
          if (d === '"' || d === "'") {
            let q = i + 1;
            while (q < n && code[q] !== d) q++;
            if (q < n) q++;
            out += span('tok-str', code.slice(i, q));
            i = q;
            continue;
          }
          if (isTagChar(d)) {
            let q = i;
            while (q < n && isTagChar(code[q])) q++;
            out += span('tok-attr', code.slice(i, q));
            i = q;
            continue;
          }
          out += escText(d); // ช่องว่าง/อื่น ๆ ภายใน tag
          i++;
        }
        continue;
      }
      // text ระหว่าง tag
      let j = code.indexOf('<', i);
      if (j === -1) j = n;
      out += escText(code.slice(i, j));
      i = j;
    }
    return out;
  }

  /* ------------------------------------------------------------------- JSON */

  function startsJsonToken(c) {
    return c === '"' || c === '-' || isDigit(c) || isWordStart(c) ||
      '{}[]:,'.indexOf(c) !== -1;
  }

  function scanJson(code) {
    let out = '';
    let i = 0;
    const n = code.length;

    while (i < n) {
      const c = code[i];

      if (c === '"') {
        let j = i + 1;
        while (j < n) {
          const d = code[j];
          if (d === '\\') { j += 2; continue; }
          if (d === '"') { j++; break; }
          if (d === '\n') break;
          j++;
        }
        if (j > n) j = n;
        // key ถ้าตามด้วย ':' (ข้าม whitespace)
        let k = j;
        while (k < n && (code[k] === ' ' || code[k] === '\t' || code[k] === '\n' || code[k] === '\r')) k++;
        out += span(code[k] === ':' ? 'tok-attr' : 'tok-str', code.slice(i, j));
        i = j;
        continue;
      }
      if (isDigit(c) || (c === '-' && isDigit(peek(code, i, n)))) {
        let j = i;
        if (code[j] === '-') j++;
        while (j < n && isDigit(code[j])) j++;
        if (code[j] === '.') { j++; while (j < n && isDigit(code[j])) j++; }
        if (code[j] === 'e' || code[j] === 'E') {
          j++;
          if (code[j] === '+' || code[j] === '-') j++;
          while (j < n && isDigit(code[j])) j++;
        }
        out += span('tok-num', code.slice(i, j));
        i = j;
        continue;
      }
      if (isWordStart(c)) {
        let j = i;
        while (j < n && isWordChar(code[j])) j++;
        const word = code.slice(i, j);
        out += BOOLS[word] === true ? span('tok-bool', word) : escText(word);
        i = j;
        continue;
      }
      if ('{}[]:,'.indexOf(c) !== -1) {
        let j = i;
        while (j < n && '{}[]:,'.indexOf(code[j]) !== -1) j++;
        out += span('tok-punct', code.slice(i, j));
        i = j;
        continue;
      }
      let j = i + 1;
      while (j < n && !startsJsonToken(code[j])) j++;
      out += escText(code.slice(i, j));
      i = j;
    }
    return out;
  }

  /* ------------------------------------------------------------------- YAML */

  const YAML_NUM = /^[+-]?\d[\d_]*(\.\d+)?([eE][+-]?\d+)?$/; // anchored, linear

  function scanYaml(code) {
    let out = '';
    let i = 0;
    const n = code.length;
    let atLineHead = true; // ยังไม่เจอ token เนื้อหาบนบรรทัดนี้ (ใช้จับ '- ')

    while (i < n) {
      const c = code[i];

      if (c === '\n') { out += '\n'; i++; atLineHead = true; continue; }

      if (c === ' ' || c === '\t' || c === '\r') {
        let j = i + 1;
        while (j < n && (code[j] === ' ' || code[j] === '\t' || code[j] === '\r')) j++;
        out += escText(code.slice(i, j));
        i = j;
        continue;
      }
      // # comment — เฉพาะต้นบรรทัดหรือหลังช่องว่าง (กติกา YAML)
      if (c === '#' && (i === 0 || code[i - 1] === ' ' || code[i - 1] === '\t' || code[i - 1] === '\n')) {
        let j = i;
        while (j < n && code[j] !== '\n') j++;
        out += span('tok-com', code.slice(i, j));
        i = j;
        atLineHead = false;
        continue;
      }
      // list dash "- " หรือ document separator "---"
      if (c === '-' && atLineHead &&
          (i + 1 >= n || code[i + 1] === ' ' || code[i + 1] === '\n' || code[i + 1] === '-')) {
        let j = i;
        while (j < n && code[j] === '-') j++;
        out += span('tok-punct', code.slice(i, j));
        i = j;
        continue; // ยังถือเป็นหัวบรรทัด — key ตามหลัง "- " ได้
      }
      // flow punctuation
      if (c === '{' || c === '}' || c === '[' || c === ']' || c === ',') {
        out += span('tok-punct', c);
        i++;
        continue;
      }
      // ':' คั่น key/value (เฉพาะเมื่อตามด้วยช่องว่าง/จบบรรทัด/จบไฟล์)
      if (c === ':' && (i + 1 >= n || code[i + 1] === ' ' || code[i + 1] === '\n' ||
          code[i + 1] === '\t' || code[i + 1] === '\r')) {
        out += span('tok-punct', ':');
        i++;
        atLineHead = false;
        continue;
      }
      // quoted string — เป็น key ถ้าตามด้วย ':'
      if (c === '"' || c === "'") {
        let j = i + 1;
        while (j < n) {
          const d = code[j];
          if (c === '"' && d === '\\') { j += 2; continue; }
          if (d === c) { j++; break; }
          if (d === '\n') break;
          j++;
        }
        if (j > n) j = n;
        let k = j;
        while (k < n && (code[k] === ' ' || code[k] === '\t')) k++;
        out += span(code[k] === ':' ? 'tok-attr' : 'tok-str', code.slice(i, j));
        i = j;
        atLineHead = false;
        continue;
      }
      // scalar — วิ่งจนถึงจบบรรทัด / ' #' / ':' ที่ตามด้วยช่องว่าง
      let j = i;
      let stoppedAtColon = false;
      while (j < n) {
        const d = code[j];
        if (d === '\n') break;
        if (d === '#' && j > 0 && (code[j - 1] === ' ' || code[j - 1] === '\t')) break;
        if (d === ':' && (j + 1 >= n || code[j + 1] === ' ' || code[j + 1] === '\n' ||
            code[j + 1] === '\t' || code[j + 1] === '\r')) {
          stoppedAtColon = true;
          break;
        }
        j++;
      }
      if (j === i) j = i + 1; // กันหลุด — ต้องกินอย่างน้อย 1 ตัวเสมอ
      const word = code.slice(i, j);
      const trimmed = word.trim();
      if (stoppedAtColon) out += span('tok-attr', word);
      else if (BOOLS[trimmed] === true) out += span('tok-bool', word);
      else if (YAML_NUM.test(trimmed)) out += span('tok-num', word);
      else out += escText(word);
      i = j;
      atLineHead = false;
    }
    return out;
  }

  /* ------------------------------------------------------------------ entry */

  function highlight(code, lang) {
    code = code == null ? '' : String(code);
    try {
      switch (lang) {
        case 'java': return scanClike(code, JAVA_KEYWORDS, true);
        case 'js': return scanClike(code, JS_KEYWORDS, false);
        case 'xml': return scanXml(code);
        case 'json': return scanJson(code);
        case 'yaml': return scanYaml(code);
        default: return scanClike(code, GENERIC_KEYWORDS, false);
      }
    } catch (e) {
      return escText(code); // ห้าม throw เด็ดขาด — ถอยไป plain text
    }
  }

  const api = { highlight: highlight, escText: escText };
  global.Highlighter = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
