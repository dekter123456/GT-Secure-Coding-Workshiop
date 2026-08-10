/* ============================================================================
 * editor.js — window.CodeEditor
 * เอดิเตอร์โค้ดพร้อม live highlight overlay: <textarea> โปร่งใสวางทับ
 * <pre> ที่ถือผลจาก Highlighter.highlight() + gutter เลขบรรทัด
 * สามชั้นต้องใช้ font/padding/line-height เดียวกันเป๊ะ ไม่งั้นภาพเหลื่อม
 * คีย์: Tab/Shift+Tab, Enter รักษา indent, auto-close วงเล็บ/เครื่องหมายคำพูด,
 * Ctrl/Cmd+Enter = ส่งตรวจ, Ctrl/Cmd+/ = toggle comment
 * ==========================================================================*/
(function (global) {
  'use strict';

  const INDENT = ' '; // 2 spaces
  const PAIRS = { '(': ')', '[': ']', '{': '}', '"': '"', "'": "'", '`': '`' };
  const CLOSERS = { ')': '(', ']': '[', '}': '{' };

  function noop() {}

  function isWordChar(c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9') || c === '_' || c === '$';
  }

  function escFallback(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // จัดสไตล์ขั้นต่ำที่ "ห้ามพลาด" จาก JS — ที่เหลือเป็นหน้าที่ styles.css
  function applyMetrics(el) {
    const st = el.style;
    st.margin = '0';
    st.whiteSpace = 'pre';
    st.wordBreak = 'normal';
    st.boxSizing = 'border-box';
    st.tabSize = '2';
    st.MozTabSize = '2';
  }

  function CodeEditor(hostEl, opts) {
    opts = opts || {};
    const doc = hostEl && hostEl.ownerDocument ? hostEl.ownerDocument : (global.document || null);
    if (!hostEl || !doc) throw new Error('CodeEditor: host element with a DOM is required');

    this._doc = doc;
    this._host = hostEl;
    this.onChange = typeof opts.onChange === 'function' ? opts.onChange : noop;
    this.onSubmit = typeof opts.onSubmit === 'function' ? opts.onSubmit : noop;
    this.language = opts.language || 'java';
    this.readOnly = !!opts.readOnly;

    this._renderPending = null;
    this._scrollPending = null;
    this._lastHighlighted = null;
    this._lastNotified = null;
    this._gutterCount = 0;
    this._marks = { numbers: [], className: '' };
    this._markEls = [];

    // ---- DOM -------------------------------------------------------------
    const root = doc.createElement('div');
    root.className = 'editor' + (this.readOnly ? ' is-readonly' : '');
    root.setAttribute('data-lang', this.language);

    const gutter = doc.createElement('div');
    gutter.className = 'editor-gutter';
    gutter.setAttribute('aria-hidden', 'true');

    const stack = doc.createElement('div');
    stack.className = 'editor-stack';
    stack.style.position = 'relative';

    const pre = doc.createElement('pre');
    pre.className = 'editor-highlight';
    pre.setAttribute('aria-hidden', 'true');
    applyMetrics(pre);

    const ta = doc.createElement('textarea');
    ta.className = 'editor-area';
    const attrs = [['aria-label', 'Code editor'], ['spellcheck', 'false'], ['autocomplete', 'off'],
      ['autocorrect', 'off'], ['autocapitalize', 'off'], ['wrap', 'off']];
    for (let i = 0; i < attrs.length; i++) ta.setAttribute(attrs[i][0], attrs[i][1]);
    if (this.readOnly) ta.setAttribute('readonly', 'readonly');
    applyMetrics(ta);

    stack.appendChild(pre);
    stack.appendChild(ta);
    root.appendChild(gutter);
    root.appendChild(stack);
    hostEl.innerHTML = '';
    hostEl.appendChild(root);

    this._root = root;
    this._gutter = gutter;
    this._stack = stack;
    this._pre = pre;
    this._ta = ta;

    // ---- listeners (เก็บ reference ไว้ให้ destroy() ถอดครบ) ---------------
    const self = this;
    this._onInput = function () { self._handleInput(); };
    this._onScroll = function () { self._syncScrollSoon(); };
    this._onKeydown = function (e) { self._handleKey(e); };
    ta.addEventListener('input', this._onInput);
    ta.addEventListener('scroll', this._onScroll);
    ta.addEventListener('keydown', this._onKeydown);

    this._render();
  }

  /* ---- rAF helpers (fallback เป็น setTimeout เมื่อไม่มี เช่นใต้ jsdom) --- */

  CodeEditor.prototype._requestFrame = function (fn) {
    const win = this._doc.defaultView || global;
    if (typeof win.requestAnimationFrame === 'function') {
      return { raf: true, win: win, id: win.requestAnimationFrame(fn) };
    }
    return { raf: false, id: setTimeout(fn, 16) };
  };

  CodeEditor.prototype._cancelFrame = function (h) {
    if (!h) return;
    if (h.raf && typeof h.win.cancelAnimationFrame === 'function') h.win.cancelAnimationFrame(h.id);
    else if (!h.raf) clearTimeout(h.id);
  };

  /* ---- rendering -------------------------------------------------------- */

  CodeEditor.prototype._scheduleRender = function () {
    if (this._renderPending) return; // coalesce: หนึ่งเฟรมวาดครั้งเดียวพอ
    const self = this;
    this._renderPending = this._requestFrame(function () {
      self._renderPending = null;
      self._render();
    });
  };

  CodeEditor.prototype._render = function () {
    const v = this._ta.value;
    if (v !== this._lastHighlighted) { // ค่าไม่เปลี่ยน → ไม่ต้อง highlight ซ้ำ
      this._lastHighlighted = v;
      const H = global.Highlighter;
      const html = (H && typeof H.highlight === 'function')
        ? H.highlight(v, this.language)
        : escFallback(v);
      // ต่อ \n ปิดท้ายเสมอ ให้บรรทัดสุดท้ายมีความสูงเท่า textarea
      this._pre.innerHTML = html + '\n';
    }
    const count = v.split('\n').length;
    if (count !== this._gutterCount) this._renderGutter(count);
  };

  CodeEditor.prototype._renderGutter = function (count) {
    const g = this._gutter;
    const doc = this._doc;
    let cur = this._gutterCount;
    while (cur > count && g.lastChild) { g.removeChild(g.lastChild); cur--; }
    if (cur < count) {
      const frag = doc.createDocumentFragment();
      for (let i = cur + 1; i <= count; i++) {
        const line = doc.createElement('div');
        line.className = 'editor-gutter-line';
        line.textContent = String(i);
        frag.appendChild(line);
      }
      g.appendChild(frag);
    }
    this._gutterCount = count;
    this._applyMarks();
  };

  CodeEditor.prototype._applyMarks = function () {
    for (let i = 0; i < this._markEls.length; i++) {
      const el = this._markEls[i];
      if (el.parentNode) el.parentNode.removeChild(el);
    }
    this._markEls = [];
    const nums = this._marks.numbers;
    for (let i = 0; i < nums.length; i++) {
      const nLine = nums[i];
      if (nLine < 1 || nLine > this._gutterCount) continue;
      const lineEl = this._gutter.children[nLine - 1];
      if (!lineEl) continue;
      const m = this._doc.createElement('span');
      m.className = 'editor-mark' + (this._marks.className ? ' ' + this._marks.className : '');
      lineEl.appendChild(m);
      this._markEls.push(m);
    }
  };

  /* ---- scroll sync ------------------------------------------------------ */

  CodeEditor.prototype._syncScrollSoon = function () {
    if (this._scrollPending) return;
    const self = this;
    this._scrollPending = this._requestFrame(function () {
      self._scrollPending = null;
      self._syncScroll();
    });
  };

  CodeEditor.prototype._syncScroll = function () {
    const ta = this._ta;
    this._pre.scrollTop = ta.scrollTop;
    this._pre.scrollLeft = ta.scrollLeft;
    this._gutter.scrollTop = ta.scrollTop;
  };

  /* ---- edits (พยายามผ่าน execCommand ก่อน เพื่อรักษา undo stack) --------- */

  CodeEditor.prototype._handleInput = function () {
    const v = this._ta.value;
    this._scheduleRender();
    if (v !== this._lastNotified) {
      this._lastNotified = v;
      this.onChange(v);
    }
  };

  CodeEditor.prototype._replaceRange = function (start, end, text, selStart, selEnd) {
    const ta = this._ta;
    const doc = this._doc;
    const before = ta.value;
    const expected = before.slice(0, start) + text + before.slice(end);
    ta.focus();
    ta.setSelectionRange(start, end);
    if (doc && typeof doc.execCommand === 'function') {
      try { doc.execCommand('insertText', false, text); } catch (err) { /* fall through */ }
    }
    if (ta.value !== expected) ta.value = expected; // fallback: splice ตรง ๆ
    if (typeof selStart === 'number') {
      ta.setSelectionRange(selStart, typeof selEnd === 'number' ? selEnd : selStart);
    }
    this._handleInput(); // dedupe ภายใน กัน onChange ยิงซ้ำจาก input event
  };

  /* ---- keyboard --------------------------------------------------------- */

  CodeEditor.prototype._handleKey = function (e) {
    const key = e.key;
    const mod = e.ctrlKey || e.metaKey;

    if (mod && key === 'Enter') {
      e.preventDefault();
      this.onSubmit(this.getValue());
      return;
    }
    if (this.readOnly) return;
    if (mod && (key === '/' || e.code === 'Slash')) {
      e.preventDefault();
      this._toggleComment();
      return;
    }
    if (mod || e.altKey) return; // ปล่อย shortcut อื่นของเบราว์เซอร์
    if (key === 'Tab') {
      e.preventDefault();
      this._handleTab(e.shiftKey);
      return;
    }
    if (key === 'Enter') {
      e.preventDefault();
      this._handleEnter();
      return;
    }
    if (key === 'Backspace') {
      if (this._handlePairBackspace()) e.preventDefault();
      return;
    }
    if (PAIRS.hasOwnProperty(key) || CLOSERS.hasOwnProperty(key)) {
      if (this._handleBracket(key)) e.preventDefault();
    }
  };

  CodeEditor.prototype._handleTab = function (shift) {
    const ta = this._ta;
    const v = ta.value;
    const s = ta.selectionStart;
    const e = ta.selectionEnd;
    const multiline = v.slice(s, e).indexOf('\n') !== -1;

    if (!shift && !multiline) {
      this._replaceRange(s, e, INDENT, s + INDENT.length, s + INDENT.length);
      return;
    }
    // ทำทีละบรรทัดทั้งบล็อกที่ selection คร่อม
    const blockStart = v.lastIndexOf('\n', s - 1) + 1;
    let effEnd = e;
    if (multiline && e > s && v.charAt(e - 1) === '\n') effEnd = e - 1;
    let blockEnd = v.indexOf('\n', effEnd);
    if (blockEnd === -1) blockEnd = v.length;
    const block = v.slice(blockStart, blockEnd);
    const lines = block.split('\n');
    let firstDelta = 0;
    let totalDelta = 0;
    const outLines = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (shift) {
        let cut = 0;
        if (line.charAt(0) === '\t') cut = 1;
        else if (line.slice(0, 2) === INDENT) cut = 2;
        else if (line.charAt(0) === ' ') cut = 1;
        if (i === 0) firstDelta = -cut;
        totalDelta -= cut;
        outLines.push(line.slice(cut));
      } else if (line === '' && lines.length > 1) {
        outLines.push(line); // ไม่ indent บรรทัดว่างในบล็อก
      } else {
        if (i === 0) firstDelta = INDENT.length;
        totalDelta += INDENT.length;
        outLines.push(INDENT + line);
      }
    }
    const newBlock = outLines.join('\n');
    if (newBlock === block) return;
    const newS = Math.max(blockStart, s + firstDelta);
    const newE = Math.max(newS, e + totalDelta);
    this._replaceRange(blockStart, blockEnd, newBlock, newS, newE);
  };

  CodeEditor.prototype._handleEnter = function () {
    const ta = this._ta;
    const v = ta.value;
    const s = ta.selectionStart;
    const e = ta.selectionEnd;
    const lineStart = v.lastIndexOf('\n', s - 1) + 1;
    const indent = (v.slice(lineStart, s).match(/^[ \t]*/) || [''])[0];
    const beforeTrim = v.slice(0, s).replace(/[ \t]+$/, '');
    const prevCh = beforeTrim.charAt(beforeTrim.length - 1);
    const nextCh = v.charAt(e);
    const opensBlock = prevCh === '{' || prevCh === '[' || prevCh === '(';

    if (opensBlock && nextCh === PAIRS[prevCh]) {
      // caret อยู่ระหว่างคู่เปิด-ปิด → ดันตัวปิดลงบรรทัดของมันเอง
      const insert = '\n' + indent + INDENT + '\n' + indent;
      const caret = s + 1 + indent.length + INDENT.length;
      this._replaceRange(s, e, insert, caret, caret);
    } else if (opensBlock) {
      const insert = '\n' + indent + INDENT;
      this._replaceRange(s, e, insert, s + insert.length, s + insert.length);
    } else {
      const insert = '\n' + indent;
      this._replaceRange(s, e, insert, s + insert.length, s + insert.length);
    }
  };

  CodeEditor.prototype._handleBracket = function (key) {
    const ta = this._ta;
    const v = ta.value;
    const s = ta.selectionStart;
    const e = ta.selectionEnd;
    const isQuote = key === '"' || key === "'" || key === '`';

    // 1) skip-over: พิมพ์ตัวปิดทับตัวปิดที่มีอยู่แล้ว → เลื่อน caret เฉย ๆ
    if (s === e && v.charAt(s) === key && (CLOSERS.hasOwnProperty(key) || isQuote)) {
      ta.setSelectionRange(s + 1, s + 1);
      return true;
    }
    if (!PAIRS.hasOwnProperty(key)) return false; // ตัวปิดล้วน → ปล่อยพิมพ์ปกติ

    const closer = PAIRS[key];
    // 2) มี selection → ห่อด้วยคู่เปิด-ปิด
    if (s !== e) {
      this._replaceRange(s, e, key + v.slice(s, e) + closer, s + 1, e + 1);
      return true;
    }
    // 3) auto-close (เครื่องหมายคำพูดไม่ปิดให้เมื่อพิมพ์กลางคำ/หลัง \ )
    const prevCh = s > 0 ? v.charAt(s - 1) : '';
    const nextCh = v.charAt(s);
    if (isQuote && (isWordChar(prevCh) || prevCh === key || prevCh === '\\')) return false;
    if (nextCh === '' || nextCh === '\n' || ' \t)]},;.:'.indexOf(nextCh) !== -1) {
      this._replaceRange(s, s, key + closer, s + 1, s + 1);
      return true;
    }
    return false;
  };

  CodeEditor.prototype._handlePairBackspace = function () {
    const ta = this._ta;
    const v = ta.value;
    const s = ta.selectionStart;
    if (s !== ta.selectionEnd || s === 0) return false;
    const prev = v.charAt(s - 1);
    if (PAIRS.hasOwnProperty(prev) && PAIRS[prev] === v.charAt(s)) {
      this._replaceRange(s - 1, s + 1, '', s - 1, s - 1);
      return true;
    }
    return false;
  };

  CodeEditor.prototype._toggleComment = function () {
    const lang = this.language;
    if (lang === 'json') return; // JSON ไม่มี comment มาตรฐาน
    const xml = lang === 'xml';
    const marker = lang === 'yaml' ? '#' : '//';
    const ta = this._ta;
    const v = ta.value;
    const s = ta.selectionStart;
    const e = ta.selectionEnd;
    const blockStart = v.lastIndexOf('\n', s - 1) + 1;
    let effEnd = e;
    if (e > s && v.charAt(e - 1) === '\n') effEnd = e - 1;
    let blockEnd = v.indexOf('\n', effEnd);
    if (blockEnd === -1) blockEnd = v.length;
    const lines = v.slice(blockStart, blockEnd).split('\n');

    let hasContent = false;
    let allCommented = true;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t === '') continue;
      hasContent = true;
      if (xml) {
        if (!(t.slice(0, 4) === '<!--' && t.slice(-3) === '-->')) allCommented = false;
      } else if (t.slice(0, marker.length) !== marker) {
        allCommented = false;
      }
    }
    if (!hasContent) return;

    const outLines = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim() === '') { outLines.push(line); continue; }
      const ind = (line.match(/^[ \t]*/) || [''])[0];
      const body = line.slice(ind.length);
      if (allCommented) {
        if (xml) outLines.push(ind + body.replace(/^<!--\s?/, '').replace(/\s?-->\s*$/, ''));
        else if (marker === '#') outLines.push(ind + body.replace(/^#\s?/, ''));
        else outLines.push(ind + body.replace(/^\/\/\s?/, ''));
      } else {
        if (xml) outLines.push(ind + '<!-- ' + body + ' -->');
        else outLines.push(ind + marker + ' ' + body);
      }
    }
    const newBlock = outLines.join('\n');
    this._replaceRange(blockStart, blockEnd, newBlock, blockStart, blockStart + newBlock.length);
  };

  /* ---- public API -------------------------------------------------------- */

  CodeEditor.prototype.getValue = function () {
    return this._ta.value;
  };

  CodeEditor.prototype.setValue = function (v) {
    v = v == null ? '' : String(v);
    this._ta.value = v;
    this._lastNotified = v; // setValue เป็นการตั้งค่าโปรแกรม — ไม่ยิง onChange
    this._lastHighlighted = null;
    this._render(); // วาดทันที (ไม่รอเฟรม) ให้สถานะตรงเสมอหลัง setValue
    this._ta.scrollTop = 0;
    this._ta.scrollLeft = 0;
    this._syncScroll();
  };

  CodeEditor.prototype.focus = function () {
    this._ta.focus();
  };

  CodeEditor.prototype.setLanguage = function (l) {
    this.language = l || 'generic';
    this._root.setAttribute('data-lang', this.language);
    this._lastHighlighted = null;
    this._render();
  };

  CodeEditor.prototype.markLines = function (numbers, className) {
    this._marks = {
      numbers: Array.isArray(numbers) ? numbers.slice() : [],
      className: className || ''
    };
    this._applyMarks();
  };

  CodeEditor.prototype.destroy = function () {
    const ta = this._ta;
    if (ta) {
      ta.removeEventListener('input', this._onInput);
      ta.removeEventListener('scroll', this._onScroll);
      ta.removeEventListener('keydown', this._onKeydown);
    }
    this._cancelFrame(this._renderPending);
    this._cancelFrame(this._scrollPending);
    this._renderPending = null;
    this._scrollPending = null;
    if (this._root && this._root.parentNode) this._root.parentNode.removeChild(this._root);
    this._markEls = [];
    this._root = this._gutter = this._stack = this._pre = this._ta = this._host = null;
  };

  global.CodeEditor = CodeEditor;
  if (typeof module !== 'undefined' && module.exports) module.exports = CodeEditor;
})(typeof window !== 'undefined' ? window : globalThis);
