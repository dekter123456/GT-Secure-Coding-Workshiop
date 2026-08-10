/* ============================================================================
 * js/app.js — window.App (v2 contract)
 *
 * Routing, rendering, wiring and persistence for the Secure Coding Workshop.
 * Owns its own markup and emits ONLY the class names from
 *
 * Hard rules honoured here:
 *   - Zero dependencies, no ES modules, no build, works from file://.
 *   - No optional chaining, no nullish coalescing, no class fields.
 *   - Must NOT throw when merely require()d under Node without a DOM.
 *   - Every interpolated value is HTML-escaped through esc(); learner code,
 *     exercise content and the certificate name are all untrusted.
 * ==========================================================================*/
(function (global) {
  'use strict';

  var LS = 'scw_progress_v2';
  var LS_V1 = 'scw_progress_v1';
  var SEV = ['Critical', 'High', 'Medium', 'Low'];

  var state = {
    v: 2,
    lang: 'th',
    theme: 'dark',
    codeLang: 'java',
    route: { view: 'intro', id: null },
    working: {},
    completed: {},
    hints: {},
    revealed: {},
    quiz: {},
    learner: { name: '' },
    // ค่าที่ผู้เรียนเลือกไว้ทั้งเซสชัน ไม่ผูกกับโจทย์ข้อใดข้อหนึ่ง
    // detailsOpen: กาง "อ่านรายละเอียด" ค้างไว้ทุกข้อ จะได้ไม่ต้องกดใหม่ 24 รอบ
    ui: { detailsOpen: false, tab: 'learn' }
  };

  var flat = [];
  var editor = null;
  // ตัวคุม animation ของไดอะแกรม — ต้อง destroy ทุกครั้งที่เปลี่ยนหน้า
  // ไม่งั้น requestAnimationFrame loop จะค้างสะสมทีละโจทย์
  var diagramCtl = null;
  var wired = false;
  var overlayEl = null;
  var toastStack = null;
  var searchQuery = '';
  var gPending = 0;

  /* ---------------------------------------------------------------- utils */

  function hasDoc() { return typeof document !== 'undefined' && !!document; }

  function L(x) {
    var i = global.I18N;
    if (i && typeof i.L === 'function') return i.L(x);
    if (x === null || x === undefined) return '';
    if (typeof x === 'string') return x;
    if (typeof x === 'object') { if (x.th) return x.th; if (x.en) return x.en; }
    return '';
  }

  function t(key, fb, params) {
    var i = global.I18N;
    if (i && typeof i.t === 'function') return i.t(key, fb, params);
    var s = (fb === null || fb === undefined) ? String(key) : String(fb);
    if (params) {
      s = s.replace(/\{(\w+)\}/g, function (whole, p) {
        return Object.prototype.hasOwnProperty.call(params, p) ? String(params[p]) : whole;
      });
    }
    return s;
  }

  function esc(s) {
    s = (s === null || s === undefined) ? '' : String(s);
    return s.replace(/[&<>"']/g, function (c) {
      if (c === '&') return '&amp;';
      if (c === '<') return '&lt;';
      if (c === '>') return '&gt;';
      if (c === '"') return '&quot;';
      return '&#39;';
    });
  }

  function safeUrl(u) {
    u = String(u === null || u === undefined ? '' : u);
    if (/^https?:\/\//i.test(u)) return u;
    return '#';
  }

  function elem(tag, cls, txt) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt !== null && txt !== undefined) e.textContent = String(txt);
    return e;
  }
  function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  }

  function sevClass(sev) {
    switch (String(sev || '').toLowerCase()) {
      case 'critical': return 'sev-critical';
      case 'high': return 'sev-high';
      case 'medium': return 'sev-medium';
      default: return 'sev-low';
    }
  }
  function sevLabel(sev) { return t('sev.' + sev, sev); }

  function currentLang() {
    var i = global.I18N;
    return (i && i.lang === 'en') ? 'en' : 'th';
  }

  function prefersReducedMotion() {
    try {
      return typeof global.matchMedia === 'function' &&
        global.matchMedia('(prefers-reduced-motion: reduce)').matches;
    } catch (e) { return false; }
  }

  function now() { return (global.Date && Date.now) ? Date.now() : (new Date()).getTime(); }

  function shortcutMod() {
    try {
      var p = (global.navigator && global.navigator.platform) || '';
      if (/Mac|iPhone|iPad/i.test(p)) return '⌘';
    } catch (e) {}
    return 'Ctrl';
  }

  function shieldSvg() {
    return '<svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true">' +
      '<path fill="currentColor" d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5z"/></svg>';
  }

  /* -------------------------------------------------------- persistence */

  function readLS(key) {
    try {
      if (typeof localStorage === 'undefined' || !localStorage) return null;
      return localStorage.getItem(key);
    } catch (e) { return null; }
  }
  function writeLS(key, val) {
    try {
      if (typeof localStorage === 'undefined' || !localStorage) return;
      localStorage.setItem(key, val);
    } catch (e) {}
  }
  function save() {
    try { writeLS(LS, JSON.stringify(state)); } catch (e) {}
  }

  function mergeState(d) {
    if (!d || typeof d !== 'object') return;
    if (d.lang === 'th' || d.lang === 'en') state.lang = d.lang;
    if (d.theme === 'dark' || d.theme === 'light') state.theme = d.theme;
    if (d.codeLang === 'java' || d.codeLang === 'node') state.codeLang = d.codeLang;
    if (d.route && typeof d.route === 'object' && typeof d.route.view === 'string') {
      state.route = { view: d.route.view, id: d.route.id !== null && d.route.id !== undefined ? String(d.route.id) : null };
    }
    if (d.working && typeof d.working === 'object') state.working = d.working;
    if (d.completed && typeof d.completed === 'object') state.completed = d.completed;
    if (d.hints && typeof d.hints === 'object') state.hints = d.hints;
    if (d.revealed && typeof d.revealed === 'object') state.revealed = d.revealed;
    if (d.quiz && typeof d.quiz === 'object') state.quiz = d.quiz;
    if (d.learner && typeof d.learner === 'object' && typeof d.learner.name === 'string') {
      state.learner = { name: d.learner.name };
    }
    if (d.ui && typeof d.ui === 'object') {
      state.ui = { detailsOpen: d.ui.detailsOpen === true, tab: d.ui.tab || 'learn' };
    }
  }

  /* Migrate the old v1 shape: { lang:'java'|'node', working, completed:{id:true}, hints } */
  function migrateV1(v1) {
    if (!v1 || typeof v1 !== 'object') return;
    if (v1.lang === 'java' || v1.lang === 'node') state.codeLang = v1.lang;
    if (v1.working && typeof v1.working === 'object') state.working = v1.working;
    if (v1.hints && typeof v1.hints === 'object') state.hints = v1.hints;
    if (v1.completed && typeof v1.completed === 'object') {
      var stamp = now();
      for (var id in v1.completed) {
        if (!Object.prototype.hasOwnProperty.call(v1.completed, id)) continue;
        if (!v1.completed[id]) continue;
        var h = (v1.hints && typeof v1.hints[id] === 'number') ? v1.hints[id] : 0;
        state.completed[id] = { at: stamp, hintsUsed: h, revealed: false, score: 0, maxScore: 0 };
      }
    }
    if (typeof v1.currentId === 'string') {
      if (v1.currentId === '__checklist__') state.route = { view: 'checklist', id: null };
      else state.route = { view: 'exercise', id: v1.currentId };
    }
  }

  /* Returns true if a v2 payload was loaded. */
  function loadState() {
    var rawV2 = readLS(LS);
    if (rawV2) {
      try { mergeState(JSON.parse(rawV2)); return true; } catch (e) {}
    }
    var rawV1 = readLS(LS_V1);
    if (rawV1) {
      try { migrateV1(JSON.parse(rawV1)); save(); } catch (e) {}
    }
    return false;
  }

  /* -------------------------------------------------------- registry */

  function buildFlat() {
    var scw = global.SCW;
    if (scw && typeof scw.finalize === 'function') { try { scw.finalize(); } catch (e) {} }
    if (scw && typeof scw.flatten === 'function') {
      try { flat = scw.flatten() || []; } catch (e) { flat = []; }
      return;
    }
    flat = [];
    var ws = global.WORKSHOPS || [];
    var idx = 0;
    for (var i = 0; i < ws.length; i++) {
      var exs = (ws[i] && ws[i].exercises) || [];
      for (var j = 0; j < exs.length; j++) { flat.push({ workshop: ws[i], ex: exs[j], index: idx++ }); }
    }
  }
  function findFlat(id) {
    for (var i = 0; i < flat.length; i++) { if (flat[i].ex && flat[i].ex.id === id) return flat[i]; }
    return null;
  }
  function indexOfId(id) {
    for (var i = 0; i < flat.length; i++) { if (flat[i].ex && flat[i].ex.id === id) return i; }
    return -1;
  }

  /* -------------------------------------------------------- stats */

  function computeStats() {
    var g = global.Gamify;
    if (g && typeof g.computeStats === 'function') {
      try { return g.computeStats(state, flat); } catch (e) {}
    }
    return fallbackStats();
  }
  function fallbackStats() {
    var solved = 0, total = flat.length;
    for (var i = 0; i < flat.length; i++) { if (state.completed[flat[i].ex.id]) solved++; }
    return {
      solved: solved, total: total, percent: total ? Math.round(solved / total * 100) : 0,
      xp: 0, maxXp: 0, rank: { name: { th: '', en: '' }, icon: '', min: 0 }, nextRank: null, xpToNext: 0,
      quizCorrect: 0, quizTotal: 0, hintsUsed: 0, solutionsRevealed: 0,
      perWorkshop: [], perSeverity: {}, badges: []
    };
  }

  /* -------------------------------------------------------- routing */

  function go(view, id) {
    state.route = { view: view, id: (id !== null && id !== undefined) ? String(id) : null };
    if (view === 'exercise' && !state.route.id && flat.length) state.route.id = flat[0].ex.id;
    save();
    closeOverlay();
    renderAll();
    var main = document.getElementById('main');
    if (main) { try { main.scrollTop = 0; } catch (e) {} }
    if (document.body) document.body.classList.remove('sidebar-open');
  }

  function navigate(arg) {
    if (!arg) return;
    if (typeof arg === 'object') { if (arg.view) go(arg.view, arg.id); return; }
    var name = String(arg);
    if (name === 'intro' || name === 'dashboard' || name === 'checklist') { go(name); return; }
    if (findFlat(name)) { go('exercise', name); return; }
    go('dashboard');
  }

  function renderAll() {
    if (document.body) document.body.setAttribute('data-view', state.route.view);
    renderSidebar();
    renderMain();
  }

  function renderMain() {
    var main = document.getElementById('main');
    if (!main) return;
    if (editor && typeof editor.destroy === 'function') { try { editor.destroy(); } catch (e) {} }
    editor = null;
    clear(main);
    var v = state.route.view;
    if (v === 'intro') { renderIntro(main); return; }
    if (v === 'checklist') { renderChecklist(main); return; }
    if (v === 'exercise') { renderExercise(main); return; }
    renderDashboard(main);
  }

  /* -------------------------------------------------------- sidebar */

  function renderSidebar() {
    var sb = document.getElementById('sidebar');
    if (!sb) return;
    clear(sb);

    var brand = elem('div', 'brand');
    var mark = elem('span', 'brand-mark');
    mark.setAttribute('aria-hidden', 'true');
    mark.innerHTML = shieldSvg();
    var bt = elem('div');
    bt.appendChild(elem('div', 'brand-title', t('app.title', 'Secure Coding Workshop')));
    bt.appendChild(elem('div', 'brand-sub', t('app.subtitle', 'ฝึกแก้ช่องโหว่จริง · Java & Node.js')));
    brand.appendChild(mark);
    brand.appendChild(bt);
    brand.style.cursor = 'pointer';
    brand.setAttribute('role', 'button');
    brand.setAttribute('tabindex', '0');
    brand.setAttribute('aria-label', t('nav.dashboard', 'ภาพรวม'));
    brand.addEventListener('click', function () { go('dashboard'); });
    brand.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go('dashboard'); }
    });
    sb.appendChild(brand);

    var views = elem('div', 'nav-views');
    views.style.display = 'grid';
    views.style.gap = '6px';
    views.style.margin = '0 4px 16px';
    views.appendChild(viewBtn('intro', t('nav.intro', 'เริ่มต้นที่นี่'), '◆'));
    views.appendChild(viewBtn('dashboard', t('nav.dashboard', 'ภาพรวม'), '▤'));
    sb.appendChild(views);

    var navHost = elem('nav', 'nav');

    var box = elem('div', 'searchbox');
    var ic = elem('span', 'searchbox-icon', '⌕');
    ic.setAttribute('aria-hidden', 'true');
    var input = document.createElement('input');
    input.type = 'search';
    input.setAttribute('aria-label', t('nav.searchPlaceholder', 'ค้นหาโจทย์ / CWE / OWASP'));
    input.placeholder = t('nav.searchPlaceholder', 'ค้นหาโจทย์ / CWE / OWASP');
    input.value = searchQuery;
    var kb = elem('span', 'kbd', shortcutMod() + 'K');
    kb.setAttribute('aria-hidden', 'true');
    input.addEventListener('input', function () { searchQuery = input.value; renderNav(navHost); });
    box.appendChild(ic);
    box.appendChild(input);
    box.appendChild(kb);
    sb.appendChild(box);

    sb.appendChild(navHost);
    renderNav(navHost);

    // Checklist เป็นของอ้างอิงท้ายคาบ ไม่ใช่ทางเข้าหลัก จึงวางไว้ล่างสุดใต้รายการโจทย์
    var tail = elem('div', 'nav-views nav-views-tail');
    tail.appendChild(viewBtn('checklist', t('nav.checklist', 'Secure Coding Checklist'), '☑'));
    sb.appendChild(tail);

    var foot = elem('div', 'sidebar-foot');
    var prog = elem('div', 'foot-progress');
    var st = computeStats();
    prog.innerHTML = esc(t('dash.solved', 'แก้แล้ว')) + ' <b>' + st.solved + '/' + st.total + '</b>';
    var reset = elem('button', 'link-btn', t('nav.reset', 'ล้างความคืบหน้าทั้งหมด'));
    reset.type = 'button';
    reset.addEventListener('click', onReset);
    foot.appendChild(prog);
    foot.appendChild(reset);
    sb.appendChild(foot);
  }

  function viewBtn(view, label, ico) {
    var b = elem('button', 'nav-view btn btn-ghost btn-small');
    b.type = 'button';
    b.style.justifyContent = 'flex-start';
    b.setAttribute('data-view', view);
    b.textContent = (ico ? ico + ' ' : '') + label;
    if (state.route.view === view) {
      b.classList.add('is-active');
      b.style.borderColor = 'var(--accent)';
      b.style.color = 'var(--text)';
    }
    b.addEventListener('click', function () { go(view); });
    return b;
  }

  function matchesQuery(entry) {
    if (!searchQuery) return true;
    var qq = searchQuery.toLowerCase();
    var ex = entry.ex;
    var hay = [L(ex.title), L(ex.category), ex.cwe || '', ex.owasp || '',
      ex.severity || '', sevLabel(ex.severity)].join(' ').toLowerCase();
    return hay.indexOf(qq) !== -1;
  }

  function renderNav(host) {
    clear(host);
    var groups = {}, order = [];
    for (var i = 0; i < flat.length; i++) {
      if (!matchesQuery(flat[i])) continue;
      var w = flat[i].workshop;
      var wid = (w && w.id) || 'w';
      if (!groups[wid]) { groups[wid] = { w: w, items: [] }; order.push(wid); }
      groups[wid].items.push(flat[i]);
    }
    if (order.length === 0) {
      host.appendChild(elem('div', 'empty', t('nav.noResults', 'ไม่พบโจทย์ที่ค้นหา')));
      return;
    }
    for (var k = 0; k < order.length; k++) {
      var grp = groups[order[k]];
      var g = elem('div', 'nav-group');
      g.appendChild(elem('div', 'nav-group-title', L(grp.w && grp.w.title)));
      for (var j = 0; j < grp.items.length; j++) g.appendChild(navItem(grp.items[j]));
      host.appendChild(g);
    }
  }

  function navItem(entry) {
    var ex = entry.ex;
    var active = (state.route.view === 'exercise' && state.route.id === ex.id) ? ' active' : '';
    var b = elem('button', 'nav-item' + active);
    b.type = 'button';
    b.setAttribute('data-id', ex.id);
    var dot = elem('span', 'dot ' + sevClass(ex.severity));
    dot.setAttribute('aria-hidden', 'true');
    var label = elem('span', 'nav-label', L(ex.title));
    var meta = elem('span', 'nav-meta');
    if (typeof ex.estMinutes === 'number') meta.textContent = t('nav.minutes', '{n} นาที', { n: ex.estMinutes });
    var done = !!state.completed[ex.id];
    var chk = elem('span', 'check' + (done ? ' on' : ''), done ? '✓' : '');
    b.appendChild(dot);
    b.appendChild(label);
    b.appendChild(meta);
    b.appendChild(chk);
    if (done) b.setAttribute('aria-label', L(ex.title) + ' — ' + t('dash.solved', 'แก้แล้ว'));
    b.addEventListener('click', function () { go('exercise', ex.id); });
    return b;
  }

  function onReset() {
    var okc = true;
    try {
      if (typeof global.confirm === 'function') {
        okc = global.confirm(t('nav.resetConfirm', 'ล้างความคืบหน้าและโค้ดที่แก้ไว้ทั้งหมด?'));
      }
    } catch (e) {}
    if (!okc) return;
    state.working = {}; state.completed = {}; state.hints = {};
    state.revealed = {}; state.quiz = {};
    save();
    renderAll();
  }

  /* -------------------------------------------------------- theme / lang */

  function applyTheme() {
    try {
      if (document.documentElement) document.documentElement.setAttribute('data-theme', state.theme);
    } catch (e) {}
  }
  function toggleTheme() {
    state.theme = (state.theme === 'dark') ? 'light' : 'dark';
    applyTheme();
    save();
  }
  function applyLangUI() {
    var lb = document.getElementById('btn-lang');
    if (lb) lb.textContent = (currentLang() === 'th') ? 'EN' : 'ไทย';
    var st = document.getElementById('app-subtitle');
    if (st) st.textContent = t('app.subtitle', 'ฝึกแก้ช่องโหว่จริง · Java & Node.js');
  }
  function toggleLang() {
    var i = global.I18N;
    var nextL = (currentLang() === 'th') ? 'en' : 'th';
    if (i && typeof i.setLang === 'function') i.setLang(nextL);
    else onLangChanged(nextL);
  }
  function onLangChanged(lang) {
    state.lang = (lang === 'en') ? 'en' : 'th';
    save();
    applyLangUI();
    renderAll();
  }

  /* -------------------------------------------------------- keyboard */

  function isEditorTarget(el) {
    return !!(el && el.classList && el.classList.contains('editor-area'));
  }
  function isFieldTarget(el) {
    if (!el) return false;
    var tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable === true;
  }
  function pagerMove(dir) {
    if (state.route.view !== 'exercise') return;
    var idx = state.route.id ? indexOfId(state.route.id) : -1;
    if (idx < 0) return;
    var ni = idx + dir;
    if (ni < 0 || ni >= flat.length) return;
    go('exercise', flat[ni].ex.id);
  }
  function onKeydown(e) {
    var key = e.key;
    var mod = e.ctrlKey || e.metaKey;
    var target = e.target;

    if (key === 'Escape') {
      if (overlayEl) { closeOverlay(); e.preventDefault(); }
      else if (document.body && document.body.classList.contains('sidebar-open')) {
        document.body.classList.remove('sidebar-open');
      }
      return;
    }
    if (mod && key === 'Enter') {
      if (!isEditorTarget(target) && state.route.view === 'exercise') {
        var f = state.route.id ? findFlat(state.route.id) : null;
        if (f) { triggerCheckShortcut(f.ex); e.preventDefault(); }
      }
      return;
    }
    if (mod && (key === 'k' || key === 'K')) {
      if (isEditorTarget(target)) return; // don't hijack keys while typing in the editor
      var input = $('.searchbox input');
      if (input) { input.focus(); try { input.select(); } catch (e2) {} e.preventDefault(); }
      return;
    }
    if (mod || e.altKey) return;
    if (isEditorTarget(target) || isFieldTarget(target)) return;

    if (key === ']') { pagerMove(1); e.preventDefault(); return; }
    if (key === '[') { pagerMove(-1); e.preventDefault(); return; }
    if (key === '?' || (e.shiftKey && key === '/')) { openShortcuts(); e.preventDefault(); return; }
    if (key === 'g' || key === 'G') { gPending = now(); return; }
    if ((key === 'd' || key === 'D') && (now() - gPending) < 800) {
      gPending = 0; go('dashboard'); e.preventDefault(); return;
    }
  }

  function wireGlobalOnce() {
    if (wired) return;
    wired = true;
    var help = document.getElementById('btn-help');
    if (help) help.addEventListener('click', function () { if (overlayEl) closeOverlay(); else openShortcuts(); });
    var th = document.getElementById('btn-theme');
    if (th) th.addEventListener('click', toggleTheme);
    var lg = document.getElementById('btn-lang');
    if (lg) lg.addEventListener('click', toggleLang);
    var menu = document.getElementById('btn-menu');
    if (menu) menu.addEventListener('click', function () {
      if (document.body) document.body.classList.toggle('sidebar-open');
    });
    var scrim = document.getElementById('sidebar-scrim');
    if (scrim) scrim.addEventListener('click', function () {
      if (document.body) document.body.classList.remove('sidebar-open');
    });
    var i = global.I18N;
    if (i && typeof i.onChange === 'function') i.onChange(onLangChanged);
    if (typeof document.addEventListener === 'function') document.addEventListener('keydown', onKeydown, true);
  }

  /* -------------------------------------------------------- overlay */

  function openShortcuts() {
    closeOverlay();
    if (!document.body) return;
    var ov = elem('div', 'overlay');
    ov.addEventListener('click', function (e) { if (e.target === ov) closeOverlay(); });
    var card = elem('div', 'overlay-card');
    card.setAttribute('role', 'dialog');
    card.setAttribute('aria-modal', 'true');
    card.appendChild(elem('div', 'overlay-title', t('keys.title', 'คีย์ลัด')));
    var rows = [
      [t('keys.check', 'ตรวจคำตอบ'), [shortcutMod(), 'Enter']],
      [t('keys.search', 'ค้นหา'), [shortcutMod(), 'K']],
      [t('keys.nav', 'โจทย์ก่อนหน้า / ถัดไป'), ['[', ']']],
      [t('keys.dash', 'ไปหน้าภาพรวม'), ['G', 'D']],
      [t('keys.help', 'เปิดคีย์ลัด'), ['?']],
      [t('keys.esc', 'ปิดหน้าต่างซ้อน'), ['Esc']]
    ];
    for (var i = 0; i < rows.length; i++) {
      var row = elem('div', 'key-row');
      row.appendChild(elem('span', null, rows[i][0]));
      var combo = elem('span', 'key-combo');
      var keys = rows[i][1];
      for (var k = 0; k < keys.length; k++) combo.appendChild(elem('span', 'kbd', keys[k]));
      row.appendChild(combo);
      card.appendChild(row);
    }
    var act = elem('div', 'overlay-actions');
    var close = elem('button', 'btn btn-ghost btn-small', t('btn.close', 'ปิด'));
    close.type = 'button';
    close.addEventListener('click', closeOverlay);
    act.appendChild(close);
    card.appendChild(act);
    ov.appendChild(card);
    document.body.appendChild(ov);
    overlayEl = ov;
  }
  function closeOverlay() {
    if (overlayEl && overlayEl.parentNode) overlayEl.parentNode.removeChild(overlayEl);
    overlayEl = null;
  }

  /* -------------------------------------------------------- toasts / copy */

  function ensureToastStack() {
    if (toastStack && toastStack.parentNode) return;
    if (!document.body) return;
    toastStack = document.getElementById('scw-toast-stack');
    if (!toastStack) {
      toastStack = elem('div', 'toast-stack');
      toastStack.id = 'scw-toast-stack';
      toastStack.setAttribute('aria-live', 'polite');
      document.body.appendChild(toastStack);
    }
  }
  function toast(msg, celebrateFlag) {
    if (celebrateFlag && prefersReducedMotion()) return;
    ensureToastStack();
    if (!toastStack) return;
    var el = elem('div', 'toast' + (celebrateFlag ? ' celebrate' : ''), msg);
    el.setAttribute('role', 'status');
    toastStack.appendChild(el);
    setTimeout(function () {
      el.classList.add('out');
      setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 400);
    }, 2600);
  }
  function copyText(text) {
    text = String(text === null || text === undefined ? '' : text);
    var done = function () { toast(t('toast.copied', 'คัดลอกแล้ว'), false); };
    try {
      if (global.navigator && global.navigator.clipboard &&
        typeof global.navigator.clipboard.writeText === 'function') {
        global.navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text, done); });
        return;
      }
    } catch (e) {}
    fallbackCopy(text, done);
  }
  function fallbackCopy(text, done) {
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'absolute';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      try { if (document.execCommand) document.execCommand('copy'); } catch (e) {}
      document.body.removeChild(ta);
      if (done) done();
    } catch (e) {}
  }

  /* -------------------------------------------------------- dashboard */

  function renderDashboard(main) {
    var s = computeStats();
    var pct = s.percent || 0;
    var html = '';
    html += '<div class="dash">';

    html += '<div class="dash-hero"><div class="dash-hero-main">';
    html += '<h1>' + esc(t('dash.welcome', 'ยินดีต้อนรับสู่เวิร์กช็อป Secure Coding')) + '</h1>';
    html += '<p class="dash-lead">' + esc(t('dash.lead', 'เรียนรู้จากช่องโหว่จริง ลงมือแก้โค้ดเอง แล้วให้ระบบตรวจให้ทันที')) + '</p>';
    html += '<div class="dash-cta">' + ctaHTML(s) + '</div>';
    html += '</div>';
    html += ringHTML(pct);
    html += '</div>';

    html += '<div class="stat-grid">';
    html += statCard(String(s.solved) + '/' + String(s.total), '', t('dash.solved', 'แก้แล้ว'),
      t('progress.label', 'ความคืบหน้า') + ' ' + pct + '%');
    html += '</div>';

    html += dashSection(t('dash.byWorkshop', 'ความคืบหน้าตาม Workshop'), wkBarsHTML(s));
    html += dashSection(t('dash.bySeverity', 'ตามระดับความรุนแรง'), sevGridHTML(s));

    html += '</div>';
    main.innerHTML = html;

    var cta = document.getElementById('dash-cta-btn');
    if (cta) cta.addEventListener('click', function () {
      var id = cta.getAttribute('data-id');
      if (id) go('exercise', id); else go('dashboard');
    });
    animateRing(main);
  }

  function rankLineHTML(s) {
    var rank = s.rank || {};
    var line = '<div class="dash-rankline">';
    line += '<span>' + esc((rank.icon ? rank.icon + ' ' : '') + L(rank.name)) + '</span>';
    if (s.nextRank) {
      line += '<span aria-hidden="true">·</span><span>' +
        esc(t('progress.toNext', 'อีก {n} XP ถึงระดับ {a}', { n: s.xpToNext, a: L(s.nextRank.name) })) + '</span>';
    } else {
      line += '<span aria-hidden="true">·</span><span>' + esc(t('progress.maxRank', 'ถึงระดับสูงสุดแล้ว')) + '</span>';
    }
    line += '</div>';
    return line;
  }

  function ctaHTML(s) {
    if (flat.length === 0) return '';
    var contId = null;
    if (state.route.id && findFlat(state.route.id)) contId = state.route.id;
    if (!contId) {
      for (var i = 0; i < flat.length; i++) {
        if (!state.completed[flat[i].ex.id]) { contId = flat[i].ex.id; break; }
      }
    }
    if (!contId) contId = flat[0].ex.id;
    var label = (s.solved > 0) ? t('dash.continue', 'ทำต่อจากที่ค้างไว้') : t('dash.start', 'เริ่มโจทย์แรก');
    return '<button id="dash-cta-btn" class="btn btn-primary" type="button" data-id="' + esc(contId) + '">' +
      esc(label) + '</button>';
  }

  function ringHTML(pct) {
    var r = 66;
    var c = 2 * Math.PI * r;
    var off = c * (1 - Math.max(0, Math.min(100, pct)) / 100);
    var h = '<div class="ring">';
    h += '<svg class="ring-svg" viewBox="0 0 152 152" role="img" aria-label="' +
      esc(t('progress.label', 'ความคืบหน้า') + ' ' + pct + '%') + '">';
    h += '<circle class="ring-track" cx="76" cy="76" r="' + r + '"></circle>';
    h += '<circle class="ring-fill" cx="76" cy="76" r="' + r + '" stroke="var(--accent)" ' +
      'stroke-dasharray="' + c.toFixed(1) + '" stroke-dashoffset="' + c.toFixed(1) +
      '" data-off="' + off.toFixed(1) + '"></circle>';
    h += '</svg>';
    h += '<div class="ring-label"><b>' + pct + '%</b><span>' + esc(t('dash.solved', 'แก้แล้ว')) + '</span></div>';
    h += '</div>';
    return h;
  }
  function animateRing(root) {
    var fill = root.querySelector('.ring-fill');
    if (!fill) return;
    var off = fill.getAttribute('data-off');
    if (prefersReducedMotion()) { fill.setAttribute('stroke-dashoffset', off); return; }
    var set = function () { fill.setAttribute('stroke-dashoffset', off); };
    if (typeof global.requestAnimationFrame === 'function') {
      global.requestAnimationFrame(function () { global.requestAnimationFrame(set); });
    } else setTimeout(set, 30);
  }

  function statCard(num, unit, label, sub) {
    var h = '<div class="stat-card"><div class="stat-top"><span class="stat-num">' + esc(num) + '</span>';
    if (unit) h += '<span class="stat-unit">' + esc(unit) + '</span>';
    h += '</div><div class="stat-label">' + esc(label) + '</div>';
    if (sub) h += '<div class="stat-sub">' + esc(sub) + '</div>';
    h += '</div>';
    return h;
  }
  function xpStatCard(s) {
    var rank = s.rank || {};
    var h = '<div class="stat-card"><div class="stat-top"><span class="stat-num">' + esc(String(s.xp)) +
      '</span><span class="stat-unit">XP</span></div>';
    h += '<div class="stat-label">' + esc((rank.icon ? rank.icon + ' ' : '') + L(rank.name)) + '</div>';
    h += '<div class="rank-bar"><i style="width:' + rankFraction(s) + '%"></i></div>';
    if (s.nextRank) {
      h += '<div class="stat-sub">' +
        esc(t('progress.toNext', 'อีก {n} XP ถึงระดับ {a}', { n: s.xpToNext, a: L(s.nextRank.name) })) + '</div>';
    } else {
      h += '<div class="stat-sub">' + esc(t('progress.maxRank', 'ถึงระดับสูงสุดแล้ว')) + '</div>';
    }
    h += '</div>';
    return h;
  }
  function rankFraction(s) {
    var rank = s.rank || {};
    var min = typeof rank.min === 'number' ? rank.min : 0;
    if (!s.nextRank) return 100;
    var span = s.nextRank.min - min;
    if (span <= 0) return 100;
    var f = Math.round(((s.xp - min) / span) * 100);
    return Math.max(0, Math.min(100, f));
  }

  function dashSection(title, inner) {
    return '<div class="dash-sec"><h2>' + esc(title) + '</h2>' + inner + '</div>';
  }

  function badgeShelfHTML(s) {
    var g = global.Gamify;
    var all = (g && Array.isArray(g.BADGES)) ? g.BADGES : [];
    if (all.length === 0) return '<div class="empty">' + esc(t('dash.noBadges', 'ยังไม่ได้เหรียญ')) + '</div>';
    var earned = {};
    var eb = s.badges || [];
    for (var i = 0; i < eb.length; i++) { if (eb[i] && eb[i].id) earned[eb[i].id] = true; }
    var h = '<div class="badge-shelf">';
    for (var j = 0; j < all.length; j++) {
      var b = all[j];
      var on = !!earned[b.id];
      h += '<div class="badge-chip ' + (on ? 'earned' : 'locked') + '">';
      h += '<span class="badge-ico" aria-hidden="true">' + esc(b.icon || '●') + '</span>';
      h += '<span class="badge-name">' + esc(L(b.name)) + '</span>';
      h += '<span class="badge-desc">' + esc(L(b.desc)) + '</span>';
      h += '</div>';
    }
    h += '</div>';
    return h;
  }

  function wkBarsHTML(s) {
    var pw = s.perWorkshop || [];
    if (pw.length === 0) return '<div class="empty">—</div>';
    var h = '<div class="wk-bars">';
    for (var i = 0; i < pw.length; i++) {
      var w = pw[i];
      var pct = w.total ? Math.round(w.solved / w.total * 100) : 0;
      h += '<div class="wk-bar"><div class="wk-bar-head"><span>' + esc(L(w.title)) + '</span><b>' +
        w.solved + '/' + w.total + '</b></div>';
      h += '<div class="wk-track"><i style="width:' + pct + '%"></i></div></div>';
    }
    h += '</div>';
    return h;
  }

  function sevGridHTML(s) {
    var ps = s.perSeverity || {};
    var h = '<div class="sev-grid">';
    for (var i = 0; i < SEV.length; i++) {
      var sv = SEV[i];
      var cell = ps[sv] || { solved: 0, total: 0 };
      h += '<div class="sev-cell"><span class="dot ' + sevClass(sv) + '" aria-hidden="true"></span>';
      h += '<span class="sev-name">' + esc(sevLabel(sv)) + '</span><b>' +
        (cell.solved || 0) + '/' + (cell.total || 0) + '</b></div>';
    }
    h += '</div>';
    return h;
  }

  function howStepsHTML() {
    var steps = [t('dash.step1', 'อ่านช่องโหว่ · การโจมตี · แนวทางแก้'),
      t('dash.step2', 'ลองยิง payload ใน Attack Lab เพื่อเห็นผลจริง'),
      t('dash.step3', 'แก้โค้ดในเอดิเตอร์ แล้วกดตรวจคำตอบ'),
      t('dash.step4', 'ทำควิซเพื่อยืนยันความเข้าใจ')];
    var h = '<ol class="how-steps">';
    for (var i = 0; i < steps.length; i++) {
      h += '<li class="how-step"><span class="how-num">' + (i + 1) + '</span><span>' + esc(steps[i]) + '</span></li>';
    }
    h += '</ol>';
    return h;
  }

  /* -------------------------------------------------------- exercise */

  function resolveCodeLang(ex, pref) {
    var langs = ex.languages || {};
    if (langs[pref]) return pref;
    if (langs.java) return 'java';
    if (langs.node) return 'node';
    return pref;
  }
  function highlightLang(langData, codeLang) {
    if (langData && langData.lang) return langData.lang;
    return codeLang === 'node' ? 'js' : 'java';
  }
  function fileName(langData, codeLang) {
    if (langData && langData.filename) return langData.filename;
    return codeLang === 'node' ? 'example.js' : 'Example.java';
  }

  function renderExercise(main) {
    if (editor && typeof editor.destroy === 'function') { try { editor.destroy(); } catch (e) {} }
    editor = null;

    var f = state.route.id ? findFlat(state.route.id) : (flat[0] || null);
    if (!f) {
      main.innerHTML = '<div class="empty">' + esc(t('nav.noResults', 'ไม่พบโจทย์ที่ค้นหา')) + '</div>';
      return;
    }
    var ex = f.ex;
    var codeLang = resolveCodeLang(ex, state.codeLang);
    var langs = ex.languages || {};
    var langData = langs[codeLang] || {};
    var idx = indexOfId(ex.id);
    var wkey = ex.id + ':' + codeLang;
    var code = (state.working[wkey] !== null && state.working[wkey] !== undefined)
      ? state.working[wkey] : (langData.starter || '');

    var html = '';
    html += '<div class="ex-header">';
    html += '<div class="ex-crumb">' + esc(L(f.workshop && f.workshop.title)) + '</div>';
    html += '<div class="ex-title-row"><h1 class="ex-title">' + esc(L(ex.title)) + '</h1>';
    html += '<span class="badge ' + sevClass(ex.severity) + '">' + esc(sevLabel(ex.severity)) + '</span></div>';
    html += metaChipsHTML(ex);
    html += '</div>';

    // แยกให้ชัดว่ากำลัง "เรียน" / "ลงมือแก้" / "ทดสอบความเข้าใจ"
    html += tabsHTML();

    html += '<section class="tab-panel" data-tab="learn">';
    var what = VULN_WHAT[ex.id];
    if (what) {
      html += '<div class="vuln-what"><span class="vuln-what-k">' +
        esc(t('sec.whatIsIt', 'ช่องโหว่นี้คืออะไร')) + '</span>' +
        esc(L(what)) + '</div>';
    }
    html += '<div class="cards">';
    var kp = ex.keyPoints || {};
    cardSeq = 0;
    html += cardHTML('card-attack', '⚠️', t('sec.attack', 'การโจมตี'), L(ex.attack), kp.attack);
    html += cardHTML('card-fix', '✅', t('sec.fix', 'แนวทางแก้'), L(ex.fix), kp.fix);
    html += '</div>';
    if (ex.impact) {
      html += '<div class="impact-line"><span class="impact-k">' + esc(t('sec.impact', 'ผลกระทบทางธุรกิจ')) +
        '</span><span>' + esc(L(ex.impact)) + '</span></div>';
    }

    html += vulnCodeHTML(ex, langData, codeLang, langs);
    html += safeCodeHTML(ex, langData, codeLang, langs);
    html += pitfallsHTML(ex);
    html += reviewHTML(ex);
    html += testitHTML(ex);
    html += caseStudyHTML(ex);
    html += refsHTML(ex);
    html += '</section>';

    html += '<section class="tab-panel" data-tab="practice" hidden>';
    html += '<div class="work-bar"><div class="lang-switch" role="tablist" aria-label="' +
      esc(t('lang.toggle', 'สลับภาษา ไทย/English')) + '">';
    html += langBtn('java', 'Java', codeLang, !!langs.java);
    html += langBtn('node', 'Node.js', codeLang, !!langs.node);
    html += '</div><span class="file-chip">' + esc(fileName(langData, codeLang)) + '</span></div>';
    html += '<div class="task-hint">' + esc(t('dash.step3', 'แก้โค้ดในเอดิเตอร์ แล้วกดตรวจคำตอบ')) + '</div>';

    html += '<div id="editor-host"></div>';

    html += '<div class="toolbar">';
    html += '<button id="btn-check" class="btn btn-primary" type="button">' + esc(t('btn.check', 'ตรวจคำตอบ')) + '</button>';
    html += '<button id="btn-reset" class="btn btn-danger" type="button">' + esc(t('btn.reset', 'รีเซ็ตโค้ด')) + '</button>';
    html += '<button id="btn-hint" class="btn btn-ghost" type="button">' + esc(t('btn.hint', 'คำใบ้')) + '</button>';
    html += '<button id="btn-solution" class="btn btn-ghost" type="button">' + esc(t('btn.solution', 'ดูเฉลย')) + '</button>';
    html += '<button id="btn-diff" class="btn btn-ghost" type="button">' + esc(t('btn.diff', 'เทียบกับเฉลย')) + '</button>';
    html += '</div>';

    html += '<div id="result-host" class="result-host"></div>';
    html += '<div id="hint-host"></div>';
    html += '<div id="solution-host"></div>';
    html += '<div id="diff-host"></div>';

    html += '</section>';


    html += pagerHTML(idx);

    main.innerHTML = html;

    mountEditor(document.getElementById('editor-host'), langData, code, wkey, ex, codeLang);
    wireExercise(ex, langData, codeLang, wkey, main);
    wireTabs(main);

    if (state.completed[ex.id]) showSolvedBanner();
    if ((state.hints[ex.id] || 0) > 0) renderHints(ex);
  }

  function metaChipsHTML(ex) {
    var h = '<div class="ex-meta">';
    h += chip(t('meta.severity', 'ความรุนแรง'), sevLabel(ex.severity));
    if (ex.cwe) h += chip(t('meta.cwe', 'CWE'), ex.cwe);
    if (ex.owasp) h += chip(t('meta.owasp', 'OWASP'), ex.owasp);
    if (typeof ex.estMinutes === 'number') h += chip(t('meta.time', 'เวลาโดยประมาณ'), t('nav.minutes', '{n} นาที', { n: ex.estMinutes }));
    if (state.completed[ex.id]) h += '<span class="meta-chip solved">✓ ' + esc(t('dash.solved', 'แก้แล้ว')) + '</span>';
    h += '</div>';
    return h;
  }
  function chip(k, v) {
    return '<span class="meta-chip"><span class="meta-k">' + esc(k) + '</span>' + esc(v) + '</span>';
  }
  /* การ์ดอธิบาย: ถ้ามี keyPoints ให้ bullet ขึ้นก่อน แล้วซ่อนย่อหน้าไว้หลังปุ่ม
     "อ่านรายละเอียด" — ถ้าไม่มี keyPoints ก็แสดงย่อหน้าตรง ๆ เหมือนเดิม */
  /* นิยามสั้น ๆ ว่า "ช่องโหว่นี้คืออะไร" แสดงบนสุดของแท็บ Vulnerability Information
     ก่อนจะลงรายละเอียด — intro เต็ม ๆ ยาวเฉลี่ย 385 ตัวอักษร ยาวไปสำหรับตรงนี้ */
  var VULN_WHAT = {
    'sql-injection': { th: 'ช่องโหว่ที่ attacker สามารถแทรกคำสั่ง SQL ผ่าน input ของระบบ ทำให้ query เดิมถูกเปลี่ยนไปจากที่ developer ตั้งใจ เกิดจากการนำค่าจากผู้ใช้ไปต่อรวมกับคำสั่ง SQL โดยตรง จน database แยกไม่ออกว่าส่วนไหนคือข้อมูลและส่วนไหนคือคำสั่ง', en: 'An attacker types malicious SQL syntax into a form field and can then read, modify or delete data in the database. It happens because the code concatenates user input into the command string, so the database cannot tell instruction from data.' },
    'xss': { th: 'ช่องโหว่ที่ attacker สามารถฝัง JavaScript ผ่าน input แล้วทำให้โค้ดนั้นไปรันใน browser ของผู้ใช้อื่น เกิดจากระบบนำข้อมูลไปแสดงเป็น HTML โดยไม่ encode ทำให้ browser ตีความเป็นโค้ดแทนข้อความธรรมดา', en: 'An attacker plants script into a page through a user-supplied value, and it runs in another victim browser. It comes from rendering the value without encoding, so the browser reads it as script instead of text.' },
    'command-injection': { th: 'ช่องโหว่ที่ attacker แทรกคำสั่งของระบบปฏิบัติการผ่าน input แล้ว server นำไปรันด้วยสิทธิ์ของแอป เกิดจากการประกอบคำสั่งเป็นสตริงแล้วส่งเข้า shell จนอักขระอย่าง ; หรือ && ถูกตีความเป็นคำสั่งเพิ่มเติม', en: 'An attacker injects an OS command through an input and the server runs it with the application privileges. It comes from building a command string and handing it to a shell, where ; or && starts a second command.' },
    'path-traversal': { th: 'ช่องโหว่ที่ attacker ใส่ค่าอย่าง ../ ในชื่อไฟล์หรือ path เพื่อออกจากโฟลเดอร์ที่ระบบอนุญาต แล้วไปอ่านหรือเขียนไฟล์อื่นบนเครื่อง เช่น /etc/passwd หรือไฟล์ config ที่มี secret', en: 'An attacker puts ../ in a filename to escape the intended folder and read other files on the machine, such as /etc/passwd or a config file holding secrets.' },
    'hardcoded-secrets': { th: 'ช่องโหว่ที่ password, API key หรือ token ถูกเขียนไว้ใน source code โดยตรง ใครที่อ่านหรือ clone repo ได้ก็เห็นค่าเหล่านี้ และเมื่อเคย commit ไปแล้ว ค่าจะยังอยู่ในประวัติ Git แม้จะลบออกจากไฟล์ภายหลัง', en: 'Passwords, API keys or tokens are written straight into the source. Anyone who can clone the repo sees them, and once committed they stay in git history forever, even after being deleted.' },
    'cors-misconfig': { th: 'ช่องโหว่ที่ตั้งค่า CORS กว้างเกินไป ทำให้เว็บของ attacker เรียก API ในนามผู้ใช้ที่ล็อกอินอยู่และอ่าน response กลับไปได้ มักเกิดจากการใช้ wildcard หรือสะท้อน Origin กลับโดยไม่ตรวจ allowlist', en: 'CORS is configured so loosely that an attacker site can call your API as the logged-in user and read the response. It usually comes from a wildcard, or from reflecting whatever Origin was sent.' },
    'verbose-errors': { th: 'ช่องโหว่ที่ระบบส่งรายละเอียดภายในกลับไปพร้อม error เช่น stack trace, คำสั่ง SQL, path บน server หรือเวอร์ชัน framework ข้อมูลเหล่านี้ช่วยให้ attacker เข้าใจโครงสร้างระบบและวางแผนโจมตีต่อได้ง่ายขึ้น', en: 'Error responses hand internal detail back to the caller — stack traces, SQL, real file paths, framework versions — all of which an attacker uses to plan the next step.' },
    'weak-hashing': { th: 'ช่องโหว่ที่เก็บ password ด้วย hash ที่ออกแบบมาให้คำนวณเร็ว เช่น MD5 หรือ SHA-256 เมื่อ database รั่ว attacker สามารถใช้ GPU เดา password จำนวนมากได้อย่างรวดเร็ว เพราะอัลกอริทึมเหล่านี้ไม่ได้ออกแบบมาให้ต้านการเดารหัส', en: 'Passwords are stored with a hash built for speed, such as MD5 or SHA-256. If the database leaks, a GPU can guess billions per second, so the real passwords fall quickly.' },
    'idor': { th: 'ช่องโหว่ที่ระบบตรวจเพียงว่า "ล็อกอินแล้วหรือยัง" แต่ไม่ตรวจว่า "ข้อมูลรายการนี้เป็นของผู้ใช้คนนี้หรือไม่" ผู้ใช้จึงเปลี่ยน id ใน URL หรือ request เพื่อเข้าถึงข้อมูลของบัญชีอื่นได้', en: 'The system checks that you are logged in but never that the record is yours. A user changes an id in the URL or request and reads other people data across the whole system.' },
    'jwt-forgery': { th: 'ช่องโหว่ที่ระบบอ่าน claims จาก JWT โดยไม่ verify signature ก่อน ทั้งที่ payload ของ JWT ไม่ได้เข้ารหัสและแก้ไขได้ attacker จึงอาจเปลี่ยน role หรือ user id แล้วส่ง token ปลอมให้ระบบยอมรับ', en: 'The app reads JWT claims without verifying the signature first. A JWT payload is not encrypted, so an attacker edits role to admin and sends the forged token without knowing the secret.' },
    'file-upload': { th: 'ช่องโหว่ที่ระบบรับไฟล์โดยเชื่อชนิดและชื่อไฟล์จาก client แล้วเก็บไว้ในตำแหน่งที่เรียกผ่านเว็บได้ attacker จึงอาจอัปโหลดไฟล์ที่รันได้ เช่น .jsp และเรียก URL ของไฟล์นั้นเพื่อรันโค้ดบน server', en: 'Uploads are accepted without a type check, keep the client filename, and land in a served folder. An attacker uploads an executable file such as .jsp and opens its URL to run commands.' },
    'vulnerable-deps': { th: 'ช่องโหว่ที่โปรเจกต์ใช้ library หรือ dependency เวอร์ชันที่มี CVE ประกาศแล้ว ต่อให้โค้ดของเราไม่มีบั๊ก ช่องโหว่ก็ยังติดมากับ component ที่นำมาใช้ และมักมีข้อมูลหรือ exploit สาธารณะให้ attacker ทดลองได้', en: 'The project depends on a library version with a published CVE. However well your own code is written, the flaw arrives with the dependency — and off-the-shelf exploits already exist.' },
    'ssrf': { th: 'ช่องโหว่ที่ attacker ควบคุม URL แล้วหลอกให้ server ของเราเป็นผู้ส่ง request ไปยังปลายทางแทน เช่น metadata service ของ cloud หรือบริการภายในที่เข้าจากภายนอกไม่ได้', en: 'An attacker tricks your server into making the request to a destination they cannot reach themselves — cloud instance metadata, or an internal service with no auth — because the request originates inside the firewall.' },
    'sensitive-logging': { th: 'ช่องโหว่ที่ระบบบันทึกข้อมูลอ่อนไหวลง log เช่น password, token, Authorization header หรือเลขบัตร ทำให้คนหรือระบบที่เข้าถึง log ได้สามารถนำข้อมูลเหล่านี้ไปใช้ต่อได้', en: 'Passwords, card numbers or tokens get written into the logs, then flow onward to the log aggregator, monitoring and backups — and sit there for the full retention period.' },
    'csrf': { th: 'ช่องโหว่ที่เว็บของ attacker ทำให้ browser ของเหยื่อส่ง request มายังระบบของเราโดยที่ผู้ใช้ไม่ได้ตั้งใจ และ browser แนบ session cookie ให้อัตโนมัติ ระบบจึงอาจเข้าใจผิดว่า request นั้นมาจากผู้ใช้จริง', en: 'An attacker page makes the victim browser send a request to your system. The browser attaches the session cookie automatically, so the server believes the victim did it — when they only opened a page.' },
    'rate-limit': { th: 'ช่องโหว่ที่ endpoint ล็อกอินไม่จำกัดจำนวนครั้ง ทำให้ attacker เดา password ซ้ำได้ต่อเนื่อง หรือใช้ username/password ที่รั่วจากระบบอื่นมาลองกับบัญชีจำนวนมากได้', en: 'The login endpoint has no attempt limit, so an attacker can guess passwords indefinitely, or replay credentials leaked elsewhere across tens of thousands of accounts.' },
    'open-redirect': { th: 'ช่องโหว่ที่ระบบ redirect ผู้ใช้ไปยัง URL ที่รับมาจาก parameter โดยไม่ตรวจปลายทาง attacker จึงสร้างลิงก์ที่เริ่มจากโดเมนที่น่าเชื่อถือ แล้วพาผู้ใช้ไปยังหน้า phishing ของตนได้', en: 'The app redirects to a URL taken from a parameter without checking it, so a phishing link can start on your trusted domain before bouncing to the attacker fake page.' }
  };


  var cardSeq = 0;
  // การ์ดอธิบาย: แสดงเฉพาะ bullet สั้น ๆ ไม่มีย่อหน้ายาวและไม่มีปุ่มกาง
  // ถ้าโจทย์ไหนยังไม่มี keyPoints ค่อยตกกลับไปใช้ย่อหน้าเดิม
  function cardHTML(cls, ico, title, body, points) {
    var h = '<div class="card ' + cls + '"><div class="card-title"><span aria-hidden="true">' + esc(ico) +
      '</span>' + esc(title) + '</div>';
    var list = Array.isArray(points) ? points : null;
    if (list && list.length) {
      h += '<ul class="card-points">';
      for (var i = 0; i < list.length; i++) h += '<li>' + esc(L(list[i])) + '</li>';
      h += '</ul>';
    } else if (body) {
      h += '<div class="card-body">' + esc(body) + '</div>';
    }
    return h + '</div>';
  }
  function langBtn(lang, label, current, exists) {
    var cls = 'lang-btn' + (lang === current ? ' on' : '');
    return '<button class="' + cls + '" type="button" role="tab" data-lang="' + lang + '"' +
      (exists ? '' : ' disabled') + ' aria-selected="' + (lang === current ? 'true' : 'false') + '">' +
      esc(label) + '</button>';
  }
  function pagerHTML(idx) {
    var prev = idx > 0 ? flat[idx - 1] : null;
    var next = (idx >= 0 && idx < flat.length - 1) ? flat[idx + 1] : null;
    var h = '<div class="pager">';
    if (prev) {
      h += '<button class="btn pager-prev" type="button" data-id="' + esc(prev.ex.id) + '">' +
        '<span class="pager-dir">← ' + esc(t('btn.prev', 'ก่อนหน้า')) + '</span>' +
        '<span class="pager-title">' + esc(L(prev.ex.title)) + '</span></button>';
    } else {
      h += '<button class="btn pager-prev" type="button" disabled><span class="pager-dir">← ' +
        esc(t('btn.prev', 'ก่อนหน้า')) + '</span></button>';
    }
    if (next) {
      h += '<button class="btn pager-next" type="button" data-id="' + esc(next.ex.id) + '">' +
        '<span class="pager-dir">' + esc(t('btn.next', 'ถัดไป')) + ' →</span>' +
        '<span class="pager-title">' + esc(L(next.ex.title)) + '</span></button>';
    } else {
      h += '<button class="btn pager-next" type="button" disabled><span class="pager-dir">' +
        esc(t('btn.next', 'ถัดไป')) + ' →</span></button>';
    }
    h += '</div>';
    return h;
  }

  function mountEditor(host, langData, code, wkey, ex, codeLang) {
    if (!host) return;
    var Ed = global.CodeEditor;
    var hlLang = highlightLang(langData, codeLang);
    if (typeof Ed === 'function') {
      try {
        editor = new Ed(host, {
          language: hlLang,
          onChange: function (val) { state.working[wkey] = val; save(); },
          onSubmit: function () { doCheck(ex, langData, wkey); }
        });
        editor.setValue(code);
        return;
      } catch (e) { editor = null; }
    }
    var ta = document.createElement('textarea');
    ta.className = 'editor-area editor-area-solo';
    ta.value = code;
    ta.setAttribute('spellcheck', 'false');
    ta.style.width = '100%';
    ta.style.minHeight = '300px';
    ta.addEventListener('input', function () { state.working[wkey] = ta.value; save(); });
    host.appendChild(ta);
    editor = {
      getValue: function () { return ta.value; },
      setValue: function (v) { ta.value = (v === null || v === undefined) ? '' : String(v); },
      focus: function () { try { ta.focus(); } catch (e) {} },
      destroy: function () { if (ta.parentNode) ta.parentNode.removeChild(ta); }
    };
  }

  function wireExercise(ex, langData, codeLang, wkey, main) {
    var lbtns = $all('.lang-switch .lang-btn', main);
    for (var i = 0; i < lbtns.length; i++) {
      (function (btn) {
        btn.addEventListener('click', function () {
          if (btn.disabled) return;
          var l = btn.getAttribute('data-lang');
          if (l === state.codeLang) return;
          if (!(ex.languages && ex.languages[l])) return;
          state.codeLang = l;
          save();
          renderExercise(main);
        });
      })(lbtns[i]);
    }
    var bc = document.getElementById('btn-check');
    if (bc) bc.addEventListener('click', function () { doCheck(ex, langData, wkey); });
    var br = document.getElementById('btn-reset');
    if (br) br.addEventListener('click', function () {
      if (editor) editor.setValue(langData.starter || '');
      state.working[wkey] = langData.starter || '';
      save();
      var rh = document.getElementById('result-host');
      if (rh) clear(rh);
      if (editor && editor.focus) editor.focus();
    });
    var bh = document.getElementById('btn-hint');
    if (bh) bh.addEventListener('click', function () { onHintButton(ex); });
    var bs = document.getElementById('btn-solution');
    if (bs) bs.addEventListener('click', function () { toggleSolution(ex, langData, codeLang, wkey); });
    var bd = document.getElementById('btn-diff');
    if (bd) bd.addEventListener('click', function () { toggleDiff(langData); });
    var pp = $('.pager-prev', main);
    if (pp && !pp.disabled) pp.addEventListener('click', function () {
      var id = pp.getAttribute('data-id'); if (id) go('exercise', id);
    });
    var pn = $('.pager-next', main);
    if (pn && !pn.disabled) pn.addEventListener('click', function () {
      var id = pn.getAttribute('data-id'); if (id) go('exercise', id);
    });
    var cp = $('[data-copy="testit"]', main);
    if (cp) cp.addEventListener('click', function () {
      var pre = $('.testit-cmd pre', main);
      if (pre) copyText(pre.textContent);
    });
    var cpay = $('[data-copy="payload"]', main);
    if (cpay) cpay.addEventListener('click', function () {
      var code = $('.testit-payload code', main);
      if (code) copyText(code.textContent);
    });
  }

  function triggerCheckShortcut(ex) {
    var codeLang = resolveCodeLang(ex, state.codeLang);
    var langData = (ex.languages || {})[codeLang] || {};
    doCheck(ex, langData, ex.id + ':' + codeLang);
  }

  /* -------------------------------------------------------- grading result */

  function doCheck(ex, langData, wkey) {
    var G = global.Grader;
    var host = document.getElementById('result-host');
    if (!G || typeof G.runChecks !== 'function') {
      if (host) {
        clear(host);
        host.appendChild(banner('fail', '✗', 'Grader ' + t('lab.unavailable', 'ไม่พร้อมใช้งาน')));
      }
      return;
    }
    var val = editor ? editor.getValue() : '';
    var res = G.runChecks(val, langData.checks || [], langData.traps || []);
    renderResult(res);
    if (res && res.passed) onSolved(ex, res);
  }

  function banner(kind, ico, text) {
    var b = elem('div', 'result-banner ' + kind);
    var i = elem('span', 'rb-ico', ico);
    b.appendChild(i);
    b.appendChild(document.createTextNode(' ' + text));
    return b;
  }

  function renderResult(res) {
    var host = document.getElementById('result-host');
    if (!host) return;
    clear(host);
    if (!res) return;
    if (res.error === 'too-short') {
      host.appendChild(banner('fail', '✗', t('result.tooShort', 'โค้ดสั้นเกินไป — แก้ไขโค้ดในเอดิเตอร์ก่อนกดตรวจ')));
      return;
    }
    var results = res.results || [];
    var passCount = 0;
    for (var i = 0; i < results.length; i++) { if (results[i].passed) passCount++; }
    var totalC = results.length;
    if (res.passed) {
      host.appendChild(banner('pass', '✓', t('result.passAll', 'ผ่านทุกกติกาแล้ว ({a}/{b}) — เยี่ยมมาก', { a: passCount, b: totalC })));
    } else {
      host.appendChild(banner('fail', '✗', t('result.partial', 'ผ่าน {a}/{b} กติกา — แก้ตามรายการด้านล่างแล้วลองใหม่', { a: passCount, b: totalC })));
    }
    var ul = elem('ul', 'checks');
    for (var j = 0; j < results.length; j++) {
      var r = results[j];
      var li = elem('li', r.passed ? 'ok' : 'no');
      li.appendChild(elem('span', 'ck-icon', r.passed ? '✓' : '✗'));
      var body = elem('span', 'ck-body');
      body.appendChild(elem('span', 'ck-label', L(r.label)));
      if (!r.passed && r.hint) body.appendChild(elem('span', 'ck-hint', '💡 ' + L(r.hint)));
      li.appendChild(body);
      ul.appendChild(li);
    }
    host.appendChild(ul);
    var traps = res.traps || [];
    if (traps.length) {
      var tb = elem('div', 'traps');
      var tt = elem('div', 'traps-title');
      tt.appendChild(elem('span', null, '⚠'));
      tt.appendChild(document.createTextNode(' ' + t('result.trapTitle', 'ระวัง — วิธีนี้ยังไม่ปลอดภัยจริง')));
      tb.appendChild(tt);
      for (var k = 0; k < traps.length; k++) tb.appendChild(elem('div', 'trap', L(traps[k].message)));
      host.appendChild(tb);
    }
    try {
      if (host.scrollIntoView) host.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'nearest' });
    } catch (e) {}
  }

  function showSolvedBanner() {
    var host = document.getElementById('result-host');
    if (!host || host.firstChild) return;
    host.appendChild(banner('pass', '✓', t('result.solvedAlready', 'คุณแก้โจทย์นี้ผ่านแล้ว')));
  }

  function onSolved(ex, res) {
    var before = computeStats();
    var wasSolved = !!state.completed[ex.id];
    var prevAt = (wasSolved && state.completed[ex.id].at) ? state.completed[ex.id].at : now();
    state.completed[ex.id] = {
      at: prevAt,
      hintsUsed: state.hints[ex.id] || 0,
      revealed: !!state.revealed[ex.id],
      score: res.score || 0,
      maxScore: res.maxScore || 0
    };
    save();
    renderSidebar();
    if (!wasSolved) celebrate();
  }

  // XP, rank และเหรียญถูกเอาออกจากหน้าจอแล้ว จึงไม่มีอะไรต้องประกาศ
  function celebrate() {}


  /* -------------------------------------------------------- hints */

  function onHintButton(ex) {
    var host = document.getElementById('hint-host');
    var count = state.hints[ex.id] || 0;
    if (count === 0 && host && !host.firstChild) { renderHints(ex); return; }
    revealNextHint(ex);
  }
  function revealNextHint(ex) {
    var hints = Array.isArray(ex.hints) ? ex.hints : [];
    var count = state.hints[ex.id] || 0;
    if (count < hints.length) { state.hints[ex.id] = count + 1; save(); }
    renderHints(ex);
  }
  function renderHints(ex) {
    var host = document.getElementById('hint-host');
    if (!host) return;
    clear(host);
    var hints = Array.isArray(ex.hints) ? ex.hints : [];
    if (hints.length === 0) return;
    var count = state.hints[ex.id] || 0;
    var box = elem('div', 'hints');
    box.appendChild(elem('div', 'hints-title', t('sec.hints', 'คำใบ้')));
    if (count === 0) {
      box.appendChild(elem('div', 'hints-warn', t('hint.tryFirst', 'ลองแก้เองก่อนสักรอบ แล้วค่อยเปิดคำใบ้')));
    } else {
      var ol = document.createElement('ol');
      for (var i = 0; i < count && i < hints.length; i++) ol.appendChild(elem('li', null, L(hints[i])));
      box.appendChild(ol);
    }
    if (count < hints.length) {
      var actions = elem('div', 'hints-actions');
      var btn = elem('button', 'btn btn-ghost btn-small',
        count === 0 ? t('btn.hint', 'คำใบ้') : t('hint.more', 'กด "คำใบ้" อีกครั้งเพื่อดูเพิ่ม'));
      btn.type = 'button';
      btn.addEventListener('click', function () { revealNextHint(ex); });
      actions.appendChild(btn);
      box.appendChild(actions);
    }
    host.appendChild(box);
  }

  /* -------------------------------------------------------- solution / diff */

  function highlightCode(code, lang) {
    var H = global.Highlighter;
    if (H && typeof H.highlight === 'function') { try { return H.highlight(code, lang); } catch (e) {} }
    return esc(code);
  }
  function toggleSolution(ex, langData, codeLang, wkey) {
    var host = document.getElementById('solution-host');
    if (!host) return;
    if (host.firstChild) { clear(host); return; }
    if (!state.completed[ex.id] && !state.revealed[ex.id]) { state.revealed[ex.id] = true; save(); }
    renderSolution(host, ex, langData, codeLang, wkey);
  }
  function renderSolution(host, ex, langData, codeLang, wkey) {
    clear(host);
    var box = elem('div', 'solution');
    box.appendChild(elem('div', 'solution-title',
      t('sec.solution', 'เฉลย') + ' · ' + (codeLang === 'node' ? 'Node.js' : 'Java')));
    var pre = elem('pre', 'code-view');
    var codeEl = document.createElement('code');
    codeEl.innerHTML = highlightCode(langData.solution || '', highlightLang(langData, codeLang));
    pre.appendChild(codeEl);
    box.appendChild(pre);
    if (langData.explain) {
      var ex2 = elem('div', 'solution-explain');
      ex2.innerHTML = '<b>' + esc(t('sec.fix', 'แนวทางแก้')) + ':</b> ' + esc(L(langData.explain));
      box.appendChild(ex2);
    }
    var actions = elem('div', 'solution-actions');
    var load = elem('button', 'btn btn-ghost btn-small', t('btn.loadSolution', 'โหลดเฉลยลงเอดิเตอร์'));
    load.type = 'button';
    load.addEventListener('click', function () {
      if (editor) editor.setValue(langData.solution || '');
      state.working[wkey] = langData.solution || '';
      save();
      if (editor && editor.focus) editor.focus();
    });
    var hide = elem('button', 'btn btn-ghost btn-small', t('btn.hideSolution', 'ซ่อนเฉลย'));
    hide.type = 'button';
    hide.addEventListener('click', function () { clear(host); });
    actions.appendChild(load);
    actions.appendChild(hide);
    box.appendChild(actions);
    host.appendChild(box);
  }

  function toggleDiff(langData) {
    var host = document.getElementById('diff-host');
    if (!host) return;
    if (host.firstChild) { clear(host); return; }
    var D = global.Diff;
    var yours = editor ? editor.getValue() : '';
    var solution = langData.solution || '';
    var box = elem('div', 'diffview');
    var head = elem('div', 'diff-head');
    head.appendChild(elem('span', null, t('diff.yours', 'โค้ดของคุณ')));
    head.appendChild(elem('span', null, t('diff.solution', 'เฉลย')));
    box.appendChild(head);
    if (!D || typeof D.lines !== 'function') {
      box.appendChild(elem('div', 'diff-same', '—'));
      host.appendChild(box);
      return;
    }
    var rows = D.lines(yours, solution);
    var changed = false;
    for (var i = 0; i < rows.length; i++) { if (rows[i].type !== 'ctx') { changed = true; break; } }
    if (!changed) {
      box.appendChild(elem('div', 'diff-same', t('diff.same', 'โค้ดของคุณตรงกับเฉลยทุกบรรทัด')));
      host.appendChild(box);
      return;
    }
    var body = elem('div', 'diff-body');
    for (var j = 0; j < rows.length; j++) body.appendChild(diffRow(rows[j]));
    box.appendChild(body);
    host.appendChild(box);
  }
  function diffRow(r) {
    var cls = r.type === 'add' ? 'diff-add' : (r.type === 'del' ? 'diff-del' : 'diff-ctx');
    var line = elem('div', 'diff-line ' + cls);
    var gut = elem('span', 'diff-gut');
    gut.textContent = r.type === 'add' ? (r.bLine !== null && r.bLine !== undefined ? String(r.bLine) : '')
      : (r.aLine !== null && r.aLine !== undefined ? String(r.aLine) : '');
    var sign = elem('span', 'diff-sign', r.type === 'add' ? '+' : (r.type === 'del' ? '−' : ' '));
    sign.setAttribute('aria-hidden', 'true');
    var text = elem('span', 'diff-text', r.text);
    line.appendChild(gut);
    line.appendChild(sign);
    line.appendChild(text);
    return line;
  }

  /* -------------------------------------------------------- learning blocks */

  /* ปุ่ม "อ่านรายละเอียด" ทุกปุ่มในหน้าเดียวกันทำงานพร้อมกัน และจำค่าไว้ข้ามโจทย์
     ผู้สอนที่อยากเห็นย่อหน้าเต็มจะได้ไม่ต้องกดใหม่ทั้ง 24 ข้อ */
  function wireReadMore(main) {
    var btns = $all('.card-more', main);
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener('click', function () {
        var open = !state.ui.detailsOpen;
        state.ui.detailsOpen = open;
        save();
        applyReadMore(main, open);
      });
    }
  }
  function applyReadMore(main, open) {
    var i;
    var panels = $all('.card-detail', main);
    for (i = 0; i < panels.length; i++) {
      var c = panels[i].className.replace(/\s*\bopen\b/g, '');
      panels[i].className = open ? c + ' open' : c;
    }
    var btns = $all('.card-more', main);
    for (i = 0; i < btns.length; i++) {
      btns[i].setAttribute('aria-expanded', open ? 'true' : 'false');
      btns[i].textContent = open
        ? t('btn.readLess', 'ย่อรายละเอียด')
        : t('btn.readMore', 'อ่านรายละเอียด');
    }
  }

  /* ------------------------------------------------ tabs: เรียน / แก้ / ควิซ
     แยกสามโหมดออกจากกัน ผู้เรียนจะได้ไม่ต้องเลื่อนผ่านคำอธิบายยาว ๆ
     ทุกครั้งที่อยากกลับไปแก้โค้ด แท็บที่เลือกไว้จำข้ามโจทย์ */
  var TABS = [
    { id: 'learn', label: 'sec.tabLearn', fallback: 'Vulnerability Information' },
    { id: 'practice', label: 'sec.tabPractice', fallback: 'Coding Practice' }
  ];
  function currentTab() {
    var v = state.ui && state.ui.tab;
    for (var i = 0; i < TABS.length; i++) if (TABS[i].id === v) return v;
    return 'learn';
  }
  function tabsHTML() {
    var cur = currentTab();
    var h = '<div class="ex-tabs" role="tablist">';
    for (var i = 0; i < TABS.length; i++) {
      var tb = TABS[i];
      h += '<button type="button" role="tab" class="ex-tab' + (tb.id === cur ? ' on' : '') +
        '" data-tab="' + tb.id + '" aria-selected="' + (tb.id === cur ? 'true' : 'false') + '">' +
        esc(t(tb.label, tb.fallback)) + '</button>';
    }
    return h + '</div>';
  }
  function showTab(main, id) {
    var i;
    var panels = $all('.tab-panel', main);
    for (i = 0; i < panels.length; i++) {
      var on = panels[i].getAttribute('data-tab') === id;
      if (on) panels[i].removeAttribute('hidden');
      else panels[i].setAttribute('hidden', '');
    }
    var btns = $all('.ex-tab', main);
    for (i = 0; i < btns.length; i++) {
      var sel = btns[i].getAttribute('data-tab') === id;
      btns[i].className = 'ex-tab' + (sel ? ' on' : '');
      btns[i].setAttribute('aria-selected', sel ? 'true' : 'false');
    }
  }
  function wireTabs(main) {
    var btns = $all('.ex-tab', main);
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener('click', function (ev) {
        var id = ev.currentTarget.getAttribute('data-tab');
        state.ui.tab = id;
        save();
        showTab(main, id);
      });
    }
    showTab(main, currentTab());
  }

  /* ------------------------------------------- ตัวอย่างโค้ดที่ไม่ปลอดภัย
     ไม่ต้องเขียนคำอธิบายใหม่ทีละข้อ เพราะ checks บอกไว้หมดแล้ว:
       mustNotMatch = "สิ่งที่ไม่ควรมี" -> ไฮไลต์บรรทัดนั้นเลย
       mustMatch    = "สิ่งที่ต้องมี"   -> ถ้าโค้ดยังไม่มี แปลว่านี่คือจุดที่ขาด
     บั๊กบางชนิด (เช่น IDOR, rate limit) ไม่มีบรรทัดผิด มีแต่ของที่ขาดไป */
  /* label ของ check เขียนในมุม "กฎที่ต้องทำ" (เช่น "ไม่ต่อค่า username เข้ากับ SQL")
     แต่หัวข้อนี้ต้องการมุม "ทำไมถึงเป็นช่องโหว่" จึงตัดคำปฏิเสธนำหน้าออก
     ให้เหลือประโยคที่บอกว่าโค้ดกำลังทำอะไรผิดอยู่ */
  function asVulnReason(lstr) {
    var txt = L(lstr);
    var th = /^ไม่(ใช้|ต่อ|ฝัง|เก็บ|ส่ง|เปิด|ตั้ง|รับ|เชื่อ|ปล่อย|อนุญาต|log|เขียน|คืน|ยอม)?/;
    if (/^ไม่/.test(txt)) return txt.replace(/^ไม่\s*/, '');
    var en = /^(do not|don't|never|no)\s+/i;
    if (en.test(txt)) return txt.replace(en, '');
    return txt;
  }

  function vulnCodeHTML(ex, langData, codeLang, langs) {
    if (!langData || !langData.starter) return '';
    var G = global.Grader;
    var code = langData.starter;
    var lines = code.split('\n');
    var checks = langData.checks || [];
    var i, c;

    function fresh(re) { return new RegExp(re.source, re.flags.replace('g', '')); }

    // บรรทัดไหนโดน mustNotMatch บ้าง
    var flags = {};
    var reasons = [];
    var missing = [];
    for (i = 0; i < checks.length; i++) {
      c = checks[i];
      if (!c.mustNotMatch) continue;
      var re = fresh(c.mustNotMatch);
      var hitAny = false;
      for (var n = 0; n < lines.length; n++) {
        var bare = G ? G.stripComments(lines[n]) : lines[n];
        if (re.test(bare)) {
          if (!flags[n]) flags[n] = [];
          flags[n].push(reasons.length + 1);
          hitAny = true;
        }
      }
      if (hitAny) reasons.push({ kind: 'bad', label: c.label, hint: c.hint });
    }
    // ของที่ "ต้องมี" แต่ยังไม่มี = จุดที่ขาด
    var stripped = G ? G.stripComments(code) : code;
    for (i = 0; i < checks.length; i++) {
      c = checks[i];
      if (!c.mustMatch) continue;
      if (!fresh(c.mustMatch).test(stripped)) missing.push({ kind: 'missing', label: c.label, hint: c.hint });
    }
    // บั๊กบางชนิดไม่มีบรรทัดผิด มีแต่ของที่ไม่ได้ทำ (IDOR, rate limit, CSRF)
    // กรณีนั้นค่อยใช้รายการ 'ยังไม่ได้ทำ' มาอธิบายแทน
    if (!reasons.length) reasons = missing;
    if (!reasons.length) return '';

    var H = global.Highlighter;
    var hl = H ? function (x) { return H.highlight(x, langData.lang || 'generic'); } : esc;

    var h = section(t('sec.vulnCode', 'ตัวอย่างโค้ดที่ไม่ปลอดภัย'), '!');
    h += '<div class="vulncode">';
    h += '<div class="work-bar"><div class="lang-switch" role="tablist">';
    h += langBtn('java', 'Java', codeLang, !!langs.java);
    h += langBtn('node', 'Node.js', codeLang, !!langs.node);
    h += '</div><span class="file-chip">' + esc(fileName(langData, codeLang)) + '</span></div>';

    h += '<pre class="vulncode-pre"><code>';
    for (i = 0; i < lines.length; i++) {
      var marks = flags[i];
      h += '<span class="vc-line' + (marks ? ' vc-bad' : '') + '">';
      h += '<span class="vc-no">' + (i + 1) + '</span>';
      h += '<span class="vc-src">' + hl(lines[i]) + '</span>';
      if (marks) h += '<span class="vc-tag">' + esc('!' + marks.join(',')) + '</span>';
      h += '</span>\n';
    }
    h += '</code></pre>';

    h += '<div class="vc-why-k">' + esc(t('sec.vulnWhy', 'ทำไมถึงเป็นช่องโหว่')) + '</div>';
    h += '<ol class="vc-why">';
    var badN = 0;
    for (i = 0; i < reasons.length; i++) {
      var r = reasons[i];
      var isBad = r.kind === 'bad';
      var mark;
      if (isBad) { badN++; mark = '!' + badN; } else { mark = '&#8226;'; }
      h += '<li class="' + (isBad ? 'vc-why-bad' : 'vc-why-missing') + '">';
      h += '<span class="vc-why-n">' + mark + '</span>';
      h += '<span class="vc-why-body">';
      h += '<span class="vc-why-reason">' +
        esc(isBad ? asVulnReason(r.label) : t('sec.vulnNotYet', 'ยังไม่ได้') + ' ' + L(r.label)) +
        '</span>';
      if (r.hint) {
        h += '<span class="vc-why-fix"><b>' + esc(t('sec.vulnFix', 'แก้โดย')) + '</b> ' +
          esc(L(r.hint)) + '</span>';
      }
      h += '</span></li>';
    }
    h += '</ol></div></div>';
    return h;
  }

  /* --------------------------------------------------- แนวทางแก้ (diff)
     อ้างอิงกับโค้ดที่ไม่ปลอดภัยด้านบนโดยตรง แสดงเป็น diff แบบเดียวกับตอนดู commit
     - = บรรทัดเดิมที่ต้องเอาออก   + = บรรทัดใหม่ที่ต้องใส่แทน
     แสดงเฉพาะช่วงที่เปลี่ยน (hunk) พร้อมบริบท 2 บรรทัด ไม่ใช่ไฟล์เต็ม
     ผู้เรียนจึงเห็นว่าต้องขยับอะไรบ้าง แต่ไม่ได้เฉลยทั้งไฟล์ไปวาง */
  var DIFF_CTX = 2;

  function safeCodeHTML(ex, langData, codeLang, langs) {
    if (!langData || !langData.starter || !langData.solution) return '';
    var D = global.Diff;
    if (!D || typeof D.lines !== 'function') return '';
    var rows;
    try { rows = D.lines(langData.starter, langData.solution); } catch (e) { return ''; }
    if (!rows || !rows.length) return '';

    var i, n;
    var G = global.Grader;
    var checks = langData.checks || [];
    function fresh(re) { return new RegExp(re.source, re.flags.replace('g', '')); }

    // ผูกบรรทัดที่เพิ่มเข้ามากับกฎ mustMatch เพื่อบอกว่าบรรทัดนั้นทำหน้าที่อะไร
    var tagOf = {};
    var reasons = [];
    for (i = 0; i < checks.length; i++) {
      var c = checks[i];
      if (!c.mustMatch) continue;
      var re = fresh(c.mustMatch);
      var found = false;
      for (n = 0; n < rows.length; n++) {
        if (rows[n].type !== 'add') continue;
        var bare = G ? G.stripComments(rows[n].text) : rows[n].text;
        if (!re.test(bare)) continue;
        if (!tagOf[n]) tagOf[n] = [];
        tagOf[n].push(reasons.length + 1);
        found = true;
      }
      if (found) reasons.push({ label: c.label, hint: c.hint });
    }

    // บรรทัดที่ถูกลบและ "เคยเป็นช่องโหว่" (โดน mustNotMatch) ก็ถือว่าเกี่ยวข้อง
    var relevant = {};
    for (n = 0; n < rows.length; n++) if (tagOf[n]) relevant[n] = true;
    for (i = 0; i < checks.length; i++) {
      if (!checks[i].mustNotMatch) continue;
      var bad = fresh(checks[i].mustNotMatch);
      for (n = 0; n < rows.length; n++) {
        if (rows[n].type !== 'del') continue;
        var raw = G ? G.stripComments(rows[n].text) : rows[n].text;
        if (bad.test(raw)) relevant[n] = true;
      }
    }
    // ไม่มีจุดไหนเกี่ยวกับความปลอดภัยเลย (เปลี่ยนแค่คอมเมนต์) ก็ไม่ต้องแสดง
    var anyRelevant = false;
    for (n in relevant) { if (relevant[n]) { anyRelevant = true; break; } }
    if (!anyRelevant) return '';

    // แสดงเฉพาะรอบ ๆ จุดที่เกี่ยวข้อง ไม่ใช่ทุกจุดที่ diff ต่างกัน
    var keep = {};
    for (n = 0; n < rows.length; n++) {
      if (!relevant[n]) continue;
      for (i = Math.max(0, n - DIFF_CTX); i <= Math.min(rows.length - 1, n + DIFF_CTX); i++) keep[i] = true;
    }

    var H = global.Highlighter;
    var hl = H ? function (x) { return H.highlight(x, langData.lang || 'generic'); } : esc;

    var h = section(t('sec.safeCode', 'แนวทางแก้ — เทียบกับโค้ดด้านบน'), '+');
    h += '<div class="vulncode safecode">';
    h += '<div class="safecode-lead">' +
      esc(t('sec.safeLead', 'อ่านแบบเดียวกับตอนดู commit: บรรทัด - คือของเดิมที่ต้องเอาออก บรรทัด + คือของใหม่ที่ใส่แทน')) +
      '</div>';
    h += '<div class="work-bar"><div class="lang-switch" role="tablist">';
    h += langBtn('java', 'Java', codeLang, !!langs.java);
    h += langBtn('node', 'Node.js', codeLang, !!langs.node);
    h += '</div><span class="file-chip">' + esc(fileName(langData, codeLang)) + '</span></div>';

    h += '<pre class="vulncode-pre diffcode"><code>';
    var gap = false;
    for (i = 0; i < rows.length; i++) {
      if (!keep[i]) { gap = true; continue; }
      if (gap && i > 0) {
        h += '<span class="vc-line vc-gap"><span class="vc-no">&#8942;</span>' +
          '<span class="vc-sign"></span><span class="vc-src">' +
          esc(t('sec.safeGap', '… ส่วนที่เหลือไม่ต้องแก้')) + '</span></span>\n';
      }
      gap = false;
      var r = rows[i];
      var cls = r.type === 'del' ? ' vc-del' : (r.type === 'add' ? ' vc-add' : '');
      var sign = r.type === 'del' ? '-' : (r.type === 'add' ? '+' : ' ');
      var num = r.type === 'del' ? r.aLine : r.bLine;
      h += '<span class="vc-line' + cls + '">';
      h += '<span class="vc-no">' + (num === null || num === undefined ? '' : num) + '</span>';
      h += '<span class="vc-sign">' + sign + '</span>';
      h += '<span class="vc-src">' + hl(r.text) + '</span>';
      if (tagOf[i]) h += '<span class="vc-tag vc-tag-good">' + esc('\u2713' + tagOf[i].join(',')) + '</span>';
      h += '</span>\n';
    }
    h += '</code></pre>';

    if (reasons.length) {
      h += '<div class="vc-why-k">' + esc(t('sec.safeWhy', 'บรรทัดที่เพิ่มเข้ามาทำหน้าที่อะไร')) + '</div>';
      h += '<ol class="vc-why">';
      for (i = 0; i < reasons.length; i++) {
        h += '<li class="vc-why-good"><span class="vc-why-n">&#10003;' + (i + 1) + '</span>';
        h += '<span class="vc-why-body"><span class="vc-why-reason">' + esc(L(reasons[i].label)) + '</span>';
        if (reasons[i].hint) {
          h += '<span class="vc-why-fix"><b>' + esc(t('sec.safeHow', 'ทำยังไง')) + '</b> ' +
            esc(L(reasons[i].hint)) + '</span>';
        }
        h += '</span></li>';
      }
      h += '</ol>';
    }
    h += '</div></div>';
    return h;
  }

  function section(title, ico) {
    return '<div class="ex-sec"><h2><span class="sec-ico" aria-hidden="true">' + esc(ico || '') + '</span>' +
      esc(title) + '</h2>';
  }
  function pitfallsHTML(ex) {
    var arr = Array.isArray(ex.pitfalls) ? ex.pitfalls : [];
    if (arr.length === 0) return '';
    var h = section(t('sec.pitfalls', 'กับดักที่พบบ่อย (แก้แบบนี้ยังไม่ปลอดภัย)'), '⚠');
    h += '<div class="pitfalls">';
    for (var i = 0; i < arr.length; i++) {
      var p = arr[i] || {};
      // ติดป้ายให้ชัดว่าบรรทัดไหนคือ "ความเชื่อที่ผิด" และบรรทัดไหนคือ "ความจริง"
      // ถ้าปล่อยเป็นสองประโยคลอย ๆ ผู้อ่านจะแยกไม่ออกว่าอันไหนถูก
      h += '<div class="pitfall">';
      h += '<div class="pitfall-title"><span class="pf-k pf-k-myth">' +
        esc(t('pitfall.myth', 'เข้าใจผิดว่า')) + '</span>' + esc(L(p.title)) + '</div>';
      h += '<div class="pitfall-short"><span class="pf-k pf-k-real">' +
        esc(t('pitfall.real', 'จริง ๆ แล้ว')) + '</span>' + esc(L(p.short) || L(p.why)) + '</div>';
      h += '</div>';
    }
    h += '</div></div>';
    return h;
  }
  function reviewHTML(ex) {
    var arr = Array.isArray(ex.codeReview) ? ex.codeReview : [];
    if (arr.length === 0) return '';
    var h = section(t('sec.codeReview', 'มองหาอะไรตอน Code Review'), '🔍');
    h += '<ul class="review-list">';
    for (var i = 0; i < arr.length; i++) {
      h += '<li><span class="rv-ico" aria-hidden="true">▸</span><span>' + esc(L(arr[i])) + '</span></li>';
    }
    h += '</ul></div>';
    return h;
  }
  /* payload แต่ละข้อคนละชนิดกัน บางอันพิมพ์ลงช่อง input ได้เลย บางอันเป็นคำสั่ง
     terminal และบางอันเป็นแค่ชื่อ scenario ที่ไม่ใช่ค่าที่เอาไปใช้ได้จริง
     (ตกค้างจาก Attack Lab ที่ถอดออกไป) — ข้อหลังนี้ไม่ต้องโชว์ ให้ใช้คำสั่งแทน */
  var PAYLOAD_KIND = {
    'sql-injection': 'input', 'xss': 'input', 'command-injection': 'input',
    'path-traversal': 'input', 'weak-hashing': 'input', 'idor': 'input',
    'ssrf': 'input', 'rate-limit': 'input',
    'jwt-forgery': 'body',
    'file-upload': 'file',
    'cors-misconfig': 'header',
    'hardcoded-secrets': 'shell',
    'session-cookie': 'console',
    'csrf': 'html'
    // ที่เหลือ (security-headers, verbose-errors, vulnerable-deps,
    // weak-random-token, insecure-tls, sensitive-logging) เป็นชื่อ scenario
    // ไม่ใช่ค่าที่ paste ได้ จึงไม่แสดงกล่องนี้
  };
  var PAYLOAD_LABEL = {
    input: ['testit.asInput', 'ใส่ค่านี้ในช่อง input หรือใน URL แล้วดูผล'],
    body: ['testit.asBody', 'ส่ง JSON นี้เป็น request body'],
    file: ['testit.asFile', 'ลองอัปโหลดไฟล์ที่ชื่อแบบนี้'],
    header: ['testit.asHeader', 'ส่ง header นี้ไปกับ request'],
    shell: ['testit.asShell', 'รันคำสั่งนี้ใน terminal'],
    console: ['testit.asConsole', 'พิมพ์บรรทัดนี้ใน DevTools Console'],
    html: ['testit.asHtml', 'เอา HTML นี้ไปวางไว้บนอีกเว็บหนึ่ง แล้วเปิดขณะยังล็อกอินอยู่']
  };

  function testitHTML(ex) {
    var ti = ex.testIt;
    var kind = PAYLOAD_KIND[ex.id];
    var pay = (kind && ex.sim && ex.sim.payloads && ex.sim.payloads[0]) ? ex.sim.payloads[0] : null;
    if (!ti && !pay) return '';
    var h = section(t('sec.testIt', 'ทดสอบเองได้อย่างไร'), '$');
    h += '<div class="testit">';

    if (pay && pay.value) {
      var lab = PAYLOAD_LABEL[kind] || PAYLOAD_LABEL.input;
      h += '<div class="testit-quick">';
      h += '<div class="testit-quick-k">' + esc(t(lab[0], lab[1])) + '</div>';
      h += '<div class="testit-payload"><code>' + esc(pay.value) + '</code>';
      h += '<button class="btn btn-ghost btn-small" type="button" data-copy="payload">' +
        esc(t('btn.copy', 'คัดลอก')) + '</button></div>';
      if (pay.label) h += '<div class="testit-payload-note">' + esc(L(pay.label)) + '</div>';
      h += '</div>';
    }

    // บางข้อ payload กับคำสั่ง terminal เป็นอันเดียวกัน — แสดงครั้งเดียวพอ
    var sameAsPayload = !!(pay && ti && ti.cmd &&
      String(ti.cmd).replace(/\s+/g, ' ').trim() ===
      String(pay.value).replace(/\s+/g, ' ').trim());
    if (ti && ti.cmd && !sameAsPayload) {
      h += '<div class="testit-cli-k">' +
        esc(pay ? t('testit.cli', 'หรือยิงจาก terminal')
                : t('testit.cliOnly', 'ทดสอบด้วยคำสั่งนี้')) + '</div>';
      h += '<div class="testit-cmd"><pre>' + esc(ti.cmd) +
        '</pre><button class="btn btn-ghost btn-small" type="button" data-copy="testit">' +
        esc(t('btn.copy', 'คัดลอก')) + '</button></div>';
    }
    if (ti && ti.note) h += '<div class="testit-note">' + esc(L(ti.note)) + '</div>';
    h += '</div></div>';
    return h;
  }
  function caseStudyHTML(ex) {
    var cs = ex.caseStudy;
    if (!cs) return '';
    var h = section(t('sec.caseStudy', 'เคสจริงที่เคยเกิดขึ้น'), '§');
    h += '<div class="case-study">';
    if (cs.year !== null && cs.year !== undefined) h += '<span class="case-year">' + esc(String(cs.year)) + '</span>';
    h += '<div class="case-title">' + esc(L(cs.title)) + '</div>';
    h += '<div class="case-body">' + esc(L(cs.body)) + '</div>';
    if (cs.source && cs.source.url) {
      h += '<div class="case-src"><a href="' + esc(safeUrl(cs.source.url)) +
        '" target="_blank" rel="noopener noreferrer">' + esc(cs.source.label || cs.source.url) + ' ↗</a></div>';
    }
    h += '</div></div>';
    return h;
  }
  function refsHTML(ex) {
    var arr = Array.isArray(ex.references) ? ex.references : [];
    if (arr.length === 0) return '';
    var h = section(t('sec.refs', 'อ่านเพิ่มเติม'), '↗');
    h += '<ul class="refs">';
    for (var i = 0; i < arr.length; i++) {
      var r = arr[i] || {};
      h += '<li><span class="ref-ico" aria-hidden="true">↗</span><a href="' + esc(safeUrl(r.url)) +
        '" target="_blank" rel="noopener noreferrer">' + esc(r.label || r.url || '') + '</a></li>';
    }
    h += '</ul></div>';
    return h;
  }

  /* -------------------------------------------------------- attack lab */

  /* ---------------------------------------------------- ไดอะแกรมเคลื่อนไหว */
  function destroyDiagram() {
    if (diagramCtl && typeof diagramCtl.destroy === 'function') {
      try { diagramCtl.destroy(); } catch (e) {}
    }
    diagramCtl = null;
  }

  function mountDiagram(host, ex) {
    if (!host) return;
    var D = global.Diagram;
    var kind = ex.sim ? ex.sim.kind : null;
    // ไม่มีโมดูล หรือไม่มีฉากสำหรับโจทย์นี้ => ไม่ต้องแสดง panel เลย
    if (!D || !kind || typeof D.has !== 'function' || !D.has(kind)) { clear(host); return; }

    clear(host);
    var sec = document.createElement('section');
    sec.className = 'diagram-panel';

    var h2 = document.createElement('h2');
    h2.className = 'sec-title';
    h2.appendChild(document.createTextNode(t('sec.diagram', 'ภาพจำลองการทำงาน')));
    sec.appendChild(h2);

    var lead = document.createElement('p');
    lead.className = 'sec-lead';
    lead.appendChild(document.createTextNode(t('sec.diagramLead',
      'สลับดูได้ว่า "โจมตี" กับ "ป้องกัน" ต่างกันตรงไหน — เป็นระบบเดียวกัน คนละพฤติกรรม')));
    sec.appendChild(lead);

    var box = document.createElement('div');
    box.className = 'diagram-box';
    sec.appendChild(box);
    host.appendChild(sec);

    try {
      diagramCtl = D.render(box, kind, {
        config: ex.sim.config || {},
        scene: 'vuln',
        autoplay: true
      });
    } catch (e) { diagramCtl = null; }
    // render คืน null ได้ (เช่นฉากพัง) — ถ้าเป็นแบบนั้นให้เก็บ panel ทิ้งไปเงียบ ๆ
    if (!diagramCtl) clear(host);
  }

  function renderLab(host, ex) {
    if (!host) return;
    clear(host);
    var lab = elem('div', 'lab');

    var head = elem('div', 'lab-head');
    var h2 = document.createElement('h2');
    h2.appendChild(document.createTextNode(t('sec.lab', 'Attack Lab — ลองยิงจริง') + ' '));
    h2.appendChild(elem('span', 'lab-badge', 'LAB'));
    head.appendChild(h2);
    head.appendChild(elem('p', 'lab-lead',
      t('sec.labLead', 'เลือก payload แล้วดูว่าโค้ดที่มีช่องโหว่กับโค้ดที่แก้แล้วตอบต่างกันอย่างไร')));
    lab.appendChild(head);

    var sim = ex.sim;
    var Sim = global.Simulator;
    var available = !!(sim && sim.kind && Sim && typeof Sim.run === 'function' &&
      (typeof Sim.has !== 'function' || Sim.has(sim.kind)));
    if (!available) {
      lab.appendChild(elem('div', 'empty', t('lab.unavailable', 'ไม่มีการจำลองสำหรับโจทย์นี้')));
      host.appendChild(lab);
      return;
    }

    var payloads = Array.isArray(sim.payloads) ? sim.payloads : [];
    var currentRef = { value: payloads.length ? payloads[0].value : '' };
    var btns = [];
    var panes = elem('div', 'lab-panes');

    var pl = elem('div', 'lab-payloads');
    for (var i = 0; i < payloads.length; i++) {
      (function (p, first) {
        var b = elem('button', 'payload-btn' + (first ? ' on' : ''), L(p.label));
        b.type = 'button';
        b.setAttribute('data-value', String(p.value));
        b.addEventListener('click', function () {
          setActive(btns, b);
          currentRef.value = p.value;
          runSim(panes, sim, currentRef.value);
        });
        btns.push(b);
        pl.appendChild(b);
      })(payloads[i], i === 0);
    }
    lab.appendChild(pl);

    if (sim.allowCustom) {
      var custom = elem('div', 'lab-custom');
      var input = document.createElement('input');
      input.className = 'payload-input';
      input.type = 'text';
      input.placeholder = t('lab.custom', 'ลอง payload ของคุณเอง');
      input.setAttribute('aria-label', t('lab.custom', 'ลอง payload ของคุณเอง'));
      var runBtn = elem('button', 'btn btn-primary btn-small', t('btn.run', 'จำลองการโจมตี'));
      runBtn.type = 'button';
      runBtn.addEventListener('click', function () {
        currentRef.value = input.value;
        setActive(btns, null);
        runSim(panes, sim, currentRef.value);
      });
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); runBtn.click(); }
      });
      custom.appendChild(input);
      custom.appendChild(runBtn);
      lab.appendChild(custom);
    }

    lab.appendChild(panes);
    host.appendChild(lab);
    runSim(panes, sim, currentRef.value);
  }

  function setActive(btns, active) {
    for (var i = 0; i < btns.length; i++) btns[i].classList.remove('on');
    if (active) active.classList.add('on');
  }

  function runSim(panes, sim, payload) {
    var Sim = global.Simulator;
    clear(panes);
    var result = null;
    try { result = Sim.run(sim, payload); } catch (e) { result = null; }
    if (!result || typeof result !== 'object') {
      panes.appendChild(elem('div', 'empty', t('lab.unavailable', 'ไม่มีการจำลองสำหรับโจทย์นี้')));
      return;
    }
    panes.appendChild(renderPane('vuln', result.vulnerable, t('lab.vulnerable', 'โค้ดที่มีช่องโหว่')));
    panes.appendChild(renderPane('safe', result.secure, t('lab.secure', 'โค้ดที่แก้แล้ว')));
  }

  function renderPane(kind, pane, fallbackTitle) {
    pane = pane || {};
    var wrap = elem('div', 'lab-pane ' + kind);
    var title = elem('div', 'lab-pane-title');
    title.appendChild(elem('span', null, kind === 'vuln' ? '⚠' : '✓'));
    title.appendChild(document.createTextNode(' ' + (pane.title ? L(pane.title) : fallbackTitle)));
    wrap.appendChild(title);
    var body = elem('div', 'lab-pane-body');
    var steps = Array.isArray(pane.steps) ? pane.steps : [];
    for (var i = 0; i < steps.length; i++) body.appendChild(renderStep(steps[i]));
    var v = pane.verdict || {};
    var vd = elem('div', 'lab-verdict ' + (v.ok ? 'ok' : 'no'));
    vd.appendChild(elem('span', 'lab-verdict-ico', v.ok ? '✓' : '✗'));
    vd.appendChild(document.createTextNode(' ' + L(v.text)));
    body.appendChild(vd);
    wrap.appendChild(body);
    return wrap;
  }

  function renderStep(step) {
    step = step || {};
    var wrap = elem('div', 'lab-step tone-' + (step.tone || 'neutral'));
    wrap.appendChild(elem('div', 'lab-step-label', L(step.label)));
    var body = elem('div', 'lab-step-body');
    body.innerHTML = markHtml(step.text, step.mark);
    wrap.appendChild(body);
    if (step.render !== null && step.render !== undefined) {
      var frame = document.createElement('iframe');
      frame.className = 'lab-frame';
      frame.setAttribute('sandbox', '');
      frame.setAttribute('title', t('lab.frameNote', 'แสดงผลในกรอบ sandbox (สคริปต์ถูกปิดไว้เพื่อความปลอดภัย)'));
      frame.setAttribute('srcdoc', String(step.render));
      wrap.appendChild(frame);
      var note = elem('div', 'lab-frame-note');
      note.appendChild(elem('span', null, '🔒'));
      note.appendChild(document.createTextNode(' ' + t('lab.frameNote', 'แสดงผลในกรอบ sandbox (สคริปต์ถูกปิดไว้เพื่อความปลอดภัย)')));
      wrap.appendChild(note);
    }
    return wrap;
  }

  /*
   * markHtml — Step.text is PLAIN text. Compute mark ranges on the raw string,
   * escape each slice, then join. Every slice (marked or not) is HTML-escaped,
   * so no injected markup can ever become a live node.
   */
  function markHtml(text, mark) {
    text = (text === null || text === undefined) ? '' : String(text);
    var ranges = normalizeRanges(text.length, mark);
    if (ranges.length === 0) return esc(text);
    var out = '';
    var pos = 0;
    for (var i = 0; i < ranges.length; i++) {
      var s = ranges[i][0], e = ranges[i][1];
      if (s > pos) out += esc(text.slice(pos, s));
      out += '<mark>' + esc(text.slice(s, e)) + '</mark>';
      pos = e;
    }
    if (pos < text.length) out += esc(text.slice(pos));
    return out;
  }
  function normalizeRanges(len, mark) {
    var out = [];
    if (!Array.isArray(mark)) return out;
    for (var i = 0; i < mark.length; i++) {
      var r = mark[i];
      if (!r || r.length < 2) continue;
      var a = Math.floor(Number(r[0])), b = Math.floor(Number(r[1]));
      if (!isFinite(a) || !isFinite(b)) continue;
      if (a < 0) a = 0;
      if (b > len) b = len;
      if (b <= a) continue;
      out.push([a, b]);
    }
    out.sort(function (x, y) { return x[0] - y[0]; });
    var merged = [];
    for (var j = 0; j < out.length; j++) {
      var last = merged[merged.length - 1];
      if (last && out[j][0] <= last[1]) { if (out[j][1] > last[1]) last[1] = out[j][1]; }
      else merged.push([out[j][0], out[j][1]]);
    }
    return merged;
  }

  /* -------------------------------------------------------- checklist */

  var CHECKLIST = [
    {
      title: { th: 'Input, Injection & Output Encoding', en: 'Input, Injection & Output Encoding' },
      items: [
        { th: 'ใช้ parameterized query / prepared statement เสมอ — ห้ามต่อสตริง SQL กับค่าจากผู้ใช้ (แม้จะผ่าน String.format หรือ template literal)', en: 'Always use parameterized queries / prepared statements — never concatenate user input into SQL (not even via String.format or template literals).' },
        { th: 'Encode output ตาม context ที่จะแสดงผล (HTML text / attribute / JS / URL) เพื่อกัน XSS — ไม่ใช่แค่ "sanitize"', en: 'Apply context-aware output encoding (HTML text / attribute / JS / URL) to prevent XSS — not a vague "sanitize".' },
        { th: 'เรียกคำสั่งระบบด้วย argv array (execFile / ProcessBuilder) ไม่ใช่ shell string ที่ต่อ input เข้าไป', en: 'Invoke OS commands with an argv array (execFile / ProcessBuilder), never a shell string built from input.' },
        { th: 'ตรวจ path ที่อ้างอิงไฟล์ด้วยการ resolve แล้วเช็ค startsWith(baseDir) กัน path traversal', en: 'Resolve file paths and check startsWith(baseDir) to block path traversal.' },
        { th: 'ตรวจสอบ input ด้วย allowlist (ชนิด/รูปแบบ/ช่วงค่า) ไม่ใช่ denylist ที่ผู้โจมตีเลี่ยงได้', en: 'Validate input with an allowlist of type/format/range, not a bypassable denylist.' }
      ]
    },
    {
      title: { th: 'Secrets, Config, Errors & Headers', en: 'Secrets, Config, Errors & Headers' },
      items: [
        { th: 'ไม่ hardcode ความลับในโค้ด — ใช้ environment variable หรือ secrets manager และหมุนเวียน key ที่เคยหลุดทันที', en: 'No hardcoded secrets — use environment variables or a secrets manager, and rotate any leaked key immediately.' },
        { th: 'เพิ่มไฟล์ .env / config ที่มีความลับลงใน .gitignore ตั้งแต่ก่อน commit แรก', en: 'Add .env / secret config files to .gitignore before the first commit.' },
        { th: 'ปิด verbose error / stack trace ใน production — ตอบเฉพาะ correlation id ให้ผู้ใช้', en: 'Disable verbose errors / stack traces in production — return only a correlation id to users.' },
        { th: 'ตั้ง CORS เป็น allowlist ของ origin ที่เชื่อถือได้ ห้ามสะท้อน Origin กลับพร้อม credentials', en: 'Configure CORS as an allowlist of trusted origins; never reflect Origin together with credentials.' },
        { th: 'ตั้ง security headers (HSTS, X-Content-Type-Options, CSP, frame-ancestors) ให้ครบ', en: 'Set the security headers (HSTS, X-Content-Type-Options, CSP, frame-ancestors).' }
      ]
    },
    {
      title: { th: 'Authentication & Access Control', en: 'Authentication & Access Control' },
      items: [
        { th: 'เก็บรหัสผ่านด้วย bcrypt / argon2 / scrypt พร้อม salt — ห้าม MD5/SHA ตรง ๆ', en: 'Store passwords with bcrypt / argon2 / scrypt and a salt — never plain MD5/SHA.' },
        { th: 'ตรวจสิทธิ์ระดับ object ทุกครั้งที่เข้าถึงทรัพยากรตาม id (กัน IDOR) — แค่ล็อกอินแล้วไม่พอ', en: 'Enforce object-level authorization on every id-based access (prevent IDOR) — being logged in is not enough.' },
        { th: 'Verify ลายเซ็น JWT ทุกครั้งและล็อก algorithm ที่อนุญาต — ห้ามใช้ decode() แทน verify()', en: 'Always verify the JWT signature and pin the allowed algorithm — never use decode() in place of verify().' },
        { th: 'ตั้ง session cookie เป็น HttpOnly; Secure; SameSite เสมอ', en: 'Set session cookies with HttpOnly; Secure; SameSite.' },
        { th: 'ผูก request body ผ่าน DTO allowlist ไม่ผูกตรงลง entity (กัน mass assignment เช่น role/isAdmin)', en: 'Bind request bodies through an allowlist DTO, not straight onto the entity (prevent mass assignment of role/isAdmin).' },
        { th: 'ยึดหลัก least privilege และ deny by default', en: 'Apply least privilege and deny by default.' }
      ]
    },
    {
      title: { th: 'Files, Dependencies & SSRF', en: 'Files, Dependencies & SSRF' },
      items: [
        { th: 'ตรวจชนิด/ขนาดไฟล์อัปโหลดด้วย allowlist, ตั้งชื่อใหม่แบบสุ่ม, เก็บนอก web root และห้ามให้รันเป็นสคริปต์', en: 'Validate upload type/size with an allowlist, rename randomly, store outside the web root, and never let uploads execute.' },
        { th: 'ปักหมุดเวอร์ชัน dependency และสแกนช่องโหว่อัตโนมัติ (npm audit / OWASP Dependency-Check / Snyk)', en: 'Pin dependency versions and scan for vulnerabilities automatically (npm audit / OWASP Dependency-Check / Snyk).' },
        { th: 'กัน SSRF ด้วย allowlist ปลายทาง + เช็ค scheme + ปฏิเสธ IP loopback/link-local/RFC1918 และไม่ตาม redirect ไปภายใน', en: 'Prevent SSRF with a destination allowlist, scheme checks, rejection of loopback/link-local/RFC1918, and no following redirects to internal hosts.' },
        { th: 'อย่า deserialize ข้อมูลที่ไม่น่าเชื่อถือเป็น object โดยตรง — ใช้ JSON.parse + schema ให้ได้ข้อมูลเฉื่อย', en: 'Never deserialize untrusted data straight into objects — use JSON.parse plus a schema to produce inert data.' }
      ]
    },
    {
      title: { th: 'Cryptography, TLS & Logging', en: 'Cryptography, TLS & Logging' },
      items: [
        { th: 'สร้าง token/secret ด้วย CSPRNG (SecureRandom / crypto.randomBytes) ไม่ใช่ Math.random / java.util.Random', en: 'Generate tokens/secrets with a CSPRNG (SecureRandom / crypto.randomBytes), never Math.random / java.util.Random.' },
        { th: 'เข้ารหัสด้วย AEAD เช่น AES-GCM พร้อม IV สุ่มทุกครั้ง — ห้าม AES-ECB ที่รั่วโครงสร้าง plaintext', en: 'Encrypt with an AEAD mode such as AES-GCM using a fresh random IV — never AES-ECB, which leaks plaintext structure.' },
        { th: 'ตรวจสอบใบรับรอง TLS จริง — ห้ามใช้ trust-all / disable hostname verification', en: 'Validate TLS certificates properly — never trust-all or disable hostname verification.' },
        { th: 'ห้าม log ความลับ (password, PAN, token, JWT) — redact ก่อนเขียน log ทุกครั้ง', en: 'Never log secrets (passwords, PANs, tokens, JWTs) — redact before writing any log line.' }
      ]
    },
    {
      title: { th: 'Sessions, CSRF, Redirects & Rate Limiting', en: 'Sessions, CSRF, Redirects & Rate Limiting' },
      items: [
        { th: 'กัน CSRF ด้วย anti-CSRF token และ SameSite cookie สำหรับทุก request ที่เปลี่ยน state', en: 'Protect state-changing requests with anti-CSRF tokens and SameSite cookies.' },
        { th: 'จำกัดอัตราการ login และล็อก/หน่วงแบบ exponential backoff กัน brute force', en: 'Rate-limit logins and apply lockout / exponential backoff against brute force.' },
        { th: 'ตรวจ redirect ปลายทางด้วย allowlist หรืออนุญาตเฉพาะ path สัมพัทธ์ กัน open redirect (รวม //evil และ /\\evil)', en: 'Validate redirect targets with an allowlist or allow relative paths only (block //evil and /\\evil) to stop open redirects.' },
        { th: 'ออก session id ใหม่หลัง login และตั้งอายุ/หมดเวลาให้เหมาะสม', en: 'Rotate the session id after login and set sensible expiry/idle timeouts.' },
        { th: 'รัน SAST/SCA ใน CI และบล็อก merge เมื่อพบช่องโหว่ระดับสูง', en: 'Run SAST/SCA in CI and block merges on high-severity findings.' }
      ]
    }
  ];

  /* ---------------------------------------------------------- intro
     หน้าเปิดสำหรับผู้เรียนที่เพิ่งเข้ามา: จะได้อะไรจาก session นี้,
     OWASP Top 10 กับ CWE คืออะไร และทำไมต้องสนใจเรื่องนี้ตั้งแต่ตอนเขียนโค้ด */
  var INTRO = {
    objective: {
      k: { th: 'Session Objective', en: 'Session Objective' },
      items: [
        { th: 'Developer ของ Generali ได้เรียนรู้วิธีเขียนโค้ดที่ปลอดภัยตามมาตรฐานสากล',
          en: 'Generali developers learn to write secure code against an international standard' },
        { th: 'ฝึกกับช่องโหว่จริง 16 ข้อ ครอบคลุมทั้ง Java และ Node.js',
          en: 'Practise on 16 real vulnerabilities, covering both Java and Node.js' },
        { th: 'ทีมมีมาตรฐานร่วมกันในการรีวิวโค้ดด้านความปลอดภัย',
          en: 'The team gains a shared standard for reviewing code with security in mind' },
        { th: 'ลดช่องโหว่ที่หลุดไปถึง production และลดงานแก้ย้อนหลังจากผล pentest',
          en: 'Fewer vulnerabilities reaching production, and less rework after pentests' }
      ]
    },
    owasp: {
      k: { th: 'OWASP Top 10 คืออะไร', en: 'What is the OWASP Top 10?' },
      items: [
        { th: 'รายการความเสี่ยงด้านความปลอดภัยของเว็บที่พบบ่อยและอันตรายที่สุด 10 อันดับ',
          en: 'A ranked list of the ten most common and most damaging web security risks' },
        { th: 'จัดทำโดย OWASP ซึ่งเป็นมูลนิธิไม่แสวงหากำไร ฉบับที่ใช้อ้างอิงคือปี 2021',
          en: 'Published by the OWASP Foundation; this workshop follows the 2021 edition' },
        { th: 'ใช้เป็นภาษากลางเวลาคุยเรื่องความเสี่ยง เช่น A03 หมายถึง Injection',
          en: 'A shared vocabulary for talking about risk — A03 means Injection, for example' }
      ]
    },
    cwe: {
      k: { th: 'CWE คืออะไร', en: 'What is CWE?' },
      items: [
        { th: 'CWE = Common Weakness Enumeration บัญชีจุดอ่อนของซอฟต์แวร์ ดูแลโดย MITRE',
          en: 'CWE = Common Weakness Enumeration, a catalogue of software weaknesses run by MITRE' },
        { th: 'ระบุจุดอ่อนแบบเจาะจง เช่น CWE-89 คือ SQL Injection, CWE-79 คือ XSS',
          en: 'It names the exact weakness: CWE-89 is SQL Injection, CWE-79 is XSS' },
        { th: 'รายงาน pentest และเครื่องมือสแกนส่วนใหญ่อ้างเลข CWE จึงควรอ่านออก',
          en: 'Pentest reports and scanners cite CWE numbers, so it pays to read them' }
      ]
    }
  };

  function renderIntro(main) {
    var html = '';
    html += '<div class="ex-header">';
    html += '<div class="ex-crumb">' + esc(t('app.title', 'Secure Coding Workshop')) + '</div>';
    html += '<div class="ex-title-row"><h1 class="ex-title">' +
      esc(t('intro.title', 'เริ่มต้นที่นี่')) + '</h1></div>';
    html += '<div class="intro-lead">' + esc(t('dash.lead', '')) + '</div>';
    html += '</div>';

    html += '<div class="intro-grid">';
    ['objective', 'owasp', 'cwe'].forEach(function (key) {
      var b = INTRO[key];
      html += '<section class="intro-card intro-' + key + '">';
      html += '<h2>' + esc(L(b.k)) + '</h2><ul>';
      for (var i = 0; i < b.items.length; i++) html += '<li>' + esc(L(b.items[i])) + '</li>';
      html += '</ul></section>';
    });
    html += '</div>';

    html += '<div class="intro-cta">';
    html += '<button id="intro-start" class="btn btn-primary" type="button">' +
      esc(t('intro.start', 'เริ่มโจทย์แรก')) + '</button>';
    html += '<button id="intro-dash" class="btn btn-ghost" type="button">' +
      esc(t('nav.dashboard', 'ภาพรวม')) + '</button>';
    html += '</div>';

    main.innerHTML = html;
    var st = document.getElementById('intro-start');
    if (st) st.addEventListener('click', function () {
      // ไปต่อจากข้อที่ยังไม่ผ่าน ถ้ายังไม่เริ่มเลยก็เริ่มข้อแรก
      var next = null, i;
      for (i = 0; i < flat.length; i++) {
        if (!state.completed[flat[i].ex.id]) { next = flat[i].ex.id; break; }
      }
      if (!next && flat.length) next = flat[0].ex.id;
      if (next) go('exercise', next);
    });
    var db = document.getElementById('intro-dash');
    if (db) db.addEventListener('click', function () { go('dashboard'); });
  }

  function renderChecklist(main) {
    var html = '';
    html += '<div class="ex-header"><div class="ex-crumb">' + esc(t('nav.checklist', 'Secure Coding Checklist')) + '</div>';
    html += '<div class="ex-title-row"><h1 class="ex-title">' + esc(t('checklist.title', 'Secure Coding Checklist')) + '</h1></div>';
    html += '<div class="ex-meta"><span class="meta-chip">' + esc(t('checklist.sub', 'รายการตรวจสอบสำหรับใช้ในงานประจำวัน')) + '</span></div></div>';
    html += '<div class="cl-actions">';
    html += '<button id="cl-copy" class="btn btn-ghost" type="button">' + esc(t('btn.copy', 'คัดลอก')) + '</button>';
    html += '<button id="cl-print" class="btn btn-ghost" type="button">' + esc(t('btn.print', 'พิมพ์ / บันทึกเป็น PDF')) + '</button>';
    html += '</div>';
    html += '<div class="checklist">';
    for (var i = 0; i < CHECKLIST.length; i++) {
      var g = CHECKLIST[i];
      html += '<div class="cl-group"><div class="cl-title"><span class="sec-ico" aria-hidden="true">☑</span>' +
        esc(L(g.title)) + '</div><ul>';
      for (var j = 0; j < g.items.length; j++) html += '<li>' + esc(L(g.items[j])) + '</li>';
      html += '</ul></div>';
    }
    html += '</div>';
    html += '<div class="cl-note">' + esc(t('checklist.note',
      'อ้างอิงหลักการจาก OWASP Top 10 และ OWASP Cheat Sheet Series — ปรับให้เข้ากับบริบทของทีมคุณ')) + '</div>';
    main.innerHTML = html;

    var cp = document.getElementById('cl-copy');
    if (cp) cp.addEventListener('click', function () { copyText(checklistText()); });
    var pr = document.getElementById('cl-print');
    if (pr) pr.addEventListener('click', doPrint);
  }
  function checklistText() {
    var lines = [];
    for (var i = 0; i < CHECKLIST.length; i++) {
      lines.push('## ' + L(CHECKLIST[i].title));
      for (var j = 0; j < CHECKLIST[i].items.length; j++) lines.push('- [ ] ' + L(CHECKLIST[i].items[j]));
      lines.push('');
    }
    return lines.join('\n');
  }
  function doPrint() { try { if (typeof global.print === 'function') global.print(); } catch (e) {} }

  /* -------------------------------------------------------- init */

  function init() {
    if (!hasDoc()) return;
    var hadV2 = loadState();
    buildFlat();
    var i = global.I18N;
    if (i) {
      if (hadV2 && typeof i.setLang === 'function' && state.lang !== i.lang) i.setLang(state.lang);
      else if (i.lang) state.lang = i.lang;
    }
    applyTheme();
    wireGlobalOnce();
    applyLangUI();
    if (state.route.view === 'exercise' && (!state.route.id || !findFlat(state.route.id))) {
      if (flat.length) state.route = { view: 'exercise', id: flat[0].ex.id };
      else state.route = { view: 'dashboard', id: null };
    }
    renderAll();
  }

  global.App = { init: init, navigate: navigate };
  if (typeof module !== 'undefined' && module.exports) module.exports = global.App;

  if (hasDoc()) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
  }

})(typeof window !== 'undefined' ? window : globalThis);
