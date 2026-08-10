/* ============================================================================
 * test/smoke.js — jsdom boot suite
 *
 * Loads index.html headlessly, executes every <script src> from disk in
 * document order (jsdom never fetches anything), calls App.init(), then
 * drives the app through the DOM ( class names):
 *   - sidebar lists all 23 exercises
 *   - every exercise renders: editor + check button
 *   - starter fails / solution passes, for 3 exercises x { java, node }
 *   - language switch th -> en -> th re-renders and changes titles
 *   - dashboard / checklist views render
 *
 * ENVIRONMENT NOTE: the jsdom in node_modules requires Node >= 22. Under an
 * older interpreter this suite prints a loud SKIP notice and exits 0 so that
 * `npm test` on Node 18 means "verify passed, smoke skipped" — run it for
 * real with:  ~/.nvm/versions/node/v22.17.1/bin/node test/smoke.js
 * ==========================================================================*/
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');

/* ----------------------------- colours ---------------------------------- */

const useColor = !!process.stdout.isTTY && !process.env.NO_COLOR;
function paint(code, s) { return useColor ? '\x1b[' + code + 'm' + s + '\x1b[0m' : s; }
function red(s) { return paint('31', s); }
function green(s) { return paint('32', s); }
function yellow(s) { return paint('33', s); }
function bold(s) { return paint('1', s); }
function dim(s) { return paint('2', s); }

/* ------------------------- assertion harness ----------------------------- */

let total = 0;
let failedTotal = 0;
let current = null;

function group(name) {
  flushGroup();
  current = { name: name, count: 0, failures: [] };
}

function ok(cond, msg) {
  total++;
  if (current) current.count++;
  if (!cond) {
    failedTotal++;
    if (current) current.failures.push(msg);
    else console.log(red('  FAIL ') + msg);
  }
  return !!cond;
}

function flushGroup() {
  if (!current) return;
  const g = current;
  current = null;
  if (g.failures.length === 0) {
    console.log(' ' + green('✓') + ' ' + g.name + dim(' (' + g.count + ')'));
  } else {
    console.log(' ' + red('✗') + ' ' + bold(g.name) +
      dim(' (' + (g.count - g.failures.length) + '/' + g.count + ' passed)'));
    g.failures.forEach(function (f) { console.log(red('      - ') + f); });
  }
}

function firstLine(s) { return String(s).split('\n')[0]; }

/* --------------------- jsdom availability (SKIP path) -------------------- */

let JSDOM = null;
let VirtualConsole = null;
try {
  const jsdomModule = require('jsdom');
  JSDOM = jsdomModule.JSDOM;
  VirtualConsole = jsdomModule.VirtualConsole;
} catch (e) {
  const bar = '='.repeat(72);
  console.log('\n' + yellow(bold(bar)));
  console.log(yellow(bold('  SMOKE SUITE SKIPPED — THIS IS NOT A PASS')));
  console.log(yellow(bar));
  console.log(yellow("  require('jsdom') failed under Node " + process.version + ':'));
  console.log(yellow(' ' + firstLine(e.message)));
  console.log(yellow('  The jsdom installed in node_modules needs Node >= 22.'));
  console.log(yellow('  Run the smoke suite for real with:'));
  console.log(yellow(bold('    ~/.nvm/versions/node/v22.17.1/bin/node test/smoke.js')));
  console.log(yellow(bold(bar)) + '\n');
  process.exit(0); // deliberate: environment limitation, not a defect
}

/* ------------------------------- boot ------------------------------------ */

const htmlPath = path.join(ROOT, 'index.html');
if (!fs.existsSync(htmlPath)) {
  console.log(red(bold('\nFATAL: index.html not found at ' + htmlPath + '\n')));
  process.exit(1);
}
const rawHtml = fs.readFileSync(htmlPath, 'utf8');

// Collect <script> tags in document order (src or inline body). We neutralise
// every script in the HTML handed to jsdom (type="text/plain" — a duplicate
// type attribute is ignored, ours comes first and wins) and execute them
// ourselves from disk, so jsdom never fetches and order is fully ours.
const scriptTags = [];
{
  const tagRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = tagRe.exec(rawHtml)) !== null) {
    const attrs = m[1] || '';
    const srcM = /\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
    const src = srcM ? (srcM[1] || srcM[2] || srcM[3] || '') : null;
    scriptTags.push({ src: src, inline: src ? null : m[2] });
  }
}
const neutralHtml = rawHtml.replace(/<script\b/gi, '<script type="text/plain"');

const pageErrors = []; // every uncaught error / jsdomError / rejection
const virtualConsole = new VirtualConsole();
virtualConsole.on('jsdomError', function (e) {
  pageErrors.push('jsdomError: ' + firstLine(e && e.message ? e.message : e));
});

const dom = new JSDOM(neutralHtml, {
  url: 'http://localhost:8080/',
  runScripts: 'dangerously',
  pretendToBeVisual: true,
  virtualConsole: virtualConsole
  // note: no `resources` option — jsdom must not fetch anything itself
});
const window = dom.window;
const document = window.document;
window.addEventListener('error', function (ev) {
  pageErrors.push('window.onerror: ' + firstLine(ev && (ev.message || ev.error)));
});
window.addEventListener('unhandledrejection', function (ev) {
  pageErrors.push('unhandledrejection: ' + firstLine(ev && ev.reason));
});

console.log(bold('\nSecure Coding Workshop — smoke suite (jsdom)'));
console.log(dim('root: ' + ROOT + '  node: ' + process.version));

group('boot: scripts execute in document order');
{
  const ctx = dom.getInternalVMContext();
  ok(scriptTags.length > 0, 'index.html declares at least one <script> tag');
  scriptTags.forEach(function (tag, i) {
    let label, code;
    if (tag.src) {
      if (/^[a-z]+:\/\//i.test(tag.src)) {
        ok(false, 'index.html references an EXTERNAL script (' + tag.src +
          ') — violates the zero-dependency constraint');
        return;
      }
      label = tag.src;
      const file = path.join(ROOT, tag.src.split('?')[0].split('#')[0]);
      if (!ok(fs.existsSync(file), 'index.html references missing file: ' + tag.src +
        '')) return;
      code = fs.readFileSync(file, 'utf8');
    } else {
      label = 'index.html#inline-' + i;
      code = tag.inline || '';
      if (code.trim() === '') { ok(true, ''); return; }
    }
    try {
      new vm.Script(code, { filename: label }).runInContext(ctx);
      ok(true, '');
    } catch (e) {
      ok(false, label + ' threw while loading: ' + firstLine(e.message));
    }
  });
}

group('boot: App.init()');
{
  const App = window.App;
  ok(!!App && typeof App.init === 'function', 'window.App.init must exist');
  if (App && typeof App.init === 'function') {
    let threw = null;
    try { App.init(); } catch (e) { threw = e; }
    ok(threw === null, 'App.init() threw: ' + (threw && firstLine(threw.message)));
  }
  ok(!!window.SCW && typeof window.SCW.flatten === 'function',
    'window.SCW registry must be present after boot');
}

/* ------------------------------ DOM helpers ------------------------------ */

function q(sel) { return document.querySelector(sel); }
function qa(sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); }
function textOf(el) { return el && el.textContent ? el.textContent.replace(/\s+/g, ' ').trim() : ''; }
function tick(ms) { return new Promise(function (r) { setTimeout(r, ms || 15); }); }

function L(x) {
  if (window.I18N && typeof window.I18N.L === 'function') return window.I18N.L(x);
  if (x && typeof x === 'object') return x.th || x.en || '';
  return String(x == null ? '' : x);
}

/** Run fn and return the page errors it produced (delta capture). */
async function captured(fn) {
  const before = pageErrors.length;
  try { await fn(); } catch (e) { pageErrors.push('test-driver: ' + firstLine(e.message)); }
  await tick();
  return pageErrors.slice(before);
}

function findCheckButton() {
  let btn = q('.toolbar .btn-primary');
  if (btn) return btn;
  const cands = qa('.toolbar button, .toolbar .btn, .work-bar button');
  for (let i = 0; i < cands.length; i++) {
    if (/ตรวจ|check/i.test(textOf(cands[i]))) return cands[i];
  }
  return q('.btn-primary');
}

function findEditorArea() {
  return q('.editor-area') || q('.editor textarea') || q('.main textarea');
}

function navItems() { return qa('.nav-item'); }

function findNavItemFor(ex) {
  const items = navItems();
  for (let i = 0; i < items.length; i++) {
    const t = textOf(items[i]);
    if ((ex.title.th && t.indexOf(ex.title.th) !== -1) ||
        (ex.title.en && t.indexOf(ex.title.en) !== -1) ||
        t.indexOf(L(ex.title)) !== -1) {
      return items[i];
    }
  }
  return null;
}

async function gotoExerciseByIndex(i, ex) {
  // sidebar may be re-rendered between navigations — always re-query
  let item = ex ? findNavItemFor(ex) : null;
  if (!item) item = navItems()[i] || null;
  if (!item) return { ok: false, errs: ['no .nav-item found for index ' + i] };
  const errs = await captured(function () { item.click(); });
  return { ok: errs.length === 0, errs: errs };
}

function setEditorValue(code) {
  const ta = findEditorArea();
  if (!ta) return false;
  ta.value = code;
  ta.dispatchEvent(new window.Event('input', { bubbles: true }));
  return true;
}

function bannerState() {
  const banner = q('.result-banner');
  if (!banner) return 'none';
  if (banner.classList.contains('pass')) return 'pass';
  if (banner.classList.contains('fail')) return 'fail';
  return 'unknown';
}

async function switchStack(stack) {
  // 1) documented-ish data hooks, 2) button text in .lang-switch
  let btn = q('.lang-switch [data-stack="' + stack + '"]') ||
            q('.lang-switch [data-lang="' + stack + '"]');
  if (!btn) {
    const cands = qa('.lang-switch .lang-btn, .lang-switch button');
    for (let i = 0; i < cands.length; i++) {
      const t = textOf(cands[i]);
      if (stack === 'java' && /java/i.test(t) && !/script/i.test(t)) { btn = cands[i]; break; }
      if (stack === 'node' && /node/i.test(t)) { btn = cands[i]; break; }
    }
  }
  if (!btn) return { ok: false, errs: ['no ' + stack + ' button found in .lang-switch'] };
  const errs = await captured(function () { btn.click(); });
  return { ok: errs.length === 0, errs: errs };
}

async function gotoView(name, markerSel) {
  if (q(markerSel)) return true;

  // (a) explicit data hooks
  const hook = q('[data-view="' + name + '"]') || q('[data-route="' + name + '"]');
  if (hook) { await captured(function () { hook.click(); }); if (q(markerSel)) return true; }

  // (b) buttons/links by (bilingual) label
  const labels = {
    dashboard: /dashboard|แดชบอร์ด|ภาพรวม|หน้าหลัก/i,
    checklist: /checklist|เช็คลิสต์|เช็กลิสต์|รายการตรวจ/i,
    certificate: /certificate|ใบรับรอง|เกียรติบัตร|ประกาศนียบัตร/i
  };
  const re = labels[name];
  const clickables = qa('button, a, .nav-view, .sidebar-foot *, .topbar-actions *');
  for (let i = 0; i < clickables.length && re; i++) {
    if (re.test(textOf(clickables[i]))) {
      await captured(function () { clickables[i].click(); });
      if (q(markerSel)) return true;
    }
  }

  // (c) App programmatic API, if exposed
  const App = window.App || {};
  const fns = ['navigate', 'show', 'go', 'setView', 'route'];
  for (let i = 0; i < fns.length; i++) {
    if (typeof App[fns[i]] !== 'function') continue;
    await captured(function () { App[fns[i]](name); });
    if (q(markerSel)) return true;
    await captured(function () { App[fns[i]]({ view: name }); });
    if (q(markerSel)) return true;
  }

  // (d) hash routing
  const hashes = ['#/' + name, '#' + name];
  for (let i = 0; i < hashes.length; i++) {
    await captured(function () {
      window.location.hash = hashes[i];
      window.dispatchEvent(new window.Event('hashchange'));
    });
    if (q(markerSel)) return true;
  }

  // (e) documented keyboard shortcut (dashboard only): g then d
  if (name === 'dashboard') {
    await captured(function () {
      ['g', 'd'].forEach(function (k) {
        document.dispatchEvent(new window.KeyboardEvent('keydown', { key: k, bubbles: true }));
      });
    });
    if (q(markerSel)) return true;
  }
  return false;
}

/* ------------------------------ the drive -------------------------------- */

async function main() {
  const flat = (window.SCW && typeof window.SCW.flatten === 'function')
    ? window.SCW.flatten() : [];

  group('sidebar lists all 23 exercises');
  {
    const n = navItems().length;
    ok(n === flat.length, 'sidebar must list every exercise: ' + n + ' items vs ' + flat.length + ' in the registry');
    ok(flat.length > 0, 'SCW.flatten() must return the exercise list, found ' + flat.length);
  }

  group('navigate to every exercise');
  {
    const count = Math.max(navItems().length, flat.length);
    for (let i = 0; i < count; i++) {
      const ex = flat[i] ? flat[i].ex : null;
      const name = ex ? ex.id : '#' + i;
      const nav = await gotoExerciseByIndex(i, ex);
      if (!ok(nav.ok, name + ': navigation threw — ' + nav.errs.join(' | '))) continue;
      ok(!!findEditorArea(), name + ': no editor (.editor-area) rendered');
      ok(!!findCheckButton(), name + ': no check button (.toolbar .btn-primary) rendered');
    }
  }

  // --- grade starter/solution for >=3 exercises across different workshops,
  //     in BOTH java and node ---
  if (flat.length >= 3) {
    // เลือกข้อแรกของ workshop ที่ต่างกัน 3 อัน — ไม่ผูกกับจำนวนข้อ
    // ตอนแรก hardcode index ไว้ พอลบโจทย์ออกทีเดียวก็ index ทะลุ array แล้วพัง
    const picks = [];
    const seenWs = {};
    for (let i = 0; i < flat.length && picks.length < 3; i++) {
      const wid = flat[i].workshop.id;
      if (!seenWs[wid]) { seenWs[wid] = true; picks.push(flat[i]); }
    }
    for (let p = 0; p < picks.length; p++) {
      const entry = picks[p];
      const ex = entry.ex;
      group('grade ' + entry.workshop.id + '/' + ex.id + ' (java & node)');

      const nav = await gotoExerciseByIndex(entry.index, ex);
      if (!ok(nav.ok, 'navigation threw — ' + nav.errs.join(' | '))) continue;

      const stacks = ['java', 'node'];
      for (let s = 0; s < stacks.length; s++) {
        const stack = stacks[s];
        const lb = ex.languages && ex.languages[stack];
        if (!ok(!!lb, stack + ': exercise has no ' + stack + ' language block')) continue;

        const sw = await switchStack(stack);
        ok(sw.ok, stack + ': stack switch failed — ' + sw.errs.join(' | '));

        // starter must FAIL
        ok(setEditorValue(lb.starter), stack + ': could not set starter into the editor');
        const btn1 = findCheckButton();
        if (!ok(!!btn1, stack + ': no check button')) continue;
        let errs = await captured(function () { btn1.click(); });
        ok(errs.length === 0, stack + ': checking starter threw — ' + errs.join(' | '));
        ok(bannerState() === 'fail',
          stack + ': starter should show .result-banner.fail (got "' + bannerState() + '")');

        // solution must PASS
        ok(setEditorValue(lb.solution), stack + ': could not set solution into the editor');
        const btn2 = findCheckButton();
        errs = await captured(function () { btn2.click(); });
        ok(errs.length === 0, stack + ': checking solution threw — ' + errs.join(' | '));
        ok(bannerState() === 'pass',
          stack + ': solution should show .result-banner.pass (got "' + bannerState() + '")');
      }
    }
  } else {
    group('grade starter/solution');
    ok(false, 'BLOCKED — roster is not 23 exercises, cannot pick 3 across workshops');
  }

  group('language switch th -> en -> th');
  {
    const hasI18N = !!(window.I18N && typeof window.I18N.setLang === 'function');
    ok(hasI18N, 'window.I18N.setLang must exist');
    if (hasI18N) {
      const sidebarBefore = textOf(q('.sidebar') || document.body);
      let errs = await captured(function () { window.I18N.setLang('en'); });
      ok(errs.length === 0, "setLang('en') threw — " + errs.join(' | '));
      const sidebarEn = textOf(q('.sidebar') || document.body);
      ok(sidebarEn !== sidebarBefore,
        "switching to 'en' must re-render and change the sidebar titles");
      errs = await captured(function () { window.I18N.setLang('th'); });
      ok(errs.length === 0, "setLang('th') threw — " + errs.join(' | '));
      const sidebarTh = textOf(q('.sidebar') || document.body);
      ok(sidebarTh !== sidebarEn, "switching back to 'th' must re-render again");
    }
  }

  group('dashboard / checklist views');
  {
    ok(await gotoView('dashboard', '.dash'),
      'dashboard view did not render (.dash not found after all navigation attempts)');
    ok(await gotoView('checklist', '.checklist'),
      'checklist view did not render (.checklist not found after all navigation attempts)');
    // The certificate view was removed from the product; assert it stays gone
    // rather than silently leaving a dead assertion behind.
    ok(!q('.cert, .cert-sheet, #cert-name'), 'certificate view must no longer render');
    ok(!q('.nav-view[data-view="certificate"]'), 'certificate nav entry must be gone');
  }

  // Regression guard: the editor's three layers must scroll together. This suite
  // used to never dispatch a scroll event, which let a call to an undefined
  // method sit in the scroll handler — every scroll threw and the highlight and
  // gutter layers stayed frozen while the textarea moved.
  group('editor layers scroll together');
  {
    const first = q('.nav-item[data-id]');
    if (first) first.click();
    const ta = q('.editor-area');
    const pre = q('.editor-highlight');
    const gut = q('.editor-gutter');
    ok(!!ta && !!pre && !!gut, 'editor renders gutter + highlight + textarea');
    if (ta && pre && gut) {
      ta.scrollTop = 420;
      ta.scrollLeft = 90;
      const errs = await captured(function () { ta.dispatchEvent(new window.Event('scroll')); });
      ok(errs.length === 0, 'scroll handler must not throw — ' + errs.join(' | '));
      await new Promise(function (r) { window.requestAnimationFrame(function () { r(); }); });
      ok(pre.scrollTop === 420,
        'highlight layer must follow vertical scroll (got ' + pre.scrollTop + ', want 420)');
      ok(pre.scrollLeft === 90,
        'highlight layer must follow horizontal scroll (got ' + pre.scrollLeft + ', want 90)');
      ok(gut.scrollTop === 420,
        'gutter must follow vertical scroll (got ' + gut.scrollTop + ', want 420)');
    }
  }

  group('no uncaught errors at any point');
  {
    ok(pageErrors.length === 0,
      pageErrors.length + ' uncaught page error(s): ' +
      pageErrors.slice(0, 5).join(' | ') + (pageErrors.length > 5 ? ' …' : ''));
  }
}

main().then(function () {
  finish();
}, function (e) {
  group('smoke driver crashed');
  ok(false, firstLine(e && e.stack ? e.stack : e));
  finish();
});

function finish() {
  flushGroup();
  try { window.close(); } catch (e) { /* app timers may already be gone */ }
  const passedTotal = total - failedTotal;
  console.log('\n' + bold(passedTotal + '/' + total + ' assertions passed.'));
  if (failedTotal > 0) {
    console.log(red(bold(failedTotal + ' assertion(s) FAILED.')) + '\n');
    process.exit(1);
  }
  console.log(green(bold('Smoke suite green — the app boots and drives cleanly under jsdom.')) + '\n');
  process.exit(0);
}
