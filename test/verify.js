/* ============================================================================
 * test/verify.js — data + grading invariant suite
 *
 * Run:  node test/verify.js     (or: npm run verify / npm test)
 *
 * Asserts, for every exercise (items 1–11 of):
 *   ids, severity/points table, CWE/OWASP formats, the recursive LStr walk,
 *   starter-fails / solution-passes per language, trap hygiene,
 *   simulator kinds + SimResult structure for every preset payload,
 *   and the SHA-256 / HMAC-SHA256 known vectors.
 * Plus the registry invariants and the Grader's own unit tests.
 *
 * While other modules are still being written, missing files are reported
 * as readable "blocked" failures — never a raw stack trace.
 * ==========================================================================*/
'use strict';

const fs = require('fs');
const path = require('path');

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
    g.failures.forEach(function (f) {
      console.log(red('      - ') + f);
    });
  }
}

function heading(text) {
  flushGroup();
  console.log('\n' + bold(text));
}

/* ------------------------------ helpers ---------------------------------- */

function isLStr(x) {
  return !!x && typeof x === 'object' && !Array.isArray(x) &&
    typeof x.th === 'string' && x.th.trim() !== '' &&
    typeof x.en === 'string' && x.en.trim() !== '';
}

function firstLine(s) {
  return String(s).split('\n')[0];
}

/**
 * — the recursive LStr walk.
 * Traverses every nested object/array. Any object having a `th` OR an `en`
 * key must have BOTH, both strings, both non-empty. Offenders are reported
 * with their JSON path.
 */
function walkLStr(node, p, out, seen) {
  if (node === null || node === undefined) return;
  const t = typeof node;
  if (t !== 'object') return;                 // strings/numbers/booleans: fine
  if (node instanceof RegExp) return;
  if (seen.indexOf(node) !== -1) return;      // cycle guard
  seen.push(node);

  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      walkLStr(node[i], p + '[' + i + ']', out, seen);
    }
    return;
  }

  const hasTh = Object.prototype.hasOwnProperty.call(node, 'th');
  const hasEn = Object.prototype.hasOwnProperty.call(node, 'en');
  if (hasTh || hasEn) {
    if (typeof node.th !== 'string' || node.th.trim() === '') {
      out.push('LStr at ' + (p || '(root)') + ': `th` missing or empty');
    }
    if (typeof node.en !== 'string' || node.en.trim() === '') {
      out.push('LStr at ' + (p || '(root)') + ': `en` missing or empty');
    }
  }

  const keys = Object.keys(node);
  for (let k = 0; k < keys.length; k++) {
    walkLStr(node[keys[k]], p ? p + '.' + keys[k] : keys[k], out, seen);
  }
}

/* --------------------------- module loading ------------------------------ */

function tryRequire(rel) {
  try {
    return { mod: require(path.join(ROOT, rel)), err: null };
  } catch (e) {
    return { mod: null, err: e };
  }
}

console.log(bold('\nSecure Coding Workshop — verify suite'));
console.log(dim('root: ' + ROOT));

// --- Grader (this suite is useless without it) ---
const graderLoad = tryRequire('js/grader.js');
if (graderLoad.err) {
  console.log(red('\nFATAL: could not load js/grader.js — ' + firstLine(graderLoad.err.message)));
  process.exit(1);
}
const Grader = graderLoad.mod;

// --- Data files + registry ---
const missingData = [];
['w1', 'w2', 'w3', 'w4', 'w5', 'w6'].forEach(function (n) {
  if (!fs.existsSync(path.join(ROOT, 'js', 'data', n + '.js'))) {
    missingData.push('js/data/' + n + '.js');
  }
});

let WORKSHOPS = null;
let SCW = null;
let registryError = null;
if (missingData.length > 0) {
  registryError = 'missing data file(s): ' + missingData.join(', ') +
    '';
} else {
  const reg = tryRequire('js/exercises.js');
  if (reg.err) {
    registryError = 'js/exercises.js failed to load: ' + firstLine(reg.err.message);
  } else if (!reg.mod || !Array.isArray(reg.mod.WORKSHOPS)) {
    registryError = 'js/exercises.js loaded but did not export { WORKSHOPS, SCW }';
  } else {
    WORKSHOPS = reg.mod.WORKSHOPS;
    SCW = reg.mod.SCW;
  }
}

// --- Simulator (+ extra kinds). sim-extra.js registers into the same core. ---
let Simulator = null;
let simError = null;
{
  const simLoad = tryRequire('js/simulator.js');
  if (simLoad.err) {
    simError = 'js/simulator.js failed to load: ' + firstLine(simLoad.err.message);
  } else {
    Simulator = simLoad.mod || globalThis.Simulator;
    const extraLoad = tryRequire('js/sim-extra.js');
    if (extraLoad.err) {
      simError = 'js/sim-extra.js failed to load: ' + firstLine(extraLoad.err.message) +
        ' (kinds 14-24 unavailable)';
      // keep Simulator for kinds 1-13 + util; per-exercise checks will
      // report unregistered kinds individually.
      simError = simError + '';
    }
  }
  if (Simulator && (typeof Simulator.has !== 'function' || typeof Simulator.run !== 'function')) {
    simError = 'js/simulator.js loaded but lacks has()/run() — not the surface';
    Simulator = null;
  }
}

/* ไดอะแกรมเคลื่อนไหว — โหลดแยกจาก simulator เพื่อให้รายงานพังคนละจุดได้ */
let Diagram = null;
let dgError = null;
{
  const dgLoad = tryRequire('js/diagram.js');
  if (dgLoad.err) {
    dgError = 'js/diagram.js failed to load: ' + firstLine(dgLoad.err.message);
  } else {
    Diagram = dgLoad.mod || globalThis.Diagram;
    const dgExtra = tryRequire('js/diagram-extra.js');
    if (dgExtra.err) {
      dgError = 'js/diagram-extra.js failed to load: ' + firstLine(dgExtra.err.message) +
        ' (W4-W6 scenes unavailable)';
    }
  }
  if (Diagram && (typeof Diagram.has !== 'function' || typeof Diagram.build !== 'function')) {
    dgError = 'js/diagram.js loaded but lacks has()/build() — not the surface';
    Diagram = null;
  }
}

const DG_VB = { w: 880, h: 480 };
const DG_NODE = { w: 156, h: 58 };
const DG_NODE_KINDS = ['actor', 'attacker', 'app', 'db', 'store', 'guard', 'note'];
const DG_EDGE_TONES = ['neutral', 'danger', 'safe'];
const DG_STEP_TONES = ['ok', 'warn', 'fail'];

// ตรวจฉากหนึ่งฉากตามสัญญา — คืน array ของข้อความปัญหา (ว่าง = ผ่าน)
function dgSceneProblems(sc, label) {
  const bad = [];
  if (!sc) return [label + ': scene missing'];
  if (!isLStr(sc.caption)) bad.push(label + '.caption must be an LStr');

  const nodes = Array.isArray(sc.nodes) ? sc.nodes : [];
  if (nodes.length < 3 || nodes.length > 7) bad.push(label + ': needs 3-7 nodes, got ' + nodes.length);
  const ids = new Set();
  nodes.forEach(function (n) {
    if (!n || !n.id) { bad.push(label + ': node without id'); return; }
    if (ids.has(n.id)) bad.push(label + ': duplicate node id "' + n.id + '"');
    ids.add(n.id);
    if (DG_NODE_KINDS.indexOf(n.kind) < 0) bad.push(label + ': node "' + n.id + '" bad kind "' + n.kind + '"');
    if (typeof n.label !== 'string' || !n.label) bad.push(label + ': node "' + n.id + '" has no label');
    if (!(n.x - DG_NODE.w / 2 >= 0 && n.x + DG_NODE.w / 2 <= DG_VB.w)) {
      bad.push(label + ': node "' + n.id + '" x=' + n.x + ' falls outside the viewBox');
    }
    if (!(n.y - DG_NODE.h / 2 >= 0 && n.y + DG_NODE.h / 2 <= DG_VB.h)) {
      bad.push(label + ': node "' + n.id + '" y=' + n.y + ' falls outside the viewBox');
    }
  });

  const edges = Array.isArray(sc.edges) ? sc.edges : [];
  if (!edges.length) bad.push(label + ': needs at least one edge');
  const eids = new Set();
  edges.forEach(function (e) {
    if (!e || !e.id) { bad.push(label + ': edge without id'); return; }
    if (eids.has(e.id)) bad.push(label + ': duplicate edge id "' + e.id + '"');
    eids.add(e.id);
    if (!ids.has(e.from)) bad.push(label + ': edge "' + e.id + '" from "' + e.from + '" is not a node');
    if (!ids.has(e.to)) bad.push(label + ': edge "' + e.id + '" to "' + e.to + '" is not a node');
    if (DG_EDGE_TONES.indexOf(e.tone) < 0) bad.push(label + ': edge "' + e.id + '" bad tone "' + e.tone + '"');
  });

  const steps = Array.isArray(sc.steps) ? sc.steps : [];
  if (steps.length < 2 || steps.length > 6) bad.push(label + ': needs 2-6 steps, got ' + steps.length);
  steps.forEach(function (s, i) {
    if (!s) { bad.push(label + ': step ' + i + ' missing'); return; }
    if (!eids.has(s.edge)) bad.push(label + ': step ' + i + ' edge "' + s.edge + '" is not a declared edge');
    if (DG_STEP_TONES.indexOf(s.tone) < 0) bad.push(label + ': step ' + i + ' bad tone "' + s.tone + '"');
    if (!isLStr(s.log)) bad.push(label + ': step ' + i + '.log must be an LStr');
    // packet เป็นป้ายที่ใส่หรือไม่ใส่ก็ได้ แต่ถ้าใส่ต้องเป็นสตริง
    if (s.packet !== undefined && typeof s.packet !== 'string') {
      bad.push(label + ': step ' + i + '.packet must be a string when present');
    }
  });
  return bad;
}

/* ========================================================================== *
 * 1) Grader unit tests (always run — no other files needed)
 * ========================================================================== */

heading('Grader unit tests');
group('stripComments');
{
  let s = Grader.stripComments('const url = "http://example.com"; // trailing comment\nlet x = 1;');
  ok(s.indexOf('http://example.com') !== -1, 'must keep `//` inside a double-quoted string');
  ok(s.indexOf('trailing comment') === -1, 'must remove a `//` line comment');
  ok(s.indexOf('let x = 1;') !== -1, 'must keep the code after the comment line');

  s = Grader.stripComments("const t = '# not a comment';\n# real comment\nkey: value");
  ok(s.indexOf('# not a comment') !== -1, 'must keep `#` inside a single-quoted string');
  ok(s.indexOf('real comment') === -1, 'must remove a `#` line comment');
  ok(s.indexOf('key: value') !== -1, 'must keep YAML content after a `#` comment line');

  s = Grader.stripComments('alpha /* block gone */ beta <!-- xml gone --> gamma');
  ok(s.indexOf('block gone') === -1, 'must remove a block comment');
  ok(s.indexOf('xml gone') === -1, 'must remove an XML comment');
  ok(/alpha\s+beta\s+gamma/.test(s), 'comment removal must not fuse surrounding tokens');

  s = Grader.stripComments('const s = "say \\"hi\\" // still string"; // real comment');
  ok(s.indexOf('// still string') !== -1, 'escaped quotes must not end the string early');
  ok(s.indexOf('real comment') === -1, 'the actual trailing comment must go');

  s = Grader.stripComments('const q = `select // not comment ${x}`; // gone');
  ok(s.indexOf('// not comment') !== -1, 'must keep `//` inside a template literal');
  ok(s.indexOf('gone') === -1, 'must remove the comment after the template literal');

  s = Grader.stripComments('before /* never terminated');
  ok(s.indexOf('before') !== -1 && s.indexOf('never terminated') === -1,
    'unterminated block comment must strip to EOF without throwing');

  s = Grader.stripComments('a <!-- open forever');
  ok(s.indexOf('open forever') === -1, 'unterminated XML comment must strip to EOF');

  ok(Grader.stripComments('') === '', 'empty input returns empty string');
}

group('runChecks: too-short & empty checks');
{
  let r = Grader.runChecks('x = 1', [{ id: 'a', mustMatch: /x/ }]);
  ok(r.error === 'too-short', "code with <10 non-ws chars returns error KEY 'too-short' (got: " + r.error + ')');
  ok(r.passed === false && r.results.length === 0 && r.traps.length === 0 &&
    r.score === 0 && r.maxScore === 0, 'too-short result has empty results/traps and 0/0 score');

  r = Grader.runChecks('   \n\t  x1  \n ', [{ id: 'a', mustMatch: /x/ }]);
  ok(r.error === 'too-short', 'whitespace does not count toward the 10-char minimum');

  r = Grader.runChecks(null, [{ id: 'a', mustMatch: /x/ }]);
  ok(r.error === 'too-short' && r.passed === false, 'null code is handled as too-short, not a crash');

  r = Grader.runChecks('const abcdef = 12345;', undefined, undefined);
  ok(r.error === null, 'undefined checks/traps: no error');
  ok(r.passed === false, 'empty checks can never pass');
  ok(r.results.length === 0 && r.traps.length === 0 && r.score === 0 && r.maxScore === 0,
    'undefined checks/traps treated as []');
}

group('runChecks: g-flag statefulness');
{
  const gRe = /needle/g;
  const checks = [{ id: 'find-needle', label: { th: 'x', en: 'x' }, hint: { th: 'x', en: 'x' }, mustMatch: gRe }];
  const code = 'const needle = 42; return needle;';
  const r1 = Grader.runChecks(code, checks);
  const r2 = Grader.runChecks(code, checks);
  const r3 = Grader.runChecks(code, checks);
  ok(r1.passed === true && r2.passed === true && r3.passed === true,
    'a /g regex must give identical results on repeated runs (got ' +
    [r1.passed, r2.passed, r3.passed].join(', ') + ')');
  ok(gRe.lastIndex === 0, 'the exercise-data regex object must not be mutated (lastIndex is ' + gRe.lastIndex + ')');

  const gNot = /forbidden/g;
  const checks2 = [{ id: 'no-forbidden', mustNotMatch: gNot }];
  const code2 = 'const forbidden = 1; use(forbidden);';
  const a = Grader.runChecks(code2, checks2);
  const b = Grader.runChecks(code2, checks2);
  ok(a.passed === false && b.passed === false,
    'a /g mustNotMatch stays failed on repeated runs (no lastIndex skip-over)');
}

group('runChecks: comment-aware matching');
{
  let r = Grader.runChecks('// eval(userInput)\nconst safeValue = 1234;',
    [{ id: 'no-eval', mustNotMatch: /eval\s*\(/ }]);
  ok(r.passed === true, 'a forbidden pattern that only appears in a comment must NOT fail the check');

  r = Grader.runChecks('/* PreparedStatement */ const q = "SELECT" + userInput;',
    [{ id: 'use-ps', mustMatch: /PreparedStatement/ }]);
  ok(r.passed === false, 'a required pattern that only appears in a comment must NOT pass the check');

  r = Grader.runChecks('const u = "https://example.com/api"; callApi(u);',
    [{ id: 'has-url', mustMatch: /https:\/\/example\.com/ }]);
  ok(r.passed === true, 'the `//` inside a string URL must survive stripping and still match');
}

group('runChecks: weights, score, kinds');
{
  const checks = [
    { id: 'crux', weight: 2, mustMatch: /alpha/ },
    { id: 'no-danger', mustNotMatch: /dangerZone/ }
  ];
  let r = Grader.runChecks('const value = computeSomething();', checks);
  ok(r.maxScore === 3, 'maxScore sums weights (2+1=3, got ' + r.maxScore + ')');
  ok(r.score === 1, 'score sums only passed weights (got ' + r.score + ')');
  ok(r.passed === false, 'one failing check fails the run');
  ok(r.results[0].kind === 'require' && r.results[1].kind === 'forbid',
    "kind is 'require' for mustMatch and 'forbid' for mustNotMatch");
  ok(r.results[0].weight === 2 && r.results[1].weight === 1, 'weight defaults to 1 and is echoed back');
  ok(r.results[0].id === 'crux', 'result rows carry the check id');

  r = Grader.runChecks('const alpha = computeSomething();', checks);
  ok(r.passed === true && r.score === 3 && r.score === r.maxScore, 'all checks passing gives full score');
}

group('runChecks: traps');
{
  const traps = [
    { id: 'strip-quote', match: /replace\s*\(/, message: { th: 'ไม่พอ', en: 'not enough' } },
    { id: 'never-matches', match: /zzz_not_here/, message: { th: 'x', en: 'x' } }
  ];
  let r = Grader.runChecks("value.replace('x', ''); done(value);", [{ id: 'a', mustMatch: /done/ }], traps);
  ok(r.traps.length === 1 && r.traps[0].id === 'strip-quote', 'a matching trap is reported by id');
  ok(isLStr(r.traps[0].message), 'the trap message LStr is passed through untouched');
  ok(r.passed === true, 'traps never block passing');

  r = Grader.runChecks('// value.replace("x", "")\nconst done = 1; use(done);',
    [{ id: 'a', mustMatch: /done/ }], traps);
  ok(r.traps.length === 0, 'a trap pattern inside a comment does not fire');
}

group('runChecks: malformed input never throws');
{
  let r = null;
  let threw = false;
  try {
    r = Grader.runChecks('const abcdef = 12345;', [
      { id: 'no-pattern' },                                  // neither pattern
      { id: 'both', mustMatch: /a/, mustNotMatch: /b/ },     // both patterns
      { id: 'not-a-regex', mustMatch: 'PreparedStatement' }, // string, not RegExp
      null                                                   // not even an object
    ], [{ id: 'bad-trap', match: 'nope' }, null]);
  } catch (e) { threw = true; }
  ok(!threw, 'malformed checks/traps must not throw');
  if (r) {
    ok(r.results.length === 4, 'every malformed check still yields a result row');
    ok(r.results.every(function (x) { return x.passed === false; }),
      'malformed checks are reported as failed');
    ok(r.passed === false && r.traps.length === 0, 'malformed traps simply never match');
  }
}

/* ========================================================================== *
 * 2) Registry & roster
 * ========================================================================== */

heading('Registry & roster');

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];
const POINTS = { Critical: 150, High: 120, Medium: 90, Low: 70 };
const KEBAB = /^[a-z0-9]+(-[a-z0-9]+)*$/;

if (!WORKSHOPS) {
  group('registry');
  ok(false, 'BLOCKED — ' + registryError);
  flushGroup();
} else {
  group('roster shape');
  ok(WORKSHOPS.length === 6, 'exactly 6 workshops (got ' + WORKSHOPS.length + ')');
  const allEx = SCW.allExercises();
  // นับจาก workshop จริง ไม่ผูกกับตัวเลขตายตัว เวลาเพิ่ม/ลบโจทย์จะได้ไม่ต้องแก้เทสต์
  // (ระวัง: ตัวแปร total ในไฟล์นี้คือตัวนับ assertion ของ harness คนละตัวกัน)
  const rosterCount = WORKSHOPS.reduce(function (a, w) { return a + (w.exercises || []).length; }, 0);
  ok(allEx.length === rosterCount,
    'allExercises() must match the sum of the workshops (' + allEx.length + ' vs ' + rosterCount + ')');
  WORKSHOPS.forEach(function (w, i) {
    ok(!!w && typeof w.id === 'string' && /^w[1-6]$/.test(w.id),
      'workshop[' + i + '] id must be w1..w6 (got ' + (w && w.id) + ')');
    ok(typeof w.order === 'number', 'workshop ' + (w && w.id) + ' must have a numeric order');
    const errs = [];
    walkLStr({ title: w.title, summary: w.summary, goal: w.goal }, w.id, errs, []);
    errs.forEach(function (e) { ok(false, e); });
    ok(isLStr(w.title) && isLStr(w.summary) && isLStr(w.goal),
      'workshop ' + (w && w.id) + ' needs LStr title/summary/goal');
  });
  for (let i = 1; i < WORKSHOPS.length; i++) {
    ok(WORKSHOPS[i - 1].order <= WORKSHOPS[i].order,
      'WORKSHOPS must be sorted by order (position ' + i + ' out of order)');
  }
  const seen = {};
  allEx.forEach(function (ex) {
    ok(typeof ex.id === 'string' && KEBAB.test(ex.id),
      'exercise id must be kebab-case (got ' + JSON.stringify(ex.id) + ')');
    ok(!seen[ex.id], 'exercise id must be globally unique (duplicate: ' + ex.id + ')');
    seen[ex.id] = true;
  });

  group('registry helpers');
  const f1 = SCW.flatten();
  const f2 = SCW.flatten();
  ok(f1 === f2, 'flatten() is memoised (same array on repeated calls)');
  ok(f1.length === SCW.allExercises().length,
    'flatten() must cover every exercise (' + f1.length + ' vs ' + SCW.allExercises().length + ')');
  ok(f1.every(function (e, i) { return e.index === i && !!e.workshop && !!e.ex; }),
    'flatten() entries are { workshop, ex, index } with sequential indexes');

  const beforeIds = WORKSHOPS.map(function (w) { return w.id; }).join(',');
  const again = SCW.finalize();       // must be idempotent
  const again2 = SCW.finalize();
  ok(Array.isArray(again2) && again2.length === 6 &&
    again2.map(function (w) { return w.id; }).join(',') === beforeIds,
    'finalize() is idempotent — calling twice keeps the same 6 workshops in order');
  const f3 = SCW.flatten();
  ok(f3 !== f2, 'finalize() invalidates the flatten() memo');
  ok(f3.length === f2.length, 'flatten() must be stable across re-finalize');
  WORKSHOPS = again2; // use the (re)finalized list below

  const firstId = f3[0].ex.id;
  const found = SCW.findExercise(firstId);
  ok(!!found && found.ex.id === firstId && found.index === 0,
    'findExercise() returns { workshop, ex, index } for a known id');
  ok(SCW.findExercise('definitely-not-an-exercise') === null,
    'findExercise() returns null for an unknown id');
  ok(SCW.allExercises().length === SCW.flatten().length, 'allExercises() must match flatten()');
}

/* ========================================================================== *
 * 3) Per-exercise assertions ( items 1–10)
 * ========================================================================== */

function isValidRef(r) {
  return !!r && typeof r === 'object' &&
    typeof r.label === 'string' && r.label.trim() !== '' &&
    typeof r.url === 'string' && r.url.indexOf('https://') === 0;
}

function checkSimResult(result, where) {
  if (!ok(!!result && typeof result === 'object', where + ': SimResult missing')) return;
  ok(!!result.vulnerable && !!result.secure, where + ': needs both `vulnerable` and `secure` panes');
  [['vulnerable', false], ['secure', true]].forEach(function (pair) {
    const key = pair[0];
    const wantOk = pair[1];
    const pane = result[key];
    if (!pane) return;
    ok(isLStr(pane.title), where + '.' + key + ': pane title must be an LStr');
    const steps = Array.isArray(pane.steps) ? pane.steps : [];
    ok(steps.length >= 2, where + '.' + key + ': needs >=2 steps (got ' + steps.length + ')');
    steps.forEach(function (st, j) {
      const sp = where + '.' + key + '.steps[' + j + ']';
      ok(!!st && isLStr(st.label), sp + ': label must be an LStr with th+en');
      ok(!!st && typeof st.text === 'string', sp + ': text must be a plain string');
      ok(!!st && ['neutral', 'danger', 'safe'].indexOf(st.tone) !== -1,
        sp + ": tone must be neutral|danger|safe (got " + (st && st.tone) + ')');
      if (st && st.mark !== undefined) {
        const marksOk = Array.isArray(st.mark) && st.mark.every(function (m) {
          return Array.isArray(m) && m.length === 2 &&
            typeof m[0] === 'number' && typeof m[1] === 'number' &&
            m[0] >= 0 && m[0] <= m[1] &&
            typeof st.text === 'string' && m[1] <= st.text.length;
        });
        ok(marksOk, sp + ': mark ranges must be [[start,end],…] inside text bounds');
      }
    });
    ok(!!pane.verdict && typeof pane.verdict.ok === 'boolean' && isLStr(pane.verdict.text),
      where + '.' + key + ': verdict { ok:boolean, text:LStr } required');
    if (pane.verdict && typeof pane.verdict.ok === 'boolean') {
      ok(pane.verdict.ok === wantOk,
        where + '.' + key + ': verdict.ok must be ' + wantOk + ' (attack ' +
        (wantOk ? 'blocked in secure pane' : 'succeeds in vulnerable pane') + ')');
    }
  });
}

function verifyLanguageBlock(ex, lang) {
  const lb = ex.languages ? ex.languages[lang] : null;
  if (!ok(!!lb && typeof lb === 'object', lang + ': language block missing')) return;

  ok(typeof lb.filename === 'string' && lb.filename.trim() !== '', lang + ': filename required');
  ok(['java', 'js', 'xml', 'json', 'yaml'].indexOf(lb.lang) !== -1,
    lang + ": lang must be java|js|xml|json|yaml (got " + lb.lang + ')');
  ok(typeof lb.starter === 'string' && lb.starter.trim() !== '', lang + ': starter code required');
  ok(typeof lb.solution === 'string' && lb.solution.trim() !== '', lang + ': solution code required');
  ok(isLStr(lb.explain), lang + ': explain must be an LStr');

  // ---- checks: 3..5, unique kebab ids, exactly one pattern each ----
  const checks = Array.isArray(lb.checks) ? lb.checks : [];
  ok(checks.length >= 3 && checks.length <= 5,
    lang + ': needs 3–5 checks (got ' + checks.length + ')');
  const ids = {};
  checks.forEach(function (c, i) {
    const cp = lang + '.checks[' + i + ']';
    if (!ok(!!c && typeof c === 'object', cp + ': not an object')) return;
    ok(typeof c.id === 'string' && c.id.trim() !== '', cp + ': id required');
    if (c.id) {
      ok(!ids[c.id], cp + ': duplicate check id "' + c.id + '" in this block');
      ids[c.id] = true;
    }
    ok(isLStr(c.label), cp + ' (' + c.id + '): label must be an LStr');
    ok(isLStr(c.hint), cp + ' (' + c.id + '): hint must be an LStr');
    const hasMust = c.mustMatch !== undefined;
    const hasNot = c.mustNotMatch !== undefined;
    ok(hasMust !== hasNot, cp + ' (' + c.id + '): exactly ONE of mustMatch/mustNotMatch');
    if (hasMust) ok(c.mustMatch instanceof RegExp, cp + ' (' + c.id + '): mustMatch must be a RegExp');
    if (hasNot) ok(c.mustNotMatch instanceof RegExp, cp + ' (' + c.id + '): mustNotMatch must be a RegExp');
    if (c.weight !== undefined) {
      ok(typeof c.weight === 'number' && c.weight === Math.floor(c.weight) &&
        c.weight >= 1 && c.weight <= 3, cp + ' (' + c.id + '): weight must be an integer 1..3');
    }
  });

  // ---- traps: 1..3, valid regexes ----
  const traps = Array.isArray(lb.traps) ? lb.traps : [];
  ok(traps.length >= 1 && traps.length <= 3,
    lang + ': needs 1–3 traps (got ' + traps.length + ') — see/');
  traps.forEach(function (t, i) {
    const tp = lang + '.traps[' + i + ']';
    if (!ok(!!t && typeof t === 'object', tp + ': not an object')) return;
    ok(typeof t.id === 'string' && t.id.trim() !== '', tp + ': id required');
    ok(t.match instanceof RegExp, tp + ' (' + t.id + '): match must be a valid RegExp');
    ok(isLStr(t.message), tp + ' (' + t.id + '): message must be an LStr');
  });

  // ---- starter must FAIL ----
  const starterRes = Grader.runChecks(lb.starter, checks, traps);
  ok(starterRes.error === null,
    lang + ': starter triggered grader error "' + starterRes.error + '" (is it long enough?)');
  ok(starterRes.passed === false,
    lang + ': STARTER unexpectedly PASSES every check — the vulnerability is not being caught');

  // ---- solution must PASS with full score and zero traps ----
  const solRes = Grader.runChecks(lb.solution, checks, traps);
  const failing = solRes.results.filter(function (r) { return !r.passed; });
  ok(solRes.passed === true,
    lang + ': SOLUTION FAILED check(s): ' +
    (failing.length ? failing.map(function (r) { return r.id + ' [' + r.kind + ']'; }).join(', ')
      : '(error: ' + solRes.error + ')'));
  ok(solRes.score === solRes.maxScore,
    lang + ': solution score ' + solRes.score + ' != maxScore ' + solRes.maxScore);
  ok(solRes.traps.length === 0,
    lang + ': trap(s) match the reference solution: ' +
    solRes.traps.map(function (t) { return t.id; }).join(', '));
}

heading('Exercises (contract items 1–10)');

if (!WORKSHOPS) {
  group('exercises');
  ok(false, 'BLOCKED — cannot verify exercises: ' + registryError);
  flushGroup();
} else {
  WORKSHOPS.forEach(function (w) {
    w.exercises.forEach(function (ex) {
      group(w.id + ' / ' + ex.id);

      // 1. id (uniqueness asserted globally above)
      ok(KEBAB.test(String(ex.id)), 'id must be kebab-case');

      // 2. severity / points / estMinutes
      ok(SEVERITIES.indexOf(ex.severity) !== -1,
        'severity must be Critical|High|Medium|Low (got ' + ex.severity + ')');
      if (SEVERITIES.indexOf(ex.severity) !== -1) {
        ok(ex.points === POINTS[ex.severity],
          'points must match the severity table: ' + ex.severity + ' => ' +
          POINTS[ex.severity] + ' (got ' + ex.points + ')');
      }
      ok(typeof ex.estMinutes === 'number' && ex.estMinutes === Math.floor(ex.estMinutes) &&
        ex.estMinutes >= 5 && ex.estMinutes <= 25,
        'estMinutes must be an integer 5..25 (got ' + ex.estMinutes + ')');

      // 3. cwe / owasp formats
      ok(/^CWE-\d+$/.test(String(ex.cwe)), 'cwe must match /^CWE-\\d+$/ (got ' + ex.cwe + ')');
      ok(/^A\d{2}:2021 – /.test(String(ex.owasp)),
        "owasp must match /^A\\d{2}:2021 – / with an EN DASH U+2013 (got " +
        JSON.stringify(ex.owasp) + ')');

      // 4. the recursive LStr walk over the whole exercise
      const lerrs = [];
      walkLStr(ex, ex.id, lerrs, []);
      lerrs.forEach(function (e) { ok(false, e); });
      if (lerrs.length === 0) ok(true, 'LStr walk clean');

      // core narrative fields exist as LStrs
      ['title', 'category', 'intro', 'attack', 'fix', 'impact'].forEach(function (f) {
        ok(isLStr(ex[f]), f + ' must be a non-empty LStr');
      });


      // 6. references
      ok(Array.isArray(ex.references) && ex.references.length >= 2,
        'references.length must be >= 2 (got ' + (ex.references ? ex.references.length : 'none') + ')');
      (ex.references || []).forEach(function (r, ri) {
        ok(isValidRef(r), 'references[' + ri + '] must be { label, url } with an https:// url' +
          (r && r.url ? ' (got ' + r.url + ')' : ''));
      });

      // 7. caseStudy
      const cs = ex.caseStudy;
      ok(!!cs && typeof cs === 'object', 'caseStudy required');
      if (cs) {
        ok(typeof cs.year === 'number', 'caseStudy.year must be a number');
        ok(isLStr(cs.title) && isLStr(cs.body), 'caseStudy title/body must be LStrs');
        ok(isValidRef(cs.source),
          'caseStudy.source must be { label, url } with an https:// url' +
          (cs.source && cs.source.url ? ' (got ' + cs.source.url + ')' : ''));
      }

      // 8. pitfalls & codeReview
      ok(Array.isArray(ex.pitfalls) && ex.pitfalls.length >= 2,
        'pitfalls.length must be >= 2 (got ' + (ex.pitfalls ? ex.pitfalls.length : 'none') + ')');
      (ex.pitfalls || []).forEach(function (p, pi) {
        ok(!!p && isLStr(p.title) && isLStr(p.why),
          'pitfalls[' + pi + '] must have LStr title + why');
        //: บรรทัดสรุปสั้นสำหรับใช้สอน
        ok(!!p && isLStr(p.short),
          'pitfalls[' + pi + '] must have an LStr short (one-line correction)');
        if (p && isLStr(p.short)) {
          ok(p.short.th.length <= 200,
            'pitfalls[' + pi + '].short.th must be <= 200 chars (got ' + p.short.th.length + ')');
          ok(p.short.en.length <= 220,
            'pitfalls[' + pi + '].short.en must be <= 220 chars (got ' + p.short.en.length + ')');
        }
      });

      // keyPoints — bullet สรุปสำหรับใช้สอน (ต้องสั้นพอที่จะอ่านจากจอโปรเจกเตอร์)
      ok(!!ex.keyPoints && typeof ex.keyPoints === 'object',
        'keyPoints must exist');
      ['vuln', 'attack', 'fix'].forEach(function (grp) {
        var arr = ex.keyPoints ? ex.keyPoints[grp] : null;
        // ขั้นต่ำ 1 bullet: บางข้อเจ้าของตัดให้เหลือประเด็นเดียวโดยตั้งใจ
        ok(Array.isArray(arr) && arr.length >= 1 && arr.length <= 4,
          'keyPoints.' + grp + ' must have 2-4 bullets (got ' +
          (Array.isArray(arr) ? arr.length : 'none') + ')');
        (arr || []).forEach(function (b, bi) {
          ok(isLStr(b), 'keyPoints.' + grp + '[' + bi + '] must be an LStr');
          if (isLStr(b)) {
            ok(b.th.length <= 200,
              'keyPoints.' + grp + '[' + bi + '].th must be <= 200 chars (got ' + b.th.length + ')');
            ok(b.en.length <= 220,
              'keyPoints.' + grp + '[' + bi + '].en must be <= 220 chars (got ' + b.en.length + ')');
          }
        });
      });
      ok(Array.isArray(ex.codeReview) && ex.codeReview.length >= 3,
        'codeReview.length must be >= 3 (got ' + (ex.codeReview ? ex.codeReview.length : 'none') + ')');

      // testIt (part of the contract; cmd is a plain string)
      // note เป็น optional — บางข้อคำสั่งอธิบายตัวเองได้ ไม่ต้องมีคำบรรยายซ้ำ
      ok(!!ex.testIt && typeof ex.testIt.cmd === 'string' && ex.testIt.cmd.trim() !== '',
        'testIt must have a non-empty cmd string');
      ok(!ex.testIt || ex.testIt.note === undefined || isLStr(ex.testIt.note),
        'testIt.note, when present, must be an LStr');

      // 9. per-language grading invariants
      verifyLanguageBlock(ex, 'java');
      verifyLanguageBlock(ex, 'node');

      // 10. simulator
      const sim = ex.sim;
      if (!ok(!!sim && typeof sim === 'object', 'sim spec required')) return;
      ok(Array.isArray(sim.payloads) && sim.payloads.length >= 2,
        'sim.payloads must have >= 2 presets (got ' + (sim.payloads ? sim.payloads.length : 'none') + ')');
      (sim.payloads || []).forEach(function (p, pi) {
        ok(!!p && isLStr(p.label) && typeof p.value === 'string',
          'sim.payloads[' + pi + '] must be { label: LStr, value: string }');
      });
      if (!Simulator) {
      } else {
        ok(Simulator.has(sim.kind) === true,
          'sim.kind "' + sim.kind + '" is not registered with the Simulator');
        if (Simulator.has(sim.kind)) {
          (sim.payloads || []).forEach(function (p, pi) {
            let res = null;
            let threw = null;
            try { res = Simulator.run(sim, p && p.value); } catch (e) { threw = e; }
            if (!ok(threw === null, 'Simulator.run threw for payload[' + pi + ']: ' +
              (threw && firstLine(threw.message)))) return;
            checkSimResult(res, 'sim.payload[' + pi + ']');
          });
        }
      }

      // 11. ไดอะแกรมเคลื่อนไหว — ใช้ sim.kind เดียวกัน ไม่ต้องมีฟิลด์ใหม่
      if (!Diagram) {
      } else {
        ok(Diagram.has(sim.kind) === true,
          'no Diagram scene registered for kind "' + sim.kind + '"');
        if (Diagram.has(sim.kind)) {
          // config จริงของโจทย์ และ {} เพื่อพิสูจน์ว่าฉากไม่พังเมื่อ config ขาด
          [['config', sim.config || {}], ['{}', {}]].forEach(function (pair) {
            let scenes = null;
            let threw = null;
            try { scenes = Diagram.build(sim.kind, pair[1]); } catch (e) { threw = e; }
            if (!ok(threw === null, 'Diagram.build threw with ' + pair[0] + ': ' +
              (threw && firstLine(threw.message)))) return;
            if (!ok(!!scenes && !!scenes.vuln && !!scenes.safe,
              'Diagram.build(' + pair[0] + ') must return both vuln and safe scenes')) return;
            dgSceneProblems(scenes.vuln, 'diagram[' + pair[0] + '].vuln')
              .concat(dgSceneProblems(scenes.safe, 'diagram[' + pair[0] + '].safe'))
              .forEach(function (msg) { ok(false, msg); });
          });
        }
      }
    });
  });
}

/* ========================================================================== *
 * 4) Crypto vectors
 * ========================================================================== */

flushGroup();
const passedTotal = total - failedTotal;
console.log('\n' + bold(passedTotal + '/' + total + ' assertions passed.'));
if (failedTotal > 0) {
  console.log(red(bold(failedTotal + ' assertion(s) FAILED.')) +
    '\n');
  process.exit(1);
} else {
  console.log(green(bold('All good — data, grading, simulator and crypto invariants hold.')) + '\n');
}
