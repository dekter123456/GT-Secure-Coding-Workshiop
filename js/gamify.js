/*
 * js/gamify.js — window.Gamify
 * XP, ranks, badges, and the printable certificate for the
 * Secure Coding Workshop.
 *
 * Progress scoring:
 *   - solving an exercise awards ex.points
 *     (Critical 150 / High 120 / Medium 90 / Low 70)
 *   - −15% of that exercise's points per hint revealed, capped at −45%
 *   - solution revealed before the first pass caps the exercise at 40%
 *   - each correct quiz answer awards 20 XP
 *   - per-exercise XP never drops below 0; XP is rounded to whole numbers
 *
 * Zero dependencies. Works from file:// and under require() in Node.
 * See,,,.
 */
(function (global) {
  'use strict';

  var SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];
  var HINT_PENALTY = 0.15;   /* per hint */
  var MAX_HINTS = 3;         /* penalty capped at 45% */
  var REVEAL_CAP = 0.40;     /* solution revealed before first pass */
  var QUIZ_XP = 20;          /* per correct quiz answer */

  /* ---- ranks (ascending by min XP) ---- */

  var RANKS = [
    { min: 0,    name: { th: 'มือใหม่', en: 'Novice' },                       icon: '🌱' },
    { min: 400,  name: { th: 'ผู้ฝึกหัด', en: 'Apprentice' },                  icon: '🔧' },
    { min: 900,  name: { th: 'นักปฏิบัติ', en: 'Practitioner' },               icon: '⚙️' },
    { min: 1500, name: { th: 'ผู้ป้องกันระบบ', en: 'Defender' },               icon: '🛡️' },
    { min: 2200, name: { th: 'ผู้พิทักษ์ระบบ', en: 'Guardian' },               icon: '🏰' },
    { min: 3000, name: { th: 'Security Champion', en: 'Security Champion' },  icon: '👑' }
  ];

  /* ---- badges ----
   * Every test() is pure, reads only the Stats object, and must not throw
   * on a partially-filled (or empty) stats value.
   */

  function num(v) {
    return typeof v === 'number' && isFinite(v) ? v : 0;
  }

  var BADGES = [
    {
      id: 'first-solve',
      icon: '🎯',
      name: { th: 'ปิดจ็อบแรก', en: 'First Fix' },
      desc: { th: 'แก้โจทย์ผ่านเป็นข้อแรก — ทุกตำนานเริ่มจากบั๊กเดียว', en: 'Solved your first exercise — every streak starts with one fix' },
      test: function (s) {
        return !!s && num(s.solved) >= 1;
      }
    },
    {
      id: 'halfway',
      icon: '⛰️',
      name: { th: 'มาได้ครึ่งทาง', en: 'Halfway There' },
      desc: { th: 'แก้โจทย์ผ่านแล้วอย่างน้อยครึ่งหนึ่งของทั้งหมด', en: 'Solved at least half of all exercises' },
      test: function (s) {
        return !!s && num(s.total) > 0 && num(s.solved) * 2 >= num(s.total);
      }
    },
    {
      id: 'workshop-clear',
      icon: '📗',
      name: { th: 'เคลียร์ครบหนึ่ง Workshop', en: 'Workshop Complete' },
      desc: { th: 'แก้โจทย์ผ่านครบทุกข้อใน Workshop เดียวกันอย่างน้อยหนึ่งชุด', en: 'Solved every exercise in at least one workshop' },
      test: function (s) {
        if (!s || !Array.isArray(s.perWorkshop)) return false;
        for (var i = 0; i < s.perWorkshop.length; i++) {
          var w = s.perWorkshop[i];
          if (w && num(w.total) > 0 && num(w.solved) === num(w.total)) return true;
        }
        return false;
      }
    },
    {
      id: 'critical-clear',
      icon: '🚨',
      name: { th: 'สยบระดับ Critical', en: 'Critical Sweep' },
      desc: { th: 'แก้โจทย์ระดับ Critical ผ่านครบทุกข้อ', en: 'Solved every Critical-severity exercise' },
      test: function (s) {
        var c = s && s.perSeverity && s.perSeverity.Critical;
        return !!c && num(c.total) > 0 && num(c.solved) === num(c.total);
      }
    },
    {
      id: 'injection-slayer',
      icon: '💉',
      name: { th: 'ปราบ Injection', en: 'Injection Slayer' },
      desc: { th: 'แก้โจทย์กลุ่ม Injection ผ่านครบทุกข้อ', en: 'Solved every Injection-category exercise' },
      test: function (s) {
        var pc = s && s.perCategory;
        if (!pc || typeof pc !== 'object') return false;
        var total = 0;
        var solved = 0;
        for (var key in pc) {
          if (!Object.prototype.hasOwnProperty.call(pc, key)) continue;
          if (!/injection/i.test(key)) continue;
          var c = pc[key];
          if (!c) continue;
          total += num(c.total);
          solved += num(c.solved);
        }
        return total > 0 && solved === total;
      }
    },
    {
      id: 'self-reliant',
      icon: '🧭',
      name: { th: 'ไม่ง้อคำใบ้', en: 'Self-Reliant' },
      desc: { th: 'แก้โจทย์ผ่าน 10 ข้อโดยไม่เปิดคำใบ้เลย', en: 'Solved 10 exercises without opening a single hint' },
      test: function (s) {
        return !!s && num(s.zeroHintSolves) >= 10;
      }
    },
    {
      id: 'quiz-ace',
      icon: '🧠',
      name: { th: 'เซียนควิซ', en: 'Quiz Ace' },
      desc: { th: 'ตอบควิซถูกตั้งแต่ 90% ขึ้นไป (ตอบแล้วอย่างน้อย 10 ข้อ)', en: 'Quiz accuracy of 90% or higher across at least 10 answered questions' },
      test: function (s) {
        if (!s || num(s.quizTotal) < 10) return false;
        return num(s.quizCorrect) / num(s.quizTotal) >= 0.9;
      }
    },
    {
      id: 'all-workshops',
      icon: '🗺️',
      name: { th: 'พิชิตครบหก Workshop', en: 'Grand Tour' },
      desc: { th: 'แก้โจทย์ผ่านครบทุกข้อของทั้ง 6 Workshop', en: 'Solved every exercise across all six workshops' },
      test: function (s) {
        if (!s || !Array.isArray(s.perWorkshop) || s.perWorkshop.length === 0) return false;
        for (var i = 0; i < s.perWorkshop.length; i++) {
          var w = s.perWorkshop[i];
          if (!w || num(w.total) === 0 || num(w.solved) !== num(w.total)) return false;
        }
        return true;
      }
    },
    {
      id: 'no-spoilers',
      icon: '🙈',
      name: { th: 'ไม่แอบดูเฉลย', en: 'No Spoilers' },
      desc: { th: 'แก้โจทย์ผ่านครบทุกข้อโดยไม่เปิดเฉลยแม้แต่ครั้งเดียว', en: 'Solved everything without revealing a single solution' },
      test: function (s) {
        return !!s && num(s.total) > 0 && num(s.solved) === num(s.total) && num(s.solutionsRevealed) === 0;
      }
    },
    {
      id: 'completionist',
      icon: '🏆',
      name: { th: 'ผู้พิชิตทั้งเวิร์กช็อป', en: 'Completionist' },
      desc: { th: 'แก้โจทย์ผ่านครบทั้ง 24 ข้อ — คุณคือ Security Champion ตัวจริง', en: 'Solved all 24 exercises — a true Security Champion' },
      test: function (s) {
        return !!s && num(s.total) > 0 && num(s.solved) === num(s.total);
      }
    }
  ];

  /* ---- computeStats ---- */

  function hintCountFor(comp, hintsMap, id) {
    var fromMap = hintsMap && typeof hintsMap[id] === 'number' ? hintsMap[id] : 0;
    var fromComp = comp && typeof comp.hintsUsed === 'number' ? comp.hintsUsed : 0;
    var n = Math.max(fromMap, fromComp);
    if (!isFinite(n) || n < 0) n = 0;
    return n;
  }

  /*
   * progress: persisted state
   *   { completed, hints, revealed, quiz, learner, ... }
   * flat: [ { workshop, ex, index }, ... ] for all exercises.
   *
   * Returns the Stats shape from Two supporting fields — perCategory
   * and zeroHintSolves — are included because the injection-slayer and
   * self-reliant badge tests are pure functions of Stats alone.
   */
  function computeStats(progress, flat) {
    progress = (progress && typeof progress === 'object') ? progress : {};
    var completed = (progress.completed && typeof progress.completed === 'object') ? progress.completed : {};
    var hintsMap = (progress.hints && typeof progress.hints === 'object') ? progress.hints : {};
    var revealedMap = (progress.revealed && typeof progress.revealed === 'object') ? progress.revealed : {};
    var quizMap = (progress.quiz && typeof progress.quiz === 'object') ? progress.quiz : {};
    flat = Array.isArray(flat) ? flat : [];

    var solved = 0;
    var total = 0;
    var xp = 0;
    var maxXp = 0;
    var quizCorrect = 0;
    var quizTotal = 0;
    var hintsUsed = 0;
    var solutionsRevealed = 0;
    var zeroHintSolves = 0;

    var perWorkshop = [];
    var workshopAt = {};
    var perSeverity = {};
    for (var si = 0; si < SEVERITIES.length; si++) {
      perSeverity[SEVERITIES[si]] = { solved: 0, total: 0 };
    }
    var perCategory = {};

    for (var i = 0; i < flat.length; i++) {
      var item = flat[i];
      if (!item || !item.ex || typeof item.ex !== 'object') continue;
      var ex = item.ex;
      var id = typeof ex.id === 'string' ? ex.id : String(i);
      var points = num(ex.points);

      total++;
      maxXp += points;

      var quizLen = Array.isArray(ex.quiz) ? ex.quiz.length : 0;
      maxXp += quizLen * QUIZ_XP;

      /* workshop bucket (display order preserved) */
      var w = (item.workshop && typeof item.workshop === 'object') ? item.workshop : {};
      var wid = typeof w.id === 'string' ? w.id : 'workshop';
      if (!Object.prototype.hasOwnProperty.call(workshopAt, wid)) {
        workshopAt[wid] = perWorkshop.length;
        perWorkshop.push({ id: wid, title: w.title || wid, solved: 0, total: 0 });
      }
      var wkBucket = perWorkshop[workshopAt[wid]];
      wkBucket.total++;

      /* severity bucket */
      var sevBucket = perSeverity[ex.severity];
      if (!sevBucket) {
        sevBucket = perSeverity[ex.severity] = { solved: 0, total: 0 };
      }
      sevBucket.total++;

      /* category bucket, keyed by the English category name */
      var catKey = 'Other';
      if (ex.category && typeof ex.category === 'object' && typeof ex.category.en === 'string' && ex.category.en) {
        catKey = ex.category.en;
      } else if (typeof ex.category === 'string' && ex.category) {
        catKey = ex.category;
      }
      var catBucket = perCategory[catKey];
      if (!catBucket) {
        catBucket = perCategory[catKey] = { solved: 0, total: 0 };
      }
      catBucket.total++;

      /* hints / reveals (informational totals) */
      var comp = Object.prototype.hasOwnProperty.call(completed, id) ? completed[id] : null;
      if (comp && typeof comp !== 'object') comp = {};
      var rawHints = hintCountFor(comp, hintsMap, id);
      hintsUsed += Math.min(MAX_HINTS, rawHints);
      if (revealedMap[id]) solutionsRevealed++;

      /* solve XP */
      if (comp) {
        solved++;
        wkBucket.solved++;
        sevBucket.solved++;
        catBucket.solved++;

        var hc = Math.min(MAX_HINTS, rawHints);
        if (hc === 0) zeroHintSolves++;

        var revealedEarly = comp.revealed === true ||
          (comp.revealed === undefined && revealedMap[id] === true);

        var earned = points - hc * HINT_PENALTY * points;
        if (revealedEarly) earned = Math.min(earned, REVEAL_CAP * points);
        earned = Math.round(earned);
        if (earned < 0) earned = 0;
        xp += earned;
      }

      /* quiz XP */
      var answers = quizMap[id];
      if (answers && typeof answers === 'object' && quizLen > 0) {
        for (var qi = 0; qi < quizLen; qi++) {
          if (!Object.prototype.hasOwnProperty.call(answers, qi)) continue;
          var q = ex.quiz[qi];
          if (!q || typeof q.answer !== 'number') continue;
          quizTotal++;
          if (Number(answers[qi]) === q.answer) {
            quizCorrect++;
            xp += QUIZ_XP;
          }
        }
      }
    }

    /* rank */
    var rank = RANKS[0];
    var nextRank = null;
    for (var r = 0; r < RANKS.length; r++) {
      if (xp >= RANKS[r].min) {
        rank = RANKS[r];
      } else {
        nextRank = RANKS[r];
        break;
      }
    }
    var xpToNext = nextRank ? nextRank.min - xp : 0;

    var stats = {
      solved: solved,
      total: total,
      percent: total > 0 ? Math.round((solved / total) * 100) : 0,
      xp: xp,
      maxXp: maxXp,
      rank: rank,
      nextRank: nextRank,
      xpToNext: xpToNext,
      quizCorrect: quizCorrect,
      quizTotal: quizTotal,
      hintsUsed: hintsUsed,
      solutionsRevealed: solutionsRevealed,
      zeroHintSolves: zeroHintSolves,
      perWorkshop: perWorkshop,
      perSeverity: perSeverity,
      perCategory: perCategory,
      badges: []
    };

    /* earned badges only; a broken test must never break stats */
    for (var b = 0; b < BADGES.length; b++) {
      var earned2 = false;
      try {
        earned2 = !!BADGES[b].test(stats);
      } catch (e) {
        earned2 = false;
      }
      if (earned2) stats.badges.push(BADGES[b]);
    }

    return stats;
  }

  /* ---- certificate ---- */

  function esc(value) {
    var s = (value === null || value === undefined) ? '' : String(value);
    return s.replace(/[&<>"']/g, function (ch) {
      switch (ch) {
        case '&': return '&amp;';
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '"': return '&quot;';
        default: return '&#39;';
      }
    });
  }

  function localize(x) {
    var i18n = global.I18N;
    if (i18n && typeof i18n.L === 'function') return i18n.L(x);
    if (x === null || x === undefined) return '';
    if (typeof x === 'string') return x;
    if (typeof x === 'object') {
      if (typeof x.th === 'string' && x.th) return x.th;
      if (typeof x.en === 'string' && x.en) return x.en;
    }
    return '';
  }

  function tr(key, fallback, params) {
    var i18n = global.I18N;
    if (i18n && typeof i18n.t === 'function') return i18n.t(key, fallback, params);
    var s = (fallback !== undefined && fallback !== null) ? String(fallback) : String(key);
    if (params) {
      s = s.replace(/\{(\w+)\}/g, function (whole, p) {
        return Object.prototype.hasOwnProperty.call(params, p) ? String(params[p]) : whole;
      });
    }
    return s;
  }

  function currentLang() {
    var i18n = global.I18N;
    return (i18n && i18n.lang === 'en') ? 'en' : 'th';
  }

  var TH_MONTHS = ['มกราคม', 'กุมภาพันธ์', 'มีนาคม', 'เมษายน', 'พฤษภาคม', 'มิถุนายน',
    'กรกฎาคม', 'สิงหาคม', 'กันยายน', 'ตุลาคม', 'พฤศจิกายน', 'ธันวาคม'];
  var EN_MONTHS = ['January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'];

  /* '2026-08-07' -> '7 สิงหาคม 2569' (Buddhist era) or '7 August 2026' */
  function formatDate(dateISO, lang) {
    var m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(dateISO || ''));
    if (!m) return String(dateISO || '');
    var year = parseInt(m[1], 10);
    var month = parseInt(m[2], 10);
    var day = parseInt(m[3], 10);
    if (month < 1 || month > 12 || day < 1 || day > 31) return String(dateISO);
    if (lang === 'en') return day + ' ' + EN_MONTHS[month - 1] + ' ' + year;
    return day + ' ' + TH_MONTHS[month - 1] + ' ' + (year + 543);
  }

  /* FNV-1a 32-bit — deterministic, non-cryptographic. */
  function fnv1a(str, seed) {
    var h = seed >>> 0;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      /* h *= 16777619 (mod 2^32) without overflowing double precision */
      h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    return h >>> 0;
  }

  function hex8(n) {
    return ('00000000' + (n >>> 0).toString(16).toUpperCase()).slice(-8);
  }

  /*
   * Deterministic verification id: same name + stats + date always produce
   * the same id. Explicitly NOT a cryptographic signature or a credential.
   */
  function certId(name, stats, dateISO) {
    var rankEn = (stats.rank && stats.rank.name && typeof stats.rank.name.en === 'string')
      ? stats.rank.name.en : '';
    var basis = [
      String(name === null || name === undefined ? '' : name),
      num(stats.solved), num(stats.total), num(stats.xp),
      num(stats.quizCorrect), num(stats.quizTotal),
      rankEn,
      String(dateISO || '')
    ].join('|');
    var a = fnv1a(basis, 0x811c9dc5);
    var b = fnv1a(basis + '#scw', 0x01000193);
    var h = hex8(a) + hex8(b);
    return 'SCW-' + h.slice(0, 4) + '-' + h.slice(4, 8) + '-' + h.slice(8, 12);
  }

  /*
   * Self-contained, escaped, print-friendly certificate markup.
   * Uses only the .cert-* class names; layout and
   * A4/print styling belong to css/styles.css. No JS needed after render.
   */
  function certificateHTML(input) {
    input = (input && typeof input === 'object') ? input : {};
    var stats = (input.stats && typeof input.stats === 'object') ? input.stats : {};
    var lang = currentLang();
    var rank = (stats.rank && typeof stats.rank === 'object') ? stats.rank : RANKS[0];
    var badges = Array.isArray(stats.badges) ? stats.badges : [];
    var dateISO = input.dateISO || '';

    var quizText = num(stats.quizCorrect) + '/' + num(stats.quizTotal);
    var solvedText = num(stats.solved) + '/' + num(stats.total);
    var rankText = (rank.icon ? rank.icon + ' ' : '') + localize(rank.name);

    function stat(numText, labelText) {
      return '<div class="cert-stat">' +
        '<div class="cert-stat-num">' + esc(numText) + '</div>' +
        '<div class="cert-stat-label">' + esc(labelText) + '</div>' +
        '</div>';
    }

    var badgesHTML = '';
    if (badges.length > 0) {
      var chips = [];
      for (var i = 0; i < badges.length; i++) {
        var bd = badges[i];
        if (!bd) continue;
        chips.push('<span class="cert-badge">' +
          esc((bd.icon ? bd.icon + ' ' : '') + localize(bd.name)) +
          '</span>');
      }
      badgesHTML = '<div class="cert-badges">' + chips.join('') + '</div>';
    }

    return '' +
      '<div class="cert">' +
        '<div class="cert-sheet">' +
          '<div class="cert-crest">🛡️</div>' +
          '<div class="cert-kicker">' + esc(tr('cert.kicker', 'Secure Coding Workshop')) + '</div>' +
          '<h1 class="cert-title">' + esc(tr('cert.title', 'ประกาศนียบัตร')) + '</h1>' +
          '<div class="cert-line">' + esc(tr('cert.awardedTo', 'มอบให้แก่')) + '</div>' +
          '<div class="cert-name">' + esc(input.name) + '</div>' +
          '<div class="cert-line">' + esc(tr('cert.body', 'ผู้ผ่านการอบรมและแก้ช่องโหว่ด้านความปลอดภัยได้สำเร็จ')) + '</div>' +
          '<div class="cert-stats">' +
            stat(solvedText, tr('cert.statSolved', 'โจทย์ที่แก้ผ่าน')) +
          '</div>' +
          badgesHTML +
          '<div class="cert-foot">' +
            '<span>' + esc(tr('cert.date', 'วันที่')) + ': ' + esc(formatDate(dateISO, lang)) + '</span>' +
            '<span class="cert-id">' + esc(tr('cert.verifyLabel', 'รหัสตรวจสอบ')) + ' ' + esc(certId(input.name, stats, dateISO)) + '</span>' +
            '<span>' + esc(tr('cert.disclaimer', 'ใช้อ้างอิงภายในเวิร์กช็อปเท่านั้น — ไม่ใช่วุฒิบัตรทางการ')) + '</span>' +
          '</div>' +
        '</div>' +
      '</div>';
  }

  var api = {
    RANKS: RANKS,
    BADGES: BADGES,
    computeStats: computeStats,
    certificateHTML: certificateHTML
  };

  global.Gamify = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
