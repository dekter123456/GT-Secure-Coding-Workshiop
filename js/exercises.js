/* ============================================================================
 * js/exercises.js — the workshop REGISTRY
 *
 * This file must load FIRST among the data files (see the script order in
 * index.html, of the architecture doc). Exercise CONTENT lives in
 * js/data/w1.js … js/data/w6.js; each of those calls
 * SCW.registerWorkshop(...). In the browser, app.js calls SCW.finalize() at
 * init. Under Node, this file requires the data files itself, finalizes, and
 * exports { WORKSHOPS, SCW } for the test suite.
 *
 * Public surface:
 *   SCW.workshops               — the raw registration list
 *   SCW.registerWorkshop(w)     — called by each js/data/wN.js
 *   SCW.finalize()              — idempotent; sorts by `order`, assigns
 *                                 window.WORKSHOPS, returns it
 *   SCW.flatten()               — [ { workshop, ex, index } … ] display order
 *                                 (memoised; invalidated by finalize/register)
 *   SCW.findExercise(id)        — { workshop, ex, index } | null
 *   SCW.allExercises()          — [ ex … ]
 * ==========================================================================*/
(function (global) {
  'use strict';

  // A data file may (defensively) have created a minimal SCW before us —
  // keep anything already registered.
  const existing = global.SCW && Array.isArray(global.SCW.workshops)
    ? global.SCW.workshops
    : [];

  const SCW = global.SCW && typeof global.SCW === 'object' ? global.SCW : {};
  SCW.workshops = existing;

  // flatten() is called on every render pass, so memoise it. The cache is
  // invalidated whenever the roster can change (registerWorkshop, finalize).
  let flatCache = null;

  SCW.registerWorkshop = function (w) {
    SCW.workshops.push(w);
    flatCache = null;
  };

  /**
   * Idempotent finalize: safe to call any number of times.
   * Reassigns (never appends), sorting a copy by `order` so registration
   * order never matters and a second call cannot duplicate anything.
   */
  SCW.finalize = function () {
    SCW.workshops = SCW.workshops.slice().sort(function (a, b) {
      const ao = a && typeof a.order === 'number' ? a.order : 0;
      const bo = b && typeof b.order === 'number' ? b.order : 0;
      return ao - bo;
    });
    global.WORKSHOPS = SCW.workshops;
    flatCache = null;
    return global.WORKSHOPS;
  };

  /** [ { workshop, ex, index } … ] in display order. Memoised. */
  SCW.flatten = function () {
    if (flatCache) return flatCache;
    const out = [];
    let index = 0;
    SCW.workshops.forEach(function (w) {
      const exercises = w && Array.isArray(w.exercises) ? w.exercises : [];
      exercises.forEach(function (ex) {
        out.push({ workshop: w, ex: ex, index: index });
        index++;
      });
    });
    flatCache = out;
    return out;
  };

  /** Find one exercise by id → { workshop, ex, index } | null */
  SCW.findExercise = function (id) {
    const flat = SCW.flatten();
    for (let i = 0; i < flat.length; i++) {
      if (flat[i].ex && flat[i].ex.id === id) return flat[i];
    }
    return null;
  };

  /** Every exercise object, in display order. */
  SCW.allExercises = function () {
    return SCW.flatten().map(function (entry) { return entry.ex; });
  };

  global.SCW = SCW;

  // Under Node (the test suite), pull the data files in ourselves, finalize,
  // and export. In the browser the <script> tags load the data files and
  // app.js calls SCW.finalize() at init.
  if (typeof module !== 'undefined' && module.exports) {
    ['w1', 'w2', 'w3', 'w4', 'w5', 'w6'].forEach(function (n) {
      require('./data/' + n + '.js');
    });
    SCW.finalize();
    module.exports = { WORKSHOPS: global.WORKSHOPS, SCW: SCW };
  }
})(typeof window !== 'undefined' ? window : globalThis);
