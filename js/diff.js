/* ============================================================================
 * diff.js — window.Diff
 * line diff แบบ LCS: a = โค้ดของผู้เรียน, b = เฉลย
 * del = บรรทัดที่มีเฉพาะใน a, add = บรรทัดที่มีเฉพาะใน b
 * กันตาราง O(n·m) ระเบิด: ตัดหัว/ท้ายที่เหมือนกันก่อน แล้วถ้าส่วนกลาง
 * ยังยาวเกิน ~2000 บรรทัดด้านใดด้านหนึ่ง → fallback เป็น del ทั้งหมด
 * ตามด้วย add ทั้งหมด แทนการจองเมทริกซ์มหึมา
 * ==========================================================================*/
(function (global) {
  'use strict';

  const MAX_LCS_LINES = 2000;

  function toLines(s) {
    s = s == null ? '' : String(s);
    return s === '' ? [] : s.split('\n');
  }

  function entry(type, text, aLine, bLine) {
    return { type: type, text: text, aLine: aLine, bLine: bLine };
  }

  function lines(a, b) {
    const A = toLines(a);
    const B = toLines(b);
    const n = A.length;
    const m = B.length;
    const out = [];

    // ตัด prefix/suffix ที่เหมือนกัน — เคสปกติ (แก้ไม่กี่บรรทัด) จะเหลือนิดเดียว
    let pre = 0;
    while (pre < n && pre < m && A[pre] === B[pre]) pre++;
    let endA = n;
    let endB = m;
    while (endA > pre && endB > pre && A[endA - 1] === B[endB - 1]) { endA--; endB--; }

    for (let p = 0; p < pre; p++) out.push(entry('ctx', A[p], p + 1, p + 1));

    const midA = endA - pre;
    const midB = endB - pre;

    if (midA > MAX_LCS_LINES || midB > MAX_LCS_LINES) {
      // ใหญ่เกิน — คืนผลหยาบแต่ถูกต้องเชิงเซต และเร็วแน่นอน
      for (let i = pre; i < endA; i++) out.push(entry('del', A[i], i + 1, null));
      for (let j = pre; j < endB; j++) out.push(entry('add', B[j], null, j + 1));
    } else if (midA > 0 || midB > 0) {
      // ตาราง LCS แบบแบน (Uint16Array — ค่าสูงสุด 2000 พอดีช่วง)
      const w = midB + 1;
      const t = new Uint16Array((midA + 1) * w);
      for (let i = 1; i <= midA; i++) {
        const ai = A[pre + i - 1];
        const row = i * w;
        const prev = row - w;
        for (let j = 1; j <= midB; j++) {
          if (ai === B[pre + j - 1]) t[row + j] = t[prev + j - 1] + 1;
          else {
            const up = t[prev + j];
            const left = t[row + j - 1];
            t[row + j] = up > left ? up : left;
          }
        }
      }
      // backtrack (สร้างย้อนกลับแล้ว reverse) — เลือกให้ del มาก่อน add
      const rev = [];
      let i = midA;
      let j = midB;
      while (i > 0 && j > 0) {
        if (A[pre + i - 1] === B[pre + j - 1]) {
          rev.push(entry('ctx', A[pre + i - 1], pre + i, pre + j));
          i--; j--;
        } else if (t[i * w + j - 1] >= t[(i - 1) * w + j]) {
          rev.push(entry('add', B[pre + j - 1], null, pre + j));
          j--;
        } else {
          rev.push(entry('del', A[pre + i - 1], pre + i, null));
          i--;
        }
      }
      while (j > 0) { rev.push(entry('add', B[pre + j - 1], null, pre + j)); j--; }
      while (i > 0) { rev.push(entry('del', A[pre + i - 1], pre + i, null)); i--; }
      for (let k = rev.length - 1; k >= 0; k--) out.push(rev[k]);
    }

    // suffix ที่เหมือนกัน
    for (let i = endA; i < n; i++) {
      out.push(entry('ctx', A[i], i + 1, endB + (i - endA) + 1));
    }
    return out;
  }

  function stats(result) {
    const s = { added: 0, removed: 0, same: 0 };
    const list = result || [];
    for (let i = 0; i < list.length; i++) {
      if (list[i].type === 'add') s.added++;
      else if (list[i].type === 'del') s.removed++;
      else s.same++;
    }
    return s;
  }

  const api = { lines: lines, stats: stats };
  global.Diff = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
