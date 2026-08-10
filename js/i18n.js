/*
 * js/i18n.js — window.I18N
 * UI string table + language state for the Secure Coding Workshop.
 * Thai (th) is the primary language, English (en) the secondary.
 * Zero dependencies. Works from file:// and under require() in Node.
 * See,, and docs/I18N_KEYS.md.
 */
(function (global) {
  'use strict';

  var STORE_KEY = 'scw_lang';

  var LANGS = [
    { code: 'th', label: 'ไทย' },
    { code: 'en', label: 'English' }
  ];

  /*
   * Canonical UI string table. Every key from docs/I18N_KEYS.md is defined
   * here for both th and en. Keys may be added but never removed.
   */
  var TABLE = {
    /* ---- app shell ---- */
    'app.title': {
      th: 'Secure Coding Workshop',
      en: 'Secure Coding Workshop'
    },
    'app.subtitle': {
      th: 'ฝึกแก้ช่องโหว่จริง · Java & Node.js',
      en: 'Fix real vulnerabilities, hands-on · Java & Node.js'
    },

    /* ---- navigation / sidebar ---- */
    'nav.intro': { th: 'Introduction', en: 'Introduction' },
    'intro.title': { th: 'Introduction', en: 'Introduction' },
    'intro.roster': { th: 'ช่องโหว่ 24 ข้อที่จะเจอ', en: 'The 24 vulnerabilities you will meet' },
    'intro.rosterLead': { th: 'กดที่ชื่อเพื่อกระโดดไปที่ข้อนั้นได้เลย', en: 'Click any title to jump straight to that exercise' },
    'intro.start': { th: 'เริ่มโจทย์แรก', en: 'Start the first exercise' },
    'nav.dashboard': {
      th: 'ภาพรวม',
      en: 'Dashboard'
    },
    'nav.checklist': {
      th: 'Secure Coding Checklist',
      en: 'Secure Coding Checklist'
    },
    'nav.certificate': {
      th: 'ใบประกาศ',
      en: 'Certificate'
    },
    'nav.searchPlaceholder': {
      th: 'ค้นหาโจทย์ / CWE / OWASP',
      en: 'Search exercises / CWE / OWASP'
    },
    'nav.noResults': {
      th: 'ไม่เจอโจทย์ที่ค้นหา',
      en: 'No exercises match your search'
    },
    'nav.reset': {
      th: 'ล้างความคืบหน้าทั้งหมด',
      en: 'Reset all progress'
    },
    'nav.resetConfirm': {
      th: 'ล้างความคืบหน้าและโค้ดที่แก้ไว้ทั้งหมด?',
      en: 'Erase all progress and every edit you have made?'
    },
    'nav.minutes': {
      th: '{n} นาที',
      en: '{n} min'
    },

    /* ---- progress / XP ---- */
    'progress.label': {
      th: 'ความคืบหน้า',
      en: 'Progress'
    },
    'progress.xp': {
      th: '{n} XP',
      en: '{n} XP'
    },
    'progress.toNext': {
      th: 'อีก {n} XP ถึงระดับ {a}',
      en: '{n} XP to reach {a}'
    },
    'progress.maxRank': {
      th: 'ถึงระดับสูงสุดแล้ว',
      en: 'Highest rank reached'
    },

    /* ---- dashboard ---- */
    'dash.welcome': {
      th: 'ยินดีต้อนรับสู่เวิร์กช็อป Secure Coding',
      en: 'Welcome to the Secure Coding Workshop'
    },
    'dash.lead': {
      th: 'เรียนจากช่องโหว่จริง 16 ข้อ อ้างอิงมาตรฐาน OWASP Top 10 (2021) และ CWE',
      en: '16 real vulnerabilities, mapped to OWASP Top 10 (2021) and CWE.'
    },
    'dash.continue': {
      th: 'ทำต่อจากที่ค้างไว้',
      en: 'Continue where you left off'
    },
    'dash.start': {
      th: 'เริ่มโจทย์แรก',
      en: 'Start the first exercise'
    },
    'dash.solved': {
      th: 'แก้แล้ว',
      en: 'Solved'
    },
    'dash.badges': {
      th: 'เหรียญที่ได้รับ',
      en: 'Badges earned'
    },
    'dash.noBadges': {
      th: 'ยังไม่มีเหรียญ — ผ่านโจทย์แรกก่อน แล้วเริ่มสะสมได้เลย',
      en: 'No badges yet — solve your first exercise to start collecting'
    },
    'dash.byWorkshop': {
      th: 'ความคืบหน้าตาม Workshop',
      en: 'Progress by workshop'
    },
    'dash.bySeverity': {
      th: 'ตามระดับความรุนแรง',
      en: 'By severity'
    },
    'dash.quizScore': {
      th: 'คะแนนควิซ',
      en: 'Quiz score'
    },
    'dash.howItWorks': {
      th: 'เวิร์กช็อปนี้ทำงานยังไง',
      en: 'How this workshop works'
    },
    'dash.step1': {
      th: 'อ่านช่องโหว่ · การโจมตี · แนวทางแก้',
      en: 'Read the vulnerability · the attack · the fix'
    },
    'dash.step2': {
      th: 'ยิง payload ใน Attack Lab ดูผลจริง ๆ',
      en: 'Fire payloads in the Attack Lab to see the real effect'
    },
    'dash.step3': {
      th: 'แก้โค้ดใน editor แล้วกดตรวจ',
      en: 'Fix the code in the editor, then hit Check'
    },
    'dash.step4': {
      th: 'ทำควิซเช็คความเข้าใจ',
      en: 'Take the quiz to confirm your understanding'
    },

    /* ---- exercise sections ---- */
    'sec.vuln': {
      th: 'ช่องโหว่',
      en: 'The vulnerability'
    },
    'sec.attack': {
      th: 'โดนโจมตียังไง',
      en: 'How the attack works'
    },
    'sec.fix': {
      th: 'เขียนอย่างไรให้ปลอดภัย',
      en: 'How to write it safely'
    },
    'sec.impact': {
      th: 'ผลกระทบทางธุรกิจ',
      en: 'Business impact'
    },
    'sec.diagram': {
      th: 'ดู flow จริงของมัน',
      en: 'How it actually flows'
    },
    'sec.diagramLead': {
      th: 'สลับดูได้ว่า "โจมตี" กับ "ป้องกัน" ต่างกันตรงไหน — ระบบเดียวกัน คนละพฤติกรรม',
      en: 'Toggle between the attack and the defence — same system, different behaviour'
    },
    'sec.lab': {
      th: 'Attack Lab — ลองยิงจริง',
      en: 'Attack Lab — try the attack live'
    },
    'sec.labLead': {
      th: 'เลือก payload แล้วดูว่าโค้ดที่มีช่องโหว่กับโค้ดที่แก้แล้วตอบต่างกันยังไง',
      en: 'Pick a payload and watch how the vulnerable code and the fixed code respond differently'
    },
    'sec.whatIsIt': { th: 'ช่องโหว่นี้คืออะไร', en: 'What this vulnerability is' },
    'sec.safeCode': { th: 'แนวทางแก้ — เทียบกับโค้ดด้านบน', en: 'How to fix it — diff against the code above' },
    'sec.safeLead': { th: 'อ่านแบบเดียวกับตอนดู commit: บรรทัด - คือของเดิมที่ต้องเอาออก บรรทัด + คือของใหม่ที่ใส่แทน', en: 'Read it like a commit: - is the old line to remove, + is the new line that replaces it' },
    'sec.safeGap': { th: '… ส่วนที่เหลือไม่ต้องแก้', en: '… the rest needs no change' },
    'sec.safeWhy': { th: 'บรรทัดที่เพิ่มเข้ามาทำหน้าที่อะไร', en: 'What the added lines do' },
    'sec.safeHow': { th: 'ทำยังไง', en: 'How:' },
    'sec.vulnCode': { th: 'ตัวอย่างโค้ดที่ไม่ปลอดภัย', en: 'The insecure code, annotated' },
    'sec.vulnWhy': { th: 'ทำไมถึงเป็นช่องโหว่', en: 'Why this is exploitable' },
    'sec.vulnFix': { th: 'แก้โดย', en: 'Fix:' },
    'sec.vulnNotYet': { th: 'ยังไม่ได้', en: 'The code never does this:' },
    'sec.vulnMissing': { th: 'ยังไม่มี', en: 'Still missing:' },
    'pitfall.myth': { th: 'วิธีที่มักใช้', en: 'Common approach' },
    'pitfall.real': { th: 'จริง ๆ แล้ว', en: 'Actually' },
    'sec.pitfalls': {
      th: 'สิ่งที่ Developer มักจะพลาดบ่อย',
      en: 'Common pitfalls (fixes that are not actually safe)'
    },
    'sec.codeReview': {
      th: 'ควรมองหาอะไรตอนทำ Code Review',
      en: 'What to look for in code review'
    },
    'testit.asInput': { th: 'ใส่ค่านี้ในช่อง input หรือใน URL แล้วดูผล', en: 'Paste this into the input field or URL' },
    'testit.asBody': { th: 'ส่ง JSON นี้เป็น request body', en: 'Send this JSON as the request body' },
    'testit.asFile': { th: 'ลองอัปโหลดไฟล์ที่ชื่อแบบนี้', en: 'Try uploading a file with this name' },
    'testit.asHeader': { th: 'ส่ง header นี้ไปกับ request', en: 'Send this header with the request' },
    'testit.asShell': { th: 'รันคำสั่งนี้ใน terminal', en: 'Run this command in a terminal' },
    'testit.asConsole': { th: 'พิมพ์บรรทัดนี้ใน DevTools Console', en: 'Type this line into the DevTools console' },
    'testit.asHtml': { th: 'เอา HTML นี้ไปวางไว้บนอีกเว็บหนึ่ง แล้วเปิดขณะยังล็อกอินอยู่', en: 'Host this HTML on another site and open it while still logged in' },
    'testit.cliOnly': { th: 'ทดสอบด้วยคำสั่งนี้', en: 'Test it with this command' },
    'testit.quick': { th: 'วิธีเร็ว — ใส่ค่านี้ในช่อง input แล้วดูผล', en: 'Quickest check — paste this into the input field' },
    'testit.cli': { th: 'หรือยิงจาก terminal', en: 'Or run it from a terminal' },
    'sec.testIt': {
      th: 'ทดสอบเองยังไง',
      en: 'How to test it yourself'
    },
    'sec.caseStudy': {
      th: 'เคสจริงที่เคยเกิด',
      en: 'A real incident'
    },
    'sec.tabLearn': { th: 'Vulnerability Information', en: 'Vulnerability Information' },
    'sec.tabPractice': { th: 'Coding Practice', en: 'Coding Practice' },
    'sec.tabQuiz': { th: 'Quiz', en: 'Quiz' },
    'sec.quiz': {
      th: 'ควิซเช็คความเข้าใจ',
      en: 'Knowledge check'
    },
    'sec.solution': {
      th: 'เฉลย',
      en: 'Solution'
    },
    'sec.hints': {
      th: 'คำใบ้',
      en: 'Hints'
    },
    'sec.diff': {
      th: 'เทียบโค้ดของคุณกับเฉลย',
      en: 'Compare your code with the solution'
    },
    'sec.refs': {
      th: 'อ่านเพิ่มเติม',
      en: 'Further reading'
    },

    /* ---- buttons ---- */
    'btn.check': {
      th: 'ตรวจคำตอบ',
      en: 'Check my fix'
    },
    'btn.reset': {
      th: 'รีเซ็ตโค้ด',
      en: 'Reset code'
    },
    'btn.hint': {
      th: 'คำใบ้',
      en: 'Hint'
    },
    'btn.solution': {
      th: 'ดูเฉลย',
      en: 'Show solution'
    },
    'btn.hideSolution': {
      th: 'ซ่อนเฉลย',
      en: 'Hide solution'
    },
    'btn.loadSolution': {
      th: 'โหลดเฉลยลง editor',
      en: 'Load solution into editor'
    },
    'btn.diff': {
      th: 'เทียบกับเฉลย',
      en: 'Diff against solution'
    },
    'btn.run': {
      th: 'จำลองการโจมตี',
      en: 'Simulate the attack'
    },
    'btn.prev': {
      th: 'ก่อนหน้า',
      en: 'Previous'
    },
    'btn.next': {
      th: 'ถัดไป',
      en: 'Next'
    },
    'btn.readMore': {
      th: 'อ่านต่อ',
      en: 'Read more'
    },
    'btn.readLess': {
      th: 'ย่อกลับ',
      en: 'Show less'
    },
    'btn.copy': {
      th: 'คัดลอก',
      en: 'Copy'
    },
    'btn.print': {
      th: 'พิมพ์ / บันทึกเป็น PDF',
      en: 'Print / save as PDF'
    },
    'btn.close': {
      th: 'ปิด',
      en: 'Close'
    },

    /* ---- attack lab ---- */
    'lab.payload': {
      th: 'Payload',
      en: 'Payload'
    },
    'lab.custom': {
      th: 'ลองใส่ payload เอง',
      en: 'Try your own payload'
    },
    'lab.vulnerable': {
      th: 'โค้ดที่มีช่องโหว่',
      en: 'Vulnerable code'
    },
    'lab.secure': {
      th: 'โค้ดที่แก้แล้ว',
      en: 'Fixed code'
    },
    'lab.unavailable': {
      th: 'โจทย์นี้ไม่มี simulation ให้ลอง',
      en: 'No simulation is available for this exercise'
    },
    'lab.frameNote': {
      th: 'แสดงผลใน frame แบบ sandbox (ปิด script ไว้เพื่อความปลอดภัย)',
      en: 'Rendered in a sandboxed frame (scripts are disabled for safety)'
    },

    /* ---- grading results ---- */
    'result.passAll': {
      th: 'ผ่านครบทุกข้อ ({a}/{b}) — เยี่ยมมาก',
      en: 'All checks passed ({a}/{b}) — nicely done'
    },
    'result.partial': {
      th: 'ผ่าน {a}/{b} ข้อ — แก้ตามลิสต์ข้างล่างแล้วลองอีกที',
      en: 'Passed {a}/{b} checks — fix the items below and try again'
    },
    'result.tooShort': {
      th: 'โค้ดสั้นเกินไป — แก้ใน editor ก่อนค่อยกดตรวจ',
      en: 'Your code is too short — edit it in the editor before checking'
    },
    'result.trapTitle': {
      th: 'ระวัง — วิธีนี้ยังไม่ปลอดภัยจริง',
      en: 'Careful — this approach is not actually safe'
    },
    'result.solvedAlready': {
      th: 'โจทย์นี้คุณแก้ผ่านแล้ว',
      en: 'You have already solved this exercise'
    },

    /* ---- hints ---- */
    'hint.more': {
      th: 'กด "คำใบ้" อีกทีถ้าอยากดูเพิ่ม',
      en: 'Press "Hint" again for the next one'
    },
    'hint.tryFirst': { th: 'ลองแก้เองก่อนสักรอบ แล้วค่อยเปิดคำใบ้', en: 'Try it yourself first, then open a hint' },
    'hint.cost': {
      th: 'เปิดคำใบ้แล้ว XP ของโจทย์นี้จะลดลง 15%',
      en: "Revealing a hint reduces this exercise's XP by 15%"
    },
    'hint.solutionCost': {
      th: 'เปิดเฉลยก่อนทำผ่าน XP ของโจทย์นี้จะโดนล็อกไว้ที่ 40%',
      en: "Revealing the solution before you pass caps this exercise's XP at 40%"
    },

    /* ---- quiz ---- */
    'quiz.correct': {
      th: 'ถูกต้อง',
      en: 'Correct'
    },
    'quiz.wrong': {
      th: 'ยังไม่ใช่',
      en: 'Not quite'
    },
    'quiz.why': {
      th: 'ทำไมข้อนี้ถูก',
      en: 'Why this answer is right'
    },
    'quiz.whyWrong': {
      th: 'ทำไมข้อที่เลือกถึงไม่ใช่',
      en: 'Why the answer you picked is wrong'
    },
    'quiz.score': {
      th: 'ตอบถูก {a}/{b} ข้อ',
      en: '{a}/{b} answered correctly'
    },
    'quiz.question': {
      th: 'ข้อ {n}',
      en: 'Question {n}'
    },

    /* ---- diff view ---- */
    'diff.yours': {
      th: 'โค้ดของคุณ',
      en: 'Your code'
    },
    'diff.solution': {
      th: 'เฉลย',
      en: 'Solution'
    },
    'diff.same': {
      th: 'โค้ดของคุณตรงกับเฉลยทุกบรรทัด',
      en: 'Your code matches the solution line for line'
    },

    /* ---- exercise metadata ---- */
    'meta.severity': {
      th: 'ความรุนแรง',
      en: 'Severity'
    },
    'meta.cwe': {
      th: 'CWE',
      en: 'CWE'
    },
    'meta.owasp': {
      th: 'OWASP',
      en: 'OWASP'
    },
    'meta.time': {
      th: 'เวลาโดยประมาณ',
      en: 'Estimated time'
    },
    'meta.points': {
      th: 'คะแนน',
      en: 'Points'
    },

    /* ---- severities ---- */
    'sev.Critical': {
      th: 'วิกฤต',
      en: 'Critical'
    },
    'sev.High': {
      th: 'สูง',
      en: 'High'
    },
    'sev.Medium': {
      th: 'ปานกลาง',
      en: 'Medium'
    },
    'sev.Low': {
      th: 'ต่ำ',
      en: 'Low'
    },

    /* ---- certificate ---- */
    'cert.title': {
      th: 'ประกาศนียบัตร',
      en: 'Certificate of Completion'
    },
    'cert.kicker': {
      th: 'Secure Coding Workshop',
      en: 'Secure Coding Workshop'
    },
    'cert.awardedTo': {
      th: 'มอบให้แก่',
      en: 'Awarded to'
    },
    'cert.namePlaceholder': {
      th: 'พิมพ์ชื่อของคุณ',
      en: 'Type your name'
    },
    'cert.body': {
      th: 'ผู้ผ่านการอบรมและแก้ช่องโหว่ด้านความปลอดภัยได้สำเร็จ',
      en: 'for successfully completing the training and fixing real security vulnerabilities'
    },
    'cert.statSolved': {
      th: 'โจทย์ที่แก้ผ่าน',
      en: 'Exercises solved'
    },
    'cert.statXp': {
      th: 'คะแนนสะสม',
      en: 'XP earned'
    },
    'cert.statRank': {
      th: 'ระดับ',
      en: 'Rank'
    },
    'cert.statQuiz': {
      th: 'ควิซ',
      en: 'Quiz'
    },
    'cert.date': {
      th: 'วันที่',
      en: 'Date'
    },
    'cert.needName': {
      th: 'ใส่ชื่อก่อน ถึงจะสร้างใบประกาศได้',
      en: 'Enter your name to generate the certificate'
    },
    'cert.needProgress': {
      th: 'ผ่านอย่างน้อย 1 ข้อก่อน ถึงจะรับใบประกาศได้',
      en: 'Solve at least one exercise before claiming your certificate'
    },
    /* extra keys used by gamify.certificateHTML */
    'cert.verifyLabel': {
      th: 'รหัสตรวจสอบ',
      en: 'Verification code'
    },
    'cert.disclaimer': {
      th: 'ใช้อ้างอิงภายในเวิร์กช็อปเท่านั้น — ไม่ใช่วุฒิบัตรทางการ',
      en: 'For workshop reference only — not an accredited credential'
    },

    /* ---- checklist ---- */
    'checklist.title': {
      th: 'Secure Coding Checklist',
      en: 'Secure Coding Checklist'
    },
    'checklist.sub': {
      th: 'เช็คลิสต์ไว้ใช้ในงานประจำวัน',
      en: 'A checklist for your day-to-day development work'
    },
    'checklist.note': {
      th: 'อิงจาก OWASP Top 10 กับ OWASP Cheat Sheet Series — ปรับให้เข้ากับทีมของคุณได้เลย',
      en: "Based on the OWASP Top 10 and the OWASP Cheat Sheet Series — adapt it to your team's context"
    },

    /* ---- keyboard shortcuts ---- */
    'keys.title': {
      th: 'คีย์ลัด',
      en: 'Keyboard shortcuts'
    },
    'keys.check': {
      th: 'ตรวจคำตอบ',
      en: 'Check your fix'
    },
    'keys.search': {
      th: 'ค้นหา',
      en: 'Search'
    },
    'keys.nav': {
      th: 'โจทย์ก่อนหน้า / ถัดไป',
      en: 'Previous / next exercise'
    },
    'keys.dash': {
      th: 'ไปหน้าภาพรวม',
      en: 'Go to the dashboard'
    },
    'keys.help': {
      th: 'เปิดรายการคีย์ลัดนี้',
      en: 'Open this shortcut list'
    },
    'keys.esc': {
      th: 'ปิดหน้าต่างซ้อน',
      en: 'Close overlays'
    },

    /* ---- toggles & toasts ---- */
    'theme.toggle': {
      th: 'สลับธีมสว่าง/มืด',
      en: 'Toggle light/dark theme'
    },
    'lang.toggle': {
      th: 'สลับภาษา ไทย/English',
      en: 'Switch language ไทย/English'
    },
    'toast.copied': {
      th: 'คัดลอกแล้ว',
      en: 'Copied'
    },
    'toast.saved': {
      th: 'บันทึกความคืบหน้าแล้ว',
      en: 'Progress saved'
    },
    'toast.badge': {
      th: 'ได้เหรียญใหม่: {a}',
      en: 'New badge earned: {a}'
    },
    'toast.rank': {
      th: 'เลื่อนระดับเป็น {a}',
      en: 'Ranked up to {a}'
    }
  };

  /* ---------------------------------------------------------------- */

  var subscribers = [];

  function isValidLang(l) {
    return l === 'th' || l === 'en';
  }

  function loadStoredLang() {
    try {
      if (typeof global.localStorage !== 'undefined' && global.localStorage) {
        var v = global.localStorage.getItem(STORE_KEY);
        if (isValidLang(v)) return v;
      }
    } catch (e) {
      /* file://, private mode, disabled storage — fall through */
    }
    return 'th';
  }

  function storeLang(l) {
    try {
      if (typeof global.localStorage !== 'undefined' && global.localStorage) {
        global.localStorage.setItem(STORE_KEY, l);
      }
    } catch (e) {
      /* ignore — persistence is best-effort */
    }
  }

  function applyDocumentLang(l) {
    try {
      if (typeof document !== 'undefined' && document && document.documentElement) {
        document.documentElement.lang = l;
      }
    } catch (e) {
      /* no DOM — fine */
    }
  }

  var currentLang = loadStoredLang();
  applyDocumentLang(currentLang);

  /* Substitute {name} placeholders from params; unmatched ones stay intact. */
  function substitute(str, params) {
    if (!params || typeof str !== 'string') return str;
    return str.replace(/\{(\w+)\}/g, function (whole, p) {
      if (Object.prototype.hasOwnProperty.call(params, p) && params[p] !== undefined && params[p] !== null) {
        return String(params[p]);
      }
      return whole;
    });
  }

  /* LStr {th,en} | string | null | undefined -> string (lang -> th -> en -> '') */
  function L(x) {
    if (x === null || x === undefined) return '';
    if (typeof x === 'string') return x;
    if (typeof x === 'number' || typeof x === 'boolean') return String(x);
    if (typeof x === 'object') {
      var v = x[currentLang];
      if (typeof v === 'string' && v) return v;
      if (typeof x.th === 'string' && x.th) return x.th;
      if (typeof x.en === 'string' && x.en) return x.en;
    }
    return '';
  }

  function t(key, fallback, params) {
    var entry = Object.prototype.hasOwnProperty.call(TABLE, key) ? TABLE[key] : null;
    var s;
    if (entry) {
      s = entry[currentLang];
      if (typeof s !== 'string' || !s) s = entry.th;
      if (typeof s !== 'string' || !s) s = entry.en;
    }
    if (typeof s !== 'string') {
      s = (fallback !== undefined && fallback !== null) ? String(fallback) : String(key);
    }
    return substitute(s, params);
  }

  function has(key) {
    return Object.prototype.hasOwnProperty.call(TABLE, key);
  }

  function setLang(l) {
    if (!isValidLang(l)) return;
    if (l === currentLang) return;
    currentLang = l;
    storeLang(l);
    applyDocumentLang(l);
    var subs = subscribers.slice();
    for (var i = 0; i < subs.length; i++) {
      try {
        subs[i](currentLang);
      } catch (e) {
        /* one broken subscriber must not break the rest */
      }
    }
  }

  function onChange(cb) {
    if (typeof cb !== 'function') return function () {};
    subscribers.push(cb);
    return function unsubscribe() {
      var at = subscribers.indexOf(cb);
      if (at !== -1) subscribers.splice(at, 1);
    };
  }

  var api = {
    setLang: setLang,
    onChange: onChange,
    L: L,
    t: t,
    has: has,
    langs: LANGS,
    /* test-only: lets the test suite assert th+en coverage per key */
    _TABLE: TABLE
  };

  /* I18N.lang always reflects the current language. */
  try {
    Object.defineProperty(api, 'lang', {
      get: function () { return currentLang; },
      enumerable: true
    });
  } catch (e) {
    api.lang = currentLang;
  }

  global.I18N = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
