/* ============================================================================
 * w6.js — Workshop 6: API Security & Business Logic
 *
 * เนื้อหาโจทย์ 3 ข้อ (ดูสัญญาข้อมูลใน:
 * 6.1 csrf — Cross-Site Request Forgery บนแอปที่ใช้ session cookie
 * 6.2 rate-limit — ล็อกอินไม่จำกัดอัตรา → brute-force / credential stuffing
 * 6.3 open-redirect — redirect ปลายทางที่ผู้ใช้ควบคุมได้
 *
 * ทุกสตริงที่ผู้เรียนเห็นเป็น { th, en } (ไทยเป็นภาษาหลัก)
 * โค้ดตัวอย่างอยู่ใน template literal — ระวังการ escape ` , ${ และ \\
 * ==========================================================================*/
(function (global) {
  'use strict';

  const WORKSHOP = {
    id: 'w6',
    order: 6,
    title: { th: 'Workshop 6: API Security & Business Logic', en: 'Workshop 6: API Security & Business Logic' },
    summary: {
      th: 'Workshop นี้เน้นช่องโหว่ระดับ API และ business logic ได้แก่ CSRF, การไม่จำกัดจำนวนครั้งของหน้า login และ open redirect',
      en: 'API-level and business-logic flaws: CSRF, login rate limiting, and open redirects'
    },
    goal: {
      th: 'จบ workshop นี้ คุณจะป้องกัน CSRF สำหรับระบบที่ใช้ cookie, ออกแบบ rate limiting ให้รับมือ brute-force และ credential stuffing และตรวจปลายทาง redirect ก่อนพาผู้ใช้ไปยัง URL อื่น',
      en: 'After this workshop you will be able to defend cookie-authenticated apps against CSRF, design login rate limiting that resists brute-force and credential stuffing, and validate redirect targets safely.'
    },

    exercises: [

 /* ================================================================
 * 6.1 CSRF
 * ============================================================== */
      {
        id: 'csrf',
        title: { th: 'Cross-Site Request Forgery (CSRF)', en: 'Cross-Site Request Forgery (CSRF)' },
        severity: 'High',
        cwe: 'CWE-352',
        owasp: 'A01:2021 – Broken Access Control',
        category: { th: 'Broken Access Control', en: 'Broken Access Control' },
        estMinutes: 15,
        points: 120,

        intro: {
          th: 'โค้ดปิด CSRF protection ทิ้งทั้งที่แอปล็อกอินด้วย session cookie browser แนบ cookie ให้เองกับทุก request ข้ามไซต์ เว็บของ attacker เลยสั่ง browser ของเหยื่อให้ยิง request เปลี่ยนสถานะ (เช่น POST /api/transfer) ในนามเหยื่อได้ ขอแค่เหยื่อเปิดหน้าเว็บอันตรายตอนที่ยังล็อกอินค้างอยู่',
          en: 'The code turns CSRF protection off even though the app authenticates with a session cookie. Because the browser attaches that cookie to every cross-site request automatically, an attacker page can make the victim’s browser fire a state-changing request (e.g. POST /api/transfer) as the victim — the victim only has to open a hostile page while still logged in.'
        },
        attack: {
          th: 'attacker ฝังฟอร์มที่ submit ตัวเองอัตโนมัติไว้ในหน้าเว็บ เช่น\n<form action="https://bank.example.com/api/transfer" method="POST">\n <input name="to" value="attacker">\n <input name="amount" value="100000">\n</form>\n<script>document.forms[0].submit()</script>\nพอเหยื่อที่ล็อกอิน bank ค้างอยู่เปิดหน้านี้ browser ก็แนบ SESSIONID ให้เอง เงินถูกโอนไปโดยเหยื่อไม่รู้ตัวเลย',
          en: 'The attacker embeds an auto-submitting form on a page:\n<form action="https://bank.example.com/api/transfer" method="POST">\n  <input name="to" value="attacker">\n  <input name="amount" value="100000">\n</form>\n<script>document.forms[0].submit()</script>\nWhen a victim who is logged in to the bank opens this page, the browser attaches SESSIONID automatically and the transfer succeeds without the victim knowing.'
        },
        fix: {
          th: 'เปิด CSRF protection กับทุกเมธอดที่เปลี่ยนสถานะ (POST/PUT/PATCH/DELETE) ด้วย token แบบ synchronizer หรือ double-submit ที่ผูกกับ session แล้วเช็ค Origin header เสริมอีกชั้น ตั้ง cookie เป็น SameSite=Lax และปฏิเสธ content-type ที่แอปไม่ได้ใช้ (เช่น text/plain) หัวใจที่ทำให้กันได้จริงคือ same-origin policy ทำให้ attacker อ่านหรือเดา token ข้ามไซต์ไม่ได้ เลยประกอบ request ที่ถูกต้องไม่ได้',
          en: 'Enable CSRF protection for state-changing methods (POST/PUT/PATCH/DELETE) using a synchronizer or double-submit token bound to the session, and verify the Origin header as a backup; set cookies to SameSite=Lax and reject content types the app does not use (e.g. text/plain). The real mechanism is that the attacker cannot read or guess the token across origins (same-origin policy), so they cannot forge a valid request.'
        },
        keyPoints: {
          vuln: [
            { th: 'โค้ดปิด CSRF protection ทั้งที่แอปล็อกอินด้วย session cookie', en: 'The code disables CSRF protection even though it authenticates with a session cookie' },
            { th: 'browser แนบ cookie ให้เองกับทุก request ข้ามไซต์', en: 'The browser attaches the cookie to every cross-site request automatically' },
            { th: 'เว็บของ attacker เลยยิง request เปลี่ยนสถานะในนามเหยื่อได้', en: 'An attacker page can then fire state-changing requests as the victim' }
          ],
          attack: [
            { th: 'attacker สร้างหน้าเว็บที่มีฟอร์ม auto-submit ไปยัง POST /api/transfer เมื่อเหยื่อเปิดหน้า browser จะส่ง request ไปยังระบบเป้าหมายทันที', en: 'Embed an auto-submitting form that POSTs /api/transfer to the victim app' },
            { th: 'เมื่อเหยื่อที่ยังล็อกอินอยู่เปิดหน้าเว็บของ attacker browser จะแนบ session cookie (SESSIONID) ไปกับ request ให้อัตโนมัติ ระบบจึงอาจมองว่าเป็นคำสั่งที่ผู้ใช้ส่งเอง', en: 'A logged-in victim opens the page and the browser attaches SESSIONID for them' },
            { th: 'ถ้า endpoint ตรวจเพียง session cookie request ที่ถูกบังคับจากเว็บ attacker อาจทำรายการสำเร็จในนามเหยื่อ โดย attacker ไม่ต้องรู้ password', en: 'The transfer completes without the victim noticing and without knowing any password' }
          ],
          fix: [
            { th: 'ใช้ CSRF token ที่ผูกกับ session และบังคับตรวจบน request ที่เปลี่ยนข้อมูล เพื่อพิสูจน์ว่า request มาจากหน้าเว็บของระบบ ไม่ใช่เว็บภายนอก', en: 'Enable a CSRF token (synchronizer/double-submit) bound to the session on state-changing methods' },
            { th: 'ตั้ง session cookie เป็น SameSite=Lax หรือค่าที่เหมาะกับระบบเพื่อลดการแนบ cookie ข้ามไซต์ และตรวจ Origin เป็นชั้นป้องกันเสริม', en: 'Set cookies to SameSite=Lax and verify the Origin header as a backup' },
            { th: 'จำกัด Content-Type ให้เหลือเฉพาะรูปแบบที่ API ใช้จริง เช่น application/json และปฏิเสธรูปแบบที่ไม่จำเป็นซึ่งอาจถูกใช้สร้าง cross-site request', en: 'Reject content types the app does not use, such as text/plain' }
          ]
        },
        impact: {
          th: 'attacker อาจทำให้ผู้ใช้ที่ล็อกอินอยู่ส่งคำสั่งสำคัญโดยไม่ตั้งใจ เช่น โอนเงิน เปลี่ยนอีเมล หรือแก้ข้อมูลบัญชี โดย attacker ไม่จำเป็นต้องรู้ password ของผู้ใช้',
          en: 'With a single link, the attacker makes a logged-in victim transfer money, change their email, or alter account settings in the victim’s name — silently.'
        },

        caseStudy: {
          year: 2007,
          title: {
            th: 'Gmail — CSRF ฉีดฟิลเตอร์อีเมลจนโดเมนถูกยึด (2007)',
            en: 'Gmail — CSRF email-filter injection leads to domain theft (2007)'
          },
          body: {
            th: 'กันยายน 2007 นักวิจัย pdp (GNUCITIZEN) เปิดเผยว่าหน้าเว็บอันตรายส่ง POST แบบ multipart/form-data ไปยัง Gmail เพื่อ "ฉีดฟิลเตอร์" เข้าบัญชีเหยื่อที่ล็อกอินอยู่ได้ (CSRF) ต่อมาพฤศจิกายน 2007 ผู้ใช้ชื่อ David Airey ถูกฉีดฟิลเตอร์ให้ส่งต่อและลบอีเมลอนุมัติการโอนโดเมน attacker จึงยึดโดเมน davidairey.com ไปได้ กรณีนี้แสดงว่า CSRF เปลี่ยน "การตั้งค่า" เงียบ ๆ ได้โดยไม่ต้องรู้ password ของเหยื่อเลย',
            en: 'In September 2007 researcher pdp (GNUCITIZEN) disclosed that a hostile page could send a multipart/form-data POST to Gmail to inject a mail filter into a logged-in victim’s account (CSRF). In November 2007 a user, David Airey, had a filter injected that forwarded and deleted domain-transfer approval emails, letting the attacker hijack the domain davidairey.com. It shows CSRF can silently change settings without ever knowing the victim’s password.'
          },
          source: {
            label: 'GNUCITIZEN — Google GMail E-mail Hijack Technique (pdp, 2007)',
            url: 'https://www.gnucitizen.org/blog/google-gmail-e-mail-hijack-technique/'
          }
        },

        codeReview: [
          { th: 'ถ้าเห็น `.csrf().disable()` หรือ `csrf.disable()` ใน Spring Security config ให้ตรวจต่อ ถ้าแอปยืนยันตัวตนด้วย session cookie นี่คือธงแดงเลย', en: 'Grep for `.csrf().disable()` or `csrf.disable()` in Spring Security config — a red flag if the app authenticates with a session cookie.' },
          { th: 'ตรวจว่าทุก route ที่เปลี่ยนสถานะ (POST/PUT/PATCH/DELETE) ตรวจ CSRF token หรือยัง แค่ตรวจว่า "ล็อกอินแล้ว" ไม่พอกัน CSRF', en: 'Every state-changing route (POST/PUT/PATCH/DELETE) must verify a CSRF token, not just that the user is authenticated.' },
          { th: 'เห็นใช้ `getHeader("Referer")` เป็นเกราะกัน CSRF ให้ตรวจต่อ Referer ถูก strip หรือทำให้ว่างได้ง่าย ควรยึด Origin header แทน', en: 'Watch for `getHeader("Referer")` used as the CSRF defense — Referer can be stripped or empty; rely on the Origin header instead.' },
          { th: 'ตรวจว่า session/CSRF cookie ตั้ง `SameSite` หรือยัง (`setSameSite("Lax")` / `sameSite: "lax"`) ถ้าไม่ตั้ง browser จะแนบ cookie ข้ามไซต์ให้', en: 'Check that the session/CSRF cookie sets `SameSite` (`setSameSite("Lax")` / `sameSite: "lax"`).' }
        ],

        testIt: {
          cmd: 'curl -i -X POST -b \'SESSIONID=<victim-session>\' -H \'Content-Type: application/x-www-form-urlencoded\' -d \'to=attacker&amount=100000\' https://bank.example.com/api/transfer',
          note: {
            th: 'ส่ง POST request ด้วย cookie แต่ไม่มี CSRF token: แอปที่มีช่องโหว่จะตอบ 200 และโอนเงินสำเร็จ; แอปที่แก้แล้วต้องตอบ 403 (missing/invalid CSRF token)',
            en: 'POST with the cookie but no CSRF token: a vulnerable app returns 200 and completes the transfer; a fixed app must return 403 (missing/invalid CSRF token).'
          }
        },

        pitfalls: [
          {
            title: { th: 'ข้าม CSRF token เพราะเป็น JSON API', en: '"We’re a JSON API, so CSRF doesn’t apply"' },
            why: {
              th: 'ถ้าคุณยืนยันตัวตนด้วย cookie มันยังโดนได้: ฟอร์ม HTML ส่ง content-type แบบ simple (application/x-www-form-urlencoded หรือ text/plain) ข้ามไซต์ได้โดยไม่ต้อง preflight และ browser แนบ cookie ให้เอง ถ้า endpoint ยอมรับ body เหล่านั้นก็ถูกปลอมได้ ส่วน SameSite=Lax ก็ยังปล่อยให้ top-level GET navigation ทำงาน จึงไม่พอถ้ามี state-changing GET',
              en: 'It does if you authenticate with cookies: an HTML form can send a simple content type (application/x-www-form-urlencoded or text/plain) cross-site with no preflight, and the browser attaches the cookie for you. If the endpoint accepts those bodies it can be forged. And SameSite=Lax still allows top-level GET navigation, so it is not enough if a GET changes state.'
            },
            short: {
              th: 'ถ้าระบบยืนยันตัวตนด้วย cookie ก็ยังมีความเสี่ยง CSRF เพราะฟอร์ม HTML สามารถส่ง simple request ข้ามไซต์ได้',
              en: 'Cookie auth is still vulnerable; an HTML form can POST a simple content type cross-site'
            }
          },
          {
            title: { th: 'ใช้ Referer header เป็นตัวกัน CSRF', en: '"Checking the Referer header is enough"' },
            why: {
              th: 'Referer หายได้บ่อย: Referrer-Policy, การเข้าจาก HTTPS ไป HTTP, พร็อกซี/ไฟร์วอลล์ หรือส่วนขยายความเป็นส่วนตัว ทำให้ Referer ว่าง โค้ดที่ "ผ่านเมื่อ Referer ว่าง" ก็ถูก bypass ส่วนโค้ดที่ "บล็อกเมื่อ Referer ว่าง" ก็พังกับผู้ใช้จริง ให้ใช้ Origin header (ถูกส่งกับ request ที่เปลี่ยนสถานะข้ามต้นทาง) ควบคู่กับ CSRF token',
              en: 'The Referer is often missing: Referrer-Policy, HTTPS→HTTP downgrades, proxies/firewalls, or privacy extensions can blank it. Code that "passes when Referer is empty" gets bypassed; code that "blocks when Referer is empty" breaks real users. Use the Origin header (sent on state-changing cross-origin requests) together with a CSRF token.'
            },
            short: {
              th: 'Referer หายได้บ่อยจน bypass หรือกระทบผู้ใช้จริง ให้ยึด Origin header + CSRF token',
              en: 'Referer is often missing, so it breaks or is bypassed; rely on Origin plus a CSRF token'
            }
          }
        ],

        languages: {
          java: {
            filename: 'SecurityConfig.java',
            lang: 'java',
            starter:
`import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

 // แอปนี้ล็อกอินด้วย session cookie (SESSIONID) และมี POST /api/transfer
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(form -> form.loginPage("/login"))
 // ปิด CSRF เพราะทีม frontend บ่นว่า token ทำให้ AJAX พัง
            .csrf(csrf -> csrf.disable());
        return http.build();
    }
}`,
            solution:
`import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(form -> form.loginPage("/login"))
 // เปิด CSRF protection ไว้สำหรับ state-changing methods (POST/PUT/DELETE)
 // เก็บ token ใน cookie ที่ JS อ่านได้ (double-submit)
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
        return http.build();
    }

 // ตั้ง SameSite=Lax + Secure บน session cookie เป็นชั้นป้องกันเสริม
    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setSameSite("Lax");
        serializer.setUseSecureCookie(true);
        return serializer;
    }
}`,
            explain: {
              th: 'เลิกเรียก.csrf(...).disable() แล้วเปิด CSRF protection ด้วย CookieCsrfTokenRepository ซึ่งวาง token ไว้ใน cookie ให้ frontend อ่านแล้วส่งกลับใน header (double-submit) Spring จะตรวจ token เฉพาะเมธอดที่เปลี่ยนสถานะ attacker อ่าน cookie/token ของโดเมนเราข้ามไซต์ไม่ได้ (same-origin policy) จึงปลอม request ไม่ได้ และตั้ง SameSite=Lax เพื่อกันไม่ให้ cookie ถูกแนบกับ POST ข้ามไซต์เป็นชั้นเสริม',
              en: 'Stop calling .csrf(...).disable() and enable CSRF protection with CookieCsrfTokenRepository, which places the token in a cookie the frontend reads and echoes back in a header (double-submit). Spring verifies the token on state-changing methods. The attacker cannot read our domain’s cookie/token cross-site (same-origin policy), so they cannot forge the request; SameSite=Lax additionally stops the cookie from riding along on cross-site POSTs.'
            },
            checks: [
              { id: 'no-csrf-disable', label: { th: 'ไม่ปิด CSRF protection', en: 'Do not disable CSRF protection' }, hint: { th: 'ลบ.csrf(csrf -> csrf.disable()) ออก แล้วตั้งค่า csrfTokenRepository แทน', en: 'Remove .csrf(csrf -> csrf.disable()) and configure csrfTokenRepository instead.' }, weight: 3, mustNotMatch: /csrf[\s\S]{0,40}\.disable\s*\(/ },
              { id: 'cookie-csrf-repo', label: { th: 'ใช้ CookieCsrfTokenRepository (double-submit)', en: 'Use CookieCsrfTokenRepository (double-submit)' }, hint: { th: 'ตั้ง.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())', en: 'Set .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).' }, weight: 2, mustMatch: /CookieCsrfTokenRepository/ },
              { id: 'csrf-token-repo-config', label: { th: 'ผูก token repository เข้ากับ csrf', en: 'Wire the token repository into csrf' }, hint: { th: 'เรียก.csrfTokenRepository(...) ภายใน.csrf(...)', en: 'Call .csrfTokenRepository(...) inside .csrf(...).' }, weight: 1, mustMatch: /csrfTokenRepository\s*\(/ },
              { id: 'samesite-lax', label: { th: 'ตั้ง cookie เป็น SameSite=Lax', en: 'Set the cookie to SameSite=Lax' }, hint: { th: 'ใช้ DefaultCookieSerializer แล้วเรียก setSameSite("Lax")', en: 'Use DefaultCookieSerializer and call setSameSite("Lax").' }, weight: 1, mustMatch: /setSameSite\s*\(\s*["']Lax["']\s*\)|SameSite\s*=\s*Lax/i }
            ],
            traps: [
              { id: 'referer-as-csrf-defense', match: /getHeader\s*\(\s*["']Referer["']/i, message: { th: 'การเช็ค Referer header ไม่ใช่การป้องกัน CSRF ที่เชื่อถือได้ — Referer หาย/ว่างได้ ให้ใช้ CSRF token และตรวจ Origin header แทน', en: 'Checking the Referer header is not a reliable CSRF defense — it can be stripped or empty. Use a CSRF token and verify the Origin header instead.' } },
              { id: 'ignoring-state-changing', match: /ignoringRequestMatchers|ignoringAntMatchers/, message: { th: 'การยกเว้น endpoint ที่เปลี่ยนสถานะ (เช่น /api/transfer) ออกจาก CSRF protection เท่ากับเปิดช่องโหว่กลับมา ให้ยกเว้นเฉพาะ endpoint stateless ที่ไม่ใช้ cookie จริง ๆ เท่านั้น', en: 'Excluding a state-changing endpoint (e.g. /api/transfer) from CSRF protection re-opens the hole. Only exempt genuinely stateless endpoints that do not use the session cookie.' } }
            ]
          },
          node: {
            filename: 'app.js',
            lang: 'js',
            starter:
`const express = require('express');
const cookieSession = require('cookie-session');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ล็อกอินด้วย session cookie
app.use(cookieSession({
  name: 'sid',
  keys: [process.env.SESSION_KEY]
}));

// โอนเงินระหว่างบัญชี — เป็น request ที่เปลี่ยนสถานะ (state-changing)
app.post('/api/transfer', (req, res) => {
  const { to, amount } = req.body;
  transfer(req.session.userId, to, amount);
  res.json({ ok: true });
});

module.exports = app;`,
            solution:
`const express = require('express');
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser(process.env.COOKIE_SECRET));

app.use(cookieSession({
  name: 'sid',
  keys: [process.env.SESSION_KEY],
  sameSite: 'lax',
  httpOnly: true,
  secure: true
}));

const { doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  cookieName: '__Host-csrf',
  cookieOptions: { sameSite: 'lax', secure: true },
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
});

// ปฏิเสธ content-type ที่ไม่ใช่ JSON เพื่อกัน simple-request CSRF (เช่น text/plain)
function requireJson(req, res, next) {
  if (!req.is('application/json')) {
    return res.status(415).json({ error: 'Unsupported Media Type' });
  }
  next();
}

app.post('/api/transfer', requireJson, doubleCsrfProtection, (req, res) => {
  const { to, amount } = req.body;
  transfer(req.session.userId, to, amount);
  res.json({ ok: true });
});

module.exports = app;`,
            explain: {
              th: 'เพิ่ม doubleCsrf() จาก csrf-csrf เพื่อออก CSRF token แบบ double-submit และตรวจ token เฉพาะเมธอดที่เปลี่ยนสถานะ (ยกเว้น GET/HEAD/OPTIONS) ตั้ง cookie เป็น sameSite: "lax" ทั้งฝั่ง session และ CSRF และปฏิเสธ request ที่ content-type ไม่ใช่ application/json ด้วย req.is() เพื่อกันฟอร์ม HTML แบบ simple-request ที่ใช้ทำ CSRF attacker อ่าน token ของโดเมนเราข้ามไซต์ไม่ได้จึงปลอม request ไม่ได้',
              en: 'Add doubleCsrf() from csrf-csrf to issue a double-submit CSRF token and verify it on state-changing methods (GET/HEAD/OPTIONS are ignored). Set sameSite: "lax" on both the session and CSRF cookies, and reject any request whose content type is not application/json with req.is(), to block simple-request HTML-form CSRF. The attacker cannot read our domain’s token cross-site, so they cannot forge the request.'
            },
            checks: [
              { id: 'csrf-protection', label: { th: 'ตรวจ CSRF token บน route ที่เปลี่ยนสถานะ', en: 'Verify a CSRF token on state-changing routes' }, hint: { th: 'ใช้ doubleCsrf() จาก csrf-csrf แล้วใส่ doubleCsrfProtection เป็น middleware ของ POST /api/transfer', en: 'Use doubleCsrf() from csrf-csrf and add doubleCsrfProtection as middleware on POST /api/transfer.' }, weight: 3, mustMatch: /doubleCsrf|csrfProtection|csrf-csrf|csrfSync|verifyCsrfToken/i },
              { id: 'samesite-lax', label: { th: 'ตั้ง cookie เป็น SameSite=Lax', en: 'Set cookies to SameSite=Lax' }, hint: { th: 'เพิ่ม sameSite: "lax" ในตัวเลือกของ cookie', en: 'Add sameSite: "lax" to the cookie options.' }, weight: 2, mustMatch: /sameSite\s*:\s*['"]lax['"]/i },
              { id: 'reject-content-type', label: { th: 'ปฏิเสธ content-type ที่ไม่ใช่ของแอป', en: 'Reject non-simple / unexpected content types' }, hint: { th: 'ใช้ req.is("application/json") แล้วตอบ 415 ถ้าไม่ตรง', en: 'Use req.is("application/json") and return 415 when it does not match.' }, weight: 1, mustMatch: /req\.is\s*\(|Unsupported Media Type|\b415\b/ },
              { id: 'csrf-secret', label: { th: 'ตั้งค่า token repository ด้วย secret', en: 'Configure the token with a secret' }, hint: { th: 'ตั้ง getSecret และ cookieName ใน doubleCsrf()', en: 'Set getSecret and cookieName in doubleCsrf().' }, weight: 1, mustMatch: /getSecret|cookieName/ }
            ],
            traps: [
              { id: 'referer-as-csrf-defense', match: /req\.headers\s*(\[\s*['"]referer['"]\s*\]|\.referer)|req\.get\s*\(\s*['"]referer['"]/i, message: { th: 'การเช็ค Referer header ไม่ใช่การป้องกัน CSRF ที่เชื่อถือได้ — Referer หาย/ว่างได้ ให้ใช้ CSRF token และตรวจ Origin header แทน', en: 'Checking the Referer header is not a reliable CSRF defense — it can be stripped or empty. Use a CSRF token and verify the Origin header instead.' } },
              { id: 'samesite-none', match: /sameSite\s*:\s*['"]none['"]/i, message: { th: 'sameSite: "none" ยกเลิกการป้องกันที่ SameSite ให้ (cookie จะถูกแนบข้ามไซต์อีกครั้ง) ใช้ "lax" หรือ "strict" สำหรับ cookie ที่ใช้ยืนยันตัวตน', en: 'sameSite: "none" removes the protection SameSite provides (the cookie rides cross-site again). Use "lax" or "strict" for authentication cookies.' } }
            ]
          }
        },

        hints: [
          { th: 'cookie ถูกแนบไปกับทุก request ข้ามไซต์โดยอัตโนมัติ ดังนั้น "ล็อกอินด้วย cookie" อย่างเดียวไม่ใช่การพิสูจน์ว่า request มาจากเว็บของเรา', en: 'The cookie is attached to every cross-site request automatically, so "authenticated by cookie" is not proof the request came from our own site.' },
          { th: 'ใช้ CSRF token แบบ synchronizer หรือ double-submit บนเมธอดที่เปลี่ยนสถานะ และตรวจ Origin header; ตั้ง SameSite=Lax เป็นชั้นเสริม', en: 'Use a synchronizer or double-submit CSRF token on state-changing methods and verify the Origin header; set SameSite=Lax as an extra layer.' },
          { th: 'Java: CookieCsrfTokenRepository.withHttpOnlyFalse() และเลิกเรียก.csrf(...).disable(); Node: csrf-csrf doubleCsrf() พร้อม sameSite: "lax"', en: 'Java: CookieCsrfTokenRepository.withHttpOnlyFalse() and stop calling .csrf(...).disable(); Node: csrf-csrf doubleCsrf() with sameSite: "lax".' }
        ],

        quiz: [
          {
            q: { th: 'แอปของคุณเป็น REST API ที่รับ-ส่ง JSON และยืนยันตัวตนด้วย session cookie ข้อใดถูกต้องที่สุดเกี่ยวกับ CSRF?', en: 'Your app is a REST API that speaks JSON and authenticates with a session cookie. Which statement about CSRF is most correct?' },
            choices: [
              { th: 'JSON API ไม่มีทางโดน CSRF เพราะ browser ส่ง JSON ข้ามไซต์ไม่ได้', en: 'A JSON API cannot be hit by CSRF because browsers cannot send JSON cross-site.' },
              { th: 'ยังเสี่ยง CSRF ถ้ายืนยันตัวตนด้วย cookie และ endpoint ยอมรับ content-type แบบ simple (เช่น text/plain) หรือฟอร์ม จึงต้องมี CSRF token และตรวจ Origin', en: 'It is still at risk if you authenticate with cookies and the endpoint accepts a simple content type (e.g. text/plain) or form bodies — so you need a CSRF token and Origin verification.' },
              { th: 'แค่ใช้ HTTPS ก็กัน CSRF ได้แล้ว', en: 'Using HTTPS is enough to prevent CSRF.' },
              { th: 'ตั้ง SameSite=Lax แล้วปลอดภัย 100% ไม่ต้องมี token', en: 'Setting SameSite=Lax makes it 100% safe with no token needed.' }
            ],
            answer: 1,
            why: { th: 'CSRF เกิดเพราะ browser แนบ cookie ให้เองกับ request ข้ามไซต์ ฟอร์ม/simple request ส่งข้ามไซต์ได้โดยไม่ต้อง preflight token ที่ผูกกับ origin ของเราจึงเป็นสิ่งที่ attacker อ่าน/เดาไม่ได้ และ SameSite เป็นเพียงชั้นเสริม', en: 'CSRF works because the browser attaches the cookie to cross-site requests; forms/simple requests cross origins with no preflight. A token bound to our origin is what the attacker cannot read or guess, and SameSite is only a supporting layer.' },
            whyWrong: [
              { th: 'ฟอร์ม HTML ส่ง content-type แบบ simple ข้ามไซต์ได้โดยไม่ต้อง preflight และ cookie ถูกแนบให้เอง — "เป็น JSON API" ไม่ได้กันอะไร', en: 'HTML forms send simple content types cross-site with no preflight, and the cookie is attached automatically — "being a JSON API" protects nothing.' },
              null,
              { th: 'HTTPS เข้ารหัสการรับส่ง แต่ browser ก็ยังแนบ cookie กับ request ข้ามไซต์อยู่ดี ไม่เกี่ยวกับ CSRF', en: 'HTTPS encrypts transport, but the browser still attaches the cookie on cross-site requests — unrelated to CSRF.' },
              { th: 'SameSite=Lax ยังปล่อยให้ top-level GET navigation ทำงาน และเป็นการป้องกันที่ขึ้นกับ browser จึงเป็นชั้นเสริม ไม่ใช่การแทน token', en: 'SameSite=Lax still allows top-level GET navigation and is browser-dependent, so it is defense-in-depth, not a replacement for a token.' }
            ]
          },
          {
            q: { th: 'ฝั่ง server ควรใช้วิธีใดในการยืนยันว่า request ที่เปลี่ยนสถานะมาจากเว็บของเราเองจริง ๆ?', en: 'On the server, which approach best verifies that a state-changing request truly came from our own site?' },
            choices: [
              { th: 'ตรวจ Referer header ว่าตรงกับโดเมนเรา', en: 'Check that the Referer header matches our domain.' },
              { th: 'ตรวจ User-Agent ว่าเป็น browser ที่รู้จัก', en: 'Check that the User-Agent is a known browser.' },
              { th: 'ใช้ CSRF token (synchronizer/double-submit) และตรวจ Origin header เป็นการเสริม', en: 'Use a CSRF token (synchronizer/double-submit) and verify the Origin header as a backup.' },
              { th: 'เชื่อว่า cookie ที่ browser แนบมาเป็นหลักฐานเพียงพออยู่แล้ว', en: 'Trust the cookie the browser attached as sufficient proof.' }
            ],
            answer: 2,
            why: { th: 'CSRF token ที่ผูกกับ session/origin เป็นค่าที่ attacker อ่านหรือเดาข้ามไซต์ไม่ได้ (same-origin policy) และ Origin header ถูกส่งกับ request ที่เปลี่ยนสถานะข้ามต้นทาง ทำให้ตรวจต้นทางได้อย่างเชื่อถือได้', en: 'A CSRF token bound to the session/origin is something the attacker cannot read or guess across sites (same-origin policy), and the Origin header is sent on state-changing cross-origin requests, giving reliable origin verification.' },
            whyWrong: [
              { th: 'Referer หาย/ถูก strip ได้จาก Referrer-Policy, พร็อกซี หรือส่วนขยาย ทำให้การเช็คนี้ทั้ง bypass ได้และพังกับผู้ใช้จริง', en: 'The Referer can be stripped by Referrer-Policy, proxies, or extensions, so this check is both bypassable and breaks real users.' },
              { th: 'User-Agent ปลอมได้ง่ายและไม่ได้บอกว่า request มาจากเว็บของเรา', en: 'The User-Agent is trivially spoofed and says nothing about whether the request came from our site.' },
              null,
              { th: 'การเชื่อ cookie คือต้นตอของ CSRF พอดี เพราะ browser แนบ cookie ให้แม้ request จะมาจากเว็บของ attacker', en: 'Trusting the cookie is exactly what CSRF abuses — the browser attaches it even when the request originates from the attacker’s site.' }
            ]
          }
        ],

        sim: {
          kind: 'csrf',
          config: { endpoint: 'POST https://bank.example.com/api/transfer', amountField: 'amount', cookie: 'SESSIONID' },
          payloads: [
            { label: { th: 'หน้าเว็บของ attacker ที่กด submit เองอัตโนมัติ', en: 'Auto-submitting form (classic)' }, value: `<form action="https://bank.example.com/api/transfer" method="POST"><input name="to" value="attacker"><input name="amount" value="100000"></form><script>document.forms[0].submit()</script>` },
            { label: { th: 'GET แบบเปลี่ยนสถานะ', en: 'State-changing GET' }, value: `<img src="https://bank.example.com/api/transfer?to=attacker&amount=100000">` },
            { label: { th: 'fetch ข้ามไซต์พร้อม credentials', en: 'Cross-site fetch with credentials' }, value: `fetch('https://bank.example.com/api/transfer', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'text/plain' }, body: 'to=attacker&amount=100000' })` }
          ],
          allowCustom: true
        },

        references: [
          { label: 'OWASP Cross-Site Request Forgery Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html' },
          { label: 'MDN — SameSite cookies', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite' }
        ]
      },

 /* ================================================================
 * 6.2 rate-limit (brute-force / credential stuffing)
 * ============================================================== */
      {
        id: 'rate-limit',
        title: { th: 'Login Rate Limiting (Brute-force / Credential Stuffing)', en: 'Login Rate Limiting (Brute-force / Credential Stuffing)' },
        severity: 'Medium',
        cwe: 'CWE-307',
        owasp: 'A07:2021 – Identification and Authentication Failures',
        category: { th: 'Authentication Failures', en: 'Authentication Failures' },
        estMinutes: 12,
        points: 90,

        intro: {
          th: 'endpoint /login ตรวจ password โดยไม่จำกัดจำนวนครั้งที่ลองผิด attacker จึงยิง password ได้ไม่จำกัด ทั้งแบบ brute-force (เดารหัสของบัญชีเดียว), credential stuffing (เอา username/password ที่รั่วจากเว็บอื่นมายิง) และ password spraying (รหัสยอดฮิตหนึ่งตัวยิงหลายบัญชี)',
          en: 'The /login endpoint checks passwords with no cap on failed attempts, so an attacker can try passwords without limit: brute-force (guessing one account), credential stuffing (replaying username/password leaked elsewhere), and password spraying (one popular password against many accounts).'
        },
        attack: {
          th: 'attacker วนยิงคู่ username/password จากไฟล์ที่รั่ว เช่น\nfor combo in $(cat combos.txt); do\n curl -s -X POST https://app.example.com/login \\\n -H "Content-Type: application/json" \\\n -d "$combo"\ndone\nเพราะไม่มีตัวจำกัดอัตรา จึงลองได้หลายพันครั้งต่อวินาทีจนกว่าจะเจอรหัสที่ถูก',
          en: 'The attacker loops through leaked username/password pairs, e.g.\nfor combo in $(cat combos.txt); do\n  curl -s -X POST https://app.example.com/login \\\n    -H "Content-Type: application/json" \\\n    -d "$combo"\ndone\nWith no rate limiter, they can try thousands per second until a valid pair hits.'
        },
        fix: {
          th: 'ใส่ตัวจำกัดอัตราทั้งราย IP และรายบัญชี (per-account) เพื่อกันทั้ง brute-force และ password spraying, เพิ่ม exponential backoff และล็อกบัญชีชั่วคราวเมื่อผิดหลายครั้ง, และบันทึก audit log ทุกครั้งที่ล้มเหลว/ถูกล็อกเพื่อให้ตรวจจับได้ กลไกสำคัญคือทำให้จำนวนการเดาต่อหน่วยเวลาต่ำจนไม่คุ้ม เสริมด้วย MFA และการตรวจ password ที่รั่ว (breached-password)',
          en: 'Add a rate limiter keyed per IP and per account to stop both brute-force and password spraying, add exponential backoff and a temporary lockout after repeated failures, and write an audit log on every failure/lockout so it can be detected. The mechanism is to drive guesses-per-unit-time low enough to be uneconomic, backed by MFA and breached-password checks.'
        },
        keyPoints: {
          vuln: [
            { th: '/login ตรวจ password โดยไม่จำกัดจำนวนครั้งที่ลองผิด', en: 'The /login endpoint checks passwords with no cap on failed attempts' },
            { th: 'attacker จึงยิงรหัสได้ไม่จำกัด ทั้ง brute-force และ credential stuffing', en: 'An attacker can try passwords without limit, both brute-force and credential stuffing' },
            { th: 'password spraying ยิงรหัสยอดฮิตหนึ่งตัวไปหลายบัญชีพร้อมกัน', en: 'Password spraying throws one popular password at many accounts at once' }
          ],
          attack: [
            { th: 'attacker ใช้ script หรือ curl ส่งคู่ username/password จำนวนมากจากข้อมูลที่เคยรั่ว มาลองกับ /login แบบอัตโนมัติ ซึ่งเรียกว่า credential stuffing', en: 'Loop through leaked username/password pairs with curl in a shell loop' },
            { th: 'ถ้าไม่มี rate limiter attacker สามารถลอง password จำนวนมากต่อวินาทีหรือกระจาย request ไปหลายบัญชีได้โดยไม่มีระบบชะลอหรือบล็อก', en: 'With no rate limiter, they can try thousands of pairs per second' },
            { th: 'การลองต่อเนื่องเพิ่มโอกาสพบบัญชีที่ใช้ password อ่อนหรือ password ที่เคยรั่วจากระบบอื่น และนำไปสู่ account takeover', en: 'They keep going until a valid pair hits and take over the customer account' }
          ],
          fix: [
            { th: 'จำกัดจำนวนครั้งทั้งต่อ IP และต่อบัญชี เพื่อรับมือทั้ง brute-force จากแหล่งเดียวและ password spraying หรือ credential stuffing ที่กระจาย request', en: 'Add a rate limiter keyed per IP and per account to stop brute-force and spraying' },
            { th: 'เพิ่ม exponential backoff หรือ temporary lock เมื่อ login ผิดซ้ำ เพื่อทำให้การเดาต่อเนื่องช้าลงโดยไม่ล็อกบัญชีถาวร', en: 'Add exponential backoff and a temporary lockout after repeated failures' },
            { th: 'บันทึก audit log ของ login failure และ lockout พร้อมเสริม MFA และการตรวจ password ที่เคยรั่ว เพื่อเพิ่มชั้นป้องกันนอกเหนือจาก rate limit', en: 'Log every failure/lockout and back it with MFA plus breached-password checks' }
          ]
        },
        impact: {
          th: 'attacker สามารถลอง password จำนวนมากต่อเนื่องจนพบบัญชีที่ใช้รหัสอ่อนหรือใช้รหัสซ้ำจากระบบอื่น ส่งผลให้บัญชีผู้ใช้ถูกยึดได้',
          en: 'The attacker can guess or replay leaked passwords tens of thousands of times per hour until they take over customer accounts.'
        },

        caseStudy: {
          year: 2019,
          title: {
            th: 'Basecamp — credential stuffing กว่า 30,000 ครั้งใน 1 ชั่วโมง (2019)',
            en: 'Basecamp — 30,000+ credential-stuffing attempts in one hour (2019)'
          },
          body: {
            th: 'วันที่ 30 มกราคม 2019 Basecamp พบความพยายามล็อกอินมากกว่า 30,000 ครั้งภายในหนึ่งชั่วโมงจาก IP จำนวนมาก เป็น credential stuffing ที่นำ username/password ซึ่งรั่วจากเว็บอื่นมาลองกับระบบ และมี 124 บัญชีถูกเข้าถึงเพราะใช้ password ซ้ำ ทีมงานตอบสนองด้วยการบล็อก IP, เปิด CAPTCHA และรีเซ็ต password ของบัญชีที่ได้รับผลกระทบ บทเรียนคือการจำกัดต่อ IP เพียงอย่างเดียวไม่พอเมื่อ attacker กระจาย request หลาย IP จึงควรมีการป้องกันระดับบัญชีและ MFA เพิ่มด้วย',
            en: 'On 30 January 2019 Basecamp saw a sudden spike in logins — more than 30,000 login attempts within one hour from a wide array of IPs. It was credential stuffing using username/password pairs leaked from other sites; 124 accounts were accessed because users reused passwords. The team blocked IPs, enabled CAPTCHA, and reset the affected accounts. The lesson: per-IP limiting alone is not enough when IPs are spread out — you need MFA and account-level limiting/detection.'
          },
          source: {
            label: 'Signal v. Noise (Basecamp) — Mass-login attack, Jan 2019',
            url: 'https://signalvnoise.com/svn3/yesterdays-mass-login-attack-on-basecamp-is-another-reminder-to-protect-yourself/'
          }
        },

        codeReview: [
          { th: 'ถ้าเห็น handler ของ /login ที่ไม่มี rate limiter คั่นอยู่ข้างหน้า ให้ตรวจต่อ ทุก endpoint ที่ยืนยันตัวตนต้องมีตัวจำกัดจำนวนครั้ง', en: 'Find /login handlers with no rate limiter in front — every authentication endpoint needs throttling.' },
          { th: 'ตรวจว่า limiter นับแยกด้วยอะไร ถ้านับด้วย IP อย่างเดียวจะกัน password spraying ไม่ได้ (กระจายหลาย IP) ต้องนับแยกรายบัญชี (username) ด้วย', en: 'Check what the limiter is keyed on: if keyed by IP only it cannot stop password spraying — you also need a per-account (username) key.' },
          { th: 'ตรวจว่ามี audit log สำหรับ login ที่ล้มเหลวหรือถูกล็อกหรือไม่ ถ้าไม่มี ทีมจะมองไม่เห็นว่าระบบกำลังถูกลอง password จำนวนมาก', en: 'Look for an audit log of failed/locked-out login events (required for detection & response).' },
          { th: 'ระวังการนำ X-Forwarded-For ดิบ ๆ มาเป็นคีย์ของ limiter เพราะ header นี้ปลอมได้ attacker เปลี่ยนไปเรื่อย ๆ ก็หลบได้ ต้องตั้ง trust proxy ให้ถูกก่อน', en: 'Beware keying the limiter on raw X-Forwarded-For — it is spoofable; configure the trusted proxy first.' }
        ],

        testIt: {
          cmd: 'for i in $(seq 1 50); do curl -s -o /dev/null -w "%{http_code}\\n" -X POST http://localhost:8080/login -H "Content-Type: application/json" -d "{\\"username\\":\\"victim@example.com\\",\\"password\\":\\"guess$i\\"}"; done',
          note: {
            th: 'ส่ง request ล็อกอินผิด 50 ครั้งติด: แอปที่มีช่องโหว่จะตอบ 401 ทั้ง 50 ครั้ง (ลองได้ไม่จำกัด); แอปที่แก้แล้วต้องเริ่มตอบ 429 หลังเกิน limit และล็อกบัญชีชั่วคราว',
            en: 'Fire 50 wrong logins in a row: a vulnerable app returns 401 all 50 times (unlimited tries); a fixed app must start returning 429 once over the limit and temporarily lock the account.'
          }
        },

        pitfalls: [
          {
            title: { th: 'จำกัด rate ต่อ IP อย่างเดียว', en: '"I limit per IP, that’s enough"' },
            why: {
              th: 'botnet หมุน IP ได้เป็นพัน ๆ ทำให้แต่ละ IP อยู่ใต้ threshold; และ password spraying ยิงหลายบัญชีบัญชีละครั้ง จึงไม่ชน limit ต่อ IP เลย ยิ่งไปกว่านั้นผู้ใช้จริงหลายคนอาจออกจาก IP เดียว (NAT/องค์กร) การจำกัดต่อ IP อย่างเดียวจึงทั้งกันไม่อยู่และบล็อกคนบริสุทธิ์ ต้องจำกัดต่อบัญชีและมี anomaly detection ระดับระบบด้วย',
              en: 'A botnet rotates thousands of IPs so each stays under the threshold; and password spraying hits many accounts once each, so it never trips a per-IP limit. Worse, many real users share one IP (NAT/corporate). Per-IP alone both fails to stop the attack and blocks innocents — you also need per-account limits and system-wide anomaly detection.'
            },
            short: {
              th: 'botnet สามารถเปลี่ยน IP และ password spraying กระจายการลองไปหลายบัญชี จึงหลบ limit ที่นับเฉพาะ IP ได้ ต้องจำกัดต่อบัญชีด้วย',
              en: 'Botnets rotate IPs and spraying hits each account once; also limit per account, not just per IP'
            }
          },
          {
            title: { th: 'ใส่ CAPTCHA แทนการจำกัด rate', en: '"CAPTCHA solves it"' },
            why: {
              th: 'มีบริการ solver (เช่น 2Captcha) และบอท headless ที่ทะลุ CAPTCHA ได้ในราคาถูก อีกทั้ง CAPTCHA ทำร้ายประสบการณ์ผู้ใช้ ทางแก้จริงต้องเป็นหลายชั้น: MFA (ลดการยึดบัญชีได้ราว 99.9% ตามรายงานของ Microsoft), การตรวจ password ที่รั่ว (breached-password), exponential backoff และการจำกัดอัตราต่อ IP และต่อบัญชี',
              en: 'Solver services (e.g. 2Captcha) and headless bots defeat CAPTCHAs cheaply, and CAPTCHAs hurt UX. The real answer is layered: MFA (which Microsoft reports would block ~99.9% of account compromises), breached-password checks, exponential backoff, and rate limiting per IP and per account.'
            },
            short: {
              th: 'มี solver และบอททะลุ CAPTCHA ได้ถูก ต้องใช้หลายชั้น: MFA, breached-password, backoff',
              en: 'Solvers and bots beat CAPTCHA cheaply; layer MFA, breached-password checks and backoff instead'
            }
          }
        ],

        languages: {
          java: {
            filename: 'LoginController.java',
            lang: 'java',
            starter:
`import org.springframework.web.bind.annotation.*;

@RestController
public class LoginController {

    private final UserService users;
    private final AuthTokenService tokens;

    public LoginController(UserService users, AuthTokenService tokens) {
        this.users = users;
        this.tokens = tokens;
    }

 // ตรวจ password แล้วออก token — ไม่มีการจำกัดจำนวนครั้งที่ลองผิด
    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest req) {
        User user = users.findByUsername(req.getUsername());
        if (user == null || !users.checkPassword(user, req.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }
        return new LoginResponse(tokens.issue(user));
    }
}`,
            solution:
`import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;

@RestController
public class LoginController {

    private final UserService users;
    private final AuthTokenService tokens;
    private final LoginThrottle throttle;   // counter + exponential backoff + lockout
    private final AuditLog audit;

    public LoginController(UserService users, AuthTokenService tokens,
                           LoginThrottle throttle, AuditLog audit) {
        this.users = users;
        this.tokens = tokens;
        this.throttle = throttle;
        this.audit = audit;
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest req, HttpServletRequest http) {
        String ip = http.getRemoteAddr();
        String account = req.getUsername();

 // 1) จำกัดทั้งราย IP และรายบัญชี (password spraying ยิงหลายบัญชีจากหลาย IP)
        if (throttle.isLocked(account) || throttle.isLocked(ip)) {
            audit.event("login_throttled", account, ip);
            throw new TooManyRequestsException("Too many attempts, try again later");
        }

        User user = users.findByUsername(account);
        if (user == null || !users.checkPassword(user, req.getPassword())) {
 // 2) นับความล้มเหลว + exponential backoff แล้วล็อกชั่วคราว
            throttle.recordFailure(account, ip);
            audit.event("login_failed", account, ip);
            throw new BadCredentialsException("Invalid username or password");
        }

        throttle.reset(account, ip);
        audit.event("login_success", account, ip);
        return new LoginResponse(tokens.issue(user));
    }
}`,
            explain: {
              th: 'ก่อนตรวจ password ให้ตรวจ throttle.isLocked ทั้งของบัญชีและของ IP ถ้าถูกล็อกให้ตอบ 429 (TooManyRequests) เมื่อรหัสผิดให้ throttle.recordFailure(account, ip) เพื่อนับและทำ exponential backoff จนล็อกชั่วคราว และบันทึก audit log ทุกเหตุการณ์ การคีย์ทั้งบัญชีและ IP ทำให้กันได้ทั้ง brute-force (IP เดียวส่ง request ต่อเนื่อง) และ password spraying (หลาย IP กระจายไปหลายบัญชี)',
              en: 'Before checking the password, test throttle.isLocked for both the account and the IP; if locked, return 429 (TooManyRequests). On a wrong password call throttle.recordFailure(account, ip) to count and apply exponential backoff up to a temporary lockout, and write an audit log for every event. Keying on both account and IP stops brute-force (one IP hammering) and password spraying (many IPs across many accounts).'
            },
            checks: [
              { id: 'has-throttle', label: { th: 'มีตัวจำกัดอัตรา/ล็อกบัญชีก่อนตรวจ password', en: 'A rate limiter / lockout runs before the password check' }, hint: { th: 'เพิ่ม throttle.isLocked(...) และตอบ 429 เมื่อเกิน limit', en: 'Add throttle.isLocked(...) and return 429 when over the limit.' }, weight: 3, mustMatch: /throttle|isLocked|rateLim|RateLim|bucket|lockout/i },
              { id: 'record-failure', label: { th: 'นับความพยายามที่ล้มเหลว (backoff)', en: 'Count failed attempts (backoff)' }, hint: { th: 'เรียก throttle.recordFailure(account, ip) เมื่อรหัสผิด', en: 'Call throttle.recordFailure(account, ip) on a wrong password.' }, weight: 2, mustMatch: /recordFailure|recordAttempt|onFailure|incrementFailures|countFailure/i },
              { id: 'per-ip', label: { th: 'จำกัดต่อ IP ด้วย (ไม่ใช่ต่อบัญชีอย่างเดียว)', en: 'Also limit per IP (not per account only)' }, hint: { th: 'ดึง IP ด้วย http.getRemoteAddr() แล้วใช้เป็นคีย์', en: 'Read the IP with http.getRemoteAddr() and use it as a key.' }, weight: 2, mustMatch: /getRemoteAddr|remoteAddr|clientIp|ipAddress|isLocked\s*\(\s*ip\b/i },
              { id: 'audit-log', label: { th: 'บันทึก audit log เหตุการณ์ login', en: 'Write an audit log of login events' }, hint: { th: 'เรียก audit.event("login_failed",...) ทุกครั้งที่ล้มเหลว/ถูกล็อก', en: 'Call audit.event("login_failed", ...) on every failure/lockout.' }, weight: 1, mustMatch: /audit|AuditLog/i },
              { id: 'lockout-response', label: { th: 'ตอบ 429 เมื่อถูกล็อก', en: 'Return 429 when locked out' }, hint: { th: 'throw TooManyRequestsException หรือคืนสถานะ 429', en: 'Throw TooManyRequestsException or return status 429.' }, weight: 1, mustMatch: /TooManyRequests|\b429\b|lockout|isLocked/i }
            ],
            traps: [
              { id: 'captcha-only', match: /captcha|recaptcha|hcaptcha/i, message: { th: 'CAPTCHA อย่างเดียวเอาไม่อยู่ — มี solver service และบอท headless ทะลุได้ ให้ทำหลายชั้น: จำกัดต่อ IP และต่อบัญชี, backoff, ตรวจ password ที่รั่ว และ MFA', en: 'CAPTCHA alone is not enough — solver services and headless bots defeat it. Layer defenses: per-IP and per-account limits, backoff, breached-password checks, and MFA.' } },
              { id: 'trust-xff', match: /getHeader\s*\(\s*["']X-Forwarded-For["']/i, message: { th: 'อย่าอ่าน X-Forwarded-For ดิบ ๆ มาเป็นคีย์ของ limiter — attacker ปลอมค่าเพื่อหมุนคีย์ได้ ให้เชื่อ header นี้เฉพาะเมื่ออยู่หลังพร็อกซีที่คุณควบคุมและตั้ง trust proxy แล้วเท่านั้น', en: 'Do not key the limiter on raw X-Forwarded-For — attackers spoof it to rotate the key. Trust it only behind a proxy you control with trust-proxy configured.' } }
            ]
          },
          node: {
            filename: 'login.routes.js',
            lang: 'js',
            starter:
`const express = require('express');
const router = express.Router();
const { verifyPassword, issueToken } = require('./auth');
const users = require('./userRepository');

// ตรวจ password แล้วออก token — ไม่มีการจำกัดจำนวนครั้งที่ลองผิด
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await users.findByUsername(username);
  if (!user || !(await verifyPassword(user, password))) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  res.json({ token: issueToken(user) });
});

module.exports = router;`,
            solution:
`const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const { verifyPassword, issueToken } = require('./auth');
const users = require('./userRepository');
const logger = require('./logger');

// จำกัดต่อ IP: กัน brute-force จาก IP เดียวที่ยิงรัว
const perIpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 50,
  standardHeaders: true,
  legacyHeaders: false
});

// จำกัดต่อบัญชี: กัน password spraying (หลาย IP ยิงบัญชีเดียว)
const perAccountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  keyGenerator: (req) => String((req.body && req.body.username) || '').toLowerCase(),
  handler: (req, res) => {
    logger.warn('login_locked', { username: req.body.username, ip: req.ip });
    res.status(429).json({ error: 'Too many attempts, try again later' });
  }
});

router.post('/login', perIpLimiter, perAccountLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = await users.findByUsername(username);
  if (!user || !(await verifyPassword(user, password))) {
    logger.warn('login_failed', { username, ip: req.ip });
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  logger.info('login_success', { username, ip: req.ip });
  res.json({ token: issueToken(user) });
});

module.exports = router;`,
            explain: {
              th: 'เพิ่ม limiter สองตัวจาก express-rate-limit เป็น middleware ของ /login: perIpLimiter คีย์ด้วย req.ip (ค่าเริ่มต้น) กัน brute-force จาก IP เดียว และ perAccountLimiter ที่ใช้ keyGenerator คีย์ด้วย username กัน password spraying เมื่อเกิน limit จะตอบ 429 และ logger บันทึกเหตุการณ์ login_failed/login_locked เพื่อ detection การคีย์ทั้ง IP และบัญชีจึงครอบคลุมทั้งสองรูปแบบการโจมตี',
              en: 'Add two express-rate-limit limiters as middleware on /login: perIpLimiter keyed on req.ip (the default) stops brute-force from one IP, and perAccountLimiter with a keyGenerator on username stops password spraying. Over the limit returns 429, and logger records login_failed/login_locked events for detection. Keying on both IP and account covers both attack shapes.'
            },
            checks: [
              { id: 'has-limiter', label: { th: 'มีตัวจำกัดอัตราคั่นก่อน handler ของ /login', en: 'A rate limiter runs before the /login handler' }, hint: { th: "ใช้ express-rate-limit: const limiter = rateLimit({...}) แล้วใส่เป็น middleware", en: 'Use express-rate-limit: const limiter = rateLimit({...}) as middleware.' }, weight: 3, mustMatch: /rateLimit|express-rate-limit/i },
              { id: 'per-account-key', label: { th: 'จำกัดต่อบัญชีด้วย keyGenerator (username)', en: 'Limit per account via keyGenerator (username)' }, hint: { th: 'ตั้ง keyGenerator: (req) => req.body.username เพื่อกัน password spraying', en: 'Set keyGenerator: (req) => req.body.username to stop password spraying.' }, weight: 2, mustMatch: /keyGenerator/ },
              { id: 'per-ip-aware', label: { th: 'จำกัด/อ้างอิงต่อ IP ด้วย', en: 'Also limit/track per IP' }, hint: { th: 'มี limiter ที่คีย์ด้วย req.ip (ค่าเริ่มต้นของ express-rate-limit)', en: 'Have a limiter keyed on req.ip (the express-rate-limit default).' }, weight: 1, mustMatch: /req\.ip|perIpLimiter|windowMs/ },
              { id: 'returns-429', label: { th: 'ตอบ 429 เมื่อเกิน limit', en: 'Return 429 when over the limit' }, hint: { th: 'ตอบ res.status(429) พร้อมข้อความ Too many attempts', en: 'Respond with res.status(429) and a Too many attempts message.' }, weight: 1, mustMatch: /\b429\b|Too many|TooMany/i },
              { id: 'audit-log', label: { th: 'บันทึก log เหตุการณ์ login', en: 'Log login events' }, hint: { th: 'เรียก logger.warn("login_failed",...) เมื่อรหัสผิด/ถูกล็อก', en: 'Call logger.warn("login_failed", ...) on failure/lockout.' }, weight: 1, mustMatch: /logger\.(warn|info|error)|audit/i }
            ],
            traps: [
              { id: 'captcha-only', match: /captcha|recaptcha|hcaptcha/i, message: { th: 'CAPTCHA อย่างเดียวเอาไม่อยู่ — มี solver service และบอท headless ทะลุได้ ให้ทำหลายชั้น: จำกัดต่อ IP และต่อบัญชี, backoff, ตรวจ password ที่รั่ว และ MFA', en: 'CAPTCHA alone is not enough — solver services and headless bots defeat it. Layer defenses: per-IP and per-account limits, backoff, breached-password checks, and MFA.' } },
              { id: 'trust-xff', match: /req\.headers\s*\[\s*['"]x-forwarded-for['"]\s*\]/i, message: { th: 'อย่าอ่าน X-Forwarded-For ดิบ ๆ มาเป็นคีย์ — ปลอมได้ ให้ตั้ง app.set("trust proxy",...) แล้วใช้ req.ip แทน', en: 'Do not key on raw X-Forwarded-For — it is spoofable. Set app.set("trust proxy", ...) and use req.ip instead.' } }
            ]
          }
        },

        hints: [
          { th: 'การจำกัดต่อ IP เพียงอย่างเดียวไม่พอ เพราะ botnet เปลี่ยน IP ได้ และ password spraying กระจายการลองไปหลายบัญชี ควรจำกัดจำนวนครั้งต่อบัญชีด้วย', en: 'Per-IP limiting alone is not enough — botnets rotate IPs and password spraying hits many accounts. Also limit per account (username).' },
          { th: 'เพิ่ม exponential backoff + ล็อกบัญชีชั่วคราว และบันทึก audit log ทุกครั้งที่ล็อกอินล้มเหลว/ถูกล็อก', en: 'Add exponential backoff + a temporary lockout, and write an audit log on every failed/locked login.' },
          { th: 'Java: ตรวจ throttle.isLocked(account/ip) แล้วตอบ 429; Node: express-rate-limit สองตัว (ต่อ IP และ keyGenerator ต่อ username)', en: 'Java: check throttle.isLocked(account/ip) and return 429; Node: two express-rate-limit limiters (per IP and a keyGenerator per username).' }
        ],

        quiz: [
          {
            q: { th: 'การจำกัดอัตราต่อ IP อย่างเดียวเพียงพอที่จะกัน credential stuffing หรือไม่?', en: 'Is per-IP rate limiting alone enough to stop credential stuffing?' },
            choices: [
              { th: 'เพียงพอ เพราะ attacker ต้องใช้ IP เดิมในการยิงทุกครั้ง', en: 'Enough, because the attacker must use the same IP every time.' },
              { th: 'ไม่พอ: botnet หมุน IP ได้ และ password spraying ยิงหลายบัญชีบัญชีละครั้ง จึงต้องจำกัดต่อบัญชีด้วย', en: 'Not enough: botnets rotate IPs and password spraying hits many accounts once each, so you must also limit per account.' },
              { th: 'พอ ถ้าตั้ง limit ให้ต่ำมาก เช่น 1 ครั้ง/นาที/IP', en: 'Enough if you set the limit very low, e.g. 1/minute/IP.' },
              { th: 'ไม่จำเป็นต้อง limit เลยถ้า password ถูก hash ด้วย bcrypt', en: 'No limiting is needed at all if passwords are hashed with bcrypt.' }
            ],
            answer: 1,
            why: { th: 'credential stuffing มักมาจาก IP กระจายหลักพันถึงหมื่น และ password spraying ยิงบัญชีละครั้งเพื่อเลี่ยง threshold ต่อ IP การจำกัดต่อบัญชีและการตรวจจับระดับระบบจึงจำเป็น', en: 'Credential stuffing comes from thousands of spread-out IPs, and password spraying uses one attempt per account to dodge per-IP thresholds. Per-account limits and system-wide detection are therefore essential.' },
            whyWrong: [
              { th: 'attacker ใช้ botnet/พร็อกซีหมุน IP นับพัน จึงไม่ต้องใช้ IP เดิมเลย', en: 'Attackers use botnets/proxies to rotate thousands of IPs, so they never need the same IP.' },
              null,
              { th: 'limit ต่ำมากต่อ IP จะบล็อกผู้ใช้จริงหลังพร็อกซี/NAT และยังถูก botnet เลี่ยงได้เพราะแต่ละ IP ยิงน้อยครั้ง', en: 'A very low per-IP limit blocks real users behind proxies/NAT and is still dodged by botnets that make few attempts per IP.' },
              { th: 'bcrypt ทำให้ hash แข็งแรงเมื่อ database รั่ว แต่ไม่ได้ลดจำนวนครั้งที่ attacker ยิงรหัสที่รั่วมาแล้วผ่านหน้า login', en: 'bcrypt strengthens stored hashes if the DB leaks, but does nothing to reduce how many already-leaked passwords an attacker can try at the login endpoint.' }
            ]
          },
          {
            q: { th: 'CAPTCHA แก้ปัญหา credential stuffing ได้จริงหรือไม่?', en: 'Does CAPTCHA really solve credential stuffing?' },
            choices: [
              { th: 'ได้ เพราะบอทแก้ CAPTCHA ไม่ได้', en: 'Yes, because bots cannot solve CAPTCHAs.' },
              { th: 'ช่วยได้บ้างแต่ถูก solver service ทะลุได้ ทางแก้จริงคือหลายชั้น: MFA, ตรวจ password ที่รั่ว, backoff และจำกัดอัตรา', en: 'It helps somewhat but solver services defeat it — the real fix is layered: MFA, breached-password checks, backoff, and rate limiting.' },
              { th: 'ไม่ช่วยเลย ควรใช้ IP allowlist แทน', en: 'It does not help at all; use an IP allowlist instead.' },
              { th: 'ใช้ CAPTCHA แล้วไม่ต้องมี rate limit หรือ MFA อีก', en: 'With CAPTCHA you no longer need rate limiting or MFA.' }
            ],
            answer: 1,
            why: { th: 'CAPTCHA เพิ่มต้นทุนให้ attacker ได้บ้าง แต่มี solver service ราคาถูกและบอท headless ที่ทะลุได้ การป้องกันที่ได้ผลจริงต้องหลายชั้นโดยมี MFA เป็นแกนหลัก', en: 'CAPTCHA raises attacker cost a little, but cheap solver services and headless bots defeat it. Effective protection is layered, with MFA as the backbone.' },
            whyWrong: [
              { th: 'มีบริการรับแก้ CAPTCHA (เช่น 2Captcha) และบอทที่แก้อัตโนมัติ จึงไม่ได้กันบอทจริง', en: 'CAPTCHA-solving services (e.g. 2Captcha) and automated bots exist, so it does not truly stop bots.' },
              null,
              { th: 'IP allowlist ใช้ไม่ได้กับผู้ใช้ทั่วไปที่ IP เปลี่ยนตลอด และไม่กัน spraying ที่มาจากบัญชีที่ถูกต้อง', en: 'An IP allowlist is impractical for general users whose IPs change and does not stop spraying with valid credentials.' },
              { th: 'CAPTCHA ไม่ได้แทน rate limit หรือ MFA — ยังต้องมีทุกชั้นเพื่อกัน solver และการยึดบัญชี', en: 'CAPTCHA does not replace rate limiting or MFA — you still need every layer to resist solvers and account takeover.' }
            ]
          }
        ],

        sim: {
          kind: 'bruteforce',
          config: { passwordSpace: 1000000, rps: 500, limitPerMin: 5, lockoutMinutes: 15 },
          payloads: [
            { label: { th: 'ไล่เดา password ของบัญชีเดียวรัว ๆ', en: 'Brute-force one account (classic)' }, value: 'password123' },
            { label: { th: 'credential stuffing (รหัสที่รั่ว)', en: 'Credential stuffing (leaked pair)' }, value: 'Summer2024!' },
            { label: { th: 'password spraying (รหัสยอดฮิตหลายบัญชี)', en: 'Password spraying (popular password)' }, value: 'Welcome@123' }
          ],
          allowCustom: true
        },

        references: [
          { label: 'OWASP Credential Stuffing Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html' },
          { label: 'OWASP Authentication Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html' }
        ]
      }
    ]
  };

  global.SCW = global.SCW || { workshops: [], registerWorkshop: function (w) { this.workshops.push(w); } };
  global.SCW.registerWorkshop(WORKSHOP);
  if (typeof module !== 'undefined' && module.exports) module.exports = WORKSHOP;
})(typeof window !== 'undefined' ? window : globalThis);
