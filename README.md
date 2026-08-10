# GT Secure Coding Workshop

เว็บฝึก **Secure Coding แบบลงมือแก้โค้ดจริง** สำหรับ developer — เปิดในเบราว์เซอร์ อ่านว่าช่องโหว่คืออะไร
ดูโค้ดที่ไม่ปลอดภัยพร้อมไฮไลต์บรรทัดต้นเหตุ แล้วแก้โค้ดในเอดิเตอร์ กดตรวจคำตอบ
ระบบเฉลยทีละกติกาว่าผ่าน/ไม่ผ่าน พร้อมคำใบ้ ทำได้ทั้ง **Java** และ **Node.js**

- **16 โจทย์** จากช่องโหว่จริง อ้างอิง OWASP Top 10 (2021) และ CWE
- **สองภาษา** ไทย / English สลับได้ทันที
- **ทำงานออฟไลน์เต็มรูปแบบ** ไม่มี dependency ตอนรัน ไม่ต่ออินเทอร์เน็ต ไม่มี build step
- ความคืบหน้าเก็บใน localStorage ของเครื่องผู้เรียนเอง

## เริ่มใช้งาน

วิธีที่ง่ายที่สุด — เปิดไฟล์ตรง ๆ:

```
เปิด index.html ด้วยเบราว์เซอร์
```

หรือรันผ่าน static server ที่ให้มา (ต้องมี Node.js 18 ขึ้นไป):

```bash
npm start          # แล้วเปิด http://localhost:8080
```

macOS / Linux ใช้ `./start.sh` · Windows ใช้ `start.bat` ก็ได้เหมือนกัน

## โครงหน้าโจทย์

แต่ละข้อแบ่งเป็นสองแท็บ

**Vulnerability Information** — ช่องโหว่นี้คืออะไร · โดนโจมตียังไง · เขียนอย่างไรให้ปลอดภัย ·
ตัวอย่างโค้ดที่ไม่ปลอดภัยพร้อมไฮไลต์บรรทัดต้นเหตุ · แนวทางแก้แบบ diff · สิ่งที่ Developer มักจะพลาดบ่อย ·
ควรมองหาอะไรตอนทำ Code Review · วิธีทดสอบเอง · เคสจริงที่เคยเกิดขึ้น

**Coding Practice** — เอดิเตอร์พร้อม syntax highlight, ตรวจคำตอบ, คำใบ้ 3 ระดับ, ดูเฉลย, เทียบกับเฉลย

## รายการโจทย์

| # | WS | id | ชื่อ | ความรุนแรง | CWE | OWASP |
|---|---|---|---|---|---|---|
| 1 | W1 | `sql-injection` | SQL Injection | Critical | CWE-89 | A03:2021 – Injection |
| 2 | W1 | `xss` | Cross-Site Scripting (XSS) | High | CWE-79 | A03:2021 – Injection |
| 3 | W1 | `command-injection` | OS Command Injection | Critical | CWE-78 | A03:2021 – Injection |
| 4 | W1 | `path-traversal` | Path Traversal | High | CWE-22 | A01:2021 – Broken Access Control |
| 5 | W2 | `hardcoded-secrets` | Hardcoded Secrets | High | CWE-798 | A05:2021 – Security Misconfiguration |
| 6 | W2 | `cors-misconfig` | CORS Misconfiguration | Medium | CWE-942 | A05:2021 – Security Misconfiguration |
| 7 | W2 | `verbose-errors` | Verbose Error Messages | Medium | CWE-209 | A05:2021 – Security Misconfiguration |
| 8 | W3 | `weak-hashing` | Weak Password Hashing (MD5) | High | CWE-916 | A02:2021 – Cryptographic Failures |
| 9 | W3 | `idor` | Insecure Direct Object Reference (IDOR) | High | CWE-639 | A01:2021 – Broken Access Control |
| 10 | W3 | `jwt-forgery` | JWT Forgery (unverified signature) | Critical | CWE-347 | A01:2021 – Broken Access Control |
| 11 | W4 | `file-upload` | Insecure File Upload | Critical | CWE-434 | A04:2021 – Insecure Design |
| 12 | W4 | `vulnerable-deps` | Vulnerable & Outdated Components | High | CWE-1104 | A06:2021 – Vulnerable and Outdated Components |
| 13 | W4 | `ssrf` | Server-Side Request Forgery (SSRF) | Critical | CWE-918 | A10:2021 – Server-Side Request Forgery (SSRF) |
| 14 | W5 | `sensitive-logging` | Sensitive Data in Logs | Medium | CWE-532 | A09:2021 – Security Logging and Monitoring Failures |
| 15 | W6 | `csrf` | Cross-Site Request Forgery (CSRF) | High | CWE-352 | A01:2021 – Broken Access Control |
| 16 | W6 | `rate-limit` | Login Rate Limiting (Brute-force / Credential Stuffing) | Medium | CWE-307 | A07:2021 – Identification and Authentication Failures |

## โครงสร้างไฟล์

```
index.html            หน้าเดียวจบ กำหนดลำดับโหลดสคริปต์
css/styles.css        สไตล์ทั้งหมด รองรับโหมดสว่าง/มืด
js/i18n.js            ตารางข้อความ UI สองภาษา
js/exercises.js       ทะเบียนรวม workshop
js/data/w1..w6.js     เนื้อหาโจทย์ (workshop ละไฟล์)
js/grader.js          ตรวจคำตอบด้วย pattern + ตรวจจับกับดัก
js/highlight.js       syntax highlight
js/editor.js          เอดิเตอร์พร้อมเลขบรรทัด
js/diff.js            เทียบโค้ดทีละบรรทัด
js/gamify.js          สรุปความคืบหน้า
js/app.js             routing และการเรนเดอร์ทั้งหมด
server.js             static server เล็ก ๆ ไม่มี dependency
test/                 ชุดทดสอบ (ต้องมี devDependencies)
```

## ทดสอบ

```bash
npm install        # เฉพาะตอนจะรันเทสต์ (jsdom)
npm test
```

- `npm run verify` — ตรวจความถูกต้องของข้อมูลโจทย์และกติกาตรวจคำตอบ
- `npm run smoke` — เปิดแอปแบบ headless แล้วกดใช้งานจริง (ต้องใช้ Node 22 ขึ้นไป)

## การเพิ่มโจทย์

เพิ่ม object ใหม่ในไฟล์ `js/data/wN.js` แล้วใส่ชื่อตัวแปรลงใน array `exercises`
รัน `npm run verify` เพื่อตรวจว่าโครงสร้างครบตามสัญญาข้อมูล ทุกข้อความต้องมีทั้ง `th` และ `en`

## License

MIT
