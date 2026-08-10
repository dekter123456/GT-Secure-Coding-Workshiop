/* ============================================================================
 * js/data/w5.js — Workshop 5: Cryptography & การปกป้องข้อมูล
 *
 * 4 โจทย์: weak-random-token, insecure-tls, sensitive-logging, weak-encryption
 * โครงสร้างตาม (ทุกข้อความที่ผู้เรียนเห็นเป็น { th, en })
 *
 * หมายเหตุสำหรับผู้ดูแลไฟล์นี้:
 * - โค้ดตัวอย่างอยู่ใน template literal ดังนั้น backtick, ${ และ backslash
 * ต้อง escape ให้ถูกต้อง
 * - Grader ตัด comment ออกก่อนตรวจเสมอ (ดู js/grader.js) regex จึงไม่ต้อง
 * กังวลว่าจะไปแมตช์กับคอมเมนต์ภาษาไทย
 * - ห้ามซ้อน block comment ในอีก block comment
 * ==========================================================================*/
(function (global) {
  'use strict';

  const SENSITIVE_LOGGING = {
    id: 'sensitive-logging',
    title: { th: 'Sensitive Data in Logs', en: 'Sensitive Data in Logs' },
    severity: 'Medium',
    cwe: 'CWE-532',
    owasp: 'A09:2021 – Security Logging and Monitoring Failures',
    category: { th: 'Logging & Monitoring', en: 'Logging & Monitoring' },
    estMinutes: 11,
    points: 90,

    intro: {
      th: 'handler ของหน้า login/checkout log ทั้ง request — password กับเลขบัตรติดไปด้วย ไว้ debug — ฝั่ง Java เป็น log.info("login req=" + request) ฝั่ง Node เป็น console.log(\'body\', req.body) แถม log req.headers อีก password, เลขบัตรเต็มใบ (PAN) และ header Authorization เลยถูกเขียนลง log แอปเป็น plaintext แล้วถูกส่งต่อไป log aggregator เก็บไว้เป็นเดือน ๆ',
      en: 'A login/checkout handler logs the whole request object for debugging — on Java, log.info("login req=" + request); on Node, console.log(\'body\', req.body) and logging req.headers. The password, the full card number (PAN) and the Authorization header end up written to the application log in plaintext, shipped to the log aggregator, and retained for months.'
    },
    attack: {
      th: 'attacker (หรือคนในที่อยากรู้อยากเห็น หรือใครก็ตามที่ได้ log export ที่หลุด, ภาพหน้าจอใน ticket, หรือเข้าถึง APM ของ vendor ได้) แค่ grep หา password หรือ authorization ก็เก็บ credential ที่ยังใช้งานได้ session token และเลขบัตรเต็มใบไปได้เลย — ไม่ต้องมี exploit อะไรทั้งนั้น แอปยื่นให้เอง ตัวอย่าง: grep -Ri \'authorization|password\' /var/log/app คืน bearer JWT กับ password แบบ cleartext ออกมา',
      en: 'An attacker (or a curious insider, or anyone who gets a leaked log export, a screenshot in a ticket, or access to the APM vendor) just greps for password or authorization and harvests live credentials, session tokens and full card numbers — no exploit needed, the app handed them over. Example: grep -Ri \'authorization|password\' /var/log/app returns bearer JWTs and cleartext passwords.'
    },
    fix: {
      th: 'อย่า log ทั้ง request/response object ใช้ structured logging แล้ว log เฉพาะ field ที่เลือกไว้ล่วงหน้าแบบ allowlist (userId, route, status) พร้อม mask/redact field ที่รู้ว่าอ่อนไหว (password, card, Authorization, Set-Cookie, token) ฝั่ง Java สร้าง structured event จาก field ที่อนุญาต ฝั่ง Node ใช้ redaction helper หรือ redact paths ของ pino จุดสำคัญคือ redact ที่จุด logging เพื่อไม่ให้ call site ไหนข้ามได้ และ mask เลขบัตรให้เหลือแค่ 4 ตัวท้าย',
      en: 'Never log whole request/response objects. Use structured logging and log only a pre-chosen allowlist of fields (userId, route, status), and mask/redact known-sensitive fields (password, card, Authorization, Set-Cookie, tokens). On Java, build a structured event from the allowed fields; on Node, use a redaction helper or pino’s redact paths. Redact at the logging boundary so no call site can bypass it, and mask the PAN down to its last 4 digits.'
    },
    keyPoints: {
      vuln: [
        { th: 'handler log ทั้ง request — password กับเลขบัตรติดไปด้วย ไว้ debug', en: 'The handler logs the whole request object for debugging' },
        { th: 'password, เลขบัตรเต็มใบ (PAN) และ header Authorization ถูกเขียนลง log เป็น plaintext', en: 'Passwords, full card numbers (PAN) and the Authorization header land in the log in plaintext' },
        { th: 'log ถูกส่งต่อไป aggregator และเก็บไว้เป็นเดือน ๆ', en: 'The log is shipped to an aggregator and retained for months' }
      ],
      attack: [
        { th: 'คนหรือระบบที่เข้าถึง log ได้สามารถค้นหา field อย่าง password หรือ token แล้วนำ credential ที่บันทึกไว้ไปใช้งานต่อได้ทันที', en: 'Anyone with log access (insider, leaked export, vendor APM) just greps to harvest credentials' },
        { th: 'ถ้า Authorization header หรือ password ถูก log แบบ cleartext การค้นหา log เพียงไม่กี่คำอาจเปิดเผย bearer token และ credential ที่ยังใช้งานได้', en: 'grep -Ri authorization|password returns bearer JWTs and cleartext passwords' },
        { th: 'กรณีนี้ไม่จำเป็นต้องมี exploit ซับซ้อน เพราะตัวแอปเป็นผู้บันทึก secret ลง log เอง และ log มักถูกส่งต่อไปหลายระบบ', en: 'No exploit is needed — the app hands the secrets over itself' }
      ],
      fix: [
        { th: 'อย่า log request หรือ response object ทั้งหมด เพราะอาจมี password, token, cookie หรือข้อมูลส่วนบุคคลปนอยู่โดยไม่ตั้งใจ', en: 'Never log whole request/response objects' },
        { th: 'ใช้ structured logging และ allowlist เฉพาะ field ที่จำเป็นต่อการตรวจสอบ เช่น userId, route และ status แทนการ dump object ทั้งหมด', en: 'Log only an allowlist of fields (userId, route, status) with structured logging' },
        { th: 'ทำ redact ที่ชั้น logging กลาง เพื่อปิดบัง field อ่อนไหวก่อนเขียน log และลดโอกาสที่แต่ละจุดในโค้ดจะลืมกรองข้อมูล', en: 'Redact at the logging boundary so no call site can bypass it' },
        { th: 'ข้อมูลที่จำเป็นต้อง log เช่นเลขบัตร ควร mask ให้เหลือเฉพาะส่วนที่ต้องใช้ตรวจสอบ เช่น 4 ตัวท้าย', en: 'Mask the card number down to its last 4 digits' }
      ]
    },
    impact: {
      th: 'ข้อมูลอ่อนไหวที่หลุดเข้า log อาจถูกเข้าถึงโดยผู้ดูแลระบบ เครื่องมือ monitoring หรือ attacker ที่ได้สิทธิ์อ่าน log ทำให้ password, token หรือข้อมูลบัตรรั่วออกจากระบบได้',
      en: 'Credentials, session tokens and full card numbers accumulate in plaintext across every log sink and backup, turning any log access (an insider, a leaked export, a third-party APM) into an immediate account or card compromise — and a PAN in logs is a PCI-DSS violation.'
    },

    caseStudy: {
      year: 2018,
      title: {
        th: 'Twitter — password ถูกเขียนลง internal log เป็น plaintext',
        en: 'Twitter — passwords written to an internal log in plaintext'
      },
      body: {
        th: 'วันที่ 3 พฤษภาคม 2018 Twitter เปิดเผยว่ามีบั๊กทำให้ password ของผู้ใช้ถูกเขียนลง internal log เป็น plaintext ก่อนขั้นตอน hash ด้วย bcrypt จะเสร็จ บริษัทเลยแนะนำให้ผู้ใช้ราว 330 ล้านคนเปลี่ยน password ถึงจะไม่พบหลักฐานว่าถูกนำไปใช้ในทางที่ผิด แต่ password ก็นอนอยู่ใน log ภายในแบบไม่ปิดบัง บทเรียนคือข้อมูลอ่อนไหวต้องไม่ไปถึง log ตั้งแต่แรก ไม่ใช่ตามไปลบทีหลัง',
        en: 'On 3 May 2018 Twitter disclosed that a bug had written user passwords to an internal log in plaintext before the bcrypt hashing process finished. It advised roughly 330 million users to change their passwords. Although no misuse was found, the passwords sat unmasked in internal logs. The lesson: sensitive data should never reach the log in the first place, not be scrubbed afterwards.'
      },
      source: {
        label: 'The Verge — Twitter advising all 330 million users to change passwords after bug exposed them in plain text (May 3, 2018)',
        url: 'https://www.theverge.com/2018/5/3/17316684/twitter-password-bug-security-flaw-exposed-change-now'
      }
    },

    codeReview: [
      {
        th: 'ถ้าเห็น log/logger/console.log/println ต่อด้วย + request, + req, req.body, req.headers, Authorization, password หรือ dump ทั้ง DTO/entity ให้ตรวจต่อ ของพวกนี้มักพก secret ติดไปด้วย',
        en: 'grep for log/logger/console.log/println joined with + request, + req, req.body, req.headers, Authorization, password, or dumping a whole DTO/entity.'
      },
      {
        th: 'ถ้าพบ Lombok @ToString บน entity ที่มี field password/token แต่ไม่มี @ToString.Exclude ให้ตรวจต่อ เพราะ toString นั้นจะปรากฏใน exception stack trace และทุก log ที่พิมพ์ object',
        en: 'Lombok @ToString on an entity with password/token fields but no @ToString.Exclude — that toString then shows up in exception stack traces and every log that prints the object.'
      },
      {
        th: 'ระวัง URL ที่มี token/secret ใน query string เพราะจะติดไปใน access log (?token=...) และ exception ที่ log request context เต็ม ๆ ก็รั่ว secret เหมือนกัน',
        en: 'URLs carrying a token/secret in the query string logged by the access log (?token=...), and exceptions that log full request context.'
      },
      {
        th: 'ถ้า log ถูกส่งไปยังบริการภายนอก เช่น Sentry, Datadog หรือ CloudWatch ให้ตรวจว่ามีการ redact ข้อมูลอ่อนไหวก่อนเรียก logger หรือไม่ เพราะเมื่อ secret ถูกส่งออกไปแล้ว การตั้งค่าที่ปลายทางไม่สามารถย้อนกลับมาป้องกันได้',
        en: 'Shipping logs to external sinks (Sentry/Datadog/CloudWatch) — redaction must happen before the log call, not rely on sink-side config alone.'
      },
      {
        th: 'ถ้าเห็น LOG_LEVEL=debug เปิดค้างไว้ใน prod ให้ตรวจต่อ ระดับ debug มักสั่ง dump payload ทั้งหมดออกมา',
        en: 'LOG_LEVEL=debug left on in prod that dumps whole payloads.'
      }
    ],

    testIt: {
      cmd: "grep -RniE 'password|authorization|4[0-9]{12,15}' ./logs",
      note: {
        th: 'แอปที่มีช่องโหว่จะคืน password แบบ cleartext, header Authorization (Bearer JWT) และเลขบัตรที่ขึ้นต้นด้วย 4 ออกมา ส่วนแอปที่แก้แล้ว grep จะไม่เจอค่าจริง เจอแต่ค่าที่ถูก mask อย่าง **** หรือ [REDACTED] ลองรัน login/checkout จริงสักครั้งแล้ว grep ดู',
        en: 'A vulnerable app returns cleartext passwords, the Authorization header (a Bearer JWT) and card numbers starting with 4; a fixed app yields no real values — only masked ones like **** or [REDACTED]. Run one real login/checkout and grep.'
      }
    },

    pitfalls: [
      {
        title: {
          th: 'mask password แล้ว แต่ที่อื่น log ทั้ง request — password กับเลขบัตรติดไปด้วย',
          en: '"I masked the password, but I log the whole request object elsewhere"'
        },
        why: {
          th: 'mask ทีละ field ที่ call site เดียว พลาดจุดอื่นที่ข้อมูลเดียวกันไหลผ่านอีกเพียบ: toString ของ request/entity ใน exception stack trace, access log ที่เก็บ ?token= ใน URL, DTO ที่ถูก log อีกเลเยอร์, Set-Cookie/JWT ใน header การ redact ต้องรวมศูนย์ที่จุด logging (allowlist ว่าอะไรเข้า log ได้) ไม่ใช่ไปโปรยทีละ field',
          en: 'Masking one field at one call site misses the many other places the same data flows: the request/entity toString in an exception stack trace, an access log capturing ?token= in the URL, a DTO logged at another layer, Set-Cookie/JWT in headers. Redaction must be centralized at the logging boundary (allowlist what may enter the log), not sprinkled field by field.'
        },
        short: {
          th: 'mask ทีละ field พลาดจุดอื่นเสมอ ต้อง redact รวมศูนย์ที่จุด logging ด้วย allowlist',
          en: 'Field-by-field masking misses other sinks; centralize redaction at the logging boundary'
        }
      },
      {
        title: {
          th: 'ปล่อย log ไม่ redact เพราะเป็นระบบภายใน',
          en: '"Logs are internal, so it is fine"'
        },
        why: {
          th: 'log กระจายออกไปไกลกว่า server ของคุณมาก: aggregator ส่วนกลาง (ELK/Splunk/CloudWatch), APM ภายนอก (Datadog/Sentry) ที่ข้อมูลวิ่งออกนอกเขตไปถึง vendor, retention ยาวหลายเดือน, ภาพหน้าจอที่แปะใน ticket/Slack และ support engineer ที่มี permission อ่าน secret แบบ plaintext ใน log เลยเป็น breach ที่รอให้จุดใดจุดหนึ่งหลุด และ PAN ใน log ก็ผิด PCI-DSS ไม่ว่าจะ "ภายใน" หรือไม่',
          en: 'Logs fan out far beyond your server: centralized aggregators (ELK/Splunk/CloudWatch), third-party APM (Datadog/Sentry) that your data leaves your perimeter to reach, retention windows of months, screenshots pasted into tickets/Slack, and support engineers with read access. Plaintext secrets in logs are a breach waiting for any of those to leak — and a PAN in logs violates PCI-DSS regardless of "internal."'
        },
        short: {
          th: 'log กระจายไป aggregator, APM ภายนอก และ backup secret ดิบใน log คือ breach ที่รอหลุด',
          en: 'Logs fan out to aggregators, external APM and backups; raw secrets there are a breach in waiting'
        }
      },
      {
        title: {
          th: 'ตั้งกฎ redact ไว้ที่ SIEM/aggregator',
          en: '"I added a redaction rule in the SIEM/aggregator"'
        },
        why: {
          th: 'redact เฉพาะที่ config ของ aggregator ยังส่ง secret ดิบข้ามสายไปถึง vendor และไปถึง sink อื่นที่อ่านก่อนกฎจะมีผล (stdout, ไฟล์, APM อีกตัว) กฎ display-time ไม่ได้ลบข้อมูลที่ vendor เก็บ index และ retain ไว้แล้ว ต้อง redact ที่ตัวแอปก่อน emit log line',
          en: 'Redacting only in the aggregator’s config still sends the raw secret over the wire to the vendor and to any other sink that reads before the rule applies (stdout, files, another APM). A display-time rule does not delete what the vendor already stored, indexed and retained. Redact in the app before the log line is emitted.'
        },
        short: {
          th: 'redact ที่ aggregator ยังส่ง secret ดิบข้ามสายไป vendor ต้อง redact ในแอปก่อน emit',
          en: 'Redacting at the aggregator still sends raw secrets to the vendor; redact in the app before emit'
        }
      }
    ],

    languages: {
      java: {
        filename: 'LoginController.java',
        lang: 'java',
        starter:
`package com.acme.checkout.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    public void handleLogin(LoginRequest request) {
 // log ทั้ง request ไว้ debug — request มี password, เลขบัตร, header Authorization
        log.info("login req=" + request);
 // ... authenticate ...
    }
}`,
        solution:
`package com.acme.checkout.web;

import net.logstash.logback.argument.StructuredArguments;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    public void handleLogin(LoginRequest request) {
 // log เฉพาะ field ที่เลือกไว้ (allowlist) ไม่แตะ password / Authorization
        log.info("login attempt",
            StructuredArguments.keyValue("userId", request.getUserId()),
            StructuredArguments.keyValue("cardLast4", maskPan(request.getCardNumber())),
            StructuredArguments.keyValue("route", "/login"));
 // ... authenticate ...
    }

 // เก็บเฉพาะ 4 ตัวท้ายของเลขบัตร ที่เหลือปิดด้วย *
    private static String maskPan(String pan) {
        if (pan == null || pan.length() < 4) return "****";
        return "**** **** **** " + pan.substring(pan.length() - 4);
    }
}`,
        explain: {
          th: 'handler เลิก serialize ทั้ง request แล้ว เปลี่ยนเป็นปล่อย structured event ที่มี key ตายตัว (userId, route) บวกเลขบัตรที่ mask แล้ว เพราะมีแค่ field พวกนี้ที่ถูกส่งให้ logger ต่อให้ภายหลังมี field อ่อนไหวเพิ่มก็รั่วไม่ได้ PAN ปรากฏแค่ 4 ตัวท้าย ส่วน password กับ Authorization ไม่ถูกอ้างถึงในคำสั่ง log ไหนเลย',
          en: 'The handler no longer serializes the whole request; it emits a structured event with a fixed set of keys (userId, route) plus a masked card. Because those are the only fields ever passed to the logger, no new sensitive field can leak later, and the PAN appears only as its last 4 digits. The password and Authorization header are never referenced in any log statement.'
        },
        checks: [
          {
            id: 'no-log-whole-request',
            label: { th: 'ไม่ log ทั้ง request — password กับเลขบัตรติดไปด้วย (ไม่มี + request)', en: 'Does not log the whole request object (no + request)' },
            hint: { th: 'ลบ log.info("..." + request) ออก แล้ว log เฉพาะ field ที่เลือก', en: 'Remove log.info("..." + request) and log only chosen fields' },
            weight: 3,
            mustNotMatch: /\+\s*request\b/
          },
          {
            id: 'no-log-sensitive-getter',
            label: { th: 'ไม่ log ค่า password/authorization ตรง ๆ', en: 'Does not log password/authorization values directly' },
            hint: { th: 'อย่าเรียก getPassword()/getAuthorization() ในคำสั่ง log', en: 'Do not call getPassword()/getAuthorization() inside a log statement' },
            weight: 2,
            mustNotMatch: /\.(?:getPassword|getAuthorization|getCvv|getPin)\s*\(/
          },
          {
            id: 'use-structured-logging',
            label: { th: 'ใช้ structured logging (key-value)', en: 'Uses structured logging (key-value)' },
            hint: { th: 'ใช้ StructuredArguments.keyValue(...) หรือ MDC', en: 'Use StructuredArguments.keyValue(...) or MDC' },
            weight: 2,
            mustMatch: /StructuredArguments|keyValue\s*\(|MDC\.put|kv\s*\(|Markers?\.append/
          },
          {
            id: 'mask-sensitive',
            label: { th: 'mask ค่าอ่อนไหว เช่น เลขบัตร', en: 'Masks sensitive values such as the card number' },
            hint: { th: 'เก็บแค่ 4 ตัวท้ายด้วย substring แล้วปิดที่เหลือด้วย *', en: 'Keep only the last 4 with substring and star out the rest' },
            weight: 1,
            mustMatch: /mask|redact|\*{2,}|substring\s*\(/i
          }
        ],
        traps: [
          {
            id: 'log-tostring-request',
            match: /log\.\w+\s*\([^)]*request\.toString\s*\(/,
            message: {
              th: 'การเรียก request.toString() ใน log ก็ดึง password/เลขบัตร/Authorization ออกมาเหมือน log ทั้ง object ให้ log เฉพาะ field ที่เลือกไว้ ไม่ใช่ทั้ง request',
              en: 'Calling request.toString() in a log pulls out the password/card/Authorization just like logging the whole object. Log only the fields you chose, not the whole request.'
            }
          },
          {
            id: 'log-object-json',
            match: /log\.\w+\s*\([^)]*(?:new\s+ObjectMapper|writeValueAsString|toJson|new\s+Gson)\s*\([^)]*request/,
            message: {
              th: 'การ serialize ทั้ง request เป็น JSON แล้ว log ก็เท่ากับ dump ทุก field รวมถึง password/เลขบัตร/token การเปลี่ยนรูปแบบเป็น JSON ไม่ได้ปิดข้อมูลอ่อนไหว ให้ใช้ allowlist ของ field',
              en: 'Serializing the whole request to JSON and logging it dumps every field, including password/card/token. Reformatting as JSON hides nothing sensitive. Use an allowlist of fields.'
            }
          },
          {
            id: 'concat-request',
            match: /"[^"]*"\s*\+\s*request\b/,
            message: {
              th: 'การต่อ request เข้ากับสตริง (แม้จะเก็บใส่ตัวแปรก่อน log) ก็เรียก toString ที่มี password/เลขบัตร/Authorization อยู่ดี ให้ log เฉพาะ field ที่เป็น allowlist',
              en: 'Concatenating request into a string (even into a variable before logging) still calls its toString, which contains the password/card/Authorization. Log only allowlisted fields.'
            }
          }
        ]
      },

      node: {
        filename: 'loginRoute.js',
        lang: 'js',
        starter:
`const express = require('express');
const router = express.Router();

router.post('/login', (req, res) => {
 // debug: log body กับ headers — body มี password/เลขบัตร, headers มี Authorization + cookie
  console.log('login body', req.body);
  console.log('headers', req.headers);
 // ... authenticate ...
  res.sendStatus(200);
});

module.exports = router;`,
        solution:
`const express = require('express');
const pino = require('pino');
const router = express.Router();

// pino ปิดข้อมูลอ่อนไหวที่ boundary: password, เลขบัตร, Authorization header, cookie
const log = pino({
  redact: {
    paths: ['req.body.password', 'req.body.card', 'req.headers.authorization', 'req.headers.cookie'],
    censor: '[REDACTED]'
  }
});

router.post('/login', (req, res) => {
 // log เฉพาะ field ที่เลือกไว้ (allowlist) ไม่ dump ทั้ง body หรือ headers
  log.info({ userId: req.body.userId, route: '/login' }, 'login attempt');
 // ... authenticate ...
  res.sendStatus(200);
});

module.exports = router;`,
        explain: {
          th: 'redact ของ pino ทำงานก่อนข้อมูลถูกเขียนลง log โดย path ที่กำหนด เช่น req.headers.authorization และ req.body.password จะถูกแทนด้วยค่า censor ก่อน serialize จากนั้น handler ยัง log เฉพาะ field ที่อนุญาต เช่น { userId, route } แทนการ log req.body หรือ req.headers ทั้งหมด จึงป้องกันได้ทั้งกรณี dump ข้อมูลมากเกินไปและกรณีลืม redact field ใหม่',
          en: 'pino’s redact runs at the logging boundary: even if a sensitive path is present on the logged object, pino replaces it with the censor value before serialization, so req.headers.authorization and req.body.password never reach any sink. The handler additionally logs only an allowlist object { userId, route } rather than the whole req.body/req.headers, closing both the "dump everything" and "forgot to redact a field" failure modes.'
        },
        checks: [
          {
            id: 'no-log-req-body',
            label: { th: 'ไม่ log ทั้ง req.body', en: 'Does not log the whole req.body' },
            hint: { th: 'ลบ console.log(..., req.body) แล้ว log เฉพาะ field ที่เลือก', en: 'Remove console.log(..., req.body) and log only chosen fields' },
            weight: 3,
            mustNotMatch: /(?:console|log|logger)\.\w+\s*\([^)]*\breq\.body\s*\)/
          },
          {
            id: 'no-log-req-headers',
            label: { th: 'ไม่ log ทั้ง req.headers', en: 'Does not log the whole req.headers' },
            hint: { th: 'อย่า log req.headers ทั้งก้อน (มี Authorization + cookie)', en: 'Do not log the whole req.headers (Authorization + cookie)' },
            weight: 2,
            mustNotMatch: /(?:console|log|logger)\.\w+\s*\([^)]*\breq\.headers\s*\)/
          },
          {
            id: 'redact-sensitive',
            label: { th: 'มีกลไก redact ข้อมูลอ่อนไหว', en: 'Has a redaction mechanism for sensitive data' },
            hint: { th: "ตั้ง pino redact paths หรือใช้ censor / [REDACTED]", en: "Configure pino redact paths or a censor / [REDACTED]" },
            weight: 2,
            mustMatch: /redact\b|censor\b|\[REDACTED\]|maskFields/i
          },
          {
            id: 'allowlist-logged-fields',
            label: { th: 'log เฉพาะ object แบบ allowlist', en: 'Logs only an allowlist object' },
            hint: { th: 'log { userId, route } แทน req.body/req.headers ทั้งก้อน', en: 'Log { userId, route } instead of the whole req.body/req.headers' },
            weight: 1,
            mustMatch: /(?:log|logger)\.\w+\s*\(\s*\{[^}]*\}/
          }
        ],
        traps: [
          {
            id: 'log-whole-req',
            match: /(?:console|log|logger)\.\w+\s*\([^)]*\breq\b\s*\)/,
            message: {
              th: 'การ log ทั้ง req dump ทั้ง body, headers, cookie และ params — รวม password/เลขบัตร/Authorization ทั้งหมด ให้ log เฉพาะ field ที่เลือกและ redact ที่ boundary',
              en: 'Logging the whole req dumps its body, headers, cookies and params — including the password/card/Authorization. Log only chosen fields and redact at the boundary.'
            }
          },
          {
            id: 'stringify-req',
            match: /JSON\.stringify\s*\(\s*req\.(?:body|headers|query)/,
            message: {
              th: 'JSON.stringify(req.body/headers) แล้ว log ก็ยังพ่นข้อมูลอ่อนไหวทั้งหมดออกมา แค่เปลี่ยนรูปแบบเป็นสตริง ให้ใช้ allowlist ของ field และ redact',
              en: 'JSON.stringify(req.body/headers) and logging it still emits all the sensitive data, just as a string. Use an allowlist of fields and redaction.'
            }
          },
          {
            id: 'log-authorization-value',
            match: /(?:console|log|logger)\.\w+\s*\([^)]*\bauthorization\b/i,
            message: {
              th: 'การ log ค่า header Authorization ตรง ๆ เขียน Bearer JWT/token ที่ยังใช้งานได้ลง log ให้ redact path นั้น (req.headers.authorization) ที่จุด logging',
              en: 'Logging the Authorization header value writes a live Bearer JWT/token to the log. Redact that path (req.headers.authorization) at the logging boundary.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'กฎคือ "เลือกว่าอะไรจะเข้า log" ไม่ใช่ "ตามไปขัดสิ่งที่ไม่ควรออก" การ log ทั้ง request/headers/body คือเปิดประตูรับทุก field ทั้งปัจจุบันและอนาคต — รวม password, PAN, Authorization — เข้า log store, aggregator และ backup',
        en: 'The rule is: decide what goes INTO the log, do not scrub what should not. Logging a whole request/headers/body opts in every current and future field — including password, PAN, Authorization — to your log store, aggregator and backups.'
      },
      {
        th: 'เปลี่ยนไปใช้ structured logging และ log เฉพาะ allowlist ของ field (userId, route, status) redact key ที่รู้ว่าอ่อนไหวที่จุด logging (password, card, authorization, cookie, token) เพื่อไม่ให้ call site ใดรั่วได้ และ mask PAN เหลือ 4 ตัวท้าย',
        en: 'Switch to structured logging and log an explicit allowlist of fields (userId, route, status). Redact known-sensitive keys at the logging boundary (password, card, authorization, cookie, token) so no call site can leak them, and mask the PAN to the last 4 digits.'
      },
      {
        th: 'Java: log ผ่าน StructuredArguments.keyValue(...) เฉพาะ field ที่เลือก แล้ว mask เลขบัตร — Node: ตั้ง pino redact: { paths: [\'req.body.password\',\'req.headers.authorization\',...], censor: \'[REDACTED]\' } แล้ว log { userId, route } ไม่ใช่ req.body/req.headers',
        en: 'Java: log via StructuredArguments.keyValue(...) with only the chosen fields and mask the card. Node: configure pino redact: { paths: [\'req.body.password\',\'req.headers.authorization\', ...], censor: \'[REDACTED]\' } and log { userId, route }, never req.body/req.headers.'
      }
    ],

    quiz: [
      {
        q: {
          th: 'นักพัฒนาเปลี่ยนจาก log.info(request) เป็น log.info("user=" + request.getUsername() + " pass=" + request.getPassword()) เพื่อ "log เฉพาะที่จำเป็น" แก้ปัญหาข้อมูลอ่อนไหวได้หรือยัง',
          en: 'A developer replaces log.info(request) with log.info("user=" + request.getUsername() + " pass=" + request.getPassword()) to "log only what we need." Is the sensitive-data problem fixed?'
        },
        choices: [
          { th: 'แก้แล้ว เพราะตอนนี้ log แค่สอง field ไม่ใช่ทั้ง object', en: 'Yes — only two fields are logged now, not the whole object' },
          { th: 'ยังไม่แก้ password ยังถูกเขียนลง log เป็น cleartext ทางแก้คืออย่า log secret เลย และ redact ที่ boundary ไม่ใช่เลือกว่าจะ log secret ตัวไหน', en: 'No — the password is still written to the log in cleartext; the fix is to never log secrets and redact at the boundary, not to hand-pick which secrets to log' },
          { th: 'แก้แล้ว ตราบใดที่ไฟล์ log ตั้ง permission 600 บน server', en: 'Yes, as long as the log file has 600 permissions on the server' },
          { th: 'แก้แล้ว เพราะ log แอปเป็นของภายในและไม่ออกจาก server', en: 'Yes, because application logs are internal and never leave the server' }
        ],
        answer: 1,
        why: {
          th: 'หัวใจคือ credential ต้องไม่ไปถึง log เลย การเลือก field เองแต่ยังมี password อยู่ก็แค่ทำให้การรั่วเป็นระเบียบขึ้น ให้ log allowlist ของ field ที่ไม่อ่อนไหว และ redact secret ที่ส่วนกลาง',
          en: 'The whole point is that credentials must not reach the log at all. Hand-selecting fields that still include the password just makes the leak tidier. Log an allowlist of non-sensitive fields and redact secrets centrally.'
        },
        whyWrong: [
          { th: 'field น้อยลงก็จริง แต่ตัวที่สำคัญ — password — ยังเป็น plaintext ในทุก sink และ backup', en: 'Fewer fields, but the one that matters — the password — is still plaintext in every sink and backup.' },
          null,
          { th: 'permission ไฟล์ไม่ได้กัน log จากการถูกส่งไป aggregator, APM หรือถูกแคปหน้าจอ และคนในที่มี permission อ่านก็ยังเห็นอยู่ดี', en: 'File permissions do not stop the log from being shipped to an aggregator or APM, or screenshotted, and an insider with read access still sees it.' },
          { th: 'log มักออกจาก server ไป aggregator ส่วนกลางและ APM ภายนอก แล้วถูกเก็บไว้อีกหลายเดือน', en: 'Logs routinely leave the server to centralized aggregators and third-party APM, and are retained for months.' }
        ]
      },
      {
        q: {
          th: 'คุณเพิ่มกฎ redact ที่ aggregator (Splunk/Datadog) ให้ mask คำว่า password ทำไมยังไม่พอในตัวมันเอง',
          en: 'You add a redaction rule in your log aggregator (Splunk/Datadog) that masks password. Why is that not sufficient on its own?'
        },
        choices: [
          { th: 'มันพอแล้ว เพราะ aggregator คือที่ที่คนอ่าน log', en: 'It is sufficient — the aggregator is where humans read logs' },
          { th: 'secret ดิบยังถูกส่งไปและถูกเก็บที่ aggregator (และ sink อื่น) ก่อน/โดยไม่ขึ้นกับกฎ display ให้ redact ที่แอปก่อน emit', en: 'The raw secret is still transmitted to and stored by the aggregator (and other sinks) before/regardless of the display rule; redact in the app before emitting' },
          { th: 'กฎ aggregator เป็น case-sensitive จึงพลาดแค่คำว่า Password', en: 'Aggregator rules are case-sensitive, so it only misses Password' },
          { th: 'พอแล้ว ถ้าเปิด TLS ไปยัง aggregator ด้วย', en: 'It is fine as long as you also enable TLS to the aggregator' }
        ],
        answer: 1,
        why: {
          th: 'กฎ display-time ที่ sink เดียวไม่ได้หยุดการส่ง secret ข้ามสาย ไปถูก index และ retain ที่ vendor และไม่ช่วย sink อื่น (stdout, ไฟล์, APM อีกตัว) ให้ redact ที่ต้นทางในแอปก่อน log line ถูก emit',
          en: 'A display-time rule in one sink does not stop the secret from being sent over the wire, indexed and retained by that vendor — and it does nothing for other sinks (stdout, files, another APM). Redact at the source, in the app, before the log line is emitted.'
        },
        whyWrong: [
          { th: 'secret ดิบถูก ingest และเก็บก่อนการ mask ตอนแสดงผล การรั่วของข้อมูล at-rest หรือ sink ที่สองก็ยังเปิดเผยมัน', en: 'The raw secret is ingested and stored before any display masking; an at-rest leak or a second sink still exposes it.' },
          null,
          { th: 'ความ case-sensitive เป็นรายละเอียดเล็ก ต่อให้กฎ display สมบูรณ์ก็ลบสิ่งที่ vendor เก็บไปแล้วไม่ได้', en: 'Case sensitivity is a minor detail; even a perfect display rule cannot un-store what the vendor already kept.' },
          { th: 'TLS ปกป้องข้อมูลระหว่างส่งไป vendor แต่ vendor ก็ยังเก็บ secret เป็น cleartext การเข้ารหัสระหว่างส่งไม่ใช่การ redact', en: 'TLS protects the data in transit to the vendor, but the vendor still stores the cleartext secret; encryption in transit is not redaction.' }
        ]
      }
    ],

    sim: {
      kind: 'log',
      config: {
        fields: {
          username: 'somchai',
          password: 'P@ssw0rd_2024!',
          card: '4111111111111111',
          authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9...'
        },
        redact: ['password', 'card', 'authorization']
      },
      payloads: [
        { label: { th: 'log ทั้ง request — password กับเลขบัตรติดไปด้วย', en: 'Log the whole request object' }, value: 'req' },
        { label: { th: 'log เฉพาะ headers (มี Authorization + Cookie)', en: 'Log the headers (Authorization + Cookie)' }, value: 'headers' },
        { label: { th: 'log body ของฟอร์มชำระเงิน (มีเลขบัตร)', en: 'Log the payment form body (contains the card number)' }, value: 'body' }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP Logging Cheat Sheet — Data to exclude', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html' },
      { label: 'CWE-532: Insertion of Sensitive Information into Log File', url: 'https://cwe.mitre.org/data/definitions/532.html' },
      { label: 'pino documentation — redaction (redact paths)', url: 'https://getpino.io/#/docs/redaction' }
    ]
  };

 /* ======================================================================
 * 5.4 Weak Encryption (AES-ECB)
 * ==================================================================== */
  const WORKSHOP = {
    id: 'w5',
    order: 5,
    title: {
      th: 'Workshop 5: Cryptography & การปกป้องข้อมูล',
      en: 'Workshop 5: Cryptography & Data Protection'
    },
    summary: {
      th: 'Workshop นี้ครอบคลุมปัญหาด้าน cryptography และการปกป้องข้อมูล เช่น token ที่เดาได้, การปิดตรวจ TLS, การ log ข้อมูลอ่อนไหว และการเข้ารหัสด้วยโหมดหรือ key ที่ไม่เหมาะสม',
      en: 'Four cryptography and data-protection failures — predictable randomness, disabled TLS validation, sensitive data in logs, and encryption with a weak mode or key.'
    },
    goal: {
      th: 'จบ workshop นี้ คุณจะเลือกใช้ CSPRNG กับค่าที่ต้องเดาไม่ได้, ตรวจ TLS ให้ถูกต้อง, ป้องกันข้อมูลอ่อนไหวไม่ให้หลุดเข้า log และใช้ authenticated encryption อย่าง AES-GCM พร้อม IV สุ่มและ key ที่โหลดจาก KMS',
      en: 'By the end of this workshop you will pick a CSPRNG for values that must be unguessable, validate TLS certificates correctly, keep sensitive data out of logs with an allowlist plus masking, and encrypt with authenticated encryption (AES-GCM) using a random IV and a KMS-supplied key — and explain why "make it longer" or "only disable verify in dev" is not a fix.'
    },
    exercises: [SENSITIVE_LOGGING]
  };

  global.SCW = global.SCW || { workshops: [], registerWorkshop: function (w) { this.workshops.push(w); } };
  global.SCW.registerWorkshop(WORKSHOP);
  if (typeof module !== 'undefined' && module.exports) module.exports = WORKSHOP;
})(typeof window !== 'undefined' ? window : globalThis);
