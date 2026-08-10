/* ============================================================================
 * js/data/w2.js — Workshop 2: การจัดการ Secret & Configuration
 *
 * 3 โจทย์: hardcoded-secrets, cors-misconfig, verbose-errors
 * โครงสร้างข้อมูลของโจทย์ (ทุกข้อความที่ผู้เรียนเห็นเป็น { th, en })
 *
 * หมายเหตุสำหรับผู้ดูแลไฟล์นี้:
 * - โค้ดตัวอย่างอยู่ใน template literal ดังนั้น backtick, ${ และ backslash
 * ต้อง escape ให้ถูกต้อง
 * - Grader ตัด comment ออกก่อนตรวจเสมอ (ดู js/grader.js) regex จึงไม่ต้อง
 * กังวลว่าจะไปแมตช์กับคอมเมนต์ภาษาไทย และผู้เรียน comment โค้ดออกก็ไม่ผ่าน
 * ==========================================================================*/
(function (global) {
  'use strict';

 /* ======================================================================
 * 2.1 Hardcoded Secrets
 * ==================================================================== */
  const HARDCODED_SECRETS = {
    id: 'hardcoded-secrets',
    title: { th: 'Hardcoded Secrets', en: 'Hardcoded Secrets' },
    severity: 'High',
    cwe: 'CWE-798',
    owasp: 'A05:2021 – Security Misconfiguration',
    category: { th: 'Security Misconfiguration', en: 'Security Misconfiguration' },
    estMinutes: 12,
    points: 120,

    intro: {
      th: 'คลาส config เก็บ password ของ database และ API key ของ Stripe ไว้เป็น string literal ตรง ๆ ในโค้ด ปัญหาไม่ได้อยู่แค่ว่าใครเปิดไฟล์ก็เห็น แต่อยู่ที่ทุกคนที่ clone repo ได้ (พนักงานเก่า, ผู้รับเหมา, เครื่อง CI, ใครก็ตามที่ repo หลุดไปถึง) ถือความลับนั้นไว้ในมือ และพอมัน commit ลง git ไปแล้ว มันจะฝังอยู่ในประวัติ commit ตลอดไป ต่อให้ลบทีหลังก็ยังกู้กลับมาได้',
      en: 'A configuration class holds the database password and the Stripe API key as plain string literals in the source. The problem is not merely that anyone opening the file can see them — it is that everyone who can clone the repo (former staff, contractors, the CI box, anyone the repo ever leaks to) is holding those secrets, and once committed they live in the git history forever, recoverable even after you delete them later.'
    },
    attack: {
      th: 'attacker ที่ ได้ permission อ่าน repo (หรือเจอ repo ที่ถูกตั้ง public โดยไม่ตั้งใจ) รัน git log -p -S \'sk_live_\' -- src/ ก็เจอ API key ตัวจริงในไม่กี่วินาที จากนั้นเรียก Stripe API ในนามคุณเพื่อดูรายการชำระเงิน คืนเงิน หรือสร้าง charge และใช้ password database เชื่อมต่อเข้า database production โดยตรง เครื่องมืออย่าง trufflehog และ gitleaks สแกนทั้ง repo และทุก commit ให้อัตโนมัติ attacker จึงไม่ต้องนั่งเปิดหาเองด้วยซ้ำ',
      en: 'An attacker with read access to the repo (or one who finds it accidentally public) runs git log -p -S \'sk_live_\' -- src/ and recovers the live API key in seconds, then calls the Stripe API as you — listing payments, issuing refunds, creating charges — and connects straight to the production database with the leaked password. Tools like trufflehog and gitleaks scan the whole repo and every commit automatically, so an attacker need not even look by hand.'
    },
    fix: {
      th: 'ย้ายความลับออกจาก source code ไปไว้ใน environment ตอน runtime (หรือ secret manager อย่าง Vault / AWS Secrets Manager / Kubernetes Secret) แล้วอ่านค่าด้วย System.getenv หรือ @Value("${...}") ใน Java และ process.env ใน Node โค้ดที่ commit ขึ้น repo จึงมีแต่ "ชื่อ" ของค่า ไม่มีตัวค่าจริง เสริมด้วย fail-fast คือถ้า env ที่จำเป็นไม่ถูกตั้ง ให้แอปหยุดตั้งแต่ boot ไม่ใช่ไปพังกลางคัน และเพิ่ม.gitignore กันไฟล์.env หลุดขึ้น repo ที่สำคัญที่สุด: ความลับใดที่เคย commit ไปแล้วถือว่ารั่วถาวร ต้อง rotate (เพิกถอนแล้วออกใหม่) เสมอ การลบบรรทัดออกเฉย ๆ ไม่ช่วยอะไร',
      en: 'Move the secrets out of the source into the runtime environment (or a secret manager such as Vault / AWS Secrets Manager / a Kubernetes Secret) and read them with System.getenv or @Value("${...}") in Java and process.env in Node, so the committed code carries only the name of each value, never the value itself. Add a fail-fast check: if a required variable is unset, the app should stop at boot rather than break mid-request. Add .gitignore so a .env file cannot slip into the repo. Most important: any secret that was ever committed must be treated as permanently leaked and rotated (revoked and reissued) — deleting the line does nothing.'
    },
    keyPoints: {
      vuln: [
        { th: 'password database และ Stripe API key ถูกเก็บเป็น string literal ใน source code', en: 'The DB password and Stripe API key are stored as plain string literals in the source.' },
        { th: 'ทุกคนที่ clone repo ได้ (พนักงานเก่า, CI, repo ที่หลุด) ถือความลับนั้นไว้', en: 'Everyone who can clone the repo — ex-staff, CI, a leaked copy — holds those secrets.' },
        { th: 'พอ commit ลง git แล้ว ความลับจะฝังในประวัติตลอดไป ลบทีหลังก็กู้กลับได้', en: 'Once committed, a secret lives in git history forever, recoverable after you delete it.' }
      ],
      attack: [
        { th: 'ถ้า attacker อ่าน repo ได้ ก็สามารถค้นย้อนหลังทั้งประวัติ Git เช่น git log -p -S \'sk_live_\' และพบ API key ที่เคยถูก commit ไว้ได้ แม้ไฟล์ปัจจุบันจะลบค่าออกแล้ว', en: 'Run git log -p -S \'sk_live_\' and the live API key surfaces in seconds.' },
        { th: 'เมื่อได้ secret ที่ใช้งานจริง attacker สามารถนำไปเรียก API ในนามระบบ หรือใช้ password เชื่อมต่อ database production ได้ทันทีตามสิทธิ์ของค่านั้น', en: 'Call the Stripe API as you, and connect to the production DB with the leaked password.' },
        { th: 'เครื่องมืออย่าง trufflehog และ gitleaks สแกนหา secret ในประวัติ Git ได้อัตโนมัติ attacker จึงไม่จำเป็นต้องเปิดทุก commit เพื่อค้นหาด้วยตัวเอง', en: 'trufflehog and gitleaks scan every commit automatically — no manual searching needed.' }
      ],
      fix: [
        { th: 'ย้าย secret ออกจาก source code ไปไว้ใน environment variable หรือ secret manager เช่น Vault แล้วให้แอปอ่านค่าตอน runtime', en: 'Move secrets into the environment or a secret manager and read them at runtime.' },
        { th: 'secret ที่เคย commit ให้ถือว่ารั่วแล้ว ต้อง rotate โดยยกเลิกค่าเดิมและออกค่าใหม่ การลบออกจากไฟล์อย่างเดียวไม่พอ เพราะค่ายังอยู่ในประวัติ Git', en: 'Always rotate any key that was ever committed — it is leaked; deleting the line does nothing.' },
        { th: 'ใช้ fail-fast: ถ้า environment variable ที่จำเป็นไม่มีค่า ให้แอปหยุดตั้งแต่เริ่มทำงาน แทนที่จะปล่อยให้ไปเกิด error ระหว่างรับ request', en: 'Add a fail-fast check so the app stops at boot when a required variable is unset.' }
      ]
    },
    impact: {
      th: 'หาก secret ที่ใช้งานจริงหลุดออกไป attacker อาจเชื่อมต่อ database production หรือเรียก API ภายนอกในนามระบบ ทำให้ข้อมูลลูกค้าและทรัพยากรของบริษัทถูกเข้าถึงโดยไม่ได้รับอนุญาต',
      en: 'An attacker connects to your production database and calls your payment API as the company outright — full access to customer data and direct financial loss.'
    },

    caseStudy: {
      year: 2016,
      title: {
        th: 'Uber 2016 — access key ใน private GitHub repo สู่ข้อมูล 57 ล้านราย',
        en: 'Uber 2016 — an access key in a private GitHub repo led to 57 million records'
      },
      body: {
        th: 'ในปี 2016 attacker สองคนเข้าถึง private GitHub repository ที่วิศวกรของ Uber ใช้ทำงาน แล้วพบ AWS access key ถูกเก็บไว้เป็น plaintext อยู่ในนั้น จากนั้นใช้คีย์ดังกล่าวเข้าถึง S3 datastore แล้วดาวน์โหลดข้อมูลส่วนบุคคลของผู้ใช้และคนขับรวม 57 ล้านรายทั่วโลก โดยมีเลขใบขับขี่ของคนขับในสหรัฐฯ ราว 600,000 รายรวมอยู่ด้วย Uber ปกปิดเหตุการณ์และจ่ายเงินให้ attacker 100,000 ดอลลาร์เพื่อให้ลบข้อมูล กว่าจะเปิดเผยต่อสาธารณะก็ปี 2017 และในปี 2018 FTC ได้ออกคำสั่งขยายข้อตกลงด้านความปลอดภัยกับ Uber บทเรียนตรงจุดคือ credential ที่อยู่ในซอร์สหรือใน repo คือความลับที่รั่วแล้ว รอแค่วันที่จะถูกใช้',
        en: 'In 2016 two attackers reached a private GitHub repository used by Uber\'s engineers and found an AWS access key stored there in plaintext. They used it to reach an S3 datastore and download the personal data of 57 million riders and drivers worldwide, including the driver\'s license numbers of about 600,000 U.S. drivers. Uber concealed the incident and paid the attackers $100,000 to delete the data, only disclosing it publicly in 2017; in 2018 the FTC issued an expanded settlement order over Uber\'s security. The lesson is precise: a credential sitting in source or in a repo is already a leaked secret, waiting only for the day it is used.'
      },
      source: {
        label: 'U.S. FTC — FTC addresses Uber\'s undisclosed data breach in new proposed order (April 2018)',
        url: 'https://www.ftc.gov/business-guidance/blog/2018/04/ftc-addresses-ubers-undisclosed-data-breach-new-proposed-order'
      }
    },

    codeReview: [
      {
        th: 'ตอน Code Review ให้ใช้ grep diff หา prefix ของคีย์ที่รู้จัก: sk_live_ (Stripe), AKIA (AWS), AIza (Google), xoxb- (Slack), ghp_ (GitHub) และบล็อก -----BEGIN... PRIVATE KEY----- เจอในไฟล์ที่ commit เมื่อไหร่ ถือว่ารั่ว',
        en: 'grep the diff for known key prefixes: sk_live_ (Stripe), AKIA (AWS), AIza (Google), xoxb- (Slack), ghp_ (GitHub), and the -----BEGIN ... PRIVATE KEY----- block.'
      },
      {
        th: 'string literal ที่ assign ให้ตัวแปร/ฟิลด์ชื่อ password, secret, token, apiKey, privateKey ค่าคงที่ตรงนี้แทบไม่มีเหตุผลที่ถูกต้อง ให้ถามว่าทำไมความลับมาปรากฏในโค้ด',
        en: 'A string literal assigned to any variable, field, or key named password, secret, token, apiKey, or privateKey — a constant there almost never has a legitimate reason to exist.'
      },
      {
        th: 'ค่าที่อ่านจาก process.env / System.getenv แต่มี fallback hardcode ต่อท้าย (|| \'ค่าเริ่มต้น\', orElse("..."), getOrDefault(name, "...")) ตัว fallback นั่นแหละคือความลับที่ commit ขึ้นไป',
        en: 'A value read from process.env / System.getenv but with a hardcoded fallback attached (|| \'default\', orElse("..."), getOrDefault(name, "...")) — that fallback is the committed secret.'
      },
      {
        th: 'ไฟล์ config/.env ที่ git ติดตามอยู่: รัน git ls-files | grep -E \'\\.env|application-.*\\.(properties|yml)\' ถ้าไฟล์พวกนี้มีค่าจริง หมายความว่าความลับถูก commit ไปแล้ว',
        en: 'Config/.env files tracked by git: run git ls-files | grep -E \'\\.env|application-.*\\.(properties|yml)\' — if one holds real values, the secret is already committed.'
      },
      {
        th: 'ตรวจว่าต่อ secret scanner (gitleaks / trufflehog) เข้ากับ CI แล้วสแกน "ทุก commit ในประวัติ" ไม่ใช่แค่ commit ล่าสุด เพราะความลับเก่ายังกู้จากประวัติได้',
        en: 'Wire a secret scanner (gitleaks / trufflehog) into CI to scan the full commit history, not just the tip — old secrets are still recoverable from history.'
      }
    ],

    testIt: {
      cmd: "git log -p -S 'sk_live_' -- src/",
      note: {
        th: 'ถ้าคำสั่งนี้แสดงคีย์จริงออกมา หมายความว่าความลับยังอยู่ในประวัติ git แม้ไฟล์ปัจจุบันจะลบไปแล้ว ต้อง rotate คีย์ทันทีและย้ายค่าใหม่ออกจาก source code จากนั้นใช้ git grep \'sk_live_\' $(git rev-list --all) ตรวจทั้งประวัติอีกครั้ง',
        en: 'If this command prints the real key, the secret is still in git history even after the current file drops it. The correct fix must both (1) rotate the key immediately and (2) read the new value from the environment — run git grep \'sk_live_\' $(git rev-list --all) to sweep the entire history as a second pass.'
      }
    },

    pitfalls: [
      {
        title: {
          th: 'ลบ secret ออกในคอมมิตถัดไป',
          en: '"I deleted the secret in a later commit"'
        },
        why: {
          th: 'git เก็บทุกเวอร์ชันของทุกไฟล์ไว้ ใครก็ตามที่มี clone อยู่ในมือรัน git log -p, git show <commit เก่า> หรือ git grep กับ git rev-list --all ก็ดึงค่ากลับมาได้ครบ การลบบรรทัดจึงแค่ทำให้ไฟล์ปัจจุบันสะอาด แต่ไม่ได้ลบความลับออกจากประวัติเลย วิธีเดียวที่ได้ผลจริงคือถือว่าคีย์นั้น "รั่วแล้ว" แล้ว rotate — เพิกถอนคีย์เก่าและออกคีย์ใหม่ที่ไม่เคยแตะ source code (การเขียนประวัติใหม่ด้วย filter-repo ช่วยลดร่องรอย แต่ก็ยังต้อง rotate อยู่ดี เพราะสำเนาเก่าอาจกระจายไปแล้ว)',
          en: 'git keeps every version of every file. Anyone holding a clone can run git log -p, git show <old commit>, or git grep across git rev-list --all and pull the value straight back. Deleting the line only makes the current file clean; it does not remove the secret from history. The only thing that actually works is to treat the key as leaked and rotate it — revoke the old one and issue a new one that never touches source. (Rewriting history with filter-repo reduces the traces, but you must still rotate, because old copies may already be out there.)'
        },
        short: {
          th: 'ความลับยังอยู่ในประวัติ git — ต้อง rotate ไม่ใช่แค่ลบบรรทัด',
          en: 'The secret is still in git history — rotate it, do not just delete the line.'
        }
      },
      {
        title: {
          th: 'ย้าย secret ไปไว้ในไฟล์ config',
          en: '"I moved it into a config file"'
        },
        why: {
          th: 'ถ้าไฟล์ config นั้น (application.properties, config.json,.env) ยังถูก commit ขึ้น repo ก็ไม่ต่างจากการ hardcode ในโค้ดเลยแม้แต่น้อย — ความลับก็ยังอยู่ในประวัติ git เหมือนเดิม สิ่งที่ทำให้ปลอดภัยไม่ใช่ "ไฟล์ไหน" แต่คือ "ค่านั้นไม่เคยเข้า repo" ให้เก็บค่าจริงไว้ใน environment หรือ secret manager, ใส่ไฟล์ที่มีค่าจริงลง.gitignore, แล้ว commit เฉพาะไฟล์ตัวอย่างอย่าง.env.example ที่มีแต่ชื่อคีย์ ไม่มีค่า',
          en: 'If that config file (application.properties, config.json, .env) is still committed to the repo, it is no different from hardcoding in code — the secret is right there in git history all the same. What makes it safe is not which file it lives in but that the value never enters the repo. Keep the real values in the environment or a secret manager, put any file with real values in .gitignore, and commit only a sample like .env.example that lists the key names with no values.'
        },
        short: {
          th: 'ถ้าไฟล์ config ยังถูก commit ก็ไม่ต่างจาก hardcode ในโค้ด',
          en: 'A config file that is still committed is no better than hardcoding in code.'
        }
      },
      {
        title: {
          th: 'เข้ารหัส secret ด้วย base64 ก่อน commit',
          en: '"I base64-encoded it so it is not readable in plaintext"'
        },
        why: {
          th: 'base64 คือการ "เข้ารหัสรูปแบบ" ไม่ใช่การเข้ารหัสลับ ใครเห็นก็ decode กลับได้ในคำสั่งเดียว (echo... | base64 -d) และตัว blob ที่เข้ารหัสก็ยัง commit อยู่ใน git อยู่ดี secret scanner สมัยใหม่ยังถอด base64 แล้วจับ prefix อย่าง sk_live_ ได้เองด้วยซ้ำ การซ่อนรูปไม่ได้ทำให้ความลับหายไปจาก repo — ต้องเอาค่าออกจาก repo จริง ๆ เท่านั้น',
          en: 'base64 is an encoding, not encryption — anyone can decode it back in one command (echo ... | base64 -d), and the encoded blob is still committed in git regardless. Modern secret scanners even base64-decode blobs and match prefixes like sk_live_ themselves. Disguising the shape does not remove the secret from the repo; only taking the value out of the repo does.'
        },
        short: {
          th: 'base64 คือการเข้ารหัสรูปแบบ decode กลับได้ในคำสั่งเดียว',
          en: 'base64 is an encoding, decodable in one command — it hides nothing.'
        }
      }
    ],

    languages: {
      java: {
        filename: 'AppConfig.java',
        lang: 'java',
        starter:
`package com.acme.billing.config;

import javax.sql.DataSource;
import com.zaxxer.hikari.HikariDataSource;

/** ค่าคอนฟิกของบริการเก็บเงิน (billing service) */
public class AppConfig {

 // TODO: ย้ายเข้า vault ทีหลัง — ตอนนี้ hardcode ไว้ก่อนให้ deploy ทัน
    private static final String DB_URL = "jdbc:postgresql://db.internal:5432/billing";
    private static final String DB_USER = "billing_app";
    private static final String DB_PASSWORD = "Pr0d$ecret_2023!";
    private static final String STRIPE_API_KEY = "sk_live_51H8xQe2eZvKYlo2CabcDEF";

    public DataSource dataSource() {
        HikariDataSource ds = new HikariDataSource();
        ds.setJdbcUrl(DB_URL);
        ds.setUsername(DB_USER);
        ds.setPassword(DB_PASSWORD);
        return ds;
    }

    public String stripeApiKey() {
        return STRIPE_API_KEY;
    }
}`,
        solution:
`package com.acme.billing.config;

import javax.sql.DataSource;
import com.zaxxer.hikari.HikariDataSource;

public class AppConfig {

 // อ่านความลับจาก environment ตอน runtime ไม่มี literal ใน source code อีกต่อไป
    private final String dbUrl = requireEnv("BILLING_DB_URL");
    private final String dbUser = requireEnv("BILLING_DB_USER");
    private final String dbPassword = requireEnv("BILLING_DB_PASSWORD");
    private final String stripeApiKey = requireEnv("STRIPE_API_KEY");

 // fail-fast: ถ้าไม่มีค่า ให้แอปหยุดตั้งแต่ boot ดีกว่าไปพังตอน query
    private static String requireEnv(String name) {
        String v = System.getenv(name);
        if (v == null || v.isEmpty()) {
            throw new IllegalStateException("missing required env var: " + name);
        }
        return v;
    }

    public DataSource dataSource() {
        HikariDataSource ds = new HikariDataSource();
        ds.setJdbcUrl(dbUrl);
        ds.setUsername(dbUser);
        ds.setPassword(dbPassword);
        return ds;
    }

    public String stripeApiKey() {
        return stripeApiKey;
    }
}`,
        explain: {
          th: 'secret ทั้งสี่ค่าถูกเปลี่ยนจาก string literal มาอ่านผ่าน System.getenv ตอน runtime ด้วย requireEnv ดังนั้นไฟล์ .java ใน repo จะมีเพียงชื่อ env var ไม่มีค่าจริงให้ Git เก็บในประวัติ และถ้า env ที่จำเป็นไม่มีค่า requireEnv จะหยุดแอปตั้งแต่เริ่มทำงานแทนที่จะปล่อยให้ไปเกิด error ตอนเชื่อมต่อ database ส่วน secret ที่เคย commit ไปแล้วต้อง rotate เพราะถือว่ารั่วแล้ว',
          en: 'All four secrets move from string literals to reads from System.getenv at runtime through the requireEnv helper, so the committed .java file carries only the env-var names (BILLING_DB_PASSWORD, STRIPE_API_KEY) — no real value for git to record in history. requireEnv also fails fast: if a variable is unset it throws while the object is being built, rather than leaving the password null and blowing up later at connection time. In a Spring project you could write this more briefly with @Value("${billing.db.password}") mapped from the environment, to the same effect. The point to remember: the values already committed (Pr0d$ecret_2023! and that sk_live_ key) are permanently leaked and must both be rotated — moving to env is not enough on its own.'
        },
        checks: [
          {
            id: 'no-secret-literal',
            label: { th: 'ไม่มี string literal ที่เป็นความลับใน source code', en: 'No secret string literals remain in the source' },
            hint: { th: 'ลบ = "..." ที่ผูกกับ password/secret/apiKey/token ออก แล้วอ่านจาก System.getenv แทน', en: 'Remove any = "..." assigned to a password/secret/apiKey/token and read it from System.getenv instead' },
            weight: 3,
            mustNotMatch: /(?:password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*=\s*['"][^'"]{5,}['"]/i
          },
          {
            id: 'no-live-key',
            label: { th: 'ไม่มี Stripe live key ฝังอยู่ในโค้ด', en: 'No Stripe live key embedded in the code' },
            hint: { th: 'ลบค่า sk_live_... ออกจากซอร์ส แล้ว rotate คีย์นั้นเพราะมันรั่วไปแล้ว', en: 'Delete the sk_live_... value from source and rotate that key — it has already leaked' },
            weight: 2,
            mustNotMatch: /sk_live_[0-9A-Za-z]/
          },
          {
            id: 'read-from-env',
            label: { th: 'อ่านความลับจาก environment (System.getenv / @Value)', en: 'Reads secrets from the environment (System.getenv / @Value)' },
            hint: { th: 'ใช้ System.getenv("BILLING_DB_PASSWORD") หรือ @Value("${...}") map จาก env', en: 'Use System.getenv("BILLING_DB_PASSWORD") or @Value("${...}") mapped from the environment' },
            weight: 3,
            mustMatch: /System\s*\.\s*getenv\s*\(|@Value\s*\(/
          },
          {
            id: 'guard-missing-env',
            label: { th: 'ตรวจว่าค่า env ที่จำเป็นไม่ว่าง (null/empty)', en: 'Guards that a required env value is not null/empty' },
            hint: { th: 'เพิ่มเงื่อนไข if (v == null || v.isEmpty()) ก่อนใช้ค่า', en: 'Add if (v == null || v.isEmpty()) before using the value' },
            weight: 2,
            mustMatch: /==\s*null|\.isEmpty\s*\(\s*\)|\.isBlank\s*\(\s*\)/
          },
          {
            id: 'fail-fast',
            label: { th: 'fail-fast เมื่อความลับที่จำเป็นหายไป', en: 'Fails fast when a required secret is missing' },
            hint: { th: 'throw IllegalStateException เมื่อ env var ที่จำเป็นไม่ถูกตั้ง', en: 'throw IllegalStateException when a required env var is not set' },
            weight: 1,
            mustMatch: /throw\s+new\s+\w+/
          }
        ],
        traps: [
          {
            id: 'env-with-hardcoded-fallback',
            match: /(?:orElse|getOrDefault|getProperty)\s*\([^)]*['"][^'"]{4,}['"]\s*\)/,
            message: {
              th: 'การอ่าน env แล้วใส่ fallback เป็นค่าจริง เช่น getenv("STRIPE_API_KEY")... orElse("sk_live_...") ทำให้ความลับยังถูก commit อยู่ในซอร์สเหมือนเดิมทุกประการ ตัว fallback คือ hardcoded secret ที่ซ่อนอยู่ ให้ลบค่า default ที่เป็นความลับทิ้ง แล้ว fail-fast แทนถ้า env ไม่ถูกตั้ง',
              en: 'Reading env with a real-value fallback such as getenv("STRIPE_API_KEY") ... orElse("sk_live_...") still commits the secret to source exactly as before — the fallback is a hidden hardcoded secret. Delete the secret default and fail fast instead when the variable is unset.'
            }
          },
          {
            id: 'base64-obfuscation',
            match: /Base64\s*\.\s*getDecoder\s*\(\s*\)\s*\.\s*decode\s*\(\s*['"][A-Za-z0-9+\/=]{16,}/,
            message: {
              th: 'การ decode ค่า base64 ที่ฝังไว้ในโค้ดไม่ได้ทำให้ปลอดภัยขึ้นเลย base64 ถอดกลับได้ในคำสั่งเดียวและ blob นั้นก็ยัง commit อยู่ใน git ให้เอาค่าออกจาก repo แล้วอ่านจาก environment แทน',
              en: 'Decoding a base64 blob embedded in the code makes nothing safer: base64 is reversible in one command and the blob is still committed in git. Take the value out of the repo and read it from the environment instead.'
            }
          }
        ]
      },

      node: {
        filename: 'config.js',
        lang: 'js',
        starter:
`// config.js — ค่าคอนฟิกของบริการเก็บเงิน (billing service)
module.exports = {
  db: {
    host: 'db.internal',
    port: 5432,
    user: 'billing_app',
 // TODO: ย้ายเข้า secret manager ทีหลัง
    password: 'Pr0d$ecret_2023!',
  },
  stripeApiKey: 'sk_live_51H8xQe2eZvKYlo2CabcDEF',
};`,
        solution:
`// config.js — อ่านความลับจาก environment เท่านั้น ไม่มี literal ในไฟล์ที่ commit
function requireEnv(name) {
  const v = process.env[name];
  if (!v) {
 // fail-fast: หยุดตั้งแต่ boot ถ้าตั้งค่า env ไม่ครบ
    throw new Error(\`missing required env var: \${name}\`);
  }
  return v;
}

module.exports = {
  db: {
    host: process.env.BILLING_DB_HOST,
    port: Number(process.env.BILLING_DB_PORT) || 5432,
    user: process.env.BILLING_DB_USER,
    password: requireEnv('BILLING_DB_PASSWORD'),
  },
  stripeApiKey: requireEnv('STRIPE_API_KEY'),
};`,
        explain: {
          th: 'โค้ดอ่าน secret จาก process.env ผ่าน requireEnv ทำให้ repo เก็บเพียงชื่อ env var ไม่ใช่ค่าจริง และถ้าค่าที่จำเป็นไม่มี แอปจะหยุดตั้งแต่เริ่มทำงานแทนที่จะไปเกิด error ตอนเชื่อมต่อ database ค่าอย่าง port ใช้ default ได้เพราะไม่ใช่ secret แต่ password หรือ API key ห้ามมี fallback แบบ hardcode และค่าที่เคย commit ไปแล้วต้อง rotate พร้อมกัน',
          en: 'The committed object literal no longer holds any real secret — only env-var names via process.env.*, wrapped by requireEnv which throws immediately if a required value is unset (fail-fast — better than leaving the password undefined and crashing later at DB connect time). Note that port can use || 5432 as a default because 5432 is not a secret; never do the same for password/apiKey, because a secret fallback is just hidden hardcoding. And as always: the values already committed (Pr0d$ecret_2023! and the sk_live_ key) are permanently leaked and must both be rotated, alongside adding .env to .gitignore.'
        },
        checks: [
          {
            id: 'no-secret-literal',
            label: { th: 'ไม่มี string literal ที่เป็นความลับใน config', en: 'No secret string literals remain in the config' },
            hint: { th: 'ลบ password/secret/apiKey/token: "..." ออก แล้วอ่านจาก process.env แทน', en: 'Remove any password/secret/apiKey/token: "..." and read it from process.env instead' },
            weight: 3,
            mustNotMatch: /(?:password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*:\s*['"][^'"]{5,}['"]/i
          },
          {
            id: 'no-live-key',
            label: { th: 'ไม่มี Stripe live key ฝังอยู่ในโค้ด', en: 'No Stripe live key embedded in the code' },
            hint: { th: 'ลบค่า sk_live_... ออก แล้ว rotate คีย์นั้นเพราะมันรั่วไปแล้ว', en: 'Delete the sk_live_... value and rotate that key — it has already leaked' },
            weight: 2,
            mustNotMatch: /sk_live_[0-9A-Za-z]/
          },
          {
            id: 'read-from-env',
            label: { th: 'อ่านความลับจาก process.env', en: 'Reads secrets from process.env' },
            hint: { th: 'ใช้ process.env.BILLING_DB_PASSWORD / process.env.STRIPE_API_KEY', en: 'Use process.env.BILLING_DB_PASSWORD / process.env.STRIPE_API_KEY' },
            weight: 3,
            mustMatch: /process\s*\.\s*env\b/
          },
          {
            id: 'guard-missing-env',
            label: { th: 'ตรวจว่าค่า env ที่จำเป็นไม่ว่าง', en: 'Guards that a required env value is present' },
            hint: { th: 'เพิ่ม if (!v) { throw... } ก่อนใช้ค่า', en: 'Add if (!v) { throw ... } before using the value' },
            weight: 2,
            mustMatch: /if\s*\(\s*!\s*\w/
          },
          {
            id: 'fail-fast',
            label: { th: 'fail-fast เมื่อความลับที่จำเป็นหายไป', en: 'Fails fast when a required secret is missing' },
            hint: { th: 'throw new Error(...) เมื่อ env var ที่จำเป็นไม่ถูกตั้ง', en: 'throw new Error(...) when a required env var is not set' },
            weight: 1,
            mustMatch: /throw\s+new\s+\w+/
          }
        ],
        traps: [
          {
            id: 'env-with-hardcoded-fallback',
            match: /process\s*\.\s*env(?:\s*\.\s*\w+|\s*\[\s*['"][^'"]+['"]\s*\])\s*\|\|\s*['"][^'"]{4,}['"]/,
            message: {
              th: 'process.env.STRIPE_API_KEY || \'sk_live_...\' คือการเก็บความลับไว้เป็น default ที่ยัง commit อยู่ในซอร์ส ตัว fallback นั่นคือ hardcoded secret ที่ซ่อนไว้ (ต่างจาก || 5432 ที่เป็น port ธรรมดา ไม่ใช่ความลับ) ให้ลบ default ที่เป็นความลับทิ้งแล้ว throw ถ้า env ไม่ถูกตั้ง',
              en: 'process.env.STRIPE_API_KEY || \'sk_live_...\' keeps the secret as a default that is still committed in source — that fallback is a hidden hardcoded secret (unlike || 5432, an ordinary non-secret port). Delete the secret default and throw when the variable is unset.'
            }
          },
          {
            id: 'base64-obfuscation',
            match: /(?:Buffer\s*\.\s*from\s*\(\s*['"][A-Za-z0-9+\/=]{16,}['"]\s*,\s*['"]base64|atob\s*\(\s*['"][A-Za-z0-9+\/=]{16,})/,
            message: {
              th: 'การ decode ค่า base64 ที่ฝังไว้ (Buffer.from(..., \'base64\') หรือ atob(...)) ไม่ได้ปลอดภัยขึ้น base64 ถอดกลับได้ทันทีและ blob ยัง commit อยู่ใน git ให้เอาค่าออกจาก repo แล้วอ่านจาก process.env แทน',
              en: 'Decoding an embedded base64 value (Buffer.from(..., \'base64\') or atob(...)) is not safer: base64 reverses instantly and the blob is still committed in git. Take the value out of the repo and read it from process.env instead.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'ลองถามตัวเองว่า "ถ้ามีคน clone repo นี้ไปทั้งประวัติ เขาจะเห็นความลับไหม" ถ้าเห็น หมายความว่าค่านั้นต้องไม่อยู่ในซอร์สตั้งแต่แรก และค่าที่เคยอยู่ต้องถูก rotate',
        en: 'Ask: "if someone clones this repo with its full history, will they see the secret?" If yes, the value must not be in source at all — and whatever was there must be rotated.'
      },
      {
        th: 'แยก "ชื่อของค่า" ออกจาก "ตัวค่า" ให้ชัด source code เก็บได้แค่ชื่อ (BILLING_DB_PASSWORD) ส่วนตัวค่าจริงอยู่ใน environment หรือ secret manager ตอน deploy เท่านั้น',
        en: 'Separate the name of a value from the value itself. Source may hold only the name (BILLING_DB_PASSWORD); the real value lives in the environment or a secret manager at deploy time.'
      },
      {
        th: 'Java: System.getenv("NAME") ห่อด้วยตัวช่วยที่ throw ถ้าค่าว่าง (fail-fast) — Node: process.env.NAME พร้อม if (!v) throw... และอย่าใส่ fallback ที่เป็นความลับ (|| \'sk_live_...\')',
        en: 'Java: System.getenv("NAME") wrapped in a helper that throws when empty (fail-fast). Node: process.env.NAME with if (!v) throw ... — and never a secret fallback (|| \'sk_live_...\').'
      }
    ],

    quiz: [
      {
        q: {
          th: 'ทีมพบว่ามี API key hardcode อยู่ จึงลบบรรทัดนั้นออกแล้ว commit ใหม่ว่า "remove secret" ตอนนี้ปลอดภัยหรือยัง',
          en: 'A team finds a hardcoded API key, deletes the line, and commits "remove secret". Are they safe now?'
        },
        choices: [
          { th: 'ปลอดภัยแล้ว เพราะไฟล์ปัจจุบันไม่มีคีย์อยู่แล้ว', en: 'Safe — the current file no longer contains the key' },
          { th: 'ยังไม่ปลอดภัย เพราะคีย์ยังอยู่ในประวัติ git และต้อง rotate คีย์นั้น', en: 'Not safe — the key is still in git history and must be rotated' },
          { th: 'ปลอดภัยแล้ว ถ้า force-push ทับ branch เพื่อลบ commit ล่าสุด', en: 'Safe, as long as you force-push over the branch to drop the last commit' },
          { th: 'ปลอดภัยแล้ว ถ้าเปลี่ยน repo เป็น private', en: 'Safe once the repo is made private' }
        ],
        answer: 1,
        why: {
          th: 'git เก็บทุกเวอร์ชันไว้ ใครมี clone อยู่ก็ git log -p / git show commit เก่าดึงคีย์กลับมาได้ การลบบรรทัดไม่ได้ลบความลับออกจากประวัติ เมื่อคีย์เคยออกไปสู่สายตาคนอื่นแล้ว วิธีเดียวที่ตัดความเสี่ยงได้จริงคือ rotate: เพิกถอนคีย์เก่าและออกใหม่',
          en: 'git keeps every version, so anyone with a clone can recover the key via git log -p or git show on an old commit. Deleting the line does not remove the secret from history. Once a key has been exposed to others, the only thing that truly removes the risk is rotation: revoke the old key and issue a new one.'
        },
        whyWrong: [
          { th: 'ไฟล์ปัจจุบันสะอาดก็จริง แต่ประวัติ commit ยังมีคีย์อยู่เต็ม ๆ กู้กลับได้ในคำสั่งเดียว', en: 'The current file is clean, but the commit history still holds the key in full and it is recoverable in one command.' },
          null,
          { th: 'force-push อาจลบ commit ออกจาก branch ได้ แต่สำเนา/clone/CI cache ที่มีคีย์อยู่แล้วยังคงมีอยู่ และคีย์ก็ยังใช้งานได้จนกว่าจะ rotate', en: 'A force-push may remove the commit from the branch, but clones, forks, and CI caches that already have the key still exist — and the key still works until it is rotated.' },
          { th: 'การเปลี่ยนเป็น private ลดคนที่เข้าถึงได้ แต่คีย์ก็ยังรั่วไปแล้วในอดีต และคนในทีม/ผู้รับเหมา/CI ก็ยังเห็นอยู่ ต้อง rotate อยู่ดี', en: 'Going private narrows who can access it, but the key has already been exposed and insiders, contractors, and CI still see it — you must rotate regardless.' }
        ]
      },
      {
        q: {
          th: 'ข้อใดคือวิธีจัดการความลับใน production ที่ถูกต้องที่สุด',
          en: 'Which is the most correct way to handle secrets in production?'
        },
        choices: [
          { th: 'เก็บไว้ใน application.properties ที่ commit ขึ้น repo แต่ใส่ comment ว่าห้ามแก้', en: 'Keep them in application.properties committed to the repo, with a comment saying not to edit' },
          { th: 'base64-encode ค่าแล้วเก็บไว้ในโค้ดเพื่อไม่ให้อ่านออกตรง ๆ', en: 'base64-encode the values and keep them in code so they are not directly readable' },
          { th: 'อ่านค่าจาก environment / secret manager ตอน runtime และใส่ไฟล์ที่มีค่าจริงลง.gitignore', en: 'Read values from the environment / a secret manager at runtime, and put any file with real values in .gitignore' },
          { th: 'ให้แต่ละคนเก็บสำเนา key ไว้ในเครื่องตัวเองแล้ว copy วางตอน build', en: 'Have each developer keep a copy of the key locally and paste it in at build time' }
        ],
        answer: 2,
        why: {
          th: 'หลักการคือ "ค่าจริงต้องไม่เคยเข้า repo" ค่าถูกฉีดเข้ามาตอน runtime ผ่าน environment หรือ secret manager (Vault, AWS Secrets Manager, Kubernetes Secret) ซึ่งจัดการเรื่อง rotation, การจำกัด permission และ audit ได้ ส่วนไฟล์ที่มีค่าจริงบนเครื่อง dev ต้องอยู่ใน.gitignore เสมอ',
          en: 'The principle is that the real value never enters the repo. Values are injected at runtime through the environment or a secret manager (Vault, AWS Secrets Manager, a Kubernetes Secret), which also handles rotation, access scoping, and auditing. Any local file holding real values must always be in .gitignore.'
        },
        whyWrong: [
          { th: 'comment ไม่ได้ป้องกันอะไร ค่าที่ commit แล้วก็อยู่ในประวัติ git ตลอดไป การอยู่ในไฟล์ properties ก็คือ hardcode แบบหนึ่ง', en: 'A comment prevents nothing; a committed value lives in git history forever. Living in a properties file is just another form of hardcoding.' },
          { th: 'base64 ถอดกลับได้ในคำสั่งเดียวและ blob ยัง commit อยู่ใน repo — เป็นการซ่อนรูป ไม่ใช่การเก็บความลับ', en: 'base64 reverses in one command and the blob is still committed — that is disguise, not secret management.' },
          null,
          { th: 'การให้ทุกคน copy วาง key เองทำให้ความลับกระจายไปหลายเครื่องแบบไร้การควบคุม เสี่ยงหลุดและ rotate ยากกว่าเดิม', en: 'Having everyone paste the key spreads the secret across many machines uncontrollably — more exposure and harder to rotate, not easier.' }
        ]
      }
    ],

    sim: {
      kind: 'secret',
      config: {
        secretSample: 'sk_live_51H8xQe2eZvKYlo2CabcDEF'
      },
      payloads: [
        { label: { th: 'ค้นประวัติ commit ย้อนหลัง — ความลับที่ลบไปแล้วยังหาเจอ', en: 'git log -p -S — the secret is still in commit history' }, value: "git log -p -S 'sk_live_' -- src/" },
        { label: { th: 'git grep ทั้งประวัติ — กวาดทุก commit ที่เคยมี', en: 'git grep across all history — sweep every commit ever made' }, value: "git grep 'sk_live_' $(git rev-list --all)" },
        { label: { th: 'trufflehog — สแกนหา secret อัตโนมัติทั้ง repo', en: 'trufflehog — automatically scan the whole repo for secrets' }, value: 'trufflehog git file://. --only-verified' }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP Secrets Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html' },
      { label: 'OWASP — Use of Hard-coded Password', url: 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password' },
      { label: 'CWE-798: Use of Hard-coded Credentials', url: 'https://cwe.mitre.org/data/definitions/798.html' }
    ]
  };

 /* ======================================================================
 * 2.2 CORS Misconfiguration
 * ==================================================================== */
  const CORS_MISCONFIG = {
    id: 'cors-misconfig',
    title: { th: 'CORS Misconfiguration', en: 'CORS Misconfiguration' },
    severity: 'Medium',
    cwe: 'CWE-942',
    owasp: 'A05:2021 – Security Misconfiguration',
    category: { th: 'Security Misconfiguration', en: 'Security Misconfiguration' },
    estMinutes: 11,
    points: 90,

    intro: {
      th: 'API เปิด CORS แบบกว้างสุด: origins="*" คู่กับ allowCredentials=true (Java) และ cors({ origin: "*", credentials: true }) (Node) CORS คือกฎที่บอก "browser" ว่า origin ของเว็บใดบ้างได้รับอนุญาตให้อ่าน response ข้าม origin ของ API นี้ ประเด็นที่ต้องเข้าใจ: ตามสเปก browser จะไม่ยอมให้ใช้ * ร่วมกับ credentials พร้อมกัน ทีมจำนวนมากจึง "แก้" ด้วยการสะท้อน Origin ที่ผู้เรียกส่งมากลับไปตรง ๆ (origin: true หรือ allowedOriginPatterns("*")) ซึ่งอันตรายกว่าเดิม เพราะกลายเป็นว่าเว็บของใครก็ได้ที่มี cookie ผู้ใช้ติดมาสามารถอ่านข้อมูลส่วนตัวจาก API ของคุณได้',
      en: 'The API opens CORS as wide as it goes: origins="*" with allowCredentials=true (Java) and cors({ origin: "*", credentials: true }) (Node). CORS is the rule that tells the browser which web origins may read this API\'s cross-origin responses. A key point: per the spec, a browser will not allow * together with credentials, so many teams "fix" that by reflecting the caller\'s Origin straight back (origin: true or allowedOriginPatterns("*")) — which is worse, because now any site carrying the user\'s cookie can read private data from your API.'
    },
    attack: {
      th: 'attacker สร้างหน้าเว็บที่ evil.example แล้วหลอกให้เหยื่อที่ล็อกอิน API ของคุณอยู่เปิดหน้านั้น สคริปต์ยิง fetch("https://api.example.com/api/account", { credentials: "include" }) browser แนบ cookie ของเหยื่อไปด้วย ถ้า API สะท้อน Origin: https://evil.example กลับมาใน Access-Control-Allow-Origin พร้อม Access-Control-Allow-Credentials: true browser จะปล่อยให้สคริปต์อ่าน response ได้ attacker จึงดูดข้อมูลบัญชี/โปรไฟล์/token ของเหยื่อออกไปได้ทันที ทดสอบเร็ว ๆ ด้วย curl -i -H "Origin: https://evil.example" แล้วดูว่า header ตอบกลับสะท้อน origin นั้นไหม',
      en: 'An attacker builds a page at evil.example and lures a victim who is logged into your API into opening it. Its script fires fetch("https://api.example.com/api/account", { credentials: "include" }); the browser attaches the victim\'s cookie. If the API reflects Origin: https://evil.example back in Access-Control-Allow-Origin along with Access-Control-Allow-Credentials: true, the browser lets the script read the response — so the attacker exfiltrates the victim\'s account, profile, or token instantly. Check it fast with curl -i -H "Origin: https://evil.example" and see whether the response header echoes that origin.'
    },
    fix: {
      th: 'กำหนด allowlist ของ origin ที่เชื่อถือได้อย่างชัดเจน (ดึงมาจาก config/env ไม่ hardcode) แล้วอนุญาตเฉพาะ origin ที่ตรงกับรายการนั้นแบบ exact match ห้ามใช้ * และห้ามสะท้อน Origin ที่ผู้เรียกส่งมาโดยไม่ตรวจ ถ้าจำเป็นต้องใช้ credentials ยิ่งต้องเป็น allowlist ที่ชัดเจน (สเปกห้าม * กับ credentials อยู่แล้ว) และต้องเทียบ origin แบบทั้งสตริงเท่านั้น อย่าใช้ endsWith/startsWith เพราะ evil-example.com และ app.example.com.evil.com จะหลุดผ่าน',
      en: 'Define an explicit allowlist of trusted origins (pulled from config/env, not hardcoded) and allow only origins that exactly match the list. Never use *, and never reflect the caller\'s Origin without checking it. If you truly need credentials, an explicit allowlist is doubly required (the spec already forbids * with credentials), and you must compare the whole origin string only — do not use endsWith/startsWith, because evil-example.com and app.example.com.evil.com would slip through.'
    },
    keyPoints: {
      vuln: [
        { th: 'API ตั้ง origins="*" คู่กับ allowCredentials=true เปิด CORS กว้างสุด', en: 'The API sets origins="*" with allowCredentials=true, opening CORS as wide as it goes.' },
        { th: 'CORS บอก browser ว่า origin ใดอ่าน response ข้าม origin ได้เท่านั้น', en: 'CORS only tells the browser which origins may read a cross-origin response.' },
        { th: 'ทีมมัก "แก้" ด้วยการสะท้อน Origin ที่ผู้เรียกส่งมา ซึ่งอันตรายกว่าเดิม', en: 'Teams often "fix" it by reflecting the caller\'s Origin back — which is worse.' }
      ],
      attack: [
        { th: 'attacker หลอกผู้ใช้ที่ล็อกอินอยู่ให้เปิดหน้า evil.example ซึ่งมี script ส่ง fetch ไปยัง API ของเราในเบื้องหลัง', en: 'Lure a logged-in victim to evil.example, whose script fetches your API.' },
        { th: 'script ของ attacker ใช้ credentials: include ทำให้ browser แนบ session cookie ของผู้ใช้ไปกับ request ข้าม origin ให้อัตโนมัติ', en: 'The browser attaches the victim\'s cookie on the credentials: include request.' },
        { th: 'ถ้า API ยอมรับ Origin ของ attacker และเปิด credentials เว็บนั้นจะอ่าน response ที่ผูกกับ session ของเหยื่อได้ เช่น ข้อมูลบัญชีหรือข้อมูลส่วนตัว', en: 'If the API reflects the Origin with credentials, the attacker site reads the account data.' }
      ],
      fix: [
        { th: 'สร้าง allowlist ของ origin ที่เชื่อถือได้ไว้ใน config แล้วอนุญาต CORS เฉพาะ origin ที่ตรงกับรายการนี้เท่านั้น', en: 'Define an allowlist of trusted origins, pulled from config, not hardcoded.' },
        { th: 'อย่าสะท้อน Origin ที่ผู้เรียกส่งมากลับไปโดยไม่ตรวจ และอย่าใช้ * กับ endpoint ที่อนุญาต credentials ต้องตรวจ Origin กับ allowlist ก่อนเสมอ', en: 'Allow only exact-match origins; never use * and never reflect the raw Origin.' },
        { th: 'เปรียบเทียบ Origin แบบตรงทั้งค่า ไม่ใช้ startsWith, endsWith หรือ contains เพราะโดเมนอย่าง app.example.com.evil.com สามารถหลบการตรวจแบบ substring ได้', en: 'Compare the whole origin string; do not use endsWith/startsWith, which can be tricked.' }
      ]
    },
    impact: {
      th: 'หากผู้ใช้ล็อกอินอยู่ เว็บของ attacker อาจเรียก API พร้อม session ของผู้ใช้และอ่านข้อมูลส่วนตัวกลับไปได้ เพียงผู้ใช้เปิดหน้าเว็บที่ attacker เตรียมไว้',
      en: 'The attacker\'s website silently reads a logged-in user\'s private data from your API, needing nothing more than for the user to open a booby-trapped page.'
    },

    caseStudy: {
      year: 2016,
      title: {
        th: 'Exploiting CORS Misconfigurations (2016) — ขโมย Bitcoin และ API key จาก CORS ที่ตั้งผิด',
        en: 'Exploiting CORS Misconfigurations (2016) — stealing Bitcoin and API keys from misconfigured CORS'
      },
      body: {
        th: 'ในปี 2016 James Kettle หัวหน้าทีมวิจัยของ PortSwigger เผยแพร่งานวิจัย (นำเสนอที่ AppSec USA 2016) ที่แสดงการโจมตีเว็บจริงผ่าน CORS ที่ตั้งค่าผิด รูปแบบที่พบบ่อยคือ server สะท้อนค่า Origin ที่ผู้เรียกส่งมากลับไปใน Access-Control-Allow-Origin พร้อมเปิด Access-Control-Allow-Credentials: true ทำให้เว็บของ attacker อ่าน response ที่ผูกกับ session ของเหยื่อได้ เขาสาธิตการดึง API key และแม้แต่ขโมย Bitcoin จาก exchange สองแห่งผ่านช่องโหว่นี้ บทเรียนคือการสะท้อน Origin แบบไม่ตรวจ (หรือใช้ allowlist ที่ทำ substring match หละหลวม) มีค่าเท่ากับเปิด API ให้ทุกเว็บ',
        en: 'In 2016 James Kettle, PortSwigger\'s head of research, published research (presented at AppSec USA 2016) demonstrating real-world attacks through misconfigured CORS. The common pattern was a server reflecting the caller\'s Origin back in Access-Control-Allow-Origin while enabling Access-Control-Allow-Credentials: true, letting an attacker\'s site read responses tied to the victim\'s session. He showed extracting API keys and even stealing Bitcoin from two exchanges through this flaw. The lesson: reflecting the Origin unchecked (or using an allowlist with a sloppy substring match) is equivalent to opening the API to every website.'
      },
      source: {
        label: 'PortSwigger Research — Exploiting CORS misconfigurations for Bitcoins and bounties (James Kettle, 2016)',
        url: 'https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties'
      }
    },

    codeReview: [
      {
        th: 'ตอน Code Review ให้ค้นหา origin: \'*\' / origins="*" / Access-Control-Allow-Origin ที่ตั้งเป็น * แล้วดูว่ามี credentials / allowCredentials อยู่ใกล้ ๆ ไหม ถ้ามีคู่กันคืออันตราย',
        en: 'grep for origin: \'*\' / origins="*" / an Access-Control-Allow-Origin set to *, then check whether credentials / allowCredentials sits nearby.'
      },
      {
        th: 'ถ้าเห็น origin: true, allowedOriginPatterns("*") หรือการนำ Origin จาก request ไปใส่ใน Access-Control-Allow-Origin โดยตรง ให้ตรวจทันที เพราะเท่ากับสะท้อน origin กลับโดยไม่ตรวจสอบ',
        en: 'origin: true, allowedOriginPatterns("*"), or reflecting req.headers.origin / request.getHeader("Origin") straight into Access-Control-Allow-Origin — all of these reflect the origin unchecked.'
      },
      {
        th: 'Access-Control-Allow-Credentials: true คู่กับ origin ที่เป็น * หรือ reflected คือคู่ที่อันตรายที่สุด เพราะเปิดให้เว็บอื่นอ่านข้อมูลที่ผูกกับ session ได้ ต้องมี allowlist ชัดเจนเสมอ',
        en: 'Access-Control-Allow-Credentials: true paired with a wildcard or reflected origin — the most dangerous combination; an explicit allowlist is mandatory whenever credentials are on.'
      },
      {
        th: 'ถ้า allowlist ตรวจ origin ด้วย endsWith/startsWith/contains เช่น endsWith("example.com") อาจถูกหลบได้ด้วยโดเมนอย่าง app.example.com.evil.com ต้องเปรียบเทียบ origin แบบตรงทั้งค่า',
        en: 'An allowlist that checks the origin with endsWith/startsWith/contains (e.g. endsWith("example.com")) — app.example.com.evil.com and example.com.evil.net all slip through; compare the whole string exactly.'
      }
    ],

    testIt: {
      cmd: "curl -i -H 'Origin: https://evil.example' http://localhost:8080/api/account",
      note: {
        th: 'แอปที่มีช่องโหว่จะตอบ Access-Control-Allow-Origin: https://evil.example (หรือ *) พร้อม Access-Control-Allow-Credentials: true — หมายความว่าเว็บ attacker อ่าน response ได้ ส่วนแอปที่แก้แล้วจะไม่สะท้อน evil.example กลับมา (ไม่มี header นั้น หรือมีเฉพาะ origin ที่อยู่ใน allowlist)',
        en: 'A vulnerable app answers Access-Control-Allow-Origin: https://evil.example (or *) with Access-Control-Allow-Credentials: true — meaning the attacker\'s site can read the response. A fixed app never echoes evil.example (either no such header, or only an allowlisted origin).'
      }
    },

    pitfalls: [
      {
        title: {
          th: 'เปลี่ยนเป็น origin: true / reflect Origin',
          en: '"I switched to origin: true / reflecting the Origin"'
        },
        why: {
          th: 'origin: true ใน library cors และ allowedOriginPatterns("*") ใน Spring ไม่ได้จำกัดอะไรเลย มันแค่ "สะท้อน" ค่า Origin ที่ผู้เรียกส่งมากลับไปใน Access-Control-Allow-Origin ทุกครั้ง เมื่อรวมกับ credentials: true ผลคือทุกเว็บ รวมถึง evil.example ได้รับ ACAO ที่ตรงกับตัวเองพร้อม permission อ่าน response ที่ผูก cookie ผู้ใช้ นี่คือช่องโหว่ตัวจริง ไม่ใช่การแก้ ต้องเทียบ Origin กับ allowlist แล้วตอบเฉพาะ origin ที่อยู่ในรายการเท่านั้น',
          en: 'origin: true in the cors library and allowedOriginPatterns("*") in Spring restrict nothing — they simply reflect the caller\'s Origin back in Access-Control-Allow-Origin every time. Combined with credentials: true, every site including evil.example receives an ACAO matching itself plus permission to read a cookie-bound response. That is the actual vulnerability, not a fix. Compare the Origin against an allowlist and echo only origins that are on the list.'
        },
        short: {
          th: 'origin: true คือการสะท้อน Origin ทุกครั้ง ไม่ได้จำกัดอะไรเลย',
          en: 'origin: true reflects every Origin; it restricts nothing.'
        }
      },
      {
        title: {
          th: 'ใช้ CORS แทนการตรวจสิทธิ์ฝั่ง server',
          en: '"With CORS locked down, the API is safe from outsiders"'
        },
        why: {
          th: 'CORS เป็นกลไกที่ "browser" บังคับใช้ เพื่อคุมว่าสคริปต์จากเว็บ origin ไหนอ่าน response ข้าม origin ได้ มันไม่ใช่ระบบยืนยันตัวตนหรือกำหนด permission และไม่ได้ปิดกั้น client ที่ไม่ใช่ browser เลย attacker ใช้ curl, Postman หรือสคริปต์ฝั่ง server เรียก API ของคุณตรง ๆ ได้โดยไม่สนใจ header CORS สักตัว เพราะฉะนั้นทุก endpoint ยังต้องมี authentication และ authorization ของตัวเองเสมอ CORS แค่กันการอ่านข้าม origin ใน browser ไม่ได้กันการเข้าถึง',
          en: 'CORS is enforced by the browser, to control which web origins\' scripts may read cross-origin responses. It is not authentication or authorization, and it does nothing to block non-browser clients. An attacker uses curl, Postman, or a server-side script to call your API directly, ignoring every CORS header. So every endpoint still needs its own authentication and authorization. CORS only governs cross-origin reads in a browser; it does not govern access.'
        },
        short: {
          th: 'CORS ไม่ใช่ authentication — curl และ Postman ข้ามมันได้ทั้งหมด',
          en: 'CORS is not authentication — curl and Postman ignore it entirely.'
        }
      }
    ],

    languages: {
      java: {
        filename: 'CorsConfig.java',
        lang: 'java',
        starter:
`package com.acme.account.web;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
// เปิด CORS ให้ frontend เรียกได้ — ตั้ง * ไว้ก่อนกันปัญหาตอน dev
@CrossOrigin(origins = "*", allowCredentials = "true")
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

 // ดึงข้อมูลบัญชีของผู้ใช้ — ต้องใช้ cookie session
    @GetMapping("/api/account")
    public AccountDto currentAccount() {
        return accountService.currentAccount();
    }
}`,
        solution:
`package com.acme.account.web;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {

 // allowlist มาจาก config ภายนอก ไม่ hardcode และไม่ใช้ *
    @Value("\${cors.allowed-origins}")
    private List<String> allowedOrigins;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
 // อนุญาตเฉพาะ origin ที่อยู่ใน allowlist แบบตรงทั้งสตริง
            .allowedOrigins(allowedOrigins.toArray(new String[0]))
            .allowedMethods("GET", "POST")
            .allowCredentials(true);
    }
}`,
        explain: {
          th: 'แทนที่จะตอบ * หรือสะท้อน Origin โค้ดนี้ให้ Spring เทียบ Origin ของ request กับ allowlist ที่ดึงมาจาก config (@Value("${cors.allowed-origins}")) แล้วตอบ Access-Control-Allow-Origin เฉพาะเมื่อ origin นั้นตรงกับรายการแบบทั้งสตริงเท่านั้น evil.example จึงไม่สามารถได้ ACAO ที่ตรงกับตัวเอง การเทียบแบบ exact match (ไม่ใช่ endsWith/contains) สำคัญมาก เพราะกันทั้ง app.example.com.evil.com และ evil-app.example.com เมื่อ origin ถูกล็อกด้วย allowlist การเปิด allowCredentials(true) จึงปลอดภัย (Spring จะไม่ยอมจับคู่ * กับ credentials ให้อยู่แล้ว) และเนื่องจาก allowlist อยู่ใน config เราปรับ origin ต่อ environment ได้โดยไม่ต้องแก้โค้ด',
          en: 'Instead of answering * or reflecting the Origin, this code has Spring compare the request\'s Origin against an allowlist pulled from config (@Value("${cors.allowed-origins}")) and emit Access-Control-Allow-Origin only when the origin matches the list as a whole string. evil.example can never receive an ACAO matching itself. Exact matching (not endsWith/contains) matters, because it stops both app.example.com.evil.com and evil-app.example.com. With the origin locked to an allowlist, enabling allowCredentials(true) is safe (Spring will not pair * with credentials anyway), and because the allowlist lives in config you can tune origins per environment without touching code.'
        },
        checks: [
          {
            id: 'no-wildcard-origin',
            label: { th: 'ไม่ตั้ง origin เป็น * (wildcard)', en: 'The origin is never set to * (wildcard)' },
            hint: { th: 'ลบ origins = "*" ออก แล้วใช้ allowedOrigins(...) จาก allowlist แทน', en: 'Remove origins = "*" and use allowedOrigins(...) from an allowlist instead' },
            weight: 3,
            mustNotMatch: /origins?\s*=\s*"\*"|allowedOrigins?\s*\(\s*"\*"|addAllowedOrigin\s*\(\s*"\*"|setAllowedOrigins?\s*\([^)]*"\*"/
          },
          {
            id: 'use-cors-allowlist',
            label: { th: 'ใช้ allowlist ของ origin (allowedOrigins)', en: 'Uses an origin allowlist (allowedOrigins)' },
            hint: { th: 'ตั้งค่า.allowedOrigins(...) ด้วยรายการ origin ที่เชื่อถือได้', en: 'Configure .allowedOrigins(...) with the list of trusted origins' },
            weight: 3,
            mustMatch: /allowedOrigins\s*\(|setAllowedOrigins\s*\(/
          },
          {
            id: 'origins-from-config',
            label: { th: 'ดึง origin จาก config/env ไม่ hardcode', en: 'Pulls origins from config/env, not hardcoded' },
            hint: { th: 'ใช้ @Value("${cors.allowed-origins}") หรือ @ConfigurationProperties', en: 'Use @Value("${cors.allowed-origins}") or @ConfigurationProperties' },
            weight: 2,
            mustMatch: /@Value\s*\(|@ConfigurationProperties|System\s*\.\s*getenv\s*\(/
          },
          {
            id: 'explicit-methods',
            label: { th: 'กำหนด HTTP method ที่อนุญาตอย่างชัดเจน', en: 'Declares the allowed HTTP methods explicitly' },
            hint: { th: 'ตั้ง.allowedMethods("GET", "POST") แทนการเปิดทุก method', en: 'Set .allowedMethods("GET", "POST") instead of allowing every method' },
            weight: 1,
            mustMatch: /allowedMethods\s*\(/
          }
        ],
        traps: [
          {
            id: 'reflect-origin-pattern',
            match: /allowedOriginPatterns?\s*\(\s*"\*"|setAllowedOriginPattern\s*\(\s*"\*"/,
            message: {
              th: 'allowedOriginPatterns("*") ไม่ใช่การจำกัด origin แต่คือการสะท้อน Origin ของผู้เรียกกลับไปใน Access-Control-Allow-Origin ทุกค่า (Spring ใช้ตัวนี้เพื่อ "หลบ" ข้อห้าม * กับ credentials) เมื่อรวมกับ allowCredentials(true) ก็เท่ากับเปิด API ให้ทุกเว็บอ่าน response ที่มี cookie ให้เทียบกับ allowedOrigins ที่เป็น allowlist ชัดเจนแทน',
              en: 'allowedOriginPatterns("*") does not restrict the origin — it reflects the caller\'s Origin back into Access-Control-Allow-Origin every time (Spring uses it to sidestep the * + credentials ban). Combined with allowCredentials(true), it opens the API to every site reading cookie-bound responses. Use allowedOrigins with an explicit allowlist instead.'
            }
          },
          {
            id: 'reflect-origin-header',
            match: /(?:setHeader|addHeader)\s*\(\s*"Access-Control-Allow-Origin"\s*,\s*[^)]*getHeader\s*\(\s*"Origin"/i,
            message: {
              th: 'การเขียน setHeader("Access-Control-Allow-Origin", request.getHeader("Origin")) คือการสะท้อน Origin ของผู้เรียกกลับไปตรง ๆ เว็บของใครก็ได้จึงได้ ACAO ที่ตรงกับตัวเอง ต้องเทียบ Origin กับ allowlist ก่อน แล้วตอบเฉพาะเมื่ออยู่ในรายการเท่านั้น',
              en: 'Writing setHeader("Access-Control-Allow-Origin", request.getHeader("Origin")) reflects the caller\'s Origin straight back, so any site receives an ACAO matching itself. Compare the Origin against an allowlist first and answer only when it is on the list.'
            }
          }
        ]
      },

      node: {
        filename: 'server.js',
        lang: 'js',
        starter:
`const express = require('express');
const cors = require('cors');
const app = express();

// เปิด CORS ให้ frontend เรียก API ที่ต้องใช้ cookie ได้
app.use(cors({ origin: '*', credentials: true }));

app.get('/api/account', requireSession, (req, res) => {
  res.json(accountService.current(req.session.userId));
});

module.exports = app;`,
        solution:
`const express = require('express');
const cors = require('cors');
const app = express();

// allowlist มาจาก env ไม่ใช้ * และไม่สะท้อน Origin ของผู้เรียกโดยไม่ตรวจ
const ALLOWED = (process.env.CORS_ALLOWED_ORIGINS || '').split(',').filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
 // ไม่มี Origin (เครื่องมือ server-side/same-origin) หรืออยู่ใน allowlist แบบตรงทั้งสตริงเท่านั้น
    if (!origin || ALLOWED.indexOf(origin) !== -1) {
      return callback(null, true);
    }
    return callback(new Error('origin not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST'],
}));

app.get('/api/account', requireSession, (req, res) => {
  res.json(accountService.current(req.session.userId));
});

module.exports = app;`,
        explain: {
          th: 'แทนที่จะตอบ origin: "*" โค้ดนี้ให้ฟังก์ชัน origin ของ library cors เทียบ Origin ที่ผู้เรียกส่งมากับ allowlist (ALLOWED ที่มาจาก process.env) แล้วเรียก callback(null, true) เฉพาะเมื่อ origin นั้นอยู่ในรายการแบบตรงทั้งสตริง (ALLOWED.indexOf(origin) !== -1) กรณีไม่มี Origin เลย (เช่น request server-side หรือ same-origin) ก็ผ่านได้ แต่ Origin ที่ไม่รู้จักจะถูกปฏิเสธ browser จึงไม่ได้ Access-Control-Allow-Origin ที่ตรงกับ evil.example จุดสำคัญคือใช้ indexOf/exact match ไม่ใช่ endsWith เพราะ endsWith("example.com") จะปล่อย app.example.com.evil.com ผ่าน และเนื่องจากได้กรอง origin ด้วย allowlist แล้ว การเปิด credentials: true จึงปลอดภัย',
          en: 'Instead of answering origin: "*", this hands the cors library an origin function that compares the caller\'s Origin against an allowlist (ALLOWED from process.env) and calls callback(null, true) only when the origin is on the list as a whole string (ALLOWED.indexOf(origin) !== -1). A request with no Origin at all (server-side or same-origin) is allowed, but an unknown Origin is rejected, so the browser never receives an Access-Control-Allow-Origin matching evil.example. Using indexOf/exact matching rather than endsWith is the point: endsWith("example.com") would let app.example.com.evil.com through. Because the origin is filtered by the allowlist, enabling credentials: true is safe.'
        },
        checks: [
          {
            id: 'no-wildcard-origin',
            label: { th: 'ไม่ตั้ง origin เป็น \'*\' (wildcard)', en: 'The origin is never set to \'*\' (wildcard)' },
            hint: { th: 'ลบ origin: \'*\' ออก แล้วใช้ origin เป็นฟังก์ชันตรวจ allowlist หรือ array ของ origin แทน', en: 'Remove origin: \'*\' and use an origin function checking an allowlist, or an array of origins' },
            weight: 3,
            mustNotMatch: /origin\s*:\s*['"]\*['"]/
          },
          {
            id: 'use-origin-allowlist',
            label: { th: 'ตรวจ Origin ด้วย allowlist', en: 'Checks the Origin against an allowlist' },
            hint: { th: 'ใช้ origin เป็นฟังก์ชันที่เทียบกับ array ของ origin ที่เชื่อถือได้ (indexOf/includes)', en: 'Use an origin function comparing against an array of trusted origins (indexOf/includes)' },
            weight: 3,
            mustMatch: /origin\s*:\s*(?:function|\[)|ALLOWED\b|\.indexOf\s*\(\s*origin|\.includes\s*\(\s*origin/
          },
          {
            id: 'origins-from-config',
            label: { th: 'ดึง origin จาก env ไม่ hardcode', en: 'Pulls origins from env, not hardcoded' },
            hint: { th: 'อ่านรายการ origin จาก process.env.CORS_ALLOWED_ORIGINS', en: 'Read the origin list from process.env.CORS_ALLOWED_ORIGINS' },
            weight: 2,
            mustMatch: /process\s*\.\s*env\b/
          },
          {
            id: 'explicit-methods',
            label: { th: 'กำหนด HTTP method ที่อนุญาตอย่างชัดเจน', en: 'Declares the allowed HTTP methods explicitly' },
            hint: { th: 'ตั้ง methods: [\'GET\', \'POST\'] แทนการเปิดทุก method', en: 'Set methods: [\'GET\', \'POST\'] instead of allowing every method' },
            weight: 1,
            mustMatch: /methods\s*:\s*\[/
          }
        ],
        traps: [
          {
            id: 'reflect-origin-true',
            match: /origin\s*:\s*true\b/,
            message: {
              th: 'cors({ origin: true }) ไม่ได้จำกัด origin แต่สะท้อน Origin ของผู้เรียกกลับไปใน Access-Control-Allow-Origin ทุกค่า เมื่อรวมกับ credentials: true เว็บของใครก็ได้ก็อ่าน response ที่ผูก cookie ของเหยื่อได้ ให้เปลี่ยน origin เป็นฟังก์ชันที่เทียบกับ allowlist แล้วปฏิเสธ origin ที่ไม่อยู่ในรายการ',
              en: 'cors({ origin: true }) does not restrict the origin — it reflects the caller\'s Origin back in Access-Control-Allow-Origin every time. With credentials: true, any site can read the victim\'s cookie-bound response. Change origin to a function that checks an allowlist and rejects origins that are not on it.'
            }
          },
          {
            id: 'reflect-origin-header',
            match: /['"]Access-Control-Allow-Origin['"]\s*,\s*[^)\n]*(?:req\s*\.\s*headers\s*\.\s*origin|headers\s*\[\s*['"]origin)/i,
            message: {
              th: 'res.setHeader("Access-Control-Allow-Origin", req.headers.origin) คือการสะท้อน Origin ของผู้เรียกกลับไปตรง ๆ เท่ากับอนุญาตทุก origin ต้องเทียบ req.headers.origin กับ allowlist ก่อน แล้วตอบเฉพาะเมื่ออยู่ในรายการ',
              en: 'res.setHeader("Access-Control-Allow-Origin", req.headers.origin) reflects the caller\'s Origin straight back — effectively allowing every origin. Compare req.headers.origin against an allowlist first and answer only when it is on the list.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'ลองถามตัวเองว่า "ถ้า evil.example ส่ง request มา server จะตอบ Access-Control-Allow-Origin เป็นอะไร" ถ้าคำตอบคือ * หรือสะท้อน evil.example กลับไป หมายความว่ายังไม่ปลอดภัย',
        en: 'Ask: "if evil.example sends a request, what will the server put in Access-Control-Allow-Origin?" If the answer is * or evil.example reflected back, it is not safe yet.'
      },
      {
        th: 'เก็บรายชื่อ origin ที่เชื่อถือได้ไว้เป็น allowlist (ใน config/env) แล้วอนุญาตเฉพาะ origin ที่ "ตรงทั้งสตริง" กับรายการนั้น อย่าใช้ endsWith/contains',
        en: 'Keep the trusted origins as an allowlist (in config/env) and allow only origins that match the list as a whole string. Do not use endsWith/contains.'
      },
      {
        th: 'Java: WebMvcConfigurer + registry.addMapping(...).allowedOrigins(allowlist) โดย allowlist มาจาก @Value — Node: cors({ origin: function(origin, cb){ ตรวจ ALLOWED.indexOf(origin) } }) โดย ALLOWED มาจาก process.env',
        en: 'Java: a WebMvcConfigurer + registry.addMapping(...).allowedOrigins(allowlist) with the allowlist from @Value. Node: cors({ origin: function(origin, cb){ check ALLOWED.indexOf(origin) } }) with ALLOWED from process.env.'
      }
    ],

    quiz: [
      {
        q: {
          th: 'ทีมเปลี่ยนจาก origin: "*" เป็น origin: true (สะท้อน Origin) เพื่อให้ credentials ทำงาน ผลเป็นอย่างไร',
          en: 'A team changes origin: "*" to origin: true (reflect the Origin) so credentials work. What is the result?'
        },
        choices: [
          { th: 'ปลอดภัยแล้ว เพราะไม่ได้ใช้ * ตรง ๆ อีกต่อไป', en: 'Safe — it no longer uses a literal *' },
          { th: 'ยังไม่ปลอดภัย เพราะมันสะท้อน Origin ของผู้เรียกทุกค่า เว็บ attacker จึงได้ ACAO ตรงกับตัวเอง + permission อ่าน response ที่มี cookie', en: 'Unsafe — it reflects every caller\'s Origin, so an attacker\'s site gets an ACAO matching itself plus permission to read the cookie-bound response' },
          { th: 'ปลอดภัยแล้ว ถ้าทุก origin ใช้ HTTPS', en: 'Safe as long as every origin uses HTTPS' },
          { th: 'ปลอดภัยแล้ว เพราะ browser จะบล็อก origin ที่ไม่รู้จักให้เอง', en: 'Safe because the browser blocks unknown origins for you' }
        ],
        answer: 1,
        why: {
          th: 'origin: true สะท้อน Origin ของผู้เรียกกลับไปเสมอ ทำให้ Access-Control-Allow-Origin ตรงกับทุกเว็บ เมื่อรวมกับ credentials เว็บของ attacker อ่านข้อมูล session ของเหยื่อได้ ต้องเทียบ Origin กับ allowlist แล้วตอบเฉพาะ origin ที่อยู่ในรายการ',
          en: 'origin: true always reflects the caller\'s Origin, so Access-Control-Allow-Origin matches every site; combined with credentials, an attacker\'s site can read the victim\'s session data. Compare the Origin against an allowlist and echo only origins on the list.'
        },
        whyWrong: [
          { th: 'การเลิกใช้ * แต่ไปสะท้อน Origin แทนไม่ได้แคบลงเลย ผลเหมือนอนุญาตทุก origin แถมยังใช้กับ credentials ได้ด้วยซึ่งอันตรายกว่า *', en: 'Dropping * but reflecting the Origin narrows nothing — it is like allowing every origin, and now works with credentials too, which is worse than *.' },
          null,
          { th: 'HTTPS ปกป้องข้อมูลระหว่างทาง ไม่เกี่ยวกับว่า origin ไหนได้รับอนุญาตให้อ่าน response — evil.example ก็ใช้ HTTPS ได้เหมือนกัน', en: 'HTTPS protects data in transit; it has nothing to do with which origin may read the response — evil.example can use HTTPS too.' },
          { th: 'browser ตัดสินตาม header ที่ server ตอบ ถ้า server สะท้อน Origin กลับไป browser ก็ถือว่าอนุญาต ไม่ได้บล็อกให้', en: 'The browser decides based on the header the server returns; if the server reflects the Origin, the browser treats it as allowed — it does not block anything.' }
        ]
      },
      {
        q: {
          th: 'CORS ที่ตั้งค่าถูกต้องช่วยป้องกันอะไร',
          en: 'What does correctly configured CORS actually protect against?'
        },
        choices: [
          { th: 'ป้องกันไม่ให้ใครก็ตามเรียก API ได้ ถ้า origin ไม่อยู่ใน allowlist', en: 'It stops anyone from calling the API at all if their origin is not on the allowlist' },
          { th: 'ป้องกัน CSRF ได้ทั้งหมด จึงไม่ต้องมี CSRF token', en: 'It fully prevents CSRF, so no CSRF token is needed' },
          { th: 'มันคุมแค่ว่า "สคริปต์ใน browser จาก origin ไหน" อ่าน response ข้าม origin ได้ ไม่ได้ยืนยันตัวตนและไม่กัน client ที่ไม่ใช่ browser (curl/Postman)', en: 'It only controls which browser-based scripts may read cross-origin responses; it does not authenticate and does not stop non-browser clients (curl/Postman)' },
          { th: 'มันซ่อน endpoint ไม่ให้คนนอกรู้ว่ามีอยู่', en: 'It hides the endpoint so outsiders cannot discover it' }
        ],
        answer: 2,
        why: {
          th: 'CORS เป็นกลไกฝั่ง browser ที่คุมการอ่านข้าม origin เท่านั้น ไม่ใช่ authentication/authorization และไม่มีผลกับ curl/Postman/สคริปต์ฝั่ง server ที่เรียก API ตรง ๆ ทุก endpoint จึงต้องมี authorization ของตัวเองเสมอ',
          en: 'CORS is a browser-side mechanism that governs cross-origin reads only. It is not authentication/authorization and has no effect on curl/Postman/server-side scripts calling the API directly, so every endpoint still needs its own authorization.'
        },
        whyWrong: [
          { th: 'CORS ไม่ได้บล็อกการเรียก API request ยังส่งถึง server และทำงานตามปกติ browser แค่ไม่ปล่อยให้สคริปต์ต่าง origin "อ่าน" response และ client ที่ไม่ใช่ browser ก็ไม่สน CORS', en: 'CORS does not block the call; the request still reaches the server and runs. The browser merely withholds the response from a cross-origin script — and non-browser clients ignore CORS entirely.' },
          { th: 'CORS ไม่ใช่กลไกกัน CSRF แม้ preflight จะช่วยบางกรณี แต่การป้องกันหลักคือ CSRF token / SameSite cookie', en: 'CORS is not a CSRF defense; even though preflight helps in some cases, the primary protections are a CSRF token / SameSite cookies.' },
          null,
          { th: 'CORS ไม่ได้ซ่อนอะไร URL ของ endpoint ยังเรียกได้ตรง ๆ และ response ยังถูกส่งกลับ browser แค่กันการอ่านข้าม origin', en: 'CORS hides nothing; the endpoint URL is still callable directly and the response is still returned — the browser only restricts the cross-origin read.' }
        ]
      }
    ],

    sim: {
      kind: 'cors',
      config: {
        allowlist: ['https://app.example.com']
      },
      payloads: [
        { label: { th: 'ส่ง Origin ของเว็บ attacker เข้ามา ระบบควรปฏิเสธ', en: 'Attacker origin — should be denied' }, value: 'https://evil.example' },
        { label: { th: 'Subdomain ปลอม — app.example.com.evil.com', en: 'Fake subdomain — app.example.com.evil.com' }, value: 'https://app.example.com.evil.com' },
        { label: { th: 'null origin — จาก sandboxed iframe / redirect', en: 'null origin — from a sandboxed iframe / redirect' }, value: 'null' }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP HTML5 Security Cheat Sheet (Cross Origin Resource Sharing)', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html' },
      { label: 'MDN — Cross-Origin Resource Sharing (CORS)', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS' },
      { label: 'CWE-942: Permissive Cross-domain Policy with Untrusted Domains', url: 'https://cwe.mitre.org/data/definitions/942.html' }
    ]
  };

  const VERBOSE_ERRORS = {
    id: 'verbose-errors',
    title: { th: 'Verbose Error Messages', en: 'Verbose Error Messages' },
    severity: 'Medium',
    cwe: 'CWE-209',
    owasp: 'A05:2021 – Security Misconfiguration',
    category: { th: 'Security Misconfiguration', en: 'Security Misconfiguration' },
    estMinutes: 11,
    points: 90,

    intro: {
      th: 'error handler ตอบกลับ 500 พร้อม e.getMessage() และ stack trace เต็ม ๆ (หรือ err.stack ใน Node) ให้ client ทีมมักทำเพื่อให้ debug ง่ายตอน integrate แต่สิ่งที่หลุดออกไปคือแผนที่ภายในของระบบ: ชนิดและเวอร์ชัน database, ชื่อ table/column, path ของไฟล์บน server, ชื่อ framework/library และโครงสร้างโค้ด ข้อมูลเหล่านี้ไม่ได้ทำให้ระบบพังเอง แต่มันคือข่าวกรองที่ช่วยให้ attacker วางแผนขั้นต่อไปได้แม่นยำขึ้นมาก',
      en: 'The error handler answers 500 with e.getMessage() and a full stack trace (or err.stack in Node) to the client. Teams often do this to make debugging easy during integration, but what leaks is a map of the system\'s internals: the database type and version, table/column names, server file paths, framework/library names, and code structure. None of it breaks the system by itself — it is the reconnaissance that lets an attacker plan their next step far more precisely.'
    },
    attack: {
      th: 'attacker จงใจส่ง input ที่ทำให้เกิด error (พารามิเตอร์ผิดชนิด, ค่าที่ยาวเกิน, อักขระที่ทำให้ SQL พัง) แล้วอ่าน 500 body ที่ตอบกลับ ถ้าเห็นข้อความอย่าง "ORA-00942: table or view does not exist" ก็รู้ทันทีว่าใช้ Oracle และเดา schema ได้ ถ้าเห็น stack trace ก็รู้ path ไฟล์ เวอร์ชัน framework และจุดที่โค้ดพัง เทคนิคนี้เรียก error-based enumeration และเป็นขั้น recon มาตรฐานก่อนโจมตีจริง เช่น error ของ SQL ยังใช้ทำ error-based SQL injection เพื่อดึงข้อมูลออกมาทีละส่วนได้ด้วย',
      en: 'An attacker deliberately sends input that triggers errors (wrong-typed parameters, over-length values, characters that break SQL) and reads the 500 body. A message like "ORA-00942: table or view does not exist" immediately reveals Oracle and lets them guess the schema; a stack trace reveals file paths, the framework version, and where the code broke. This is error-based enumeration, a standard recon step before a real attack — and SQL errors specifically enable error-based SQL injection to pull data out piece by piece.'
    },
    fix: {
      th: 'แยก "สิ่งที่ log" ออกจาก "สิ่งที่ตอบกลับ client" ให้ชัด: log รายละเอียดทั้งหมด (message + stack) ไว้ฝั่ง server พร้อม correlation id (trace id) แล้วตอบ client แค่ข้อความ generic กับ trace id เดียวกันนั้น ผู้ใช้แจ้ง trace id มา ทีมก็ค้น log เจอเหตุการณ์เดิมได้โดยไม่ต้องเปิดเผยอะไรออกไปเลย เสริมด้วยการปิด detailed-error mode และ debug/actuator endpoint ใน production ด้วย เพราะ response ที่สะอาดอย่างเดียวไม่พอถ้ายังมีช่องอื่นรั่ว',
      en: 'Cleanly separate what you log from what you return to the client: log the full detail (message + stack) server-side with a correlation id (trace id), and return to the client only a generic message plus that same trace id. When a user reports the trace id, the team finds the exact event in the logs without disclosing anything. Also disable detailed-error mode and debug/actuator endpoints in production, because a clean response alone is not enough if other channels still leak.'
    },
    keyPoints: {
      vuln: [
        { th: 'error handler ตอบ 500 พร้อม stack trace และ e.getMessage() ให้ client', en: 'The error handler returns 500 with a stack trace and e.getMessage() to the client.' },
        { th: 'สิ่งที่หลุดคือแผนที่ภายใน: ชนิด database ชื่อ table path ไฟล์ เวอร์ชัน framework', en: 'What leaks is an internal map: database type, table names, file paths, framework version.' },
        { th: 'ข้อมูลนี้ไม่ทำให้ระบบพังเอง แต่คือข่าวกรองให้ attacker วางแผนขั้นต่อไป', en: 'None of it breaks the system itself, but it is recon for the attacker\'s next step.' }
      ],
      attack: [
        { th: 'attacker จงใจส่ง input ที่ทำให้ระบบเกิด error แล้วอ่านรายละเอียดจาก response 500 เช่น stack trace, SQL หรือ path ภายใน เพื่อสำรวจโครงสร้างระบบ', en: 'Deliberately send input that triggers errors and read the detail from the 500 body.' },
        { th: 'ข้อความอย่าง ORA-00942 บอกได้ว่าระบบใช้ Oracle และอาจเปิดเผยชื่อ table หรือ column ทำให้ attacker เดา schema และวางแผนโจมตีต่อได้ง่ายขึ้น', en: 'A message like "ORA-00942" instantly reveals Oracle and lets them guess the schema.' },
        { th: 'ถ้า error เปิดเผยรายละเอียดจาก SQL attacker อาจใช้ error-based SQL injection เพื่อค่อย ๆ ดึงข้อมูลออกมาจากข้อความ error', en: 'SQL errors also enable error-based SQL injection to pull data out piece by piece.' }
      ],
      fix: [
        { th: 'แยกข้อมูลสำหรับ log กับข้อมูลที่ตอบ client ให้ชัด รายละเอียดอย่าง exception message และ stack trace ควรอยู่ใน log ฝั่ง server เท่านั้น', en: 'Separate what you log from what you return: log the full detail server-side.' },
        { th: 'ตอบ client ด้วยข้อความทั่วไปและ correlation id หรือ trace id แล้วบันทึก id เดียวกันไว้ใน log เพื่อให้ทีมตามเหตุการณ์ย้อนหลังได้', en: 'Return only a generic message plus the same correlation id you logged.' },
        { th: 'ปิด detailed-error, debug และ endpoint สำหรับตรวจระบบ เช่น actuator ใน production หรือจำกัดให้เข้าถึงได้เฉพาะผู้มีสิทธิ์', en: 'Disable detailed-error mode and debug/actuator endpoints in production.' }
      ]
    },
    impact: {
      th: 'attacker อาจได้ข้อมูลเกี่ยวกับ database, schema, path หรือเวอร์ชันของระบบจาก error message ซึ่งช่วยลดเวลาที่ต้องใช้ในการสำรวจระบบและเพิ่มโอกาสของการโจมตีขั้นต่อไป',
      en: 'Attackers get a free internal map of the system (database, schema, paths, versions) straight from the error messages, dramatically shortening the time to find a real vulnerability and raising the odds of the next stage succeeding.'
    },

    caseStudy: {
      year: 2010,
      title: {
        th: 'ASP.NET Padding Oracle (2010, MS10-070) — error ที่ต่างกันทำให้ถอดรหัสและอ่าน web.config ได้',
        en: 'ASP.NET Padding Oracle (2010, MS10-070) — differing errors allowed decryption and reading web.config'
      },
      body: {
        th: 'ในเดือนกันยายน 2010 Microsoft เปิดเผยช่องโหว่ ASP.NET Padding Oracle (CVE-2010-3332, MS10-070) ประเด็นคือ ASP.NET ตอบ error ที่ "ต่างกัน" ขึ้นกับว่า ciphertext ที่ถอดรหัสมี padding ถูกต้องหรือไม่ attacker อาศัยความต่างของ error นั้น (padding oracle) ค่อย ๆ ถอดรหัสข้อมูลที่ ASP.NET เข้ารหัสไว้ เช่น ViewState และในหลายกรณีอ่านไฟล์บน server อย่าง web.config (ที่มักมีความลับ) ออกมาได้ วิธีบรรเทาชั่วคราวที่ Microsoft แนะนำคือให้ตั้ง custom error ให้ทุก error โยงไปหน้าเดียวกัน เพื่อไม่ให้ attacker แยกแยะชนิด error ได้ บทเรียนคือแม้แต่ "ความแตกต่างของ error" ก็เป็นข้อมูลที่รั่วได้ ไม่ใช่แค่ stack trace',
        en: 'In September 2010 Microsoft disclosed the ASP.NET Padding Oracle vulnerability (CVE-2010-3332, MS10-070). The issue: ASP.NET returned different errors depending on whether decrypted ciphertext had valid padding. Attackers used that difference (a padding oracle) to gradually decrypt data ASP.NET had encrypted, such as ViewState, and in many cases to read server files like web.config (which often holds secrets). Microsoft\'s interim mitigation was to configure custom errors so every error mapped to a single page, denying attackers the ability to distinguish error types. The lesson: even the difference between errors is leaked information, not just stack traces.'
      },
      source: {
        label: 'Microsoft Security Advisory 2416728 (MS10-070 / CVE-2010-3332), September 2010',
        url: 'https://learn.microsoft.com/en-us/security-updates/securityadvisories/2010/2416728'
      }
    },

    codeReview: [
      {
        th: 'ตอน Code Review ให้ค้นหา printStackTrace, err.stack หรือ e.getMessage() ที่ถูกนำไปใส่ใน response body เช่น res.json, res.send หรือ ResponseEntity รายละเอียดเหล่านี้ควรอยู่ใน log ฝั่ง server เท่านั้น',
        en: 'grep for printStackTrace, err.stack, e.getMessage() flowing into a response body (res.json/res.send, ResponseEntity...body(...)) — that detail belongs in the log, not the response.'
      },
      {
        th: 'error handler ที่คืน exception object โดยตรง (res.json(err)) หรือคืน e.toString() / getClass().getName() เผยชนิด exception กับ framework ให้ attacker รู้ว่าเบื้องหลังใช้อะไร',
        en: 'Handlers that return the exception object directly (res.json(err)) or return e.toString() / getClass().getName(), revealing the exception type and framework.'
      },
      {
        th: 'ค่า detailed-error ที่เผลอเปิดใน prod: server.error.include-stacktrace=always (Spring Boot), Django DEBUG=True, app.get(\'env\') === \'development\' production profile ต้องปิดพวกนี้ให้หมด',
        en: 'Detailed-error settings left on in prod: Spring Boot server.error.include-stacktrace=always, Django DEBUG=True, app.get(\'env\') === \'development\' — the production profile must turn these off.'
      },
      {
        th: 'management/debug endpoint ที่เปิดโล่ง เช่น /actuator/**, /actuator/env, /actuator/heapdump, /debug พวกนี้แจก config และ memory ให้ทุกคนที่เข้าถึงได้ ต้องปิดหรือใส่ authentication และจำกัดเฉพาะภายใน',
        en: 'Exposed management/debug endpoints such as /actuator/**, /actuator/env, /actuator/heapdump, /debug — disable them or add authentication and restrict them to internal access.'
      },
      {
        th: 'ตรวจว่ามี correlation/trace id ถูก log ฝั่ง server และส่งกลับไปใน response ด้วย ทีม support จะได้ map รายงานของผู้ใช้เข้ากับ log ได้ โดยไม่ต้องส่ง detail ออกไป',
        en: 'Confirm a correlation/trace id is logged server-side and also returned in the response, so support can map a user report to the log without exposing any detail.'
      }
    ],

    testIt: {
      cmd: "curl -s 'http://localhost:8080/api/orders?status=bogus' | head -c 400",
      note: {
        th: 'แอปที่มีช่องโหว่จะคืน stack trace หรือข้อความ SQL (มองหา ORA-, java.sql., at com.acme..., ชื่อ table) ส่วนแอปที่แก้แล้วจะคืนแค่ { "error": "Internal error", "traceId": "..." } — รายละเอียดจริงไปอยู่ใน log ฝั่ง server ที่ค้นด้วย traceId เดียวกันได้',
        en: 'A vulnerable app returns a stack trace or SQL text (look for ORA-, java.sql., at com.acme..., a table name); a fixed app returns only { "error": "Internal error", "traceId": "..." } — the real detail lives in the server log, searchable by that same traceId.'
      }
    },

languages: {
      java: {
        filename: 'ApiExceptionHandler.java',
        lang: 'java',
        starter:
`package com.acme.orders.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handle(Exception e) {
        Map<String, Object> body = new HashMap<>();
 // ส่ง detail กลับไปให้ frontend จะได้ debug ง่ายตอน integrate
        body.put("error", e.getMessage());
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        body.put("stackTrace", sw.toString());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}`,
        solution:
`package com.acme.orders.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handle(Exception e) {
 // correlation id: ผูก log ฝั่ง server เข้ากับ response ที่ผู้ใช้เห็น
        String traceId = UUID.randomUUID().toString();
 // รายละเอียดทั้ง message และ stack ถูก log ไว้ฝั่ง server เท่านั้น
        log.error("unhandled exception traceId={}", traceId, e);

        Map<String, Object> body = new HashMap<>();
        body.put("error", "Internal error");
        body.put("traceId", traceId);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}`,
        explain: {
          th: 'โค้ดเดิมนำ e.getMessage() และ stack trace ใส่ใน response โดยตรง จึงอาจเปิดเผย schema, เวอร์ชัน หรือ path ภายใน โค้ดที่แก้แล้วสร้าง traceId แล้วบันทึกรายละเอียดเต็มไว้ใน log ฝั่ง server จากนั้นตอบ client เพียงข้อความทั่วไปและ traceId สำหรับใช้ค้นเหตุการณ์ภายหลัง จุดสำคัญคือไม่ส่ง e.getMessage() หรือ stack trace กลับไปยังผู้ใช้ และควรปิด detailed-error mode รวมถึง endpoint สำหรับ debug ใน production',
          en: 'The starter dumps e.getMessage() and the whole stack trace into the response body, leaking schema/version/paths to an attacker. The solution flips the logic: build a traceId (UUID), then log.error(..., e) to keep both message and stack server-side (SLF4J logs the exception object in full), and return to the client only { "error": "Internal error", "traceId": ... }. When a user reports the traceId, the team greps the log to the exact event without disclosing anything. Note the solution never calls e.getMessage() in the response, because the message itself can leak detail. And do disable detailed-error mode and /actuator in production too.'
        },
        checks: [
          {
            id: 'no-stacktrace-to-client',
            label: { th: 'ไม่ส่ง stack trace กลับไปให้ client', en: 'Never sends a stack trace back to the client' },
            hint: { th: 'ลบ e.printStackTrace(...) และ key "stackTrace" ออกจาก response แล้วไป log ฝั่ง server แทน', en: 'Remove e.printStackTrace(...) and the "stackTrace" key from the response; log it server-side instead' },
            weight: 3,
            mustNotMatch: /printStackTrace\s*\(|"stackTrace"|getStackTrace\s*\(/
          },
          {
            id: 'log-server-side',
            label: { th: 'log รายละเอียด error ไว้ฝั่ง server', en: 'Logs the error detail server-side' },
            hint: { th: 'ใช้ SLF4J: log.error("...", e) เพื่อเก็บ message และ stack ไว้ใน log', en: 'Use SLF4J: log.error("...", e) to keep the message and stack in the log' },
            weight: 3,
            mustMatch: /log\s*\.\s*(?:error|warn)\s*\(|logger\s*\.\s*(?:error|warn)\s*\(|LoggerFactory/
          },
          {
            id: 'correlation-id',
            label: { th: 'สร้าง correlation/trace id', en: 'Generates a correlation/trace id' },
            hint: { th: 'สร้าง traceId ด้วย UUID.randomUUID() แล้วใส่ทั้งใน log และ response', en: 'Create a traceId with UUID.randomUUID() and put it in both the log and the response' },
            weight: 2,
            mustMatch: /randomUUID\s*\(|traceId|correlationId|MDC\s*\.\s*put/
          },
          {
            id: 'generic-error-body',
            label: { th: 'response body เป็นข้อความ generic ไม่ใช่ detail ภายใน', en: 'The response body is a generic message, not internal detail' },
            hint: { th: 'ตั้ง body ให้เป็น "Internal error" (ค่าคงที่) แทน e.getMessage()', en: 'Set the body to "Internal error" (a constant) instead of e.getMessage()' },
            weight: 2,
            mustMatch: /"error"\s*,\s*"[^"]+"/
          },
          {
            id: 'return-500',
            label: { th: 'ยังคงตอบสถานะ 500 (ไม่กลืน error เงียบ ๆ)', en: 'Still returns a 500 status (does not swallow the error)' },
            hint: { th: 'คง ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR) ไว้', en: 'Keep ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)' },
            weight: 1,
            mustMatch: /INTERNAL_SERVER_ERROR|status\s*\(\s*500|HttpStatus\./
          }
        ],
        traps: [
          {
            id: 'getmessage-to-client',
            match: /getMessage\s*\(\s*\)/,
            message: {
              th: 'e.getMessage() มักมีข้อความจาก SQL/driver ("ORA-00942...", ชื่อ constraint, เศษ SQL) หรือ path ไฟล์ ต่อให้ซ่อน stack trace แล้ว การส่ง getMessage() กลับไปก็ยังรั่ว schema และเทคโนโลยีภายในอยู่ดี ให้ log ไว้ฝั่ง server แล้วคืนแค่ generic message + trace id',
              en: 'e.getMessage() often contains SQL/driver text ("ORA-00942...", a constraint name, a SQL fragment) or a file path. Even with the stack trace hidden, returning getMessage() still leaks your schema and internal technology. Log it server-side and return only a generic message + trace id.'
            }
          },
          {
            id: 'expose-exception-type',
            match: /e\s*\.\s*toString\s*\(\s*\)|getClass\s*\(\s*\)\s*\.\s*getName\s*\(/,
            message: {
              th: 'การคืน e.toString() หรือ e.getClass().getName() ไปให้ client ก็เผยชนิด exception และ framework ที่ใช้ ซึ่งเป็นข่าวกรองให้ attacker ตอบแค่ข้อความ generic กับ trace id พอ',
              en: 'Returning e.toString() or e.getClass().getName() to the client discloses the exception type and framework in use — intelligence for an attacker. Return only a generic message and a trace id.'
            }
          }
        ]
      },

      node: {
        filename: 'errorHandler.js',
        lang: 'js',
        starter:
`const express = require('express');
const app = express();

app.use('/api', apiRouter);

// error handler: ส่ง stack กลับไปให้ client จะได้เห็น error ตอน integrate
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
  });
});

module.exports = app;`,
        solution:
`const express = require('express');
const crypto = require('crypto');
const logger = require('./logger');   // winston/pino ที่เขียน log ฝั่ง server
const app = express();

app.use('/api', apiRouter);

// error handler: log รายละเอียดฝั่ง server ส่งกลับแค่ traceId ให้ client
app.use((err, req, res, next) => {
  const traceId = crypto.randomUUID();
  logger.error('unhandled exception', { traceId: traceId, err: err });
  res.status(500).json({
    error: 'Internal error',
    traceId: traceId,
  });
});

module.exports = app;`,
        explain: {
          th: 'โค้ดตั้งต้น คืน err.message และ err.stack ลง response โดยตรง ซึ่งเผย schema/path/เวอร์ชัน ส่วน โค้ดที่แก้แล้ว สร้าง traceId ด้วย crypto.randomUUID() แล้ว logger.error(...) เก็บทั้งข้อความและ error object (winston/pino จะ serialize stack ให้ในฝั่ง log) จากนั้นตอบ client แค่ { error: "Internal error", traceId } สังเกตว่า โค้ดที่แก้แล้ว ไม่ได้ส่ง err.message หรือ err.stack ออกไปเลย รายละเอียดจริงอยู่ใน log ที่ค้นด้วย traceId เดียวกันได้ อย่าลืมตั้ง NODE_ENV=production และไม่เปิด debug endpoint ใน prod ด้วย',
          en: 'The starter returns err.message and err.stack straight into the response, leaking schema/paths/versions. The solution builds a traceId with crypto.randomUUID(), then logger.error(...) keeps both the message and the error object (winston/pino serialize the stack on the log side), and returns to the client only { error: "Internal error", traceId }. Note the solution never sends err.message or err.stack out; the real detail lives in the log, searchable by that same traceId. Also set NODE_ENV=production and expose no debug endpoints in prod.'
        },
        checks: [
          {
            id: 'no-stack-to-client',
            label: { th: 'ไม่ส่ง err.stack กลับไปให้ client', en: 'Never sends err.stack back to the client' },
            hint: { th: 'ลบ stack: err.stack ออกจาก response แล้วไป log ไว้ฝั่ง server แทน', en: 'Remove stack: err.stack from the response; log it server-side instead' },
            weight: 3,
            mustNotMatch: /\.stack\b/
          },
          {
            id: 'log-server-side',
            label: { th: 'log รายละเอียด error ไว้ฝั่ง server', en: 'Logs the error detail server-side' },
            hint: { th: 'ใช้ logger.error(...) (winston/pino) หรือ console.error(...) เก็บรายละเอียดไว้ใน log', en: 'Use logger.error(...) (winston/pino) or console.error(...) to keep the detail in the log' },
            weight: 3,
            mustMatch: /logger\s*\.\s*(?:error|warn)\s*\(|console\s*\.\s*error\s*\(|log\s*\.\s*(?:error|warn)\s*\(/
          },
          {
            id: 'correlation-id',
            label: { th: 'สร้าง correlation/trace id', en: 'Generates a correlation/trace id' },
            hint: { th: 'สร้าง traceId ด้วย crypto.randomUUID() แล้วใส่ทั้งใน log และ response', en: 'Create a traceId with crypto.randomUUID() and put it in both the log and the response' },
            weight: 2,
            mustMatch: /randomUUID\s*\(|traceId|correlationId|randomBytes\s*\(/
          },
          {
            id: 'generic-error-body',
            label: { th: 'response body เป็นข้อความ generic ไม่ใช่ detail ภายใน', en: 'The response body is a generic message, not internal detail' },
            hint: { th: 'ตั้ง error: \'Internal error\' (ค่าคงที่) แทน err.message', en: 'Set error: \'Internal error\' (a constant) instead of err.message' },
            weight: 2,
            mustMatch: /error\s*:\s*['"][^'"]+['"]/
          },
          {
            id: 'respond-500',
            label: { th: 'ยังคงตอบสถานะ 500 (ไม่กลืน error เงียบ ๆ)', en: 'Still returns a 500 status (does not swallow the error)' },
            hint: { th: 'คง res.status(500) ไว้', en: 'Keep res.status(500)' },
            weight: 1,
            mustMatch: /status\s*\(\s*500\s*\)|statusCode\s*=\s*500/
          }
        ],
        traps: [
          {
            id: 'message-to-client',
            match: /error\s*:\s*err\s*\.\s*message/,
            message: {
              th: 'error: err.message ยังรั่ว detail อยู่ ต่อให้เอา stack ออกแล้วก็ตาม เพราะ err.message มักมีข้อความจาก SQL/driver หรือ path ไฟล์ ("ORA-00942...", ชื่อ constraint) ให้ log ไว้ฝั่ง server แล้วคืนแค่ generic message + traceId',
              en: 'error: err.message still leaks detail even after removing the stack, because err.message often contains SQL/driver text or file paths ("ORA-00942...", a constraint name). Log it server-side and return only a generic message + traceId.'
            }
          },
          {
            id: 'dump-error-object',
            match: /(?:res\s*\.\s*(?:json|send)|\.json|\.send)\s*\(\s*err\s*\)/,
            message: {
              th: 'res.json(err) หรือ res.send(err) serialize error object ทั้งก้อน (message และในหลาย setup รวม stack/cause) ออกไปให้ client เท่ากับรั่วทุกอย่าง ให้สร้าง body ที่คุมเองเป็น generic message + traceId แทน',
              en: 'res.json(err) or res.send(err) serializes the entire error object (message, and in many setups stack/cause) out to the client — leaking everything. Build a curated body of a generic message + traceId instead.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'แยกให้ชัดว่า "อะไรควรอยู่ใน log" กับ "อะไรควรอยู่ใน response" รายละเอียด (message, stack, SQL) อยู่ใน log ฝั่ง server ส่วน response ให้แค่ generic message กับ id หนึ่งตัวไว้อ้างอิง',
        en: 'Draw a clear line between what belongs in the log and what belongs in the response. The detail (message, stack, SQL) goes to the server log; the response gets only a generic message and one id to reference.'
      },
      {
        th: 'สร้าง trace id (UUID) หนึ่งค่าต่อ error หนึ่งครั้ง ใส่ลงทั้ง log และ response เพื่อให้ผู้ใช้แจ้ง id มาแล้วทีมค้น log เจอเหตุการณ์เดิมได้ โดยไม่ต้องส่ง detail ออกไป',
        en: 'Generate one trace id (UUID) per error, put it in both the log and the response, so a user can report the id and the team finds the exact event in the log — without sending any detail out.'
      },
      {
        th: 'Java: log.error("... traceId={}", traceId, e) แล้ว body.put("error", "Internal error") + traceId — Node: logger.error(msg, { traceId, err }) แล้ว res.status(500).json({ error: "Internal error", traceId }) และอย่าส่ง err.message / err.stack ออกไป',
        en: 'Java: log.error("... traceId={}", traceId, e) then body.put("error", "Internal error") + traceId. Node: logger.error(msg, { traceId, err }) then res.status(500).json({ error: "Internal error", traceId }) — and never send err.message / err.stack out.'
      }
    ],

    quiz: [
      {
        q: {
          th: 'ทีมเอา stack trace ออกจาก response แล้ว แต่ยังคืน body.put("error", e.getMessage()) กลับไป ปลอดภัยพอหรือยัง',
          en: 'A team removes the stack trace from the response but still returns body.put("error", e.getMessage()). Is that enough?'
        },
        choices: [
          { th: 'พอแล้ว เพราะไม่มี stack trace ก็ไม่มีข้อมูลภายในรั่ว', en: 'Enough — with no stack trace, nothing internal leaks' },
          { th: 'ยังไม่พอ เพราะ e.getMessage() มักมีข้อความจาก SQL/driver (ชื่อ table, constraint, path) ที่เผย schema และเทคโนโลยีภายใน', en: 'Not enough — e.getMessage() often contains SQL/driver text (table, constraint, path) that reveals the schema and internal technology' },
          { th: 'พอแล้ว ถ้าเปลี่ยน HTTP status เป็น 400 แทน 500', en: 'Enough, if you change the HTTP status to 400 instead of 500' },
          { th: 'พอแล้ว ถ้า minify ข้อความ error ให้สั้นลง', en: 'Enough, if you minify the error message to make it shorter' }
        ],
        answer: 1,
        why: {
          th: 'stack trace เป็นแค่ส่วนหนึ่งของข้อมูลที่รั่ว ตัว message ของ exception เองก็มักพก detail ภายในมาด้วย เช่น "ORA-00942: table or view does not exist" หรือชื่อ constraint ที่ละเมิด ซึ่งบอก schema และชนิด database ให้ attacker ทางแก้คือ log ทั้ง message และ stack ไว้ฝั่ง server แล้วคืนแค่ generic message + trace id',
          en: 'The stack trace is only part of what leaks; the exception message itself usually carries internal detail such as "ORA-00942: table or view does not exist" or a violated constraint name, revealing the schema and database type to an attacker. Log both message and stack server-side and return only a generic message + trace id.'
        },
        whyWrong: [
          { th: 'การเอา stack ออกช่วยลดข้อมูลที่รั่วก็จริง แต่ message ยังรั่วต่อได้ ต้องปิดทั้งคู่จาก response', en: 'Removing the stack reduces the leak, but the message keeps leaking; both must be kept out of the response.' },
          null,
          { th: 'HTTP status ไม่เกี่ยวกับว่า body รั่วอะไร ตอบ 400 หรือ 500 ก็ยังส่งข้อความ SQL กลับไปได้เหมือนกัน', en: 'The HTTP status has nothing to do with what the body leaks; whether 400 or 500, it can still return the SQL text.' },
          { th: 'การย่อข้อความไม่ได้ลบ detail ที่อ่อนไหว "ORA-00942" ก็สั้นอยู่แล้วแต่ยังบอก schema ได้ ปัญหาคือการส่ง message ภายในออกไป ไม่ใช่ความยาว', en: 'Shortening does not remove sensitive detail; "ORA-00942" is already short yet still reveals the schema. The problem is sending internal messages out, not their length.' }
        ]
      },
      {
        q: {
          th: 'นอกจากไม่ส่ง error detail ใน response แล้ว ยังต้องระวังอะไรอีกใน production เพื่อไม่ให้ข้อมูลภายในรั่ว',
          en: 'Beyond not returning error detail in responses, what else must you watch in production to avoid leaking internals?'
        },
        choices: [
          { th: 'ไม่มีอะไรต้องระวังเพิ่ม ถ้า response ไม่มี stack trace ก็จบ', en: 'Nothing more — if the response has no stack trace, you are done' },
          { th: 'debug/actuator endpoint และ detailed-error mode ที่เปิดค้างใน prod (เช่น /actuator/env, server.error.include-stacktrace=always, Django DEBUG=True) ที่เผย stack, env และ config', en: 'Debug/actuator endpoints and detailed-error mode left on in prod (e.g. /actuator/env, server.error.include-stacktrace=always, Django DEBUG=True) that expose stack, env, and config' },
          { th: 'แค่ปิด log ทั้งหมดใน server ก็พอ', en: 'Just turn off all logging on the server' },
          { th: 'แค่เปลี่ยนพอร์ตของแอปให้ไม่ใช่ค่า default', en: 'Just change the app\'s port away from the default' }
        ],
        answer: 1,
        why: {
          th: 'endpoint สำหรับ debug/monitoring อย่าง /actuator ของ Spring Boot, หน้า error แบบ verbose หรือโหมด debug ของ framework ถ้าเปิดค้างใน prod จะเผย stack trace, environment variable (ซึ่งอาจมีความลับ), mapping และแม้แต่ heap dump ให้ใครก็ได้ที่เรียกถึง ต้องปิดหรือจำกัด permission ให้เข้าได้เฉพาะภายใน และตั้ง production profile ให้ไม่แสดง detail',
          en: 'Debug/monitoring endpoints such as Spring Boot\'s /actuator, verbose error pages, or a framework debug mode — left on in prod — expose stack traces, environment variables (which may hold secrets), mappings, and even heap dumps to anyone who can reach them. Disable them or restrict access to internal only, and set a production profile that shows no detail.'
        },
        whyWrong: [
          { th: 'response เป็นแค่ช่องทางหนึ่ง ยังมี actuator/debug endpoint และ log ที่ตั้งค่าผิดเป็นช่องรั่วได้อีก', en: 'The response is just one channel; misconfigured actuator/debug endpoints and logs are other leak paths.' },
          null,
          { th: 'การปิด log ทั้งหมดกลับแย่กว่าเดิม เพราะสูญเสียความสามารถในการสืบสวน สิ่งที่ต้องทำคือ log ฝั่ง server อย่างปลอดภัย (redact ข้อมูลอ่อนไหว) ไม่ใช่ปิดทิ้ง', en: 'Turning off all logging is worse: you lose the ability to investigate. The goal is to log safely server-side (redacting sensitive data), not to disable logging.' },
          { th: 'การเปลี่ยนพอร์ตเป็น security by obscurity ที่แทบไม่ช่วยอะไร attacker สแกนเจอ endpoint ได้อยู่ดี และไม่เกี่ยวกับการรั่วของ error detail', en: 'Changing the port is security by obscurity that helps little; attackers scan and find endpoints anyway, and it is unrelated to error-detail leakage.' }
        ]
      }
    ],

    sim: {
      kind: 'errorleak',
      config: {
        stack: 'java.sql.SQLException: ORA-00942: table or view does not exist\n    at oracle.jdbc.driver.T4CTTIoer11.processError(T4CTTIoer11.java:498)\n    at com.acme.orders.repo.OrderRepository.findByUser(OrderRepository.java:73)\n    at com.acme.orders.web.OrderController.list(OrderController.java:41)\n    at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)'
      },
      payloads: [
        { label: { th: 'ทำให้ database error เพื่อดูว่าระบบเผยอะไรออกมาบ้าง', en: 'DB error — leaks the vendor and schema (ORA-00942)' }, value: 'db-error' },
        { label: { th: 'NullPointerException — เผย stack และ path ภายใน', en: 'NullPointerException — leaks the stack and internal paths' }, value: 'npe' },
        { label: { th: 'Auth error — เผยว่า username มีอยู่จริงหรือไม่', en: 'Auth error — reveals whether the username exists' }, value: 'auth-error' }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP Error Handling Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html' },
      { label: 'OWASP Logging Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html' },
      { label: 'CWE-209: Generation of Error Message Containing Sensitive Information', url: 'https://cwe.mitre.org/data/definitions/209.html' }
    ]
  };

 /* ======================================================================
 * Workshop object
 * ==================================================================== */
  const WORKSHOP = {
    id: 'w2',
    order: 2,
    title: {
      th: 'Workshop 2: การจัดการ Secret & Configuration',
      en: 'Workshop 2: Secrets & Configuration Management'
    },
    summary: {
      th: 'Workshop นี้เน้นช่องโหว่จากการตั้งค่าระบบไม่ปลอดภัย เช่น secret อยู่ใน repo, CORS เปิดกว้างเกินไป, security header ไม่ครบ และ error เปิดเผยรายละเอียดภายในมากเกินไป',
      en: 'A family of Security Misconfiguration bugs that come not from wrong code but from wrong settings — secrets in the repo, over-permissive CORS, missing headers, and errors that say too much.'
    },
    goal: {
      th: 'จบ workshop นี้ คุณจะจัดการ secret โดยไม่เก็บไว้ใน repo, rotate เมื่อค่ารั่ว, ตั้ง CORS ด้วย allowlist, ส่ง security header ที่จำเป็น และออกแบบ error ให้เก็บรายละเอียดไว้ใน log ฝั่ง server แต่ตอบผู้ใช้ด้วยข้อความทั่วไปและ trace id',
      en: 'By the end of this workshop you will keep secrets out of the repo entirely and know to rotate when they leak, configure CORS with an allowlist instead of a wildcard, ship the full set of security headers (CSP, HSTS, X-Frame-Options, and more), and design error handling that logs the detail server-side while returning only a generic message and a trace id to the user.'
    },
    exercises: [HARDCODED_SECRETS, CORS_MISCONFIG, VERBOSE_ERRORS]
  };

  global.SCW = global.SCW || { workshops: [], registerWorkshop: function (w) { this.workshops.push(w); } };
  global.SCW.registerWorkshop(WORKSHOP);
  if (typeof module !== 'undefined' && module.exports) module.exports = WORKSHOP;
})(typeof window !== 'undefined' ? window : globalThis);
