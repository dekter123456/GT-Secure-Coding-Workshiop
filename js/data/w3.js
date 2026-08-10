/* ============================================================================
 * js/data/w3.js — Workshop 3: Authentication & Access Control
 *
 * เนื้อหา 5 โจทย์:
 * weak-hashing — เก็บ password ด้วย MD5 แทน KDF ที่จงใจช้า
 * idor — ไม่ตรวจสิทธิ์ระดับ object เมื่อเข้าถึงทรัพยากรตาม id
 * jwt-forgery — อ่าน claims จาก JWT โดยไม่ตรวจลายเซ็น
 *  *
 * โครงสร้างข้อมูลทั้งหมดเป็นไปตาม
 * ==========================================================================*/
(function (global) {
  'use strict';

 /* ======================================================================
 * 3.1 Weak Password Hashing (MD5)
 * ==================================================================== */
  const EX_WEAK_HASHING = {
    id: 'weak-hashing',
    title: {
      th: 'Weak Password Hashing (MD5)',
      en: 'Weak Password Hashing (MD5)'
    },
    severity: 'High',
    cwe: 'CWE-916',
    owasp: 'A02:2021 – Cryptographic Failures',
    category: {
      th: 'Cryptographic Failures',
      en: 'Cryptographic Failures'
    },
    estMinutes: 12,
    points: 120,

    intro: {
      th: 'โค้ดเก็บ password ด้วย MD5 ซึ่งเป็น general-purpose hash ที่ออกแบบมาให้ "เร็วที่สุดเท่าที่จะทำได้" การ์ดจอตัวเดียวคำนวณ MD5 ได้หลายหมื่นล้านครั้งต่อวินาที ที่แย่กว่านั้นคือไม่มี salt password เดียวกันจึงได้ hash เท่ากันเสมอ attacker ที่ดัมป์ตาราง users ออกไปได้จึงไม่ต้อง "ถอดรหัส" อะไรเลย แค่เทียบกับ rainbow table ที่มีอยู่แล้วบนอินเทอร์เน็ต',
      en: 'The code stores passwords with MD5 — a general-purpose hash designed to be as fast as physically possible. A single GPU computes tens of billions of MD5 hashes per second. Worse, there is no salt, so the same password always produces the same hash. An attacker who dumps the users table does not need to "crack" anything; they just look the hash up in a rainbow table that already exists on the public internet.'
    },
    attack: {
      th: 'attacker ดัมป์ตาราง users ออกไปแล้วเจอค่า 482c811da5d5b4bc6d497ffa98491e38 วางลงในเว็บ lookup อย่าง crackstation หรือค้นด้วย Google ก็ได้คำตอบกลับมาทันทีว่า password คือ password123 ลอง 0d107d09f5bbe40cade3de5c71e9e9b7 (letmein) และ d8578edf8458ce06fbc5bb76a58c5ca4 (qwerty) ใน Attack Lab ดูได้ ทั้งสามค่าอยู่ในตาราง lookup สาธารณะมาสิบกว่าปีแล้ว',
      en: 'The attacker dumps the users table, finds 482c811da5d5b4bc6d497ffa98491e38, pastes it into a lookup site such as crackstation (or simply googles it) and instantly gets back password123. Try 0d107d09f5bbe40cade3de5c71e9e9b7 (letmein) and d8578edf8458ce06fbc5bb76a58c5ca4 (qwerty) in the Attack Lab too — all three have been in public lookup tables for over a decade.'
    },
    fix: {
      th: 'password ต้องผ่าน password hashing function (KDF) ที่ "จงใจให้ช้า" และปรับ cost/work factor ได้ เช่น argon2id, bcrypt, scrypt หรือ PBKDF2 กลไกที่ทำให้ปลอดภัยไม่ใช่ความลับของอัลกอริทึม แต่คือ "ต้นทุนต่อการเดาหนึ่งครั้ง" — bcrypt cost 12 ใช้เวลาราว 250 มิลลิวินาทีต่อครั้ง เปลี่ยนการเดา 10,000 ล้านครั้งต่อวินาทีให้เหลือประมาณ 4 ครั้งต่อวินาทีต่อคอร์ และ salt ที่สุ่มต่อผู้ใช้ทำให้ rainbow table ใช้ไม่ได้อีกเลย เพราะต้องสร้างตารางใหม่ทีละคน',
      en: 'Passwords must go through a deliberately slow, cost-tunable password hashing function (a KDF): argon2id, bcrypt, scrypt or PBKDF2. What makes it safe is not secrecy of the algorithm but the cost per guess — bcrypt at cost 12 takes roughly 250 ms per hash, turning ten billion guesses per second into about four per second per core. A per-user random salt then kills rainbow tables outright, because the attacker would have to build a fresh table for every single user.'
    },
    keyPoints: {
      vuln: [
        { th: 'โค้ดเก็บ password ด้วย MD5 ซึ่งเป็น general-purpose hash ที่ออกแบบให้เร็วสุด', en: 'The code stores passwords with MD5, a general-purpose hash built to be as fast as possible.' },
        { th: 'การ์ดจอตัวเดียวคำนวณ MD5 ได้หลายหมื่นล้านครั้งต่อวินาที', en: 'A single GPU computes tens of billions of MD5 hashes per second.' },
        { th: 'ไม่มี salt password เดียวกันจึงได้ hash เท่ากันเสมอ เทียบ rainbow table ได้ทันที', en: 'With no salt, the same password always yields the same hash — a rainbow-table lookup.' }
      ],
      attack: [
        { th: 'เมื่อได้ตาราง password hash attacker สามารถนำ hash ไปเทียบกับฐานข้อมูลสำเร็จรูปหรือใช้ GPU เดา password จำนวนมากแบบ offline ได้ โดยไม่ต้องส่ง request มาที่ระบบ', en: 'Dump the users table and paste a hash into a lookup site like crackstation.' },
        { th: 'hash ของ password ที่พบบ่อยอาจมีคำตอบอยู่ในฐานข้อมูลสาธารณะอยู่แล้ว เช่นค่า MD5 บางค่าค้นแล้วรู้ password ได้ทันที', en: '482c811da5d5b4bc6d497ffa98491e38 comes back instantly as password123.' },
        { th: 'ถ้าไม่มี salt ผู้ใช้ที่ตั้ง password เหมือนกันจะได้ hash เหมือนกัน ทำให้ attacker เห็นค่าซ้ำและใช้ตาราง lookup สำเร็จรูปได้ง่าย', en: 'No cracking needed — these hashes have been in public tables for over a decade.' }
      ],
      fix: [
        { th: 'ใช้ฟังก์ชันที่ออกแบบมาสำหรับ password โดยเฉพาะ เช่น Argon2id, bcrypt หรือ scrypt แทน hash ทั่วไปอย่าง MD5 หรือ SHA-256 ที่คำนวณเร็วเกินไป', en: 'Use a deliberately slow password hashing function: argon2id, bcrypt or scrypt.' },
        { th: 'ตั้ง cost หรือ work factor ให้การตรวจ password หนึ่งครั้งใช้เวลาพอสมควร เพื่อให้ผู้ใช้ปกติแทบไม่รู้สึก แต่ทำให้การเดาหลายล้านครั้งมีต้นทุนสูง', en: 'Tune the cost so each guess is expensive, e.g. bcrypt cost 12 at ~250 ms.' },
        { th: 'ใช้ salt แบบสุ่มแยกต่อ password หนึ่งค่า ทำให้ password เดียวกันได้ hash ต่างกัน และลดประโยชน์ของตาราง lookup ที่คำนวณไว้ล่วงหน้า', en: 'Use a per-user random salt so rainbow tables die — one would be needed per user.' }
      ]
    },
    impact: {
      th: 'หาก database รั่ว password จำนวนมากอาจถูกเดากลับได้อย่างรวดเร็ว และถ้าผู้ใช้ใช้ password ซ้ำ ความเสียหายอาจลามไปยังบัญชีในระบบอื่นด้วย',
      en: 'If the database leaks, nearly every customer password is recovered within hours — and because people reuse passwords, the damage spreads to their email and banking accounts too.'
    },

    caseStudy: {
      year: 2012,
      title: {
        th: 'LinkedIn 2012 — เก็บ password ด้วย SHA-1 แบบไม่มี salt',
        en: 'LinkedIn 2012 — passwords stored as unsalted SHA-1'
      },
      body: {
        th: 'มิถุนายน 2012 ไฟล์ hash SHA-1 ของ LinkedIn ราว 6.5 ล้านค่าถูกปล่อยออกสู่สาธารณะ เพราะไม่มี salt ชุมชนนักแคร็กจึงถอด password ส่วนใหญ่ได้ภายในไม่กี่วันโดยแทบไม่ต้องออกแรง ต่อมาเดือนพฤษภาคม 2016 มีการนำข้อมูลอีเมลคู่กับ hash password กว่า 117 ล้านรายการจากการโจรกรรมครั้งเดียวกันออกมาขาย LinkedIn จึงต้องบังคับรีเซ็ต password ของบัญชีทั้งหมดที่ยังไม่เคยเปลี่ยนตั้งแต่ปี 2012 บทเรียนคืออัลกอริทึมที่ "ยังไม่ถูกเจาะ" อย่าง SHA-1 ก็ยังผิดสำหรับ password อยู่ดี เพราะมันเร็วเกินไปและไม่มี salt',
        en: 'In June 2012 roughly 6.5 million LinkedIn SHA-1 password hashes were dumped publicly. With no salt, the cracking community recovered most of the plaintext passwords within days with almost no effort. Then in May 2016 more than 117 million email/hashed-password pairs from that same 2012 theft went up for sale, forcing LinkedIn to invalidate the passwords of every account that had not been changed since 2012. The lesson: an algorithm that is not "broken" — SHA-1 — is still the wrong choice for passwords, because it is fast and it carries no salt.'
      },
      source: {
        label: 'Krebs on Security — As Scope of 2012 Breach Expands, LinkedIn to Again Reset Passwords for Some Users',
        url: 'https://krebsonsecurity.com/2016/05/as-scope-of-2012-breach-expands-linkedin-to-again-reset-passwords-for-some-users/'
      }
    },

    codeReview: [
      {
        th: 'ตอน Code Review ให้ค้นหา MessageDigest.getInstance หรือ crypto.createHash ในไฟล์ที่มีคำว่า password, login, register, credential ถ้า hash ทั่วไปพวกนี้ถูกใช้กับ password เมื่อไหร่ ให้ตั้งคำถามทันที เพราะมันเร็วเกินไป',
        en: 'grep for MessageDigest.getInstance and crypto.createHash in every file whose name mentions password, login, register or credential — the moment those appear together, ask.'
      },
      {
        th: 'ดู migration ของคอลัมน์เก็บ hash: ความยาวบอกอัลกอริทึม VARCHAR(32)=MD5, (40)=SHA-1, (64)=SHA-256 hex ถ้าเป็น bcrypt ต้อง VARCHAR(60) และค่าจริงขึ้นต้นด้วย $2a$ / $2b$ / $2y$',
        en: 'Read the migration for the hash column: VARCHAR(32) is MD5 hex, VARCHAR(40) is SHA-1 hex, VARCHAR(64) is SHA-256 hex. bcrypt needs VARCHAR(60) and the stored value starts with $2a$ / $2b$ / $2y$.'
      },
      {
        th: 'มองหา .equals( หรือ === ที่มีตัวแปรชื่อ hash, digest, passwordHash, storedHash อยู่ข้างใดข้างหนึ่ง การเทียบ password ต้องเรียกฟังก์ชันของ library (เช่น bcrypt.compare) เสมอ ไม่ใช่เทียบโดยตรง',
        en: 'Look for .equals( or === with a variable named hash, digest, passwordHash or storedHash on either side — password comparison must always go through the library function.'
      },
      {
        th: 'ถ้า PR เพิ่มคอลัมน์ salt แล้วนำมาต่อกับ password ก่อน hash แสดงว่ายังใช้แนวคิดแบบเดิม bcrypt/Argon2 จัดการ salt และเก็บค่าที่จำเป็นไว้ใน hash ให้อยู่แล้ว',
        en: 'If the PR adds its own salt column and concatenates it before hashing, the author is still in the old mental model — bcrypt/argon2 embed the salt and cost inside the hash string; no salt column is needed.'
      }
    ],

    testIt: {
      cmd: "curl -s -X POST http://localhost:8080/api/register -H 'Content-Type: application/json' -d '{\"email\":\"test@example.com\",\"password\":\"password123\"}'; printf '%s' 'password123' | openssl md5",
      note: {
        th: 'สมัครผู้ใช้ใหม่แล้วเทียบค่าใน users.password_hash กับผลลัพธ์ของ openssl md5 ถ้าตรงกัน (482c811da5d5b4bc6d497ffa98491e38) หมายความว่ายังใช้ MD5 อยู่ เมื่อแก้ถูกแล้วค่าที่เก็บต้องยาว 60 ตัวอักษร ขึ้นต้นด้วย $2b$12$ และต้อง "ไม่ซ้ำกัน" ทุกครั้งที่สมัครด้วย password เดียวกัน เพราะ salt สุ่มใหม่เสมอ',
        en: 'Register a user, then compare the value in users.password_hash with the openssl md5 output. If they match (482c811da5d5b4bc6d497ffa98491e38) you are still on MD5. Once fixed, the stored value must be 60 characters long, start with $2b$12$, and differ every time you register the same password, because the salt is freshly random.'
      }
    },

    pitfalls: [
      {
        title: {
          th: 'เปลี่ยนไปใช้ SHA-256 พร้อมเติม salt เอง',
          en: '"I switched from MD5 to SHA-256 and added my own salt — that is fine now."'
        },
        why: {
          th: 'salt แก้ปัญหาเดียวคือ rainbow table แต่ไม่ได้ทำให้การเดา password ของผู้ใช้ "รายคน" ช้าลงเลย SHA-256 ถูกออกแบบให้เร็ว (ฮาร์ดแวร์ขุดบิตคอยน์ทำได้ระดับ terahash ต่อวินาที) attacker ที่ได้ทั้ง salt และ hash ไปก็แค่วน brute-force password ของเป้าหมายที่สนใจต่อได้เร็วเท่าเดิม สิ่งที่คุณต้องการคือ KDF ที่ปรับ cost ได้และจงใจกินเวลา/หน่วยความจำ (argon2id, bcrypt, scrypt, PBKDF2) ไม่ใช่ hash เร็ว ๆ ที่เติม salt',
          en: 'Salt solves exactly one problem — precomputed rainbow tables — and does nothing to slow down guessing against an individual user. SHA-256 is built for speed (bitcoin hardware runs it at terahashes per second), so an attacker who has both the salt and the hash brute-forces the accounts they care about just as fast. What you need is a cost-tunable KDF that deliberately burns time and memory (argon2id, bcrypt, scrypt, PBKDF2), not a fast hash with a salt bolted on.'
        },
        short: {
          th: 'salt กันแค่ rainbow table SHA-256 ยังเร็วเกินไป ต้องใช้ KDF ที่ปรับ cost ได้',
          en: 'Salt only stops rainbow tables; SHA-256 is still too fast — use a cost-tunable KDF.'
        }
      },
      {
        title: {
          th: 'เทียบ hash ด้วย equals() หรือ ===',
          en: '"I just recompute the hash and compare it with equals() / === — same thing."'
        },
        why: {
          th: 'สองปัญหา หนึ่ง: การเทียบสตริงจะหยุดทันทีที่เจอไบต์แรกที่ต่าง เวลาที่ใช้จึงบอกใบ้ว่าเดาถูกไปกี่ตัวแล้ว เปิดทางให้ timing attack ต้องเทียบแบบ constant-time เสมอ สอง: ค่า hash ของ bcrypt/argon2 มี salt และ cost ฝังอยู่ข้างใน (เช่น $2b$12$<salt><hash>) การเทียบตรง ๆ จะไม่มีวันตรงกัน เพราะต้องอ่าน salt ออกมาก่อนแล้วคำนวณซ้ำ ซึ่ง encoder.matches() / bcrypt.compare() ทำให้ทั้งสองอย่างอยู่แล้ว',
          en: 'Two problems. First, string comparison short-circuits on the first differing byte, so the time it takes leaks how many bytes you already guessed right — that is a timing attack; comparison must be constant-time. Second, a bcrypt/argon2 hash carries its salt and cost inside the string itself ($2b$12$<salt><hash>), so a direct comparison can never match: you must parse the salt out and recompute. encoder.matches() / bcrypt.compare() already does both.'
        },
        short: {
          th: 'ใช้ bcrypt.compare / matches ที่ constant-time และอ่าน salt จากค่า hash เอง',
          en: 'Use bcrypt.compare / matches — it is constant-time and reads the salt from the hash.'
        }
      },
      {
        title: {
          th: 'ให้ frontend hash password ก่อนส่งมา server',
          en: '"Let the frontend hash the password before sending, so the server never sees the real one."'
        },
        why: {
          th: 'เมื่อ server ยอมรับค่า hash จาก client ค่านั้นก็กลายเป็น "password ตัวจริง" ทันที ใครขโมย database ไปก็ replay ค่านั้นเข้าสู่ระบบได้เลยโดยไม่ต้องแคร็กอะไร การ hash ฝั่ง client จึงเป็นได้แค่ชั้นเสริม (ลดความเสี่ยงจาก log/proxy) ไม่ใช่ตัวแทนของการ hash ฝั่ง server ซึ่งยังต้องทำด้วย KDF ที่ช้าเสมอ',
          en: 'The moment the server accepts a hash from the client, that hash becomes the real password: anyone who steals the database can replay it straight into the login endpoint without cracking anything. Client-side hashing is at best an extra layer (it limits exposure in logs and proxies); it never replaces server-side hashing with a slow KDF.'
        },
        short: {
          th: 'hash ฝั่ง client กลายเป็น password ตัวจริงที่ replay ได้ ไม่แทน hash ฝั่ง server',
          en: 'A client-side hash becomes the real, replayable password; it never replaces server hashing.'
        }
      }
    ],

    languages: {
      java: {
        filename: 'PasswordService.java',
        lang: 'java',
        starter:
`import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.stereotype.Service;

@Service
public class PasswordService {

 // hash password ก่อนบันทึกลงคอลัมน์ users.password_hash
    public String hashPassword(String rawPassword) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
        return String.format("%032x", new BigInteger(1, digest));
    }

 // ใช้ตอน login: คำนวณ hash ใหม่แล้วเทียบกับค่าที่เก็บไว้
    public boolean verify(String rawPassword, String storedHash) throws Exception {
        return hashPassword(rawPassword).equals(storedHash);
    }
}`,
        solution:
`import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class PasswordService {

 // cost 12 = 2^12 รอบ ราว 250 ms ต่อการ hash หนึ่งครั้ง และสร้าง salt สุ่มให้เองต่อ password
    private final PasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public String hashPassword(String rawPassword) {
        return encoder.encode(rawPassword);
    }

 // matches() อ่าน salt กับ cost ออกจาก storedHash แล้วเทียบแบบ constant-time
    public boolean verify(String rawPassword, String storedHash) {
        return encoder.matches(rawPassword, storedHash);
    }
}`,
        explain: {
          th: 'BCryptPasswordEncoder(12) สร้าง salt สุ่ม 16 ไบต์ให้ทุกครั้งที่ encode() และฝัง salt กับ cost ลงในสตริงผลลัพธ์ (รูปแบบ $2b$12$<salt><hash> ยาว 60 ตัว) จึงไม่ต้องมีคอลัมน์ salt แยก กลไกที่กันการเดาคือ cost factor: bcrypt วน key schedule ของ Blowfish 2^12 รอบ ทำให้การเดาหนึ่งครั้งแพงขึ้นราวสี่พันเท่าเมื่อเทียบกับ MD5 ครั้งเดียว และเมื่อฮาร์ดแวร์เร็วขึ้น คุณแค่เพิ่มเลข cost โดยไม่ต้องเปลี่ยนโค้ด ส่วน matches() จะแยก salt/cost ออกจากค่าที่เก็บไว้ คำนวณซ้ำ แล้วเทียบผลลัพธ์แบบ constant-time จึงไม่รั่วข้อมูลผ่านเวลาที่ใช้',
          en: 'BCryptPasswordEncoder(12) generates a fresh 16-byte random salt on every encode() and embeds the salt and cost in the output string ($2b$12$<salt><hash>, 60 chars), so no separate salt column is needed. The defence is the cost factor: bcrypt runs the Blowfish key schedule 2^12 times, making one guess about four thousand times more expensive than a single MD5. When hardware gets faster you simply raise the number — no code change. matches() parses the salt and cost back out of the stored value, recomputes, and compares in constant time, so nothing leaks through response timing.'
        },
        checks: [
          {
            id: 'no-md5-sha1',
            label: { th: 'ไม่ใช้ MD5 หรือ SHA-1 กับ password', en: 'No MD5 or SHA-1 used on passwords' },
            hint: { th: 'ลบ MessageDigest.getInstance("MD5") ออกทั้งบรรทัด อย่าเปลี่ยนเป็น "SHA-1" หรือ "SHA-256" เพราะยังเร็วเกินไปอยู่ดี', en: 'Delete the MessageDigest.getInstance("MD5") line entirely. Do not swap it for "SHA-1" or "SHA-256" — those are still far too fast.' },
            weight: 2,
            mustNotMatch: /\bMD5\b|\bSHA-?1\b/i
          },
          {
            id: 'no-message-digest',
            label: { th: 'ไม่ใช้ MessageDigest (general-purpose hash) กับ password', en: 'No MessageDigest (a general-purpose hash) on passwords' },
            hint: { th: 'MessageDigest ทุกอัลกอริทึมเร็วเกินไปสำหรับ password ให้เปลี่ยนไปใช้ PasswordEncoder ของ Spring Security', en: 'Every MessageDigest algorithm is too fast for passwords — switch to a Spring Security PasswordEncoder.' },
            weight: 2,
            mustNotMatch: /MessageDigest/
          },
          {
            id: 'use-password-kdf',
            label: { th: 'ใช้ KDF สำหรับ password ที่ปรับ cost ได้ (bcrypt / argon2 / scrypt / PBKDF2)', en: 'Use a cost-tunable password KDF (bcrypt / argon2 / scrypt / PBKDF2)' },
            hint: { th: 'สร้าง field เช่น private final PasswordEncoder encoder = new BCryptPasswordEncoder(12); หรือใช้ Argon2PasswordEncoder', en: 'Add a field such as private final PasswordEncoder encoder = new BCryptPasswordEncoder(12); or use Argon2PasswordEncoder.' },
            weight: 3,
            mustMatch: /bcrypt|argon2|scrypt|pbkdf2/i
          },
          {
            id: 'constant-time-verify',
            label: { th: 'ตรวจ password ผ่านฟังก์ชันของ library (matches / verify)', en: 'Verify through the library function (matches / verify)' },
            hint: { th: 'เปลี่ยนเมธอด verify ให้ return encoder.matches(rawPassword, storedHash);', en: 'Change the verify method to return encoder.matches(rawPassword, storedHash);' },
            weight: 2,
            mustMatch: /\.matches\s*\(|\.verify\s*\(/
          },
          {
            id: 'no-hash-equals',
            label: { th: 'ไม่เทียบ hash ด้วย equals() (เสี่ยง timing attack และใช้กับ bcrypt ไม่ได้)', en: 'No equals() comparison of hashes (timing attack, and it cannot work with bcrypt)' },
            hint: { th: 'ลบบรรทัด hashPassword(rawPassword).equals(storedHash) ออก แล้วให้ library เป็นคนเทียบ', en: 'Remove the hashPassword(rawPassword).equals(storedHash) line and let the library do the comparison.' },
            weight: 2,
            mustNotMatch: /\.equals\s*\(\s*storedHash|storedHash\s*\.\s*equals\s*\(|hashPassword\s*\([^)]*\)\s*\.\s*equals/
          }
        ],
        traps: [
          {
            id: 'fast-hash-with-salt',
            match: /SHA-?(1|256|384|512)/i,
            message: {
              th: 'คุณยังใช้ hash ตระกูล SHA อยู่ ถึงจะเติม salt แล้วก็ตาม salt กันได้แค่ rainbow table แต่ไม่ได้ทำให้การเดา password รายคนช้าลงแม้แต่นิดเดียว SHA-256 ถูกออกแบบมาให้เร็วที่สุด ต้องเปลี่ยนไปใช้ KDF ที่ปรับ cost ได้ เช่น new BCryptPasswordEncoder(12) หรือ Argon2PasswordEncoder',
              en: 'You are still using a SHA-family hash, even with a salt. A salt only stops rainbow tables; it does not slow down per-user guessing at all, and SHA-256 is engineered for maximum speed. Move to a cost-tunable KDF such as new BCryptPasswordEncoder(12) or Argon2PasswordEncoder.'
            }
          },
          {
            id: 'timing-unsafe-compare',
            match: /\.equals\s*\(\s*storedHash|storedHash\s*\.\s*equals\s*\(/,
            message: {
              th: 'การเทียบด้วย String.equals() หยุดที่ไบต์แรกที่ต่าง เวลาที่ใช้จึงบอกใบ้ attacker ว่าเดาถูกไปกี่ตัว (timing attack) และค่า hash ของ bcrypt มี salt/cost ฝังอยู่ข้างใน การเทียบตรง ๆ จะไม่มีวันตรง ให้ใช้ encoder.matches(rawPassword, storedHash)',
              en: 'String.equals() short-circuits at the first differing byte, so the elapsed time tells an attacker how many bytes they already got right (a timing attack). Also, a bcrypt hash embeds its salt and cost, so a direct comparison can never match. Use encoder.matches(rawPassword, storedHash).'
            }
          },
          {
            id: 'bcrypt-cost-too-low',
            match: /new\s+BCryptPasswordEncoder\s*\(\s*[0-9]\s*\)/,
            message: {
              th: 'คุณตั้ง cost factor ไว้ต่ำกว่า 10 ซึ่งเร็วเกินไปในฮาร์ดแวร์ปัจจุบัน OWASP Password Storage Cheat Sheet แนะนำ bcrypt work factor อย่างน้อย 10 ตัวอย่างนี้ใช้ 12 เกณฑ์ที่ใช้จริงคือปรับให้การ hash หนึ่งครั้งกินเวลาประมาณ 250 มิลลิวินาทีบนเครื่อง production ของคุณ',
              en: 'Your cost factor is below 10, which is too fast on current hardware. The OWASP Password Storage Cheat Sheet recommends a bcrypt work factor of at least 10; this exercise uses 12. The practical rule is to tune it so one hash takes roughly 250 ms on your production hardware.'
            }
          }
        ]
      },

      node: {
        filename: 'password.service.js',
        lang: 'js',
        starter:
`const crypto = require('crypto');
const db = require('./db');

// hash password ก่อนบันทึกลงคอลัมน์ users.password_hash
function hashPassword(password) {
  return crypto.createHash('md5').update(password, 'utf8').digest('hex');
}

// ใช้ตอน login: คำนวณ hash ใหม่แล้วเทียบกับค่าที่เก็บไว้
async function login(email, password) {
  const user = await db.users.findByEmail(email);
  if (!user) return null;
  if (hashPassword(password) !== user.passwordHash) return null;
  return user;
}

module.exports = { hashPassword, login };`,
        solution:
`const bcrypt = require('bcrypt');
const db = require('./db');

// cost 12 = 2^12 รอบ ราว 250 ms ต่อครั้ง และ bcrypt ฝัง salt สุ่มไว้ในค่า hash เอง
const COST = 12;

// hash ของ password สุ่มที่ไม่มีใครรู้ ใช้ตอนไม่พบผู้ใช้ เพื่อให้เวลาตอบเท่ากันเสมอ
const DUMMY_HASH = '$2b$12$abcdefghijklmnopqrstuuMnZ5s0nHtQ5m0i5tZ0m4mQ2i0lqK7C';

async function hashPassword(password) {
  return bcrypt.hash(password, COST);
}

async function login(email, password) {
  const user = await db.users.findByEmail(email);
 // เทียบเสมอ แม้ไม่พบผู้ใช้ ไม่งั้นเวลาตอบจะบอกใบ้ว่าอีเมลนี้มีอยู่จริงหรือไม่
  const stored = user ? user.passwordHash : DUMMY_HASH;
  const ok = await bcrypt.compare(password, stored);
  if (!ok || !user) return null;
  return user;
}

module.exports = { hashPassword, login };`,
        explain: {
          th: 'bcrypt.hash(password, 12) สุ่ม salt ใหม่ทุกครั้งและฝังทั้ง salt และ cost ลงในสตริงผลลัพธ์ ($2b$12$... ยาว 60 ตัว) password เดียวกันของผู้ใช้สองคนเลยได้ค่าคนละอย่าง — rainbow table หมดประโยชน์ทันที ส่วนความช้าที่ตั้งใจ (2^12 รอบ) คือสิ่งที่เปลี่ยนการเดาระดับหมื่นล้านครั้งต่อวินาทีให้เหลือหลักหน่วย bcrypt.compare() อ่าน salt กับ cost ออกจากค่าที่เก็บไว้ คำนวณซ้ำ แล้วเทียบแบบ constant-time เพิ่มเติมคือโค้ดนี้ compare กับ DUMMY_HASH เมื่อไม่พบผู้ใช้ ทำให้ระยะเวลาตอบกลับของ "อีเมลไม่มีในระบบ" กับ "password ผิด" เท่ากัน ปิดช่องทาง user enumeration',
          en: 'bcrypt.hash(password, 12) draws a fresh salt every time and embeds both the salt and the cost in the output ($2b$12$..., 60 chars), so the same password for two users yields different values — rainbow tables become useless. The deliberate slowness (2^12 rounds) is what turns ten-billion-guesses-per-second into single digits. bcrypt.compare() parses the salt and cost back out of the stored value, recomputes and compares in constant time. The code also compares against DUMMY_HASH when no user is found, so "unknown email" and "wrong password" take the same time and user enumeration is closed off.'
        },
        checks: [
          {
            id: 'no-create-hash',
            label: { th: 'ไม่ใช้ crypto.createHash กับ password', en: 'No crypto.createHash on passwords' },
            hint: { th: 'ลบ crypto.createHash(...) ออกทั้งบรรทัด แล้ว require("bcrypt") หรือ require("argon2") แทน', en: 'Delete the crypto.createHash(...) line and require("bcrypt") or require("argon2") instead.' },
            weight: 2,
            mustNotMatch: /createHash\s*\(/
          },
          {
            id: 'no-fast-digest-name',
            label: { th: 'ไม่มีชื่ออัลกอริทึม md5 / sha1 / sha256 หลงเหลือในโค้ด', en: 'No md5 / sha1 / sha256 algorithm name left in the code' },
            hint: { th: 'การเปลี่ยน "md5" เป็น "sha256" ไม่ใช่การแก้ — hash ตระกูลนี้เร็วเกินไปสำหรับ password ทั้งหมด', en: 'Changing "md5" to "sha256" is not a fix — that whole family is too fast for passwords.' },
            weight: 2,
            mustNotMatch: /['"](md5|sha1|sha256|sha512)['"]/i
          },
          {
            id: 'use-slow-kdf',
            label: { th: 'ใช้ KDF ที่จงใจช้าและปรับ cost ได้ (bcrypt / argon2 / scrypt)', en: 'Use a deliberately slow, cost-tunable KDF (bcrypt / argon2 / scrypt)' },
            hint: { th: 'const bcrypt = require("bcrypt"); แล้วเรียก bcrypt.hash(password, 12) — หรือใช้ argon2.hash() ซึ่ง OWASP แนะนำเป็นตัวเลือกแรก', en: 'const bcrypt = require("bcrypt"); then call bcrypt.hash(password, 12) — or use argon2.hash(), which OWASP recommends first.' },
            weight: 3,
            mustMatch: /bcrypt|argon2|scrypt|pbkdf2/i
          },
          {
            id: 'use-library-compare',
            label: { th: 'ตรวจ password ด้วย compare/verify ของ library', en: 'Verify with the library compare/verify function' },
            hint: { th: 'ใช้ await bcrypt.compare(password, storedHash) (หรือ argon2.verify(storedHash, password))', en: 'Use await bcrypt.compare(password, storedHash) (or argon2.verify(storedHash, password)).' },
            weight: 2,
            mustMatch: /\.compare\s*\(|argon2\.verify\s*\(|timingSafeEqual\s*\(/
          },
          {
            id: 'no-equality-on-hash',
            label: { th: 'ไม่เทียบ hash ด้วย === / !== (เสี่ยง timing attack)', en: 'No === / !== comparison of hashes (timing attack)' },
            hint: { th: 'ลบเงื่อนไข hashPassword(password) !== user.passwordHash ออก แล้วให้ bcrypt.compare เป็นคนตัดสิน', en: 'Remove the hashPassword(password) !== user.passwordHash condition and let bcrypt.compare decide.' },
            weight: 2,
            mustNotMatch: /passwordHash\s*(===|!==|==)|(===|!==|==)\s*user\.passwordHash/
          }
        ],
        traps: [
          {
            id: 'sha-family-swap',
            match: /createHash\s*\(\s*['"]sha/i,
            message: {
              th: 'การเปลี่ยนจาก md5 เป็น sha256 ไม่ได้แก้ปัญหา ต้นเหตุคือ "ความเร็ว" ไม่ใช่ตัวอัลกอริทึม GPU ทำ SHA-256 ได้หลายพันล้านครั้งต่อวินาที ต้องใช้ bcrypt.hash(password, 12) หรือ argon2.hash(password) ที่ปรับ cost ได้',
              en: 'Swapping md5 for sha256 does not fix anything: the root cause is speed, not the algorithm. A GPU computes billions of SHA-256 hashes per second. Use bcrypt.hash(password, 12) or argon2.hash(password), where you control the cost.'
            }
          },
          {
            id: 'strict-equal-hash',
            match: /passwordHash\s*(===|!==)|(===|!==)\s*user\.passwordHash|hashPassword\s*\([^)]*\)\s*(===|!==)/,
            message: {
              th: 'ยังมีการเทียบ hash ด้วย === / !== อยู่ การเทียบสตริงใน JavaScript หยุดที่ตัวอักษรแรกที่ต่าง เวลาที่ใช้จึงรั่วข้อมูลให้ attacker และค่า hash ของ bcrypt มี salt ฝังอยู่จึงเทียบตรง ๆ ไม่ได้ ให้ใช้ await bcrypt.compare(password, user.passwordHash)',
              en: 'A === / !== hash comparison is still present. JavaScript string comparison stops at the first differing character, so the elapsed time leaks information, and a bcrypt hash embeds its salt so a direct comparison cannot work. Use await bcrypt.compare(password, user.passwordHash).'
            }
          },
          {
            id: 'cost-too-low',
            match: /bcrypt\.hash(Sync)?\s*\([^,)]+,\s*[1-9]\s*\)/,
            message: {
              th: 'cost factor ต่ำกว่า 10 เร็วเกินไปสำหรับฮาร์ดแวร์ปัจจุบัน OWASP แนะนำอย่างน้อย 10 (ตัวอย่างนี้ใช้ 12) วิธีเลือกที่ถูกคือจับเวลาบนเครื่อง production แล้วปรับให้ hash หนึ่งครั้งใช้เวลาราว 250 มิลลิวินาที',
              en: 'A cost factor below 10 is too fast for current hardware. OWASP recommends at least 10 (this exercise uses 12). The right way to choose is to time it on your production hardware and tune until one hash takes roughly 250 ms.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'ปัญหาของ MD5 ไม่ใช่ว่ามัน "ถูกเจาะแล้ว" แต่คือมัน "เร็วเกินไป" ลองถามตัวเองว่าอะไรจะทำให้ attacker ที่ได้ database ไปเดา password ได้ช้าลงเป็นล้านเท่า',
        en: 'The problem with MD5 is not that it is "broken" — it is that it is fast. Ask yourself what would make an attacker who already has the database guess a million times slower.'
      },
      {
        th: 'คุณต้องใช้ฟังก์ชันที่ออกแบบมาสำหรับ password โดยเฉพาะ: ปรับ cost / work factor ได้ และสร้าง salt สุ่มให้เองต่อ password หนึ่งค่า ไม่ต้องมีคอลัมน์ salt แยก',
        en: 'You need a function built specifically for passwords: it exposes a cost / work factor and generates its own per-password random salt — no separate salt column required.'
      },
      {
        th: 'Java: private final PasswordEncoder encoder = new BCryptPasswordEncoder(12); แล้วใช้ encoder.encode() กับ encoder.matches() / Node: bcrypt.hash(password, 12) กับ await bcrypt.compare(password, stored) — และเลิกเทียบด้วย equals() หรือ ===',
        en: 'Java: private final PasswordEncoder encoder = new BCryptPasswordEncoder(12); then use encoder.encode() and encoder.matches(). Node: bcrypt.hash(password, 12) and await bcrypt.compare(password, stored) — and stop comparing with equals() or ===.'
      }
    ],

    quiz: [
      {
        q: {
          th: 'ทำไม MD5 (และ SHA-256) จึงไม่เหมาะกับการเก็บ password?',
          en: 'Why are MD5 (and SHA-256) unsuitable for storing passwords?'
        },
        choices: [
          { th: 'เพราะ output สั้นเกินไป (128 บิต) จึงเกิด collision และ attacker ล็อกอินด้วย password อื่นที่ได้ hash เดียวกันได้', en: 'Because the output is too short (128 bits), so collisions let an attacker log in with a different password that hashes the same' },
          { th: 'เพราะถูกออกแบบมาให้คำนวณเร็วที่สุด attacker จึงลอง password ได้หลายพันล้านค่าต่อวินาทีบน GPU', en: 'Because they are engineered to be as fast as possible, so an attacker can try billions of candidate passwords per second on a GPU' },
          { th: 'เพราะเป็นการเข้ารหัสแบบสองทาง attacker ที่มีคีย์จึงถอดกลับเป็น password เดิมได้', en: 'Because they are two-way encryption, so an attacker with the key can decrypt back to the original password' },
          { th: 'เพราะปัญหาเดียวคือไม่มี salt ในตัว ถ้าเราสร้าง salt เก็บอีกคอลัมน์แล้วก็ใช้ MD5 ต่อได้', en: 'Because the only problem is the missing salt — once we generate a salt in a separate column, MD5 is fine again' }
        ],
        answer: 1,
        why: {
          th: 'หัวใจของการเก็บ password คือ "ต้นทุนต่อการเดาหนึ่งครั้ง" MD5 และ SHA-256 ถูกออกแบบให้เร็วที่สุดเพื่อใช้ตรวจความถูกต้องของไฟล์ ฮาร์ดแวร์ทั่วไปจึงลองได้ระดับหมื่นล้านครั้งต่อวินาที ขณะที่ bcrypt cost 12 ทำได้ราวไม่กี่ครั้งต่อวินาทีต่อคอร์',
          en: 'Password storage is all about the cost per guess. MD5 and SHA-256 are built for maximum speed so they can verify files, which means commodity hardware tries tens of billions of candidates per second — whereas bcrypt at cost 12 manages a handful per second per core.'
        },
        whyWrong: [
          { th: 'collision ของ MD5 คือการหาสองข้อความที่ได้ hash เท่ากันซึ่ง attacker เลือกเองทั้งคู่ ไม่ใช่การหา preimage ของ hash ที่มีอยู่ ปัญหาของ password คือความเร็วในการเดา ไม่ใช่ collision', en: 'An MD5 collision means finding two messages the attacker chooses that hash alike — not finding a preimage for an existing hash. The password problem is guessing speed, not collisions.' },
          null,
          { th: 'hash เป็นฟังก์ชันทางเดียว ไม่มีคีย์และถอดกลับไม่ได้ attacker ไม่ได้ "ถอด" แต่ "เดาแล้ว hash ใหม่ไปเทียบ" ซึ่งทำได้เร็วมากจนได้ผลเท่ากัน', en: 'A hash is one-way; there is no key and nothing to decrypt. The attacker does not reverse it — they guess, hash, and compare, which is fast enough to amount to the same thing.' },
          { th: 'salt กันได้เฉพาะ rainbow table (ตารางที่คำนวณล่วงหน้า) แต่ไม่ได้ทำให้การ brute-force password ของผู้ใช้รายคนช้าลงเลย เพราะ salt ถูกเก็บไว้ข้าง ๆ hash และ attacker ก็ได้ไปพร้อมกัน', en: 'A salt only defeats precomputed rainbow tables; it does not slow down brute-forcing an individual user at all, because the salt sits next to the hash and the attacker gets both.' }
        ]
      },
      {
        q: {
          th: 'ทำไมต้องตรวจ password ด้วย bcrypt.compare() / encoder.matches() แทนที่จะ hash ใหม่แล้วเทียบด้วย === หรือ equals()?',
          en: 'Why verify with bcrypt.compare() / encoder.matches() instead of re-hashing and comparing with === or equals()?'
        },
        choices: [
          { th: 'เพราะ === ในภาษาสคริปต์เปรียบเทียบ reference ไม่ใช่ค่าของสตริง จึงให้ผลผิดเมื่อสตริงยาว', en: 'Because === in scripting languages compares references rather than string values, so it misbehaves on long strings' },
          { th: 'เพราะค่า hash ของ bcrypt มี salt และ cost ฝังอยู่ข้างใน ต้องอ่านออกมาก่อนจึงจะคำนวณซ้ำได้ และฟังก์ชันของ library ยังเทียบแบบ constant-time เพื่อกัน timing attack', en: 'Because a bcrypt hash embeds its salt and cost, which must be parsed out before recomputing — and the library function also compares in constant time to stop timing attacks' },
          { th: 'เพราะ compare() เข้ารหัส password ระหว่างเดินทางบนเครือข่ายให้ด้วย จึงปลอดภัยกว่าแม้ไม่มี TLS', en: 'Because compare() also encrypts the password in transit, making it safe even without TLS' },
          { th: 'เพราะ bcrypt ให้ค่า hash ไม่ซ้ำกันทุกครั้ง จึงต้องเก็บ salt ไว้อีกคอลัมน์แล้วส่งเข้า compare() เป็นพารามิเตอร์ที่สาม', en: 'Because bcrypt produces a different hash every time, so you must keep the salt in a separate column and pass it to compare() as a third parameter' }
        ],
        answer: 1,
        why: {
          th: 'สตริงที่ bcrypt คืนมา ($2b$12$<salt><hash>) บรรจุทั้งเวอร์ชัน cost และ salt เอาไว้ compare() จึงอ่านค่าเหล่านั้นออกมาแล้วคำนวณซ้ำด้วยพารามิเตอร์เดิม จากนั้นเทียบผลลัพธ์แบบ constant-time ซึ่งใช้เวลาเท่ากันเสมอไม่ว่าจะตรงกันกี่ไบต์',
          en: 'The string bcrypt returns ($2b$12$<salt><hash>) carries the version, the cost and the salt. compare() reads them back, recomputes with exactly those parameters, then compares in constant time — always taking the same duration regardless of how many bytes match.'
        },
        whyWrong: [
          { th: 'ใน JavaScript === เปรียบเทียบค่าของสตริงจริง (ไม่ใช่ reference) ปัญหาไม่ได้อยู่ที่ความถูกต้องของผลลัพธ์ แต่อยู่ที่ "เวลา" ที่ใช้และการที่ bcrypt hash ไม่ deterministic', en: 'In JavaScript === does compare string values (not references). The issue is not correctness of the result but the time it takes, plus the fact that bcrypt hashes are not deterministic.' },
          null,
          { th: 'compare() ทำงานอยู่ใน server เท่านั้น ไม่เกี่ยวกับการเข้ารหัสระหว่างเดินทาง การป้องกันข้อมูลบนเครือข่ายเป็นหน้าที่ของ TLS ล้วน ๆ', en: 'compare() runs purely on the server and has nothing to do with transport encryption — protecting data on the wire is entirely the job of TLS.' },
          { th: 'จริงที่ hash ไม่ซ้ำกัน แต่ salt ถูกฝังอยู่ในสตริงผลลัพธ์แล้ว จึงไม่ต้องมีคอลัมน์ salt แยก และ compare() รับแค่สองอาร์กิวเมนต์', en: 'It is true the hashes differ, but the salt is already embedded in the result string — no salt column is needed, and compare() takes only two arguments.' }
        ]
      }
    ],

    sim: {
      kind: 'hash',
      config: {
        table: {
          'password123': '482c811da5d5b4bc6d497ffa98491e38',
          'letmein': '0d107d09f5bbe40cade3de5c71e9e9b7',
          'qwerty': 'd8578edf8458ce06fbc5bb76a58c5ca4'
        }
      },
      payloads: [
        { label: { th: 'password ที่คนใช้กันเยอะที่สุด — ถอดกลับได้ในพริบตา', en: 'password123 — a perennial top-list password' }, value: 'password123' },
        { label: { th: 'letmein —จากรายการ password ที่รั่ว', en: 'letmein — a classic from every leaked list' }, value: 'letmein' },
        { label: { th: 'qwerty — เรียงตามแป้นพิมพ์', en: 'qwerty — straight off the keyboard' }, value: 'qwerty' }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP Password Storage Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html' },
      { label: 'NIST SP 800-63B — Digital Identity Guidelines: Authentication', url: 'https://pages.nist.gov/800-63-3/sp800-63b.html' },
      { label: 'CWE-916: Use of Password Hash With Insufficient Computational Effort', url: 'https://cwe.mitre.org/data/definitions/916.html' }
    ]
  };

 /* ======================================================================
 * 3.2 Insecure Direct Object Reference (IDOR)
 * ==================================================================== */
  const EX_IDOR = {
    id: 'idor',
    title: {
      th: 'Insecure Direct Object Reference (IDOR)',
      en: 'Insecure Direct Object Reference (IDOR)'
    },
    severity: 'High',
    cwe: 'CWE-639',
    owasp: 'A01:2021 – Broken Access Control',
    category: {
      th: 'Broken Access Control',
      en: 'Broken Access Control'
    },
    estMinutes: 11,
    points: 120,

    intro: {
      th: 'endpoint คืนใบแจ้งหนี้โดยดูจาก id บน URL อย่างเดียว แล้วเชื่อว่า "ใครที่ส่ง id ถูกก็คือเจ้าของ" โค้ดตรวจแค่ว่าผู้ใช้ล็อกอินอยู่ไหม (authentication) แต่ไม่เคยถามว่าใบแจ้งหนี้ใบนั้น "เป็นของคนที่กำลังเรียกหรือเปล่า" (authorization ระดับ object) เมื่อ id เรียงกันเป็นเลขต่อเนื่อง (1001, 1002, 1003...) ผู้ใช้ที่ล็อกอินคนไหนก็แค่บวกเลขไปเรื่อย ๆ แล้วอ่านใบแจ้งหนี้ของทุกคนได้ นี่คือ Broken Access Control ระดับ object (บางทีเรียก BOLA)',
      en: 'The endpoint returns an invoice looked up purely from the id in the URL, trusting that "whoever sends a valid id must be the owner". The code checks only that the user is logged in (authentication) but never asks whether that invoice belongs to the caller (object-level authorization). Because ids run in sequence (1001, 1002, 1003...), any logged-in user just increments the number and reads everyone else\'s invoices. This is object-level Broken Access Control, sometimes called BOLA.'
    },
    attack: {
      th: 'คุณล็อกอินเป็นผู้ใช้ A ซึ่งเป็นเจ้าของใบแจ้งหนี้ 1001 จริง แล้วลองเปลี่ยน id บน URL เป็น 1002: GET /api/invoices/1002 — คุณได้ใบแจ้งหนี้ของผู้ใช้ B กลับมาเต็ม ๆ จากนั้นกวาดทีละใบ 1001, 1002, 1003, 1004 (เขียนเป็นสคริปต์ไม่กี่บรรทัด) ก็ดัมป์ข้อมูลบิลของลูกค้าทั้งระบบออกไปได้ โดยไม่ต้องเจาะ password หรือปลอม token อะไรเลย แค่แก้ตัวเลขบน URL',
      en: 'Log in as user A, the real owner of invoice 1001, then change the id in the URL to 1002: GET /api/invoices/1002 — user B\'s invoice comes back in full. Now sweep 1001, 1002, 1003, 1004 (a few lines of script) and you dump every customer\'s billing data, with no password to crack and no token to forge — just editing a number in the URL.'
    },
    fix: {
      th: 'บังคับ object-level authorization กับทุกทรัพยากรที่อ้างด้วย id: หลังโหลดใบแจ้งหนี้ ให้เทียบ "เจ้าของของทรัพยากร" กับ "ตัวตนของผู้เรียกที่ได้จาก session/token" ถ้าไม่ตรงให้ตอบ 404 หรือ 403 ทางที่แข็งแรงที่สุดคือฝังเงื่อนไขเจ้าของลงใน query ตั้งแต่ต้น (findByIdAndOwnerId) เพื่อไม่ให้มีทางลืม กลไกที่กันได้จริงคือ authorization ตัดสินจากตัวตนฝั่ง server ไม่ใช่จากการที่ client เดา id ถูก ความลับของ id ไม่ใช่การตรวจ authorization',
      en: 'Enforce object-level authorization on every id-addressed resource: after loading the invoice, compare the resource\'s owner against the caller\'s identity taken from the session/token, and return 404 or 403 on a mismatch. The strongest form bakes the ownership condition into the query itself (findByIdAndOwnerId) so it can never be forgotten. The defence is that authorization is decided from the server-side identity, not from the client having guessed a valid id — the secrecy of an id is not an authorization check.'
    },
    keyPoints: {
      vuln: [
        { th: 'endpoint คืนใบแจ้งหนี้จาก id บน URL อย่างเดียว โดยเชื่อว่าผู้ส่ง id คือเจ้าของ', en: 'The endpoint returns an invoice from the URL id alone, trusting the sender is the owner.' },
        { th: 'โค้ดตรวจแค่ว่าล็อกอินอยู่ไหม แต่ไม่ถามว่าใบนั้นเป็นของผู้เรียกหรือเปล่า', en: 'The code checks only that you are logged in, never whether the invoice is yours.' },
        { th: 'id เรียงต่อเนื่อง (1001, 1002...) ใครก็บวกเลขไปอ่านใบของคนอื่นได้', en: 'Ids run in sequence (1001, 1002...), so anyone increments to read others\' invoices.' }
      ],
      attack: [
        { th: 'ผู้ใช้ A ล็อกอินแล้วเปลี่ยน id ใน URL จาก /api/invoices/1001 เป็น /api/invoices/1002 หากระบบตรวจแค่การล็อกอิน ก็อาจได้ invoice ของผู้ใช้ B กลับมา', en: 'Log in as A who owns 1001, change the URL to 1002, and you get B\'s invoice.' },
        { th: 'attacker สามารถเขียน script วนเปลี่ยน id เช่น 1001, 1002, 1003 แล้วเรียก API ต่อเนื่องเพื่อดึงข้อมูลของผู้ใช้อื่นออกมาได้ หากระบบไม่ตรวจเจ้าของข้อมูล', en: 'Sweep 1001, 1002, 1003 with a short script and dump every customer\'s billing.' },
        { th: 'attacker ไม่ต้องขโมย password หรือปลอม token เพราะใช้ session ของตัวเองได้ เพียง endpoint ไม่ตรวจว่า object ที่ร้องขอเป็นของผู้ใช้คนปัจจุบันหรือไม่', en: 'No password to crack and no token to forge — just edit a number in the URL.' }
      ],
      fix: [
        { th: 'ทุกครั้งที่โหลดข้อมูลด้วย id ต้องตรวจ authorization ระดับ object ว่าผู้เรียกมีสิทธิ์เข้าถึงข้อมูลรายการนั้น ไม่ใช่ตรวจแค่ว่าล็อกอินแล้ว', en: 'Enforce object-level authorization on every id-addressed resource.' },
        { th: 'เปรียบเทียบ ownerId ของข้อมูลกับ user id ที่ได้จาก session หรือ token ที่ server ตรวจแล้ว หากไม่ตรงให้ตอบ 403 หรือ 404 และไม่ส่งข้อมูลกลับ', en: 'Compare the resource\'s owner with the caller\'s session identity; 403/404 on mismatch.' },
        { th: 'วิธีที่ลดโอกาสลืมตรวจคือใส่เงื่อนไขเจ้าของลงใน query ตั้งแต่ต้น เช่น findByIdAndOwnerId(id, userId) เพื่อให้ดึงได้เฉพาะข้อมูลของผู้เรียก', en: 'Bake the owner condition into the query (findByIdAndOwnerId) so it cannot be forgotten.' }
      ]
    },
    impact: {
      th: 'ผู้ใช้ที่ล็อกอินแล้วอาจอ่าน แก้ไข หรือลบข้อมูลของบัญชีอื่นได้ เพียงเปลี่ยน id ใน URL หรือ request หาก endpoint ไม่ตรวจสิทธิ์ระดับ object',
      en: 'A single logged-in user can read — or, if the same flaw sits on PUT/DELETE, modify or delete — every other customer\'s invoices, a full cross-account data breach, just by editing a number in the URL.'
    },

    caseStudy: {
      year: 2019,
      title: {
        th: 'First American Financial 2019 — IDOR ทำเอกสารสินเชื่อบ้านหลุดราว 885 ล้านรายการ',
        en: 'First American Financial 2019 — an IDOR exposed ~885 million mortgage documents'
      },
      body: {
        th: 'พฤษภาคม 2019 KrebsOnSecurity รายงานว่าเว็บไซต์ของ First American Financial บริษัทประกันกรรมสิทธิ์อสังหาริมทรัพย์รายใหญ่ของสหรัฐฯ เปิดให้เข้าถึงเอกสารราว 885 ล้านรายการย้อนหลังถึงปี 2003 ได้โดยไม่ต้องล็อกอิน เพราะลิงก์เอกสารใช้เลขที่เรียงต่อเนื่อง เพียงเปลี่ยนตัวเลขใน URL ก็สามารถเปิดเอกสารของผู้อื่นได้ ข้อมูลที่เปิดเผยมีทั้งเลขบัญชีธนาคาร เลขประกันสังคม ใบขับขี่ และสลิปโอนเงิน กรณีนี้เป็นตัวอย่างของ IDOR ที่ระบบตรวจว่า resource มีอยู่จริง แต่ไม่ได้ตรวจว่าผู้เรียกมี permission เข้าถึง resource นั้นหรือไม่',
        en: 'In May 2019 KrebsOnSecurity reported that the website of First American Financial, a major U.S. title-insurance company, exposed roughly 885 million documents dating back to 2003 with no login required, because document links used sequential numbers — changing a single digit in the link opened someone else\'s document. The exposed records included bank account numbers, Social Security numbers, drivers\' licenses and wire-transfer receipts. This is textbook IDOR: the system checked that the link was valid but never that the viewer was allowed to see that document.'
      },
      source: {
        label: 'KrebsOnSecurity — First American Financial Corp. Leaked Hundreds of Millions of Title Insurance Records (24 May 2019)',
        url: 'https://krebsonsecurity.com/2019/05/first-american-financial-corp-leaked-hundreds-of-millions-of-title-insurance-records/'
      }
    },

    codeReview: [
      {
        th: 'ถ้าพบ handler ที่รับ :id แล้ว findById(id) ก่อนคืน entity โดยตรง ให้ถามต่อทันทีว่ามีบรรทัดเทียบเจ้าของกับผู้ใช้ที่ล็อกอินไหม ถ้าไม่มี คือ IDOR ใครก็ดึงของคนอื่นได้',
        en: 'Look for any handler that takes a path variable or :id, does findById(id), and returns the entity directly — trace immediately whether an owner check against the logged-in user follows. If none, that is IDOR.'
      },
      {
        th: 'ระวังจุดที่นำ req.user / principal มาใช้แค่ "ยืนยันว่าล็อกอินแล้ว" แต่ไม่เคยนำไปเทียบกับ ownerId / userId ของข้อมูล นั่นคือมี authentication แต่ authorization หายไป',
        en: 'The logged-in user (req.user / principal) is used only to prove authentication but is never compared with the resource\'s ownerId / userId / accountId — that is authentication present, authorization missing.'
      },
      {
        th: 'repository เรียก findById(id) เฉย ๆ แทนที่จะเป็น findByIdAndOwnerId(id, currentUserId) การใส่เงื่อนไขเจ้าของลงใน query เลยคือวิธีกันลืมที่ดีที่สุด เพราะ query จะไม่คืนของคนอื่นตั้งแต่แรก',
        en: 'Repository calls findById(id) instead of findByIdAndOwnerId(id, currentUserId) — scoping the query to the owner is the most forget-proof fix.'
      },
      {
        th: 'endpoint แบบ list เช่น /invoices มักมีการกรองตามเจ้าของอยู่แล้ว แต่ endpoint รายการเดียว เช่น /invoices/{id} อาจลืมตรวจเงื่อนไขนี้ จึงควรตรวจ route ที่รับ resource id เป็นพิเศษ',
        en: 'List endpoints (/invoices) filter by owner, but the detail endpoint (/invoices/{id}) does not — IDOR usually hides in exactly that per-object route.'
      }
    ],

    testIt: {
      cmd: "for id in 1001 1002 1003 1004; do curl -s -o /dev/null -w \"%{http_code} invoice $id\\n\" -H 'Authorization: Bearer USER_A_TOKEN' http://localhost:8080/api/invoices/$id; done",
      note: {
        th: 'ทดสอบในฐานะผู้ใช้ A ซึ่งเป็นเจ้าของเฉพาะ invoice 1001 แอปที่มีช่องโหว่จะตอบ 200 ให้ทุก id ส่วนแอปที่แก้แล้วต้องตอบ 200 เฉพาะ 1001 และตอบ 403 หรือ 404 สำหรับ 1002/1003/1004',
        en: 'Run as user A, who owns only 1001. A vulnerable app answers 200 for all four; a fixed app answers 200 only for 1001 and 403 or 404 for 1002/1003/1004. If you still get 200 across the board, ownership is not really being checked.'
      }
    },

    pitfalls: [
      {
        title: {
          th: 'เปลี่ยน id เป็น UUID แทนการตรวจ authorization',
          en: '"I switched the ids to UUIDs — they are unguessable now, so it is safe."'
        },
        why: {
          th: 'การทำให้ id เดายากเป็น security by obscurity ไม่ใช่การตรวจ authorization UUID ยัง "รั่ว" ออกไปได้สารพัดทาง: อยู่ใน URL ที่ถูกแชร์ ในไฟล์ export/CSV ใน log ของ server และ proxy ใน Referer header ที่ส่งไปเว็บอื่น หรือในผลลัพธ์ของ API อื่นในระบบเดียวกัน เมื่อ attacker ได้ UUID ของเหยื่อมาสักตัว (ซึ่งได้ไม่ยาก) ระบบที่ไม่มี ownership check ก็ยอมให้เปิดอยู่ดี ต้องตรวจว่าคนเรียกเป็นเจ้าของทุกครั้ง ไม่ว่ารูปแบบ id จะเป็นอะไร',
          en: 'Making an id hard to guess is security by obscurity, not authorization. UUIDs still leak everywhere: in shared URLs, in CSV/export files, in server and proxy logs, in the Referer header sent to other sites, and in the output of other APIs in the same system. Once an attacker obtains one victim\'s UUID — which is not hard — a system with no ownership check still serves it. You must verify the caller is the owner every time, whatever the id format.'
        },
        short: {
          th: 'UUID เดายากคือ obscurity ไม่ใช่ authorization — มันรั่วออกได้สารพัดทาง',
          en: 'A hard-to-guess UUID is obscurity, not authorization — and it leaks in many ways.'
        }
      },
      {
        title: {
          th: 'ซ่อนปุ่มบน frontend แทนการตรวจฝั่ง server',
          en: '"The frontend hides the button for invoices that are not the user\'s."'
        },
        why: {
          th: 'การควบคุมที่ฝั่ง UI เป็นแค่เครื่องสำอาง attacker ไม่ได้ใช้หน้าเว็บของคุณ เขายิง GET /api/invoices/1002 ตรง ๆ ด้วย curl หรือ Postman การซ่อนปุ่ม ปิดเมนู หรือ disable field ใน JavaScript ไม่มีผลใด ๆ กับ HTTP request ที่ส่งมาจากเครื่องมืออื่น การตรวจ authorization ต้องเกิดที่ server ในทุก request เสมอ',
          en: 'A UI-side control is cosmetic. The attacker does not use your web page; they hit GET /api/invoices/1002 directly with curl or Postman. Hiding a button, removing a menu, or disabling a field in JavaScript has no effect on an HTTP request sent from another tool. Authorization must happen on the server for every request.'
        },
        short: {
          th: 'การซ่อนปุ่มใน UI ไม่ใช่การตรวจสิทธิ์ เพราะ attacker สามารถเรียก API โดยตรงด้วย curl หรือเครื่องมืออื่นได้',
          en: 'Hiding a button is cosmetic; the attacker hits the API directly with curl.'
        }
      },
      {
        title: {
          th: 'ตรวจแล้วว่าผู้ใช้ล็อกอินอยู่ (@PreAuthorize(\'isAuthenticated()\'))',
          en: '"I check that the user is authenticated (@PreAuthorize(\'isAuthenticated()\'))."'
        },
        why: {
          th: 'authentication ("คุณคือใคร") กับ authorization ระดับ object ("คุณเห็นสิ่งนี้ได้ไหม") เป็นคนละเรื่อง ผู้ใช้ B ล็อกอินถูกต้องทุกอย่าง แต่ก็ยังไม่ควรเห็นใบแจ้งหนี้ของผู้ใช้ A การเช็คแค่ว่า "ล็อกอินแล้ว" หรือแม้แต่ "มี role USER" ก็ผ่านสำหรับผู้ใช้ทุกคน — ยังต้องเทียบเจ้าของของทรัพยากรกับตัวตนของผู้เรียกอยู่ดี',
          en: 'Authentication ("who are you") and object-level authorization ("may you see this specific thing") are different questions. User B is perfectly authenticated yet still must not see user A\'s invoice. Checking only "is logged in" — or even "has role USER" — passes for every user; you still have to compare the resource\'s owner with the caller\'s identity.'
        },
        short: {
          th: 'authentication บอกว่าคุณคือใคร ไม่ได้บอกว่าคุณเห็นทรัพยากรนี้ได้',
          en: 'Authentication says who you are, not whether you may see this resource.'
        }
      }
    ],

    languages: {
      java: {
        filename: 'InvoiceController.java',
        lang: 'java',
        starter:
`package com.acme.billing.web;

import com.acme.billing.Invoice;
import com.acme.billing.InvoiceRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InvoiceController {

    private final InvoiceRepository invoices;

    public InvoiceController(InvoiceRepository invoices) {
        this.invoices = invoices;
    }

 // GET /api/invoices/1001 — ดึงใบแจ้งหนี้ตามเลขที่ผู้ใช้ขอมา
    @GetMapping("/api/invoices/{id}")
    public ResponseEntity<Invoice> getInvoice(@PathVariable Long id) {
        Invoice invoice = invoices.findById(id).orElse(null);
        if (invoice == null) {
            return ResponseEntity.notFound().build();
        }
 // ผู้ใช้ล็อกอินแล้ว จึงคืนใบแจ้งหนี้กลับไป
        return ResponseEntity.ok(invoice);
    }
}`,
        solution:
`package com.acme.billing.web;

import com.acme.billing.AppUser;
import com.acme.billing.Invoice;
import com.acme.billing.InvoiceRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InvoiceController {

    private final InvoiceRepository invoices;

    public InvoiceController(InvoiceRepository invoices) {
        this.invoices = invoices;
    }

    @GetMapping("/api/invoices/{id}")
    public ResponseEntity<Invoice> getInvoice(@PathVariable Long id,
                                              @AuthenticationPrincipal AppUser user) {
        Invoice invoice = invoices.findById(id).orElse(null);
        if (invoice == null) {
            return ResponseEntity.notFound().build();
        }
 // ตรวจความเป็นเจ้าของระดับ object ก่อนคืนข้อมูลเสมอ
        if (!invoice.getOwnerId().equals(user.getId())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(invoice);
    }
}`,
        explain: {
          th: 'ตัวตนของผู้เรียกมาจาก @AuthenticationPrincipal ซึ่ง Spring Security เติมให้จาก session/token ฝั่ง server ไม่ใช่ค่าที่ client ส่งมาเอง หลังโหลด invoice เราเทียบ invoice.getOwnerId() กับ user.getId() ถ้าไม่ตรงคือคนเรียกไม่ใช่เจ้าของ จึงตอบ 403 (หรือจะตอบ 404 เพื่อไม่บอกด้วยซ้ำว่าใบนี้มีอยู่จริงก็ยิ่งดี ป้องกันการ enumerate) กลไกสำคัญคือ authorization ตัดสินจาก "เจ้าของจริงเทียบกับผู้เรียกจริง" ไม่ใช่จากการที่ client รู้เลข id ที่ถูกต้อง ทางที่กันลืมยิ่งกว่านี้คือใช้ invoices.findByIdAndOwnerId(id, user.getId()) ให้ query กรองเจ้าของตั้งแต่ต้น',
          en: 'The caller\'s identity comes from @AuthenticationPrincipal, which Spring Security populates from the server-side session/token, not from anything the client sends. After loading the invoice we compare invoice.getOwnerId() with user.getId(); a mismatch means the caller is not the owner, so we return 403 (returning 404 to avoid even confirming the invoice exists is better still, since it blocks enumeration). The key mechanism is that authorization is decided from the real owner versus the real caller, not from the client knowing a valid id. An even more forget-proof form is invoices.findByIdAndOwnerId(id, user.getId()), letting the query filter by owner from the start.'
        },
        checks: [
          {
            id: 'resolve-principal',
            label: { th: 'ดึงตัวตนของผู้เรียกจากฝั่ง server (@AuthenticationPrincipal / SecurityContext)', en: 'Resolves the caller identity server-side (@AuthenticationPrincipal / SecurityContext)' },
            hint: { th: 'เพิ่มพารามิเตอร์ @AuthenticationPrincipal AppUser user เข้าไปในเมธอด', en: 'Add an @AuthenticationPrincipal AppUser user parameter to the method.' },
            weight: 2,
            mustMatch: /@AuthenticationPrincipal|SecurityContextHolder|getPrincipal\s*\(/
          },
          {
            id: 'ownership-check',
            label: { th: 'เทียบเจ้าของของทรัพยากรกับผู้เรียก (object-level authorization)', en: 'Compares the resource owner with the caller (object-level authorization)' },
            hint: { th: 'เช็ค !invoice.getOwnerId().equals(user.getId()) หรือ query ด้วย findByIdAndOwnerId(id, user.getId())', en: 'Check !invoice.getOwnerId().equals(user.getId()) or query with findByIdAndOwnerId(id, user.getId()).' },
            weight: 3,
            mustMatch: /getOwnerId\s*\(\s*\)\s*\.\s*equals\s*\(|findByIdAndOwner\w*\s*\(|getOwnerId\s*\(\s*\)\s*==/
          },
          {
            id: 'deny-on-mismatch',
            label: { th: 'ตอบ 403 หรือ 404 เมื่อไม่ใช่เจ้าของ', en: 'Returns 403 or 404 when the caller is not the owner' },
            hint: { th: 'return ResponseEntity.status(HttpStatus.FORBIDDEN).build(); (หรือ notFound()) ในสาขาที่เจ้าของไม่ตรง', en: 'return ResponseEntity.status(HttpStatus.FORBIDDEN).build(); (or notFound()) in the not-owner branch.' },
            weight: 2,
            mustMatch: /HttpStatus\.(FORBIDDEN|NOT_FOUND)|notFound\s*\(\s*\)|\.forbidden\s*\(/
          }
        ],
        traps: [
          {
            id: 'uuid-not-authz',
            match: /UUID|randomUUID/,
            message: {
              th: 'การเปลี่ยน id เป็น UUID ทำให้เดายากขึ้นก็จริง แต่ไม่ใช่ การตรวจ authorization UUID รั่วได้ทาง log, Referer, ไฟล์ export และ URL ที่แชร์ ถ้าไม่มีการเทียบเจ้าของกับผู้เรียก attacker ที่ได้ UUID ของเหยื่อมาก็ยังเปิดได้อยู่ดี ต้องเช็ค ownership ทุกครั้งไม่ว่ารูปแบบ id จะเป็นอะไร',
              en: 'Switching ids to UUIDs makes them harder to guess but is not an authorization check. UUIDs leak via logs, Referer headers, export files and shared URLs, so without comparing the owner to the caller, an attacker who obtains a victim\'s UUID still gets in. Verify ownership every time, regardless of id format.'
            }
          },
          {
            id: 'authn-not-authz',
            match: /isAuthenticated\s*\(\s*\)/,
            message: {
              th: 'การเช็คแค่ว่า "ล็อกอินอยู่" (isAuthenticated()) คือ authentication ไม่ใช่ object-level authorization ผู้ใช้ B ล็อกอินถูกต้องก็ยังไม่ควรเห็นใบแจ้งหนี้ของ A ต้องเทียบ invoice.getOwnerId() กับ user.getId() เพิ่ม',
              en: 'Checking only that the user "is logged in" (isAuthenticated()) is authentication, not object-level authorization. User B is properly authenticated yet still must not see A\'s invoice. You must additionally compare invoice.getOwnerId() with user.getId().'
            }
          }
        ]
      },

      node: {
        filename: 'invoices.routes.js',
        lang: 'js',
        starter:
`const express = require('express');
const router = express.Router();
const db = require('./db');

// GET /api/invoices/:id — ดึงใบแจ้งหนี้ตามเลขที่อยู่บน URL
router.get('/api/invoices/:id', async (req, res) => {
  const invoice = await db.invoices.findById(req.params.id);
  if (!invoice) {
    return res.status(404).json({ error: 'not found' });
  }
 // ผู้ใช้ล็อกอินแล้ว จึงส่งใบแจ้งหนี้กลับไป
  res.json(invoice);
});

module.exports = router;`,
        solution:
`const express = require('express');
const router = express.Router();
const db = require('./db');

// GET /api/invoices/:id — ต้องเป็นเจ้าของใบแจ้งหนี้เท่านั้นจึงจะดูได้
router.get('/api/invoices/:id', async (req, res) => {
  const invoice = await db.invoices.findById(req.params.id);
  if (!invoice) {
    return res.status(404).json({ error: 'not found' });
  }
 // ตรวจความเป็นเจ้าของระดับ object: เทียบเจ้าของทรัพยากรกับผู้ใช้ที่ยืนยันตัวแล้ว
  if (invoice.ownerId !== req.user.id) {
    return res.status(403).json({ error: 'forbidden' });
  }
  res.json(invoice);
});

module.exports = router;`,
        explain: {
          th: 'req.user มาจาก middleware ยืนยันตัวตน (เช่น session หรือ JWT ที่ verify แล้ว) ฝั่ง server ไม่ใช่ค่าที่ผู้เรียกกำหนดเองได้ เมื่อโหลด invoice แล้วเราเทียบ invoice.ownerId !== req.user.id ถ้าไม่ตรงคือคนเรียกไม่ใช่เจ้าของ จึงตอบ 403 การแยก 404 (ไม่พบ) กับ 403 (พบแต่ไม่ใช่ของคุณ) ทำให้ตรรกะชัด แต่ถ้าอยากกันการ enumerate ว่ามี id ไหนอยู่จริง จะตอบ 404 ทั้งสองกรณีก็ได้ หัวใจคือ authorization ตัดสินจากเจ้าของจริงเทียบผู้เรียกจริง วิธีที่กันลืมกว่านั้นคือ db.invoices.findByIdAndOwnerId(req.params.id, req.user.id) ให้ query กรองเจ้าของเอง',
          en: 'req.user comes from the authentication middleware (a session, or a verified JWT) on the server, not a value the caller can set. Once the invoice is loaded we compare invoice.ownerId !== req.user.id; a mismatch means the caller is not the owner, so we return 403. Splitting 404 (absent) from 403 (present but not yours) keeps the logic clear, but to avoid letting an attacker enumerate which ids exist you may return 404 in both cases. The core is that authorization is decided from the real owner versus the real caller. An even more forget-proof form is db.invoices.findByIdAndOwnerId(req.params.id, req.user.id), letting the query filter by owner.'
        },
        checks: [
          {
            id: 'resolve-principal',
            label: { th: 'ใช้ตัวตนของผู้เรียกจากฝั่ง server (req.user)', en: 'Uses the server-side caller identity (req.user)' },
            hint: { th: 'อ้าง req.user.id ที่ middleware ยืนยันตัวตนใส่มาให้ ไม่ใช่ค่าจาก query/body', en: 'Reference req.user.id set by the auth middleware, not a value from the query/body.' },
            weight: 2,
            mustMatch: /req\.user\b/
          },
          {
            id: 'ownership-check',
            label: { th: 'เทียบเจ้าของของทรัพยากรกับผู้เรียก (object-level authorization)', en: 'Compares the resource owner with the caller (object-level authorization)' },
            hint: { th: 'เช็ค if (invoice.ownerId !== req.user.id) return res.status(403)... หรือใช้ findByIdAndOwnerId', en: 'Check if (invoice.ownerId !== req.user.id) return res.status(403)... or use findByIdAndOwnerId.' },
            weight: 3,
            mustMatch: /ownerId\s*(?:!==|===|!=|==)\s*req\.user|req\.user\.id\s*(?:!==|===|!=|==)[^;\n]*ownerId|findByIdAndOwner\w*\s*\(/
          },
          {
            id: 'deny-on-mismatch',
            label: { th: 'ตอบ 403 หรือ 404 เมื่อไม่ใช่เจ้าของ', en: 'Returns 403 or 404 when the caller is not the owner' },
            hint: { th: 'return res.status(403).json(...) (หรือ 404) ในสาขาที่เจ้าของไม่ตรง', en: 'return res.status(403).json(...) (or 404) in the not-owner branch.' },
            weight: 2,
            mustMatch: /status\s*\(\s*40[34]\s*\)/
          }
        ],
        traps: [
          {
            id: 'uuid-not-authz',
            match: /uuid|randomUUID/i,
            message: {
              th: 'เปลี่ยน id เป็น UUID ทำให้เดายากขึ้น แต่ไม่ใช่ การตรวจ authorization UUID รั่วได้ทาง log, Referer, ไฟล์ export และลิงก์ที่แชร์ ถ้าไม่มี ownership check attacker ที่ได้ UUID ของเหยื่อก็ยังเปิดได้ ต้องเทียบ invoice.ownerId กับ req.user.id ทุกครั้ง',
              en: 'Switching ids to UUIDs makes them harder to guess but is not authorization. UUIDs leak via logs, Referer headers, exports and shared links, so without an ownership check an attacker holding a victim\'s UUID still gets in. Compare invoice.ownerId with req.user.id every time.'
            }
          },
          {
            id: 'authn-not-authz',
            match: /req\.isAuthenticated\s*\(\s*\)|isAuthenticated\s*\(\s*\)/,
            message: {
              th: 'req.isAuthenticated() บอกแค่ว่า "ล็อกอินอยู่" ซึ่งเป็น authentication ไม่ใช่ object-level authorization ผู้ใช้ทุกคนที่ล็อกอินจะผ่านหมด ต้องเทียบเจ้าของของ invoice กับ req.user.id เพิ่ม',
              en: 'req.isAuthenticated() only says the user is logged in — that is authentication, not object-level authorization, and every logged-in user passes it. You must additionally compare the invoice\'s owner with req.user.id.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'ลองถามตัวเองว่า "server รู้ได้ยังไงว่าคนที่เรียกเป็นเจ้าของใบแจ้งหนี้ใบนี้" ตอนนี้มันเชื่อแค่ว่าใครส่ง id ที่ถูกต้องมาก็ให้ผ่าน ซึ่งไม่ใช่การตรวจ authorization',
        en: 'Ask yourself how the server knows the caller owns this particular invoice. Right now it trusts anyone who sends a valid id — that is not an authorization check.'
      },
      {
        th: 'ดึงตัวตนของผู้เรียกจาก session/token (ไม่ใช่จาก query หรือ body) แล้วเทียบกับเจ้าของของทรัพยากรที่โหลดมา ถ้าไม่ตรงให้ตอบ 403 หรือ 404',
        en: 'Take the caller\'s identity from the session/token (never from the query or body) and compare it with the loaded resource\'s owner; on a mismatch return 403 or 404.'
      },
      {
        th: 'Java: เพิ่ม @AuthenticationPrincipal AppUser user แล้วตรวจ !invoice.getOwnerId().equals(user.getId()) — Node: if (invoice.ownerId !== req.user.id) return res.status(403)... หรือทั้งสองภาษาใช้ query แบบ findByIdAndOwnerId ให้กรองเจ้าของตั้งแต่ต้น',
        en: 'Java: add @AuthenticationPrincipal AppUser user and check !invoice.getOwnerId().equals(user.getId()). Node: if (invoice.ownerId !== req.user.id) return res.status(403)... In either language, a findByIdAndOwnerId query filters by owner from the start.'
      }
    ],

    quiz: [
      {
        q: {
          th: 'ทีมเปลี่ยนเลข id ของใบแจ้งหนี้จากเลขเรียงเป็น UUID สุ่ม แล้วบอกว่า IDOR หายแล้ว ถูกต้องหรือไม่',
          en: 'A team changes invoice ids from sequential numbers to random UUIDs and says the IDOR is gone. Are they right?'
        },
        choices: [
          { th: 'ถูก เพราะ UUID เดาไม่ได้ ไม่มีใครไปถึงใบแจ้งหนี้ของคนอื่นได้', en: 'Yes — UUIDs are unguessable, so nobody can reach another user\'s invoice' },
          { th: 'ยังไม่ถูก เพราะการที่ id เดายากไม่ใช่การตรวจ authorization server ยังต้องเทียบว่าผู้เรียกเป็นเจ้าของ เพราะ id รั่วได้ทาง log, Referer, ไฟล์ export และลิงก์ที่แชร์', en: 'No — a hard-to-guess id is not an authorization check; the server must still verify the caller owns the object, because ids leak via logs, Referer headers, exports and shared links' },
          { th: 'ถูก ถ้าเพิ่ม HTTPS ด้วย เพื่อไม่ให้เห็น UUID บนสาย', en: 'Yes, as long as you also add HTTPS so the UUID is not visible on the wire' },
          { th: 'ถูก เพราะ UUID เพิ่มทีละหนึ่งไม่ได้ จึง sweep ไล่เลขไม่ได้', en: 'Yes — a UUID cannot be incremented by one, so it cannot be swept' }
        ],
        answer: 1,
        why: {
          th: 'IDOR แก้ได้ด้วย object-level authorization เท่านั้น: ต้องเทียบเจ้าของของทรัพยากรกับตัวตนของผู้เรียกที่ได้จากฝั่ง server รูปแบบของ id (เลขหรือ UUID) ไม่เกี่ยว เพราะ id ไม่ใช่ความลับและรั่วได้หลายทาง',
          en: 'IDOR is fixed only by object-level authorization: compare the resource\'s owner with the caller\'s server-derived identity. The id\'s format (number or UUID) is irrelevant because an id is not a secret and leaks through many channels.'
        },
        whyWrong: [
          { th: 'UUID เดายากก็จริง แต่ attacker ไม่ต้องเดา เขาได้ UUID ของเหยื่อมาจาก log, ลิงก์ที่แชร์, ไฟล์ export หรือ API อื่น แล้วเปิดตรง ๆ ได้เลยถ้าไม่มี ownership check', en: 'UUIDs are hard to guess, but the attacker need not guess — they obtain a victim\'s UUID from logs, shared links, exports or another API and open it directly if there is no ownership check.' },
          null,
          { th: 'HTTPS ปกป้องข้อมูลระหว่างเดินทางเท่านั้น ไม่ได้ตัดสินว่าใครมี permission เห็นทรัพยากรใด id ยังรั่วได้หลังถึงปลายทาง (log, Referer, export) อยู่ดี', en: 'HTTPS only protects data in transit; it does not decide who may see which resource, and the id still leaks after arrival (logs, Referer, exports).' },
          { th: 'การ sweep เป็นแค่วิธีหนึ่งในการหา id attacker ที่มี UUID ของเหยื่ออยู่แล้วไม่ต้อง sweep เลย และต้นเหตุที่แท้จริงคือ endpoint ไม่ตรวจเจ้าของ', en: 'Sweeping is just one way to find ids; an attacker who already holds a victim\'s UUID need not sweep at all, and the real root cause is that the endpoint never checks ownership.' }
        ]
      },
      {
        q: {
          th: 'frontend ซ่อนปุ่ม "ดูใบแจ้งหนี้" ของใบที่ไม่ใช่ของผู้ใช้ไว้แล้ว เพียงพอไหมที่จะกัน IDOR',
          en: 'The frontend hides the "view invoice" button for invoices the user does not own. Is that enough to stop IDOR?'
        },
        choices: [
          { th: 'พอ เพราะถ้า UI ไม่แสดงปุ่ม request ก็จะไม่ถูกส่งออกไป', en: 'Yes — if the UI never shows the button, the request is never sent' },
          { th: 'ไม่พอ เพราะการควบคุมที่ browser เป็นแค่เครื่องสำอาง ใครก็ยิง GET /api/invoices/1002 ตรง ๆ ด้วย curl ได้ การตรวจ authorization ต้องอยู่ที่ server ทุก request', en: 'No — the browser control is cosmetic; anyone can call GET /api/invoices/1002 directly with curl, so authorization must run on the server for every request' },
          { th: 'พอ ถ้าลบปุ่มด้วยการ render ฝั่ง server แทน JavaScript', en: 'Yes, as long as the button is removed by server-side rendering rather than JavaScript' },
          { th: 'พอ เพราะ CORS จะบล็อก request ที่ยิงมาตรง ๆ อยู่แล้ว', en: 'Yes — CORS will block the direct request anyway' }
        ],
        answer: 1,
        why: {
          th: 'สิ่งที่ผู้ใช้เห็นบนหน้าจอกับสิ่งที่ API ยอมให้ทำเป็นคนละชั้นกัน attacker ข้ามหน้าเว็บไปยิง endpoint ตรง ๆ ได้เสมอ การบังคับ authorization เลยต้องเกิดที่ server ในทุก request ไม่ใช่ที่ UI',
          en: 'What the user sees on screen and what the API allows are separate layers; an attacker bypasses the page and hits the endpoint directly. Authorization must therefore be enforced on the server for every request, not in the UI.'
        },
        whyWrong: [
          { th: 'การซ่อนปุ่มมีผลแค่กับหน้าเว็บของคุณ attacker ใช้ curl/Postman ยิง HTTP request เองได้โดยไม่ต้องพึ่ง UI', en: 'Hiding the button affects only your page; an attacker issues the HTTP request themselves with curl/Postman without touching the UI.' },
          null,
          { th: 'ไม่ว่าจะลบปุ่มด้วย server-side rendering หรือ JavaScript ปลายทางก็ยังเป็น API เดิมที่ใครยิงตรง ๆ ก็ได้ การ render ไม่ใช่การตรวจ authorization', en: 'Whether the button is removed by server-side rendering or JavaScript, the endpoint is still the same API anyone can call directly; rendering is not authorization.' },
          { th: 'CORS จำกัดแค่ว่าโค้ด JavaScript จากเว็บอื่นจะอ่าน response ข้าม origin ได้ไหม แต่ไม่ได้บล็อก curl, Postman หรือ server-to-server request จึงกัน IDOR ไม่ได้', en: 'CORS only limits whether cross-origin JavaScript can read the response; it does not block curl, Postman or server-to-server requests, so it does not stop IDOR.' }
        ]
      }
    ],

    sim: {
      kind: 'idor',
      config: {
        owners: { '1001': 'A', '1002': 'B', '1003': 'B', '1004': 'C' },
        currentUser: 'A'
      },
      payloads: [
        { label: { th: 'เปลี่ยนเลข id เป็นของคนอื่น แล้วดูว่าเปิดได้ไหม', en: 'Request id 1002 — user B\'s invoice (a neighbouring id)' }, value: '1002' },
        { label: { th: 'ขอ id 1003 — อีกใบของผู้ใช้ B', en: 'Request id 1003 — another of user B\'s invoices' }, value: '1003' },
        { label: { th: 'ขอ id 1004 — ใบแจ้งหนี้ของผู้ใช้ C', en: 'Request id 1004 — user C\'s invoice' }, value: '1004' }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP Insecure Direct Object Reference Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html' },
      { label: 'OWASP Authorization Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html' },
      { label: 'CWE-639: Authorization Bypass Through User-Controlled Key', url: 'https://cwe.mitre.org/data/definitions/639.html' }
    ]
  };

 /* ======================================================================
 * 3.3 JWT Forgery (unverified signature)
 * ==================================================================== */
  const EX_JWT_FORGERY = {
    id: 'jwt-forgery',
    title: {
      th: 'JWT Forgery (ไม่ตรวจ signature)',
      en: 'JWT Forgery (unverified signature)'
    },
    severity: 'Critical',
    cwe: 'CWE-347',
    owasp: 'A01:2021 – Broken Access Control',
    category: {
      th: 'Broken Access Control',
      en: 'Broken Access Control'
    },
    estMinutes: 15,
    points: 150,

    intro: {
      th: 'โค้ดอ่าน claims จาก JWT (เช่น role, sub) โดย base64url-decode เอาส่วน payload ออกมาตรง ๆ แล้วเชื่อค่าในนั้นเลย โดยไม่เคยตรวจ signature จุดพลาดอยู่ตรงที่ payload ของ JWT ไม่ได้เข้ารหัส ใครก็อ่านและ "แก้" ได้ signature (ส่วนที่สาม) ต่างหากที่พิสูจน์ว่า token ออกโดย server ที่ถือ secret จริง พอโค้ดข้ามการ verify attacker เลยแก้ role เป็น admin, เปลี่ยน sub เป็น id ของคนอื่น หรือยืดวันหมดอายุ แล้วส่ง token ปลอมเข้ามาได้ตามใจ',
      en: 'The code reads claims from a JWT (role, sub, ...) by base64url-decoding the payload segment directly and trusting whatever is inside — never verifying the signature. The catch is that a JWT payload is not encrypted; anyone can read and edit it. The signature (the third segment) is what proves the token was minted by a server holding the secret. When the code skips verification, an attacker flips role to admin, changes sub to someone else\'s id, or extends the expiry, and sends the forged token in at will.'
    },
    attack: {
      th: 'ถ้าเดิม token มี payload {"sub":"1001","role":"user","exp":1893456000} attacker ก็แค่ base64url-decode ส่วนกลาง แก้เป็น {"sub":"1001","role":"admin","exp":1893456000} แล้ว base64url-encode กลับ ประกอบเป็น token ใหม่ เพราะ server เรียกแค่ decode() (ไม่ verify) มันจึงยอมรับทันที ไม่ต้องรู้ secret ด้วยซ้ำ และต่อให้ server "ตรวจ alg เอง" ก็ยังโดน alg confusion ได้: ตั้ง header เป็น {"alg":"none"} แล้วตัด signature ทิ้ง หรือส่ง token ที่เซ็นแบบ HS256 โดยใช้ RSA public key (ซึ่งเปิดเผยอยู่แล้ว) เป็น HMAC secret',
      en: 'If the original payload is {"sub":"1001","role":"user","exp":1893456000}, the attacker just base64url-decodes the middle segment, edits it to {"sub":"1001","role":"admin","exp":1893456000}, base64url-encodes it back, and reassembles the token. Because the server only calls decode() (never verify), it accepts it immediately — without even knowing the secret. And even a server that "checks alg itself" is still exposed to algorithm confusion: set the header to {"alg":"none"} and drop the signature, or send an HS256-signed token using the RSA public key (which is public) as the HMAC secret.'
    },
    fix: {
      th: 'ต้อง verify signature ก่อนอ่าน claims ทุกครั้ง และ "ล็อก algorithm" ไว้ที่ฝั่ง server ไม่ปล่อยให้ header ของ token เป็นคนเลือกว่าจะตรวจด้วยอัลกอริทึมอะไร (นี่คือหัวใจของ alg confusion) หลัง verify ผ่านแล้วยังต้องตรวจ claims มาตรฐานให้ครบ: exp (หมดอายุหรือยัง), iss (ใครออก token), aud (ตั้งใจให้ใครใช้) กลไกที่กันของปลอมคือ HMAC/digital signature ที่คำนวณจาก secret ซึ่ง attacker ไม่มี ไม่ใช่การที่ payload "ดูปกติ"',
      en: 'Always verify the signature before reading any claim, and pin the algorithm on the server side — never let the token\'s own header choose how it is verified (that is the heart of algorithm confusion). After verification passes, still validate the standard claims: exp (is it expired), iss (who issued it), aud (who it was meant for). The defence is the HMAC/digital signature computed from a secret the attacker does not have, not the payload merely "looking normal".'
    },
    keyPoints: {
      vuln: [
        { th: 'โค้ด base64url-decode payload ของ JWT แล้วเชื่อ claims เลย ไม่ตรวจ signature', en: 'The code base64url-decodes the JWT payload and trusts the claims without verifying.' },
        { th: 'payload ของ JWT ไม่ได้เข้ารหัส ใครก็อ่านและแก้ค่าในนั้นได้', en: 'A JWT payload is not encrypted; anyone can read and edit the values in it.' },
        { th: 'signature (ส่วนที่สาม) ต่างหากที่พิสูจน์ว่า token ออกโดย server ที่ถือ secret', en: 'The signature — the third segment — is what proves a server holding the secret minted it.' }
      ],
      attack: [
        { th: 'JWT payload สามารถ decode และแก้ไขได้ attacker จึงเปลี่ยน claim เช่น "role":"user" เป็น "role":"admin" แล้วประกอบ token ใหม่ได้ หากระบบไม่ตรวจ signature', en: 'Edit the payload to role:admin, re-encode, and decode() accepts it at once.' },
        { th: 'ถ้า server ใช้เพียง decode() โดยไม่ verify signature ก็จะเชื่อ claims ที่ attacker แก้เองได้ โดย attacker ไม่จำเป็นต้องรู้ secret หรือ private key', en: 'No secret needed, because the server only calls decode(), never verify.' },
        { th: 'แม้ server จะ verify signature แล้ว ก็ยังต้องระวัง algorithm confusion เช่น alg:none หรือการสลับจาก RSA ไปเป็น HMAC หาก library ยอมให้ token เป็นผู้เลือกวิธี verify', en: 'Try algorithm confusion: alg:none with no signature, or the public key as HMAC secret.' }
      ],
      fix: [
        { th: 'verify signature ก่อนเชื่อ claims ทุกครั้ง เพื่อยืนยันว่า token ถูกออกและเซ็นด้วย key ที่ server ไว้ใจจริง', en: 'Always verify the signature before reading any claim.' },
        { th: 'กำหนด algorithm ที่อนุญาตไว้ฝั่ง server อย่าให้ค่า alg ใน header ของ token เป็นตัวเลือกวิธี verify เพื่อปิดช่อง algorithm confusion', en: 'Pin the algorithm server-side; never let the token header choose how it is verified.' },
        { th: 'หลัง signature ผ่าน ยังต้องตรวจ claims สำคัญ เช่น exp ว่ายังไม่หมดอายุ, iss ว่าออกจาก issuer ที่เชื่อถือ และ aud ว่า token ถูกออกมาให้บริการนี้', en: 'After verification passes, still validate exp, iss and aud.' }
      ]
    },
    impact: {
      th: 'attacker อาจปลอมตัวเป็นผู้ใช้อื่นหรือยกระดับสิทธิ์เป็น admin ได้โดยไม่ต้องรู้ password หากระบบเชื่อ claims จาก token ที่ไม่ได้ verify อย่างถูกต้อง',
      en: 'An attacker impersonates any user or elevates themselves to admin without knowing any password or secret — the entire authentication and authorization layer is bypassed by editing a few characters of text.'
    },

    caseStudy: {
      year: 2015,
      title: {
        th: 'CVE-2015-9235 — ช่องโหว่ข้ามการ verify ใน jsonwebtoken (Node)',
        en: 'CVE-2015-9235 — verification bypass in jsonwebtoken (Node)'
      },
      body: {
        th: 'มีนาคม 2015 Tim McLean เปิดเผยช่องโหว่ข้ามการตรวจ signature ใน library JWT หลายตัว รวมถึง jsonwebtoken ของ Node (CVE-2015-9235 แก้ใน 4.2.2) แบบแรก: token ที่ตั้ง header เป็น alg:none ถูกยอมรับว่า "ถูกต้อง" ทั้งที่ไม่มี signature แบบที่สอง (alg confusion): server ที่คาดว่าจะได้ token เซ็นด้วย RSA (RS256) ถูกหลอกได้ด้วย token ที่เซ็นแบบ HS256 โดยใช้ RSA public key ของ server (ซึ่งเปิดเผย) มาเป็น HMAC secret เพราะ verify() เลือกอัลกอริทึมจาก header ที่ attacker คุมเอง การแก้คือบังคับให้ผู้เรียกระบุ allowlist ของ algorithm บทเรียนคืออย่าให้ header ของ token เป็นคนกำหนดวิธี verify',
        en: 'In March 2015 Tim McLean disclosed signature-verification bypasses in several JWT libraries, including Node\'s jsonwebtoken (CVE-2015-9235, fixed in 4.2.2). First: a token whose header said alg:none was accepted as "valid" despite carrying no signature. Second (algorithm confusion): a server expecting an RSA-signed (RS256) token could be tricked by an HS256-signed token that used the server\'s RSA public key (which is published) as the HMAC secret, because verify() picked the algorithm from the attacker-controlled header. The fix was to require callers to pass an algorithm allowlist. The lesson: never let a token\'s header decide how it is verified.'
      },
      source: {
        label: 'Auth0 — Critical vulnerabilities in JSON Web Token libraries (Tim McLean)',
        url: 'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/'
      }
    },

    codeReview: [
      {
        th: 'ตอน Code Review ให้ค้นหา jwt.decode(, parseClaimsJwt, หรือ Base64.getUrlDecoder().decode(...) ที่ใช้กับส่วนกลางของ token พวกนี้อ่าน claims ออกมาโดยไม่ตรวจ signature หมายความว่าเชื่อค่าที่ใครก็ปลอมได้',
        en: 'grep for jwt.decode(, parseClaimsJwt, or Base64.getUrlDecoder().decode(...) applied to the second token segment — all of these read claims without verifying the signature.'
      },
      {
        th: 'การเรียก verify()/parser ที่ไม่ได้ส่ง allowlist ของ algorithm (หรือไม่ได้ล็อกชนิดคีย์) พอไม่ล็อก header ของ token จะเลือกอัลกอริทึมเอง เปิดช่องให้ alg confusion หรือ alg:none',
        en: 'A verify()/parser call that passes no algorithms allowlist (or does not pin the key type) — without pinning, the token\'s own alg header selects the algorithm, enabling confusion or alg:none.'
      },
      {
        th: 'การ verify ที่ตรวจแค่ signature แต่ไม่เคยตรวจ exp / iss / aud ก็ยังปล่อยให้ token หมดอายุ หรือ token ที่ออกไว้ให้บริการอื่น ผ่านเข้ามาได้ ต้องตรวจ claims พวกนี้ด้วย',
        en: 'Verification that never checks exp / iss / aud — a valid signature alone still lets expired tokens or tokens meant for another service through.'
      },
      {
        th: 'secret ของ HMAC หรือคีย์ที่ใช้ verify ถูก hardcode ไว้ใน repo หรือใช้คีย์เดียวเซ็นและ verify ข้ามหลายบริการ ใครได้คีย์ไปก็ปลอม token ได้ สุขอนามัยของคีย์เป็นส่วนหนึ่งของการแก้',
        en: 'The HMAC secret or verification key hardcoded in the repo, or one key used to both sign and verify across services — key hygiene is part of the fix.'
      }
    ],

    testIt: {
      cmd: "ALG=$(printf '%s' '{\"alg\":\"none\",\"typ\":\"JWT\"}' | openssl base64 -A | tr '+/' '-_' | tr -d '='); PAY=$(printf '%s' '{\"sub\":\"1001\",\"role\":\"admin\",\"exp\":1893456000}' | openssl base64 -A | tr '+/' '-_' | tr -d '='); curl -s -o /dev/null -w '%{http_code}\\n' -H \"Authorization: Bearer $ALG.$PAY.\" http://localhost:8080/api/me",
      note: {
        th: 'คำสั่งนี้สร้าง token ปลอมที่ตั้ง alg:none และ role:admin โดยไม่มี signature แอปที่มีช่องโหว่ (decode หรือไม่ล็อก alg) จะตอบ 200 และมองว่าเป็น admin ส่วนแอปที่แก้แล้วต้องตอบ 401 เพราะไม่มี signature ที่ถูกต้องและ none ไม่อยู่ใน allowlist',
        en: 'This builds a forged token with alg:none and role:admin and no signature. A vulnerable app (decode, or no alg pin) answers 200 and treats you as admin; a fixed app must answer 401 because there is no valid signature and none is not in the allowlist.'
      }
    },

    pitfalls: [
      {
        title: {
          th: 'อ่าน alg จาก header แล้วเลือกวิธี verify ตามนั้น',
          en: '"I read the alg from the header myself and verify accordingly."'
        },
        why: {
          th: 'header ของ JWT ถูกควบคุมโดย attacker ทั้งหมด การให้มันเป็นคนบอกว่าจะ verify ด้วยอัลกอริทึมอะไรคือช่องโหว่ทั้งดุ้น (alg confusion) สองกรณีที่เจอบ่อย: (1) ตั้ง alg:none แล้วตัด signature ระบบที่รองรับ none จะผ่านทันที (2) ระบบที่คาด RS256 (คีย์อสมมาตร) ถูกส่ง token ที่เซ็นแบบ HS256 โดยเอา RSA public key ซึ่ง "เปิดเผยอยู่แล้ว" มาใช้เป็น HMAC secret เพราะโค้ด verify เอา public key ไปใช้ตรงกับที่ attacker เซ็นมา วิธีที่ถูกคือ "ล็อก" algorithm ที่ฝั่ง server (allowlist) และปฏิเสธทุกอย่างที่ไม่ตรง',
          en: 'A JWT header is fully attacker-controlled, so letting it dictate the verification algorithm is the whole vulnerability (algorithm confusion). Two classics: (1) set alg:none and drop the signature — a system that honours none passes it instantly; (2) a system expecting RS256 (asymmetric) receives an HS256-signed token that uses the RSA public key — which is already published — as the HMAC secret, and because the verify code feeds that public key in, it matches what the attacker signed with. The fix is to pin the algorithm on the server (an allowlist) and reject anything else.'
        },
        short: {
          th: 'header คุมโดย attacker — ล็อก algorithm ฝั่ง server อย่าอ่าน alg จาก token',
          en: 'The header is attacker-controlled — pin the algorithm server-side, do not read alg from it.'
        }
      },
      {
        title: {
          th: 'verify signature แล้วข้ามการตรวจ exp / iss / aud',
          en: '"I verify the signature — that is enough; I do not check exp/iss/aud."'
        },
        why: {
          th: 'signature ที่ถูกต้องพิสูจน์แค่ว่า "token นี้ออกโดยคนที่ถือ secret" เท่านั้น ไม่ได้บอกว่ายังไม่หมดอายุ ไม่ได้บอกว่าออกโดย issuer ที่คุณไว้ใจ และไม่ได้บอกว่าตั้งใจให้บริการของคุณใช้ token ที่หมดอายุแล้วแต่ signature ยังถูก (เช่นหลุดจาก log เก่า) จะถูก replay ได้ และ token ที่เซ็นถูกต้องสำหรับบริการ B อาจถูกนำมาใช้กับบริการ A ถ้าไม่เช็ค aud ต้องตรวจ exp (ปฏิเสธถ้าหมดอายุ), iss และ aud เสมอ',
          en: 'A valid signature proves only that the token was minted by someone holding the secret — not that it is unexpired, not that it came from an issuer you trust, and not that it was meant for your service. An expired-but-validly-signed token (say, leaked from an old log) can be replayed, and a token correctly signed for service B may be used against service A if you do not check aud. Always validate exp (reject if expired), iss and aud.'
        },
        short: {
          th: 'signature ถูกไม่ได้หมายความว่าไม่หมดอายุหรือถูก issuer — ต้องตรวจ exp/iss/aud',
          en: 'A valid signature is not unexpired or right-issuer — still check exp/iss/aud.'
        }
      },
      {
        title: {
          th: 'ใช้ jwt.decode() ดึง user id มาแสดงโดยไม่ verify',
          en: '"I only use jwt.decode() to pull the user id for display, not for authorization."'
        },
        why: {
          th: 'decode() ไม่ verify อะไรเลย ค่าที่ได้จึงเป็นค่าที่ attacker กำหนดได้ทั้งหมด ตรงที่พลาดคือ id/ชื่อที่ "เอามาแค่แสดง" มักไหลต่อไปเป็นคีย์ในการ query, เป็นค่าใน log, หรือถูกส่งต่อให้โค้ดส่วนอื่นที่เชื่อมัน กลายเป็นช่องโหว่โดยไม่ตั้งใจ กติกาที่ปลอดภัยคือ verify ก่อนเสมอ แล้วค่อยอ่าน claims ไม่ว่าจะเอาไปใช้ทำอะไร',
          en: 'decode() verifies nothing, so its output is entirely attacker-controlled. The trouble is that an id or name pulled out "just for display" tends to flow onward as a query key, a log value, or input to other code that trusts it — an accidental vulnerability. The safe rule is: always verify first, then read claims, whatever you use them for.'
        },
        short: {
          th: 'decode() แค่อ่านข้อมูลใน token ไม่ได้ตรวจ signature ดังนั้นค่าที่อ่านออกมายังเป็นข้อมูลที่ attacker สามารถกำหนดเองได้',
          en: 'decode() verifies nothing; even values "just for display" stay attacker-controlled.'
        }
      }
    ],

    languages: {
      java: {
        filename: 'TokenAuth.java',
        lang: 'java',
        starter:
`package com.acme.gateway.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class TokenAuth {

    private final ObjectMapper mapper = new ObjectMapper();

 // อ่าน role จาก JWT ที่แนบมากับ header Authorization
    public String roleOf(String token) throws Exception {
        String[] parts = token.split("\\\\.");
 // ถอด payload (ส่วนที่สอง) เป็น JSON แล้วอ่าน field role ออกมาเลย
        byte[] json = Base64.getUrlDecoder().decode(parts[1]);
        JsonNode claims = mapper.readTree(new String(json, StandardCharsets.UTF_8));
        return claims.get("role").asText();
    }
}`,
        solution:
`package com.acme.gateway.auth;

import javax.crypto.SecretKey;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class TokenAuth {

 // คีย์ HMAC เก็บฝั่ง server เท่านั้น โหลดจาก env / secret manager
    private final SecretKey key;

    public TokenAuth(byte[] hmacSecret) {
        this.key = Keys.hmacShaKeyFor(hmacSecret);
    }

    public String roleOf(String token) {
 // verifyWith ล็อกการตรวจไว้ที่คีย์ HMAC และตรวจลายเซ็นก่อนคืน claims
 // parseSignedClaims ยังตรวจ exp ให้อัตโนมัติ ส่วน iss/aud บังคับด้วย require*
        Jws<Claims> jws = Jwts.parser()
            .verifyWith(key)
            .requireIssuer("acme-auth")
            .requireAudience("acme-api")
            .build()
            .parseSignedClaims(token);
        Claims claims = jws.getPayload();
        return claims.get("role", String.class);
    }
}`,
        explain: {
          th: 'จุดสำคัญคือเปลี่ยนจาก "ถอด payload มาอ่าน" เป็น "ตรวจ signature ก่อนแล้วค่อยอ่าน" verifyWith(key) ผูกการตรวจไว้กับคีย์ HMAC ที่เรากำหนดเอง header alg ของ token เลยเลือกอัลกอริทึมเองไม่ได้ (ปิด alg confusion และ alg:none) parseSignedClaims จะโยน exception ถ้า signature ผิดหรือ token หมดอายุ (ตรวจ exp ให้อยู่แล้ว) ส่วน requireIssuer/requireAudience บังคับว่า iss ต้องเป็น acme-auth และ aud ต้องมี acme-api เท่ากับปฏิเสธ token ที่เซ็นถูกแต่ตั้งใจให้บริการอื่นใช้ ความปลอดภัยมาจากการที่ attacker ไม่มีคีย์ จึงปลอม signature ที่ผ่าน verifyWith ไม่ได้',
          en: 'The key change is moving from "decode the payload and read it" to "verify the signature first, then read". verifyWith(key) binds verification to our own HMAC key, so the token\'s alg header can no longer choose the algorithm (closing algorithm confusion and alg:none). parseSignedClaims throws if the signature is wrong or the token is expired (it checks exp for you), while requireIssuer/requireAudience enforce that iss is acme-auth and aud contains acme-api — rejecting tokens that are validly signed but intended for another service. The security comes from the attacker not having the key, so they cannot forge a signature that passes verifyWith.'
        },
        checks: [
          {
            id: 'verify-signature',
            label: { th: 'ตรวจ signature ก่อนอ่าน claims (parseSignedClaims / parseClaimsJws)', en: 'Verifies the signature before reading claims (parseSignedClaims / parseClaimsJws)' },
            hint: { th: 'ใช้ Jwts.parser().verifyWith(key).build().parseSignedClaims(token) แทนการถอด payload เอง', en: 'Use Jwts.parser().verifyWith(key).build().parseSignedClaims(token) instead of decoding the payload yourself.' },
            weight: 3,
            mustMatch: /parseSignedClaims\s*\(|parseClaimsJws\s*\(/
          },
          {
            id: 'pin-key',
            label: { th: 'ล็อกคีย์/อัลกอริทึมไว้ฝั่ง server (verifyWith / hmacShaKeyFor)', en: 'Pins the key/algorithm server-side (verifyWith / hmacShaKeyFor)' },
            hint: { th: 'สร้างคีย์ด้วย Keys.hmacShaKeyFor(secret) แล้ว.verifyWith(key) — อย่าปล่อยให้ header เลือกอัลกอริทึม', en: 'Build the key with Keys.hmacShaKeyFor(secret) and .verifyWith(key) — do not let the header choose the algorithm.' },
            weight: 2,
            mustMatch: /verifyWith\s*\(|hmacShaKeyFor\s*\(|setSigningKey\s*\(/
          },
          {
            id: 'no-manual-decode',
            label: { th: 'ไม่ base64-decode payload มาอ่าน claims เอง', en: 'Does not base64-decode the payload to read claims by hand' },
            hint: { th: 'ลบ Base64.getUrlDecoder().decode(parts[1]) และการ split token ออก ให้ library เป็นคน parse หลัง verify', en: 'Remove Base64.getUrlDecoder().decode(parts[1]) and the token split; let the library parse after verification.' },
            weight: 2,
            mustNotMatch: /getUrlDecoder\s*\(\s*\)|getDecoder\s*\(\s*\)|getMimeDecoder\s*\(\s*\)/
          },
          {
            id: 'validate-claims',
            label: { th: 'ตรวจ claims มาตรฐาน (iss / aud / exp)', en: 'Validates standard claims (iss / aud / exp)' },
            hint: { th: 'เพิ่ม.requireIssuer("acme-auth") และ.requireAudience("acme-api"); exp ถูกตรวจโดย parseSignedClaims อยู่แล้ว', en: 'Add .requireIssuer("acme-auth") and .requireAudience("acme-api"); exp is already checked by parseSignedClaims.' },
            weight: 1,
            mustMatch: /requireIssuer\s*\(|requireAudience\s*\(|requireExpiration\s*\(|\.require\s*\(/
          }
        ],
        traps: [
          {
            id: 'alg-none',
            match: /SignatureAlgorithm\.NONE|["']none["']|parseClaimsJwt\s*\(|parseUnsecured/,
            message: {
              th: 'พบการยอมรับ token แบบไม่มี signature (alg:none / parseClaimsJwt / unsecured) นี่คือช่องโหว่ CVE-2015-9235 แบบแรก: ใครก็สร้าง token ที่ตั้ง alg:none แล้วใส่ claims อะไรก็ได้ ต้องใช้ parseSignedClaims กับ verifyWith(key) ที่ล็อกอัลกอริทึมไว้เท่านั้น',
              en: 'This accepts unsigned tokens (alg:none / parseClaimsJwt / unsecured) — the first CVE-2015-9235 flaw: anyone can mint a token with alg:none and any claims. Use parseSignedClaims with verifyWith(key), which pins the algorithm.'
            }
          },
          {
            id: 'manual-decode-left',
            match: /getUrlDecoder\s*\(\s*\)|getDecoder\s*\(\s*\)/,
            message: {
              th: 'ยังมีการ base64-decode payload มาอ่านเองอยู่ ค่าที่ได้ยังเป็นค่าที่ attacker ปลอมได้เพราะไม่ผ่านการ verify signature ให้ตรวจ token ด้วย Jwts.parser().verifyWith(key).build().parseSignedClaims(token) แล้วอ่าน claims จากผลลัพธ์',
              en: 'A manual base64-decode of the payload is still here, and its values remain forgeable because the signature was never verified. Verify the token with Jwts.parser().verifyWith(key).build().parseSignedClaims(token) and read claims from the result.'
            }
          }
        ]
      },

      node: {
        filename: 'authorize.js',
        lang: 'js',
        starter:
`const jwt = require('jsonwebtoken');

// อ่าน claims จาก JWT เพื่อรู้ว่าใครเรียกและมีสิทธิ์อะไร
function authorize(token) {
 // decode ดึง payload ออกมาได้เลยโดยไม่ต้องมี secret สะดวกดี
  const claims = jwt.decode(token);
  if (!claims) {
    return { ok: false };
  }
  return { ok: true, userId: claims.sub, role: claims.role };
}

module.exports = { authorize };`,
        solution:
`const jwt = require('jsonwebtoken');

// secret เก็บฝั่ง server เท่านั้น (env / secret manager) ห้าม commit ลง repo
const SECRET = process.env.JWT_SECRET;

function authorize(token) {
  try {
 // verify ตรวจลายเซ็น + ล็อก algorithm ไว้ที่ HS256 + ตรวจ iss/aud/exp ให้ครบ
    const claims = jwt.verify(token, SECRET, {
      algorithms: ['HS256'],
      issuer: 'acme-auth',
      audience: 'acme-api'
    });
    return { ok: true, userId: claims.sub, role: claims.role };
  } catch (err) {
 // ลายเซ็นผิด, หมดอายุ, หรือ iss/aud ไม่ตรง → ปฏิเสธทั้งหมด
    return { ok: false };
  }
}

module.exports = { authorize };`,
        explain: {
          th: 'jwt.verify() คำนวณ HMAC ของ header.payload ด้วย SECRET แล้วเทียบกับ signature ในส่วนที่สาม ถ้าไม่ตรงจะโยน error ทันที attacker ที่ไม่มี SECRET จึงปลอม signature ไม่ได้ ออปชัน algorithms:[\'HS256\'] คือการ "ล็อก" อัลกอริทึมไว้ฝั่ง server ทำให้ header alg ของ token เลือกเองไม่ได้ ปิดทั้ง alg:none และ RS→HS confusion ส่วน issuer และ audience สั่งให้ jwt.verify ตรวจ iss/aud ให้ และ exp ถูกตรวจโดยค่าเริ่มต้นอยู่แล้ว จุดต่างจากโค้ดเดิมคือเลิกใช้ jwt.decode() ซึ่งแค่ base64-decode โดยไม่ตรวจอะไรเลย',
          en: 'jwt.verify() computes the HMAC of header.payload with SECRET and compares it to the signature in the third segment, throwing immediately on a mismatch, so an attacker without SECRET cannot forge a signature. The algorithms:[\'HS256\'] option pins the algorithm server-side so the token\'s alg header cannot choose it, closing both alg:none and RS→HS confusion. issuer and audience make jwt.verify check iss/aud, and exp is validated by default. The difference from before is dropping jwt.decode(), which merely base64-decodes and verifies nothing.'
        },
        checks: [
          {
            id: 'verify-not-decode',
            label: { th: 'ตรวจ token ด้วย jwt.verify() ไม่ใช่แค่ decode', en: 'Validates the token with jwt.verify(), not just decode' },
            hint: { th: 'เปลี่ยนมาใช้ jwt.verify(token, SECRET, {... }) ที่ตรวจ signature จริง', en: 'Switch to jwt.verify(token, SECRET, { ... }), which actually checks the signature.' },
            weight: 3,
            mustMatch: /jwt\.verify\s*\(|\.verify\s*\(\s*token/
          },
          {
            id: 'no-decode-for-authz',
            label: { th: 'ไม่ใช้ jwt.decode() ในการ ตัดสิน authorization', en: 'Does not use jwt.decode() for authorization' },
            hint: { th: 'ลบ jwt.decode(token) ออก เพราะมันไม่ตรวจ signature เลย', en: 'Remove jwt.decode(token) — it verifies nothing.' },
            weight: 2,
            mustNotMatch: /jwt\.decode\s*\(/
          },
          {
            id: 'pin-algorithm',
            label: { th: 'ล็อก algorithm ด้วย allowlist (algorithms: [...])', en: 'Pins the algorithm with an allowlist (algorithms: [...])' },
            hint: { th: 'ส่งออปชัน algorithms: [\'HS256\'] เข้าไปใน jwt.verify เพื่อไม่ให้ header เลือกอัลกอริทึมเอง', en: 'Pass the algorithms: [\'HS256\'] option to jwt.verify so the header cannot pick the algorithm.' },
            weight: 2,
            mustMatch: /algorithms\s*:\s*\[/
          },
          {
            id: 'validate-claims',
            label: { th: 'ตรวจ claims มาตรฐาน (iss / aud; exp ตรวจโดยค่าเริ่มต้น)', en: 'Validates standard claims (iss / aud; exp checked by default)' },
            hint: { th: 'เพิ่ม issuer: \'acme-auth\' และ audience: \'acme-api\' ในออปชันของ jwt.verify', en: 'Add issuer: \'acme-auth\' and audience: \'acme-api\' to the jwt.verify options.' },
            weight: 1,
            mustMatch: /issuer\s*:|audience\s*:/
          }
        ],
        traps: [
          {
            id: 'decode-left-in',
            match: /jwt\.decode\s*\(/,
            message: {
              th: 'ยังเรียก jwt.decode() อยู่ ฟังก์ชันนี้แค่ base64-decode payload โดยไม่ตรวจ signature ค่าที่ได้จึงปลอมได้ทั้งหมด ต้องใช้ jwt.verify(token, SECRET, { algorithms: [\'HS256\'], issuer, audience }) เท่านั้นในการ ตัดสิน authorization',
              en: 'jwt.decode() is still here. It only base64-decodes the payload and checks no signature, so its values are fully forgeable. Use jwt.verify(token, SECRET, { algorithms: [\'HS256\'], issuer, audience }) for any authorization decision.'
            }
          },
          {
            id: 'alg-none-or-empty',
            match: /algorithms\s*:\s*\[\s*\]|["']none["']/i,
            message: {
              th: 'พบ alg:none หรือ allowlist ว่าง ซึ่งเปิดให้ token ที่ไม่มี signature ผ่านได้ (CVE-2015-9235) ต้องระบุอัลกอริทึมที่ยอมรับให้ชัด เช่น algorithms: [\'HS256\'] และห้ามมี none',
              en: 'This allows alg:none or an empty allowlist, letting unsigned tokens through (CVE-2015-9235). Specify the accepted algorithm explicitly, e.g. algorithms: [\'HS256\'], and never include none.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'payload ของ JWT ไม่ได้ถูกเข้ารหัส ใครก็อ่านและแก้ได้ ถามตัวเองว่า "อะไรพิสูจน์ว่า token นี้ออกโดย server ของเราจริง" คำตอบคือ signature ซึ่งโค้ดตอนนี้ไม่เคยตรวจ',
        en: 'A JWT payload is not encrypted — anyone can read and edit it. Ask what proves the token really came from your server. The answer is the signature, which this code never checks.'
      },
      {
        th: 'ต้อง verify signature ก่อนอ่าน claims และต้อง "ล็อก" algorithm ไว้ที่ฝั่ง server ไม่ให้ header ของ token เป็นคนเลือก (ถ้าไม่ทำพบ alg confusion / alg:none) แล้วยังต้องตรวจ exp, iss, aud ต่อ',
        en: 'Verify the signature before reading claims, and pin the algorithm on the server so the token\'s header cannot choose it (otherwise you meet algorithm confusion / alg:none). Then still validate exp, iss and aud.'
      },
      {
        th: 'Java: Jwts.parser().verifyWith(key).requireIssuer("acme-auth").requireAudience("acme-api").build().parseSignedClaims(token) — Node: jwt.verify(token, SECRET, { algorithms: [\'HS256\'], issuer: \'acme-auth\', audience: \'acme-api\' }) และเลิกใช้ jwt.decode()',
        en: 'Java: Jwts.parser().verifyWith(key).requireIssuer("acme-auth").requireAudience("acme-api").build().parseSignedClaims(token). Node: jwt.verify(token, SECRET, { algorithms: [\'HS256\'], issuer: \'acme-auth\', audience: \'acme-api\' }) — and stop using jwt.decode().'
      }
    ],

    quiz: [
      {
        q: {
          th: 'บริการคาดว่าจะได้ token เซ็นด้วย RS256 attacker ส่ง token ที่ header เป็น alg:HS256 โดยเซ็นด้วย RSA public key ของ server (ซึ่งเปิดเผย) เป็น HMAC secret และโค้ด verify ไม่ได้ล็อก algorithm จะเกิดอะไรขึ้น',
          en: 'A service expects RS256 tokens. An attacker sends a token with header alg:HS256, signed using the server\'s public RSA key (which is published) as the HMAC secret, and the verify call does not pin the algorithm. What happens?'
        },
        choices: [
          { th: 'ไม่มีอะไรเกิดขึ้น เพราะ public key สร้าง signature ที่ถูกต้องไม่ได้', en: 'Nothing — a public key cannot create a valid signature' },
          { th: 'token ถูกยอมรับ เพราะ verify() อ่านอัลกอริทึมจาก header ที่ attacker คุม แล้วเอา public key ไป HMAC-verify ซึ่ง attacker ก็ถือ public key อยู่แล้วเช่นกัน', en: 'The token is accepted, because verify() reads the algorithm from the attacker-controlled header and HMAC-verifies with the public key, which the attacker also holds' },
          { th: 'ไม่มีอะไรเกิดขึ้น เพราะ token แบบ HS256 กับ RS256 มีโครงสร้างที่เข้ากันไม่ได้', en: 'Nothing — HS256 and RS256 tokens are structurally incompatible' },
          { th: 'token ถูกปฏิเสธ เพราะไม่มี claim exp', en: 'The token is rejected because it has no exp claim' }
        ],
        answer: 1,
        why: {
          th: 'นี่คือ algorithm confusion: เมื่อ verify เชื่อ alg จาก header ระบบที่ตั้งใจใช้ RSA (ตรวจด้วย public key) จะถูกหลอกให้ทำ HMAC โดยใช้ public key เป็น secret ซึ่ง attacker ก็มี public key เหมือนกัน จึงเซ็น token ที่ผ่าน verify ได้ ทางแก้คือล็อก algorithms ไว้ฝั่ง server',
          en: 'This is algorithm confusion: when verify trusts the header\'s alg, a system meant to use RSA (verified with the public key) is tricked into doing HMAC with that public key as the secret — and the attacker has the public key too, so they can sign a token that verifies. The fix is to pin algorithms on the server.'
        },
        whyWrong: [
          { th: 'ถูกที่ public key เซ็นแบบ RSA ไม่ได้ แต่ที่นี่ attacker ไม่ได้เซ็นแบบ RSA เขาเซ็นแบบ HMAC (สมมาตร) โดยใช้ public key เป็น secret ซึ่งทำได้เพราะ public key เป็นข้อมูลที่รู้กันทั้งคู่', en: 'True that a public key cannot produce an RSA signature — but the attacker is not signing with RSA; they sign with HMAC (symmetric) using the public key as the secret, which works because that key is known to both.' },
          null,
          { th: 'ทั้ง HS256 และ RS256 ใช้รูปแบบ header.payload.signature เหมือนกันทุกประการ ความต่างอยู่ที่วิธีคำนวณ signature เท่านั้น จึงไม่ได้ "เข้ากันไม่ได้" ตามโครงสร้าง', en: 'Both HS256 and RS256 use the identical header.payload.signature format; only the signature computation differs, so they are not structurally incompatible.' },
          { th: 'ปัญหาไม่ได้อยู่ที่ claim exp การไม่มี exp เป็นคนละประเด็น สิ่งที่ทำให้ token ผ่านคือการที่ verify ไม่ได้ล็อก algorithm', en: 'The issue is not the exp claim; a missing exp is a separate matter. What lets the token through is that verify did not pin the algorithm.' }
        ]
      },
      {
        q: {
          th: 'jwt.decode(token) รับประกันอะไรเกี่ยวกับ claims ที่คืนกลับมา',
          en: 'What does jwt.decode(token) guarantee about the claims it returns?'
        },
        choices: [
          { th: 'รับประกันว่า token ถูกเซ็นโดย server ของเราและยังไม่หมดอายุ', en: 'That the token was signed by our server and is not expired' },
          { th: 'ไม่รับประกันความถูกต้องใด ๆ decode แค่ base64url-decode payload ใครก็ปลอม token ได้ เลยห้ามเชื่อ claims จาก decode() ในการตัดสิน authorization', en: 'Nothing about authenticity — decode only base64url-decodes the payload; anyone can forge a token, so claims from decode() must never be trusted for authorization' },
          { th: 'รับประกันว่า signature ถูกต้อง แต่ไม่รับประกันว่ายังไม่หมดอายุ', en: 'That the signature is valid, but not that the token is unexpired' },
          { th: 'รับประกันว่า iss และ aud ตรงกับที่เราตั้งค่าไว้', en: 'That the issuer and audience match our configuration' }
        ],
        answer: 1,
        why: {
          th: 'decode() ทำหน้าที่เดียวคือแยก token แล้ว base64url-decode ส่วน payload ออกมาเป็น object ไม่มีการตรวจ signature, exp, iss หรือ aud เลย ค่าที่ได้จึงเป็นเพียง "สิ่งที่ผู้ส่งอ้าง" ซึ่ง attacker กำหนดเองได้ทั้งหมด ต้องใช้ verify() เสมอเมื่อจะตัดสินใจด้านความปลอดภัย',
          en: 'decode() does one thing: split the token and base64url-decode the payload into an object. It checks no signature, no exp, no iss, no aud, so its output is merely "what the sender claims", fully attacker-controlled. Always use verify() for any security decision.'
        },
        whyWrong: [
          { th: 'decode() ไม่แตะ signature และไม่ดู exp เลย การรับประกันเรื่องผู้เซ็นและวันหมดอายุเป็นงานของ verify()', en: 'decode() never touches the signature or exp; guaranteeing the signer and expiry is the job of verify().' },
          null,
          { th: 'decode() ไม่ตรวจ signature แม้แต่น้อย จึงไม่รับประกันแม้แต่ว่า signature ถูกต้อง', en: 'decode() performs no signature check at all, so it does not even guarantee the signature is valid.' },
          { th: 'การตรวจ iss/aud เกิดใน verify() เมื่อส่งออปชัน issuer/audience เท่านั้น decode() ไม่เกี่ยวข้องกับ claims เหล่านี้', en: 'iss/aud checking happens in verify() when you pass the issuer/audience options; decode() has nothing to do with those claims.' }
        ]
      }
    ],

    sim: {
      kind: 'jwt',
      config: {
        secret: 'server-side-secret-do-not-share',
        header: { alg: 'HS256', typ: 'JWT' },
        claims: { sub: '1001', role: 'user', exp: 1893456000 }
      },
      payloads: [
        { label: { th: 'แก้ role ใน token เป็น admin แล้วส่งกลับเข้ามา', en: 'Escalate to admin — flip role to admin (the classic)' }, value: '{"sub":"1001","role":"admin","exp":1893456000}' },
        { label: { th: 'สวมรอยผู้ใช้อื่น — เปลี่ยน sub เป็น 1002', en: 'Impersonate another user — change sub to 1002' }, value: '{"sub":"1002","role":"user","exp":1893456000}' },
        { label: { th: 'admin + ยืดวันหมดอายุถึงปี 9999', en: 'admin + expiry stretched to year 9999' }, value: '{"sub":"1001","role":"admin","exp":253402300799}' }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP JSON Web Token for Java Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html' },
      { label: 'IETF RFC 8725 — JSON Web Token Best Current Practices', url: 'https://www.rfc-editor.org/rfc/rfc8725' },
      { label: 'CWE-347: Improper Verification of Cryptographic Signature', url: 'https://cwe.mitre.org/data/definitions/347.html' }
    ]
  };

  const WORKSHOP = {
    id: 'w3',
    order: 3,
    title: {
      th: 'Workshop 3: Authentication & Access Control',
      en: 'Workshop 3: Authentication & Access Control'
    },
    summary: {
      th: 'Workshop นี้ครอบคลุมจุดที่ระบบต้องตอบให้ถูกว่า "ผู้ใช้คือใคร" และ "มีสิทธิ์ทำอะไร" ตั้งแต่การเก็บ password, authorization ระดับข้อมูล, การตรวจ JWT, session cookie ไปจนถึงการรับ field จาก request body',
      en: 'The bugs that appear when a system answers "who are you?" and "are you allowed to do this?" — password storage, object-level authorization, JWT verification, session cookie flags, and binding request bodies onto entities.'
    },
    goal: {
      th: 'จบ workshop นี้ คุณจะเก็บ password ด้วย KDF ที่ปรับ cost ได้, ตรวจสิทธิ์ระดับ object ทุกครั้ง, verify JWT พร้อมล็อก algorithm และตรวจ iss/aud/exp, ตั้ง session cookie ให้ปลอดภัย และรับ field จาก request ด้วย allowlist',
      en: 'By the end of this workshop you will store passwords with a cost-tunable KDF, check ownership on every id-addressed resource, verify JWTs with a pinned algorithm and validated iss/aud/exp, set every session cookie flag correctly, and bind request data through an allowlist instead of accepting the whole body.'
    },
    exercises: [
      EX_WEAK_HASHING,
      EX_IDOR,
      EX_JWT_FORGERY
    ]
  };

  global.SCW = global.SCW || { workshops: [], registerWorkshop: function (w) { this.workshops.push(w); } };
  global.SCW.registerWorkshop(WORKSHOP);
  if (typeof module !== 'undefined' && module.exports) module.exports = WORKSHOP;
})(typeof window !== 'undefined' ? window : globalThis);
