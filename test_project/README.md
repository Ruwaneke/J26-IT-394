# 🛡️ Sentinel — OWASP Top 10 Test Project

This is a sample project designed to test and demonstrate all vulnerability tracking rules implemented in **Sentinel**. It contains realistic code patterns across all **OWASP Top 10 (2021)** security categories.

---

## 📋 OWASP Top 10 Coverage & File Mapping

| OWASP Category | Vulnerability Type | File Location | Line / Pattern Description |
| :--- | :--- | :--- | :--- |
| **A01: Broken Access Control** | `PATH_TRAVERSAL`<br>`BROKEN_ACCESS_CONTROL` | `src/routes/fileRoutes.js`<br>`src/app.js` | • `fs.readFileSync(path.join('/var/uploads', req.query.file))` (Path Traversal)<br>• `res.redirect(req.query.returnUrl)` (Open Redirect)<br>• `cors({ origin: '*' })` (Permissive CORS) |
| **A02: Cryptographic Failures** | `WEAK_CRYPTOGRAPHY` | `src/utils/cryptoHelper.js` | • `crypto.createHash('md5')` for password storage<br>• `crypto.createCipheriv('des-ecb', key, '')` (Broken DES cipher)<br>• `Math.random().toString(36)` (Predictable reset token) |
| **A03: Injection** | `SQL_INJECTION`<br>`COMMAND_INJECTION`<br>`XSS` | `src/routes/userRoutes.js`<br>`src/routes/apiRoutes.js`<br>`src/routes/uiRoutes.js` | • `"SELECT * FROM users WHERE email = '" + req.body.email + "'"` (Concatenation SQLi)<br>• `` `SELECT * FROM accounts WHERE id = ${req.params.id}` `` (Template literal SQLi)<br>• `exec("ping -c 4 " + host)` (OS Command Injection)<br>• `innerHTML = bio;` and `document.write(...)` (DOM XSS) |
| **A04: Insecure Design** | `INSECURE_DESIGN` | `src/routes/fileRoutes.js`<br>`src/app.js` | • `const skip_auth = true;` (Backdoor/bypass flag)<br>• `multer({ dest: 'uploads/' })` (Unrestricted file upload with no size/MIME filters) |
| **A05: Security Misconfiguration** | `SECURITY_MISCONFIGURATION` | `src/app.js`<br>`src/routes/uiRoutes.js` | • `res.status(500).send(err.stack)` (Internal stack trace leak)<br>• `res.cookie('authToken', token, { httpOnly: false, secure: false })` (Missing security flags) |
| **A06: Vulnerable Components** | `VULNERABLE_COMPONENT` | `src/utils/dataParser.js`<br>`package.json` | • `require('node-serialize')` (Known RCE package)<br>• Outdated `"lodash": "4.17.15"` (Prototype pollution) in `package.json` |
| **A07: Identification & Auth Failures / Secrets** | `INSECURE_AUTH`<br>`HARDCODED_SECRET` | `src/routes/authRoutes.js`<br>`src/routes/userRoutes.js`<br>`src/routes/apiRoutes.js` | • `jwt.verify(token, secret, { algorithms: ['none'] })` (Algorithm none)<br>• `jwt.decode(token)` without signature verification<br>• Plaintext password comparison `user.password === req.body.password`<br>• Hardcoded secrets: `jwtSecret`, `dbPassword`, `apiKey` |
| **A08: Software & Data Integrity Failures** | `UNSAFE_DESERIALIZATION` | `src/utils/dataParser.js` | • `serialize.unserialize(rawPayload)` (Arbitrary code execution)<br>• `eval(expression)` (Dynamic code execution) |
| **A09: Logging & Monitoring Failures** | `INSUFFICIENT_LOGGING` | `src/routes/authRoutes.js`<br>`src/routes/userRoutes.js`<br>`src/app.js` | • `console.log("Login password: " + req.body.password)` (Password logged)<br>• Empty catch block `catch (err) {}` (Swallowed database errors)<br>• `console.log(req.body)` (Raw request body logged) |
| **A10: Server-Side Request Forgery (SSRF)** | `SSRF` | `src/routes/apiRoutes.js` | • `fetch(req.query.url)` (Direct SSRF fetching untrusted URL)<br>• `axios({ url: req.query.webhookUrl })` (SSRF via Axios options) |

---

## 🚀 How to Test All Rules

### Option 1: Automated Verification Suite (Command Line)
Run the automated test runner from inside the `test_project` directory:

```bash
cd test_project
node test-all-rules.js
```

This scans all files with Sentinel's `SecurityAnalyzer`, confirms 100% coverage across all 10 OWASP categories, and verifies that AI suggestions (root-cause, attack scenario, remediation, and secure code snippet) are generated.

### Option 2: Real-Time Interactive Testing in VS Code
1. Open any file in `test_project` inside VS Code (e.g., `src/routes/userRoutes.js`).
2. Sentinel immediately identifies the vulnerability as you open or type in the file.
3. **Hover over the wavy squiggly line** in the editor:
   - Read the **AI Root-Cause Explanation** ("Why it is vulnerable").
   - Read the **Attack Vector** scenario.
   - Inspect the **Secure Replacement Code** recommendation.
4. Open the Sentinel Dashboard by clicking **$(shield) Sentinel** in the status bar or editor title bar.
   - Switch to the **DB Vulnerability Tracker** tab to see all tracked records stored in Neon PostgreSQL with status `OPEN`.
5. **Real-Time Fix Testing**:
   - Manually replace the vulnerable line with the secure pattern recommended by the AI.
   - Sentinel automatically detects that the vulnerability is resolved without requiring any button click!
   - The status bar announces `✅ Sentinel: Fixed [VulnerabilityType]`.
   - The database status automatically transitions to `FIXED`.
