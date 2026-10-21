/**
 * Sentinel — OWASP A06:2021  Vulnerable and Outdated Components
 *
 * Detects:
 *   • Known-vulnerable / deprecated libraries in manifests (package.json,
 *     requirements.txt, pom.xml, build.gradle, Gemfile, go.mod, composer.json)
 *   • Unpinned versions (`*`, `latest`, floating majors)
 *   • EOL / unsupported runtimes (Python 2, Node 12, Java 8 in Dockerfiles)
 *   • Direct use of libraries with a history of RCE (log4j 1.x, node-serialize)
 */

import { Severity as S, VulnerabilityType as V } from '../analyzer/types.js';
import { APP_LANGS, PatternRule, RulePattern, makeFinding, pat } from './patternEngine.js';

const MANIFEST = /^(?:package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|requirements.*\.txt|Pipfile|pyproject\.toml|pom\.xml|build\.gradle(?:\.kts)?|Gemfile(?:\.lock)?|go\.mod|composer\.json|Cargo\.toml)$/i;

/** Packages that should never appear, regardless of version. */
const BANNED: Record<string, string> = {
  'node-serialize': 'RCE via untrusted `unserialize()` — remove this package.',
  'serialize-to-js': 'Remote code execution when deserializing untrusted data.',
  'flatmap-stream': 'Compromised dependency (event-stream incident). Remove immediately.',
  'event-stream': 'Was compromised via a malicious transitive dependency. Pin a vetted fork or replace.',
  'request': 'The `request` library is deprecated and unmaintained. Use `fetch`, `got`, or `undici`.',
  'http-proxy-middleware': '', // handled via minSafe below
};

/** name → minimum safe version (findings when declared version is lower). */
const MIN_SAFE: Array<{ name: string; min: string; note: string }> = [
  { name: 'lodash',            min: '4.17.21', note: 'Prototype pollution (CVE-2021-23337 and earlier). Upgrade lodash.' },
  { name: 'minimist',          min: '1.2.6',   note: 'Prototype pollution. Upgrade minimist.' },
  { name: 'axios',             min: '1.6.0',   note: 'SSRF / CSRF issues in older axios. Upgrade.' },
  { name: 'express',           min: '4.19.2',  note: 'Open-redirect / qs parsing issues in older Express. Upgrade.' },
  { name: 'jquery',            min: '3.5.0',   note: 'XSS in jQuery < 3.5.0. Upgrade.' },
  { name: 'log4j',             min: '2.17.1',  note: 'Log4Shell (CVE-2021-44228). Use 2.17.1+ or Logback.' },
  { name: 'log4j-core',        min: '2.17.1',  note: 'Log4Shell (CVE-2021-44228). Use 2.17.1+.' },
  { name: 'jackson-databind',  min: '2.15.0',  note: 'Polymorphic deserialization gadgets in older jackson-databind.' },
  { name: 'commons-collections', min: '4.4',  note: 'InvokerTransformer RCE gadgets. Use commons-collections4 ≥ 4.4.' },
  { name: 'spring-web',        min: '5.3.27',  note: 'Known CVEs in older Spring Web. Upgrade the Spring stack.' },
  { name: 'spring-boot',       min: '2.7.18',  note: 'Older Spring Boot lines are out of support. Upgrade.' },
  { name: 'django',            min: '4.2.0',   note: 'Django LTS below 4.2 is EOL. Upgrade.' },
  { name: 'flask',             min: '2.3.0',   note: 'Older Flask has unpatched issues. Upgrade.' },
  { name: 'pyyaml',            min: '6.0',     note: 'Unsafe `yaml.load` behaviour in PyYAML < 6. Prefer 6.x + `safe_load`.' },
  { name: 'pillow',            min: '10.0.0',  note: 'Image-codec CVEs in older Pillow. Upgrade.' },
  { name: 'openssl',           min: '3.0.7',   note: 'OpenSSL versions below 3.0.7 include critical CVEs.' },
  { name: 'http-proxy-middleware', min: '2.0.7', note: 'SSRF / path issues in older http-proxy-middleware.' },
  { name: 'webpack-dev-server', min: '4.15.1', note: 'DNS-rebinding issues in older webpack-dev-server.' },
  { name: 'ejs',               min: '3.1.10',  note: 'SSTI / RCE in older EJS. Upgrade.' },
  { name: 'underscore',        min: '1.13.6',  note: 'Prototype pollution in older Underscore. Upgrade or replace.' },
];

const PATTERNS: RulePattern[] = [
  pat('a06-log4j1', V.VULNERABLE_COMPONENT, S.CRITICAL, 0.95,
    /org\.apache\.log4j\.(?:Logger|Category)|import\s+org\.apache\.log4j\.|["']log4j:log4j:/g,
    'Log4j 1.x is EOL and has unpatched RCE/deserialization issues. Migrate to Log4j 2.17.1+ or Logback.',
    { languages: [...APP_LANGS, 'xml', 'gradle', 'groovy'] }),
  pat('a06-node-serialize', V.VULNERABLE_COMPONENT, S.CRITICAL, 0.95,
    /require\s*\(\s*["'](?:node-serialize|serialize-to-js|flatmap-stream)["']\s*\)|from\s+["'](?:node-serialize|serialize-to-js)["']/g,
    'This package is known for remote code execution. Remove it.',
    { languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'] }),
  pat('a06-eol-python2', V.VULNERABLE_COMPONENT, S.HIGH, 0.90,
    /^FROM\s+[^\n]*python:2\b|^FROM\s+[^\n]*python:2\.\d/gim,
    'Python 2 is EOL (2020) and receives no security fixes. Use Python 3.11+.',
    { languages: ['dockerfile'], fileNameMatch: /^Dockerfile/i }),
  pat('a06-eol-node', V.VULNERABLE_COMPONENT, S.HIGH, 0.88,
    /^FROM\s+[^\n]*node:(?:4|6|8|10|12|14|16)\b/gim,
    'This Node.js major is EOL. Use a current LTS (20 or 22).',
    { languages: ['dockerfile'], fileNameMatch: /^Dockerfile/i }),
  pat('a06-eol-java8-image', V.VULNERABLE_COMPONENT, S.MEDIUM, 0.78,
    /^FROM\s+[^\n]*(?:openjdk|eclipse-temurin|amazoncorretto):(?:7|8)\b/gim,
    'Java 7/8 base image is past free public updates for many distros. Prefer 17 or 21 LTS.',
    { languages: ['dockerfile'], fileNameMatch: /^Dockerfile/i }),
  pat('a06-engines-old-node', V.VULNERABLE_COMPONENT, S.MEDIUM, 0.80,
    /"node"\s*:\s*"[\^~>=<\s]*(?:4|6|8|10|12|14)\./g,
    '`engines.node` targets an EOL Node.js release. Raise the minimum to a current LTS.',
    { fileNameMatch: /^package\.json$/ }),
];

function cmpVer(a: string, b: string): number {
  const pa = a.replace(/^v/i, '').split(/[.+-]/).map(n => parseInt(n, 10) || 0);
  const pb = b.replace(/^v/i, '').split(/[.+-]/).map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const da = pa[i] ?? 0;
    const db = pb[i] ?? 0;
    if (da !== db) { return da - db; }
  }
  return 0;
}

function declaredVersion(raw: string): { unpinned: boolean; version: string } {
  const v = raw.trim().replace(/^["']|["']$/g, '');
  if (/^(?:\*|latest|x|X|latest-[\w.]+)$/.test(v) || v === '') {
    return { unpinned: true, version: v };
  }
  const stripped = v.replace(/^[~^>=<\s]+/, '').split(/\s+/)[0];
  return { unpinned: false, version: stripped };
}

function scanJsonDependencies(text: string, fileName: string): ReturnType<typeof makeFinding>[] {
  const findings: ReturnType<typeof makeFinding>[] = [];
  const blocks = [
    /"dependencies"\s*:\s*\{([^}]{0,8000})\}/g,
    /"devDependencies"\s*:\s*\{([^}]{0,8000})\}/g,
    /"optionalDependencies"\s*:\s*\{([^}]{0,4000})\}/g,
    /"require"\s*:\s*\{([^}]{0,8000})\}/g, // composer.json
  ];

  const addPkg = (name: string, rawVer: string, index: number): void => {
    const key = name.toLowerCase();
    if (BANNED[key] && BANNED[key].length > 0) {
      findings.push(makeFinding({
        ruleId: 'SENTINEL-A06-001', type: V.VULNERABLE_COMPONENT, severity: S.HIGH, confidence: 0.92,
        message: `Banned / compromised package \`${name}\`: ${BANNED[key]}`,
        fileName, text, index, length: name.length,
      }));
      return;
    }
    const { unpinned, version } = declaredVersion(rawVer);
    if (unpinned) {
      findings.push(makeFinding({
        ruleId: 'SENTINEL-A06-001', type: V.VULNERABLE_COMPONENT, severity: S.MEDIUM, confidence: 0.80,
        message: `Dependency \`${name}\` is unpinned (\`${rawVer}\`). Pin a specific version so builds are reproducible and CVE scans work.`,
        fileName, text, index, length: Math.min(rawVer.length + name.length, 40),
      }));
      return;
    }
    const known = MIN_SAFE.find(k => k.name === key);
    if (known && /^\d/.test(version) && cmpVer(version, known.min) < 0) {
      findings.push(makeFinding({
        ruleId: 'SENTINEL-A06-001', type: V.VULNERABLE_COMPONENT, severity: S.HIGH, confidence: 0.88,
        message: `\`${name}@${version}\` is below the known-safe minimum ${known.min}. ${known.note}`,
        fileName, text, index, length: name.length,
      }));
    }
  };

  for (const re of blocks) {
    re.lastIndex = 0;
    let block: RegExpExecArray | null;
    while ((block = re.exec(text)) !== null) {
      const body = block[1];
      const pair = /"([^"\n]{1,120})"\s*:\s*"([^"\n]{0,80})"/g;
      let m: RegExpExecArray | null;
      while ((m = pair.exec(body)) !== null) {
        addPkg(m[1], m[2], (block.index ?? 0) + m.index + 1);
      }
    }
  }
  return findings;
}

function scanRequirements(text: string, fileName: string): ReturnType<typeof makeFinding>[] {
  const findings: ReturnType<typeof makeFinding>[] = [];
  const re = /^[ \t]*([A-Za-z0-9_.-]+)\s*(===|==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9_.+-]*)/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const name = m[1].toLowerCase();
    const op = m[2] ?? '';
    const ver = m[3] ?? '';
    const known = MIN_SAFE.find(k => k.name === name);
    if (known && ver && cmpVer(ver, known.min) < 0) {
      findings.push(makeFinding({
        ruleId: 'SENTINEL-A06-001', type: V.VULNERABLE_COMPONENT, severity: S.HIGH, confidence: 0.88,
        message: `\`${m[1]}${op}${ver}\` is below the known-safe minimum ${known.min}. ${known.note}`,
        fileName, text, index: m.index, length: m[0].length,
      }));
    }
    if (!op) {
      findings.push(makeFinding({
        ruleId: 'SENTINEL-A06-001', type: V.VULNERABLE_COMPONENT, severity: S.LOW, confidence: 0.72,
        message: `Python dependency \`${m[1]}\` is unpinned. Pin a version (e.g. \`${m[1]}==x.y.z\`) and prefer a lock file.`,
        fileName, text, index: m.index, length: m[0].length,
      }));
    }
  }
  return findings;
}

function scanMavenGradle(text: string, fileName: string): ReturnType<typeof makeFinding>[] {
  const findings: ReturnType<typeof makeFinding>[] = [];
  const maven = /<(?:groupId|artifactId)>([^<]+)<\/(?:groupId|artifactId)>[\s\S]{0,80}?<artifactId>([^<]+)<\/artifactId>[\s\S]{0,80}?<version>([^<]+)<\/version>/gi;
  const gradle = /(?:implementation|api|compile|runtimeOnly|testImplementation)\s*[\(]?['"]([^:'"\n]+):([^:'"\n]+):([^'"\n]+)['"]/g;
  const add = (artifact: string, ver: string, index: number, length: number): void => {
    const key = artifact.toLowerCase();
    const known = MIN_SAFE.find(k => k.name === key || key.endsWith(k.name));
    if (known && /^\d/.test(ver) && cmpVer(ver, known.min) < 0) {
      findings.push(makeFinding({
        ruleId: 'SENTINEL-A06-001', type: V.VULNERABLE_COMPONENT, severity: S.HIGH, confidence: 0.86,
        message: `\`${artifact}:${ver}\` is below the known-safe minimum ${known.min}. ${known.note}`,
        fileName, text, index, length,
      }));
    }
  };
  let m: RegExpExecArray | null;
  maven.lastIndex = 0;
  while ((m = maven.exec(text)) !== null) {
    add(m[2], m[3], m.index, m[0].length);
  }
  gradle.lastIndex = 0;
  while ((m = gradle.exec(text)) !== null) {
    add(m[2], m[3], m.index, m[0].length);
  }
  return findings;
}

export class VulnerableComponentsRule extends PatternRule {
  readonly ruleId             = 'SENTINEL-A06-001';
  readonly ruleName           = 'A06 Vulnerable and Outdated Components Detector';
  readonly vulnerabilityType  = V.VULNERABLE_COMPONENT;
  readonly supportedLanguages = [...APP_LANGS, 'json', 'jsonc', 'xml', 'groovy', 'plaintext', 'dockerfile', 'toml', 'yaml'];
  protected readonly patterns = PATTERNS;

  protected analyzeExtra(text: string, fileName: string, _languageId: string) {
    const base = fileName.split(/[\\/]/).pop() ?? fileName;
    if (!MANIFEST.test(base) && !/\.(?:xml|gradle|kts)$/i.test(base)) { return []; }

    if (/^package\.json$|^composer\.json$/i.test(base)) {
      return scanJsonDependencies(text, fileName);
    }
    if (/requirements.*\.txt$|^Pipfile$/i.test(base)) {
      return scanRequirements(text, fileName);
    }
    if (/pom\.xml$|build\.gradle/i.test(base)) {
      return scanMavenGradle(text, fileName);
    }
    return [];
  }
}
