/**
 * Sentinel — OWASP A08:2021  Software and Data Integrity Failures
 *
 * Detects:
 *   • Insecure deserialization (pickle, yaml.load, ObjectInputStream,
 *     BinaryFormatter, PHP unserialize, node-serialize, JSON.parse + eval)
 *   • Unsigned / unverified auto-update and plugin loading
 *   • Remote script / package install piped to a shell (`curl | sh`)
 *   • CDN / <script> tags without Subresource Integrity
 *   • npm/yarn scripts or GitHub Actions that run untrusted code
 *   • Integrity checks skipped (checksums, SSL, signature verify)
 */

import { Severity as S, VulnerabilityType as V } from '../analyzer/types.js';
import { APP_LANGS, LANGS, PatternRule, RulePattern, TaintSink, pat, sink } from './patternEngine.js';

const PICKLE_SAFE = /hmac\.compare_digest|itsdangerous|RestrictedUnpickler|find_class\s*\(/i;

const PATTERNS: RulePattern[] = [
  // ── Insecure deserialization ──────────────────────────────────────────────
  pat('a08-pickle', V.UNSAFE_DESERIALIZATION, S.CRITICAL, 0.95,
    /\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|\bjoblib\.load\s*\(|\bshelve\.open\s*\(/g,
    '`pickle.load(s)` executes arbitrary bytecode from the stream — never unpickle untrusted data. Use JSON or a signed serializer.',
    { safeIfContext: PICKLE_SAFE, languages: ['python'] }),
  pat('a08-yaml-unsafe', V.UNSAFE_DESERIALIZATION, S.HIGH, 0.92,
    /\byaml\.load\s*\(\s*(?!.*Loader\s*=\s*yaml\.SafeLoader)/g,
    '`yaml.load()` without `SafeLoader` can construct arbitrary Python objects (RCE). Use `yaml.safe_load()`.',
    { languages: ['python'], safeIfLine: /SafeLoader|safe_load|CSafeLoader/ }),
  pat('a08-marshal', V.UNSAFE_DESERIALIZATION, S.HIGH, 0.90,
    /\bmarshal\.loads?\s*\(/g,
    '`marshal.load` is not a security boundary. Do not deserialize untrusted bytes.',
    { languages: ['python'] }),
  pat('a08-java-ois', V.UNSAFE_DESERIALIZATION, S.HIGH, 0.88,
    /\bnew\s+ObjectInputStream\s*\(|\breadObject\s*\(\s*\)/g,
    '`ObjectInputStream.readObject()` can instantiate gadget chains (RCE). Avoid Java serialization or use an allow-list filter (`ObjectInputFilter`).',
    { languages: [...LANGS.JAVA], safeIfContext: /ObjectInputFilter|ValidatingObjectInputStream|enableLookAheadDeserializationFilter/ }),
  pat('a08-java-enable-typing', V.UNSAFE_DESERIALIZATION, S.CRITICAL, 0.95,
    /\benableDefaultTyping\s*\(|\bactivateDefaultTyping\s*\(|@JsonTypeInfo\s*\([^)]*use\s*=\s*JsonTypeInfo\.Id\.CLASS/g,
    'Jackson default typing / `@JsonTypeInfo(Id.CLASS)` lets attackers pick the deserialized class (RCE gadgets).',
    { languages: [...LANGS.JAVA] }),
  pat('a08-csharp-binaryformatter', V.UNSAFE_DESERIALIZATION, S.CRITICAL, 0.95,
    /\bnew\s+BinaryFormatter\s*\(|\bBinaryFormatter\s*\(\s*\)\s*\.\s*Deserialize|LosFormatter\s*\(\s*\)|NetDataContractSerializer|SoapFormatter/g,
    '`BinaryFormatter` and related serializers are unsafe and obsolete. Use `System.Text.Json` or `DataContractSerializer` with known types.',
    { languages: ['csharp'] }),
  pat('a08-php-unserialize', V.UNSAFE_DESERIALIZATION, S.HIGH, 0.90,
    /\bunserialize\s*\(\s*\$(?:_(?:GET|POST|REQUEST|COOKIE)|[A-Za-z_]\w*)/g,
    'PHP `unserialize()` on user data enables object-injection gadgets. Use `json_decode` or allowed_classes = false.',
    { languages: ['php'], safeIfLine: /allowed_classes\s*=>\s*(?:false|FALSE)/ }),
  pat('a08-node-serialize', V.UNSAFE_DESERIALIZATION, S.CRITICAL, 0.95,
    /\b(?:serialize|unserialize)\s*\(\s*(?:req|request)\.(?:body|query)|node-serialize|serialize-to-js/g,
    'JavaScript serialize/unserialize of request data can evaluate functions (RCE). Use JSON.parse on trusted shapes.',
    { languages: [...LANGS.JS] }),
  pat('a08-eval-json', V.UNSAFE_DESERIALIZATION, S.HIGH, 0.88,
    /\beval\s*\(\s*(?:JSON\.stringify|["']\s*\+\s*)|\beval\s*\(\s*(?:req|request|data|body|payload|input)/g,
    '`eval` on data that looks like JSON — use `JSON.parse`.',
    { languages: [...LANGS.JS] }),

  // ── Supply chain / install-from-internet ──────────────────────────────────
  pat('a08-curl-pipe-sh', V.SOFTWARE_INTEGRITY_FAILURE, S.HIGH, 0.92,
    /\b(?:curl|wget)\b[^\n]{0,120}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python|python3|perl)\b/g,
    'Remote script piped into a shell — the payload is never integrity-checked. Download, verify a checksum/signature, then run.',
    { languages: ['shellscript', 'dockerfile', 'makefile', 'plaintext', 'yaml'] }),
  pat('a08-npm-install-remote', V.SOFTWARE_INTEGRITY_FAILURE, S.MEDIUM, 0.78,
    /\bnpm\s+install\s+[^\n]*(?:https?:\/\/|git\+|github:)/g,
    'Package installed from a raw URL / git remote instead of the registry — pin a commit SHA and verify integrity.',
    { languages: ['shellscript', 'dockerfile', 'plaintext', 'json'] }),
  pat('a08-pip-untrusted', V.SOFTWARE_INTEGRITY_FAILURE, S.MEDIUM, 0.78,
    /\bpip(?:3)?\s+install\s+[^\n]*(?:--trusted-host|--index-url\s+http:\/\/)/g,
    'pip install from an HTTP / untrusted index. Use HTTPS PyPI and hash-checking mode (`--require-hashes`).',
    { languages: ['shellscript', 'dockerfile', 'makefile', 'plaintext'] }),
  pat('a08-auto-update-unsigned', V.SOFTWARE_INTEGRITY_FAILURE, S.HIGH, 0.82,
    /\b(?:auto(?:matic)?Update|checkForUpdates|updater)\b[^\n]{0,80}\b(?:verify|signature|checksum)\s*[:=]\s*(?:false|False|0)/gi,
    'Auto-update verification is disabled — a MITM can push malware. Require signed updates.'),
  pat('a08-plugin-require-var', V.SOFTWARE_INTEGRITY_FAILURE, S.HIGH, 0.85,
    /\brequire\s*\(\s*(?:req|request)\.(?:body|query|params)|import\(\s*(?:req|request)\.(?:body|query|params)/g,
    'Module path taken from the request — attackers can load arbitrary code. Allow-list plugin names.',
    { languages: [...LANGS.JS] }),

  // ── Missing SRI ───────────────────────────────────────────────────────────
  pat('a08-script-no-sri', V.SOFTWARE_INTEGRITY_FAILURE, S.MEDIUM, 0.78,
    /<script\b[^>]*\bsrc\s*=\s*["']https?:\/\/[^"']+["'][^>]*>/gi,
    'Third-party `<script>` without `integrity` (SRI) — a compromised CDN can run code on your origin. Add `integrity` and `crossorigin`.',
    {
      languages: [...LANGS.WEB, 'html', 'javascriptreact', 'typescriptreact'],
      validate: (m) => !/\bintegrity\s*=/.test(m[0]) && /cdn\.|unpkg|jsdelivr|cdnjs|googleapis|cloudflare|bootstrapcdn/i.test(m[0]),
    }),
  pat('a08-link-no-sri', V.SOFTWARE_INTEGRITY_FAILURE, S.LOW, 0.74,
    /<link\b[^>]*\brel\s*=\s*["']stylesheet["'][^>]*href\s*=\s*["']https?:\/\/[^"']+["'][^>]*>/gi,
    'Third-party stylesheet without SRI. Add `integrity` so a CDN compromise cannot restyle/exfiltrate via CSS.',
    {
      languages: [...LANGS.WEB, 'html'],
      validate: (m) => !/\bintegrity\s*=/.test(m[0]) && /cdn\.|unpkg|jsdelivr|cdnjs|googleapis|cloudflare|bootstrapcdn/i.test(m[0]),
    }),

  // ── Integrity skipped ─────────────────────────────────────────────────────
  pat('a08-checksum-skipped', V.SOFTWARE_INTEGRITY_FAILURE, S.MEDIUM, 0.80,
    /\b(?:skip|ignore|disable)[A-Z_]*(?:Checksum|Signature|Integrity|Verify)\w*\s*[=:]\s*(?:true|True|1)|CHECKSUM_VERIFY\s*=\s*(?:false|0)/gi,
    'Integrity / checksum verification is skipped. Do not ship this flag in production.'),
  pat('a08-gha-unpinned-action', V.SOFTWARE_INTEGRITY_FAILURE, S.MEDIUM, 0.80,
    /uses:\s*[^\s#]+@(?:main|master|latest|v\d+)\s*$/gm,
    'GitHub Action pinned to a moving tag (`v1`, `main`) — the tag can be force-pushed. Pin the full commit SHA.',
    { languages: ['yaml'], fileNameMatch: /\.ya?ml$/ }),
];

const SINKS: TaintSink[] = [
  sink('a08-taint-pickle', V.UNSAFE_DESERIALIZATION, S.CRITICAL, 0.92,
    /\bpickle\.loads?\s*\(\s*__TAINT__|\byaml\.load\s*\(\s*__TAINT__|\bunserialize\s*\(\s*__TAINT__/g,
    'User-controlled data is deserialized with an unsafe loader — this is typically remote code execution.',
    { safeIfContext: PICKLE_SAFE }),
  sink('a08-taint-ois', V.UNSAFE_DESERIALIZATION, S.HIGH, 0.88,
    /\bnew\s+ObjectInputStream\s*\([^\n)]{0,80}?__TAINT__|\breadObject\s*\(\s*__TAINT__/g,
    'User-controlled bytes reach `ObjectInputStream` — Java deserialization RCE risk.',
    { languages: [...LANGS.JAVA] }),
];

export class IntegrityFailuresRule extends PatternRule {
  readonly ruleId             = 'SENTINEL-A08-001';
  readonly ruleName           = 'A08 Software and Data Integrity Failures Detector';
  readonly vulnerabilityType  = V.SOFTWARE_INTEGRITY_FAILURE;
  readonly supportedLanguages = [...APP_LANGS, 'html', 'yaml', 'shellscript', 'dockerfile', 'makefile', 'plaintext'];
  protected readonly patterns = PATTERNS;
  protected readonly taintSinks = SINKS;
}
