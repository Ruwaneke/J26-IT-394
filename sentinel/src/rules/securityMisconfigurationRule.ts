/**
 * Sentinel — OWASP A05:2021  Security Misconfiguration
 *
 * Detects insecure configuration in application code AND configuration files:
 *
 *   • Debug / developer modes left on (Django, Flask, Laravel, ASP.NET, Spring Boot)
 *   • Stack traces / internal errors returned to clients
 *   • XML External Entity (XXE) parsing enabled                        (CWE-611)
 *   • Cookies without HttpOnly / Secure, security headers disabled, CSP unsafe-*
 *   • Directory listing / static root exposure, world-writable permissions
 *   • Container hardening gaps (Dockerfile, docker-compose, Kubernetes)
 *   • Infrastructure-as-Code: open security groups, public buckets, wildcard IAM
 *   • Secrets committed in .properties / .ini / .cfg configuration files
 */

import { Severity as S, VulnerabilityType as V } from '../analyzer/types.js';
import { APP_LANGS, LANGS, PatternRule, RulePattern, pat } from './patternEngine.js';

const CONFIG_LANGS = ['yaml', 'json', 'jsonc', 'xml', 'properties', 'ini', 'toml', 'dockerfile', 'terraform', 'hcl', 'plaintext', 'shellscript', 'dotenv'];
const IAC_FILE     = /\.(?:tf|tfvars)$|(?:template|cloudformation|stack)[\w.-]*\.(?:ya?ml|json)$/i;
const XXE_SAFE     = /disallow-doctype-decl|FEATURE_SECURE_PROCESSING|external-general-entities|IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD|ACCESS_EXTERNAL_DTD|XMLConstants/;

const PATTERNS: RulePattern[] = [
  // ── Debug / developer modes ───────────────────────────────────────────────
  pat('a05-django-debug', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.88,
    /^[ \t]*DEBUG\s*=\s*True\b/gm,
    '`DEBUG = True` exposes stack traces, settings and SQL in production. Load it from the environment and default to False.',
    { languages: ['python'] }),
  pat('a05-flask-debug', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.93,
    /\bapp\.run\s*\([^\n)]*\bdebug\s*=\s*True|\bFLASK_DEBUG["']?\s*[=:]\s*["']?(?:1|true|True)|\bapp\.debug\s*=\s*True|\bapp\.config\[\s*["']DEBUG["']\s*\]\s*=\s*True/g,
    'Flask debug mode enabled — the Werkzeug debugger allows remote code execution. Never enable in production.',
    { languages: ['python', 'dockerfile', 'yaml', 'shellscript'] }),
  pat('a05-django-allowed-hosts', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.90,
    /\bALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]/g,
    '`ALLOWED_HOSTS = ["*"]` disables Host-header validation. List your real hostnames.',
    { languages: ['python'] }),
  pat('a05-django-security-flags', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.85,
    /\bSECURE_SSL_REDIRECT\s*=\s*False|\bSECURE_HSTS_SECONDS\s*=\s*0\b/g,
    'HTTPS redirect / HSTS disabled in Django security settings.',
    { languages: ['python'] }),
  pat('a05-php-display-errors', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.88,
    /\bini_set\s*\(\s*["']display_errors["']\s*,\s*["']?(?:1|On|true|stdout)["']?|^[ \t]*display_errors\s*=\s*(?:On|1|stdout)\b/gim,
    '`display_errors` is on — PHP errors (paths, queries) are shown to users. Log them instead.',
    { languages: ['php', 'ini', 'plaintext', 'properties'] }),
  pat('a05-php-url-include', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.92,
    /^[ \t]*allow_url_include\s*=\s*(?:On|1)\b/gim,
    '`allow_url_include` enables remote file inclusion. Disable it.',
    { languages: ['php', 'ini', 'plaintext', 'properties'] }),
  pat('a05-php-phpinfo', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.90,
    /\bphpinfo\s*\(\s*\)/g,
    '`phpinfo()` discloses server configuration. Remove it from deployed code.',
    { languages: ['php'] }),
  pat('a05-laravel-debug', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.90,
    /\bAPP_DEBUG\s*[=:]\s*["']?true\b/gi,
    '`APP_DEBUG=true` leaks stack traces and environment values. Set to false in production.',
    { languages: ['php', 'yaml', 'dockerfile', 'dotenv', 'plaintext'], fileNameMatch: /^\.env/ }),
  pat('a05-dotnet-config', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.90,
    /<customErrors\s+mode\s*=\s*["']Off["']|<compilation\b[^>]*\bdebug\s*=\s*["']true["']|<trace\s+enabled\s*=\s*["']true["']/gi,
    'ASP.NET debug/trace/custom-errors misconfiguration — detailed errors are exposed to users.',
    { languages: ['xml'], fileNameMatch: /\.config$/i }),
  pat('a05-dotnet-dev-exception-page', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.72,
    /\bUseDeveloperExceptionPage\s*\(\s*\)/g,
    'Developer exception page enabled — make sure it is wrapped in `if (env.IsDevelopment())`.',
    { safeIfContext: /IsDevelopment|env\.Is|Environment\./, contextChars: 200, languages: ['csharp'] }),
  pat('a05-spring-actuator', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.88,
    /management\.endpoints\.web\.exposure\.include\s*[=:]\s*["']?\*/g,
    'All Spring Boot actuator endpoints are exposed (env, heapdump, ...). Expose only `health`/`info` and secure the rest.',
    { languages: ['properties', 'yaml', 'plaintext'], fileNameMatch: /^application.*\.(?:properties|ya?ml)$/ }),
  pat('a05-spring-h2-console', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.90,
    /spring\.h2\.console\.enabled\s*[=:]\s*true/g,
    'H2 web console enabled — allows database access and remote code execution if reachable.',
    { languages: ['properties', 'yaml', 'plaintext'], fileNameMatch: /^application.*\.(?:properties|ya?ml)$/ }),
  pat('a05-spring-error-detail', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.88,
    /server\.error\.include-(?:stacktrace|message|exception)\s*[=:]\s*always/g,
    'Spring error responses include stack traces/messages. Use `never` or `on_param` outside development.',
    { languages: ['properties', 'yaml', 'plaintext'], fileNameMatch: /^application.*\.(?:properties|ya?ml)$/ }),
  pat('a05-node-errorhandler', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.85,
    /\bapp\.use\s*\(\s*errorhandler\s*\(/g,
    'The `errorhandler` middleware sends stack traces to clients. Enable it only in development.',
    { safeIfContext: /NODE_ENV|isDev|development/i, contextChars: 200, languages: [...LANGS.JS] }),
  pat('a05-dev-env-var', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.75,
    /\b(?:NODE_ENV|FLASK_ENV|APP_ENV|RAILS_ENV|ASPNETCORE_ENVIRONMENT)\s*[=:]\s*["']?(?:development|Development)\b/g,
    'Container / deployment config sets a development environment. Use `production` for deployed builds.',
    { languages: ['dockerfile', 'yaml', 'shellscript'] }),
  pat('a05-graphql-introspection', V.SECURITY_MISCONFIGURATION, S.LOW, 0.78,
    /\b(?:introspection|playground|graphiql)\s*:\s*true\b/g,
    'GraphQL introspection/playground enabled — disable in production to avoid schema disclosure.',
    { safeIfContext: /NODE_ENV|isDev|development|process\.env/i, contextChars: 200, languages: [...LANGS.JS] }),
  pat('a05-rails-force-ssl', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.85,
    /\bconfig\.force_ssl\s*=\s*false/g,
    '`force_ssl = false` — traffic is not forced onto HTTPS.',
    { languages: ['ruby'] }),
  pat('a05-webpack-host-check', V.SECURITY_MISCONFIGURATION, S.LOW, 0.85,
    /\bdisableHostCheck\s*:\s*true|\ballowedHosts\s*:\s*["']all["']/g,
    'Dev-server host check disabled — exposes the dev server to DNS-rebinding attacks.',
    { languages: [...LANGS.JS] }),

  // ── Error / stack-trace leakage ───────────────────────────────────────────
  pat('a05-leak-node', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.88,
    /\b(?:res|response)\s*\.\s*(?:status\s*\([^)]*\)\s*\.\s*)?(?:send|json|end)\s*\(\s*(?:\{[^}\n]{0,80}?)?\b(?:err|error|e|ex)\.stack\b|\b(?:res|response)\s*\.\s*(?:status\s*\([^)]*\)\s*\.\s*)?(?:send|json)\s*\(\s*(?:err|error|e|ex)\s*\)/g,
    'Stack trace / raw error object returned to the client — leaks internals. Log it server-side and return a generic message.',
    { languages: [...LANGS.JS] }),
  pat('a05-leak-python', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.80,
    /\b(?:return|jsonify|Response|HttpResponse|JsonResponse)\b[^\n]{0,60}?traceback\.(?:format_exc|print_exc)\s*\(|\b(?:return|jsonify|Response|HttpResponse|JsonResponse)\s*\(?[^\n]{0,40}?\bstr\s*\(\s*(?:e|ex|err|exc|exception)\s*\)/g,
    'Exception details returned in the response — leaks internals. Log it and return a generic error.',
    { languages: ['python'] }),
  pat('a05-leak-java', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.85,
    /\bprintStackTrace\s*\(\s*(?:response|resp|out)\b|\bresponse\.getWriter\(\)\.(?:print|println|write)\s*\([^\n)]*\b(?:e|ex|exception)\.(?:getMessage|toString|getStackTrace)/g,
    'Exception details written to the HTTP response — leaks internals.',
    { languages: [...LANGS.JAVA] }),
  pat('a05-leak-php', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.82,
    /\b(?:echo|print|die|exit)\s*\(?[^\n;]{0,40}?\$(?:e|ex|exception)->(?:getMessage|getTraceAsString|getTrace)\s*\(|\bmysqli?_error\s*\(|\b(?:print_r|var_dump)\s*\(\s*\$(?:e|ex|exception)\b/g,
    'Exception / database error details printed to the user — leaks internals.',
    { languages: ['php'] }),
  pat('a05-leak-csharp', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.80,
    /\bResponse\.Write\s*\([^\n)]*\b(?:ex|e|exception)\.(?:ToString|StackTrace|Message)\b|\breturn\s+(?:Ok|BadRequest|StatusCode\s*\(\s*500\s*,)\s*\(?\s*(?:ex|e|exception)\.(?:ToString\(\)|StackTrace|Message)\b/g,
    'Exception details returned to the client — leaks internals.',
    { languages: ['csharp'] }),

  // ── XML External Entities ─────────────────────────────────────────────────
  pat('a05-xxe-node', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.93,
    /\bnoent\s*:\s*true/g,
    'XML parsed with `noent: true` — external entities are resolved (XXE). Remove it.',
    { languages: [...LANGS.JS] }),
  pat('a05-xxe-java', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.75,
    /\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|XPathFactory|SAXTransformerFactory)\.newInstance\s*\(|\bXMLReaderFactory\.createXMLReader\s*\(/g,
    'XML parser factory created — make sure DOCTYPE / external entities are disabled (XXE). Set `disallow-doctype-decl` or `FEATURE_SECURE_PROCESSING`.',
    { safeIfFile: XXE_SAFE, languages: [...LANGS.JAVA] }),
  pat('a05-xxe-python', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.90,
    /\betree\.XMLParser\s*\([^\n)]*resolve_entities\s*=\s*True|\bsetFeature\s*\(\s*(?:xml\.sax\.handler\.)?feature_external_ges\s*,\s*True|\b(?:etree|lxml\.etree)\.(?:fromstring|parse|XML)\s*\(\s*request\./g,
    'XML parser resolves external entities or parses request data directly (XXE). Use `defusedxml` or disable entity resolution.',
    { languages: ['python'] }),
  pat('a05-xxe-csharp', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.88,
    /\bXmlResolver\s*=\s*new\s+XmlUrlResolver|\bDtdProcessing\s*=\s*DtdProcessing\.Parse|\bnew\s+XmlTextReader\s*\(/g,
    'XML reader allows DTD/external entities (XXE). Set `DtdProcessing.Prohibit` and `XmlResolver = null`.',
    { languages: ['csharp'] }),
  pat('a05-xxe-php', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.92,
    /\blibxml_disable_entity_loader\s*\(\s*false\s*\)|\bLIBXML_NOENT\b/g,
    'PHP XML parsing with entity substitution enabled (XXE).',
    { languages: ['php'] }),

  // ── Cookies, headers, exposure ────────────────────────────────────────────
  pat('a05-cookie-flags', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.85,
    /\b(?:httpOnly|http_only|HttpOnly)\s*[:=]\s*(?:false|False|0)\b|\bsecure\s*:\s*false\b|\bSESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False|\bCSRF_COOKIE_SECURE\s*=\s*False|\bsession\.cookie_(?:httponly|secure)\s*=\s*(?:0|Off|false)|\bsetHttpOnly\s*\(\s*false\s*\)|\bsetSecure\s*\(\s*false\s*\)|httpOnlyCookies\s*=\s*["']false["']|requireSSL\s*=\s*["']false["']/gi,
    'Cookie without `HttpOnly` / `Secure` — it can be stolen by XSS or sent over plain HTTP.',
    { languages: [...APP_LANGS, 'xml', 'ini'] }),
  pat('a05-headers-disabled', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.90,
    /\b(?:contentSecurityPolicy|frameguard|hsts|noSniff|xssFilter|referrerPolicy|crossOriginEmbedderPolicy)\s*:\s*false\b/g,
    'A security header is switched off (helmet option set to false).',
    { languages: [...LANGS.JS] }),
  pat('a05-csp-unsafe', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.85,
    /(?:Content-Security-Policy|contentSecurityPolicy|script-src)[^\n]{0,200}unsafe-(?:inline|eval)/gi,
    'CSP allows `unsafe-inline` / `unsafe-eval` — this defeats most of its XSS protection.',
    { languages: [...APP_LANGS, 'xml', 'yaml', 'plaintext'] }),
  pat('a05-xframe-allowall', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.90,
    /X-Frame-Options["']?\s*[,:=]\s*["']?(?:ALLOWALL|ALLOW-FROM\s+\*)/gi,
    '`X-Frame-Options: ALLOWALL` permits clickjacking from any site.',
    { languages: [...APP_LANGS, 'xml', 'yaml', 'plaintext'] }),
  pat('a05-express-no-helmet', V.SECURITY_MISCONFIGURATION, S.LOW, 0.72,
    /\b(?:const|let|var)\s+\w+\s*=\s*express\s*\(\s*\)/g,
    'Express app created without `helmet` — add it to set secure HTTP headers (CSP, HSTS, X-Content-Type-Options...).',
    { safeIfFile: /helmet|lusca|secure-headers|X-Content-Type-Options|Strict-Transport-Security/i, languages: [...LANGS.JS] }),
  pat('a05-dir-listing', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.85,
    /\bexpress\.static\s*\(\s*(?:__dirname|["'](?:\.|\.\/|\/)["'])\s*[,)]|\bserveIndex\s*\(|\bautoindex\s+on\b|^[ \t]*Options\s+\+?Indexes\b/gm,
    'Directory listing or the project root is served statically — source and config files may be downloadable.',
    { languages: [...LANGS.JS, 'plaintext', 'yaml'] }),
  pat('a05-spring-headers-disabled', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.88,
    /\.headers\s*\(\s*\)\s*\.\s*(?:disable|frameOptions\s*\(\s*\)\s*\.\s*disable)\s*\(/g,
    'Spring Security default headers disabled (clickjacking / MIME-sniffing protection removed).',
    { languages: [...LANGS.JAVA] }),
  pat('a05-world-writable', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.88,
    /\bchmod(?:Sync)?\s*\([^\n)]*(?:0o?777|0o?666)|\bos\.chmod\s*\([^\n)]*0o?777|\bchmod\s*\(\s*0?777|\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx|666)\b|\bumask\s*\(\s*0+\s*\)/g,
    'World-writable permissions (777/666) — any local user can modify the file.',
    { languages: [...APP_LANGS, 'shellscript', 'dockerfile', 'makefile'] }),
  pat('a05-webserver-misc', V.SECURITY_MISCONFIGURATION, S.LOW, 0.78,
    /^[ \t]*expose_php\s*=\s*On\b/gim,
    '`expose_php = On` reveals the PHP version in response headers.',
    { languages: ['ini', 'plaintext', 'properties'] }),

  // ── Containers (Docker / Compose / Kubernetes) ────────────────────────────
  pat('a05-docker-root-user', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.80,
    /^[ \t]*USER\s+root\s*$/gim,
    'Container runs as root. Add a non-root `USER` to limit the impact of a compromise.',
    { languages: ['dockerfile'], fileNameMatch: /^Dockerfile/i }),
  pat('a05-docker-secret-env', V.HARDCODED_SECRET, S.HIGH, 0.82,
    /^[ \t]*(?:ENV|ARG)\s+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)\w*(?:[ \t]+|[ \t]*=[ \t]*)["']?(?![$\s{<])[^\s"'$]{4,}/gim,
    'Secret baked into the image via ENV/ARG — it is readable from the image layers. Use runtime secrets.',
    { redact: true, languages: ['dockerfile'], fileNameMatch: /^Dockerfile/i }),
  pat('a05-docker-exposed-admin-port', V.SECURITY_MISCONFIGURATION, S.MEDIUM, 0.78,
    /^[ \t]*EXPOSE\s+(?:22|23|3389|5900)\b/gim,
    'Remote-administration port (SSH/Telnet/RDP/VNC) exposed by the container.',
    { languages: ['dockerfile'], fileNameMatch: /^Dockerfile/i }),
  pat('a05-container-privileged', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.85,
    /--privileged\b|\bnetwork_mode\s*:\s*["']?host\b|\bprivileged\s*:\s*true\b|\bpid\s*:\s*["']?host\b|\bhost(?:Network|PID|IPC)\s*:\s*true\b|\ballowPrivilegeEscalation\s*:\s*true\b|\brunAsUser\s*:\s*0\b|\brunAsNonRoot\s*:\s*false\b|\breadOnlyRootFilesystem\s*:\s*false\b|\bcap_add\s*:\s*\[?\s*-?\s*["']?(?:SYS_ADMIN|ALL)\b|\/var\/run\/docker\.sock/g,
    'Container is given excessive privileges (privileged / host namespaces / root / docker.sock). Apply least privilege.',
    { languages: ['yaml', 'dockerfile', 'shellscript', 'plaintext'] }),

  // ── Infrastructure as Code ────────────────────────────────────────────────
  pat('a05-iac-open-ingress', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.82,
    /\bcidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]|\bCidrIp\s*["']?\s*:\s*["']?0\.0\.0\.0\/0|\bsource_ranges\s*=\s*\[\s*"0\.0\.0\.0\/0"/gi,
    'Network rule open to the entire internet (0.0.0.0/0). Restrict to the required CIDR ranges.',
    { fileNameMatch: IAC_FILE, languages: ['terraform', 'hcl', 'yaml', 'json'] }),
  pat('a05-iac-public-storage', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.85,
    /\bacl\s*=\s*"public-read(?:-write)?"|\bblock_public_(?:acls|policy)\s*=\s*false|\bpublicly_accessible\s*=\s*true|\bAccessControl\s*["']?\s*:\s*["']?PublicRead|\bstorage_encrypted\s*=\s*false|\bencrypted\s*=\s*false/gi,
    'Storage/database is public or unencrypted. Enable encryption and block public access.',
    { fileNameMatch: IAC_FILE, languages: ['terraform', 'hcl', 'yaml', 'json'] }),
  pat('a05-iac-iam-wildcard', V.SECURITY_MISCONFIGURATION, S.HIGH, 0.85,
    /"Action"\s*:\s*"\*"|\bActions?\s*["']?\s*[:=]\s*\[?\s*["']\*["']|\bPrincipal\s*["']?\s*[:=]\s*\{?\s*["']?(?:AWS["']?\s*:\s*)?["']\*["']/g,
    'IAM policy grants `*` actions/principals. Apply least privilege.',
    { fileNameMatch: IAC_FILE, languages: ['terraform', 'hcl', 'yaml', 'json'] }),

  // ── Secrets in configuration files ────────────────────────────────────────
  pat('a05-config-file-secret', V.HARDCODED_SECRET, S.HIGH, 0.78,
    /^[ \t]*[\w.-]*(?:password|passwd|secret|api[_.-]?key|access[_.-]?key|private[_.-]?key|token)[\w.-]*[ \t]*[=:][ \t]*(?!changeme|your|xxx|<|\$|\{|%|\*|\s|["']?\s*$)[^\s#]{4,}/gim,
    'Credential stored in a configuration file that is usually committed. Use environment variables or a secrets manager.',
    {
      redact: true,
      languages: ['properties', 'ini', 'toml'],
      fileNameMatch: /\.(?:properties|ini|cfg|conf|toml)$/i,
      validate: (m) => {
        const value = m[0].split(/[=:]/).slice(1).join('=').trim().replace(/^["']|["']$/g, '');
        return /[A-Z0-9!@#$%^&*_+=-]/.test(value) && !/^(?:true|false|none|null|empty|bcrypt|argon2|pbkdf2)$/i.test(value);
      },
    }),
];

export class SecurityMisconfigurationRule extends PatternRule {
  readonly ruleId             = 'SENTINEL-A05-001';
  readonly ruleName           = 'A05 Security Misconfiguration Detector';
  readonly vulnerabilityType  = V.SECURITY_MISCONFIGURATION;
  readonly supportedLanguages = [...APP_LANGS, ...CONFIG_LANGS];
  protected readonly patterns = PATTERNS;
}
