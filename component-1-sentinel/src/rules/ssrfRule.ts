/**
 * Sentinel — OWASP A10:2021  Server-Side Request Forgery (SSRF)
 *
 * Detects:
 *   • HTTP clients (`fetch`, `axios`, `requests`, `HttpClient`, `file_get_contents`…)
 *     whose URL is taken from the request
 *   • Webhooks / image-download / preview / proxy endpoints that fetch a user URL
 *   • Cloud metadata-style URLs (169.254.169.254, metadata.google.internal)
 *   • Taint: `const target = req.query.url; axios.get(target)`
 *
 * Mitigations recognised: allow-lists, URL parsers that force https + public hosts,
 * `ssrf-req-filter`, `private-ip`, `isPublic`, blocked host checks.
 */

import { Severity as S, VulnerabilityType as V } from '../analyzer/types.js';
import { APP_LANGS, LANGS, PatternRule, RulePattern, TaintSink, pat, sink } from './patternEngine.js';

const SSRF_SAFE = /allowlist|whitelist|allowedHosts|allowed_hosts|isPublicUrl|is_public|blockedHosts|private-ip|ssrf-req-filter|ssrfProtect|validateUrl|UrlValidator|isSafeUrl|REJECT_PRIVATE|notIpAddress|dnsLookup/i;

const USER_URL = String.raw`(?:req|request)\.(?:body|query|params)(?:\.\w+|\[[^\]]+\])?`;
const PY_USER  = String.raw`request\.(?:args|form|values|json|GET|POST|data|query_params)`;
const JAVA_USER = String.raw`(?:getParameter|getQueryString|getHeader)\s*\(`;

const HTTP_JS = String.raw`(?:fetch|axios(?:\.(?:get|post|put|patch|delete|head|request))?|got|needle|superagent|http(?:s)?\.request|http(?:s)?\.get|request(?:\.get)?|undici\.request|\$\.ajax|\$\.get|\$\.post|cy\.request)`;
const HTTP_PY = String.raw`(?:requests|httpx|urllib\.request|urllib2|aiohttp(?:\.ClientSession\(\))?)\.(?:get|post|put|patch|delete|head|request|urlopen)`;
const HTTP_JAVA = String.raw`(?:RestTemplate|WebClient|HttpClient|OkHttpClient|URL)\s*(?:\.\s*\w+)*`;

const PATTERNS: RulePattern[] = [
  // ── Direct user-controlled URL ────────────────────────────────────────────
  pat('a10-js-fetch-req', V.SSRF, S.HIGH, 0.92,
    new RegExp(String.raw`\b${HTTP_JS}\s*\(\s*${USER_URL}`, 'g'),
    'HTTP client called with a URL from the request — Server-Side Request Forgery. Allow-list hosts and block private/link-local IPs (including 169.254.169.254).',
    { safeIfContext: SSRF_SAFE, languages: [...LANGS.JS] }),
  pat('a10-js-axios-url-opt', V.SSRF, S.HIGH, 0.90,
    new RegExp(String.raw`\baxios\s*\(\s*\{[^}]{0,200}?\burl\s*:\s*${USER_URL}`, 'g'),
    '`axios({ url: req... })` — the server will fetch an attacker-chosen address (SSRF).',
    { safeIfContext: SSRF_SAFE, languages: [...LANGS.JS] }),
  pat('a10-js-new-url', V.SSRF, S.MEDIUM, 0.78,
    new RegExp(String.raw`\bnew\s+URL\s*\(\s*${USER_URL}`, 'g'),
    'URL object built from request data. If this is later fetched server-side, restrict scheme/host first.',
    { safeIfContext: SSRF_SAFE, languages: [...LANGS.JS] }),

  pat('a10-python-requests', V.SSRF, S.HIGH, 0.92,
    new RegExp(String.raw`\b${HTTP_PY}\s*\(\s*${PY_USER}`, 'g'),
    'Python HTTP client called with a request-supplied URL — SSRF. Allow-list hosts and block link-local / cloud metadata IPs.',
    { safeIfContext: SSRF_SAFE, languages: ['python'] }),
  pat('a10-python-urlopen', V.SSRF, S.HIGH, 0.90,
    new RegExp(String.raw`\burllib\.request\.urlopen\s*\(\s*${PY_USER}|\burlopen\s*\(\s*${PY_USER}`, 'g'),
    '`urlopen` on a user-supplied URL — SSRF.',
    { safeIfContext: SSRF_SAFE, languages: ['python'] }),

  pat('a10-java-url', V.SSRF, S.HIGH, 0.90,
    new RegExp(String.raw`\bnew\s+URL\s*\(\s*(?:\w+\.)?${JAVA_USER}|\bURI\.create\s*\(\s*(?:\w+\.)?${JAVA_USER}`, 'g'),
    'Java `URL`/`URI` built from `getParameter` — if opened, this is SSRF. Allow-list hosts.',
    { safeIfContext: SSRF_SAFE, languages: [...LANGS.JAVA] }),
  pat('a10-java-resttemplate', V.SSRF, S.HIGH, 0.90,
    /\b(?:restTemplate|webClient|httpClient|okHttp)\.\w+\s*\([^\n)]{0,80}?getParameter\s*\(/gi,
    'HTTP client invoked with a request parameter as the URL — SSRF.',
    { safeIfContext: SSRF_SAFE, languages: [...LANGS.JAVA] }),

  pat('a10-php-file-get', V.SSRF, S.HIGH, 0.92,
    /\b(?:file_get_contents|fopen|readfile|curl_init|file)\s*\(\s*\$_(?:GET|POST|REQUEST)\b/g,
    'PHP network/file wrapper opened on user input (`http://`, `file://`, `phar://`) — SSRF / LFI. Disable wrappers or allow-list.',
    { safeIfContext: SSRF_SAFE, languages: ['php'] }),
  pat('a10-php-curl-setopt', V.SSRF, S.HIGH, 0.90,
    /CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)/g,
    '`CURLOPT_URL` set from user input — SSRF.',
    { safeIfContext: SSRF_SAFE, languages: ['php'] }),

  pat('a10-csharp-httpclient', V.SSRF, S.HIGH, 0.90,
    /\b(?:HttpClient|WebClient|HttpRequestMessage|WebRequest)\b[^\n]{0,80}?Request\.(?:Query|Form|QueryString)/g,
    '.NET HTTP client called with a request-supplied URL — SSRF. Allow-list hosts; block link-local IPs.',
    { safeIfContext: SSRF_SAFE, languages: ['csharp'] }),

  pat('a10-go-http-get', V.SSRF, S.HIGH, 0.90,
    /\bhttp\.(?:Get|Post|Head|Do)\s*\([^\n)]{0,80}?(?:r\.URL\.Query\(\)\.Get|r\.FormValue|c\.(?:Query|Param))\s*\(/g,
    'Go `http.Get/Do` with request data as the URL — SSRF.',
    { safeIfContext: SSRF_SAFE, languages: ['go'] }),

  pat('a10-ruby-open-uri', V.SSRF, S.HIGH, 0.90,
    /\b(?:URI\.open|open|Net::HTTP\.(?:get|post|start)|HTTParty\.(?:get|post)|RestClient\.(?:get|post))\s*\(\s*params\[/g,
    'HTTP fetch of `params[...]` — SSRF. Allow-list hosts.',
    { safeIfContext: SSRF_SAFE, languages: ['ruby'] }),

  // ── Cloud metadata ────────────────────────────────────────────────────────
  pat('a10-metadata-ip', V.SSRF, S.CRITICAL, 0.95,
    /169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254|instance-data\/latest\/meta-data/gi,
    'Cloud instance-metadata address. If reachable from user-controlled SSRF, attackers steal IAM tokens. Block link-local IPs and this host.'),

  // ── Webhook / proxy patterns ──────────────────────────────────────────────
  pat('a10-webhook-endpoint', V.SSRF, S.MEDIUM, 0.76,
    /\b(?:app|router)\.(?:get|post)\s*\(\s*["'`][^"'`\n]*(?:webhook|callback|fetch-url|proxy|preview|og-image|screenshot)[^"'`\n]*["'`]/gi,
    'Webhook / URL-preview endpoint — confirm the fetched host is allow-listed and not a private/metadata address.',
    { safeIfContext: SSRF_SAFE, languages: [...LANGS.JS] }),
];

void HTTP_JAVA;

const SINKS: TaintSink[] = [
  sink('a10-taint-js', V.SSRF, S.HIGH, 0.90,
    /\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|got|http(?:s)?\.(?:get|request))\s*\([^\n)]{0,80}?__TAINT__/g,
    'User-controlled value used as an HTTP URL — SSRF. Allow-list hosts and block private/link-local IPs.',
    { safeIfContext: SSRF_SAFE, languages: [...LANGS.JS] }),
  sink('a10-taint-python', V.SSRF, S.HIGH, 0.90,
    /\b(?:requests|httpx|urllib\.request)\.\w+\s*\([^\n)]{0,80}?__TAINT__|\burlopen\s*\([^\n)]{0,40}?__TAINT__/g,
    'User-controlled value used as an HTTP URL — SSRF.',
    { safeIfContext: SSRF_SAFE, languages: ['python'] }),
  sink('a10-taint-php', V.SSRF, S.HIGH, 0.92,
    /\b(?:file_get_contents|fopen|curl_init|file)\s*\([^\n)]{0,40}?__TAINT__/g,
    'User-controlled value passed to a PHP network/file wrapper — SSRF / LFI.',
    { safeIfContext: SSRF_SAFE, languages: ['php'] }),
  sink('a10-taint-java', V.SSRF, S.HIGH, 0.88,
    /\bnew\s+URL\s*\(\s*__TAINT__|\bURI\.create\s*\(\s*__TAINT__/g,
    'User-controlled value used to build a Java URL — SSRF if opened.',
    { safeIfContext: SSRF_SAFE, languages: [...LANGS.JAVA] }),
  sink('a10-taint-csharp', V.SSRF, S.HIGH, 0.88,
    /\bnew\s+HttpRequestMessage\s*\([^,\n]+,\s*__TAINT__|\b(?:GetAsync|PostAsync|SendAsync)\s*\(\s*__TAINT__/g,
    'User-controlled value used as an HTTP URL — SSRF.',
    { safeIfContext: SSRF_SAFE, languages: ['csharp'] }),
  sink('a10-taint-go', V.SSRF, S.HIGH, 0.88,
    /\bhttp\.(?:Get|Post|Head|Do)\s*\([^\n)]{0,60}?__TAINT__/g,
    'User-controlled value used as an HTTP URL — SSRF.',
    { safeIfContext: SSRF_SAFE, languages: ['go'] }),
];

export class SsrfRule extends PatternRule {
  readonly ruleId             = 'SENTINEL-A10-001';
  readonly ruleName           = 'A10 Server-Side Request Forgery Detector';
  readonly vulnerabilityType  = V.SSRF;
  readonly supportedLanguages = APP_LANGS;
  protected readonly patterns = PATTERNS;
  protected readonly taintSinks = SINKS;
}
