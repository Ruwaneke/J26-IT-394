/**
 * Sentinel — OWASP A02:2021  Cryptographic Failures
 *
 * Detects:
 *   • Broken / weak hash algorithms (MD5, SHA-1) — especially for passwords
 *   • Broken ciphers and modes (DES, 3DES, RC2, RC4, Blowfish, AES-ECB)
 *   • Hardcoded encryption keys / static IVs and salts
 *   • Predictable randomness used for tokens, secrets, OTPs
 *   • TLS certificate validation disabled; obsolete SSL/TLS protocol versions
 *   • Weak RSA key sizes, low bcrypt cost factors
 *   • Sensitive data in URLs, browser storage and cleartext (http://) transport
 */

import { Severity as S, VulnerabilityType as V } from '../analyzer/types.js';
import { APP_LANGS, LANGS, PatternRule, RulePattern, pat } from './patternEngine.js';

const SECURITY_WORDS = ['password', 'passwd', 'token', 'secret', 'session', 'auth', 'login', 'credential', 'otp', 'reset'];

const PRIVATE_NET = String.raw`(?:localhost|127\.|0\.0\.0\.0|\[::1\]|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|[\w.-]*\.(?:local|internal|test|example|invalid|localhost)\b|(?:www\.)?w3\.org|schemas?\.|xmlns|json-schema\.org|[\w.-]*example\.(?:com|org|net)|purl\.org|java\.sun\.com|maven\.apache\.org|ns\.adobe\.com|(?:www|xml)\.apache\.org)`;

const CRYPTO_LANGS = [...APP_LANGS, 'xml', 'yaml', 'properties', 'ini', 'dockerfile'];

const PATTERNS: RulePattern[] = [
  // ── Weak hashes ───────────────────────────────────────────────────────────
  pat('a02-password-fast-hash', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.93,
    /(?:password|passwd|pwd)[^\n]{0,80}?\b(?:md5|sha1|sha-1)\s*\(|\b(?:md5|sha1)\s*\([^\n)]{0,40}?(?:password|passwd|pwd)/gi,
    'Password hashed with a fast, broken hash (MD5/SHA-1). Use bcrypt, scrypt or Argon2.'),
  pat('a02-node-weak-hash', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.90,
    /\bcreateHash\s*\(\s*["'](?:md5|md4|sha1|sha-1|ripemd160)["']/gi,
    'Weak hash algorithm (MD5/SHA-1). Use SHA-256+ for integrity, and bcrypt/Argon2 for passwords.',
    { boostKeywords: SECURITY_WORDS, languages: [...LANGS.JS] }),
  pat('a02-python-weak-hash', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.90,
    /\bhashlib\.(?:md5|sha1)\s*\(|\bhashlib\.new\s*\(\s*["'](?:md5|sha1)/g,
    'Weak hash algorithm (MD5/SHA-1). Use `hashlib.sha256` or a password hasher (bcrypt/argon2).',
    { boostKeywords: SECURITY_WORDS, safeIfLine: /usedforsecurity\s*=\s*False/, languages: ['python'] }),
  pat('a02-java-weak-digest', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.90,
    /MessageDigest\.getInstance\s*\(\s*"(?:MD5|MD2|MD4|SHA-?1)"|Mac\.getInstance\s*\(\s*"Hmac(?:MD5|SHA1)"/gi,
    'Weak digest algorithm (MD5/SHA-1). Use SHA-256 or stronger.',
    { boostKeywords: SECURITY_WORDS, languages: [...LANGS.JAVA] }),
  pat('a02-csharp-weak-crypto', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.90,
    /\b(?:MD5|SHA1|DES|TripleDES|RC2)(?:CryptoServiceProvider|Managed|\.Create\s*\()|CipherMode\.ECB/g,
    'Broken crypto primitive (MD5/SHA-1/DES/3DES/RC2 or ECB mode). Use SHA-256+ and AES-GCM.',
    { boostKeywords: SECURITY_WORDS, languages: ['csharp'] }),
  pat('a02-php-weak-hash', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.78,
    /\b(?:md5|sha1|crypt)\s*\(\s*\$/g,
    '`md5()/sha1()/crypt()` are not suitable for security purposes. Use `password_hash()` for passwords, `hash("sha256")` for integrity.',
    { boostKeywords: SECURITY_WORDS, languages: ['php'] }),
  pat('a02-php-mcrypt', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.92,
    /\bmcrypt_\w+\s*\(|\bopenssl_encrypt\s*\([^)\n]*["'](?:des|rc4|rc2|bf)[-\w]*["']|\bopenssl_encrypt\s*\([^)\n]*["']aes-\d+-ecb["']/gi,
    'Deprecated/broken PHP encryption (mcrypt, DES, RC4, ECB). Use `openssl_encrypt` with AES-256-GCM.',
    { languages: ['php'] }),
  pat('a02-go-weak-import', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.85,
    /["']crypto\/(?:md5|sha1|des|rc4)["']/g,
    'Weak crypto package imported (md5/sha1/des/rc4). Use `crypto/sha256` and `crypto/aes` (GCM).',
    { languages: ['go'] }),
  pat('a02-ruby-weak-digest', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.90,
    /\bDigest::(?:MD5|SHA1)\b/g,
    'Weak digest (MD5/SHA-1). Use `Digest::SHA256` or bcrypt for passwords.',
    { languages: ['ruby'] }),

  // ── Weak ciphers / modes ──────────────────────────────────────────────────
  pat('a02-node-weak-cipher', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.93,
    /\bcreateCipher(?:iv)?\s*\(\s*["'](?:des|des-ede3?(?:-cbc)?|des3|rc4|rc2|bf(?:-cbc)?|blowfish|aes-\d+-ecb)["']/gi,
    'Weak cipher or ECB mode. Use `aes-256-gcm` with a random IV.',
    { languages: [...LANGS.JS] }),
  pat('a02-node-createcipher', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.88,
    /\bcreateCipher\s*\(/g,
    '`crypto.createCipher()` is deprecated — it derives the key weakly and uses no IV. Use `createCipheriv` with a random IV.',
    { languages: [...LANGS.JS] }),
  pat('a02-java-weak-cipher', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.92,
    /Cipher\.getInstance\s*\(\s*"(?:DES|DESede|RC2|RC4|ARCFOUR|Blowfish)(?:\/[^"]*)?"|Cipher\.getInstance\s*\(\s*"AES"\s*\)|Cipher\.getInstance\s*\(\s*"[^"]*\/ECB\/[^"]*"/g,
    'Weak cipher or ECB mode (plain "AES" defaults to ECB). Use `AES/GCM/NoPadding`.',
    { languages: [...LANGS.JAVA] }),
  pat('a02-python-weak-cipher', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.92,
    /AES\.new\s*\([^)\n]*MODE_ECB|\b(?:DES|DES3|ARC4|ARC2|Blowfish)\.new\s*\(|from\s+Crypto\.Cipher\s+import\s+(?:DES|ARC4|ARC2|Blowfish)\b/g,
    'Weak cipher or ECB mode. Use AES in GCM mode (`AES.MODE_GCM`).',
    { languages: ['python'] }),

  // ── Hardcoded keys / static IV ────────────────────────────────────────────
  pat('a02-hardcoded-key-node', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.93,
    /\b(?:createCipheriv|createDecipheriv)\s*\(\s*["'][^"'\n]+["']\s*,\s*["'][^"'\n]{8,}["']/g,
    'Encryption key is a string literal in source code. Load keys from a KMS / secrets manager.',
    { redact: true, languages: [...LANGS.JS] }),
  pat('a02-hardcoded-key-java', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.95,
    /new\s+SecretKeySpec\s*\(\s*"[^"\n]{4,}"/g,
    'SecretKeySpec built from a hardcoded string. Load keys from a KeyStore / KMS.',
    { redact: true, languages: [...LANGS.JAVA] }),
  pat('a02-hardcoded-key-python', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.93,
    /\b(?:AES|DES3|Fernet)(?:\.new)?\s*\(\s*b?["'][^"'\n]{8,}["']/g,
    'Encryption key is a literal in source code. Load keys from a KMS / secrets manager.',
    { redact: true, languages: ['python'] }),
  pat('a02-hardcoded-key-csharp', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.90,
    /\bKey\s*=\s*Encoding\.(?:UTF8|ASCII|Unicode)\.GetBytes\s*\(\s*"[^"\n]+"/g,
    'Encryption key derived from a string literal. Use a key vault / DPAPI.',
    { redact: true, languages: ['csharp'] }),
  pat('a02-hardcoded-key-php', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.90,
    /\bopenssl_(?:en|de)crypt\s*\([^,\n]+,\s*[^,\n]+,\s*["'][^"'\n]{8,}["']/g,
    'Encryption key is a literal in source code. Store keys outside the codebase.',
    { redact: true, languages: ['php'] }),
  pat('a02-static-iv', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.76,
    /\b(?:iv|salt|nonce|initializationVector|init_vector)\s*[=:]\s*(?:Buffer\.from\s*\(\s*|bytes\s*\(\s*|b)?["'][^"'\n]{8,}["']/gi,
    'Static IV / salt / nonce. Generate a fresh random value for every encryption or hash.',
    { boostKeywords: ['aes', 'cipher', 'encrypt', 'hash'], redact: true }),

  // ── Predictable randomness ────────────────────────────────────────────────
  pat('a02-weak-random-secret', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.85,
    /\b(?:token|secret|password|passwd|pwd|session\w*|apikey|api_key|otp|nonce|salt|csrf\w*|reset\w*|verification\w*|auth\w*)\w*\s*[=:(][^\n]{0,80}?\b(?:Math\.random|random\.(?:random|randint|choice|choices|randrange|getrandbits|sample)|new\s+Random|mt_rand|rand|uniqid|lcg_value)\s*\(/gi,
    'Predictable random generator used for a security token/secret. Use a CSPRNG (`crypto.randomBytes`, `secrets`, `SecureRandom`, `random_bytes`).'),
  pat('a02-math-random-tostring', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.71,
    /\bMath\.random\s*\(\s*\)\s*\.toString\s*\(\s*(?:16|36)\s*\)/g,
    '`Math.random().toString(..)` is predictable — do not use it for tokens or identifiers that must be unguessable. Use `crypto.randomUUID()` / `crypto.randomBytes()`.',
    { boostKeywords: ['token', 'secret', 'session', 'password', 'key', 'auth', 'reset', 'otp'], languages: [...LANGS.JS] }),

  // ── TLS / certificate validation ──────────────────────────────────────────
  pat('a02-tls-reject-unauthorized', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.95,
    /\brejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED["']?\]?\s*[=:]\s*["']?0/g,
    'TLS certificate validation is disabled — connections are open to man-in-the-middle attacks.',
    { languages: [...LANGS.JS, 'dockerfile', 'yaml', 'shellscript'] }),
  pat('a02-tls-python-verify-false', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.93,
    /\b(?:requests|httpx|session|client|s)\.\w+\s*\([^\n)]*\bverify\s*=\s*False|ssl\._create_unverified_context|ssl\._create_default_https_context\s*=\s*ssl\._create_unverified_context|\bcheck_hostname\s*=\s*False|\.verify_mode\s*=\s*ssl\.CERT_NONE/g,
    'TLS certificate verification disabled (`verify=False` / `CERT_NONE`).',
    { languages: ['python'] }),
  pat('a02-tls-go', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.95,
    /\bInsecureSkipVerify\s*:\s*true/g,
    '`InsecureSkipVerify: true` disables TLS certificate validation.',
    { languages: ['go'] }),
  pat('a02-tls-php', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.93,
    /CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)\b|["']verify_peer(?:_name)?["']\s*=>\s*false/g,
    'cURL/stream TLS verification disabled.',
    { languages: ['php'] }),
  pat('a02-tls-java', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.88,
    /ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|TrustAllStrategy|\bTrustAllCerts\b|new\s+X509TrustManager\s*\(\s*\)|setHostnameVerifier\s*\([^)]*->\s*true\s*\)/g,
    'Trust manager / hostname verifier accepts every certificate.',
    { languages: [...LANGS.JAVA] }),
  pat('a02-tls-csharp', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.93,
    /ServerCertificateValidationCallback\s*\+?=[^\n;]*(?:\btrue\b|delegate|=>)|DangerousAcceptAnyServerCertificateValidator/g,
    'Certificate validation callback accepts every certificate.',
    { languages: ['csharp'] }),
  pat('a02-tls-ruby', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.95,
    /verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE/g,
    'SSL verification disabled (`VERIFY_NONE`).',
    { languages: ['ruby'] }),
  pat('a02-obsolete-tls', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.82,
    /(?:SSLv[23]|TLSv1(?:[._][01])?)(?![\w.]*\d)|SecurityProtocolType\.(?:Ssl3|Tls|Tls11)\b/g,
    'Obsolete SSL/TLS protocol version. Require TLS 1.2 or newer.',
    { safeIfLine: /NO_SSL|NO_TLS|disable|ssl_prefer|\bblock|\bdeny/i, languages: CRYPTO_LANGS }),

  // ── Key size / password-hash cost ─────────────────────────────────────────
  pat('a02-weak-rsa-key', V.WEAK_CRYPTOGRAPHY, S.HIGH, 0.88,
    /\b(?:modulusLength|key_?size|key_?length)\s*[:=(]\s*(?:512|768|1024)\b|\.initialize\s*\(\s*(?:512|768|1024)\s*\)|RSA\.generate\s*\(\s*(?:512|768|1024)\b|\bRSACryptoServiceProvider\s*\(\s*(?:512|768|1024)\s*\)/gi,
    'RSA key shorter than 2048 bits is considered breakable. Use ≥ 2048 (3072 recommended).'),
  pat('a02-bcrypt-low-cost', V.WEAK_CRYPTOGRAPHY, S.MEDIUM, 0.82,
    /\bbcrypt\w*\.(?:hash|hashSync|genSalt|genSaltSync|gensalt)\s*\(\s*(?:[^,\n)]+,\s*)?(?:rounds\s*=\s*)?[1-9]\s*\)/gi,
    'bcrypt cost factor is too low. Use at least 10–12 rounds.'),

  // ── Sensitive data exposure (cleartext / URL / browser storage) ───────────
  pat('a02-secret-in-url', V.SENSITIVE_DATA_EXPOSURE, S.HIGH, 0.86,
    /[?&](?:password|passwd|pwd|token|secret|api_?key|access_?token|auth)=["'`]\s*\+|[?&](?:password|passwd|pwd|token|secret|api_?key|access_?token)=\$\{|[?&](?:password|passwd|pwd|secret|api_?key|access_?token)=%s|[?&](?:password|passwd|pwd|token|secret|api_?key|access_?token)=["']\s*\.\s*\$/gi,
    'Credential/token placed in a URL query string — it will leak via logs, history and Referer headers. Send it in a header or request body.'),
  pat('a02-sensitive-browser-storage', V.SENSITIVE_DATA_EXPOSURE, S.MEDIUM, 0.78,
    /\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'](?:password|passwd|pwd|token|jwt|access_?token|refresh_?token|secret|ssn|credit_?card|card_?number|cvv|api_?key|private_?key)["']/gi,
    'Sensitive value stored in browser storage — readable by any XSS payload. Prefer HttpOnly, Secure cookies.',
    { languages: [...LANGS.JS, 'html'] }),
  pat('a02-cleartext-http', V.SENSITIVE_DATA_EXPOSURE, S.MEDIUM, 0.76,
    new RegExp(
      String.raw`\b(?:fetch|axios(?:\.\w+)?|requests\.\w+|urlopen|\w*[uU]rl|\w*[uU]ri|endpoint|baseURL|base_url|API\w*|BASE\w*|host|HttpGet|HttpPost|WebClient|URL|URI|curl_init)\s*[(=:,]\s*(?:new\s+\w+\s*\(\s*)?["'` + '`' + String.raw`]http:\/\/(?!` + PRIVATE_NET + String.raw`)`,
      'g',
    ),
    'Data sent over unencrypted HTTP. Use HTTPS so credentials and personal data cannot be intercepted.'),
];

export class CryptographicFailuresRule extends PatternRule {
  readonly ruleId             = 'SENTINEL-A02-001';
  readonly ruleName           = 'A02 Cryptographic Failures Detector';
  readonly vulnerabilityType  = V.WEAK_CRYPTOGRAPHY;
  readonly supportedLanguages = APP_LANGS;
  protected readonly patterns = PATTERNS;
}
