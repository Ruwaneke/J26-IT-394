/**
 * Sentinel — OWASP A07:2021  Identification and Authentication Failures
 *
 * Detects:
 *   • JWT verified with algorithm "none", or decoded without verification
 *   • Weak / hardcoded session and JWT secrets
 *   • Plaintext password comparison (no hash)
 *   • NoOp / empty / unsalted password encoders
 *   • Default / empty credentials and overly short password policies
 *   • Session not rotated after login (session fixation)
 *   • Authentication that trusts a client-supplied user id
 *
 * Hardcoded API keys / passwords themselves are covered by HardcodedSecretRule
 * (also mapped to A07). This rule focuses on the authentication *design*.
 */

import { Severity as S, VulnerabilityType as V } from '../analyzer/types.js';
import { APP_LANGS, LANGS, PatternRule, RulePattern, pat } from './patternEngine.js';

const PATTERNS: RulePattern[] = [
  // ── JWT ───────────────────────────────────────────────────────────────────
  pat('a07-jwt-none', V.INSECURE_AUTH, S.CRITICAL, 0.95,
    /algorithm\s*:\s*["']none["']|algorithms\s*:\s*\[\s*["']none["']|alg\s*=\s*["']none["']|\.verify\s*\([^)\n]*algorithm\s*=\s*["']none["']/gi,
    'JWT accepted with algorithm `none` — attackers can forge tokens with no signature. Allow only RS256/ES256/HS256.'),
  pat('a07-jwt-decode-no-verify', V.INSECURE_AUTH, S.HIGH, 0.90,
    /\bjwt\.decode\s*\(|\bjsonwebtoken\.decode\s*\(|\bJWT\.decode\s*\(|\bJose\.JWT\.Decode\s*\(|PyJWT\.decode\s*\([^)\n]*options\s*=\s*\{[^}]*verify_signature\s*:\s*False/g,
    '`jwt.decode()` does not verify the signature. Use `jwt.verify()` / `decode(..., verify=True)` before trusting claims.',
    { safeIfLine: /\.verify\s*\(|verify_signature\s*:\s*True|verify\s*:\s*true/i }),
  pat('a07-jwt-no-expiry', V.INSECURE_AUTH, S.MEDIUM, 0.76,
    /\bjwt\.sign\s*\(\s*[^,\n]+,\s*[^,\n]+(?:\s*\)|\s*,\s*\{\s*\})/g,
    'JWT signed with no `expiresIn` / `exp` claim — stolen tokens stay valid forever. Set a short expiry and refresh.',
    { languages: [...LANGS.JS], safeIfContext: /expiresIn|exp\s*:|maxAge/ }),
  pat('a07-jwt-weak-secret', V.INSECURE_AUTH, S.HIGH, 0.90,
    /\b(?:jwt|jsonwebtoken)\.(?:sign|verify)\s*\([^,\n]+,\s*["'][^"'\n]{0,12}["']|\bJWT_SECRET\s*[=:]\s*["'](?:secret|changeme|password|jwt|token|123456)["']/gi,
    'JWT HMAC secret is a short or default string — tokens can be brute-forced. Use a long random secret from the environment.',
    { redact: true }),
  pat('a07-session-weak-secret', V.INSECURE_AUTH, S.HIGH, 0.90,
    /\bsecret\s*:\s*["'](?:secret|keyboard cat|changeme|password|session)["']/gi,
    'Session middleware uses a well-known default secret (`keyboard cat` / `secret`). Set a unique high-entropy secret.',
    { languages: [...LANGS.JS], redact: true }),

  // ── Password handling ─────────────────────────────────────────────────────
  pat('a07-plaintext-compare-js', V.INSECURE_AUTH, S.HIGH, 0.88,
    /(?:password|passwd|pwd)\s*===?\s*(?:req|request)\.(?:body|query)\.(?:password|passwd|pwd)|(?:req|request)\.(?:body|query)\.(?:password|passwd|pwd)\s*===?\s*(?:user\.)?(?:password|passwd|pwd)/g,
    'Password compared in plaintext. Store a slow hash (bcrypt / Argon2 / scrypt) and compare with the hasher API.',
    { languages: [...LANGS.JS] }),
  pat('a07-plaintext-compare-python', V.INSECURE_AUTH, S.HIGH, 0.88,
    /(?:user\.)?(?:password|passwd)\s*==\s*(?:request\.(?:form|json|args|POST)|password)|check_password_hash\s+is\s+None/g,
    'Password compared in plaintext. Use `werkzeug.security.check_password_hash` / Django `check_password`.',
    { languages: ['python'] }),
  pat('a07-plaintext-compare-php', V.INSECURE_AUTH, S.HIGH, 0.90,
    /\$\w*(?:password|passwd|pwd)\s*===?\s*\$_(?:POST|GET|REQUEST)\s*\[|password_verify\s*\(\s*\$_POST[^,]+,\s*\$\w+\s*\)\s*;\s*\/\/\s*plain/gi,
    'Password compared in plaintext. Use `password_hash()` / `password_verify()`.',
    { languages: ['php'] }),
  pat('a07-noop-encoder', V.INSECURE_AUTH, S.CRITICAL, 0.95,
    /\bNoOpPasswordEncoder\b|\bwithDefaultPasswordEncoder\b|\bPasswordEncoderFactories\.createDelegatingPasswordEncoder\s*\(\s*\)\s*;[^\n]*noop|\bPASSWORD_HASHERS\s*=\s*\[[^\]]*(?:UnsaltedMD5|SHA1PasswordHasher|MD5PasswordHasher)/g,
    'Passwords stored with a no-op or unsalted hasher. Use bcrypt / Argon2 / PBKDF2.'),
  pat('a07-empty-password-allowed', V.INSECURE_AUTH, S.HIGH, 0.85,
    /(?:password|passwd|pwd)\s*(?:===?|==)\s*["']{2}|\.isEmpty\(\)\s*\|\|\s*.{0,20}password|ALLOW_EMPTY_PASSWORD\s*[=:]\s*(?:true|True|1)|MinLength\s*=\s*[0-3]\b/g,
    'Empty or extremely short passwords are accepted. Enforce a minimum length (8+) and a breached-password check.'),

  // ── Default credentials ───────────────────────────────────────────────────
  pat('a07-default-creds', V.INSECURE_AUTH, S.HIGH, 0.86,
    /(?:username|user|login|email)\s*[:=]\s*["'](?:admin|root|test|user)["'][^\n]{0,80}(?:password|passwd|pwd)\s*[:=]\s*["'](?:admin|root|password|pass|123456|test)["']|(?:password|passwd)\s*[:=]\s*["'](?:admin|root|password|123456|changeme)["']/gi,
    'Default / textbook credentials in source. Remove them and force a unique password on first boot.',
    { redact: true }),
  pat('a07-in-memory-user-spring', V.INSECURE_AUTH, S.MEDIUM, 0.80,
    /\binMemoryUserDetailsManager\s*\(|\.withUser\s*\(\s*["']admin["']/g,
    'In-memory / default admin user defined in code — acceptable only for local demos, never production.',
    { languages: [...LANGS.JAVA] }),

  // ── Session fixation / client-trusted identity ────────────────────────────
  pat('a07-no-session-regen', V.INSECURE_AUTH, S.MEDIUM, 0.74,
    /\b(?:login|signin|authenticate)\w*\s*(?:=\s*(?:async\s+)?(?:function|\()|:\s*(?:async\s+)?(?:function|\())[^{]{0,200}\{[^}]{0,800}?(?:session|passport)[^}]{0,400}?\}/gi,
    'Login handler does not regenerate the session id — session-fixation risk. Call `req.session.regenerate()` after success.',
    {
      languages: [...LANGS.JS],
      validate: (m) => !/regenerate|rotate|changeSessionId|session\.new/i.test(m[0]),
    }),
  pat('a07-user-from-request', V.INSECURE_AUTH, S.HIGH, 0.88,
    /\b(?:currentUser|current_user|loggedInUser|authUser|req\.user)\s*=\s*(?:req|request)\.(?:body|query|params|headers)\b|\bsetUser\s*\(\s*(?:req|request)\.(?:body|query)/g,
    'Authenticated identity taken from the request body/query — attackers can impersonate any user. Read identity from a verified session/JWT.',
    { languages: [...LANGS.JS] }),
  pat('a07-basic-auth-http', V.INSECURE_AUTH, S.HIGH, 0.82,
    /Authorization["']?\s*[:=]\s*["']Basic\s+|auth\s*:\s*\{\s*username[\s\S]{0,80}http:\/\//g,
    'HTTP Basic credentials appear over (or next to) cleartext HTTP. Use HTTPS and prefer token/session auth.'),
  pat('a07-django-empty-validators', V.INSECURE_AUTH, S.MEDIUM, 0.82,
    /\bAUTH_PASSWORD_VALIDATORS\s*=\s*\[\s*\]/g,
    '`AUTH_PASSWORD_VALIDATORS` is empty — Django will accept any password. Restore the default validators.',
    { languages: ['python'] }),
  pat('a07-flask-secret-weak', V.INSECURE_AUTH, S.HIGH, 0.88,
    /\b(?:app\.secret_key|SECRET_KEY)\s*=\s*["'](?:secret|dev|changeme|flask|development)["']/gi,
    'Flask/Django `SECRET_KEY` is a default string — sessions and CSRF tokens are forgeable. Load a random value from the environment.',
    { languages: ['python'], redact: true }),
  pat('a07-aspnet-allow-anonymous-all', V.INSECURE_AUTH, S.HIGH, 0.80,
    /\[AllowAnonymous\][\s\S]{0,200}class\s+\w*(?:Admin|Account|Auth)/g,
    '`[AllowAnonymous]` on an authentication/admin controller disables access control for every action.',
    { languages: ['csharp'] }),
];

export class AuthFailuresRule extends PatternRule {
  readonly ruleId             = 'SENTINEL-A07-001';
  readonly ruleName           = 'A07 Identification and Authentication Failures Detector';
  readonly vulnerabilityType  = V.INSECURE_AUTH;
  readonly supportedLanguages = APP_LANGS;
  protected readonly patterns = PATTERNS;
}
