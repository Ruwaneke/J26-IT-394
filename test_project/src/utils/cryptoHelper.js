/**
 * Cryptographic Utility Functions
 *
 * Demonstrates weak cryptography, broken ciphers, and predictable randomness:
 *  - OWASP A02: Weak hashing algorithm (MD5) used for password storage
 *  - OWASP A02: Deprecated broken cipher (DES in ECB mode)
 *  - OWASP A02: Predictable pseudo-random generator for security reset tokens
 */

const crypto = require('crypto');

function hashUserPassword(password) {
  // ── VULNERABILITY A02: Password Hashed With Broken/Fast Hash (MD5) ─────────
  // MD5 is vulnerable to collision attacks and fast GPU-based brute forcing.
  // Use bcrypt, scrypt, or Argon2id with appropriate work factors.
  const hash = crypto.createHash('md5').update(password).digest('hex');
  return hash;
}

function encryptSensitiveData(text, key) {
  // ── VULNERABILITY A02: Broken Cipher Primitive (DES in ECB mode) ───────────
  // DES uses a 56-bit key that can be broken in hours; ECB leaks patterns.
  // Use aes-256-gcm with authenticated encryption and a fresh nonce.
  const cipher = crypto.createCipheriv('des-ecb', key, '');
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function generatePasswordResetToken() {
  // ── VULNERABILITY A02: Predictable Randomness For Security Token ────────────
  // Math.random() uses a predictable PRNG (Xoroshiro128+); attackers can predict future tokens.
  // Use crypto.randomBytes(32).toString('hex') instead.
  const resetToken = Math.random().toString(36).substring(2);
  return resetToken;
}

module.exports = {
  hashUserPassword,
  encryptSensitiveData,
  generatePasswordResetToken
};
