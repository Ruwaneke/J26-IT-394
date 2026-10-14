/**
 * Authentication Routes
 *
 * Demonstrates common authentication and secret management flaws:
 *  - OWASP A07: Hardcoded JWT secret key
 *  - OWASP A07: Plaintext password comparison without hashing
 *  - OWASP A07: JWT accepted with algorithm 'none'
 *  - OWASP A07: JWT claims decoded without cryptographic verification
 *  - OWASP A09: Plaintext credentials printed to log/console
 */

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');

// ── VULNERABILITY A07: Hardcoded Secret Key ──────────────────────────────────
// Sensitive keys must never be hardcoded in source code; use environment variables
const jwtSecret = "super-secret-key-1234567890123456";

// Dummy in-memory user table
const usersDb = [
  { id: 1, email: 'developer@example.com', password: 'plainPassword123' }
];

router.post('/login', (req, res) => {
  // ── VULNERABILITY A09: Credential / Password Written to Log ────────────────
  console.log("User login attempt with password: " + req.body.password);

  const user = usersDb.find(u => u.email === req.body.email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // ── VULNERABILITY A07: Plaintext Password Comparison ───────────────────────
  // Passwords must be hashed using bcrypt/Argon2, never compared directly in plaintext
  if (user.password === req.body.password) {
    const token = jwt.sign({ userId: user.id, email: user.email }, jwtSecret);
    return res.json({ token });
  }

  return res.status(401).json({ error: 'Invalid email or password' });
});

router.post('/verify-token', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Token missing' });
  }

  // ── VULNERABILITY A07: JWT Algorithm 'none' Allowed ────────────────────────
  // Attackers can forge arbitrary valid tokens by omitting the cryptographic signature
  try {
    const payload = jwt.verify(token, jwtSecret, { algorithms: ['none'] });
    return res.json({ valid: true, payload });
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
});

router.get('/profile-unverified', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  // ── VULNERABILITY A07: JWT Decoded Without Verification ────────────────────
  // jwt.decode() does not verify the signature; attacker claims are blindly trusted
  const decoded = jwt.decode(token);
  return res.json({ profile: decoded });
});

module.exports = router;
