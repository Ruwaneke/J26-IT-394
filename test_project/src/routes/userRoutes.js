/**
 * User & Account Routes
 *
 * Demonstrates common SQL Injection patterns and database handling flaws:
 *  - OWASP A03: SQL Injection via string concatenation in query
 *  - OWASP A03: SQL Injection via template literal interpolation
 *  - OWASP A07: Hardcoded database credentials
 *  - OWASP A09: Empty catch block swallowing database error
 */

const express = require('express');
const router = express.Router();

// Mock database interface
const db = {
  query: async (sqlString) => {
    return [{ id: 1, name: 'Admin', email: 'admin@example.com' }];
  }
};

// ── VULNERABILITY A07: Hardcoded Database Password ────────────────────────────
// Passwords should be stored in secure vaults or environment variables
const dbPassword = "SuperAdminPassword2024!";

router.post('/search', async (req, res) => {
  // ── VULNERABILITY A03: Classic String Concatenation SQL Injection ────────────
  // An attacker can input: ' OR '1'='1 to extract the entire database table
  const query = "SELECT * FROM users WHERE email = '" + req.body.email + "'";

  try {
    const results = await db.query(query);
    res.json(results);
  } catch (err) {
    // ── VULNERABILITY A09: Empty catch block swallows errors ─────────────────
    // Critical security faults and database errors vanish without monitoring
  }
});

router.get('/account/:id', async (req, res) => {
  // ── VULNERABILITY A03: Template Literal SQL Injection ────────────────────────
  // Interpolating untrusted variables directly into SQL template literals bypasses escaping
  const sql = `SELECT * FROM accounts WHERE id = ${req.params.id}`;
  
  const account = await db.query(sql);
  res.json(account);
});

module.exports = router;
