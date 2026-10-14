/**
 * File Management & Navigation Routes
 *
 * Demonstrates broken access control and insecure design patterns:
 *  - OWASP A01: Path Traversal via untrusted file path
 *  - OWASP A01: Open Redirect via untrusted URL parameter
 *  - OWASP A04: Insecure Design authentication bypass flag
 */

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

// ── VULNERABILITY A04: Insecure Design - Authentication Bypass Flag ───────────
// Hardcoded bypass flags allow unauthorized access and backdoors
const skip_auth = true;

router.get('/download', (req, res) => {
  // ── VULNERABILITY A01: Path Traversal (Arbitrary File Read) ─────────────────
  // Attackers passing '../../../../etc/passwd' can escape the uploads directory
  const userFile = req.query.file;
  const filePath = path.join('/var/uploads', userFile);
  const content = fs.readFileSync(filePath, 'utf8');

  res.send(content);
});

router.get('/external-redirect', (req, res) => {
  // ── VULNERABILITY A01: Open Redirect ─────────────────────────────────────────
  // Redirecting to an unvalidated user-controlled URL enables phishing attacks
  const target = req.query.returnUrl;
  res.redirect(target);
});

module.exports = router;
