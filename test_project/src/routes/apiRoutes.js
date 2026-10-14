/**
 * External API & Integration Routes
 *
 * Demonstrates SSRF, Command Injection, and API credentials exposure:
 *  - OWASP A10: Server-Side Request Forgery (SSRF) via direct fetch()
 *  - OWASP A10: SSRF via axios configuration
 *  - OWASP A03: OS Command Injection via child_process.exec()
 *  - OWASP A07: Hardcoded Third-Party API Key
 */

const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const axios = require('axios');

// ── VULNERABILITY A07: Hardcoded Third-Party API Key ──────────────────────────
// Hardcoded cloud and third-party API credentials exposed in source control
const apiKey = "AIzaSyD-1234567890abcdef123456";

router.get('/proxy-fetch', async (req, res) => {
  // ── VULNERABILITY A10: Server-Side Request Forgery (SSRF) ────────────────────
  // Attacker can pass internal IPs (e.g., http://169.254.169.254/latest/meta-data/)
  const target = req.query.url;
  const response = await fetch(target);
  const data = await response.text();
  res.send(data);
});

router.post('/webhook-trigger', async (req, res) => {
  // ── VULNERABILITY A10: SSRF via Axios Configuration ──────────────────────────
  // The server fetches an untrusted destination URL supplied in request body
  const webhookUrl = req.query.webhookUrl;
  const result = await axios({ url: webhookUrl });
  res.json({ status: 'delivered', data: result.data });
});

router.get('/network-ping', (req, res) => {
  // ── VULNERABILITY A03: OS Command Injection ──────────────────────────────────
  // Concatenating user input into shell commands allows arbitrary command execution
  // e.g., host = "8.8.8.8; cat /etc/passwd"
  const host = req.query.host;
  exec("ping -c 4 " + host, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send(stderr);
    }
    res.send(stdout);
  });
});

module.exports = router;
