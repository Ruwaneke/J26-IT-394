/**
 * User Interface & Web Presentation Logic
 *
 * Demonstrates Client/Server XSS and Insecure Cookie settings:
 *  - OWASP A03: Cross-Site Scripting (XSS) via innerHTML assignment
 *  - OWASP A03: Cross-Site Scripting (XSS) via document.write()
 *  - OWASP A05: Insecure Cookie Flags (httpOnly: false, secure: false)
 */

const express = require('express');
const router = express.Router();

router.get('/render-comment', (req, res) => {
  // ── VULNERABILITY A03: Cross-Site Scripting (XSS) via document.write ─────────
  // Writing unescaped user input into document allows script execution
  document.write("<p>User Feedback: " + req.query.comment + "</p>");
  res.send('Rendered');
});

router.get('/update-profile-dom', (req, res) => {
  // ── VULNERABILITY A03: DOM-based XSS via innerHTML ────────────────────────────
  // Assigning user input to innerHTML executes malicious <script> or <img onerror> payloads
  const bio = req.query.bio;
  document.getElementById('user-bio').innerHTML = bio;
  res.send('Updated');
});

router.post('/set-session-cookie', (req, res) => {
  const token = 'sample-session-auth-token-12345';

  // ── VULNERABILITY A05: Cookie Missing HttpOnly & Secure Flags ─────────────────
  // httpOnly: false allows JavaScript to steal cookies via XSS
  // secure: false allows cookies to be intercepted over plain HTTP
  res.cookie('authToken', token, { httpOnly: false, secure: false });
  res.json({ success: true });
});

module.exports = router;
