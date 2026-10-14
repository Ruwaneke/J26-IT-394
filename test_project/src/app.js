/**
 * Sample Express Application — Core Server Setup
 *
 * Contains intentional security misconfigurations to verify Sentinel detection:
 *  - OWASP A01 / A05: Permissive CORS configuration (wildcard origin)
 *  - OWASP A04: Insecure file upload via multer with no file filter or size limits
 *  - OWASP A05: Stack trace and internal error exposure in error handler
 *  - OWASP A07: Session middleware configured with a weak/default secret
 *  - OWASP A09: Logging sensitive raw request body to console
 */

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const session = require('express-session');

const app = express();
app.use(express.json());

// ── VULNERABILITY A01/A05: Permissive CORS Wildcard ──────────────────────────
// Allowing '*' allows any malicious website to read responses from this API
app.use(cors({ origin: '*' }));

// ── VULNERABILITY A07: Session With Weak / Default Secret ────────────────────
// Using well-known default secret allows attackers to forge session cookies
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true
}));

// ── VULNERABILITY A04: Insecure Design - Unrestricted File Upload ─────────────
// Multer configured without `fileFilter` or `limits` allows arbitrary file uploads
const upload = multer({ dest: 'uploads/' });

app.post('/api/upload', upload.single('document'), (req, res) => {
  // ── VULNERABILITY A09: Logging entire raw request body ─────────────────────
  console.log(req.body);
  res.json({ message: 'File uploaded successfully' });
});

// Import route modules
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const fileRoutes = require('./routes/fileRoutes');
const apiRoutes = require('./routes/apiRoutes');
const uiRoutes = require('./routes/uiRoutes');

app.use('/auth', authRoutes);
app.use('/users', userRoutes);
app.use('/files', fileRoutes);
app.use('/api', apiRoutes);
app.use('/ui', uiRoutes);

// ── VULNERABILITY A05: Security Misconfiguration - Stack Trace Exposure ───────
// Returning raw err.stack exposes internal directory paths, libraries, and logic
app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});

module.exports = app;
