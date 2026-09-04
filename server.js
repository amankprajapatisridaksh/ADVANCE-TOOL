// Minimal auth server for ADVANCE-TOOL
// - Put the bcrypt hash of your access code in .env as BCRYPT_HASH
// - npm install express bcrypt helmet express-rate-limit dotenv
// - Run with: node server.js

require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(helmet());
app.use(express.json());

// Basic rate limiter to slow brute force attempts
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // limit each IP to 30 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/auth', limiter);

// Serve static files (index.html, assets) from repo root
app.use(express.static(path.join(__dirname)));

const BCRYPT_HASH = process.env.BCRYPT_HASH || '';
if (!BCRYPT_HASH) {
  console.warn('Warning: BCRYPT_HASH not set in environment. Authentication will fail.');
}

app.post('/auth', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || typeof password !== 'string') {
      return res.status(400).json({ ok: false, error: 'missing password' });
    }

    // Compare with bcrypt hash stored in env
    const valid = BCRYPT_HASH ? await bcrypt.compare(password, BCRYPT_HASH) : false;
    if (!valid) return res.status(401).json({ ok: false, error: 'invalid' });

    // OK: return ephemeral success. In production, create a session or JWT.
    return res.json({ ok: true, message: 'authorized' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Auth server listening on port ${port}`));
