// WARDKEY Auth Routes
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const { getDB } = require('../models/db');
const { authenticate } = require('../middleware/auth');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '7d';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;

// ═══════ REGISTER ═══════
router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const db = getDB();
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const id = uuid();
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    db.prepare('INSERT INTO users (id, email, password_hash, name) VALUES (?, ?, ?, ?)').run(id, email.toLowerCase(), hash, name || null);

    const token = jwt.sign({ id, email: email.toLowerCase(), plan: 'free' }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    res.status(201).json({
      token,
      user: { id, email: email.toLowerCase(), name, plan: 'free', mfa_enabled: 0 }
    });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ═══════ LOGIN ═══════
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const db = getDB();
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    // Update last login
    db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

    // If 2FA is enabled, return a temporary token instead of a full session
    if (user.mfa_enabled) {
      const tempToken = jwt.sign(
        { id: user.id, email: user.email, plan: user.plan, purpose: '2fa-verify' },
        JWT_SECRET,
        { expiresIn: '5m' }
      );
      return res.json({ requires2fa: true, tempToken });
    }

    const token = jwt.sign({ id: user.id, email: user.email, plan: user.plan }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    // Create session
    const sessionId = uuid();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare('INSERT INTO sessions (id, user_id, device_name, ip_address, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(sessionId, user.id, req.headers['user-agent']?.substring(0, 100), req.ip, expiresAt);

    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name, plan: user.plan, mfa_enabled: user.mfa_enabled }
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// ═══════ 2FA: SETUP ═══════
router.post('/2fa/setup', authenticate, async (req, res) => {
  try {
    const db = getDB();
    const user = db.prepare('SELECT email, mfa_enabled FROM users WHERE id = ?').get(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const secret = authenticator.generateSecret();
    const otpauthUri = authenticator.keyuri(user.email, 'WARDKEY', secret);
    const qrDataUri = await QRCode.toDataURL(otpauthUri);

    // Store secret but keep mfa_enabled=0 until confirmed
    db.prepare('UPDATE users SET mfa_secret = ? WHERE id = ?').run(secret, req.user.id);

    res.json({ secret, qrDataUri });
  } catch (err) {
    res.status(500).json({ error: '2FA setup failed' });
  }
});

// ═══════ 2FA: CONFIRM (enable after scanning QR) ═══════
router.post('/2fa/confirm', authenticate, async (req, res) => {
  try {
    const { totpCode } = req.body;
    if (!totpCode) return res.status(400).json({ error: 'TOTP code required' });

    const db = getDB();
    const user = db.prepare('SELECT mfa_secret FROM users WHERE id = ?').get(req.user.id);
    if (!user || !user.mfa_secret) return res.status(400).json({ error: '2FA not set up — call /2fa/setup first' });

    const isValid = authenticator.check(totpCode, user.mfa_secret);
    if (!isValid) return res.status(400).json({ error: 'Invalid code — please try again' });

    db.prepare('UPDATE users SET mfa_enabled = 1 WHERE id = ?').run(req.user.id);
    res.json({ success: true, message: '2FA enabled successfully' });
  } catch (err) {
    res.status(500).json({ error: '2FA confirmation failed' });
  }
});

// ═══════ 2FA: VERIFY LOGIN (complete login after 2FA) ═══════
router.post('/2fa/verify-login', async (req, res) => {
  try {
    const { tempToken, totpCode } = req.body;
    if (!tempToken || !totpCode) return res.status(400).json({ error: 'Token and TOTP code required' });

    let decoded;
    try {
      decoded = jwt.verify(tempToken, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Token expired or invalid — please log in again' });
    }

    if (decoded.purpose !== '2fa-verify') {
      return res.status(401).json({ error: 'Invalid token purpose' });
    }

    const db = getDB();
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.id);
    if (!user || !user.mfa_secret) return res.status(401).json({ error: 'Invalid user or 2FA not configured' });

    const isValid = authenticator.check(totpCode, user.mfa_secret);
    if (!isValid) return res.status(401).json({ error: 'Invalid 2FA code' });

    // Issue full token and create session
    const token = jwt.sign({ id: user.id, email: user.email, plan: user.plan }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    const sessionId = uuid();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare('INSERT INTO sessions (id, user_id, device_name, ip_address, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(sessionId, user.id, req.headers['user-agent']?.substring(0, 100), req.ip, expiresAt);

    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name, plan: user.plan, mfa_enabled: user.mfa_enabled }
    });
  } catch (err) {
    res.status(500).json({ error: '2FA verification failed' });
  }
});

// ═══════ 2FA: DISABLE ═══════
router.post('/2fa/disable', authenticate, async (req, res) => {
  try {
    const { totpCode } = req.body;
    if (!totpCode) return res.status(400).json({ error: 'TOTP code required to disable 2FA' });

    const db = getDB();
    const user = db.prepare('SELECT mfa_secret, mfa_enabled FROM users WHERE id = ?').get(req.user.id);
    if (!user || !user.mfa_enabled) return res.status(400).json({ error: '2FA is not enabled' });

    const isValid = authenticator.check(totpCode, user.mfa_secret);
    if (!isValid) return res.status(400).json({ error: 'Invalid code — please try again' });

    db.prepare('UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?').run(req.user.id);
    res.json({ success: true, message: '2FA disabled' });
  } catch (err) {
    res.status(500).json({ error: '2FA disable failed' });
  }
});

// ═══════ PROFILE ═══════
router.get('/me', authenticate, (req, res) => {
  const db = getDB();
  const user = db.prepare('SELECT id, email, name, plan, created_at, last_login, mfa_enabled FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

router.patch('/me', authenticate, async (req, res) => {
  const { name, currentPassword, newPassword } = req.body;
  const db = getDB();

  if (name !== undefined) {
    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, req.user.id);
  }

  if (newPassword) {
    if (!currentPassword) return res.status(400).json({ error: 'Current password required' });
    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password incorrect' });

    const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
  }

  res.json({ success: true });
});

// ═══════ SESSIONS ═══════
router.get('/sessions', authenticate, (req, res) => {
  const db = getDB();
  const sessions = db.prepare('SELECT id, device_name, ip_address, created_at FROM sessions WHERE user_id = ? AND revoked = 0 ORDER BY created_at DESC').all(req.user.id);
  res.json({ sessions });
});

router.delete('/sessions/:id', authenticate, (req, res) => {
  const db = getDB();
  db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ success: true });
});

// ═══════ DELETE ACCOUNT ═══════
router.delete('/me', authenticate, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required for account deletion' });

  const db = getDB();
  const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid password' });

  db.prepare('DELETE FROM users WHERE id = ?').run(req.user.id);
  res.json({ success: true, message: 'Account and all data permanently deleted' });
});

module.exports = router;
