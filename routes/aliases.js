// WARDKEY Email Alias Routes
const express = require('express');
const { v4: uuid } = require('uuid');
const crypto = require('crypto');
const { getDB } = require('../models/db');
const { authenticate } = require('../middleware/auth');

const router = express.Router();
const ALIAS_DOMAIN = process.env.ALIAS_DOMAIN || 'wardkey.email';

// ═══════ LIST ALIASES ═══════
router.get('/', authenticate, (req, res) => {
  const db = getDB();
  const aliases = db.prepare('SELECT * FROM aliases WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json({ aliases });
});

// ═══════ CREATE ALIAS ═══════
router.post('/', authenticate, (req, res) => {
  const { label, targetEmail } = req.body;
  const db = getDB();

  // Check plan limits (free: 3, pro: unlimited)
  const user = db.prepare('SELECT plan, email FROM users WHERE id = ?').get(req.user.id);
  if (user?.plan === 'free') {
    const count = db.prepare('SELECT COUNT(*) as count FROM aliases WHERE user_id = ?').get(req.user.id);
    if (count.count >= 3) {
      return res.status(403).json({ error: 'Free plan limited to 3 aliases. Upgrade to Pro for unlimited.' });
    }
  }

  // Generate random alias
  const random = crypto.randomBytes(4).toString('hex');
  const prefix = (user?.email?.split('@')[0] || 'user').substring(0, 10).replace(/[^a-z0-9]/gi, '');
  const alias = `${prefix}.${random}@${ALIAS_DOMAIN}`;
  const target = targetEmail || user?.email;

  if (!target) return res.status(400).json({ error: 'Target email required' });

  const id = uuid();
  db.prepare('INSERT INTO aliases (id, user_id, alias, target_email, label) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.user.id, alias, target, label || null);

  res.status(201).json({
    id,
    alias,
    targetEmail: target,
    label,
    active: true,
    forwardedCount: 0
  });
});

// ═══════ TOGGLE ALIAS ═══════
router.patch('/:id', authenticate, (req, res) => {
  const { active, label } = req.body;
  const db = getDB();

  const alias = db.prepare('SELECT * FROM aliases WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!alias) return res.status(404).json({ error: 'Alias not found' });

  if (active !== undefined) {
    db.prepare('UPDATE aliases SET active = ? WHERE id = ?').run(active ? 1 : 0, req.params.id);
  }
  if (label !== undefined) {
    db.prepare('UPDATE aliases SET label = ? WHERE id = ?').run(label, req.params.id);
  }

  res.json({ success: true });
});

// ═══════ DELETE ALIAS ═══════
router.delete('/:id', authenticate, (req, res) => {
  const db = getDB();
  const result = db.prepare('DELETE FROM aliases WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Alias not found' });
  res.json({ success: true });
});

// ═══════ INCOMING EMAIL WEBHOOK ═══════
// This endpoint receives forwarded emails from your mail server (Cloudflare Email Routing, Postfix, etc.)
router.post('/incoming', async (req, res) => {
  const { to, from, subject } = req.body;
  if (!to) return res.status(400).json({ error: 'Missing recipient' });

  const db = getDB();
  const alias = db.prepare('SELECT * FROM aliases WHERE alias = ? AND active = 1').get(to.toLowerCase());

  if (!alias) {
    return res.status(404).json({ error: 'Alias not found or inactive', bounce: true });
  }

  // Increment counter
  db.prepare('UPDATE aliases SET forwarded_count = forwarded_count + 1 WHERE id = ?').run(alias.id);

  // In production: use nodemailer to forward the email to alias.target_email
  // For now, just acknowledge
  res.json({
    forward: true,
    target: alias.target_email,
    aliasId: alias.id
  });
});

module.exports = router;
