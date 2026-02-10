// WARDKEY Vault Sync Routes
// IMPORTANT: Server NEVER sees decrypted data. All encryption is client-side.
const express = require('express');
const { v4: uuid } = require('uuid');
const { getDB } = require('../models/db');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

// ═══════ GET VAULT ═══════
// Download encrypted vault blob
router.get('/', authenticate, (req, res) => {
  const db = getDB();
  const vault = db.prepare('SELECT id, encrypted_data, iv, salt, version, updated_at FROM vaults WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1').get(req.user.id);

  if (!vault) {
    return res.json({ vault: null, message: 'No vault found. Upload to create one.' });
  }

  res.json({
    vault: {
      id: vault.id,
      data: vault.encrypted_data,
      iv: vault.iv,
      salt: vault.salt,
      version: vault.version,
      updatedAt: vault.updated_at
    }
  });
});

// ═══════ SYNC VAULT ═══════
// Upload encrypted vault blob (full replace)
router.put('/', authenticate, (req, res) => {
  const { data, iv, salt, version, deviceId } = req.body;
  if (!data || !iv || !salt) {
    return res.status(400).json({ error: 'Missing encrypted data, iv, or salt' });
  }

  const db = getDB();
  const existing = db.prepare('SELECT id, version FROM vaults WHERE user_id = ?').get(req.user.id);

  // Conflict detection
  if (existing && version && existing.version > version) {
    return res.status(409).json({
      error: 'Conflict: server has newer version',
      serverVersion: existing.version,
      clientVersion: version
    });
  }

  const id = existing?.id || uuid();
  const newVersion = (existing?.version || 0) + 1;
  const sizeBytes = Buffer.byteLength(data, 'utf8');

  // Check plan limits (10MB free, 1GB pro)
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.user.id);
  const maxSize = user?.plan === 'pro' ? 1073741824 : 10485760;
  if (sizeBytes > maxSize) {
    return res.status(413).json({ error: 'Vault exceeds plan storage limit', maxBytes: maxSize });
  }

  if (existing) {
    db.prepare('UPDATE vaults SET encrypted_data = ?, iv = ?, salt = ?, version = ?, updated_at = CURRENT_TIMESTAMP, size_bytes = ? WHERE id = ?')
      .run(data, iv, salt, newVersion, sizeBytes, id);
  } else {
    db.prepare('INSERT INTO vaults (id, user_id, encrypted_data, iv, salt, version, size_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(id, req.user.id, data, iv, salt, newVersion, sizeBytes);
  }

  // Log sync
  db.prepare('INSERT INTO sync_log (user_id, device_id, action) VALUES (?, ?, ?)')
    .run(req.user.id, deviceId || 'unknown', 'sync_upload');

  res.json({
    success: true,
    version: newVersion,
    updatedAt: new Date().toISOString()
  });
});

// ═══════ SYNC STATUS ═══════
router.get('/status', authenticate, (req, res) => {
  const db = getDB();
  const vault = db.prepare('SELECT version, updated_at, size_bytes FROM vaults WHERE user_id = ?').get(req.user.id);
  const lastSync = db.prepare('SELECT timestamp, device_id FROM sync_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1').get(req.user.id);

  res.json({
    hasVault: !!vault,
    version: vault?.version || 0,
    lastUpdated: vault?.updated_at,
    sizeBytes: vault?.size_bytes || 0,
    lastSync: lastSync?.timestamp,
    lastDevice: lastSync?.device_id
  });
});

// ═══════ DELETE VAULT ═══════
router.delete('/', authenticate, (req, res) => {
  const db = getDB();
  db.prepare('DELETE FROM vaults WHERE user_id = ?').run(req.user.id);
  db.prepare('INSERT INTO sync_log (user_id, action) VALUES (?, ?)').run(req.user.id, 'vault_deleted');
  res.json({ success: true, message: 'Vault deleted from server' });
});

module.exports = router;
