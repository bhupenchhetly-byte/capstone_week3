const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const { PORT, JWT_SECRET, JWT_EXPIRES_IN } = require('./config');
const { db, driver, DB_FILE } = require('./db');
const { seedIfEmpty } = require('./database/seed');

const app = express();

// --- MIDDLEWARE SYSTEM ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// --- HELPERS ---
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role });

const insertAudit = db.prepare('INSERT INTO audit_logs (action, performed_by, user_id) VALUES (?, ?, ?)');
const audit = (action, performedBy, userId = null) => insertAudit.run(action, performedBy, userId);

// --- AUTHORIZATION MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access Denied: Token Missing' });

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) return res.status(403).json({ error: 'Session Expired or Corrupted Token' });
    req.user = decodedUser;
    next();
  });
};

// --- HEALTH CHECK (public) ---
app.get('/api/health', (req, res) => {
  const { count } = db.prepare('SELECT COUNT(*) AS count FROM users').get();
  res.json({ status: 'Operational', database: 'connected', driver, users: Number(count) });
});

app.get('/', (req, res) => res.redirect('/login.html'));

// --- AUTHENTICATION ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).trim());
    // Same message for unknown email and wrong password (prevents account guessing)
    const valid = user && (await bcrypt.compare(String(password), user.password_hash));
    if (!valid) return res.status(400).json({ error: 'Invalid email or password.' });

    const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    audit(`User Authentication Success: ${user.email}`, user.name, user.id);
    res.json({ token, user: { name: user.name, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// --- DASHBOARD METRICS ---
app.get('/api/dashboard/metrics', authenticateToken, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  const openTickets = db.prepare("SELECT COUNT(*) AS c FROM support_tickets WHERE status = 'Open'").get().c;
  res.json({
    totalUsers: Number(total),
    openTickets: Number(openTickets),
    activeSessions: 42, // placeholder until real session tracking is built (Week 8+)
    engineStatus: 'Operational',
  });
});

// --- USER CRUD ---
app.get('/api/users', authenticateToken, (req, res) => {
  const { search } = req.query;
  const cols = 'id, name, email, role, created_at';
  if (search) {
    const q = `%${String(search)}%`;
    return res.json(
      db.prepare(`SELECT ${cols} FROM users WHERE name LIKE ? OR email LIKE ? ORDER BY name`).all(q, q)
    );
  }
  res.json(db.prepare(`SELECT ${cols} FROM users ORDER BY name`).all());
});

app.post('/api/users', authenticateToken, async (req, res) => {
  try {
    const { name, email, password, role } = req.body || {};
    if (!name || !String(name).trim()) return res.status(400).json({ error: 'Name is required.' });
    if (!email || !EMAIL_RE.test(String(email))) return res.status(400).json({ error: 'A valid email is required.' });
    if (!password || String(password).length < 6) {
      return res.status(400).json({ error: 'Password is required (minimum 6 characters).' });
    }
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(String(email).trim())) {
      return res.status(400).json({ error: 'Data Conflict: Email already registered.' });
    }

    const id = 'usr_' + crypto.randomBytes(4).toString('hex');
    const hash = await bcrypt.hash(String(password), 10);
    db.prepare('INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)')
      .run(id, String(name).trim(), String(email).trim(), hash, role || 'Staff Admin');

    audit(`Created User Profile: ${email}`, req.user.name, req.user.id);
    res.status(201).json(publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(id)));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'Record not found' });

    const { name, email, role, password } = req.body || {};
    if (email && !EMAIL_RE.test(String(email))) return res.status(400).json({ error: 'A valid email is required.' });
    if (email) {
      const clash = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(String(email).trim(), user.id);
      if (clash) return res.status(400).json({ error: 'Data Conflict: Email already registered.' });
    }
    const changingPassword = password && String(password).trim() !== '';
    if (changingPassword && String(password).length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    const hash = changingPassword ? await bcrypt.hash(String(password), 10) : user.password_hash;
    db.prepare(
      "UPDATE users SET name = ?, email = ?, role = ?, password_hash = ?, updated_at = datetime('now') WHERE id = ?"
    ).run(name || user.name, email ? String(email).trim() : user.email, role || user.role, hash, user.id);

    audit(
      `Updated User Profile ID: ${user.id} (${changingPassword ? 'Password changed individually' : 'Profile fields updated'})`,
      req.user.name,
      req.user.id
    );
    res.json(publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(user.id)));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account.' });
  }
  const result = db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  if (!result.changes) return res.status(404).json({ error: 'Record not found' });
  audit(`Terminated User Record ID: ${req.params.id}`, req.user.name, req.user.id);
  res.json({ success: true, message: 'Record removed' });
});

// --- AUDIT LOG CSV EXPORT (now requires login) ---
const csvCell = (v) => {
  let s = String(v ?? '');
  if (/^[=+\-@]/.test(s)) s = "'" + s; // stop spreadsheet formula injection
  return `"${s.replace(/"/g, '""')}"`;
};
app.get('/api/reports/telemetry-csv', authenticateToken, (req, res) => {
  const rows = db.prepare('SELECT created_at, action, performed_by FROM audit_logs ORDER BY id').all();
  let csv = 'Timestamp,Executed Operational Event,Operator Identity\n';
  for (const r of rows) csv += [r.created_at, r.action, r.performed_by].map(csvCell).join(',') + '\n';
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=telemetry_audit_log.csv');
  res.status(200).send(csv);
});

// --- SUPPORT TICKETS ---
app.post('/api/support/ticket', (req, res) => {
  const { name, email, message } = req.body || {};

  const cleanName = String(name || '').trim();
  const cleanEmail = String(email || '').trim().toLowerCase();
  const cleanMessage = String(message || '').trim();

  if (!cleanName || !cleanEmail || !cleanMessage) {
    return res.status(400).json({
      error: 'Name, email and message are required.'
    });
  }

  if (cleanName.length > 100) {
    return res.status(400).json({
      error: 'Name must not exceed 100 characters.'
    });
  }

  if (!EMAIL_RE.test(cleanEmail)) {
    return res.status(400).json({
      error: 'A valid email is required.'
    });
  }

  if (cleanMessage.length > 2000) {
    return res.status(400).json({
      error: 'Message is too long (max 2000 characters).'
    });
  }

  const result = db.prepare(
    'INSERT INTO support_tickets (name, email, message) VALUES (?, ?, ?)'
  ).run(cleanName, cleanEmail, cleanMessage);

  const ticket = db.prepare(
    'SELECT * FROM support_tickets WHERE id = ?'
  ).get(Number(result.lastInsertRowid));

  res.status(201).json({
    success: true,
    payload: ticket
  });
});

app.get('/api/support/tickets', authenticateToken, (req, res) => {
  res.json(db.prepare('SELECT * FROM support_tickets ORDER BY id DESC').all());
});

// --- START ---
const seeded = seedIfEmpty();
app.listen(PORT, () => {
  console.log('\n=============================================================');
  console.log('PROTO-SERVER RUNNING');
  console.log(`Database : ${DB_FILE} (${driver})${seeded ? ' - seeded with demo data' : ''}`);
  console.log(`Open     : http://localhost:${PORT}/login.html`);
  console.log(`Health   : http://localhost:${PORT}/api/health`);
  console.log('=============================================================\n');
});
