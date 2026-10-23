// Roha Computer Solution - backend (Express + SQLite + JWT login)
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'change-this-secret-before-going-online';
const KINDS = ['stock', 'sales', 'service'];

const db = new Database(process.env.DB_PATH || path.join(__dirname, 'roha.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, data TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP);
`);
// upgrade older databases (safe to run every time)
try { db.exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'staff'"); } catch {}
try { db.exec("ALTER TABLE records ADD COLUMN created_by TEXT"); } catch {}
db.exec("UPDATE users SET role='owner' WHERE id=(SELECT MIN(id) FROM users)");

const app = express();
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const userCount = () => db.prepare('SELECT COUNT(*) c FROM users').get().c;
const token = u => jwt.sign({ id: u.id, email: u.email, role: u.role }, SECRET, { expiresIn: '7d' });

function auth(req, res, next) {
  try {
    req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    next();
  } catch { res.status(401).json({ error: 'Please log in' }); }
}
const ownerOnly = (req, res, next) =>
  req.user.role === 'owner' ? next() : res.status(403).json({ error: 'Only the owner can do this' });
const kindOk = (req, res, next) =>
  KINDS.includes(req.params.kind) ? next() : res.status(404).json({ error: 'Unknown list' });

// Is this the first run? (no owner account yet)
app.get('/api/status', (req, res) => res.json({ setup: userCount() === 0 }));

// Create the owner account - only allowed once
app.post('/api/register', (req, res) => {
  if (userCount() > 0) return res.status(403).json({ error: 'Owner account already exists' });
  const { email, password } = req.body || {};
  if (!email || !password || password.length < 6)
    return res.status(400).json({ error: 'Email and password (min 6 characters) required' });
  const r = db.prepare('INSERT INTO users(email,hash,role) VALUES(?,?,?)')
    .run(email.toLowerCase().trim(), bcrypt.hashSync(password, 10), 'owner');
  res.json({ token: token({ id: r.lastInsertRowid, email: email.toLowerCase().trim(), role: 'owner' }) });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((email || '').toLowerCase().trim());
  if (!u || !bcrypt.compareSync(password || '', u.hash))
    return res.status(401).json({ error: 'Wrong email or password' });
  res.json({ token: token(u) });
});

app.get('/api/me', auth, (req, res) => res.json({ email: req.user.email, role: req.user.role }));

// Owner manages staff accounts
app.get('/api/users', auth, ownerOnly, (req, res) =>
  res.json(db.prepare('SELECT id,email,role FROM users ORDER BY id').all()));
app.post('/api/users', auth, ownerOnly, (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password || password.length < 6)
    return res.status(400).json({ error: 'Email and password (min 6 characters) required' });
  try {
    db.prepare('INSERT INTO users(email,hash,role) VALUES(?,?,?)')
      .run(email.toLowerCase().trim(), bcrypt.hashSync(password, 10), 'staff');
    res.json({ ok: true });
  } catch { res.status(400).json({ error: 'This email already exists' }); }
});
app.delete('/api/users/:id', auth, ownerOnly, (req, res) => {
  if (+req.params.id === req.user.id) return res.status(400).json({ error: 'You cannot delete yourself' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// Records: stock / sales / service
app.get('/api/records/:kind', auth, kindOk, (req, res) => {
  const rows = db.prepare('SELECT id,data,created_by,created FROM records WHERE kind=? ORDER BY id').all(req.params.kind);
  res.json(rows.map(r => ({ ...JSON.parse(r.data), id: r.id, created_by: r.created_by, created: r.created })));
});

app.post('/api/records/:kind', auth, kindOk, (req, res) => {
  const clean = {};
  for (const [k, v] of Object.entries(req.body || {})) clean[k.slice(0, 30)] = String(v).slice(0, 300);
  const r = db.prepare('INSERT INTO records(kind,data,created_by) VALUES(?,?,?)').run(req.params.kind, JSON.stringify(clean), req.user.email);
  res.json({ id: r.lastInsertRowid, ...clean });
});

// Owner can correct a mistake
app.put('/api/records/:kind/:id', auth, ownerOnly, kindOk, (req, res) => {
  const clean = {};
  for (const [k, v] of Object.entries(req.body || {})) clean[k.slice(0, 30)] = String(v).slice(0, 300);
  const r = db.prepare('UPDATE records SET data=? WHERE kind=? AND id=?').run(JSON.stringify(clean), req.params.kind, req.params.id);
  r.changes ? res.json({ ok: true }) : res.status(404).json({ error: 'Record not found' });
});

app.delete('/api/records/:kind/:id', auth, ownerOnly, kindOk, (req, res) => {
  db.prepare('DELETE FROM records WHERE kind=? AND id=?').run(req.params.kind, req.params.id);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log('Roha Computer Solution running on http://localhost:' + PORT));
