import './env.js';
import crypto from 'node:crypto';
import path from 'node:path';
import express from 'express';
import { db } from './db.js';
import { initCrypto, encrypt, decrypt, safeEqual } from './crypto.js';
import { totp, verifyTotp, normalizeSecret, parseOtpauth } from './totp.js';
import { syncAccount, syncAll, startSyncLoop } from './imapSync.js';

const {
  ADMIN_USER = 'admin',
  ADMIN_PASSWORD,
  LOGIN_TOTP_SECRET,
  APP_SECRET,
  PORT = 3000,
  TRUST_PROXY = '0',
  SYNC_INTERVAL = '60',
} = process.env;

if (!ADMIN_PASSWORD) {
  console.error('Chybí ADMIN_PASSWORD v .env');
  process.exit(1);
}
initCrypto(APP_SECRET);

// ---------- seed IMAP účtu z .env ----------
if (process.env.IMAP_HOST && process.env.IMAP_USER && process.env.IMAP_PASSWORD) {
  db.prepare(
    `INSERT INTO mail_accounts (label, host, port, secure, username, password_enc, folders)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(host, username) DO UPDATE SET
       port = excluded.port, secure = excluded.secure,
       password_enc = excluded.password_enc, folders = excluded.folders`
  ).run(
    process.env.IMAP_USER,
    process.env.IMAP_HOST,
    Number(process.env.IMAP_PORT || 993),
    process.env.IMAP_SECURE === '0' ? 0 : 1,
    process.env.IMAP_USER,
    encrypt(process.env.IMAP_PASSWORD),
    process.env.IMAP_FOLDERS || 'INBOX'
  );
}

const app = express();
if (TRUST_PROXY === '1') app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.set({
    'X-Frame-Options': 'SAMEORIGIN',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
  next();
});

// ---------- session ----------
const SESSION_TTL = 7 * 24 * 3600 * 1000;
const COOKIE = 'sid';

function getCookie(req, name) {
  const m = (req.headers.cookie || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}

function isAuthed(req) {
  const t = getCookie(req, COOKIE);
  if (!t) return false;
  const row = db.prepare('SELECT expires FROM sessions WHERE token = ?').get(t);
  return !!row && row.expires > Date.now();
}

function requireAuth(req, res, next) {
  if (isAuthed(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Nepřihlášen' });
  res.redirect('/login.html');
}

// jednoduchý rate-limit na login
const attempts = new Map();
function tooMany(ip) {
  const now = Date.now();
  const a = (attempts.get(ip) || []).filter((t) => now - t < 15 * 60 * 1000);
  attempts.set(ip, a);
  return a.length >= 10;
}

app.get('/api/login-info', (req, res) => res.json({ totp: !!LOGIN_TOTP_SECRET }));

app.post('/api/login', (req, res) => {
  const ip = req.ip;
  if (tooMany(ip)) return res.status(429).json({ error: 'Příliš mnoho pokusů, zkus to za 15 minut.' });
  const { username, password, code } = req.body || {};
  const okUser = safeEqual(username || '', ADMIN_USER);
  const okPass = safeEqual(password || '', ADMIN_PASSWORD);
  const okCode = !LOGIN_TOTP_SECRET || verifyTotp(LOGIN_TOTP_SECRET, code);
  if (!(okUser && okPass && okCode)) {
    attempts.get(ip).push(Date.now());
    return res.status(401).json({ error: 'Špatné přihlašovací údaje' });
  }
  attempts.delete(ip);
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, expires) VALUES (?, ?)').run(token, Date.now() + SESSION_TTL);
  db.prepare('DELETE FROM sessions WHERE expires < ?').run(Date.now());
  const secure = req.secure ? '; Secure' : '';
  res.set(
    'Set-Cookie',
    `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}${secure}`
  );
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  const t = getCookie(req, COOKIE);
  if (t) db.prepare('DELETE FROM sessions WHERE token = ?').run(t);
  res.set('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
  res.json({ ok: true });
});

const pub = path.resolve('public');
app.get(['/login.html', '/style.css', '/login.js'], (req, res) => res.sendFile(path.join(pub, req.path)));

app.use(requireAuth);
app.use(express.static(pub));

// ---------- webmail ----------
app.get('/api/messages', (req, res) => {
  const { q = '', account = '', page = '1' } = req.query;
  const limit = 50;
  const offset = (Math.max(1, Number(page)) - 1) * limit;
  const where = [];
  const params = [];
  if (account) {
    where.push('m.account_id = ?');
    params.push(Number(account));
  }
  if (q) {
    where.push('(m.subject LIKE ? OR m.from_addr LIKE ? OR m.to_addr LIKE ? OR m.text LIKE ?)');
    const like = `%${q}%`;
    params.push(like, like, like, like);
  }
  const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const rows = db
    .prepare(
      `SELECT m.id, m.account_id, a.label AS account, m.folder, m.date, m.from_addr, m.to_addr,
              m.subject, m.snippet, m.seen
       FROM messages m JOIN mail_accounts a ON a.id = m.account_id
       ${w} ORDER BY m.date DESC LIMIT ${limit} OFFSET ${offset}`
    )
    .all(...params);
  const { n } = db.prepare(`SELECT COUNT(*) AS n FROM messages m ${w}`).get(...params);
  res.json({ messages: rows, total: n, limit });
});

app.get('/api/messages/:id', (req, res) => {
  const m = db
    .prepare(
      `SELECT m.*, a.label AS account FROM messages m JOIN mail_accounts a ON a.id = m.account_id WHERE m.id = ?`
    )
    .get(Number(req.params.id));
  if (!m) return res.status(404).json({ error: 'Nenalezeno' });
  db.prepare('UPDATE messages SET seen = 1 WHERE id = ?').run(m.id);
  res.json(m);
});

app.delete('/api/messages/:id', (req, res) => {
  db.prepare('DELETE FROM messages WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

// ---------- IMAP účty ----------
const publicAccount = (a) => ({
  id: a.id,
  label: a.label,
  host: a.host,
  port: a.port,
  secure: !!a.secure,
  username: a.username,
  folders: a.folders,
  enabled: !!a.enabled,
  last_sync: a.last_sync,
  last_error: a.last_error,
  count: db.prepare('SELECT COUNT(*) AS n FROM messages WHERE account_id = ?').get(a.id).n,
});

app.get('/api/accounts', (req, res) => {
  res.json(db.prepare('SELECT * FROM mail_accounts ORDER BY label').all().map(publicAccount));
});

app.post('/api/accounts', async (req, res) => {
  const { label, host, port = 993, secure = true, username, password, folders = 'INBOX' } = req.body || {};
  if (!host || !username || !password) return res.status(400).json({ error: 'Vyplň host, uživatele a heslo' });
  try {
    const r = db
      .prepare(
        `INSERT INTO mail_accounts (label, host, port, secure, username, password_enc, folders)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(label || username, host.trim(), Number(port), secure ? 1 : 0, username.trim(), encrypt(password), folders);
    const acc = db.prepare('SELECT * FROM mail_accounts WHERE id = ?').get(r.lastInsertRowid);
    const result = await syncAccount(acc);
    res.json({ account: publicAccount(db.prepare('SELECT * FROM mail_accounts WHERE id = ?').get(acc.id)), result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.patch('/api/accounts/:id', (req, res) => {
  const acc = db.prepare('SELECT * FROM mail_accounts WHERE id = ?').get(Number(req.params.id));
  if (!acc) return res.status(404).json({ error: 'Nenalezeno' });
  const b = req.body || {};
  db.prepare(
    `UPDATE mail_accounts SET label = ?, host = ?, port = ?, secure = ?, username = ?, password_enc = ?,
       folders = ?, enabled = ? WHERE id = ?`
  ).run(
    b.label ?? acc.label,
    b.host ?? acc.host,
    Number(b.port ?? acc.port),
    b.secure === undefined ? acc.secure : b.secure ? 1 : 0,
    b.username ?? acc.username,
    b.password ? encrypt(b.password) : acc.password_enc,
    b.folders ?? acc.folders,
    b.enabled === undefined ? acc.enabled : b.enabled ? 1 : 0,
    acc.id
  );
  res.json(publicAccount(db.prepare('SELECT * FROM mail_accounts WHERE id = ?').get(acc.id)));
});

app.delete('/api/accounts/:id', (req, res) => {
  db.prepare('DELETE FROM mail_accounts WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

app.post('/api/sync', async (req, res) => {
  const id = req.body?.id;
  if (id) {
    const acc = db.prepare('SELECT * FROM mail_accounts WHERE id = ?').get(Number(id));
    if (!acc) return res.status(404).json({ error: 'Nenalezeno' });
    return res.json({ [id]: await syncAccount(acc) });
  }
  res.json(await syncAll());
});

// ---------- Authenticator ----------
app.get('/api/otp', (req, res) => {
  const rows = db.prepare('SELECT * FROM otp_entries ORDER BY issuer, name').all();
  const now = Date.now();
  res.json(
    rows.map((r) => {
      let out;
      try {
        out = totp(decrypt(r.secret_enc), { period: r.period, digits: r.digits, algorithm: r.algorithm, time: now });
      } catch (e) {
        out = { code: 'CHYBA', next: '', remaining: 0, error: e.message };
      }
      return { id: r.id, issuer: r.issuer, name: r.name, period: r.period, digits: r.digits, ...out };
    })
  );
});

app.post('/api/otp', (req, res) => {
  try {
    let { issuer = '', name = '', secret = '', digits = 6, period = 30, algorithm = 'SHA1', uri } = req.body || {};
    if (uri || String(secret).startsWith('otpauth://')) {
      const p = parseOtpauth(uri || secret);
      issuer = issuer || p.issuer;
      name = name || p.name;
      ({ secret, digits, period, algorithm } = p);
    }
    secret = normalizeSecret(secret);
    algorithm = String(algorithm).toUpperCase();
    if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) throw new Error('Nepodporovaný algoritmus');
    if (![6, 7, 8].includes(Number(digits))) throw new Error('Počet číslic musí být 6–8');
    if (!name) name = issuer || 'Účet';
    const r = db
      .prepare(
        `INSERT INTO otp_entries (issuer, name, secret_enc, digits, period, algorithm, created)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(issuer, name, encrypt(secret), Number(digits), Number(period) || 30, algorithm, Date.now());
    res.json({ id: Number(r.lastInsertRowid) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.patch('/api/otp/:id', (req, res) => {
  const { issuer, name } = req.body || {};
  const e = db.prepare('SELECT * FROM otp_entries WHERE id = ?').get(Number(req.params.id));
  if (!e) return res.status(404).json({ error: 'Nenalezeno' });
  db.prepare('UPDATE otp_entries SET issuer = ?, name = ? WHERE id = ?').run(issuer ?? e.issuer, name ?? e.name, e.id);
  res.json({ ok: true });
});

app.get('/api/otp/:id/secret', (req, res) => {
  const e = db.prepare('SELECT * FROM otp_entries WHERE id = ?').get(Number(req.params.id));
  if (!e) return res.status(404).json({ error: 'Nenalezeno' });
  res.json({ secret: decrypt(e.secret_enc) });
});

app.delete('/api/otp/:id', (req, res) => {
  db.prepare('DELETE FROM otp_entries WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

app.listen(Number(PORT), () => {
  console.log(`G2G Auth běží na http://localhost:${PORT}`);
  startSyncLoop(Number(SYNC_INTERVAL));
});
