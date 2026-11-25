import './env.js';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { initDb, all, get, run } from './db.js';
import { initCrypto, encrypt, decrypt, safeEqual } from './crypto.js';
import { totp, verifyTotp, normalizeSecret, parseOtpauth } from './totp.js';
import { syncAccount, syncAll } from './imapSync.js';

const {
  ADMIN_USER = 'admin',
  ADMIN_PASSWORD,
  LOGIN_TOTP_SECRET,
  APP_SECRET,
  CRON_SECRET,
  SYNC_INTERVAL = '60',
} = process.env;

const PUBLIC_DIR = fileURLToPath(new URL('../public', import.meta.url));

// ---------- one-time init (works for both a long-running server and serverless) ----------
let readyPromise;
export function ready() {
  readyPromise ??= (async () => {
    if (!ADMIN_PASSWORD) throw new Error('ADMIN_PASSWORD is not set');
    initCrypto(APP_SECRET);
    await initDb();
    // Seed an IMAP account from env vars (optional)
    if (process.env.IMAP_HOST && process.env.IMAP_USER && process.env.IMAP_PASSWORD) {
      await run(
        `INSERT INTO mail_accounts (label, host, port, secure, username, password_enc, folders)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(host, username) DO UPDATE SET
           port = excluded.port, secure = excluded.secure,
           password_enc = excluded.password_enc, folders = excluded.folders`,
        process.env.IMAP_USER,
        process.env.IMAP_HOST,
        Number(process.env.IMAP_PORT || 993),
        process.env.IMAP_SECURE === '0' ? 0 : 1,
        process.env.IMAP_USER,
        encrypt(process.env.IMAP_PASSWORD),
        process.env.IMAP_FOLDERS || 'INBOX'
      );
    }
  })();
  readyPromise.catch(() => (readyPromise = undefined)); // retry on next request
  return readyPromise;
}

export const app = express();
if (process.env.TRUST_PROXY === '1' || process.env.VERCEL) app.set('trust proxy', true);
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(async (req, res, next) => {
  res.set({
    'X-Frame-Options': 'SAMEORIGIN',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
  try {
    await ready();
    next();
  } catch (e) {
    console.error(e);
    res.status(500).type('text').send('Server misconfigured: ' + e.message);
  }
});

// ---------- sessions ----------
const SESSION_TTL = 7 * 24 * 3600 * 1000;
const COOKIE = 'sid';

function getCookie(req, name) {
  const m = (req.headers.cookie || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}

async function isAuthed(req) {
  const t = getCookie(req, COOKIE);
  if (!t) return false;
  const row = await get('SELECT expires FROM sessions WHERE token = ?', t);
  return !!row && row.expires > Date.now();
}

async function requireAuth(req, res, next) {
  if (await isAuthed(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not logged in' });
  res.redirect('/login.html');
}

// ---------- login (rate-limited: 10 failed attempts / 15 min per IP) ----------
const WINDOW = 15 * 60 * 1000;

app.get('/api/login-info', (req, res) => res.json({ totp: !!LOGIN_TOTP_SECRET }));

app.post('/api/login', async (req, res) => {
  const ip = req.ip || 'unknown';
  await run('DELETE FROM login_attempts WHERE ts < ?', Date.now() - WINDOW);
  const { n } = await get('SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ?', ip);
  if (n >= 10) return res.status(429).json({ error: 'Too many attempts, try again in 15 minutes.' });

  const { username, password, code } = req.body || {};
  const okUser = safeEqual(username || '', ADMIN_USER);
  const okPass = safeEqual(password || '', ADMIN_PASSWORD);
  const okCode = !LOGIN_TOTP_SECRET || verifyTotp(LOGIN_TOTP_SECRET, code);
  if (!(okUser && okPass && okCode)) {
    await run('INSERT INTO login_attempts (ip, ts) VALUES (?, ?)', ip, Date.now());
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  await run('DELETE FROM login_attempts WHERE ip = ?', ip);
  const token = crypto.randomBytes(32).toString('hex');
  await run('INSERT INTO sessions (token, expires) VALUES (?, ?)', token, Date.now() + SESSION_TTL);
  await run('DELETE FROM sessions WHERE expires < ?', Date.now());
  const secure = req.secure ? '; Secure' : '';
  res.set('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}${secure}`);
  res.json({ ok: true });
});

app.post('/api/logout', async (req, res) => {
  const t = getCookie(req, COOKIE);
  if (t) await run('DELETE FROM sessions WHERE token = ?', t);
  res.set('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
  res.json({ ok: true });
});

// ---------- cron endpoint (Vercel Cron / cron-job.org / any pinger) ----------
// Vercel Cron sends "Authorization: Bearer $CRON_SECRET"; other pingers can use ?key=CRON_SECRET
app.get('/api/cron', async (req, res) => {
  const auth = req.headers.authorization || '';
  const key = auth.startsWith('Bearer ') ? auth.slice(7) : req.query.key;
  if (!CRON_SECRET || !safeEqual(key || '', CRON_SECRET)) return res.status(401).json({ error: 'Unauthorized' });
  res.json(await syncAll());
});

app.get(['/login.html', '/style.css', '/login.js'], (req, res) => res.sendFile(PUBLIC_DIR + req.path));

app.use(requireAuth);
app.use(express.static(PUBLIC_DIR));

// ---------- webmail ----------
app.get('/api/messages', async (req, res) => {
  const { q = '', account = '', page = '1' } = req.query;
  const limit = 50;
  const offset = (Math.max(1, Number(page) || 1) - 1) * limit;
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
  const rows = await all(
    `SELECT m.id, m.account_id, a.label AS account, m.folder, m.date, m.from_addr, m.to_addr,
            m.subject, m.snippet, m.seen
     FROM messages m JOIN mail_accounts a ON a.id = m.account_id
     ${w} ORDER BY m.date DESC LIMIT ${limit} OFFSET ${offset}`,
    ...params
  );
  const { n } = await get(`SELECT COUNT(*) AS n FROM messages m ${w}`, ...params);
  res.json({ messages: rows, total: n, limit });
});

app.get('/api/messages/:id', async (req, res) => {
  const m = await get(
    `SELECT m.*, a.label AS account FROM messages m JOIN mail_accounts a ON a.id = m.account_id WHERE m.id = ?`,
    Number(req.params.id)
  );
  if (!m) return res.status(404).json({ error: 'Not found' });
  await run('UPDATE messages SET seen = 1 WHERE id = ?', m.id);
  res.json(m);
});

app.delete('/api/messages/:id', async (req, res) => {
  await run('DELETE FROM messages WHERE id = ?', Number(req.params.id));
  res.json({ ok: true });
});

// ---------- IMAP accounts ----------
async function publicAccount(a) {
  const { n } = await get('SELECT COUNT(*) AS n FROM messages WHERE account_id = ?', a.id);
  return {
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
    count: n,
  };
}
const getAccount = (id) => get('SELECT * FROM mail_accounts WHERE id = ?', Number(id));

app.get('/api/accounts', async (req, res) => {
  const rows = await all('SELECT * FROM mail_accounts ORDER BY label');
  res.json(await Promise.all(rows.map(publicAccount)));
});

app.post('/api/accounts', async (req, res) => {
  const { label, host, port = 993, secure = true, username, password, folders = 'INBOX' } = req.body || {};
  if (!host || !username || !password) return res.status(400).json({ error: 'Host, username and password are required' });
  try {
    const r = await run(
      `INSERT INTO mail_accounts (label, host, port, secure, username, password_enc, folders)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      label || username,
      host.trim(),
      Number(port),
      secure ? 1 : 0,
      username.trim(),
      encrypt(password),
      folders
    );
    const result = await syncAccount(await getAccount(r.lastInsertRowid));
    res.json({ account: await publicAccount(await getAccount(r.lastInsertRowid)), result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.patch('/api/accounts/:id', async (req, res) => {
  const acc = await getAccount(req.params.id);
  if (!acc) return res.status(404).json({ error: 'Not found' });
  const b = req.body || {};
  await run(
    `UPDATE mail_accounts SET label = ?, host = ?, port = ?, secure = ?, username = ?, password_enc = ?,
       folders = ?, enabled = ? WHERE id = ?`,
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
  res.json(await publicAccount(await getAccount(acc.id)));
});

app.delete('/api/accounts/:id', async (req, res) => {
  const id = Number(req.params.id);
  await run('DELETE FROM messages WHERE account_id = ?', id);
  await run('DELETE FROM folder_state WHERE account_id = ?', id);
  await run('DELETE FROM mail_accounts WHERE id = ?', id);
  res.json({ ok: true });
});

// body: { id } to sync one account, { stale: true } to sync only accounts not synced in SYNC_INTERVAL
app.post('/api/sync', async (req, res) => {
  const { id, stale } = req.body || {};
  if (id) {
    const acc = await getAccount(id);
    if (!acc) return res.status(404).json({ error: 'Not found' });
    return res.json({ [id]: await syncAccount(acc) });
  }
  res.json(await syncAll({ staleSec: stale ? Number(SYNC_INTERVAL) : 0 }));
});

// ---------- authenticator ----------
app.get('/api/otp', async (req, res) => {
  const rows = await all('SELECT * FROM otp_entries ORDER BY issuer, name');
  const now = Date.now();
  res.json(
    rows.map((r) => {
      let out;
      try {
        out = totp(decrypt(r.secret_enc), { period: r.period, digits: r.digits, algorithm: r.algorithm, time: now });
      } catch (e) {
        out = { code: 'ERROR', next: '', remaining: 0, error: e.message };
      }
      return { id: r.id, issuer: r.issuer, name: r.name, period: r.period, digits: r.digits, ...out };
    })
  );
});

app.post('/api/otp', async (req, res) => {
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
    if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) throw new Error('Unsupported algorithm');
    if (![6, 7, 8].includes(Number(digits))) throw new Error('Digits must be 6-8');
    if (!name) name = issuer || 'Account';
    const r = await run(
      `INSERT INTO otp_entries (issuer, name, secret_enc, digits, period, algorithm, created)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      issuer,
      name,
      encrypt(secret),
      Number(digits),
      Number(period) || 30,
      algorithm,
      Date.now()
    );
    res.json({ id: r.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.patch('/api/otp/:id', async (req, res) => {
  const { issuer, name } = req.body || {};
  const e = await get('SELECT * FROM otp_entries WHERE id = ?', Number(req.params.id));
  if (!e) return res.status(404).json({ error: 'Not found' });
  await run('UPDATE otp_entries SET issuer = ?, name = ? WHERE id = ?', issuer ?? e.issuer, name ?? e.name, e.id);
  res.json({ ok: true });
});

app.get('/api/otp/:id/secret', async (req, res) => {
  const e = await get('SELECT * FROM otp_entries WHERE id = ?', Number(req.params.id));
  if (!e) return res.status(404).json({ error: 'Not found' });
  res.json({ secret: decrypt(e.secret_enc) });
});

app.delete('/api/otp/:id', async (req, res) => {
  await run('DELETE FROM otp_entries WHERE id = ?', Number(req.params.id));
  res.json({ ok: true });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Server error' });
});

export default app;
