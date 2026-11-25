import './env.js';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { initDb, all, get, run } from './db.js';
import { initCrypto, encrypt, decrypt, safeEqual, hashPassword, verifyPassword } from './crypto.js';
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

// Loads the session and attaches req.ctx = { token, accountId, admin }.
// admin = logged in as ADMIN_USER (account_id is NULL); otherwise a single game account.
async function loadSession(req) {
  const t = getCookie(req, COOKIE);
  if (!t) return null;
  const row = await get('SELECT token, expires, account_id FROM sessions WHERE token = ?', t);
  if (!row || row.expires <= Date.now()) return null;
  const accountId = row.account_id == null ? null : Number(row.account_id);
  // If the account was deleted/disabled, drop the session.
  if (accountId != null) {
    const acc = await get('SELECT id FROM mail_accounts WHERE id = ? AND enabled = 1', accountId);
    if (!acc) return null;
  }
  return { token: t, accountId, admin: accountId == null };
}

async function requireAuth(req, res, next) {
  const ctx = await loadSession(req);
  if (ctx) {
    req.ctx = ctx;
    return next();
  }
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not logged in' });
  res.redirect('/login.html');
}

function requireAdmin(req, res, next) {
  if (req.ctx?.admin) return next();
  res.status(403).json({ error: 'Admin only' });
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
  const uname = String(username || '').trim();

  // 1) Admin login (username + password from env, optional TOTP).
  const isAdmin =
    safeEqual(uname, ADMIN_USER) &&
    safeEqual(password || '', ADMIN_PASSWORD) &&
    (!LOGIN_TOTP_SECRET || verifyTotp(LOGIN_TOTP_SECRET, code));

  // 2) Per-account login (email + that account's web password).
  let accountId = null;
  if (!isAdmin && uname && password) {
    const acc = await get(
      'SELECT id, web_password_hash FROM mail_accounts WHERE username = ? AND enabled = 1',
      uname
    );
    if (acc && verifyPassword(password, acc.web_password_hash)) accountId = acc.id;
  }

  if (!isAdmin && accountId == null) {
    await run('INSERT INTO login_attempts (ip, ts) VALUES (?, ?)', ip, Date.now());
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  await run('DELETE FROM login_attempts WHERE ip = ?', ip);
  const token = crypto.randomBytes(32).toString('hex');
  await run('INSERT INTO sessions (token, expires, account_id) VALUES (?, ?, ?)', token, Date.now() + SESSION_TTL, accountId);
  await run('DELETE FROM sessions WHERE expires < ?', Date.now());
  const secure = req.secure ? '; Secure' : '';
  res.set('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}${secure}`);
  res.json({ ok: true, admin: isAdmin });
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

// Who am I? Drives the UI (admin sees everything, an account sees only itself).
app.get('/api/me', async (req, res) => {
  if (req.ctx.admin) return res.json({ admin: true, username: ADMIN_USER });
  const acc = await get('SELECT username, game_password_enc FROM mail_accounts WHERE id = ?', req.ctx.accountId);
  res.json({
    admin: false,
    account_id: req.ctx.accountId,
    username: acc?.username || '',
    has_game_password: !!acc?.game_password_enc,
  });
});

// ---------- webmail ----------
app.get('/api/messages', async (req, res) => {
  const { q = '', account = '', page = '1' } = req.query;
  const limit = 50;
  const offset = (Math.max(1, Number(page) || 1) - 1) * limit;
  const where = [];
  const params = [];
  // Account users only ever see their own mailbox; admin may filter by one.
  const scope = req.ctx.admin ? (account ? Number(account) : null) : req.ctx.accountId;
  if (scope != null) {
    where.push('m.account_id = ?');
    params.push(scope);
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
  if (!req.ctx.admin && m.account_id !== req.ctx.accountId) return res.status(404).json({ error: 'Not found' });
  await run('UPDATE messages SET seen = 1 WHERE id = ?', m.id);
  res.json(m);
});

app.delete('/api/messages/:id', async (req, res) => {
  const m = await get('SELECT account_id FROM messages WHERE id = ?', Number(req.params.id));
  if (!m) return res.json({ ok: true });
  if (!req.ctx.admin && m.account_id !== req.ctx.accountId) return res.status(404).json({ error: 'Not found' });
  await run('DELETE FROM messages WHERE id = ?', Number(req.params.id));
  res.json({ ok: true });
});

// ---------- IMAP accounts (admin only) ----------
async function publicAccount(a) {
  const { n } = await get('SELECT COUNT(*) AS n FROM messages WHERE account_id = ?', a.id);
  const { o } = await get('SELECT COUNT(*) AS o FROM otp_entries WHERE account_id = ?', a.id);
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
    otp_count: o,
    has_login: !!a.web_password_hash, // can this account log into the web app?
    has_game_password: !!a.game_password_enc,
  };
}
const getAccount = (id) => get('SELECT * FROM mail_accounts WHERE id = ?', Number(id));

app.get('/api/accounts', requireAdmin, async (req, res) => {
  const rows = await all('SELECT * FROM mail_accounts ORDER BY label');
  res.json(await Promise.all(rows.map(publicAccount)));
});

app.post('/api/accounts', requireAdmin, async (req, res) => {
  const {
    label, host, port = 993, secure = true, username, password,
    folders = 'INBOX', web_password, game_password,
  } = req.body || {};
  if (!host || !username || !password) return res.status(400).json({ error: 'Host, username and password are required' });
  try {
    const r = await run(
      `INSERT INTO mail_accounts (label, host, port, secure, username, password_enc, folders, web_password_hash, game_password_enc)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      label || username,
      host.trim(),
      Number(port),
      secure ? 1 : 0,
      username.trim(),
      encrypt(password),
      folders,
      web_password ? hashPassword(web_password) : null,
      game_password ? encrypt(game_password) : null
    );
    const result = await syncAccount(await getAccount(r.lastInsertRowid));
    res.json({ account: await publicAccount(await getAccount(r.lastInsertRowid)), result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Reveal an account's stored game password (admin, or that account's own user).
app.get('/api/accounts/:id/game-password', async (req, res) => {
  const id = Number(req.params.id);
  if (!req.ctx.admin && id !== req.ctx.accountId) return res.status(403).json({ error: 'Forbidden' });
  const acc = await getAccount(id);
  if (!acc) return res.status(404).json({ error: 'Not found' });
  res.json({ game_password: acc.game_password_enc ? decrypt(acc.game_password_enc) : '' });
});

// Bulk import accounts from CSV text. Columns: email, mail_password, game_password[, ...ignored].
//  - mail_password  -> IMAP login (to fetch the mailbox)
//  - game_password  -> stored, shown to that account, AND set as its web-login password
//    (so each account logs into the web app with: email + game password)
// All imported mailboxes share one IMAP server/port/folders. Does not sync them
// (the sync loop / cron picks them up) so the request stays fast.
app.post('/api/accounts/import', requireAdmin, async (req, res) => {
  const { csv = '', host, port = 993, secure = true, folders = 'INBOX' } = req.body || {};
  if (!host || !host.trim()) return res.status(400).json({ error: 'IMAP server host is required' });
  const h = host.trim();
  let added = 0;
  let updated = 0;
  let skipped = 0;
  const errors = [];
  for (const line of String(csv).split(/\r?\n/)) {
    const cols = line.split(',');
    const email = (cols[0] || '').trim();
    const mailPassword = (cols[1] || '').trim();
    const gamePassword = (cols[2] || '').trim();
    if (!email || !mailPassword) { skipped++; continue; }
    if (!email.includes('@') || email.toLowerCase() === 'email') { skipped++; continue; } // header / junk
    try {
      const existing = await get('SELECT id FROM mail_accounts WHERE host = ? AND username = ?', h, email);
      await run(
        `INSERT INTO mail_accounts
           (label, host, port, secure, username, password_enc, folders, web_password_hash, game_password_enc)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(host, username) DO UPDATE SET
           password_enc = excluded.password_enc, port = excluded.port,
           secure = excluded.secure, folders = excluded.folders,
           web_password_hash = COALESCE(excluded.web_password_hash, mail_accounts.web_password_hash),
           game_password_enc = COALESCE(excluded.game_password_enc, mail_accounts.game_password_enc)`,
        email, h, Number(port), secure ? 1 : 0, email, encrypt(mailPassword), folders || 'INBOX',
        gamePassword ? hashPassword(gamePassword) : null,
        gamePassword ? encrypt(gamePassword) : null
      );
      if (existing) updated++; else added++;
    } catch (e) {
      errors.push(email + ': ' + e.message);
    }
  }
  res.json({ added, updated, skipped, errors: errors.slice(0, 20) });
});

app.patch('/api/accounts/:id', requireAdmin, async (req, res) => {
  const acc = await getAccount(req.params.id);
  if (!acc) return res.status(404).json({ error: 'Not found' });
  const b = req.body || {};
  // web_password: '' clears the web login, a string sets it, undefined keeps it.
  let webHash = acc.web_password_hash;
  if (b.web_password !== undefined) webHash = b.web_password ? hashPassword(b.web_password) : null;
  let gameEnc = acc.game_password_enc;
  if (b.game_password !== undefined) gameEnc = b.game_password ? encrypt(b.game_password) : null;
  await run(
    `UPDATE mail_accounts SET label = ?, host = ?, port = ?, secure = ?, username = ?, password_enc = ?,
       folders = ?, enabled = ?, web_password_hash = ?, game_password_enc = ? WHERE id = ?`,
    b.label ?? acc.label,
    b.host ?? acc.host,
    Number(b.port ?? acc.port),
    b.secure === undefined ? acc.secure : b.secure ? 1 : 0,
    b.username ?? acc.username,
    b.password ? encrypt(b.password) : acc.password_enc,
    b.folders ?? acc.folders,
    b.enabled === undefined ? acc.enabled : b.enabled ? 1 : 0,
    webHash,
    gameEnc,
    acc.id
  );
  res.json(await publicAccount(await getAccount(acc.id)));
});

// Remove ALL mailboxes (and their downloaded messages). Used to undo a bad bulk import.
app.delete('/api/accounts', requireAdmin, async (req, res) => {
  const { n } = await get('SELECT COUNT(*) AS n FROM mail_accounts');
  await run('DELETE FROM messages');
  await run('DELETE FROM folder_state');
  await run('DELETE FROM otp_entries WHERE account_id IS NOT NULL');
  await run('DELETE FROM sessions WHERE account_id IS NOT NULL');
  await run('DELETE FROM mail_accounts');
  res.json({ ok: true, removed: n });
});

app.delete('/api/accounts/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  await run('DELETE FROM messages WHERE account_id = ?', id);
  await run('DELETE FROM folder_state WHERE account_id = ?', id);
  await run('DELETE FROM otp_entries WHERE account_id = ?', id);
  await run('DELETE FROM sessions WHERE account_id = ?', id);
  await run('DELETE FROM mail_accounts WHERE id = ?', id);
  res.json({ ok: true });
});

// body: { id } to sync one account, { stale: true } for a stale-only pass (admin).
// An account user can only sync their own mailbox.
app.post('/api/sync', async (req, res) => {
  const { id, stale } = req.body || {};
  if (!req.ctx.admin) {
    const acc = await getAccount(req.ctx.accountId);
    if (!acc) return res.status(404).json({ error: 'Not found' });
    return res.json({ [acc.id]: await syncAccount(acc) });
  }
  if (id) {
    const acc = await getAccount(id);
    if (!acc) return res.status(404).json({ error: 'Not found' });
    return res.json({ [id]: await syncAccount(acc) });
  }
  res.json(await syncAll({ staleSec: stale ? Number(SYNC_INTERVAL) : 0 }));
});

// ---------- authenticator ----------
// Each 2FA entry belongs to an account (account_id). Admin entries have account_id NULL.
// An account user only sees/manages its own; admin sees all.
async function ownedOtp(req, id) {
  const e = await get('SELECT * FROM otp_entries WHERE id = ?', Number(id));
  if (!e) return null;
  if (!req.ctx.admin && e.account_id !== req.ctx.accountId) return null;
  return e;
}

app.get('/api/otp', async (req, res) => {
  const rows = req.ctx.admin
    ? await all('SELECT * FROM otp_entries ORDER BY issuer, name')
    : await all('SELECT * FROM otp_entries WHERE account_id = ? ORDER BY issuer, name', req.ctx.accountId);
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
    let { issuer = '', name = '', secret = '', digits = 6, period = 30, algorithm = 'SHA1', uri, account_id } = req.body || {};
    // Account users always attach to their own account; admin may target one (or leave global).
    const accountId = req.ctx.admin ? (account_id != null ? Number(account_id) : null) : req.ctx.accountId;
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
      `INSERT INTO otp_entries (account_id, issuer, name, secret_enc, digits, period, algorithm, created)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      accountId,
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
  const e = await ownedOtp(req, req.params.id);
  if (!e) return res.status(404).json({ error: 'Not found' });
  await run('UPDATE otp_entries SET issuer = ?, name = ? WHERE id = ?', issuer ?? e.issuer, name ?? e.name, e.id);
  res.json({ ok: true });
});

app.get('/api/otp/:id/secret', async (req, res) => {
  const e = await ownedOtp(req, req.params.id);
  if (!e) return res.status(404).json({ error: 'Not found' });
  res.json({ secret: decrypt(e.secret_enc) });
});

app.delete('/api/otp/:id', async (req, res) => {
  const e = await ownedOtp(req, req.params.id);
  if (!e) return res.status(404).json({ error: 'Not found' });
  await run('DELETE FROM otp_entries WHERE id = ?', e.id);
  res.json({ ok: true });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Server error' });
});

export default app;
