import fs from 'node:fs';
import path from 'node:path';
import { createClient } from '@libsql/client';

// DATABASE_URL:
//   - libsql://your-db.turso.io  (Turso – free, used on Vercel / serverless hosts)
//   - file:data/app.db           (local file – default)
let url = process.env.DATABASE_URL || process.env.TURSO_DATABASE_URL;
const isLocal = !url || url.startsWith('file:');
let client;

function db() {
  if (client) return client;
  if (!url) {
    if (process.env.VERCEL) {
      throw new Error('DATABASE_URL is not set. On Vercel you need a Turso database (see README).');
    }
    const dir = path.resolve(process.env.DATA_DIR || 'data');
    fs.mkdirSync(dir, { recursive: true });
    url = 'file:' + path.join(dir, 'app.db');
  }
  client = createClient({ url, authToken: process.env.DATABASE_AUTH_TOKEN || process.env.TURSO_AUTH_TOKEN });
  return client;
}

export async function all(sql, ...args) {
  return (await db().execute({ sql, args })).rows;
}
export async function get(sql, ...args) {
  return (await all(sql, ...args))[0];
}
export async function run(sql, ...args) {
  const r = await db().execute({ sql, args });
  return { changes: r.rowsAffected, lastInsertRowid: Number(r.lastInsertRowid ?? 0) };
}

export async function initDb() {
  if (isLocal) await db().execute('PRAGMA journal_mode = WAL');
  await db().executeMultiple(`
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  expires INTEGER NOT NULL,
  account_id INTEGER
);

CREATE TABLE IF NOT EXISTS login_attempts (
  ip TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(ip, ts);

CREATE TABLE IF NOT EXISTS mail_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  label TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 993,
  secure INTEGER NOT NULL DEFAULT 1,
  username TEXT NOT NULL,
  password_enc TEXT NOT NULL,
  folders TEXT NOT NULL DEFAULT 'INBOX',
  enabled INTEGER NOT NULL DEFAULT 1,
  last_sync INTEGER,
  last_error TEXT,
  web_password_hash TEXT,
  game_password_enc TEXT,
  UNIQUE(host, username)
);

CREATE TABLE IF NOT EXISTS folder_state (
  account_id INTEGER NOT NULL,
  folder TEXT NOT NULL,
  uidvalidity TEXT,
  last_uid INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (account_id, folder)
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL,
  folder TEXT NOT NULL,
  uid INTEGER NOT NULL,
  message_id TEXT,
  date INTEGER,
  from_addr TEXT,
  to_addr TEXT,
  subject TEXT,
  snippet TEXT,
  text TEXT,
  html TEXT,
  seen INTEGER NOT NULL DEFAULT 0,
  UNIQUE(account_id, folder, uid)
);
CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date DESC);

CREATE TABLE IF NOT EXISTS otp_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER,
  issuer TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  secret_enc TEXT NOT NULL,
  digits INTEGER NOT NULL DEFAULT 6,
  period INTEGER NOT NULL DEFAULT 30,
  algorithm TEXT NOT NULL DEFAULT 'SHA1',
  created INTEGER NOT NULL
);
`);

  // Migrations for databases created by an earlier version (ignore "duplicate column").
  for (const sql of [
    'ALTER TABLE sessions ADD COLUMN account_id INTEGER',
    'ALTER TABLE mail_accounts ADD COLUMN web_password_hash TEXT',
    'ALTER TABLE mail_accounts ADD COLUMN game_password_enc TEXT',
    'ALTER TABLE otp_entries ADD COLUMN account_id INTEGER',
  ]) {
    try {
      await db().execute(sql);
    } catch (e) {
      if (!/duplicate column/i.test(String(e.message || e))) throw e;
    }
  }
}
