import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

const dir = path.resolve(process.env.DATA_DIR || 'data');
fs.mkdirSync(dir, { recursive: true });

export const db = new DatabaseSync(path.join(dir, 'app.db'));

db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  expires INTEGER NOT NULL
);

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
  UNIQUE(host, username)
);

CREATE TABLE IF NOT EXISTS folder_state (
  account_id INTEGER NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
  folder TEXT NOT NULL,
  uidvalidity TEXT,
  last_uid INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (account_id, folder)
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
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
  issuer TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  secret_enc TEXT NOT NULL,
  digits INTEGER NOT NULL DEFAULT 6,
  period INTEGER NOT NULL DEFAULT 30,
  algorithm TEXT NOT NULL DEFAULT 'SHA1',
  created INTEGER NOT NULL
);
`);
