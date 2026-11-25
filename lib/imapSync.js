import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';
import { all, get, run } from './db.js';
import { decrypt } from './crypto.js';

// Limits keep a single sync short enough for serverless functions (Vercel etc.).
// Remaining messages are picked up by the next sync.
const MAX_INITIAL = Number(process.env.SYNC_INITIAL_LIMIT || 200); // newest N on first sync of a folder
const MAX_PER_RUN = Number(process.env.SYNC_BATCH_LIMIT || 100);

const running = new Set();

function addrText(a) {
  if (!a) return '';
  return Array.isArray(a) ? a.map((x) => x.text).join(', ') : a.text || '';
}

async function syncFolder(client, acc, folder) {
  let added = 0;
  const lock = await client.getMailboxLock(folder);
  try {
    const mb = client.mailbox;
    const uidvalidity = String(mb.uidValidity);
    let state = await get('SELECT * FROM folder_state WHERE account_id = ? AND folder = ?', acc.id, folder);

    if (state && state.uidvalidity !== uidvalidity) {
      // Server renumbered UIDs -> download the folder again
      await run('DELETE FROM messages WHERE account_id = ? AND folder = ?', acc.id, folder);
      state = null;
    }
    const firstSync = !state;
    if (firstSync) {
      await run(
        'INSERT OR REPLACE INTO folder_state (account_id, folder, uidvalidity, last_uid) VALUES (?, ?, ?, 0)',
        acc.id,
        folder,
        uidvalidity
      );
      state = { last_uid: 0 };
    }
    if (!mb.exists) return 0;

    let uids = (await client.search({ uid: `${state.last_uid + 1}:*` }, { uid: true })) || [];
    uids = uids.filter((u) => u > state.last_uid).sort((a, b) => a - b);
    if (!uids.length) return 0;
    if (firstSync && uids.length > MAX_INITIAL) uids = uids.slice(-MAX_INITIAL);
    uids = uids.slice(0, MAX_PER_RUN);

    let maxUid = state.last_uid;
    for await (const msg of client.fetch(uids.join(','), { uid: true, flags: true, source: true }, { uid: true })) {
      const parsed = await simpleParser(msg.source);
      const text = parsed.text || '';
      const r = await run(
        `INSERT OR IGNORE INTO messages
           (account_id, folder, uid, message_id, date, from_addr, to_addr, subject, snippet, text, html, seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        acc.id,
        folder,
        msg.uid,
        parsed.messageId || null,
        (parsed.date || new Date()).getTime(),
        addrText(parsed.from),
        addrText(parsed.to),
        parsed.subject || '(no subject)',
        text.replace(/\s+/g, ' ').trim().slice(0, 200),
        text,
        parsed.html || null,
        msg.flags?.has('\\Seen') ? 1 : 0
      );
      added += r.changes;
      if (msg.uid > maxUid) maxUid = msg.uid;
    }
    await run(
      'UPDATE folder_state SET last_uid = MAX(last_uid, ?) WHERE account_id = ? AND folder = ?',
      maxUid,
      acc.id,
      folder
    );
  } finally {
    lock.release();
  }
  return added;
}

export async function syncAccount(acc) {
  if (running.has(acc.id)) return { skipped: true };
  running.add(acc.id);
  let added = 0;
  const secure = !!acc.secure;
  const client = new ImapFlow({
    host: acc.host,
    port: acc.port,
    secure,
    auth: { user: acc.username, pass: decrypt(acc.password_enc) },
    logger: false,
    socketTimeout: 60_000,
    // Plaintext (no-SSL) servers: still allow a STARTTLS upgrade if the server
    // offers one, even with a self-signed cert, instead of failing the connection.
    ...(secure ? {} : { tls: { rejectUnauthorized: false } }),
  });
  try {
    await client.connect();
    const folders = acc.folders.split(',').map((f) => f.trim()).filter(Boolean);
    for (const folder of folders) added += await syncFolder(client, acc, folder);
    await client.logout();
    await run('UPDATE mail_accounts SET last_sync = ?, last_error = NULL WHERE id = ?', Date.now(), acc.id);
    return { added };
  } catch (err) {
    await run(
      'UPDATE mail_accounts SET last_sync = ?, last_error = ? WHERE id = ?',
      Date.now(),
      String(err.responseText || err.message || err),
      acc.id
    );
    try { client.close(); } catch {}
    return { error: String(err.message || err), added };
  } finally {
    running.delete(acc.id);
  }
}

// staleSec: only sync accounts whose last sync is older than this (0 = always)
// concurrency: how many mailboxes to sync at once (important with many mailboxes)
// limit: cap how many mailboxes are synced in this run (0 = all)
export async function syncAll({
  staleSec = 0,
  concurrency = Number(process.env.SYNC_CONCURRENCY || 5),
  limit = Number(process.env.SYNC_ACCOUNTS_PER_RUN || 0),
} = {}) {
  const cutoff = Date.now() - staleSec * 1000;
  // Oldest sync first, so a capped run keeps rotating through all mailboxes.
  let accounts = await all(
    `SELECT * FROM mail_accounts WHERE enabled = 1 AND (last_sync IS NULL OR last_sync < ?)
     ORDER BY last_sync IS NOT NULL, last_sync ASC`,
    staleSec ? cutoff : Date.now() + 1
  );
  if (limit > 0) accounts = accounts.slice(0, limit);

  const results = {};
  let idx = 0;
  async function worker() {
    while (idx < accounts.length) {
      const acc = accounts[idx++];
      results[acc.id] = await syncAccount(acc);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, accounts.length) }, worker));
  return results;
}

export function startSyncLoop(intervalSec) {
  const tick = () =>
    syncAll()
      .then((r) => {
        const total = Object.values(r).reduce((s, x) => s + (x.added || 0), 0);
        if (total) console.log(`[sync] fetched ${total} new messages`);
      })
      .catch((e) => console.error('[sync]', e));
  tick();
  return setInterval(tick, Math.max(15, intervalSec) * 1000);
}
