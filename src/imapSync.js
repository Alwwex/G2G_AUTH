import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';
import { db } from './db.js';
import { decrypt } from './crypto.js';

const running = new Set();

function addrText(a) {
  if (!a) return '';
  return Array.isArray(a) ? a.map((x) => x.text).join(', ') : a.text || '';
}

const insertMsg = db.prepare(`
  INSERT OR IGNORE INTO messages
    (account_id, folder, uid, message_id, date, from_addr, to_addr, subject, snippet, text, html, seen)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

export async function syncAccount(acc) {
  if (running.has(acc.id)) return { skipped: true };
  running.add(acc.id);
  let added = 0;
  const client = new ImapFlow({
    host: acc.host,
    port: acc.port,
    secure: !!acc.secure,
    auth: { user: acc.username, pass: decrypt(acc.password_enc) },
    logger: false,
    socketTimeout: 60_000,
  });
  try {
    await client.connect();
    const folders = acc.folders.split(',').map((f) => f.trim()).filter(Boolean);
    for (const folder of folders) {
      const lock = await client.getMailboxLock(folder);
      try {
        const mb = client.mailbox;
        const uidvalidity = String(mb.uidValidity);
        let state = db
          .prepare('SELECT * FROM folder_state WHERE account_id = ? AND folder = ?')
          .get(acc.id, folder);

        if (state && state.uidvalidity !== uidvalidity) {
          // Server přečísloval UID -> stáhnout složku znovu
          db.prepare('DELETE FROM messages WHERE account_id = ? AND folder = ?').run(acc.id, folder);
          state = null;
        }
        if (!state) {
          db.prepare(
            'INSERT OR REPLACE INTO folder_state (account_id, folder, uidvalidity, last_uid) VALUES (?, ?, ?, 0)'
          ).run(acc.id, folder, uidvalidity);
          state = { last_uid: 0 };
        }

        if (!mb.exists) continue;
        let maxUid = state.last_uid;
        const range = `${state.last_uid + 1}:*`;
        for await (const msg of client.fetch(range, { uid: true, flags: true, source: true }, { uid: true })) {
          if (msg.uid <= state.last_uid) continue; // "N:*" vrací vždy aspoň poslední zprávu
          const parsed = await simpleParser(msg.source);
          const text = parsed.text || '';
          const r = insertMsg.run(
            acc.id,
            folder,
            msg.uid,
            parsed.messageId || null,
            (parsed.date || new Date()).getTime(),
            addrText(parsed.from),
            addrText(parsed.to),
            parsed.subject || '(bez předmětu)',
            text.replace(/\s+/g, ' ').trim().slice(0, 200),
            text,
            parsed.html || null,
            msg.flags?.has('\\Seen') ? 1 : 0
          );
          added += Number(r.changes);
          if (msg.uid > maxUid) maxUid = msg.uid;
        }
        db.prepare('UPDATE folder_state SET last_uid = ? WHERE account_id = ? AND folder = ?').run(
          maxUid,
          acc.id,
          folder
        );
      } finally {
        lock.release();
      }
    }
    await client.logout();
    db.prepare('UPDATE mail_accounts SET last_sync = ?, last_error = NULL WHERE id = ?').run(Date.now(), acc.id);
    return { added };
  } catch (err) {
    db.prepare('UPDATE mail_accounts SET last_sync = ?, last_error = ? WHERE id = ?').run(
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

export async function syncAll() {
  const accounts = db.prepare('SELECT * FROM mail_accounts WHERE enabled = 1').all();
  const results = {};
  for (const acc of accounts) results[acc.id] = await syncAccount(acc);
  return results;
}

export function startSyncLoop(intervalSec) {
  const tick = () =>
    syncAll()
      .then((r) => {
        const total = Object.values(r).reduce((s, x) => s + (x.added || 0), 0);
        if (total) console.log(`[sync] staženo ${total} nových zpráv`);
      })
      .catch((e) => console.error('[sync]', e));
  tick();
  return setInterval(tick, Math.max(15, intervalSec) * 1000);
}
