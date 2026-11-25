const $ = (s, el = document) => el.querySelector(s);
const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

async function api(url, opts = {}) {
  const r = await fetch(url, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    body: opts.body && typeof opts.body !== 'string' ? JSON.stringify(opts.body) : opts.body,
  });
  if (r.status === 401) {
    location.href = '/login.html';
    throw new Error('401');
  }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 2000);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  toast('Copied: ' + text);
}

function fmtDate(ms) {
  const d = new Date(ms);
  const today = new Date();
  return d.toDateString() === today.toDateString()
    ? d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'numeric', year: '2-digit' });
}

// ---------------- tabs ----------------
const views = { mail: loadMail, otp: loadOtp, accounts: loadAccounts };
function show(view) {
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.view === view));
  document.querySelectorAll('.view').forEach((v) => (v.hidden = v.id !== 'view-' + view));
  localStorage.setItem('view', view);
  views[view]();
}
document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => show(t.dataset.view)));
$('#logout').onclick = async () => {
  await api('/api/logout', { method: 'POST' });
  location.href = '/login.html';
};

// ---------------- MAIL ----------------
let page = 1;
let currentId = null;
let searchTimer;

async function loadAccountFilter() {
  const accs = await api('/api/accounts');
  const sel = $('#accountFilter');
  const cur = sel.value;
  sel.innerHTML =
    '<option value="">All mailboxes</option>' +
    accs.map((a) => `<option value="${a.id}">${esc(a.label)} (${a.count})</option>`).join('');
  sel.value = cur;
}

// On serverless hosts (Vercel) there's no background sync loop, so the open page
// asks the server to sync mailboxes that haven't been synced recently.
let staleSyncing = false;
async function staleSync() {
  if (staleSyncing) return;
  staleSyncing = true;
  try {
    const r = await api('/api/sync', { method: 'POST', body: { stale: true } });
    if (Object.values(r).some((x) => x.added)) loadMail(false);
  } catch {}
  staleSyncing = false;
}

async function loadMail(triggerSync = true) {
  if (triggerSync) staleSync();
  loadAccountFilter();
  const q = $('#search').value;
  const account = $('#accountFilter').value;
  const data = await api(`/api/messages?q=${encodeURIComponent(q)}&account=${account}&page=${page}`);
  const list = $('#mailList');
  if (!data.messages.length) {
    list.innerHTML = '<div class="empty">No messages. Add a mailbox in the Mailboxes tab.</div>';
  } else {
    list.innerHTML = data.messages
      .map(
        (m) => `
      <article class="mail-item ${m.seen ? '' : 'unread'} ${m.id === currentId ? 'active' : ''}" data-id="${m.id}">
        <div class="mi-top"><span class="from">${esc(m.from_addr)}</span><span class="date">${fmtDate(m.date)}</span></div>
        <div class="subject">${esc(m.subject)}</div>
        <div class="snippet">${esc(m.snippet)}</div>
        <div class="to">→ ${esc(m.to_addr)}</div>
      </article>`
      )
      .join('');
  }
  const pages = Math.max(1, Math.ceil(data.total / data.limit));
  $('#pageInfo').textContent = `${page} / ${pages} · ${data.total} messages`;
  $('#prev').disabled = page <= 1;
  $('#next').disabled = page >= pages;
}

$('#mailList').addEventListener('click', (e) => {
  const item = e.target.closest('.mail-item');
  if (item) openMessage(Number(item.dataset.id));
});

function findCodes(text) {
  const codes = new Set();
  for (const m of String(text).matchAll(/(?<![\w#])(\d{4,8}|[A-Z0-9]{6})(?![\w])/g)) {
    if (/\d/.test(m[1]) && !/^(19|20)\d\d$/.test(m[1])) codes.add(m[1]);
    if (codes.size >= 4) break;
  }
  return [...codes];
}

async function openMessage(id) {
  currentId = id;
  document.querySelectorAll('.mail-item').forEach((el) => {
    el.classList.toggle('active', Number(el.dataset.id) === id);
    if (Number(el.dataset.id) === id) el.classList.remove('unread');
  });
  const m = await api('/api/messages/' + id);
  const codes = findCodes((m.subject || '') + ' ' + (m.text || ''));
  const v = $('#mailView');
  v.classList.add('open');
  v.innerHTML = `
    <div class="mv-head">
      <button class="btn ghost back">‹ Back</button>
      <h2>${esc(m.subject)}</h2>
      <div class="meta"><b>From:</b> ${esc(m.from_addr)}</div>
      <div class="meta"><b>To:</b> ${esc(m.to_addr)}</div>
      <div class="meta"><b>Date:</b> ${new Date(m.date).toLocaleString('en-GB')} · <span class="tag">${esc(m.account)} / ${esc(m.folder)}</span></div>
      ${codes.length ? `<div class="codes">Detected codes: ${codes.map((c) => `<button class="code-chip" data-code="${esc(c)}">${esc(c)}</button>`).join('')}</div>` : ''}
      <div class="row"><button class="btn ghost del">🗑 Delete from web</button></div>
    </div>
    <iframe class="mv-body" sandbox="allow-popups allow-popups-to-escape-sandbox" referrerpolicy="no-referrer"></iframe>`;
  const frame = $('.mv-body', v);
  const html = m.html
    ? m.html
    : `<pre style="white-space:pre-wrap;font:14px/1.5 system-ui,sans-serif">${esc(m.text)}</pre>`;
  frame.srcdoc = `<!doctype html><meta charset="utf-8"><base target="_blank"><style>body{margin:12px;font-family:system-ui,sans-serif;color:#111;background:#fff}img{max-width:100%;height:auto}</style>${html}`;
  $('.back', v).onclick = () => v.classList.remove('open');
  $('.del', v).onclick = async () => {
    if (!confirm('Delete this message from the web app? (It stays on the IMAP server.)')) return;
    await api('/api/messages/' + id, { method: 'DELETE' });
    v.innerHTML = '<div class="empty">Deleted</div>';
    v.classList.remove('open');
    loadMail();
  };
  v.querySelectorAll('.code-chip').forEach((b) => (b.onclick = () => copy(b.dataset.code)));
}

$('#search').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => ((page = 1), loadMail()), 250);
});
$('#accountFilter').onchange = () => ((page = 1), loadMail());
$('#prev').onclick = () => (page--, loadMail());
$('#next').onclick = () => (page++, loadMail());
$('#syncBtn').onclick = async () => {
  const b = $('#syncBtn');
  b.disabled = true;
  b.textContent = '↻ Syncing…';
  try {
    const r = await api('/api/sync', { method: 'POST', body: {} });
    const added = Object.values(r).reduce((s, x) => s + (x.added || 0), 0);
    const errs = Object.values(r).filter((x) => x.error);
    toast(errs.length ? 'Error: ' + errs[0].error : `New messages: ${added}`);
    loadMail();
  } finally {
    b.disabled = false;
    b.textContent = '↻ Refresh';
  }
};

// ---------------- AUTHENTICATOR ----------------
let otpData = [];
let otpFetchedAt = 0;
let otpTimer;

async function loadOtp() {
  otpData = await api('/api/otp');
  otpFetchedAt = Date.now();
  renderOtp();
  clearInterval(otpTimer);
  otpTimer = setInterval(tickOtp, 250);
}

function renderOtp() {
  const q = $('#otpSearch').value.toLowerCase();
  const items = otpData.filter((o) => (o.issuer + ' ' + o.name).toLowerCase().includes(q));
  $('#otpList').innerHTML = items.length
    ? items
        .map(
          (o) => `
    <article class="otp-card" data-id="${o.id}">
      <div class="otp-info">
        <div class="issuer">${esc(o.issuer || '—')}</div>
        <div class="acc">${esc(o.name)}</div>
      </div>
      <button class="otp-code" data-code="${esc(o.code)}" title="Click to copy">${fmtCode(o.code)}</button>
      <div class="otp-foot">
        <svg class="ring" viewBox="0 0 36 36"><circle cx="18" cy="18" r="15" class="bg"/><circle cx="18" cy="18" r="15" class="fg"/></svg>
        <span class="secs"></span>
        <span class="next">next: ${esc(o.next)}</span>
        <span class="spacer"></span>
        <button class="icon edit" title="Rename">✏️</button>
        <button class="icon secret" title="Show secret">👁</button>
        <button class="icon del" title="Delete">🗑</button>
      </div>
    </article>`
        )
        .join('')
    : '<div class="empty">No 2FA accounts yet. Click “+ Add”.</div>';
  tickOtp();
}

function fmtCode(c) {
  return c.length === 6 ? c.slice(0, 3) + ' ' + c.slice(3) : c;
}

function tickOtp() {
  if ($('#view-otp').hidden) return clearInterval(otpTimer);
  const elapsed = (Date.now() - otpFetchedAt) / 1000;
  let needRefresh = false;
  for (const o of otpData) {
    const card = document.querySelector(`.otp-card[data-id="${o.id}"]`);
    const left = o.remaining - elapsed;
    if (left <= 0) needRefresh = true;
    if (!card) continue;
    const frac = Math.max(0, left) / o.period;
    const fg = $('.fg', card);
    fg.style.strokeDashoffset = String(94.25 * (1 - frac));
    card.classList.toggle('expiring', left <= 5);
    $('.secs', card).textContent = Math.max(0, Math.ceil(left)) + ' s';
  }
  if (needRefresh && Date.now() - otpFetchedAt > 1000) loadOtp();
}

$('#otpSearch').addEventListener('input', renderOtp);
$('#otpAddBtn').onclick = () => {
  $('#otpForm').hidden = false;
  $('#otpForm').issuer.focus();
};
$('#otpCancel').onclick = () => {
  $('#otpForm').reset();
  $('#otpForm').hidden = true;
};
$('#otpForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#otpErr').textContent = '';
  try {
    await api('/api/otp', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) });
    e.target.reset();
    e.target.hidden = true;
    toast('Saved');
    loadOtp();
  } catch (err) {
    $('#otpErr').textContent = err.message;
  }
});

$('#otpList').addEventListener('click', async (e) => {
  const card = e.target.closest('.otp-card');
  if (!card) return;
  const id = card.dataset.id;
  const o = otpData.find((x) => String(x.id) === id);
  if (e.target.closest('.otp-code')) return copy(o.code);
  if (e.target.closest('.del')) {
    if (!confirm(`Delete ${o.issuer} – ${o.name}? Without the secret you won't be able to log in!`)) return;
    await api('/api/otp/' + id, { method: 'DELETE' });
    return loadOtp();
  }
  if (e.target.closest('.edit')) {
    const issuer = prompt('Service', o.issuer);
    if (issuer === null) return;
    const name = prompt('Account name', o.name);
    if (name === null) return;
    await api('/api/otp/' + id, { method: 'PATCH', body: { issuer, name } });
    return loadOtp();
  }
  if (e.target.closest('.secret')) {
    const { secret } = await api(`/api/otp/${id}/secret`);
    if (confirm(`Secret for ${o.name}:\n\n${secret}\n\nCopy it?`)) copy(secret);
  }
});

// ---------------- ACCOUNTS ----------------
async function loadAccounts() {
  const accs = await api('/api/accounts');
  $('#accList').innerHTML = accs.length
    ? accs
        .map(
          (a) => `
    <article class="card acc" data-id="${a.id}">
      <div>
        <b>${esc(a.label)}</b> <span class="tag">${a.enabled ? 'active' : 'disabled'}</span><br/>
        <small>${esc(a.username)} @ ${esc(a.host)}:${a.port} · folders: ${esc(a.folders)} · ${a.count} messages</small><br/>
        <small>Last sync: ${a.last_sync ? new Date(a.last_sync).toLocaleString('en-GB') : '—'}</small>
        ${a.last_error ? `<div class="error">⚠ ${esc(a.last_error)}</div>` : ''}
      </div>
      <div class="row">
        <button class="btn sync">↻ Sync</button>
        <button class="btn ghost toggle">${a.enabled ? 'Disable' : 'Enable'}</button>
        <button class="btn ghost pass">Change password</button>
        <button class="btn ghost del">Delete</button>
      </div>
    </article>`
        )
        .join('')
    : '<div class="empty">No mailboxes yet.</div>';
}

$('#accList').addEventListener('click', async (e) => {
  const card = e.target.closest('.acc');
  if (!card) return;
  const id = card.dataset.id;
  try {
    if (e.target.closest('.sync')) {
      e.target.disabled = true;
      const r = await api('/api/sync', { method: 'POST', body: { id } });
      toast(r[id].error ? 'Error: ' + r[id].error : `New messages: ${r[id].added}`);
    } else if (e.target.closest('.toggle')) {
      const enabled = e.target.textContent.trim() === 'Enable';
      await api('/api/accounts/' + id, { method: 'PATCH', body: { enabled } });
    } else if (e.target.closest('.pass')) {
      const password = prompt('New IMAP password');
      if (!password) return;
      await api('/api/accounts/' + id, { method: 'PATCH', body: { password } });
      toast('Password changed');
    } else if (e.target.closest('.del')) {
      if (!confirm('Delete this mailbox and all its downloaded messages from the web app?')) return;
      await api('/api/accounts/' + id, { method: 'DELETE' });
    } else return;
  } catch (err) {
    toast('Error: ' + err.message);
  }
  loadAccounts();
});

$('#accForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const body = Object.fromEntries(new FormData(f));
  body.secure = f.secure.checked;
  $('#accMsg').textContent = 'Connecting and syncing…';
  $('#accMsg').className = '';
  try {
    const r = await api('/api/accounts', { method: 'POST', body });
    if (r.result?.error) {
      $('#accMsg').textContent = 'Saved, but connection failed: ' + r.result.error;
      $('#accMsg').className = 'error';
    } else {
      $('#accMsg').textContent = `Done, fetched ${r.result?.added ?? 0} messages.`;
      f.reset();
    }
  } catch (err) {
    $('#accMsg').textContent = err.message;
    $('#accMsg').className = 'error';
  }
  loadAccounts();
});

$('#impBtn').onclick = async () => {
  const csv = $('#impCsv').value.trim();
  const host = $('#impHost').value.trim();
  if (!csv) return;
  if (!host) return (($('#impMsg').textContent = 'Fill in the IMAP server first'), ($('#impMsg').className = 'error'));
  $('#impMsg').className = '';
  $('#impMsg').textContent = 'Importing…';
  $('#impBtn').disabled = true;
  try {
    const r = await api('/api/accounts/import', {
      method: 'POST',
      body: {
        csv,
        host,
        port: Number($('#impPort').value) || 993,
        secure: $('#impSecure').checked,
        folders: $('#impFolders').value.trim() || 'INBOX',
      },
    });
    $('#impMsg').textContent =
      `Imported ${r.added} new, updated ${r.updated}, skipped ${r.skipped}` +
      (r.errors.length ? ` · ${r.errors.length} errors (${r.errors[0]})` : '') +
      '. Mail will be fetched by the next sync.';
    if (r.added || r.updated) $('#impCsv').value = '';
    loadAccounts();
  } catch (err) {
    $('#impMsg').textContent = 'Error: ' + err.message;
    $('#impMsg').className = 'error';
  }
  $('#impBtn').disabled = false;
};

// auto-refresh mail
setInterval(() => {
  if (!$('#view-mail').hidden) loadMail();
}, 30000);

show(localStorage.getItem('view') || 'mail');
