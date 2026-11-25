# G2G Auth – webmail + authenticator

A small private web app (e.g. for **taolitakefu.vip**):

- 🔒 **Login** with a username/password from env vars (+ optional 2FA code), brute-force protection.
- 📬 **Webmail** – copies emails from one or more IMAP mailboxes into its own database
  (only new messages each sync). Search, filter by mailbox, automatic detection of codes
  in emails (click = copy). Nothing is ever deleted on the IMAP server.
- 🔑 **Authenticator** (like Authy / Google Authenticator) – paste a secret key
  (e.g. from Escape from Tarkov) or an `otpauth://` link and get the live 6-digit code
  with a countdown. Click the code to copy it.

TOTP secrets and IMAP passwords are stored encrypted (AES-256-GCM, key = `APP_SECRET`).

---

## Option A – Vercel (free) + Turso database (free)

Vercel functions have no persistent disk, so the data lives in a free
[Turso](https://turso.tech) (hosted SQLite) database.

1. **Create the database** – sign up at turso.tech, create a database, then copy
   its **URL** (`libsql://…turso.io`) and create an **auth token**.
   With the CLI:
   ```bash
   turso db create g2g-auth
   turso db show g2g-auth --url
   turso db tokens create g2g-auth
   ```
   (Alternatively add Turso from the Vercel Marketplace – it sets `TURSO_DATABASE_URL` /
   `TURSO_AUTH_TOKEN` automatically, which the app also understands.)
2. **Import the repo on Vercel** – vercel.com → *Add New → Project* → pick this GitHub repo.
   No build settings needed (`vercel.json` handles it).
3. **Environment variables** (Project → Settings → Environment Variables):

   | Name | Value |
   |---|---|
   | `ADMIN_USER` | your login name |
   | `ADMIN_PASSWORD` | your login password |
   | `APP_SECRET` | long random string (see `.env.example`) – never change it |
   | `DATABASE_URL` | `libsql://…turso.io` |
   | `DATABASE_AUTH_TOKEN` | Turso token |
   | `CRON_SECRET` | random string |
   | `IMAP_HOST`, `IMAP_USER`, `IMAP_PASSWORD` | optional – or add mailboxes in the UI |

4. **Deploy**, then add your domain (Project → Settings → Domains → `taolitakefu.vip`)
   and set the DNS records Vercel shows you. HTTPS is automatic.

**How mail sync works on Vercel:** there's no always-running process, so mail is fetched
(a) whenever the web app is open (every ~60 s), (b) when you click *Refresh*, and
(c) by Vercel Cron once a day (the free Hobby plan allows only daily crons).
For background sync every few minutes, create a free job at
[cron-job.org](https://cron-job.org) that calls:

```
https://taolitakefu.vip/api/cron?key=YOUR_CRON_SECRET
```

Each sync downloads at most 100 messages per mailbox (first sync: the newest 200),
so it fits into the serverless time limit; the rest follows on the next sync.
Tune with `SYNC_BATCH_LIMIT` / `SYNC_INITIAL_LIMIT`.

> Note: Vercel's free Hobby plan is meant for non-commercial use.

## Option B – Render.com free web service

`render.yaml` is included: on Render → *New → Blueprint* → pick the repo, fill in the env
vars (use Turso for `DATABASE_URL`, free instances have no persistent disk).
The free instance sleeps after ~15 min idle; a cron-job.org ping of `/api/cron?key=…`
every 10 minutes keeps it awake and syncing.

## Option C – own server / VPS (Docker, automatic HTTPS)

Works with a local SQLite file, no Turso needed. Background sync runs every `SYNC_INTERVAL` s.

1. DNS A record `taolitakefu.vip` → server IP.
2. `cp .env.example .env` and fill it in.
3. `docker compose up -d --build` (Caddy gets the HTTPS certificate automatically).

Back up `./data` **together with `APP_SECRET`**.

## Run locally

Requires Node.js 20.12+.

```bash
npm install
cp .env.example .env   # set ADMIN_PASSWORD, APP_SECRET, optionally IMAP_*
npm start              # http://localhost:3000
```

## Bulk import mailboxes (CSV)

In the **Mailboxes** tab open **Bulk import mailboxes (CSV)**, set the IMAP server
(e.g. `mail.taolitakefu.vip`) and paste rows as `email,password` — one per line.
Extra columns are ignored, so an `email,mail_password,…` export pastes in as-is; only the
first two columns (email + mailbox password) are used. Re-importing the same email updates
its password. Imported mailboxes are synced by the normal sync loop / cron afterwards.

With **many mailboxes**, a single always-on server (Option C) is far better than serverless:
sync runs continuously with limited concurrency (`SYNC_CONCURRENCY`, default 5). On Vercel/Render
use `SYNC_ACCOUNTS_PER_RUN` to cap how many mailboxes each cron run touches (oldest first), and
call `/api/cron` often enough to rotate through all of them.

## Escape from Tarkov 2FA

On the EFT website open your profile → enable the Authenticator → under the QR code show the
text key → paste it into **Authenticator → + Add** → type the code the app shows back into EFT
to confirm. Keep a backup of the secret somewhere safe (the 👁 button shows it any time).
