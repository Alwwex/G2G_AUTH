# G2G Auth – webmail + authenticator

Malá webová appka pro **taolitakefu.vip**:

- 🔒 **Přihlášení** jménem a heslem z `.env` (+ volitelně 2FA kód), ochrana proti brute-force.
- 📬 **Webmail** – přes IMAP kopíruje e-maily z jedné nebo více schránek do lokální databáze
  (každých `SYNC_INTERVAL` sekund jen nové zprávy). Hledání, filtr podle schránky,
  automatické zvýraznění kódů z e-mailů (klik = zkopírovat). Na IMAP serveru se nic nemaže.
- 🔑 **Authenticator** (jako Authy / Google Authenticator) – vložíš secret key
  (např. z Escape from Tarkov) nebo `otpauth://` odkaz a web ukazuje aktuální 6místný kód
  s odpočtem. Klik na kód = zkopírovat.

TOTP secrety i IMAP hesla jsou v databázi šifrované (AES-256-GCM, klíč z `APP_SECRET`).

## Spuštění lokálně

Potřeba Node.js 22.13+.

```bash
npm install
cp .env.example .env      # vyplň ADMIN_PASSWORD, APP_SECRET, případně IMAP_*
npm start                 # http://localhost:3000
```

## Nasazení na taolitakefu.vip (Docker + automatické HTTPS)

1. DNS A záznam `taolitakefu.vip` → IP serveru.
2. Na serveru: `git clone …`, `cp .env.example .env` a vyplnit.
3. `docker compose up -d --build`

Data (databáze) jsou v `./data` – zálohuj je. **Bez `APP_SECRET` se secrety nedají dešifrovat**,
takže ho nikdy neměň a zálohuj spolu s daty.

## Escape from Tarkov 2FA

Na webu EFT v nastavení profilu zapni Authenticator → u QR kódu zobraz textový klíč
→ zkopíruj ho do záložky **Authenticator → + Přidat** → kód, který web ukáže, opiš zpět do EFT pro potvrzení.
Secret si navíc ulož někam bokem (tlačítko 👁 ho kdykoliv zobrazí).
