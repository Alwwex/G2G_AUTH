import crypto from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input) {
  const clean = String(input).toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('Neplatný znak v base32 secretu: ' + ch);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function normalizeSecret(secret) {
  const s = String(secret).toUpperCase().replace(/[\s=-]/g, '');
  base32Decode(s); // validace
  if (!s.length) throw new Error('Prázdný secret');
  return s;
}

export function hotp(secret, counter, digits = 6, algorithm = 'SHA1') {
  const key = base32Decode(secret);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac(algorithm.toLowerCase(), key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return String(code % 10 ** digits).padStart(digits, '0');
}

export function totp(secret, { period = 30, digits = 6, algorithm = 'SHA1', time = Date.now() } = {}) {
  const counter = Math.floor(time / 1000 / period);
  return {
    code: hotp(secret, counter, digits, algorithm),
    next: hotp(secret, counter + 1, digits, algorithm),
    remaining: period - (Math.floor(time / 1000) % period),
  };
}

export function verifyTotp(secret, token, window = 1) {
  const t = String(token || '').replace(/\s/g, '');
  const counter = Math.floor(Date.now() / 1000 / 30);
  for (let i = -window; i <= window; i++) {
    if (hotp(secret, counter + i) === t) return true;
  }
  return false;
}

// otpauth://totp/Issuer:label?secret=XXX&issuer=Issuer&digits=6&period=30&algorithm=SHA1
export function parseOtpauth(uri) {
  const u = new URL(uri);
  if (u.protocol !== 'otpauth:') throw new Error('Není otpauth:// URI');
  if (u.host !== 'totp') throw new Error('Podporováno je jen TOTP');
  const label = decodeURIComponent(u.pathname.replace(/^\//, ''));
  const p = u.searchParams;
  const [issuerFromLabel, account] = label.includes(':') ? label.split(':', 2) : ['', label];
  return {
    issuer: p.get('issuer') || issuerFromLabel || '',
    name: account.trim() || label,
    secret: p.get('secret') || '',
    digits: Number(p.get('digits') || 6),
    period: Number(p.get('period') || 30),
    algorithm: (p.get('algorithm') || 'SHA1').toUpperCase(),
  };
}
