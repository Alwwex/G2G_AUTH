import crypto from 'node:crypto';

let key;

export function initCrypto(secret) {
  if (!secret || secret.length < 16) {
    throw new Error('APP_SECRET must be set (min. 16 chars) - see .env.example');
  }
  key = crypto.scryptSync(secret, 'g2g-auth-v1', 32);
}

// AES-256-GCM; output: base64(iv|tag|ciphertext)
export function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
}

export function decrypt(blob) {
  const buf = Buffer.from(blob, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}

export function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// Per-account web login password: scrypt with random salt. Stored as salt:hash (hex).
export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(String(password), salt, 32);
  return salt.toString('hex') + ':' + h.toString('hex');
}

export function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [saltHex, hashHex] = stored.split(':');
  const h = crypto.scryptSync(String(password), Buffer.from(saltHex, 'hex'), 32);
  const hb = Buffer.from(hashHex, 'hex');
  return h.length === hb.length && crypto.timingSafeEqual(h, hb);
}
