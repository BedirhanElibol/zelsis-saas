import crypto from 'node:crypto';

/**
 * AES-256-GCM for third-party credentials kept in the database (Jira API tokens).
 * The key comes from INTEGRATION_ENCRYPTION_KEY: 32 random bytes, base64. Server only.
 * Format: v1.<iv>.<tag>.<ciphertext>, each part base64url.
 */
const VERSION = 'v1';

export function integrationKey(raw = process.env.INTEGRATION_ENCRYPTION_KEY): Buffer | null {
  if (!raw) return null;
  const key = Buffer.from(raw, 'base64');
  return key.length === 32 ? key : null;
}

export function seal(plaintext: string, key: Buffer): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return [VERSION, iv, cipher.getAuthTag(), data].map((p) => (typeof p === 'string' ? p : p.toString('base64url'))).join('.');
}

/** The plaintext, or null when the value was not sealed with this key or was changed. */
export function open(sealed: string, key: Buffer): string | null {
  const [version, iv, tag, data] = sealed.split('.');
  if (version !== VERSION || !iv || !tag || data === undefined) return null;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
    decipher.setAuthTag(Buffer.from(tag, 'base64url'));
    return Buffer.concat([decipher.update(Buffer.from(data, 'base64url')), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}
