import { timingSafeEqual } from 'crypto';

const DEV_INTERNAL_SECRET = 'zelsis-dev-internal-worker-secret';

const isProduction = () => process.env.NODE_ENV === 'production';

/**
 * Shared secret for server-to-server worker calls.
 * Production requires a dedicated INTERNAL_API_SECRET; it never falls back to the
 * Supabase service role key, so that key is never sent over the network.
 */
export function getInternalSecret(): string | null {
  const secret = process.env.INTERNAL_API_SECRET?.trim();
  if (secret) return secret;
  return isProduction() ? null : DEV_INTERNAL_SECRET;
}

/**
 * Constant-time comparison of a received internal secret.
 */
export function isValidInternalSecret(received: string | null): boolean {
  const expected = getInternalSecret();
  if (!expected || !received) return false;

  const expectedBuf = Buffer.from(expected);
  const receivedBuf = Buffer.from(received);
  if (expectedBuf.length !== receivedBuf.length) return false;
  return timingSafeEqual(expectedBuf, receivedBuf);
}

/**
 * Trusted origin for internal worker calls, resolved from configuration only.
 * Never derived from request headers (Host / X-Forwarded-*), which a client can influence.
 */
export function getInternalBaseUrl(): string | null {
  const configured = process.env.NEXT_PUBLIC_APP_URL?.trim();
  if (configured) {
    try {
      return new URL(configured.startsWith('http') ? configured : `https://${configured}`).origin;
    } catch {
      // Fall through to platform defaults
    }
  }

  const vercelUrl = process.env.VERCEL_URL?.trim();
  if (vercelUrl) return `https://${vercelUrl}`;

  return isProduction() ? null : 'http://localhost:3000';
}
