import crypto from 'crypto';
import { logger } from '@/lib/logger';

/**
 * Verifies Polar / Standard Webhooks HMAC-SHA256 signatures.
 * Supports both Standard Webhooks format (v1,base64... where toSign is ${webhookId}.${timestamp}.${rawBody})
 * and raw HMAC-SHA256 hex or base64 signatures.
 */
export function verifyPolarWebhookSignature(
  rawBody: string,
  headers: Headers,
  secret: string
): boolean {
  const signatureHeader =
    headers.get('webhook-signature') ||
    headers.get('polar-webhook-signature') ||
    headers.get('x-polar-signature');

  if (!signatureHeader) {
    return false;
  }

  const webhookId =
    headers.get('webhook-id') ||
    headers.get('polar-webhook-id') ||
    '';
  const timestamp =
    headers.get('webhook-timestamp') ||
    headers.get('polar-webhook-timestamp') ||
    '';

  // Enforce timestamp freshness: reject payloads older than 5 minutes (300 seconds) or in the future
  if (timestamp) {
    const tsNum = parseInt(timestamp, 10);
    if (isNaN(tsNum)) {
      return false;
    }
    const nowSec = Math.floor(Date.now() / 1000);
    const eventSec = tsNum > 1e11 ? Math.floor(tsNum / 1000) : tsNum;
    if (Math.abs(nowSec - eventSec) > 300) {
      logger.warn('[Polar Webhook] Rejected webhook payload due to stale/future timestamp');
      return false;
    }
  }

  // Support keys starting with "whsec_" (standard webhooks) as base64 or raw
  const secretKeys: Buffer[] = [];
  if (secret.startsWith('whsec_')) {
    try {
      secretKeys.push(Buffer.from(secret.slice(6), 'base64'));
    } catch {
      // Ignore decoding failure
    }
  }
  secretKeys.push(Buffer.from(secret, 'utf-8'));

  // Prepare possible signing payloads
  const payloads: string[] = [];
  if (webhookId && timestamp) {
    payloads.push(`${webhookId}.${timestamp}.${rawBody}`);
  }
  payloads.push(rawBody);

  // Signatures can be space-delimited list of tokens, e.g. "v1,abc v1,def"
  const tokens = signatureHeader.trim().split(/\s+/);

  for (const token of tokens) {
    let sigCandidate = token;
    if (token.startsWith('v1,')) {
      sigCandidate = token.slice(3);
    } else if (token.includes(',')) {
      const parts = token.split(',');
      sigCandidate = parts[parts.length - 1];
    }

    for (const key of secretKeys) {
      for (const payload of payloads) {
        try {
          const hmac = crypto.createHmac('sha256', key).update(payload, 'utf-8').digest();
          const expectedBase64 = hmac.toString('base64');
          const expectedHex = hmac.toString('hex');

          // Base64 compare
          const candBase64Buf = Buffer.from(sigCandidate, 'utf-8');
          const expBase64Buf = Buffer.from(expectedBase64, 'utf-8');
          if (candBase64Buf.length === expBase64Buf.length && crypto.timingSafeEqual(candBase64Buf, expBase64Buf)) {
            return true;
          }

          // Hex compare
          const candHexBuf = Buffer.from(sigCandidate.toLowerCase(), 'utf-8');
          const expHexBuf = Buffer.from(expectedHex.toLowerCase(), 'utf-8');
          if (candHexBuf.length === expHexBuf.length && crypto.timingSafeEqual(candHexBuf, expHexBuf)) {
            return true;
          }

          // Direct byte buffer compare (if candidate is valid base64)
          try {
            const rawCandBuf = Buffer.from(sigCandidate, 'base64');
            if (rawCandBuf.length === hmac.length && crypto.timingSafeEqual(rawCandBuf, hmac)) {
              return true;
            }
          } catch {
            // Ignore
          }
        } catch {
          // Continue trying candidates
        }
      }
    }
  }

  return false;
}
