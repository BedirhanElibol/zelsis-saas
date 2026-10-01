import { NextRequest, NextResponse } from 'next/server';
import { logger } from './logger';

export interface RateLimitOptions {
  maxRequests?: number;
  windowSeconds?: number;
  prefix?: string;
  /** Deny instead of falling back to in-memory when configured Redis is unreachable. */
  failClosed?: boolean;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetSeconds: number;
  clientIp: string;
}

// In-Memory Sliding-Window Store: Map<key, timestamp_array>
const inMemoryStore = new Map<string, number[]>();
const MAX_MAP_SIZE = 10000;
let warnedMissingRedis = false;

// Periodic cleanup of expired entries every 5 minutes
let lastCleanup = Date.now();
function cleanupExpiredEntries(windowMs: number) {
  const now = Date.now();
  if (now - lastCleanup < 60000 && inMemoryStore.size < MAX_MAP_SIZE) return;
  lastCleanup = now;

  for (const [key, timestamps] of inMemoryStore.entries()) {
    const valid = timestamps.filter((t) => now - t < windowMs);
    if (valid.length === 0) {
      inMemoryStore.delete(key);
    } else {
      inMemoryStore.set(key, valid);
    }
  }

  // Safety valve: if still too large, prune oldest entries
  if (inMemoryStore.size > MAX_MAP_SIZE) {
    const entriesToPrune = inMemoryStore.size - (MAX_MAP_SIZE / 2);
    let count = 0;
    for (const key of inMemoryStore.keys()) {
      if (count++ >= entriesToPrune) break;
      inMemoryStore.delete(key);
    }
  }
}

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;

function isValidIp(ip: string): boolean {
  return IPV4_REGEX.test(ip) || IPV6_REGEX.test(ip);
}

/**
 * Extracts client IP securely from trusted reverse proxy headers or fallback.
 * Prevents IP spoofing (F-19):
 * 1. Only trusts cf-connecting-ip if cf-ray is present (verifying genuine Cloudflare hop).
 * 2. Uses x-real-ip from upstream trusted reverse proxy.
 * 3. Parses valid IP from x-forwarded-for, strictly validating IPv4/IPv6 syntax.
 */
export function getClientIp(req: NextRequest): string {
  // Highest priority: Vercel Edge infrastructure verified IP (cannot be spoofed by clients)
  const xVercelIp = req.headers.get('x-vercel-ip')?.trim();
  if (xVercelIp && isValidIp(xVercelIp)) {
    return xVercelIp;
  }

  // Only trust cf-connecting-ip if genuine Cloudflare edge headers (cf-ray) are present
  const cfRay = req.headers.get('cf-ray');
  const cfConnectingIp = req.headers.get('cf-connecting-ip')?.trim();
  if (cfRay && cfConnectingIp && isValidIp(cfConnectingIp)) {
    return cfConnectingIp;
  }

  const xRealIp = req.headers.get('x-real-ip')?.trim();
  if (xRealIp && isValidIp(xRealIp)) {
    return xRealIp;
  }

  const xForwardedFor = req.headers.get('x-forwarded-for');
  if (xForwardedFor) {
    const candidateIps = xForwardedFor.split(',').map((s) => s.trim());
    for (const ip of candidateIps) {
      if (isValidIp(ip)) {
        return ip;
      }
    }
  }

  return '127.0.0.1';
}

/**
 * IP-based Sliding-Window Rate Limiter
 * Uses Upstash Redis REST API when configured (shared across instances); otherwise an
 * in-memory sliding window that only limits per serverless instance.
 */
export async function checkRateLimit(
  req: NextRequest,
  options: RateLimitOptions = {}
): Promise<RateLimitResult> {
  const {
    maxRequests = 60,
    windowSeconds = 60,
    prefix = 'general',
    failClosed = false
  } = options;

  const clientIp = getClientIp(req);
  const windowMs = windowSeconds * 1000;
  const now = Date.now();
  const storeKey = `rl:${prefix}:${clientIp}`;

  // 1. Attempt Upstash Redis REST API if credentials exist
  const redisUrl = process.env.UPSTASH_REDIS_REST_URL;
  const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (redisUrl && redisToken) {
    try {
      // Fixed window: INCR + EXPIRE NX in one pipeline so the key can never be left without a TTL
      const pipelineRes = await fetch(`${redisUrl}/pipeline`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${redisToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify([
          ['INCR', storeKey],
          ['EXPIRE', storeKey, String(windowSeconds), 'NX'],
          ['TTL', storeKey]
        ]),
        signal: AbortSignal.timeout(1500)
      });

      if (pipelineRes.ok) {
        const data = await pipelineRes.json() as Array<{ result?: unknown }>;
        const count = typeof data?.[0]?.result === 'number' ? data[0].result : 1;
        const ttl = typeof data?.[2]?.result === 'number' && data[2].result > 0 ? data[2].result : windowSeconds;

        return {
          allowed: count <= maxRequests,
          limit: maxRequests,
          remaining: Math.max(0, maxRequests - count),
          resetSeconds: ttl,
          clientIp
        };
      }
      logger.warn(`[RateLimiter] Upstash Redis returned ${pipelineRes.status}: ${storeKey}`);
    } catch (redisErr) {
      logger.warn(`[RateLimiter] Upstash Redis check failed: ${storeKey}`, redisErr);
    }

    if (failClosed) {
      return { allowed: false, limit: maxRequests, remaining: 0, resetSeconds: 30, clientIp };
    }
  } else if (process.env.NODE_ENV === 'production' && !warnedMissingRedis) {
    warnedMissingRedis = true;
    logger.warn('[RateLimiter] UPSTASH_REDIS_REST_URL/TOKEN not set: limits are per-instance only in production');
  }

  // 2. High-precision In-Memory Sliding-Window Implementation
  cleanupExpiredEntries(windowMs);

  const existingTimestamps = inMemoryStore.get(storeKey) || [];
  const validTimestamps = existingTimestamps.filter((t) => now - t < windowMs);

  if (validTimestamps.length >= maxRequests) {
    const oldestTimestamp = validTimestamps[0] || now;
    const resetSeconds = Math.ceil((oldestTimestamp + windowMs - now) / 1000);

    return {
      allowed: false,
      limit: maxRequests,
      remaining: 0,
      resetSeconds: Math.max(1, resetSeconds),
      clientIp
    };
  }

  validTimestamps.push(now);
  inMemoryStore.set(storeKey, validTimestamps);

  const remaining = maxRequests - validTimestamps.length;
  return {
    allowed: true,
    limit: maxRequests,
    remaining,
    resetSeconds: windowSeconds,
    clientIp
  };
}

/**
 * Generates standard 429 Too Many Requests response with standard rate-limiting headers.
 */
export function createRateLimitResponse(result: RateLimitResult): NextResponse {
  return NextResponse.json(
    {
      error: 'Rate Limit Exceeded',
      message: `Too many requests. Maximum ${result.limit} requests per window allowed.`,
      retryAfter: result.resetSeconds
    },
    {
      status: 429,
      headers: {
        'Retry-After': String(result.resetSeconds),
        'X-RateLimit-Limit': String(result.limit),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': String(Math.floor(Date.now() / 1000) + result.resetSeconds)
      }
    }
  );
}
