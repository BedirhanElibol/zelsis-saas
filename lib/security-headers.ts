import { NextResponse } from 'next/server';

/**
 * Canonical Security Headers Configuration (SEC-04 & SEC-05)
 * Single Source of Truth for Zelsis SaaS across Middleware, Next.js Config, and Edge Runtime.
 * Strictly adheres to OWASP 2025, NIST SP 800-53, and CIS Benchmarks.
 */

export const CSP_DIRECTIVES = {
  'default-src': ["'self'"],
  'script-src': [
    "'self'",
    "'unsafe-inline'", // Required for Next.js inline bootstrap scripts
  ],
  'worker-src': [
    "'self'",
    'blob:',
  ],
  'style-src': [
    "'self'",
    "'unsafe-inline'", // Required for Tailwind CSS runtime emotion/styles
  ],
  'img-src': [
    "'self'",
    'data:',
    'blob:',
    'https://avatars.githubusercontent.com',
    'https://raw.githubusercontent.com',
    'https://images.unsplash.com',
    'https://lh3.googleusercontent.com',
    'https://*.googleusercontent.com'
  ],
  'font-src': [
    "'self'",
    'data:',
  ],
  'connect-src': [
    "'self'",
    'https://*.supabase.co',
    'wss://*.supabase.co',
    'https://api.polar.sh',
    'https://api.github.com',
    'https://raw.githubusercontent.com',
    'https://api.pwnedpasswords.com'
  ],
  'frame-ancestors': ["'none'"],
  'base-uri': ["'self'"],
  'form-action': ["'self'"],
  'object-src': ["'none'"]
};

export function buildCspString(): string {
  return Object.entries(CSP_DIRECTIVES)
    .map(([key, values]) => `${key} ${values.join(' ')}`)
    .join('; ');
}

export const CANONICAL_SECURITY_HEADERS: Record<string, string> = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(self)',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'X-Permitted-Cross-Domain-Policies': 'none',
  'Content-Security-Policy': buildCspString()
};

/**
 * Injects canonical security headers into any Next.js NextResponse
 */
export function applyCanonicalSecurityHeaders(res: NextResponse): NextResponse {
  for (const [key, value] of Object.entries(CANONICAL_SECURITY_HEADERS)) {
    res.headers.set(key, value);
  }
  return res;
}
