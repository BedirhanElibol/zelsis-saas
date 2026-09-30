import { NextRequest, NextResponse } from 'next/server';
import { applyCanonicalSecurityHeaders } from '@/lib/security-headers';

/**
 * Global Edge Security Middleware for Zelsis SaaS (SEC-02, SEC-03, SEC-04, SEC-05)
 * - Injects enterprise-grade canonical security headers (HSTS, CSP, X-Frame-Options, COOP)
 * - Enforces Origin whitelist and strict 403 blocking on disallowed cross-origin API calls
 * - Sanitizes client IP headers using trusted platform priority (x-vercel-ip, cf-ray verified cf-connecting-ip)
 * - Protects against Clickjacking (CWE-1021) and MIME sniffing (CWE-79)
 */

const ALLOWED_ORIGINS = new Set([
  'http://localhost:3000',
  'http://localhost:3001',
  'http://127.0.0.1:3000',
  'https://zelsis.com',
  'https://zelsis-saas.vercel.app',
  'https://shipguard-saas.vercel.app'
]);

// Dynamically add production client URL from env if configured
const prodClientUrl = process.env.PRODUCTION_CLIENT_URL;
if (prodClientUrl) {
  try {
    ALLOWED_ORIGINS.add(new URL(prodClientUrl).origin);
  } catch {
    ALLOWED_ORIGINS.add(prodClientUrl);
  }
}

const nextPublicUrl = process.env.NEXT_PUBLIC_APP_URL;
if (nextPublicUrl) {
  try {
    const formatted = nextPublicUrl.startsWith('http') ? nextPublicUrl : `https://${nextPublicUrl}`;
    ALLOWED_ORIGINS.add(new URL(formatted).origin);
  } catch (_err) {
    // Ignore malformed NEXT_PUBLIC_APP_URL
  }
}

const vercelUrl = process.env.VERCEL_URL;
if (vercelUrl) {
  try {
    ALLOWED_ORIGINS.add(new URL(`https://${vercelUrl}`).origin);
  } catch (_err) {
    // Ignore malformed VERCEL_URL
  }
}

export function middleware(req: NextRequest) {
  // SEC-03: Platform-authenticated client IP resolution (prevents spoofing via arbitrary x-forwarded-for)
  const isCfVerified = Boolean(req.headers.get('cf-ray') && req.headers.get('cf-connecting-ip'));
  const clientIp =
    req.headers.get('x-vercel-ip') ||
    (isCfVerified ? req.headers.get('cf-connecting-ip') : null) ||
    req.headers.get('x-real-ip') ||
    req.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
    '127.0.0.1';

  const requestHeaders = new Headers(req.headers);
  requestHeaders.set('x-client-ip', clientIp);

  const origin = req.headers.get('origin');
  const pathname = req.nextUrl.pathname;

  // Handle API route CORS & preflight
  if (pathname.startsWith('/api/')) {
    // Badges are public resources embedded in markdown/HTML across domains
    if (pathname.startsWith('/api/v1/badge')) {
      const response = NextResponse.next({ request: { headers: requestHeaders } });
      response.headers.set('Access-Control-Allow-Origin', '*');
      response.headers.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
      return applyCanonicalSecurityHeaders(response);
    }

    // Polar webhooks are server-to-server HTTP POSTs from Polar edge IPs
    if (pathname.startsWith('/api/v1/polar-webhook')) {
      const response = NextResponse.next({ request: { headers: requestHeaders } });
      return applyCanonicalSecurityHeaders(response);
    }

    // Handle OPTIONS preflight requests
    if (req.method === 'OPTIONS') {
      const isAllowed = origin ? ALLOWED_ORIGINS.has(origin) : false;
      if (origin && !isAllowed) {
        return new NextResponse(null, { status: 403 });
      }

      const preflightHeaders = new Headers({
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, polar-webhook-signature, x-api-key',
        'Access-Control-Max-Age': '86400'
      });

      if (origin && isAllowed) {
        preflightHeaders.set('Access-Control-Allow-Origin', origin);
        preflightHeaders.set('Access-Control-Allow-Credentials', 'true');
      }

      const preflightResponse = new NextResponse(null, { status: 204, headers: preflightHeaders });
      return applyCanonicalSecurityHeaders(preflightResponse);
    }

    // SEC-02: Strict Origin Enforcement for browser requests
    if (origin && !ALLOWED_ORIGINS.has(origin)) {
      return new NextResponse(JSON.stringify({ error: 'Origin Forbidden' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const response = NextResponse.next({ request: { headers: requestHeaders } });

    if (origin && ALLOWED_ORIGINS.has(origin)) {
      response.headers.set('Access-Control-Allow-Origin', origin);
      response.headers.set('Access-Control-Allow-Credentials', 'true');
    }

    // GW-05: Attach standard API Deprecation and Sunset announcements for v1 endpoints
    if (pathname.startsWith('/api/v1/')) {
      response.headers.set('Deprecation', '@1798761600');
      response.headers.set('Sunset', 'Fri, 01 Jan 2027 00:00:00 GMT');
      response.headers.set('Link', '<https://zelsis.com/docs/api/v1>; rel="deprecation"');
    }

    return applyCanonicalSecurityHeaders(response);
  }

  // Non-API routes (HTML pages, layouts, SSR documents)
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  return applyCanonicalSecurityHeaders(response);
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']
};
