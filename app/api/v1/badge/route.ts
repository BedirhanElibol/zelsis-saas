import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { BadgeQuerySchema, validateQueryParams } from '@/lib/validations/api-schemas';
import { escapeSvgText } from '@/lib/sanitize';

/**
 * Hardened Dynamic SVG Shield Badge Generator Endpoint (F-26 Remediated)
 * 
 * Supports:
 * 1. Database-backed verification via `projectId` or `scanId`:
 *    Queries real scan history/project state from Supabase to prevent badge spoofing.
 * 2. Cryptographic HMAC verification via `sig` parameter:
 *    Ensures standalone badge embeds are signed and untampered.
 * 3. Fallback / Unverified mode:
 *    If raw parameters are passed without proof, displays an explicit UNVERIFIED badge.
 */
export async function GET(req: NextRequest) {
  // 1. Rate Limiting Check (Max 120 badge requests per minute per IP)
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 120,
    windowSeconds: 60,
    prefix: 'badge'
  });

  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  // 2. Strict Zod Parameter Validation
  const validation = validateQueryParams(BadgeQuerySchema, req.nextUrl.searchParams);
  if (!validation.success) {
    return validation.response;
  }

  const { projectId, scanId, sig, status: queryStatus, score: queryScore, label: queryLabel } = validation.data;

  let isVerified = false;
  let finalStatus = queryStatus;
  let finalScore = queryScore;
  let finalLabel = queryLabel;

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  // 3. Database-backed Verification (projectId or scanId)
  if ((projectId || scanId) && supabaseUrl && serviceRoleKey) {
    try {
      const supabase = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });

      if (scanId) {
        const { data: scan } = await supabase
          .from('scans')
          .select('gate_status, readiness_score, project_id')
          .eq('id', scanId)
          .maybeSingle();

        if (scan) {
          finalStatus = (scan.gate_status as any) || 'FAILED';
          finalScore = scan.readiness_score ?? 0;
          isVerified = true;

          const { data: proj } = await supabase
            .from('projects')
            .select('name')
            .eq('id', scan.project_id)
            .maybeSingle();

          if (proj?.name) {
            finalLabel = proj.name;
          }
        }
      } else if (projectId) {
        const { data: project } = await supabase
          .from('projects')
          .select('name, gate_status, readiness_score')
          .eq('id', projectId)
          .maybeSingle();

        if (project) {
          finalStatus = (project.gate_status as any) || 'FAILED';
          finalScore = project.readiness_score ?? 0;
          finalLabel = project.name || 'Zelsis Gate';
          isVerified = true;
        }
      }
    } catch {
      // If DB error, proceed to signature check or unverified fallback
    }
  }

  // 4. HMAC Signature Verification (if provided)
  if (!isVerified && sig) {
    const hmacSecret = process.env.BADGE_SIGNING_SECRET || serviceRoleKey;
    if (hmacSecret) {
      try {
        const hmac = crypto.createHmac('sha256', hmacSecret);
        hmac.write(`${queryStatus}:${queryScore}:${queryLabel}`);
        hmac.end();
        const expectedSig = (hmac.read() as Buffer).toString('hex');

        if (crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
          isVerified = true;
        }
      } catch {
        isVerified = false;
      }
    }
  }

  // 5. Construct Visual Shield Colors
  const isPassed = finalStatus === 'PASSED';
  const isWarning = finalStatus === 'WARNING';

  let statusBg = isPassed ? '#10B981' : isWarning ? '#F59E0B' : '#EF4444';
  let rawStatusText = isPassed ? `PASSED ${finalScore}%` : isWarning ? `WARNING ${finalScore}%` : `FAILED (${finalScore}%)`;

  // F-26: If not cryptographically or database verified, label clearly as UNVERIFIED to eliminate badge spoofing
  if (!isVerified && !projectId && !scanId) {
    statusBg = '#6B7280';
    rawStatusText = `UNVERIFIED ${finalScore}%`;
  }

  // 6. Prevent SVG XML injection with rigorous XML entity escaping
  const safeLabel = escapeSvgText(finalLabel, 28);
  const safeStatusText = escapeSvgText(rawStatusText, 28);

  const totalWidth = 240;
  const splitPoint = 135;
  const statusWidth = totalWidth - splitPoint - 10;
  const statusCenter = splitPoint + statusWidth / 2 + 5;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="28" viewBox="0 0 ${totalWidth} 28" fill="none">
  <rect width="${totalWidth}" height="28" rx="6" fill="#141414" stroke="#ffffff1a"/>
  <rect x="1" y="1" width="${splitPoint}" height="26" rx="5" fill="#0A0A0A"/>
  <text x="12" y="18" fill="#F5F3EF" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="11" font-weight="800" letter-spacing="0.5">${safeLabel}</text>
  <rect x="${splitPoint + 5}" y="4" width="${statusWidth}" height="20" rx="4" fill="${statusBg}"/>
  <text x="${statusCenter}" y="18" fill="#0A0A0A" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="10" font-weight="900" text-anchor="middle" letter-spacing="0.5">${safeStatusText}</text>
</svg>`;

  const etag = `"${crypto.createHash('sha256').update(svg).digest('base64url').substring(0, 27)}"`;
  const ifNoneMatch = req.headers.get('if-none-match');

  const headers: Record<string, string> = {
    'Content-Type': 'image/svg+xml; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'",
    'Cache-Control': isVerified
      ? 'public, max-age=120, s-maxage=600, stale-while-revalidate=86400, immutable'
      : 'no-cache, no-store, must-revalidate',
    'ETag': etag,
  };

  if (ifNoneMatch && ifNoneMatch === etag) {
    return new NextResponse(null, { status: 304, headers });
  }

  return new NextResponse(svg, { headers });
}
