import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { safeFetch } from '@/lib/ssrf-guard';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { checkSiteReadiness } from '@/lib/site-readiness';
import { logger } from '@/lib/logger';

export const maxDuration = 20;

const BodySchema = z.object({ url: z.string().trim().min(4).max(300) });
const MAX_HTML_BYTES = 2_000_000;

/**
 * POST /api/v1/site-readiness
 * Signup-free check of one public page for what a visitor notices first. Reads the HTML only; no crawling.
 */
export async function POST(req: NextRequest) {
  const burst = await checkRateLimit(req, { maxRequests: 5, windowSeconds: 60, prefix: 'site-readiness-burst', failClosed: true });
  if (!burst.allowed) return createRateLimitResponse(burst);
  const daily = await checkRateLimit(req, { maxRequests: 20, windowSeconds: 86400, prefix: 'site-readiness-daily', failClosed: true });
  if (!daily.allowed) return NextResponse.json({ error: 'Daily limit reached. Create a free account to keep checking.', code: 'LIMIT' }, { status: 429 });

  const parsed = BodySchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: 'Enter a website address.', code: 'BAD_URL' }, { status: 400 });
  const raw = parsed.data.url;
  const target = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;

  try {
    const res = await safeFetch(target, { timeoutMs: 10_000, headers: { 'User-Agent': 'ZelsisSiteCheck/1.0 (+https://zelsis.com/site-check)', Accept: 'text/html' } });
    const type = res.headers.get('content-type') || '';
    if (!res.ok || !/text\/html/i.test(type)) {
      return NextResponse.json({ error: `The page answered ${res.status}${type ? ` (${type.split(';')[0]})` : ''}, not an HTML page.`, code: 'NOT_HTML' }, { status: 422 });
    }
    const html = (await res.text()).slice(0, MAX_HTML_BYTES);
    const finalUrl = res.url || target;
    let faviconFallbackOk = false;
    if (!/<link\b[^>]*\brel\s*=\s*["']?[^"'>]*\bicon\b/i.test(html)) {
      // Browsers fall back to /favicon.ico when the page declares no icon
      faviconFallbackOk = await safeFetch(new URL('/favicon.ico', finalUrl).toString(), { method: 'HEAD', timeoutMs: 5_000 })
        .then((r) => r.ok)
        .catch(() => false);
    }
    const items = checkSiteReadiness(html, finalUrl, { faviconFallbackOk });
    return NextResponse.json({ url: finalUrl, items, passed: items.filter((i) => i.ok).length, total: items.length });
  } catch (error) {
    logger.warn('site-readiness fetch failed', { error: String(error).slice(0, 200) });
    const blocked = /SSRF Guard Blocked/.test(String(error));
    return NextResponse.json(
      { error: blocked ? 'That address is not a public website.' : 'Could not load the page. Check the address and try again.', code: blocked ? 'BLOCKED' : 'FETCH_FAILED' },
      { status: 422 }
    );
  }
}
