import { CodeFile } from './scanner-engine';

import { validateSafeTargetUrl, safeFetch } from '@/lib/ssrf-guard';
import { probeLiveSite, type LiveProbeResult } from '@/lib/scanner/live-checks';
import { analyzeBundles, lazyChunkUrls, sourceMapUrl } from './live-bundle-analyzer';
import { createRequestLimiter } from '@/lib/scanner/request-limiter';
import type { ChallengeProvider } from '@/lib/bot-challenge';

/** Bundles are read in full for secrets (Vite/Lovable main bundles are 0.4-2 MB), within these limits. */
const MAX_BUNDLE_BYTES = 5_000_000;
const MAX_LAZY_CHUNKS = 20;
const MAX_TOTAL_BUNDLE_BYTES = 15_000_000;

export interface WebsiteAuditData {
  url: string;
  statusCode: number;
  headers: Record<string, string>;
  title: string;
  files: CodeFile[];
  securityHeadersMissing: string[];
  discoveredButtonsCount: number;
  crawledPagesCount: number;
  liveProbe?: LiveProbeResult;
  isCloudflareChallenge?: boolean;
  /** Which layer answered with the challenge (the error code stays CLOUDFLARE_BOT_PROTECTION for existing callers). */
  challengeProvider?: ChallengeProvider;
  /** The target started challenging part-way through, so subpages / bundles / probes after that point were skipped. */
  challengedDuringScan?: boolean;
  /** The first request the target challenged and how many requests had been sent by then (diagnoses rate vs path triggers). */
  challengeTrigger?: { url: string; index: number };
  error?: 'CLOUDFLARE_BOT_PROTECTION' | string;
}

export function isValidWebUrl(url: string): boolean {
  if (!url || typeof url !== 'string') return false;
  const clean = url.trim().toLowerCase();
  if (clean.includes('github.com/')) return false; // GitHub repos handle separately via AST
  try {
    const formatted = clean.includes('://') ? clean : `https://${clean}`;
    const parsed = new URL(formatted);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.hostname.includes('.');
  } catch (e: any) {
    return false;
  }
}

/**
 * Live Web Deployment Deep Inspector & Subpage Crawler
 * Audits live web app deployment URLs (e.g. Vercel, Netlify, Custom Domain like trustmrr.com) by:
 * 1. Crawling all internal links (<a href="/...">) and fetching subpages (/pricing, /login, /dashboard, etc.)
 * 2. Discovering & inspecting interactive buttons (<button>, [role="button"], <input type="submit">)
 * 3. Auditing HTTP Security Headers (CSP, HSTS, X-Frame-Options, CORS)
 * 4. Scanning Client JS Bundles for leaked API secret keys
 */
export async function fetchWebsiteAuditData(siteUrl: string, signal?: AbortSignal, options: { deepProbes?: boolean } = {}): Promise<WebsiteAuditData | null> {
  const formattedUrl = siteUrl.startsWith('http') ? siteUrl : `https://${siteUrl}`;
  const origin = new URL(formattedUrl).origin;

  let htmlText = '';
  let statusCode = 200;
  let headers: Record<string, string> = {};
  let setCookies: string[] = [];
  let usedProxy = false;

  // 1. Internal First-Party Hardened Proxy Attempt (Browser environment)
  if (typeof window !== 'undefined') {
    try {
      const internalProxyUrl = `/api/v1/proxy?url=${encodeURIComponent(formattedUrl)}`;
      const proxyRes = await fetch(internalProxyUrl, { signal: signal || AbortSignal.timeout(10000) });
      if (proxyRes.ok) {
        const data = await proxyRes.json();
        if (data && data.content) {
          htmlText = data.content;
          statusCode = data.status || 200;
          headers = data.headers || {};
          usedProxy = true;
        }
      }
    } catch (err) {
      if (signal?.aborted) return null;
      console.warn(`Internal hardened proxy fetch failed for ${formattedUrl}:`, err);
    }
  }

  // 2. Direct Fetch (Server environment with SSRF check, or browser fallback)
  if (!htmlText) {
    try {
      const res = await safeFetch(formattedUrl, {
        headers: {
          'User-Agent': 'Zelsis-Release-Gate-Scanner/3.5'
        },
        maxRedirects: 5,
        signal: signal || AbortSignal.timeout(8000)
      });

      statusCode = res.status;
      res.headers.forEach((val, key) => {
        headers[key.toLowerCase()] = val;
      });
      setCookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];

      htmlText = await res.text();
    } catch (directErr) {
      if (signal?.aborted) return null;
      console.warn(`Direct fetch to ${formattedUrl} failed:`, directErr);
    }

    // In browser environment, fallback to internal hardened proxy if not already used
    if (typeof window !== 'undefined' && !usedProxy && !htmlText) {
      try {
        const internalProxyUrl = `/api/v1/proxy?url=${encodeURIComponent(formattedUrl)}`;
        const proxyRes = await fetch(internalProxyUrl, { signal: signal || AbortSignal.timeout(10000) });
        if (proxyRes.ok) {
          const data = await proxyRes.json();
          if (data && data.content) {
            htmlText = data.content;
            statusCode = data.status || 200;
            headers = data.headers || {};
            usedProxy = true;
          }
        }
      } catch {
        if (signal?.aborted) return null;
      }
    }
  }

  // Return null if unreachable or fetching failed (no placebo HTML)
  if (!htmlText) {
    return null;
  }

  // Detect Cloudflare bot protection challenges
  const isCfHtml =
    htmlText.includes('cf-mitigated') ||
    /<title[^>]*>\s*Just a moment\.\.\.\s*<\/title>/i.test(htmlText) ||
    htmlText.includes('Attention Required! | Cloudflare');

  const isCfHeader = headers['cf-mitigated'] === 'challenge';
  const isCfServer = (headers['server'] || '').toLowerCase().includes('cloudflare');
  const isCfTitle = /<title[^>]*>(?:just a moment\.\.\.|attention required!\s*\|\s*cloudflare|cloudflare)<\/title>/i.test(htmlText);
  const hasCfIndicators = /challenges\.cloudflare\.com|cf-browser-verification|cf-turnstile|ray id:|\/cdn-cgi\/challenge-platform/i.test(htmlText);

  // Vercel's bot checkpoint answers 200/429 with a challenge page; scanning it would report a clean site that was never read
  const isVercelChallenge = headers['x-vercel-mitigated'] === 'challenge' || /<title[^>]*>\s*Vercel Security Checkpoint\s*<\/title>/i.test(htmlText);

  if (isVercelChallenge || isCfHtml || isCfHeader || ((statusCode === 403 || statusCode === 503) && (isCfServer || isCfTitle || hasCfIndicators)) || (isCfTitle && hasCfIndicators)) {
    return {
      url: formattedUrl,
      statusCode: statusCode === 200 ? 403 : statusCode,
      headers,
      title: isVercelChallenge ? 'Vercel Bot Protection Challenge' : 'Cloudflare Bot Protection Challenge',
      files: [],
      securityHeadersMissing: [],
      discoveredButtonsCount: 0,
      crawledPagesCount: 0,
      isCloudflareChallenge: true,
      challengeProvider: isVercelChallenge ? 'vercel' : 'cloudflare',
      error: 'CLOUDFLARE_BOT_PROTECTION'
    };
  }

  // Check Missing Security Headers
  const securityHeadersMissing: string[] = [];
  if (!headers['content-security-policy']) securityHeadersMissing.push('Content-Security-Policy');
  // preload is optional; only an absent header or max-age=0 leaves HTTPS downgradable
  const hstsMaxAge = Number((headers['strict-transport-security'] || '').match(/max-age\s*=\s*"?(\d+)/i)?.[1] ?? 0);
  if (hstsMaxAge <= 0) securityHeadersMissing.push('Strict-Transport-Security (HSTS)');
  if (!headers['x-frame-options']) securityHeadersMissing.push('X-Frame-Options');
  if (!headers['x-content-type-options']) securityHeadersMissing.push('X-Content-Type-Options');

  // Extract Page Title
  const titleMatch = htmlText.match(/<title[^>]*>([^<]+)<\/title>/i);
  const title = titleMatch ? titleMatch[1].trim() : `Live Site (${new URL(formattedUrl).hostname})`;

  // 2. Discover Interactive Buttons & Controls (HTML tags, submit inputs, and ARIA button roles)
  const buttonMatches = Array.from(htmlText.matchAll(/<(button|input[^>]+type=["']submit["']|a[^>]+role=["']button["']|div[^>]+role=["']button["'])[^>]*>(.*?)<\/\1>/gi));
  const discoveredButtonsCount = buttonMatches.length;

  // 3. Subpage Link Crawler (Extract internal links with full relative URL resolution)
  const linkMatches = Array.from(htmlText.matchAll(/<a[^>]+href=["']([^"'#\s]+)["']/gi));
  const subpageUrls = new Set<string>();

  for (const m of linkMatches) {
    const rawHref = m[1].trim();
    if (!rawHref || rawHref.startsWith('javascript:') || rawHref.startsWith('mailto:') || rawHref.startsWith('tel:')) continue;
    try {
      const resolved = new URL(rawHref, formattedUrl);
      if (resolved.origin === origin && resolved.pathname !== '/' && !resolved.pathname.includes('.')) {
        subpageUrls.add(resolved.href);
      }
    } catch {
      // Ignore unparseable hrefs
    }
  }

  const subpagesToCrawl = Array.from(subpageUrls).slice(0, 8);

  // Every request after the homepage goes through one limiter: at most 4 in flight, starts spaced out, and nothing more
  // is sent once the target challenges us (a burst makes Vercel / Cloudflare block the scanner IP for minutes)
  const limiter = createRequestLimiter({ concurrency: 4, minIntervalMs: 120 });
  const politeFetch = (url: string, init: Parameters<typeof safeFetch>[1]) => limiter.run(async () => limiter.note(await safeFetch(url, init), url));

  const isHealthy = statusCode >= 200 && statusCode < 400;
  const linkStatusText = statusCode === 200 ? '200 OK (Healthy Target)' : statusCode === 404 ? '404 Not Found (Broken Link)' : statusCode >= 500 ? `HTTP ${statusCode} Server Error (Dead Endpoint)` : `HTTP ${statusCode} Response`;

  // Virtual Code Files for Scanner Engine
  const files: CodeFile[] = [
    {
      path: 'live-deployment/index.html',
      content: htmlText
    },
    {
      path: 'live-deployment/security-headers.json',
      content: JSON.stringify(
        {
          targetUrl: formattedUrl,
          statusCode,
          isHealthy,
          linkStatusText,
          usedProxy,
          missingSecurityHeaders: securityHeadersMissing,
          headers,
          buttonsInspected: discoveredButtonsCount,
          subpagesCrawledCount: subpagesToCrawl.length
        },
        null,
        2
      )
    }
  ];

  // Concurrent Subpages Content Ingestion via Promise.allSettled with SSRF protection
  const subpagePromises = subpagesToCrawl.map(async (subUrl) => {
    const pathName = new URL(subUrl).pathname.replace(/[^a-zA-Z0-9_-]/g, '_');
    try {
      const subRes = await politeFetch(subUrl, { 
        headers: { 'User-Agent': 'Zelsis-Release-Gate-Scanner/3.5' },
        maxRedirects: 3,
        signal: signal || AbortSignal.timeout(5000) 
      });
      if (subRes.ok) {
        const subHtml = await subRes.text();
        return {
          path: `live-deployment/pages${pathName || '_page'}.html`,
          content: subHtml
        };
      }
    } catch (e: any) {
      console.warn(`Could not crawl subpage ${subUrl}:`, e?.message || e);
    }
    return null;
  });

  const crawledResults = await Promise.allSettled(subpagePromises);
  for (const item of crawledResults) {
    if (item.status === 'fulfilled' && item.value) {
      files.push(item.value);
    }
  }

  // Extract & Fetch Top Client Script Bundles concurrently with SSRF validation
  const scriptMatches = Array.from(htmlText.matchAll(/<script[^>]+src=["']([^"']+)["']/g));
  const scriptSrcs = scriptMatches.map((m) => m[1]).slice(0, 6);

  const fullBundles: { url: string; text: string }[] = [];
  const scriptPromises = scriptSrcs.map(async (src, i) => {
    let scriptUrl = src;
    if (src.startsWith('//')) {
      scriptUrl = `https:${src}`;
    } else if (src.startsWith('http://') || src.startsWith('https://')) {
      scriptUrl = src;
    } else if (src.startsWith('/')) {
      scriptUrl = `${origin}${src}`;
    } else {
      scriptUrl = `${origin}/${src}`;
    }

    try {
      const scriptRes = await politeFetch(scriptUrl, { 
        headers: { 'User-Agent': 'Zelsis-Release-Gate-Scanner/3.5' },
        maxRedirects: 3,
        signal: signal || AbortSignal.timeout(5000) 
      });
      if (scriptRes.ok) {
        const scriptText = (await scriptRes.text()).slice(0, MAX_BUNDLE_BYTES);
        fullBundles.push({ url: scriptUrl, text: scriptText });
        // The general rules read the first 250 KB; the full text goes to the bundle analyzer below
        return {
          path: `live-deployment/bundle-${i + 1}.js`,
          content: scriptText.slice(0, 250000)
        };
      }
    } catch (err: any) {
      console.warn(`Could not fetch client script bundle ${scriptUrl}:`, err?.message || err);
    }
    return null;
  });

  const bundleResults = await Promise.allSettled(scriptPromises);
  for (const item of bundleResults) {
    if (item.status === 'fulfilled' && item.value) {
      files.push(item.value);
    }
  }

  // Lazy chunks (same origin only) and public source maps, then secrets across the full bundles
  try {
    const chunkUrls = [...new Set(fullBundles.flatMap((b) => lazyChunkUrls(b.text, origin)))]
      .filter((u) => u.startsWith(origin) && !fullBundles.some((b) => b.url === u))
      .slice(0, MAX_LAZY_CHUNKS);
    let budget = MAX_TOTAL_BUNDLE_BYTES - fullBundles.reduce((n, b) => n + b.text.length, 0);
    const chunkResults = await Promise.allSettled(chunkUrls.map(async (u) => {
      const res = await politeFetch(u, { headers: { 'User-Agent': 'Zelsis-Release-Gate-Scanner/3.5' }, maxRedirects: 2, signal: signal || AbortSignal.timeout(6000) });
      return res.ok ? { url: u, text: (await res.text()).slice(0, MAX_BUNDLE_BYTES) } : null;
    }));
    for (const c of chunkResults) {
      if (c.status !== 'fulfilled' || !c.value || budget <= 0) continue;
      budget -= c.value.text.length;
      fullBundles.push(c.value);
    }
    const publicSourceMaps: string[] = [];
    for (const b of fullBundles.slice(0, 8)) {
      const mapUrl = sourceMapUrl(b.text, b.url);
      if (!mapUrl || !mapUrl.startsWith(origin)) continue;
      try {
        const mapRes = await politeFetch(mapUrl, { headers: { 'User-Agent': 'Zelsis-Release-Gate-Scanner/3.5' }, maxRedirects: 2, signal: signal || AbortSignal.timeout(4000) });
        if (mapRes.ok && /"sources"\s*:/.test((await mapRes.text()).slice(0, 4000))) publicSourceMaps.push(mapUrl);
      } catch { /* unreachable map is the good case */ }
    }
    if (fullBundles.length > 0) {
      files.push({
        path: 'live-deployment/bundle-analysis.json',
        content: JSON.stringify({ ...analyzeBundles(fullBundles), publicSourceMaps }, null, 2)
      });
    }
  } catch (err: unknown) {
    console.warn('Bundle analysis skipped:', err instanceof Error ? err.message : String(err));
  }

  // Exposure probes (.env/.git, deploy artifacts, TLS, HTTP redirect, cookies) run last: requests for paths such as
  // /.env or /phpmyadmin look like a vulnerability scanner and are the likeliest to get the IP challenged, so the pages
  // and bundles above are read first. Server only: browser runs cannot open raw TLS sockets.
  // Challenged while reading pages / bundles: the content is incomplete and the scan must fail rather than look clean
  const contentChallenged = limiter.challenged;
  const liveProbe = typeof window === 'undefined' && !contentChallenged
    ? await probeLiveSite(formattedUrl, setCookies, { deepProbes: options.deepProbes === true, fetchImpl: limiter.fetch, probeIntervalMs: 1500 }).catch((err) => {
        console.warn(`Live probes failed for ${formattedUrl}:`, err?.message || err);
        return undefined;
      })
    : undefined;
  if (liveProbe) {
    const headerFile = files.find((f) => f.path === 'live-deployment/security-headers.json');
    if (headerFile) headerFile.content = JSON.stringify({ ...JSON.parse(headerFile.content), liveProbe, ...(limiter.challenged ? { probesIncomplete: true, challengeTrigger: limiter.trigger } : {}) }, null, 2);
  }

  return {
    url: formattedUrl,
    statusCode,
    headers,
    title,
    files,
    liveProbe,
    securityHeadersMissing,
    discoveredButtonsCount,
    crawledPagesCount: subpagesToCrawl.length + 1,
    // Challenged during the probes only: pages and bundles were read, the probes after the challenge were skipped
    // (probesIncomplete). Challenged while reading content: an error, never a clean result for a site we could not read.
    ...(limiter.challenged ? { challengedDuringScan: true, challengeTrigger: limiter.trigger, challengeProvider: limiter.provider } : {}),
    ...(contentChallenged ? { isCloudflareChallenge: true, error: 'CLOUDFLARE_BOT_PROTECTION' } : {})
  };
}
