import { CodeFile } from './scanner-engine';

import { validateSafeTargetUrl, safeFetch } from '@/lib/ssrf-guard';

export interface WebsiteAuditData {
  url: string;
  statusCode: number;
  headers: Record<string, string>;
  title: string;
  files: CodeFile[];
  securityHeadersMissing: string[];
  discoveredButtonsCount: number;
  crawledPagesCount: number;
  isCloudflareChallenge?: boolean;
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
export async function fetchWebsiteAuditData(siteUrl: string, signal?: AbortSignal): Promise<WebsiteAuditData | null> {
  const formattedUrl = siteUrl.startsWith('http') ? siteUrl : `https://${siteUrl}`;
  const origin = new URL(formattedUrl).origin;

  let htmlText = '';
  let statusCode = 200;
  let headers: Record<string, string> = {};
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

  if (isCfHtml || isCfHeader || ((statusCode === 403 || statusCode === 503) && (isCfServer || isCfTitle || hasCfIndicators)) || (isCfTitle && hasCfIndicators)) {
    return {
      url: formattedUrl,
      statusCode: statusCode === 200 ? 403 : statusCode,
      headers,
      title: 'Cloudflare Bot Protection Challenge',
      files: [],
      securityHeadersMissing: [],
      discoveredButtonsCount: 0,
      crawledPagesCount: 0,
      isCloudflareChallenge: true,
      error: 'CLOUDFLARE_BOT_PROTECTION'
    };
  }

  // Check Missing Security Headers
  const securityHeadersMissing: string[] = [];
  if (!headers['content-security-policy']) securityHeadersMissing.push('Content-Security-Policy');
  const hsts = headers['strict-transport-security'];
  if (!hsts || !hsts.toLowerCase().includes('preload')) securityHeadersMissing.push('Strict-Transport-Security (HSTS)');
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
      const subRes = await safeFetch(subUrl, { 
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
      const scriptRes = await safeFetch(scriptUrl, { 
        headers: { 'User-Agent': 'Zelsis-Release-Gate-Scanner/3.5' },
        maxRedirects: 3,
        signal: signal || AbortSignal.timeout(5000) 
      });
      if (scriptRes.ok) {
        const scriptText = await scriptRes.text();
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

  return {
    url: formattedUrl,
    statusCode,
    headers,
    title,
    files,
    securityHeadersMissing,
    discoveredButtonsCount,
    crawledPagesCount: subpagesToCrawl.length + 1
  };
}
