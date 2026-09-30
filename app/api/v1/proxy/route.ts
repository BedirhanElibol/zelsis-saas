import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { ProxyQuerySchema, validateQueryParams } from '@/lib/validations/api-schemas';
import { validateSafeTargetUrl } from '@/lib/ssrf-guard';
import { logger } from '@/lib/logger';

/**
 * Hardened Zelsis Serverless Proxy Endpoint
 * Allows server-side website fetching for live web release gate audits
 * without browser CORS restrictions or reliance on unverified third-party proxies.
 * Includes strict SSRF protection against RFC 1918 CIDRs, loopbacks, cloud metadata,
 * DNS rebinding, and port probing attacks.
 */
export async function GET(req: NextRequest) {
  // 1. Sliding-Window Rate Limit Check (Max 30 requests per minute per IP)
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 30,
    windowSeconds: 60,
    prefix: 'proxy'
  });

  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  // 2. Caller Authorization Defense (F-19: Prevent open proxy abuse)
  const authHeader = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  const apiKeyHeader = req.headers.get('x-api-key')?.trim();
  const secFetchSite = req.headers.get('sec-fetch-site');
  const origin = req.headers.get('origin');
  const host = req.headers.get('host');

  const isSameOrigin = secFetchSite === 'same-origin' || (origin && host && origin.includes(host));
  const hasValidAuth = Boolean(authHeader || apiKeyHeader || isSameOrigin);

  if (!hasValidAuth && process.env.NODE_ENV === 'production') {
    return NextResponse.json(
      {
        error: 'Unauthorized',
        message: 'Authentication required. Provide an Authorization Bearer token or API key to utilize the proxy audit service.'
      },
      { status: 401 }
    );
  }

  // 3. Server-side Zod Query Validation
  const validation = validateQueryParams(ProxyQuerySchema, req.nextUrl.searchParams);
  if (!validation.success) {
    return validation.response;
  }

  const { url: rawUrl } = validation.data;

  // 3. Enterprise SSRF Defense: Check RFC 1918 CIDRs, IPv6, Cloud Metadata, DNS Rebinding
  const ssrfCheck = await validateSafeTargetUrl(rawUrl);
  if (!ssrfCheck.safe || !ssrfCheck.url) {
    logger.warn(`[SSRF Blocked] Prohibited request to target: ${rawUrl} - Reason: ${ssrfCheck.reason}`);
    return NextResponse.json(
      {
        error: 'SSRF Protection Blocked Request',
        message: ssrfCheck.reason || 'Access to internal, private, or restricted network endpoints is forbidden.'
      },
      { status: 403 }
    );
  }

  const targetUrl = ssrfCheck.url.toString();

  let currentUrl = targetUrl;
  let finalRes: Response | null = null;
  let redirectHops = 0;
  const MAX_REDIRECTS = 3;

  try {
    while (true) {
      // TOCTOU DNS Rebinding Defense: Re-verify host IP immediately prior to outbound connection
      const preFlightCheck = await validateSafeTargetUrl(currentUrl);
      if (!preFlightCheck.safe || !preFlightCheck.url) {
        logger.warn(`[SSRF Blocked / DNS Rebinding] Target ${currentUrl} failed pre-flight check: ${preFlightCheck.reason}`);
        return NextResponse.json(
          {
            error: 'SSRF Protection Blocked Request',
            message: preFlightCheck.reason || 'Access to internal, private, or restricted network endpoints is forbidden.'
          },
          { status: 403 }
        );
      }

      logger.info(`[Proxy Fetch] Requesting verified target: ${currentUrl} (IP: ${preFlightCheck.resolvedIp || 'verified'})`);
      const res: Response = await fetch(currentUrl, {
        headers: {
          'User-Agent': 'Zelsis-Release-Gate-Scanner/4.0 (Enterprise Auditor)',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        },
        redirect: 'manual',
        signal: AbortSignal.timeout(10000)
      });

      // Handle HTTP redirects with strict SSRF re-validation
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        redirectHops++;
        if (redirectHops > MAX_REDIRECTS) {
          return NextResponse.json(
            { error: 'SSRF Protection Blocked Request', message: 'Exceeded maximum redirect depth (3 hops).' },
            { status: 403 }
          );
        }

        const locationHeader = res.headers.get('location');
        if (!locationHeader) {
          finalRes = res;
          break;
        }

        const resolvedRedirectUrl = new URL(locationHeader, currentUrl).toString();
        const redirectCheck = await validateSafeTargetUrl(resolvedRedirectUrl);
        if (!redirectCheck.safe || !redirectCheck.url) {
          logger.warn(`[SSRF Blocked] Prohibited redirect to: ${resolvedRedirectUrl} - ${redirectCheck.reason}`);
          return NextResponse.json(
            {
              error: 'SSRF Protection Blocked Request',
              message: redirectCheck.reason || 'Redirect to restricted or internal endpoint forbidden.'
            },
            { status: 403 }
          );
        }

        currentUrl = redirectCheck.url.toString();
        continue;
      }

      finalRes = res;
      break;
    }

    if (!finalRes) {
      throw new Error('No response received from proxy target.');
    }

    // VULN-02: Bounded Stream Reading (Max 2 MB / 2,097,152 bytes) to prevent OOM / DoS
    const MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2 MB

    // Fast-path: check Content-Length header if present
    const contentLengthHeader = finalRes.headers.get('content-length');
    if (contentLengthHeader) {
      const contentLength = parseInt(contentLengthHeader, 10);
      if (!isNaN(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
        return NextResponse.json(
          {
            error: 'Payload Too Large',
            message: `Proxy target response size (${contentLength} bytes) exceeds maximum allowable limit of 2 MB.`
          },
          { status: 413 }
        );
      }
    }

    // Stream reader with byte counter and early cancellation
    let bodyText = '';
    if (finalRes.body) {
      const reader = finalRes.body.getReader();
      const decoder = new TextDecoder('utf-8', { fatal: false });
      let totalBytesRead = 0;
      const chunks: string[] = [];

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          if (value) {
            totalBytesRead += value.byteLength;
            if (totalBytesRead > MAX_RESPONSE_BYTES) {
              await reader.cancel('Payload exceeded 2 MB limit');
              return NextResponse.json(
                {
                  error: 'Payload Too Large',
                  message: 'Proxy response stream exceeded the maximum allowable limit of 2 MB (2,097,152 bytes).'
                },
                { status: 413 }
              );
            }
            chunks.push(decoder.decode(value, { stream: true }));
          }
        }
        chunks.push(decoder.decode()); // Flush any remaining bytes
        bodyText = chunks.join('');
      } catch (streamErr: any) {
        if (totalBytesRead > MAX_RESPONSE_BYTES) {
          return NextResponse.json(
            {
              error: 'Payload Too Large',
              message: 'Proxy response stream exceeded the maximum allowable limit of 2 MB (2,097,152 bytes).'
            },
            { status: 413 }
          );
        }
        throw streamErr;
      }
    } else {
      bodyText = await finalRes.text();
    }

    const headersObj: Record<string, string> = {};

    // Forward safe HTTP response headers (excluding sensitive set-cookie)
    finalRes.headers.forEach((val, key) => {
      const lowerKey = key.toLowerCase();
      if (lowerKey !== 'set-cookie' && lowerKey !== 'set-cookie2') {
        headersObj[lowerKey] = val;
      }
    });

    const responseData = {
      url: currentUrl,
      status: finalRes.status,
      statusText: finalRes.statusText,
      headers: headersObj,
      content: bodyText.slice(0, 1000000) // Cap payload to 1MB
    };

    const payloadJson = JSON.stringify(responseData);
    const contentHash = crypto.createHash('sha256').update(payloadJson).digest('hex');
    const etag = `"${contentHash.slice(0, 16)}"`;

    if (req.headers.get('if-none-match') === etag) {
      return new NextResponse(null, {
        status: 304,
        headers: {
          'ETag': etag,
          'Cache-Control': 'private, s-maxage=60, stale-while-revalidate=300'
        }
      });
    }

    return new NextResponse(payloadJson, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'ETag': etag,
        'Cache-Control': 'private, s-maxage=60, stale-while-revalidate=300'
      }
    });
  } catch (err: any) {
    logger.error(`[Proxy Fetch Error] Failed to fetch: ${targetUrl}`, err?.message);
    return NextResponse.json(
      {
        error: 'Proxy Fetch Failed',
        message: process.env.NODE_ENV === 'production'
          ? 'Failed to establish connection to target website.'
          : (err?.message || 'Failed to reach target URL')
      },
      { status: 502 }
    );
  }
}
