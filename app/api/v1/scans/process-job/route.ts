import { NextRequest, NextResponse } from 'next/server';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { logger } from '@/lib/logger';
import { isValidInternalSecret } from '@/lib/internal-auth';
import { executeScanJob, ScanJobError } from '@/lib/scan-processor';

export const maxDuration = 30;
export const revalidate = 3600;

export async function POST(req: NextRequest) {
  // 1. Authenticate Internal Invocation (constant-time). Only unauthenticated callers are
  // IP rate-limited: genuine worker calls all share the server's egress IP.
  if (!isValidInternalSecret(req.headers.get('x-zelsis-internal-secret'))) {
    const rateLimit = await checkRateLimit(req, {
      maxRequests: 10,
      windowSeconds: 60,
      prefix: 'process-job'
    });
    if (!rateLimit.allowed) {
      return createRateLimitResponse(rateLimit);
    }
    logger.warn('[Process Job] Unauthorized background worker invocation attempted');
    return NextResponse.json({ error: 'Unauthorized internal worker route' }, { status: 401 });
  }

  // Validate Content-Type
  const contentType = req.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    return NextResponse.json(
      { error: 'Unsupported Media Type: Content-Type must be application/json' },
      { status: 415 }
    );
  }

  let body: any = {};
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON payload' }, { status: 400 });
  }

  try {
    const result = await executeScanJob(body);
    return NextResponse.json(result);
  } catch (err: any) {
    if (err instanceof ScanJobError) {
      return NextResponse.json({ error: err.message }, { status: err.status, headers: err.headers });
    }
    return NextResponse.json({ error: err?.message || 'Processing failed' }, { status: 500 });
  }
}
