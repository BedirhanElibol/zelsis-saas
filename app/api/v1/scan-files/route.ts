import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { getSupabaseAdmin } from '@/lib/supabase-admin';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { ScanFilesRequestSchema, validateRequestBody, type ScanFilesRequest } from '@/lib/validations/api-schemas';
import { hasFixPromptAccess } from '@/lib/subscription-utils';
import { getEffectivePlanTier, getOrgPolicy } from '@/lib/organization';
import { scanUploadedFiles } from '@/lib/scan-files';
import { logger } from '@/lib/logger';

export const maxDuration = 60;
export const dynamic = 'force-dynamic';

/**
 * Scans local files sent by the zelsis CLI or MCP server. Requires an API key (Settings -> API keys).
 * Files are scanned in memory and not stored; only the response leaves this handler.
 */
export async function POST(req: NextRequest) {
  try {
    const rateLimit = await checkRateLimit(req, { maxRequests: 30, windowSeconds: 60, prefix: 'scan-files' });
    if (!rateLimit.allowed) return createRateLimitResponse(rateLimit);

    const apiKey = req.headers.get('x-api-key')?.trim();
    if (!apiKey) {
      return NextResponse.json({ error: 'Missing API key. Create one in Zelsis: Settings -> API keys, then set ZELSIS_API_KEY.' }, { status: 401 });
    }

    const admin = getSupabaseAdmin();
    if (!admin) return NextResponse.json({ error: 'Scanning is temporarily unavailable.' }, { status: 503 });
    const hash = crypto.createHash('sha256').update(apiKey).digest('hex');
    const { data: keyRow } = await admin.from('api_keys').select('id, user_id, expires_at').eq('key_hash', hash).maybeSingle();
    if (!keyRow) return NextResponse.json({ error: 'Invalid API key.' }, { status: 401 });
    if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() < Date.now()) {
      return NextResponse.json({ error: 'This API key has expired. Create a new one in Settings -> API keys.' }, { status: 401 });
    }
    admin.from('api_keys').update({ last_used_at: new Date().toISOString() }).eq('id', keyRow.id).then(
      () => {},
      (err: unknown) => logger.warn('[Scan Files] Notice updating last_used_at:', err),
    );

    const rawBody = await req.json().catch(() => null);
    const validation = validateRequestBody<ScanFilesRequest>(ScanFilesRequestSchema, rawBody);
    if (!validation.success) return validation.response;

    const userId: string = keyRow.user_id;
    const tier = await getEffectivePlanTier(admin, userId);
    const orgPolicy = await getOrgPolicy(admin, userId);
    const { data: dismissalRows } = await admin
      .from('finding_dismissals')
      .select('rule_id, file_path')
      .eq('user_id', userId)
      .eq('status', 'ACTIVE');

    const result = await scanUploadedFiles(validation.data.files, {
      projectName: validation.data.projectName,
      changed: validation.data.changed,
      canSeeFixes: hasFixPromptAccess(tier),
      orgPolicy,
      dismissals: (dismissalRows ?? []).map((d: { rule_id: number; file_path: string }) => ({ ruleId: d.rule_id, filePath: d.file_path })),
    });

    return NextResponse.json(result);
  } catch (error) {
    logger.error('[Scan Files] Internal error:', error);
    return NextResponse.json({ error: 'Scan failed. Try again in a minute.' }, { status: 500 });
  }
}
