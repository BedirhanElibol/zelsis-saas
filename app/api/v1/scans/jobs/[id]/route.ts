import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { logger } from '@/lib/logger';
import { getEffectiveSupabaseUrl, getEffectiveSupabaseAnonKey, getEffectiveSupabaseServiceRoleKey, getSupabaseAdmin } from '@/lib/supabase-admin';
import { isValidInternalSecret } from '@/lib/internal-auth';

export const dynamic = 'force-dynamic';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function GET(req: NextRequest, { params }: RouteParams) {
  try {
    const { id: jobId } = await params;

    if (!jobId || !/^[0-9a-fA-F-]{36}$/.test(jobId)) {
      return NextResponse.json(
        { status: 'ERROR', error: 'Invalid Job UUID format' },
        { status: 400 }
      );
    }

    const supabaseUrl = getEffectiveSupabaseUrl();
    const serviceRoleKey = getEffectiveSupabaseServiceRoleKey();

    if (!supabaseUrl || !serviceRoleKey) {
      return NextResponse.json(
        { status: 'ERROR', error: 'Database service configuration missing' },
        { status: 500 }
      );
    }

    const adminClient = getSupabaseAdmin();

    const { data: job, error: jobErr } = await adminClient
      .from('scan_jobs')
      .select('*')
      .eq('id', jobId)
      .maybeSingle();

    if (jobErr) {
      logger.error('[Scan Jobs API] Database query error:', jobErr);
      return NextResponse.json(
        { status: 'ERROR', error: 'Failed to retrieve scan job' },
        { status: 500 }
      );
    }

    if (!job) {
      return NextResponse.json(
        { status: 'ERROR', error: `Scan job "${jobId}" not found` },
        { status: 404 }
      );
    }

    // BOLA/IDOR Defense: Validate caller access rights if job is bound to a tenant
    if (job.user_id) {
      const authHeader = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '');
      const internalSecret = req.headers.get('x-zelsis-internal-secret');
      const isInternal = isValidInternalSecret(internalSecret);
      const anonKey = getEffectiveSupabaseAnonKey();

      let callerUserId: string | null = null;
      let isCallerAdmin = isInternal;

      // Extract bearer token from Authorization header or Supabase auth cookies
      let token = authHeader;
      if (!token) {
        for (const cookie of req.cookies.getAll()) {
          if (cookie.name.includes('-auth-token') || cookie.name === 'sb-access-token') {
            try {
              const parsed = JSON.parse(cookie.value);
              if (Array.isArray(parsed) && parsed[0]) {
                token = parsed[0];
                break;
              } else if (parsed?.access_token) {
                token = parsed.access_token;
                break;
              }
            } catch {
              if (cookie.value && cookie.value.length > 50) {
                token = cookie.value;
                break;
              }
            }
          }
        }
      }

      if (token && anonKey) {
        try {
          const authClient = createClient(supabaseUrl, anonKey, { auth: { persistSession: false } });
          const { data: { user } } = await authClient.auth.getUser(token);
          if (user) {
            callerUserId = user.id;
            const { data: profile } = await adminClient
              .from('profiles')
              .select('role')
              .eq('id', user.id)
              .maybeSingle();
            if (profile?.role === 'admin' || profile?.role === 'super_admin' || user.app_metadata?.role === 'admin') {
              isCallerAdmin = true;
            }
          }
        } catch {
          // Token decoding failure
        }
      }

      if (!isCallerAdmin && (!callerUserId || callerUserId !== job.user_id)) {
        // Return 404 to prevent malicious tenant job enumeration
        return NextResponse.json(
          { status: 'ERROR', error: `Scan job "${jobId}" not found` },
          { status: 404 }
        );
      }
    }

    // Optional: Fetch scan summary if job has finished successfully
    let scanSummary: Record<string, unknown> | null = null;
    if (job.status === 'COMPLETED' && job.scan_id) {
      const { data: scanRow } = await adminClient
        .from('scans')
        .select('id, readiness_score, gate_status, critical_count, high_count, medium_count, low_count, ui_cliche_count')
        .eq('id', job.scan_id)
        .maybeSingle();

      if (scanRow) {
        scanSummary = scanRow as Record<string, unknown>;
      }
    }

    const responsePayload = {
      status: 'SUCCESS',
      job: {
        id: job.id,
        projectId: job.project_id,
        repoUrl: job.repo_url,
        commitSha: job.commit_sha,
        status: job.status,
        progress: job.progress_percent,
        currentPhase: job.current_phase,
        currentFile: job.current_file,
        totalFiles: job.total_files,
        processedFiles: job.processed_files,
        findingsCount: job.findings_count,
        readinessScore: job.readiness_score,
        gateStatus: job.gate_status,
        scanId: job.scan_id,
        errorMessage: job.error_message,
        result: job.result_data,
        createdAt: job.created_at,
        updatedAt: job.updated_at
      },
      scanSummary
    };

    const bodyStr = JSON.stringify(responsePayload);
    const etag = `"${crypto.createHash('sha256').update(bodyStr).digest('hex')}"`;

    const headers: Record<string, string> = {
      'ETag': etag,
      'Cache-Control': job.status === 'COMPLETED' || job.status === 'FAILED'
        ? 'private, s-maxage=10, stale-while-revalidate=60'
        : 'private, no-cache, no-store, must-revalidate',
      'Deprecation': 'true',
      'Sunset': 'Fri, 01 Jan 2027 00:00:00 GMT',
      'Link': '</api/v2/scans/jobs>; rel="successor-version"'
    };

    const ifNoneMatch = req.headers.get('if-none-match');
    if (ifNoneMatch === etag) {
      return new NextResponse(null, {
        status: 304,
        headers
      });
    }

    return new NextResponse(bodyStr, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    });
  } catch (err: unknown) {
    logger.error('[Scan Jobs API] Unexpected error:', err);
    const message = err instanceof Error ? err.message : 'Internal job query error';
    return NextResponse.json(
      { status: 'ERROR', error: message },
      { status: 500 }
    );
  }
}
