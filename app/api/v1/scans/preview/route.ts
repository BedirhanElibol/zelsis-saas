import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { runStaticCodeScan } from '@/lib/scanner-engine';
import { fetchGithubRepositoryData, normalizeRepoUrl, parseGithubUrl } from '@/lib/github-api';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { logger } from '@/lib/logger';

export const maxDuration = 30;

const PreviewRequestSchema = z.object({
  repoUrl: z.string().trim().min(1).max(200),
});

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
const PREVIEW_FINDING_LIMIT = 3;

/**
 * POST /api/v1/scans/preview
 * Signup-free teaser scan for public GitHub repositories.
 * Returns only the summary (score, gate, severity counts, top finding titles);
 * file paths, snippets and remediation prompts stay behind sign-in.
 */
export async function POST(req: NextRequest) {
  const burstLimit = await checkRateLimit(req, {
    maxRequests: 3,
    windowSeconds: 60,
    prefix: 'scan-preview-burst',
    failClosed: true
  });
  if (!burstLimit.allowed) {
    return createRateLimitResponse(burstLimit);
  }

  const dailyLimit = await checkRateLimit(req, {
    maxRequests: 3,
    windowSeconds: 86400,
    prefix: 'scan-preview-daily',
    failClosed: true
  });
  if (!dailyLimit.allowed) {
    return NextResponse.json(
      {
        error: 'Free preview limit reached for today. Create a free account to keep scanning.',
        code: 'PREVIEW_LIMIT'
      },
      { status: 429 }
    );
  }

  const contentType = req.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    return NextResponse.json(
      { error: 'Unsupported Media Type: Content-Type must be application/json' },
      { status: 415 }
    );
  }

  const parsedBody = PreviewRequestSchema.safeParse(await req.json().catch(() => null));
  if (!parsedBody.success) {
    return NextResponse.json({ error: 'A repository URL is required.' }, { status: 400 });
  }

  const repoUrl = normalizeRepoUrl(parsedBody.data.repoUrl);
  if (!repoUrl || !parseGithubUrl(repoUrl)) {
    return NextResponse.json(
      { error: 'Enter a public GitHub repository (owner/repo or a github.com URL).' },
      { status: 400 }
    );
  }

  try {
    const repoData = await fetchGithubRepositoryData(repoUrl);

    if (repoData?.error === 'RATE_LIMIT_EXCEEDED') {
      return NextResponse.json(
        { error: 'GitHub is rate limiting us right now. Try again in a minute.' },
        { status: 429, headers: { 'Retry-After': '60' } }
      );
    }
    if (!repoData || repoData.error === 'REPO_NOT_FOUND' || repoData.error === 'PRIVATE_OR_UNAUTHENTICATED') {
      return NextResponse.json(
        { error: 'Repository not found. Previews work for public repositories only.' },
        { status: 404 }
      );
    }
    if (repoData.error && repoData.error !== 'EMPTY_REPOSITORY') {
      return NextResponse.json(
        { error: 'Could not fetch this repository from GitHub. Please try again.' },
        { status: 502 }
      );
    }
    if (repoData.error === 'EMPTY_REPOSITORY' || !repoData.files?.length) {
      return NextResponse.json(
        { error: 'No scannable source files found in this repository.' },
        { status: 422 }
      );
    }

    const result = await runStaticCodeScan(repoData.files, repoData.name || repoUrl, { dependencyAudit: { timeoutMs: 8000 } });

    const openFindings = result.findings.filter((f) => f.status === 'OPEN');
    const topFindings = [...openFindings]
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity as never) - SEVERITY_ORDER.indexOf(b.severity as never))
      .slice(0, PREVIEW_FINDING_LIMIT)
      .map((f) => ({ title: f.title, severity: f.severity, category: f.category }));

    return NextResponse.json({
      repoUrl,
      repoName: repoData.name || repoUrl,
      filesScanned: repoData.files.length,
      score: result.score,
      gateStatus: result.gateStatus,
      counts: {
        critical: result.criticalCount,
        high: result.highCount,
        medium: result.mediumCount,
        low: result.lowCount
      },
      totalFindings: openFindings.length,
      topFindings,
      remaining: dailyLimit.remaining
    });
  } catch (err: unknown) {
    logger.error('[Scan Preview] Failed:', err instanceof Error ? err.message : String(err));
    return NextResponse.json({ error: 'Preview scan failed. Please try again.' }, { status: 500 });
  }
}
