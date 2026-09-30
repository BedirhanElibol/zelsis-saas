import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { parseGithubUrl, prioritizeFilesForScan } from '@/lib/github-api';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { GithubProxyQuerySchema, validateQueryParams } from '@/lib/validations/api-schemas';
import { logger } from '@/lib/logger';
import { createClient } from '@supabase/supabase-js';

// CLOUD-01 Remediation: Enforce <= 15s synchronous serverless execution ceiling.
// Long-running batch background tasks (>15s) must be queued to async workers (SQS/Inngest/QStash)
// to prevent gateway 504 timeouts, client connection hanging, and serverless compute exhaustion (OWASP A04:2021).
export const maxDuration = 15;
export const dynamic = 'force-dynamic';

const GITHUB_RATE_LIMIT_MESSAGE =
  'GitHub API rate limit reached (60 req/hr). Add a GitHub Personal Access Token (PAT) in Settings to unlock 5,000 req/hr.';

/**
 * Checks whether a GitHub API response indicates a primary or secondary rate limit.
 */
function isGitHubRateLimited(
  status: number,
  headers: Headers,
  bodyText: string = '',
  hasToken: boolean = false
): boolean {
  if (status === 429) return true;
  if (headers.get('x-ratelimit-remaining') === '0') return true;
  if (headers.has('retry-after')) return true;
  if (status === 403) {
    if (headers.get('x-ratelimit-remaining') === '0') return true;
    if (/rate limit|secondary rate|abuse detection/i.test(bodyText)) return true;
    if (!hasToken) return true;
  }
  return false;
}

interface TokenState {
  token: string;
  remaining: number;
  resetTime: number; // Unix epoch ms
  isCoolingDown: boolean;
  consecutiveErrors: number;
}

/**
 * Server-Side Managed Rotating GitHub Token Pool
 * Distributes requests across multiple tokens configured via process.env.GITHUB_TOKENS,
 * tracks rate-limit quotas, automatically applies cooldowns for throttled tokens (< 10 requests remaining or 429s),
 * and seamlessly rotates to the next healthiest token without user intervention.
 */
class GitHubTokenPool {
  private tokens: TokenState[] = [];
  private currentIndex: number = 0;

  constructor() {
    this.initTokens();
  }

  public initTokens(): void {
    const rawTokens =
      process.env.GITHUB_TOKENS ||
      process.env.GITHUB_TOKEN ||
      process.env.GITHUB_PAT ||
      '';

    const tokenList = rawTokens
      .split(',')
      .map(t => t.trim())
      .filter(t => t.length > 0);

    const existingMap = new Map(this.tokens.map(t => [t.token, t]));
    this.tokens = tokenList.map(token => {
      const existing = existingMap.get(token);
      return (
        existing || {
          token,
          remaining: 5000,
          resetTime: 0,
          isCoolingDown: false,
          consecutiveErrors: 0
        }
      );
    });
  }

  /**
   * Retrieves the healthiest available token.
   * If a user-provided token (OAuth or custom PAT) is passed, it takes precedence.
   */
  public getEffectiveToken(userOverrideToken?: string): string | undefined {
    if (userOverrideToken && userOverrideToken.trim().length > 0) {
      return userOverrideToken.trim();
    }

    if (this.tokens.length === 0) {
      this.initTokens();
    }

    if (this.tokens.length === 0) {
      return undefined;
    }

    const now = Date.now();
    // Release tokens whose cooldown has expired
    for (const t of this.tokens) {
      if (t.isCoolingDown && now > t.resetTime) {
        t.isCoolingDown = false;
        t.remaining = 5000;
        t.consecutiveErrors = 0;
      }
    }

    // Filter tokens that are not cooling down and have at least 10 remaining requests
    const healthyTokens = this.tokens.filter(t => !t.isCoolingDown && t.remaining >= 10);

    if (healthyTokens.length > 0) {
      // Pick token with highest remaining quota
      healthyTokens.sort((a, b) => b.remaining - a.remaining);
      return healthyTokens[0].token;
    }

    // Fallback: If all tokens are cooling down or depleted, select the one closest to reset
    const sortedByReset = [...this.tokens].sort((a, b) => a.resetTime - b.resetTime);
    const fallback = sortedByReset[this.currentIndex % sortedByReset.length];
    this.currentIndex = (this.currentIndex + 1) % sortedByReset.length;
    return fallback?.token;
  }

  /**
   * Records rate limit telemetry and status feedback for a token.
   */
  public reportFeedback(
    token: string | undefined,
    status: number,
    headers: Headers,
    bodyText: string = ''
  ): void {
    if (!token) return;
    const state = this.tokens.find(t => t.token === token);
    if (!state) return;

    const remainingHeader = headers.get('x-ratelimit-remaining');
    const resetHeader = headers.get('x-ratelimit-reset');

    if (remainingHeader !== null) {
      const parsedRemaining = parseInt(remainingHeader, 10);
      if (!isNaN(parsedRemaining)) {
        state.remaining = parsedRemaining;
      }
    }

    if (resetHeader !== null) {
      const parsedReset = parseInt(resetHeader, 10);
      if (!isNaN(parsedReset)) {
        state.resetTime = parsedReset * 1000;
      }
    }

    const rateLimited = isGitHubRateLimited(status, headers, bodyText, true);

    if (rateLimited || status === 429 || state.remaining < 10) {
      state.isCoolingDown = true;
      state.consecutiveErrors++;
      if (!state.resetTime || state.resetTime <= Date.now()) {
        state.resetTime = Date.now() + 60_000; // 1-minute fallback cooldown
      }
      logger.warn(
        `[GitHubTokenPool] Token marked for cooldown until ${new Date(state.resetTime).toISOString()}. Remaining: ${state.remaining}`
      );
    } else if (status >= 200 && status < 300) {
      state.consecutiveErrors = 0;
      if (state.remaining >= 10) {
        state.isCoolingDown = false;
      }
    }
  }

  public getPoolSize(): number {
    return this.tokens.length;
  }

  public getStats(): { total: number; healthy: number; coolingDown: number } {
    const now = Date.now();
    return {
      total: this.tokens.length,
      healthy: this.tokens.filter(t => !t.isCoolingDown && t.remaining >= 10).length,
      coolingDown: this.tokens.filter(t => t.isCoolingDown || (t.resetTime > now && t.remaining < 10)).length
    };
  }
}

const tokenPool = new GitHubTokenPool();

function getAuthHeader(token: string): string {
  const trimmed = token.trim();
  if (trimmed.startsWith('ghp_')) {
    return `token ${trimmed}`;
  }
  return `Bearer ${trimmed}`;
}

/**
 * Hardened Server-side GitHub API Proxy Endpoint
 * Securely routes GitHub API requests through the Next.js server to prevent unauthenticated
 * 404/403 network error logs in client browser DevTools for private repositories.
 * Strictly verifies GitHub repository syntax and prevents Path Traversal and SSRF.
 */
export async function GET(req: NextRequest) {
  // 1. Rate Limiting Check (Max 40 requests per minute per IP)
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 40,
    windowSeconds: 60,
    prefix: 'github-proxy'
  });

  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  // 2. Caller Authorization Defense (F-09: Proper JWT verification instead of presence-only check)
  const authHeaderRaw = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  let authenticatedUserId: string | null = null;

  // If a Bearer token is provided, verify it's a valid Supabase JWT
  if (authHeaderRaw && supabaseUrl && supabaseAnonKey) {
    try {
      const authClient = createClient(supabaseUrl, supabaseAnonKey);
      const { data: authData, error: authError } = await authClient.auth.getUser(authHeaderRaw);
      if (authError || !authData?.user) {
        logger.warn(`[GitHub Proxy] Invalid Bearer token rejected`);
        return NextResponse.json(
          { error: 'Unauthorized', message: 'Invalid or expired authentication token.' },
          { status: 401 }
        );
      }
      authenticatedUserId = authData.user.id;
    } catch {
      return NextResponse.json(
        { error: 'Unauthorized', message: 'Authentication verification failed.' },
        { status: 401 }
      );
    }
  }
  // Note: Unauthenticated access is allowed for public repo scanning (core product feature).
  // Private repo access is separately guarded at the repo-level check below (line ~378).

  // 3. Prohibit credential transmission via URL query string (CWE-598)
  if (req.nextUrl.searchParams.has('token')) {
    return NextResponse.json(
      {
        error: 'Insecure Credential Transmission (CWE-598)',
        message: 'Passing GitHub tokens in URL query string is prohibited due to CWE-598. Pass via Authorization: Bearer header.'
      },
      { status: 400 }
    );
  }

  // 4. Strict Zod Query Parameter Validation
  const validation = validateQueryParams(GithubProxyQuerySchema, req.nextUrl.searchParams);
  if (!validation.success) {
    return validation.response;
  }

  const { repoUrl } = validation.data;
  const parsed = parseGithubUrl(repoUrl);

  if (!parsed || !parsed.owner || !parsed.repo || parsed.owner === 'local') {
    return NextResponse.json(
      { error: 'Invalid GitHub repository format. Expected "owner/repo" or "https://github.com/owner/repo"' },
      { status: 400 }
    );
  }

  const { owner, repo } = parsed;

  // Sanitize owner and repo to only contain valid GitHub characters [a-zA-Z0-9_.-]
  const safeIdentifier = /^[a-zA-Z0-9_\-\.]+$/;
  if (!safeIdentifier.test(owner) || !safeIdentifier.test(repo)) {
    return NextResponse.json(
      { error: 'Invalid repository owner or name characters' },
      { status: 400 }
    );
  }

  // 4. Secure Token Extraction: User-provided token (Authorization header, custom header, or OAuth cookie) takes precedence
  const authHeader = req.headers.get('authorization');
  const userToken =
    authHeader?.replace(/^Bearer\s+/i, '').trim() ||
    req.headers.get('x-github-token')?.trim() ||
    req.cookies.get('sb-provider-token')?.value?.trim() ||
    req.cookies.get('github_token')?.value?.trim() ||
    undefined;

  let activeToken = tokenPool.getEffectiveToken(userToken);

  try {
    let repoRes: Response | null = null;
    let attempts = 0;
    const maxAttempts = !userToken && tokenPool.getPoolSize() > 1 ? 2 : 1;

    while (attempts < maxAttempts) {
      attempts++;
      const headers: Record<string, string> = {
        Accept: 'application/vnd.github.v3+json',
        'User-Agent': 'Zelsis-Release-Gate-Scanner/4.0'
      };

      if (activeToken) {
        headers['Authorization'] = getAuthHeader(activeToken);
      }

      logger.info(`Fetching GitHub repository metadata: ${owner}/${repo} (attempt ${attempts}/${maxAttempts})`);
      repoRes = await fetch(
        `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
        {
          headers,
          signal: AbortSignal.timeout(5000)
        }
      );

      let bodyText = '';
      if (!repoRes.ok && repoRes.status !== 404) {
        try {
          bodyText = await repoRes.clone().text();
        } catch {
          bodyText = '';
        }
      }

      tokenPool.reportFeedback(activeToken, repoRes.status, repoRes.headers, bodyText);

      const isRateLimit = isGitHubRateLimited(repoRes.status, repoRes.headers, bodyText, Boolean(activeToken));

      if (isRateLimit && !userToken && attempts < maxAttempts) {
        logger.warn(`[GitHub Proxy] Primary token rate limited. Rotating to next token from pool...`);
        activeToken = tokenPool.getEffectiveToken();
        continue;
      }

      break;
    }

    if (!repoRes || !repoRes.ok) {
      if (repoRes && repoRes.status === 404) {
        return NextResponse.json({
          name: repo,
          fullName: `${owner}/${repo}`,
          error: 'REPO_NOT_FOUND',
          message: 'GitHub repository not found. Verify the owner and repository name for typos.',
          files: []
        });
      }

      let bodyText = '';
      try {
        if (repoRes) bodyText = await repoRes.text();
      } catch {
        bodyText = '';
      }

      const isRateLimit = repoRes ? isGitHubRateLimited(repoRes.status, repoRes.headers, bodyText, Boolean(activeToken)) : false;

      return NextResponse.json({
        name: repo,
        fullName: `${owner}/${repo}`,
        description: isRateLimit
          ? GITHUB_RATE_LIMIT_MESSAGE
          : 'Private or Unauthenticated GitHub Repository. Provide a GitHub PAT token in Settings to access private repos.',
        message: isRateLimit
          ? GITHUB_RATE_LIMIT_MESSAGE
          : 'Private or Unauthenticated GitHub Repository. Provide a GitHub PAT token in Settings to access private repos.',
        defaultBranch: 'main',
        stars: 0,
        language: 'TypeScript',
        files: [],
        error: isRateLimit ? 'RATE_LIMIT_EXCEEDED' : 'PRIVATE_OR_UNAUTHENTICATED',
        isPrivate: !isRateLimit
      });
    }

    const repoData = await repoRes.json();

    // F-09 Remediation: Strict Token Pool Isolation.
    // If the repository is private and no user-supplied token was provided, reject immediately.
    // The server's token pool is strictly for public repository read rate-limit headroom.
    if (repoData.private && !userToken) {
      logger.warn(`[GitHub Proxy Security] Blocked attempt to access private repo ${owner}/${repo} via server token pool without user token`);
      return NextResponse.json({
        name: repoData.name || repo,
        fullName: repoData.full_name || `${owner}/${repo}`,
        description: 'Private repository access restricted. Provide your own GitHub PAT token to access private repositories.',
        message: 'Private repository access restricted. Provide your own GitHub PAT token to access private repositories.',
        error: 'PRIVATE_OR_UNAUTHENTICATED',
        isPrivate: true,
        files: []
      }, { status: 401 });
    }

    const detectedBranch = typeof repoData.default_branch === 'string' && repoData.default_branch
      ? repoData.default_branch
      : 'main';

    // Handle empty repository immediately if size is 0
    if (typeof repoData.size === 'number' && repoData.size === 0) {
      return NextResponse.json({
        name: repoData.name || repo,
        fullName: repoData.full_name || `${owner}/${repo}`,
        isEmpty: true,
        error: 'EMPTY_REPOSITORY',
        message: 'Empty repository. No scannable source code files found.',
        files: []
      });
    }

    // Default branch detection with fallback checks for main, master, and develop
    const candidateBranches = Array.from(
      new Set([detectedBranch, 'main', 'master', 'develop'].filter(Boolean))
    );
    let treeRes: Response | null = null;
    let activeBranch = detectedBranch;

    for (const branch of candidateBranches) {
      try {
        const headers: Record<string, string> = {
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'Zelsis-Release-Gate-Scanner/4.0'
        };
        if (activeToken) {
          headers['Authorization'] = getAuthHeader(activeToken);
        }

        const res = await fetch(
          `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
          { headers, signal: AbortSignal.timeout(5000) }
        );

        tokenPool.reportFeedback(activeToken, res.status, res.headers);

        if (res.ok) {
          treeRes = res;
          activeBranch = branch;
          break;
        } else if (res.status === 409) {
          // GitHub returns 409 Conflict when repository is empty
          treeRes = res;
          activeBranch = branch;
          break;
        } else if (res.status === 403 || res.status === 429 || res.headers.get('x-ratelimit-remaining') === '0') {
          // If rate limited and using server pool, rotate token once and retry branch
          if (!userToken && tokenPool.getPoolSize() > 1) {
            activeToken = tokenPool.getEffectiveToken();
            const retryHeaders: Record<string, string> = {
              Accept: 'application/vnd.github.v3+json',
              'User-Agent': 'Zelsis-Release-Gate-Scanner/4.0'
            };
            if (activeToken) {
              retryHeaders['Authorization'] = getAuthHeader(activeToken);
            }
            const retryRes = await fetch(
              `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
              { headers: retryHeaders, signal: AbortSignal.timeout(5000) }
            );
            tokenPool.reportFeedback(activeToken, retryRes.status, retryRes.headers);
            if (retryRes.ok || retryRes.status === 409) {
              treeRes = retryRes;
              activeBranch = branch;
              break;
            }
          }
          treeRes = res;
          break;
        }
      } catch {
        // Fallback to next branch candidate
      }
    }

    if (!treeRes || !treeRes.ok) {
      // Empty repository handling (409 Conflict)
      if (treeRes && treeRes.status === 409) {
        return NextResponse.json({
          name: repoData.name || repo,
          fullName: repoData.full_name || `${owner}/${repo}`,
          isEmpty: true,
          error: 'EMPTY_REPOSITORY',
          message: 'Empty repository. No scannable source code files found.',
          files: []
        });
      }

      // Check if rate limited during tree fetch
      let treeBody = '';
      try {
        if (treeRes) treeBody = await treeRes.text();
      } catch {
        treeBody = '';
      }
      const isTreeRateLimit = treeRes ? isGitHubRateLimited(treeRes.status, treeRes.headers, treeBody, Boolean(activeToken)) : false;

      if (isTreeRateLimit) {
        return NextResponse.json({
          name: repoData.name || repo,
          fullName: repoData.full_name || `${owner}/${repo}`,
          description: GITHUB_RATE_LIMIT_MESSAGE,
          message: GITHUB_RATE_LIMIT_MESSAGE,
          defaultBranch: activeBranch,
          stars: repoData.stargazers_count || 0,
          language: repoData.language || 'TypeScript',
          files: [],
          error: 'RATE_LIMIT_EXCEEDED'
        });
      }

      return NextResponse.json({
        name: repoData.name,
        fullName: repoData.full_name,
        description: `GitHub Tree Fetch Failed (HTTP ${treeRes ? treeRes.status : 'Unknown'})`,
        defaultBranch: activeBranch,
        stars: repoData.stargazers_count,
        language: repoData.language,
        files: [],
        error: 'TREE_FETCH_FAILED'
      });
    }

    let treeData: { tree?: Array<{ type: string; path: string; size?: number }> } = {};
    try {
      treeData = await treeRes.json();
    } catch {
      treeData = { tree: [] };
    }

    const treeFiles = (treeData.tree || [])
      .filter(
        (item: any) =>
          item.type === 'blob' &&
          typeof item.path === 'string' &&
          (!item.size || item.size <= 2000000) &&
          (/(\.(ts|tsx|js|jsx|json|css|sql|html|py|yml|yaml|toml|sh|ps1|c|cpp|cc|cxx|h|hpp|java|kt|kts|go|rs|php|cs|rb|swift|xml|plist|gradle|md|mdx|zelsisignore|shipguardignore)$)|(\.env(\.[a-zA-Z0-9_\-]+)?$)|((?:^|\/)(?:dockerfile|makefile|podfile)$)/i.test(item.path)) &&
          !item.path.includes('node_modules') &&
          !item.path.includes('.next') &&
          !item.path.includes('.git') &&
          !item.path.includes('dist/') &&
          !item.path.includes('build/') &&
          !item.path.includes('vendor/') &&
          !item.path.includes('.agent') &&
          !item.path.includes('.antigravity') &&
          !item.path.includes('artifacts') &&
          !item.path.includes('venv/') &&
          !item.path.includes('.venv/') &&
          !item.path.includes('__pycache__/')
      );

    if (treeFiles.length === 0) {
      return NextResponse.json({
        name: repoData.name || repo,
        fullName: repoData.full_name || `${owner}/${repo}`,
        isEmpty: true,
        error: 'EMPTY_REPOSITORY',
        message: 'Empty repository. No scannable source code files found.',
        files: []
      });
    }

    // Prioritize and fetch all scannable source code files in parallel chunks
    const filesToFetch = prioritizeFilesForScan(treeFiles);

    // Fetch raw file contents in parallel chunks from GitHub
    const CHUNK_SIZE = 30;
    const fetchedFiles: Array<{ path: string; content: string }> = [];

    for (let i = 0; i < filesToFetch.length; i += CHUNK_SIZE) {
      const chunk = filesToFetch.slice(i, i + CHUNK_SIZE);
      const chunkResults = await Promise.all(
        chunk.map(async (file: any) => {
          try {
            const currentToken = tokenPool.getEffectiveToken(userToken);
            const rawHeaders: Record<string, string> = {};
            if (currentToken) {
              rawHeaders['Authorization'] = getAuthHeader(currentToken);
            }

            // Encode URI components in path while preserving slashes
            const encodedPath = file.path.split('/').map(encodeURIComponent).join('/');
            const rawRes = await fetch(
              `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(activeBranch)}/${encodedPath}`,
              {
                headers: rawHeaders,
                signal: AbortSignal.timeout(4000)
              }
            );

            tokenPool.reportFeedback(currentToken, rawRes.status, rawRes.headers);

            if (rawRes.ok) {
              let content = await rawRes.text();
              // File size guard: cap at 200KB per-file limit to avoid ReDoS or memory exhaustion across rules
              if (content.length > 200000) {
                content = content.slice(0, 200000);
              }
              return { path: file.path, content };
            }
          } catch (err: any) {
            logger.warn(`[GitHub Proxy] Error fetching raw file ${file.path}`, err?.message);
          }
          return null;
        })
      );
      fetchedFiles.push(...chunkResults.filter((f): f is { path: string; content: string } => f !== null));
    }

    if (fetchedFiles.length === 0) {
      return NextResponse.json({
        name: repoData.name || repo,
        fullName: repoData.full_name || `${owner}/${repo}`,
        isEmpty: true,
        error: 'EMPTY_REPOSITORY',
        message: 'Empty repository. No scannable source code files found.',
        files: []
      });
    }

    const responsePayload = {
      name: repoData.name,
      fullName: repoData.full_name,
      description: repoData.description || `Public GitHub Repository (${repoData.stargazers_count} stars)`,
      defaultBranch: activeBranch,
      stars: repoData.stargazers_count,
      language: repoData.language || 'TypeScript',
      files: fetchedFiles,
      isPrivate: repoData.private || false
    };

    const payloadJson = JSON.stringify(responsePayload);
    const contentHash = crypto.createHash('sha256').update(payloadJson).digest('hex');
    const etag = `"${contentHash.slice(0, 16)}"`;

    if (req.headers.get('if-none-match') === etag) {
      return new NextResponse(null, {
        status: 304,
        headers: {
          'ETag': etag,
          'Cache-Control': 'public, s-maxage=60, stale-while-revalidate=300'
        }
      });
    }

    return new NextResponse(payloadJson, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'ETag': etag,
        'Cache-Control': 'public, s-maxage=60, stale-while-revalidate=300'
      }
    });
  } catch (err: any) {
    logger.error(`[GitHub Proxy] Failed to proxy repository: ${owner}/${repo}`, err);
    return NextResponse.json(
      {
        name: repo,
        fullName: `${owner}/${repo}`,
        description: 'Failed to complete GitHub repository fetch request',
        defaultBranch: 'main',
        stars: 0,
        language: 'TypeScript',
        files: [],
        error: process.env.NODE_ENV === 'production' ? 'GITHUB_PROXY_ERROR' : err?.message
      },
      { status: 502 }
    );
  }
}
