import { CodeFile } from './scanner-engine';
import { isDependencyFile } from '@/lib/scanner/dependencies';

export interface FetchProgress {
  phase: 'connecting' | 'tree' | 'fetching';
  loaded: number;
  total: number;
  currentFile: string;
}

export function createTimeoutSignal(timeoutMs: number, userSignal?: AbortSignal): AbortSignal {
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  if (!userSignal) return timeoutSignal;
  if (typeof (AbortSignal as any).any === 'function') {
    return (AbortSignal as any).any([userSignal, timeoutSignal]);
  }
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  userSignal.addEventListener('abort', onAbort, { once: true });
  timeoutSignal.addEventListener('abort', onAbort, { once: true });
  return controller.signal;
}

export interface GithubRepoInfo {
  name: string;
  fullName: string;
  description: string;
  defaultBranch: string;
  stars: number;
  language: string;
  files: CodeFile[];
  isPrivate?: boolean;
  requiresAuth?: boolean;
  isEmpty?: boolean;
  error?: 'RATE_LIMIT_EXCEEDED' | 'PRIVATE_OR_UNAUTHENTICATED' | 'TREE_FETCH_FAILED' | 'REPO_NOT_FOUND' | 'EMPTY_REPOSITORY' | 'CLOUDFLARE_BOT_PROTECTION' | string;
}

const GITHUB_RATE_LIMIT_MESSAGE =
  'GitHub API rate limit reached (60 req/hr on shared server IP). Add a GitHub Personal Access Token (PAT) for free in Settings to unlock 5,000 req/hr without upgrading.';

/**
 * Checks whether a GitHub API response indicates a primary or secondary rate limit.
 */
function isGitHubRateLimited(status: number, headers: Headers, bodyText: string = '', hasToken: boolean = false): boolean {
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

export function sanitizeTargetUrl(url: string): string {
  if (!url || typeof url !== 'string') return '';
  let clean = url.trim();

  if (clean.startsWith('git@github.com:')) {
    clean = `https://github.com/${clean.replace('git@github.com:', '')}`;
  }

  clean = clean.replace(/\.git$/i, '');
  clean = clean.replace(/\/tree\/[^\/]+.*$/i, '');
  clean = clean.replace(/\/blob\/[^\/]+.*$/i, '');
  clean = clean.replace(/\/+$/, '');

  return clean;
}

export function parseGithubUrl(url: string): { owner: string; repo: string } | null {
  if (!url || typeof url !== 'string' || url.trim().length === 0) return null;
  const clean = sanitizeTargetUrl(url);

  try {
    const match = clean.match(/github\.com\/([^\/]+)\/([^\/?#]+)/i);
    if (match && match[1] && match[2]) {
      return { owner: match[1].trim(), repo: match[2].replace(/\.git$/i, '').trim() };
    }

    // Support owner/repo format without domain (e.g. "facebook/react" or "leerob/site")
    const shortMatch = clean.match(/^([a-zA-Z0-9_\-\.]+)\/([a-zA-Z0-9_\-\.]+)$/);
    if (shortMatch && shortMatch[1] && shortMatch[2]) {
      return { owner: shortMatch[1].trim(), repo: shortMatch[2].replace(/\.git$/i, '').trim() };
    }

    return null;
  } catch (e: any) {
    return null;
  }
}

export function normalizeRepoUrl(raw: string): string {
  if (!raw || typeof raw !== 'string') return '';
  let clean = raw.trim();

  // If it's a live web URL (not github.com), return normalized URL
  if (/^https?:\/\/(?!github\.com)/i.test(clean)) {
    return clean.replace(/\/+$/, '');
  }

  // Handle git@github.com:owner/repo
  if (clean.startsWith('git@github.com:')) {
    clean = clean.replace('git@github.com:', '');
  }

  // Remove trailing .git, tree/..., blob/...
  clean = clean.replace(/\.git$/i, '');
  clean = clean.replace(/\/tree\/[^\/]+.*$/i, '');
  clean = clean.replace(/\/blob\/[^\/]+.*$/i, '');
  clean = clean.replace(/\/+$/, '');

  // Strip leading protocols or domain for uniform parsing
  clean = clean.replace(/^https?:\/\//i, '');
  clean = clean.replace(/^github\.com\//i, '');

  const parts = clean.split('/').filter(Boolean);
  if (parts.length >= 2) {
    return `https://github.com/${parts[0]}/${parts[1]}`;
  }
  if (parts.length === 1 && parts[0]) {
    return `https://github.com/${parts[0]}`;
  }

  return `https://github.com/${clean}`;
}

export function extractRepoDisplayName(url: string): string {
  if (!url || typeof url !== 'string') return 'Repository';
  const clean = sanitizeTargetUrl(url);
  const parsed = parseGithubUrl(clean);
  if (parsed) {
    return `${parsed.owner}/${parsed.repo}`;
  }
  try {
    const parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
    return parsedUrl.hostname || 'Target Deployment';
  } catch {
    return clean.replace(/^https?:\/\//, '') || 'Repository';
  }
}

export function isValidGithubUrl(url: string): boolean {
  if (!url || typeof url !== 'string' || url.trim().length === 0) return false;
  const clean = sanitizeTargetUrl(url);
  return /^(?:https?:\/\/github\.com\/)?([a-zA-Z0-9_\-\.]+)\/([a-zA-Z0-9_\-\.]+)(?:\.git)?(?:\/.*)?$/.test(clean);
}

/**
 * Intelligent file prioritizer for AST security & deployment readiness scanning.
 * Ensures the most impactful architecture, manifest, route, and security files are audited
 * while keeping scans fast (2-3s) and well within GitHub API & Vercel serverless bounds.
 */
export function prioritizeFilesForScan<T extends { path: string }>(files: T[], maxFiles?: number): T[] {
  const getFileScore = (filePath: string): number => {
    const lower = filePath.toLowerCase();

    // Lowest priority: test suites, fixtures, sample mock data, markdown docs
    if (
      lower.includes('__tests__') ||
      lower.includes('.test.') ||
      lower.includes('.spec.') ||
      lower.includes('/fixtures/') ||
      lower.includes('/examples/') ||
      lower.includes('/e2e/') ||
      lower.includes('/cypress/') ||
      lower.includes('/test/') ||
      lower.includes('/tests/') ||
      lower.includes('/mock') ||
      lower.includes('test_')
    ) {
      return 10;
    }

    // Tier 1: Critical project manifests & infrastructure configs (90-100)
    if (lower.endsWith('package.json')) return 100;
    // Lockfiles carry the exact dependency versions checked against OSV.dev
    if (isDependencyFile(lower)) return 99;
    if (lower.endsWith('next.config.js') || lower.endsWith('next.config.mjs') || lower.endsWith('next.config.ts')) return 98;
    if (lower.includes('.env')) return 97;
    if (lower.endsWith('dockerfile') || lower.includes('docker-compose')) return 96;
    if (lower.includes('.github/workflows/')) return 95;
    if (lower.endsWith('tsconfig.json')) return 94;
    if (lower.endsWith('security.md')) return 93;
    if (lower.endsWith('requirements.txt') || lower.endsWith('pyproject.toml') || lower.endsWith('cargo.toml') || lower.endsWith('go.mod')) return 92;

    // Tier 2: Server endpoints, auth, middlewares & routing (80-90)
    if (lower.includes('middleware.')) return 90;
    if (lower.includes('/api/') || lower.startsWith('api/')) return 88;
    if (lower.includes('auth') || lower.includes('session')) return 87;
    if (lower.endsWith('layout.tsx') || lower.endsWith('layout.jsx') || lower.endsWith('layout.js')) return 85;
    if (lower.endsWith('page.tsx') || lower.endsWith('page.jsx') || lower.endsWith('route.ts') || lower.endsWith('route.js')) return 84;
    if (lower.includes('/lib/') || lower.includes('/utils/') || lower.includes('/server/') || lower.includes('/services/')) return 80;

    // Tier 3: UI Components & Application Logic (60-79)
    if (lower.includes('/components/')) return 75;
    if (lower.endsWith('.ts') || lower.endsWith('.tsx') || lower.endsWith('.js') || lower.endsWith('.jsx')) return 70;
    if (lower.endsWith('.py') || lower.endsWith('.go') || lower.endsWith('.rs') || lower.endsWith('.php')) return 68;

    // F-39: Exclude minified bundles, source maps, and vendored third-party code
    if (
      lower.endsWith('.min.js') ||
      lower.endsWith('.min.css') ||
      lower.endsWith('.bundle.js') ||
      lower.endsWith('.map') ||
      lower.includes('/vendor/') ||
      lower.includes('/third_party/') ||
      lower.includes('node_modules/')
    ) {
      return -1;
    }

    return 30;
  };

  const sorted = [...files]
    .filter((f) => getFileScore(f.path) > 0)
    .sort((a, b) => getFileScore(b.path) - getFileScore(a.path));

  if (typeof maxFiles === 'number' && maxFiles > 0) {
    return sorted.slice(0, maxFiles);
  }
  return sorted;
}

/**
 * Live GitHub Repository Fetcher
 * Verifies that the GitHub repository exists and fetches its real file tree & source contents via GitHub REST API.
 */
export async function fetchGithubRepositoryData(
  repoUrl: string,
  token?: string,
  signal?: AbortSignal,
  onProgress?: (progress: FetchProgress) => void
): Promise<GithubRepoInfo | null> {
  const parsed = parseGithubUrl(repoUrl);
  if (!parsed) return null;

  // 1. Browser Client Proxy Attempt (Runs only in browser where relative URLs resolve)
  const isBrowser = typeof window !== 'undefined';
  if (isBrowser) {
    try {
      onProgress?.({
        phase: 'connecting',
        loaded: 0,
        total: 0,
        currentFile: `Connecting to ${parsed.owner}/${parsed.repo}...`
      });

      const proxyEndpoint = `/api/v1/github-proxy?repoUrl=${encodeURIComponent(repoUrl)}`;
      const proxyHeaders: Record<string, string> = {};
      let effectiveToken = token;
      if (!effectiveToken && isBrowser) {
        try {
          effectiveToken =
            sessionStorage.getItem('zelsis_github_token') ||
            undefined;
          try {
            localStorage.removeItem('zelsis_github_token');
            localStorage.removeItem('github_token');
          } catch (storageErr) {
            console.debug('[GitHub API] LocalStorage removal notice:', storageErr);
          }
        } catch (sessionErr) {
          console.debug('[GitHub API] SessionStorage access notice:', sessionErr);
        }
      }
      if (effectiveToken) {
        proxyHeaders['x-github-token'] = effectiveToken.trim();
      }
      // The session lets the proxy check the plan before it serves a private repository.
      try {
        const { getActiveUserAuth } = await import('@/lib/supabase-client');
        const { accessToken } = await getActiveUserAuth();
        if (accessToken) proxyHeaders['Authorization'] = `Bearer ${accessToken}`;
      } catch (sessionErr) {
        console.debug('[GitHub API] Session lookup notice:', sessionErr);
      }
      const proxyRes = await fetch(proxyEndpoint, {
        headers: proxyHeaders,
        signal: createTimeoutSignal(15000, signal)
      });
      if (proxyRes.status === 403) {
        const denied = await proxyRes.json().catch(() => null);
        if (denied?.error === 'PLAN_REQUIRED') {
          // Plan gate: do not fall back to fetching the private repo directly from GitHub.
          return {
            name: denied.name || parsed.repo,
            fullName: denied.fullName || `${parsed.owner}/${parsed.repo}`,
            description: denied.message,
            defaultBranch: 'main',
            stars: 0,
            language: 'None',
            files: [],
            isPrivate: true,
            requiresAuth: true,
            error: 'PRIVATE_OR_UNAUTHENTICATED'
          };
        }
      }
      if (proxyRes.ok) {
        const data = await proxyRes.json();
        if (data) {
          // Handle rate limit response from proxy
          if (data.error === 'RATE_LIMIT_EXCEEDED' || data.description?.includes('rate limit') || data.description?.includes('60 req/hr')) {
            return {
              name: data.name || parsed.repo,
              fullName: data.fullName || `${parsed.owner}/${parsed.repo}`,
              description: GITHUB_RATE_LIMIT_MESSAGE,
              defaultBranch: data.defaultBranch || 'main',
              stars: data.stars || 0,
              language: data.language || 'TypeScript',
              files: [],
              error: 'RATE_LIMIT_EXCEEDED'
            };
          }

          // Handle repo not found from proxy (HTTP 404)
          if (data.error === 'REPO_NOT_FOUND') {
            return {
              name: data.name || parsed.repo,
              fullName: data.fullName || `${parsed.owner}/${parsed.repo}`,
              description: data.message || `GitHub repository "${parsed.owner}/${parsed.repo}" was not found (HTTP 404).`,
              defaultBranch: data.defaultBranch || 'main',
              stars: 0,
              language: 'None',
              files: [],
              error: 'REPO_NOT_FOUND'
            };
          }

          // Handle Cloudflare bot protection from proxy
          if (data.error === 'CLOUDFLARE_BOT_PROTECTION') {
            return {
              name: data.name || parsed.repo,
              fullName: data.fullName || `${parsed.owner}/${parsed.repo}`,
              description: 'Blocked by Cloudflare Bot Protection',
              defaultBranch: data.defaultBranch || 'main',
              stars: 0,
              language: 'None',
              files: [],
              error: 'CLOUDFLARE_BOT_PROTECTION'
            };
          }

          // Handle private or unauthenticated from proxy
          if (data.error === 'PRIVATE_OR_UNAUTHENTICATED' || data.isPrivate) {
            return {
              name: data.name || parsed.repo,
              fullName: data.fullName || `${parsed.owner}/${parsed.repo}`,
              description: data.description || 'Private or Unauthenticated GitHub Repository. Provide a GitHub PAT token in Settings to access private repos.',
              defaultBranch: data.defaultBranch || 'main',
              stars: data.stars || 0,
              language: data.language || 'TypeScript',
              files: [],
              isPrivate: true,
              requiresAuth: true,
              error: 'PRIVATE_OR_UNAUTHENTICATED'
            };
          }

          // Handle empty repository gracefully (Zero Fake Passes!)
          if (data.isEmpty || data.error === 'EMPTY_REPOSITORY' || (Array.isArray(data.files) && data.files.length === 0 && !data.error)) {
            return {
              name: data.name || parsed.repo,
              fullName: data.fullName || `${parsed.owner}/${parsed.repo}`,
              description: data.description || 'Empty GitHub repository (no commits or files yet)',
              defaultBranch: data.defaultBranch || 'main',
              stars: data.stars || 0,
              language: data.language || 'None',
              files: [],
              isEmpty: true,
              error: 'EMPTY_REPOSITORY'
            };
          }

          if (Array.isArray(data.files) && data.files.length > 0) {
            // Apply 200KB per-file cap to prevent ReDoS or memory exhaustion across rules
            const files: CodeFile[] = data.files.map((f: { path: string; content?: string }) => {
              let content = typeof f.content === 'string' ? f.content : '';
              if (content.length > 200000 && !isDependencyFile(f.path)) {
                content = content.slice(0, 200000);
              }
              return { path: f.path, content };
            });

            onProgress?.({
              phase: 'fetching',
              loaded: files.length,
              total: files.length,
              currentFile: `Retrieved ${files.length} source code files`
            });

            return {
              name: data.name || parsed.repo,
              fullName: data.fullName || `${parsed.owner}/${parsed.repo}`,
              description: data.description || 'GitHub Application Repository',
              defaultBranch: data.defaultBranch || 'main',
              stars: data.stars || 0,
              language: data.language || 'TypeScript',
              files
            };
          }
        }
      }
    } catch (err: any) {
      if (signal?.aborted || err?.name === 'AbortError') return null;
    }
  }

  // 2. Direct GitHub API Fetch (Server routes or client fallback)
  const { owner, repo } = parsed;
  const serverToken = typeof process !== 'undefined' ? (process.env.GITHUB_TOKEN || process.env.GITHUB_PAT) : undefined;
  const effectiveToken = token || serverToken;

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'Zelsis-AI-Release-Gate'
  };

  if (effectiveToken) {
    headers['Authorization'] = `Bearer ${effectiveToken.trim()}`;
  }

  try {
    onProgress?.({
      phase: 'connecting',
      loaded: 0,
      total: 0,
      currentFile: `Connecting directly to GitHub API: ${owner}/${repo}...`
    });

    const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers,
      signal: createTimeoutSignal(8000, signal)
    });

    if (!repoRes.ok) {
      if (repoRes.status === 404) {
        return {
          name: repo,
          fullName: `${owner}/${repo}`,
          description: 'GitHub repository not found. Verify the owner and repository name for typos.',
          defaultBranch: 'main',
          stars: 0,
          language: 'None',
          files: [],
          error: 'REPO_NOT_FOUND'
        };
      }

      let bodyText = '';
      try {
        bodyText = await repoRes.text();
      } catch {
        bodyText = '';
      }

      const isRateLimit = isGitHubRateLimited(repoRes.status, repoRes.headers, bodyText, Boolean(effectiveToken));

      if (isRateLimit) {
        return {
          name: repo,
          fullName: `${owner}/${repo}`,
          description: GITHUB_RATE_LIMIT_MESSAGE,
          defaultBranch: 'main',
          stars: 0,
          language: 'TypeScript',
          files: [],
          error: 'RATE_LIMIT_EXCEEDED'
        };
      }

      return {
        name: repo,
        fullName: `${owner}/${repo}`,
        description: 'Private or Unauthenticated GitHub Repository. Provide a GitHub PAT token in Settings to access private repos.',
        defaultBranch: 'main',
        stars: 0,
        language: 'TypeScript',
        files: [],
        isPrivate: true,
        requiresAuth: true,
        error: 'PRIVATE_OR_UNAUTHENTICATED'
      };
    }

    const repoData = (await repoRes.json()) as Record<string, unknown>;
    const detectedBranch = typeof repoData?.default_branch === 'string' && repoData.default_branch ? repoData.default_branch : 'main';

    // Handle empty repository immediately if size is 0
    if (typeof repoData?.size === 'number' && repoData.size === 0) {
      return {
        name: (repoData?.name as string) || repo,
        fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
        description: 'Empty repository. No scannable source code files found.',
        defaultBranch: detectedBranch,
        stars: (repoData?.stargazers_count as number) || 0,
        language: (repoData?.language as string) || 'None',
        files: [],
        isEmpty: true,
        error: 'EMPTY_REPOSITORY'
      };
    }

    if (signal?.aborted) return null;

    // Default branch detection with fallback checks for main, master, and develop
    const candidateBranches = Array.from(
      new Set([detectedBranch, 'main', 'master', 'develop'].filter(Boolean))
    );
    let treeRes: Response | null = null;
    let resolvedBranch = detectedBranch;

    for (const branch of candidateBranches) {
      if (signal?.aborted) return null;
      try {
        onProgress?.({
          phase: 'tree',
          loaded: 0,
          total: 0,
          currentFile: `Resolving Git tree for branch "${branch}"...`
        });
        const res = await fetch(
          `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
          { headers, signal: createTimeoutSignal(10000, signal) }
        );
        if (res.ok) {
          treeRes = res;
          resolvedBranch = branch;
          break;
        } else if (res.status === 409) {
          // GitHub returns 409 Conflict when repository is empty
          treeRes = res;
          resolvedBranch = branch;
          break;
        } else if (res.status === 403 || res.status === 429 || res.headers.get('x-ratelimit-remaining') === '0') {
          treeRes = res;
          break;
        }
      } catch (err: unknown) {
        const errObj = err as { name?: string; message?: string };
        if (errObj?.name === 'AbortError' || signal?.aborted) return null;
      }
    }

    if (signal?.aborted) return null;

    // Handle tree fetch failure or empty repo or rate limit
    if (!treeRes || !treeRes.ok) {
      if (treeRes && treeRes.status === 409) {
        return {
          name: (repoData?.name as string) || repo,
          fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
          description: (repoData?.description as string) || 'Empty GitHub repository (no commits or files yet)',
          defaultBranch: resolvedBranch,
          stars: (repoData?.stargazers_count as number) || 0,
          language: (repoData?.language as string) || 'None',
          files: [],
          isEmpty: true,
          error: 'EMPTY_REPOSITORY'
        };
      }

      let treeBody = '';
      try {
        if (treeRes) treeBody = await treeRes.text();
      } catch {
        treeBody = '';
      }

      const isTreeRateLimit =
        treeRes && (
          treeRes.status === 429 ||
          treeRes.headers.get('x-ratelimit-remaining') === '0' ||
          treeRes.headers.has('retry-after') ||
          (treeRes.status === 403 && (/rate limit|secondary rate|abuse detection/i.test(treeBody) || !effectiveToken))
        );

      if (isTreeRateLimit) {
        return {
          name: (repoData?.name as string) || repo,
          fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
          description: GITHUB_RATE_LIMIT_MESSAGE,
          defaultBranch: resolvedBranch,
          stars: (repoData?.stargazers_count as number) || 0,
          language: (repoData?.language as string) || 'TypeScript',
          files: [],
          error: 'RATE_LIMIT_EXCEEDED'
        };
      }

      return {
        name: (repoData?.name as string) || repo,
        fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
        description: (repoData?.description as string) || 'GitHub repository files could not be retrieved',
        defaultBranch: resolvedBranch,
        stars: (repoData?.stargazers_count as number) || 0,
        language: (repoData?.language as string) || 'None',
        files: [],
        isEmpty: true,
        error: 'EMPTY_REPOSITORY'
      };
    }

    let treeData: { tree?: Array<{ type: string; path: string; size?: number }> } = {};
    try {
      treeData = (await treeRes.json()) as { tree?: Array<{ type: string; path: string; size?: number }> };
    } catch {
      treeData = { tree: [] };
    }

    const treeFiles = (treeData.tree || [])
      .filter(
        (item) =>
          item.type === 'blob' &&
          typeof item.path === 'string' &&
          (!item.size || item.size <= (isDependencyFile(item.path) ? 8000000 : 2000000)) &&
          (isDependencyFile(item.path) || /(\.(ts|tsx|js|jsx|json|css|sql|html|py|yml|yaml|toml|sh|ps1|c|cpp|cc|cxx|h|hpp|java|kt|kts|go|rs|php|cs|rb|swift|xml|plist|gradle|md|mdx|zelsisignore|shipguardignore)$)|(\.env(\.[a-zA-Z0-9_\-]+)?$)|((?:^|\/)(?:dockerfile|makefile|podfile)$)/i.test(item.path)) &&
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

    if (signal?.aborted) return null;

    if (treeFiles.length === 0) {
      return {
        name: (repoData?.name as string) || repo,
        fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
        description: (repoData?.description as string) || 'Empty GitHub repository (0 scannable files)',
        defaultBranch: resolvedBranch,
        stars: (repoData?.stargazers_count as number) || 0,
        language: (repoData?.language as string) || 'None',
        files: [],
        isEmpty: true,
        error: 'EMPTY_REPOSITORY'
      };
    }

    const filesToFetch = prioritizeFilesForScan(treeFiles);

    onProgress?.({
      phase: 'tree',
      loaded: 0,
      total: filesToFetch.length,
      currentFile: `Discovered ${treeFiles.length} files (queued ${filesToFetch.length} source files for audit)`
    });

    const CHUNK_SIZE = 30;
    const fetchedFiles: (CodeFile | null)[] = [];

    for (let i = 0; i < filesToFetch.length; i += CHUNK_SIZE) {
      if (signal?.aborted) return null;
      const chunk = filesToFetch.slice(i, i + CHUNK_SIZE);
      const chunkResults = await Promise.all(
        chunk.map(async (file) => {
          try {
            const encodedPath = file.path.split('/').map(encodeURIComponent).join('/');
            const rawRes = await fetch(
              `https://raw.githubusercontent.com/${owner}/${repo}/${resolvedBranch}/${encodedPath}`,
              {
                headers: effectiveToken ? { Authorization: `token ${effectiveToken.trim()}` } : {},
                signal: createTimeoutSignal(8000, signal)
              }
            );
            if (rawRes.ok) {
              let content = await rawRes.text();
              // File size guard: cap at 200KB per-file limit to avoid ReDoS or memory exhaustion across rules
              if (content.length > 200000 && !isDependencyFile(file.path)) {
                content = content.slice(0, 200000);
              }
              return { path: file.path, content };
            }
          } catch (err: unknown) {
            const errObj = err as { name?: string; message?: string };
            if (errObj?.name !== 'AbortError' && !signal?.aborted) {
              console.warn(`[GitHub API Chunking] Failed to fetch raw file ${file.path}:`, errObj?.message || err);
            }
          }
          return null;
        })
      );
      fetchedFiles.push(...chunkResults);
      const currentLoaded = Math.min(filesToFetch.length, i + chunk.length);
      const activePath = chunk[chunk.length - 1]?.path || 'source file';
      onProgress?.({
        phase: 'fetching',
        loaded: currentLoaded,
        total: filesToFetch.length,
        currentFile: activePath
      });
    }

    const codeFiles: CodeFile[] = fetchedFiles.filter((f): f is CodeFile => f !== null);

    if (codeFiles.length > 0) {
      return {
        name: (repoData?.name as string) || repo,
        fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
        description: (repoData?.description as string) || 'GitHub Application Repository',
        defaultBranch: resolvedBranch,
        stars: (repoData?.stargazers_count as number) || 0,
        language: (repoData?.language as string) || 'TypeScript',
        files: codeFiles,
        isPrivate: repoData?.private === true
      };
    }

    return {
      name: (repoData?.name as string) || repo,
      fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
      description: 'Empty repository. No scannable source code files found.',
      defaultBranch: resolvedBranch,
      stars: (repoData?.stargazers_count as number) || 0,
      language: (repoData?.language as string) || 'TypeScript',
      files: [],
      isEmpty: true,
      error: 'EMPTY_REPOSITORY'
    };
  } catch (err: unknown) {
    const errObj = err as { name?: string; message?: string };
    if (errObj?.name !== 'AbortError' && !signal?.aborted) {
      console.warn('Live GitHub API Fetch notice:', errObj?.message || err);
    }
    return null;
  }
}

