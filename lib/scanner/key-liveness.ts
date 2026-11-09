import type { Finding } from '@/data/schema';

/**
 * Does a leaked secret still work? One read-only request per key to its provider, nothing is stored or logged.
 * Live keys raise the finding to CRITICAL (it blocks the release); rejected keys drop it to LOW (rotate anyway).
 * Only providers whose check is a plain authenticated GET are covered. AWS and Supabase need request signing or
 * a project URL, so they stay as they were.
 */

export type KeyProvider = 'stripe' | 'github' | 'openai';
export type KeyState = 'live' | 'dead' | 'unknown';

interface FoundKey { provider: KeyProvider; key: string; line: number }

const PATTERNS: { provider: KeyProvider; re: RegExp }[] = [
  { provider: 'stripe', re: /\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b/g },
  { provider: 'github', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g },
  { provider: 'openai', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b/g },
];

/** Stop after this many provider calls per scan, so a repo full of keys cannot run up compute or hit rate limits. */
export const MAX_KEY_CHECKS = 10;
const TIMEOUT_MS = 4000;

export type FetchLike = (url: string, init: { headers: Record<string, string>; method: 'GET'; signal: AbortSignal }) => Promise<{ status: number }>;

/** Every provider key in a file, with its 1-based line. Keys are used only for the probe. */
export function extractKeys(content: string): FoundKey[] {
  const out: FoundKey[] = [];
  const lines = content.split('\n');
  lines.forEach((text, i) => {
    for (const { provider, re } of PATTERNS) {
      for (const m of text.matchAll(re)) out.push({ provider, key: m[0], line: i + 1 });
    }
  });
  return out;
}

const REQUESTS: Record<KeyProvider, (key: string) => { url: string; headers: Record<string, string> }> = {
  stripe: (key) => ({ url: 'https://api.stripe.com/v1/balance', headers: { Authorization: `Basic ${Buffer.from(`${key}:`).toString('base64')}` } }),
  github: (key) => ({ url: 'https://api.github.com/user', headers: { Authorization: `Bearer ${key}`, 'User-Agent': 'zelsis-key-check' } }),
  openai: (key) => ({ url: 'https://api.openai.com/v1/models', headers: { Authorization: `Bearer ${key}` } }),
};

/** One read-only request. 200 means the key works, 401 or 403 means the provider rejected it, anything else is unknown. */
export async function probeKey(provider: KeyProvider, key: string, fetchImpl: FetchLike = fetch as unknown as FetchLike): Promise<KeyState> {
  const { url, headers } = REQUESTS[provider](key);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetchImpl(url, { headers, method: 'GET', signal: controller.signal });
    if (res.status === 200) return 'live';
    if (res.status === 401 || res.status === 403) return 'dead';
    return 'unknown';
  } catch {
    return 'unknown';
  } finally {
    clearTimeout(timer);
  }
}

const SECRET_RULE = (ruleId: number) => ruleId >= 5001 && ruleId <= 5100;

/**
 * Adjusts secret findings in place: the key on the finding's line is probed once and the finding is raised or
 * lowered. Findings without a recognised key, and every other rule, are left as they are.
 */
export async function applyKeyLiveness(
  findings: Finding[],
  files: { path: string; content: string }[],
  fetchImpl?: FetchLike,
): Promise<{ checks: number }> {
  const byPath = new Map(files.map((f) => [f.path, f.content]));
  const cache = new Map<string, KeyState>();
  let checks = 0;
  for (const f of findings) {
    if (!SECRET_RULE(f.ruleId) || !f.filePath) continue;
    const content = byPath.get(f.filePath);
    const line = Number(/^L(\d+)/.exec(f.lineRange ?? '')?.[1]);
    if (!content || !line) continue;
    const hit = extractKeys(content).find((k) => k.line === line);
    if (!hit) continue;
    const cacheKey = `${hit.provider}:${hit.key}`;
    let state = cache.get(cacheKey);
    if (state === undefined) {
      if (checks >= MAX_KEY_CHECKS) continue;
      checks++;
      state = await probeKey(hit.provider, hit.key, fetchImpl);
      cache.set(cacheKey, state);
    }
    if (state === 'live') {
      f.severity = 'CRITICAL';
      f.title = `LIVE KEY: ${f.title}`;
      f.reproductionSteps = [...(f.reproductionSteps ?? []), `${hit.provider} accepted this key on a read-only check. Revoke it now and check the provider's activity log.`];
    } else if (state === 'dead') {
      f.severity = 'LOW';
      f.reproductionSteps = [...(f.reproductionSteps ?? []), `${hit.provider} rejected this key on a read-only check. It does not work now; rotate it anyway if it was ever committed publicly.`];
    }
  }
  return { checks };
}
