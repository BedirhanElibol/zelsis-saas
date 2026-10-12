/**
 * Polite request scheduling for live-site scans. A scan sends 40+ requests to one host (subpages, bundles, lazy chunks,
 * exposure probes); fired at once they look like a burst and make Vercel / Cloudflare challenge the scanner's IP, which
 * then blocks the target for everyone on that IP for a while. The limiter caps requests in flight, spaces their starts,
 * and stops sending once the target answers with a challenge.
 */

export class TargetChallengedError extends Error {
  constructor() {
    super('Target answered with a bot-protection challenge; remaining requests skipped');
    this.name = 'TargetChallengedError';
  }
}

/** True when a response is a Vercel / Cloudflare bot or DDoS challenge rather than the site. */
export function isChallengeResponse(res: Response): boolean {
  return res.headers.get('x-vercel-mitigated') === 'challenge' || res.headers.get('cf-mitigated') === 'challenge';
}

export interface RequestLimiter {
  /** Runs fn when a slot is free; rejects with TargetChallengedError once the target challenged us. */
  run<T>(fn: () => Promise<T>): Promise<T>;
  /** A fetch that goes through the limiter and records challenges. */
  fetch: typeof fetch;
  /** Records a response obtained through run() (for callers that use their own fetch wrapper). */
  note(res: Response, url?: string): Response;
  readonly challenged: boolean;
  /** Which layer challenged (when challenged). */
  readonly provider: 'vercel' | 'cloudflare' | undefined;
  /** Requests actually sent to the target so far. */
  readonly sent: number;
  /** The first request the target answered with a challenge: which URL and how many requests had gone out by then. */
  readonly trigger: { url: string; index: number } | undefined;
}

export function createRequestLimiter({ concurrency = 4, minIntervalMs = 120, fetchImpl = globalThis.fetch } = {}): RequestLimiter {
  let active = 0;
  let lastStart = 0;
  let challenged = false;
  let provider: 'vercel' | 'cloudflare' | undefined;
  let sent = 0;
  let trigger: { url: string; index: number } | undefined;
  const queue: (() => void)[] = [];

  const next = () => {
    if (active >= concurrency || !queue.length) return;
    const wait = Math.max(0, lastStart + minIntervalMs - Date.now());
    if (wait > 0) { setTimeout(next, wait); return; }
    lastStart = Date.now();
    active++;
    queue.shift()!();
  };

  const run = <T>(fn: () => Promise<T>): Promise<T> => new Promise<T>((resolve, reject) => {
    queue.push(() => {
      const task = challenged ? Promise.reject(new TargetChallengedError()) : (sent++, fn());
      task.then(resolve, reject).finally(() => { active--; next(); });
    });
    next();
  });

  const note = (res: Response, url?: string) => {
    if (isChallengeResponse(res)) {
      if (!challenged) trigger = { url: url || res.url || '(unknown)', index: sent };
      challenged = true;
      provider ??= res.headers.get('x-vercel-mitigated') ? 'vercel' : 'cloudflare';
    }
    return res;
  };
  const limitedFetch = ((input: RequestInfo | URL, init?: RequestInit) => run(async () => note(await fetchImpl(input, init), input instanceof Request ? input.url : String(input)))) as typeof fetch;

  return { run, fetch: limitedFetch, note, get challenged() { return challenged; }, get provider() { return provider; }, get sent() { return sent; }, get trigger() { return trigger; } };
}
