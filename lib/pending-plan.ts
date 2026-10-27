/**
 * Remembers which paid plan a signed-out visitor pressed, so sign-up (including the GitHub and Google round-trip, or an
 * email confirmation opened in a new tab) can end at checkout instead of dropping the buyer on the dashboard.
 * The record expires after an hour so an old click never redirects someone later.
 */
export type PendingPlanId = 'zelsis-core' | 'vibecare';

const KEY = 'zelsis_pending_plan';
const TTL_MS = 60 * 60 * 1000;

type PlanStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

function browserStorage(): PlanStorage | null {
  try {
    return typeof window === 'undefined' ? null : window.localStorage;
  } catch {
    return null;
  }
}

export function rememberPendingPlan(plan: PendingPlanId, now = Date.now(), storage: PlanStorage | null = browserStorage()): void {
  try {
    storage?.setItem(KEY, JSON.stringify({ plan, at: now }));
  } catch {
    /* storage blocked: the visitor just picks the plan again after signing up */
  }
}

/** Returns the remembered plan once, then forgets it. Null when nothing was remembered or it is older than an hour. */
export function takePendingPlan(now = Date.now(), storage: PlanStorage | null = browserStorage()): PendingPlanId | null {
  if (!storage) return null;
  try {
    const raw = storage.getItem(KEY);
    storage.removeItem(KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { plan?: unknown; at?: unknown };
    if ((parsed.plan !== 'zelsis-core' && parsed.plan !== 'vibecare') || typeof parsed.at !== 'number') return null;
    return now - parsed.at <= TTL_MS ? parsed.plan : null;
  } catch {
    return null;
  }
}
