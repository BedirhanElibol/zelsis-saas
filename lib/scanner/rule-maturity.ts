import maturity from '@/data/rule-maturity.generated.json';

/**
 * Rules shown to fire HIGH/CRITICAL on clean, maintained repositories (docs/benchmark) and not
 * reviewed as true positives. Their findings are still reported, but do not decide the release gate.
 * Regenerate with `npx tsx scripts/benchmark/run.ts`.
 */
const EXPERIMENTAL = new Set<number>((maturity.experimental as { ruleId: number }[]).map((r) => r.ruleId));

export const isExperimentalRule = (ruleId: number): boolean => EXPERIMENTAL.has(ruleId);
