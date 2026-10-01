import maturity from '@/data/rule-maturity.generated.json';
import evidence from '@/data/rule-evidence.generated.json';

/**
 * Rules shown to fire HIGH/CRITICAL on clean, maintained repositories (docs/benchmark) and not
 * reviewed as true positives. Their findings are still reported, but do not decide the release gate.
 * Regenerate with `npx tsx scripts/benchmark/run.ts`.
 */
const EXPERIMENTAL = new Set<number>((maturity.experimental as { ruleId: number }[]).map((r) => r.ruleId));

/**
 * Rules with evidence: fixture-tested, caught a documented flaw in the benchmark, or a reviewed
 * true positive. Only these can fail the release gate. Regenerate with `npm run audit:rules`.
 */
const EVIDENCE = new Set<number>(evidence.canBlockRelease);

export const isExperimentalRule = (ruleId: number): boolean => EXPERIMENTAL.has(ruleId);

export const canBlockRelease = (ruleId: number): boolean => EVIDENCE.has(ruleId) && !EXPERIMENTAL.has(ruleId);

export const ruleMaturity = (ruleId: number): 'verified' | 'unproven' | 'experimental' =>
  isExperimentalRule(ruleId) ? 'experimental' : canBlockRelease(ruleId) ? 'verified' : 'unproven';
