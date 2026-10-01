import summary from '@/data/rule-summary.generated.json';
import maturity from '@/data/rule-maturity.generated.json';

/**
 * Measured rule counts and per-rule status for the UI. Generated from the engine sources
 * (scripts/rule-audit.ts) and the benchmark (scripts/benchmark/run.ts), never from catalog length.
 */
export const RULE_COUNTS = summary.counts;

const implementedIds = new Set<number>(summary.ids);
const implementedCodes = new Set<string>(summary.codes);
const experimentalIds = new Set<number>((maturity.experimental as { ruleId: number }[]).map((r) => r.ruleId));

export type RuleStatus = 'active' | 'experimental' | 'planned';

/** active = scanned and gate-enforcing; experimental = scanned, advisory only; planned = catalog entry not yet implemented. */
export function getRuleStatus(rule: { id: number | string; code?: string }): RuleStatus {
  const id = Number(rule.id);
  const implemented = implementedIds.has(id) || (rule.code !== undefined && implementedCodes.has(rule.code));
  if (!implemented) return 'planned';
  return experimentalIds.has(id) ? 'experimental' : 'active';
}

export const isImplementedRule = (rule: { id: number | string; code?: string }): boolean => getRuleStatus(rule) !== 'planned';

/** Formats e.g. 1397 as "1,397" for copy. */
export const formatCount = (n: number): string => n.toLocaleString('en-US');
