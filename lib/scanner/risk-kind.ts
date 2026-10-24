/**
 * What kind of damage a finding leads to, in words a founder or team lead reads: money, data, uptime,
 * accounts or the server itself. Derived from the rule first (exact), then from the category text.
 * Only SECURITY / infra findings get a label; UI and style findings have none.
 */
export type RiskKind = 'FINANCIAL' | 'DATA_LEAK' | 'ACCOUNT_TAKEOVER' | 'CODE_EXECUTION' | 'DOWNTIME';

export const RISK_LABEL: Record<RiskKind, string> = {
  FINANCIAL: 'Financial risk',
  DATA_LEAK: 'Data leak',
  ACCOUNT_TAKEOVER: 'Account takeover',
  CODE_EXECUTION: 'Server takeover',
  DOWNTIME: 'Downtime risk',
};

/** Impact sentence for a CRITICAL/HIGH finding whose rule has no sentence of its own in data/rule-impact.ts. */
export const RISK_FALLBACK_IMPACT: Record<RiskKind, string> = {
  FINANCIAL: 'Someone can use this to cost you money or use paid features for free.',
  DATA_LEAK: 'Someone can use this to read or change data they should not reach.',
  ACCOUNT_TAKEOVER: 'Someone can use this to act as another user or keep a stolen login.',
  CODE_EXECUTION: 'Someone can use this to run their own code on your servers or builds.',
  DOWNTIME: 'This can slow down or take down the app under load or a crafted request.',
};

const BY_RULE: Record<number, RiskKind> = {
  23004: 'FINANCIAL', 23006: 'FINANCIAL', 5015: 'FINANCIAL', 23007: 'DATA_LEAK',
  23001: 'DATA_LEAK', 3: 'DATA_LEAK', 28005: 'DATA_LEAK', 29301: 'DATA_LEAK', 29309: 'DATA_LEAK', 29302: 'DATA_LEAK',
  23002: 'ACCOUNT_TAKEOVER', 23005: 'ACCOUNT_TAKEOVER', 14: 'ACCOUNT_TAKEOVER', 28808: 'ACCOUNT_TAKEOVER', 29797: 'ACCOUNT_TAKEOVER',
  23008: 'ACCOUNT_TAKEOVER', 29977: 'ACCOUNT_TAKEOVER', 16: 'ACCOUNT_TAKEOVER', 24105: 'ACCOUNT_TAKEOVER',
  27: 'DOWNTIME', 29618: 'DOWNTIME', 7004: 'CODE_EXECUTION',
};

const BY_CATEGORY: [RegExp, RiskKind][] = [
  [/revenue|payment|billing|fintech|checkout|pricing|cost|quota|rate limit|abuse/i, 'FINANCIAL'],
  [/remote code|code execution|command injection|code injection|deserializ|container|kubernetes|ci\/cd|supply chain/i, 'CODE_EXECUTION'],
  [/denial of service|dos\b|performance|availability|resource|race|concurrency|deployment bug|reliability|timeout/i, 'DOWNTIME'],
  [/session|authentication|jwt|token|cross-site scripting|xss|csrf|open redirect|cryptograph/i, 'ACCOUNT_TAKEOVER'],
  [/access control|authorization|idor|bola|exposure|disclosure|secret|credential|leak|pii|privacy|database|sql injection|injection|path traversal|ssrf|storage|mass assignment|ai|llm|cloud|network|transport/i, 'DATA_LEAK'],
];

export function riskKind(f: { ruleId: number; category?: string; type?: string }): RiskKind | undefined {
  if (BY_RULE[f.ruleId]) return BY_RULE[f.ruleId];
  if (f.type && f.type !== 'SECURITY' && f.type !== 'INFRA_DATABASE') return undefined;
  const category = f.category ?? '';
  return BY_CATEGORY.find(([re]) => re.test(category))?.[1];
}
