/**
 * How big a fix usually is, by the kind of finding. A class, not hours: Zelsis has not measured fix times on your
 * code, so the report says what kind of change is needed and leaves the estimate to the team that knows the codebase.
 */
import type { Finding } from '@/data/schema';
import { isSecretRuleId } from './scanner/text';

export type FixSize = 'Small' | 'Medium' | 'Large';

export interface FixSizeEstimate {
  size: FixSize;
  /** What kind of change it is, in a few words. */
  kind: string;
}

const RULES: { test: (f: Pick<Finding, 'ruleId' | 'category' | 'title' | 'type'>) => boolean; estimate: FixSizeEstimate }[] = [
  { test: (f) => isSecretRuleId(f.ruleId) || /secret|credential|api key|private key/i.test(`${f.category} ${f.title}`),
    estimate: { size: 'Small', kind: 'revoke the key, move it to the environment' } },
  { test: (f) => /race|concurren|transaction|idempot|lost update|double/i.test(`${f.category} ${f.title}`),
    estimate: { size: 'Large', kind: 'design change: locking or idempotency' } },
  { test: (f) => /row level|\brls\b|schema|index|migration|foreign key/i.test(`${f.category} ${f.title}`),
    estimate: { size: 'Medium', kind: 'database migration' } },
  { test: (f) => /access control|authori[sz]|authenticat|idor|tenant|ownership|permission|session/i.test(`${f.category} ${f.title}`),
    estimate: { size: 'Medium', kind: 'logic change that needs tests' } },
  { test: (f) => /inject|xss|cross-site|deserial|command|path traversal|ssrf|redirect/i.test(`${f.category} ${f.title}`),
    estimate: { size: 'Small', kind: 'change the call site' } },
  { test: (f) => f.type === 'INFRA_DATABASE' || /docker|container|kubernetes|terraform|workflow|header|tls|cors|config/i.test(`${f.category} ${f.title}`),
    estimate: { size: 'Small', kind: 'configuration change' } },
];

export function fixSize(finding: Pick<Finding, 'ruleId' | 'category' | 'title' | 'type'>): FixSizeEstimate {
  return RULES.find((r) => r.test(finding))?.estimate ?? { size: 'Medium', kind: 'code change' };
}

/** One line for reports, explaining what the classes mean and that they are not measured. */
export const FIX_SIZE_NOTE =
  'Fix size is a class by finding type, not a measured estimate: Small is usually one file or one setting, Medium a change that needs a migration or new tests, Large a design change. Your team knows the codebase and sets the real estimate.';
