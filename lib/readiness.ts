import type { Finding } from '@/data/schema';

/** Each scan answers two questions: is the code safe, and is the app ready for the people who will use it. */
const RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
export const severityRank = (f: Finding) => RANK[f.severity] ?? 1;

/** Bugs a user would notice: logic, payments, performance, screens and anything that looks unfinished. */
export const isUserFacing = (f: Finding) =>
  f.type === 'VIBECARE' || f.type === 'VIBEPOLISH' || /perf|payment|checkout|accessib|cliché|cliche/i.test(f.category || '');

export type ReadinessVerdict = 'Fix first' | 'Needs a look' | 'Clear';

export function verdictFor(list: Finding[]): ReadinessVerdict {
  const top = list.reduce((m, f) => Math.max(m, severityRank(f)), 0);
  return top >= 3 ? 'Fix first' : top === 2 ? 'Needs a look' : 'Clear';
}

export function splitReadiness(findings: Finding[]) {
  const users = findings.filter(isUserFacing);
  const security = findings.filter((f) => !isUserFacing(f));
  return { security, users, securityVerdict: verdictFor(security), usersVerdict: verdictFor(users) };
}

/** The same two answers as a PR comment section. */
export function readinessSection(findings: Finding[]): string {
  const { security, users, securityVerdict, usersVerdict } = splitReadiness(findings);
  const icon = (v: ReadinessVerdict) => (v === 'Fix first' ? '❌' : v === 'Needs a look' ? '⚠️' : '✅');
  return (
    `#### Two answers for this change\n` +
    `- ${icon(securityVerdict)} **Security:** ${securityVerdict} (${security.length} new)\n` +
    `- ${icon(usersVerdict)} **Ready for users:** ${usersVerdict} (${users.length} new)\n\n`
  );
}
