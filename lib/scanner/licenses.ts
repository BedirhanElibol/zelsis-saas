import type { Finding } from '@/data/schema';
import type { Dependency } from './dependencies';

/** Written out so the rule inventory (scripts/rule-audit.ts) lists both rules. */
const RULES = {
  network: { ruleId: 26003, title: 'LIC-01: Production Dependency Under a Network Copyleft License (AGPL / SSPL)', severity: 'MEDIUM' },
  copyleft: { ruleId: 26004, title: 'LIC-02: Production Dependency Under a Strong Copyleft License (GPL)', severity: 'LOW' },
} as const;
export const LICENSE_NETWORK_RULE_ID = RULES.network.ruleId;
export const LICENSE_COPYLEFT_RULE_ID = RULES.copyleft.ruleId;

/** Licenses whose terms reach software offered over a network (a SaaS), not only software you hand out. */
const NETWORK_COPYLEFT = /^(?:AGPL-[\d.]+(?:-only|-or-later|\+)?|SSPL-1\.0)$/i;
/** Strong copyleft that matters when you distribute the app (mobile, desktop, an npm package). LGPL is left out. */
const COPYLEFT = /^GPL-[\d.]+(?:-only|-or-later|\+)?$/i;

export type LicenseClass = 'network-copyleft' | 'copyleft' | null;

/**
 * The strictest class a dependency forces on you. In an "A OR B" expression you may pick either, so the
 * expression is only a problem when every alternative is; "A AND B" means all terms apply.
 */
export function licenseClass(expression: string | undefined): LicenseClass {
  if (!expression) return null;
  const expr = expression.replace(/[()]/g, ' ').trim();
  const options = expr.split(/\s+OR\s+/i).map((alt) => alt.split(/\s+AND\s+/i).map((id) => id.trim().replace(/\s+WITH\s+.*$/i, '')));
  const rank = (ids: string[]): number => Math.max(...ids.map((id) => (NETWORK_COPYLEFT.test(id) ? 2 : COPYLEFT.test(id) ? 1 : 0)));
  const best = Math.min(...options.map(rank));
  return best === 2 ? 'network-copyleft' : best === 1 ? 'copyleft' : null;
}

/** One finding per production package whose license is copyleft. Dev-only packages never ship, so they are skipped. */
export function buildLicenseFindings(deps: Dependency[], fileLines: Map<string, string[]>): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const dep of deps) {
    if (dep.dev || !dep.license) continue;
    const cls = licenseClass(dep.license);
    if (!cls || seen.has(`${dep.ecosystem}|${dep.name}`)) continue;
    seen.add(`${dep.ecosystem}|${dep.name}`);
    const network = cls === 'network-copyleft';
    const rule = network ? RULES.network : RULES.copyleft;
    findings.push({
      id: `lic-${dep.ecosystem}-${dep.name}-${dep.version}`,
      ruleId: rule.ruleId,
      type: 'LEGAL_COMPLIANCE',
      title: network
        ? `LIC-01: ${dep.name} is licensed ${dep.license}, which can require you to publish your source to users of your service`
        : `LIC-02: ${dep.name} is licensed ${dep.license}, which matters if you distribute the app`,
      severity: rule.severity,
      category: 'License Compliance',
      filePath: dep.file,
      lineRange: `L${dep.line}`,
      snippet: (fileLines.get(dep.file)?.[dep.line - 1] ?? `${dep.name}@${dep.version}`).trim().slice(0, 300),
      reproductionSteps: [
        `${dep.file}:${dep.line} records ${dep.name}@${dep.version} under ${dep.license} as a production dependency.`,
        network
          ? 'AGPL and SSPL extend copyleft to software used over a network: running it in a hosted product can oblige you to offer your own source code.'
          : 'GPL applies when you distribute the software (an app store build, a desktop installer, a published package); a server you only run yourself is usually not affected.',
      ],
      remediationPrompt: `Check whether ${dep.name} ends up in what you ship or host. If it does, replace it with a permissively licensed package, buy a commercial license if one is offered, or get a legal review before release.`,
      status: 'OPEN',
      falsePositive: false
    });
  }
  return findings;
}
