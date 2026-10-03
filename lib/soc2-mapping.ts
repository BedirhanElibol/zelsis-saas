import type { Finding } from '@/data/schema';

/**
 * Indicative mapping of scanner findings to SOC 2 Trust Services Criteria (2017, revised 2022).
 * It helps teams prepare for an audit; it is not an attestation and says so in every report.
 */
export interface Soc2Control {
  id: string;
  name: string;
  /** Lower-case keywords matched against a finding's category, title and rule code. */
  keywords: string[];
}

export const SOC2_CONTROLS: Soc2Control[] = [
  {
    id: 'CC6.1',
    name: 'Logical access security',
    keywords: ['auth', 'rls', 'row level', 'access control', 'authoriz', 'permission', 'idor', 'session', 'jwt', 'privilege', 'role'],
  },
  {
    id: 'CC6.6',
    name: 'Boundary protection',
    keywords: ['cors', 'ssrf', 'csp', 'content-security', 'header', 'rate limit', 'redirect', 'webhook', 'csrf', 'clickjack'],
  },
  {
    id: 'CC6.7',
    name: 'Credential and data-in-transit protection',
    keywords: ['secret', 'api key', 'token', 'credential', 'password', 'hash', 'md5', 'sha1', 'crypto', 'encrypt', 'tls', 'https', 'private key'],
  },
  {
    id: 'CC6.8',
    name: 'Prevention of unauthorized or malicious software',
    keywords: ['dependency', 'dependencies', 'cve', 'osv', 'supply chain', 'eval', 'deserializ', 'code injection', 'command injection', 'pickle', 'package'],
  },
  {
    id: 'CC7.1',
    name: 'Vulnerability detection and secure configuration',
    keywords: ['injection', 'sql', 'xss', 'xxe', 'misconfig', 'debug', 'docker', 'kubernetes', 'container', 'root', 'config'],
  },
  {
    id: 'CC7.2',
    name: 'Security monitoring and logging',
    keywords: ['logging', 'log ', 'monitor', 'audit trail', 'observab', 'telemetry'],
  },
  {
    id: 'CC8.1',
    name: 'Change management',
    keywords: ['ci/cd', ' ci ', 'pipeline', 'migration', 'release', 'deploy', 'workflow'],
  },
  {
    id: 'C1.1',
    name: 'Confidentiality of information',
    keywords: ['pii', 'personal data', 'privacy', 'gdpr', 'kvkk', 'exposure', 'leak', 'sensitive'],
  },
  {
    id: 'A1.2',
    name: 'Availability and recovery',
    keywords: ['backup', 'healthcheck', 'resource limit', 'memory', 'denial of service', 'redos', 'timeout', 'quota'],
  },
];

/** Pillars that describe security posture; UI polish findings are not SOC 2 evidence. */
const SECURITY_PILLARS = new Set(['SECURITY', 'LEGAL_COMPLIANCE', 'INFRA_DATABASE']);

export function mapFindingToControls(finding: Pick<Finding, 'type' | 'category' | 'title'> & { ruleCode?: string }): string[] {
  if (!SECURITY_PILLARS.has(String(finding.type))) return [];
  const haystack = ` ${finding.category ?? ''} ${finding.title ?? ''} ${finding.ruleCode ?? ''} `.toLowerCase();
  const matched = SOC2_CONTROLS.filter((c) => c.keywords.some((k) => haystack.includes(k))).map((c) => c.id);
  // Every security finding is at least a vulnerability-management item
  return matched.length > 0 ? matched : ['CC7.1'];
}

export interface Soc2ControlResult {
  control: Soc2Control;
  findings: Finding[];
}

/** Open findings grouped per control; a control with no findings had no exceptions in this scan. */
export function buildSoc2Mapping(findings: Finding[]): Soc2ControlResult[] {
  const open = findings.filter((f) => f?.status === 'OPEN');
  return SOC2_CONTROLS.map((control) => ({
    control,
    findings: open.filter((f) => mapFindingToControls(f).includes(control.id)),
  }));
}
