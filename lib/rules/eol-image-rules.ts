/**
 * Container base images past their end of life (EOL-01, Rule ID 31101).
 * An image whose runtime or distribution no longer gets security fixes keeps every new vulnerability forever.
 * Dates are compared with the scan date, so entries can be listed before they expire.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export interface EolImageRuleResult {
  findings: Finding[];
  logs: string[];
}

/** Last day of security support, from each project's published schedule. */
const EOL: Record<string, Record<string, string>> = {
  node: { 10: '2021-04-30', 12: '2022-04-30', 14: '2023-04-30', 16: '2023-09-11', 18: '2025-04-30', 20: '2026-04-30', 22: '2027-04-30' },
  python: { '3.6': '2021-12-23', '3.7': '2023-06-27', '3.8': '2024-10-07', '3.9': '2025-10-31', '3.10': '2026-10-31', '3.11': '2027-10-31' },
  php: { '7.4': '2022-11-28', '8.0': '2023-11-26', '8.1': '2025-12-31', '8.2': '2026-12-31' },
  ruby: { '2.7': '2023-03-31', '3.0': '2024-04-23', '3.1': '2025-03-26', '3.2': '2026-03-31' },
  golang: { '1.20': '2024-02-06', '1.21': '2024-08-13', '1.22': '2025-02-11', '1.23': '2025-08-12', '1.24': '2026-02-11', '1.25': '2026-08-12' },
  // Debian security support including LTS
  debian: { 9: '2022-06-30', 10: '2024-06-30', 11: '2026-08-31' },
  ubuntu: { '16.04': '2021-04-30', '18.04': '2023-05-31', '20.04': '2025-05-31', '22.04': '2027-06-01' },
  alpine: { '3.15': '2023-11-01', '3.16': '2024-05-23', '3.17': '2024-11-22', '3.18': '2025-05-09', '3.19': '2025-11-01', '3.20': '2026-04-01', '3.21': '2026-11-01' },
};

const DEBIAN_CODENAME: Record<string, string> = { stretch: '9', buster: '10', bullseye: '11' };
const UBUNTU_CODENAME: Record<string, string> = { xenial: '16.04', bionic: '18.04', focal: '20.04', jammy: '22.04' };

/** Version keys of an image reference, plus the base distribution a language image is built on. */
function versionsOf(image: string, tag: string): { family: string; version: string }[] {
  const name = image.replace(/^(?:docker\.io\/)?(?:library\/)?/, '');
  const out: { family: string; version: string }[] = [];
  const lower = tag.toLowerCase();
  if (name === 'node') { const m = lower.match(/^(\d+)/); if (m) out.push({ family: 'node', version: m[1] }); }
  if (name === 'python' || name === 'php' || name === 'ruby' || name === 'golang') {
    const m = lower.match(/^(\d+\.\d+)/);
    if (m) out.push({ family: name, version: m[1] });
  }
  if (name === 'debian') {
    const m = lower.match(/^(\d+)/) ?? null;
    out.push({ family: 'debian', version: m?.[1] ?? DEBIAN_CODENAME[lower.split('-')[0]] ?? '' });
  }
  if (name === 'ubuntu') out.push({ family: 'ubuntu', version: lower.match(/^(\d+\.\d+)/)?.[1] ?? UBUNTU_CODENAME[lower] ?? '' });
  if (name === 'alpine') { const m = lower.match(/^(\d+\.\d+)/); if (m) out.push({ family: 'alpine', version: m[1] }); }
  // node:18-buster, python:3.12-alpine3.18: the OS layer can be past its end even when the runtime is not.
  const codename = lower.match(/-(stretch|buster|bullseye)\b/)?.[1];
  if (codename) out.push({ family: 'debian', version: DEBIAN_CODENAME[codename] });
  const alpine = lower.match(/-alpine(\d+\.\d+)/)?.[1];
  if (alpine) out.push({ family: 'alpine', version: alpine });
  return out.filter((v) => v.version);
}

const LABEL: Record<string, string> = { node: 'Node.js', python: 'Python', php: 'PHP', ruby: 'Ruby', golang: 'Go', debian: 'Debian', ubuntu: 'Ubuntu', alpine: 'Alpine' };

export function evaluateEolImageRules(file: CodeFile, lines: string[], _cleanContent: string, findingCounter: { count: number }): EolImageRuleResult {
  const now = new Date();
  const findings: Finding[] = [];
  const logs: string[] = [];
  if (!/(?:^|\/)(?:Dockerfile|Containerfile)(?:\.[\w.-]+)?$|\.dockerfile$/i.test(file.path)) return { findings, logs };
  const today = now.toISOString().slice(0, 10);

  lines.forEach((line, i) => {
    const m = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?([\w./-]+):([\w.-]+)/i);
    if (!m || m[1].includes('$')) return;
    for (const { family, version } of versionsOf(m[1], m[2])) {
      const end = EOL[family]?.[version];
      if (!end || today <= end) continue;
      const label = `${LABEL[family]} ${version}`;
      findings.push({
        id: `eol31101-${Date.now()}-${findingCounter.count++}`,
        ruleId: 31101,
        type: 'SECURITY',
        title: `EOL-01: Base Image Uses ${label}, Out of Security Support Since ${end}`,
        severity: 'MEDIUM',
        category: 'Container Security',
        filePath: file.path,
        lineRange: `L${i + 1}`,
        snippet: line.trim(),
        reproductionSteps: [`Scanned ${file.path}:${i + 1}.`, `${label} stopped receiving security fixes on ${end}. Vulnerabilities found after that date stay in every image built from this line.`],
        remediationPrompt: `Move ${file.path}:${i + 1} to a supported ${LABEL[family]} release, rebuild, and run the tests.`,
        status: 'OPEN',
        owner: 'DevOps',
        falsePositive: false,
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [EOL] MEDIUM: ${label} past end of life at ${file.path}:${i + 1}`);
    }
  });
  return { findings, logs };
}
