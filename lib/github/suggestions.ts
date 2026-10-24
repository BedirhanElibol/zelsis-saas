import { parseLineRange } from '@/lib/ci-annotations';

/**
 * One-line fixes that are safe to offer as a GitHub "suggested change": the corrected line keeps the
 * code's meaning except for the flagged setting. Rules whose fix needs judgement or more than one line
 * are left out on purpose; those keep the written remediation only.
 */
const LINE_FIXES: Readonly<Record<number, (line: string) => string>> = {
  // TLS-04: certificate verification disabled
  12304: (l) => l.replace(/\brejectUnauthorized(\s*:\s*)false\b/, 'rejectUnauthorized$1true'),
  // MOB-SEC-03: cleartext HTTP allowed in the Android manifest
  9303: (l) => l.replace(/(android:usesCleartextTraffic\s*=\s*["'])true(["'])/i, '$1false$2'),
  // PY-SEC-02: yaml.load without SafeLoader (a line that already names a Loader needs a human)
  8802: (l) => (/Loader\s*=/.test(l) ? l : l.replace(/\byaml\.load\(/, 'yaml.safe_load(')),
  // GAP-13: Flask debug server reachable from the network
  28813: (l) => l.replace(/\bdebug\s*=\s*True\b/, 'debug=False'),
  // GO-10: tls.Config with InsecureSkipVerify
  9010: (l) => l.replace(/\bInsecureSkipVerify(\s*:\s*)true\b/, 'InsecureSkipVerify$1false'),
  // PY-SEC-18: requests/httpx call with verify=False
  8818: (l) => l.replace(/\bverify(\s*=\s*)False\b/, 'verify$1True'),
  // CLOUD-V2-17: container allows privilege escalation
  28517: (l) => l.replace(/\ballowPrivilegeEscalation(\s*:\s*)true\b/, 'allowPrivilegeEscalation$1false'),
  // Viewport meta that blocks pinch zoom
  1244: (l) =>
    l
      .replace(/\s*,\s*(?:maximum-scale\s*=\s*1(?:\.0)?|user-scalable\s*=\s*(?:no|0))\b/gi, '')
      .replace(/(content\s*=\s*["'])\s*(?:maximum-scale\s*=\s*1(?:\.0)?|user-scalable\s*=\s*(?:no|0))\s*,\s*/gi, '$1'),
};

/** The corrected line for a finding, or null when the rule has no safe one-line fix or nothing changes. */
export function suggestedLine(ruleId: number, line: string): string | null {
  const fix = LINE_FIXES[ruleId];
  if (!fix) return null;
  const fixed = fix(line);
  return fixed !== line ? fixed : null;
}

/** Line numbers (new side) added by a unified diff patch, as returned for each file by the GitHub pulls API. */
export function addedLines(patch: string | undefined): Set<number> {
  const added = new Set<number>();
  if (!patch) return added;
  let next = 0;
  for (const row of patch.split('\n')) {
    const hunk = row.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) { next = Number(hunk[1]); continue; }
    if (next === 0 || row.startsWith('\\')) continue;
    if (row.startsWith('+')) added.add(next++);
    else if (!row.startsWith('-')) next++;
  }
  return added;
}

export interface SuggestionComment { path: string; line: number; side: 'RIGHT'; body: string }

interface SuggestionFinding { ruleId: number; filePath: string; lineRange?: string; title: string; impact?: string }

/**
 * Review comments with a ```suggestion block for findings on lines this pull request added.
 * GitHub rejects review comments outside the diff, so findings on untouched lines are skipped.
 * Pass file contents captured before the scan: the scanner empties file contents when it finishes.
 */
export function buildSuggestionComments(
  findings: SuggestionFinding[],
  contentByPath: Map<string, string>,
  addedByFile: Map<string, Set<number>>,
  limit = 10,
): SuggestionComment[] {
  const comments: SuggestionComment[] = [];
  const seen = new Set<string>();
  for (const f of findings) {
    if (comments.length >= limit) break;
    const line = parseLineRange(f.lineRange ?? '')?.[0];
    if (!line || !addedByFile.get(f.filePath)?.has(line)) continue;
    const key = `${f.filePath}:${line}`;
    if (seen.has(key)) continue;
    const original = contentByPath.get(f.filePath)?.split(/\r?\n/)[line - 1];
    if (original === undefined) continue;
    const fixed = suggestedLine(f.ruleId, original);
    if (fixed === null) continue;
    seen.add(key);
    comments.push({
      path: f.filePath,
      line,
      side: 'RIGHT',
      body: `**Zelsis: ${f.title}**${f.impact ? `\n${f.impact}` : ''}\n\n\`\`\`suggestion\n${fixed}\n\`\`\``,
    });
  }
  return comments;
}
