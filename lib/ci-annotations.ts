/**
 * GitHub Actions workflow commands (::error file=...,line=...::) for findings, so the customer's CI job shows
 * each one on the exact line in the pull request diff. Built server-side and returned by /api/v1/gate-check,
 * so the workflow only prints them and the format can change without customers editing their YAML.
 */
interface AnnotatableFinding {
  title: string;
  severity: string;
  filePath?: string;
  lineRange?: string;
  maturity?: string;
}

/** GitHub renders at most 10 annotations of each level per step. */
export const MAX_ANNOTATIONS_PER_LEVEL = 10;

// https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions (data and property escaping)
const escapeData = (s: string) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escapeProperty = (s: string) => escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');

/** "L12", "L12-L18", "12-18" -> [12, 18]; null when no line is known. */
export function parseLineRange(lineRange?: string): [number, number] | null {
  const nums = (lineRange || '').match(/\d+/g)?.map(Number).filter((n) => n > 0) ?? [];
  if (nums.length === 0) return null;
  return [nums[0], Math.max(nums[0], nums[1] ?? nums[0])];
}

export function buildWorkflowAnnotations(findings: AnnotatableFinding[]): string[] {
  const placed = findings.filter((f) => f.filePath && f.maturity !== 'experimental' && parseLineRange(f.lineRange));
  const line = (level: 'error' | 'warning', f: AnnotatableFinding) => {
    const [start, end] = parseLineRange(f.lineRange)!;
    const props = [`file=${escapeProperty(f.filePath!)}`, `line=${start}`, ...(end > start ? [`endLine=${end}`] : []), `title=${escapeProperty(`Zelsis ${f.severity}`)}`];
    return `::${level} ${props.join(',')}::${escapeData(f.title)}`;
  };
  const rank = (s: string) => (s === 'CRITICAL' ? 0 : 1);
  const blocking = placed.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').sort((a, b) => rank(a.severity) - rank(b.severity));
  const advisory = placed.filter((f) => f.severity === 'MEDIUM');
  return [
    ...blocking.slice(0, MAX_ANNOTATIONS_PER_LEVEL).map((f) => line('error', f)),
    ...advisory.slice(0, MAX_ANNOTATIONS_PER_LEVEL).map((f) => line('warning', f)),
  ];
}
