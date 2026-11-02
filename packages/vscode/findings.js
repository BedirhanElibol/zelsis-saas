// Pure mapping from a Zelsis scan result to editor problems. No vscode import, so it can be unit tested.

/** VS Code DiagnosticSeverity values: Error 0, Warning 1, Information 2. */
const LEVEL = { CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 2 };

/**
 * Groups findings by file. Lines are 0-based for the editor; a finding without a line points at the first line.
 * @param {{ findings?: Array<{ ruleId: number, title: string, severity: string, filePath: string, lineRange?: string, fix?: string, cweId?: string }> }} result
 */
function toProblems(result) {
  /** @type {Map<string, Array<{ line: number, severity: number, message: string, code: string, cweId?: string }>>} */
  const byFile = new Map();
  for (const f of result.findings ?? []) {
    const line = Math.max(0, (Number((f.lineRange || '').match(/\d+/)?.[0]) || 1) - 1);
    const message = f.fix ? `${f.title}\n\n${f.fix}` : f.title;
    const list = byFile.get(f.filePath) ?? [];
    list.push({ line, severity: LEVEL[f.severity] ?? 2, message, code: `ZLS-${f.ruleId}`, ...(f.cweId ? { cweId: f.cweId } : {}) });
    byFile.set(f.filePath, list);
  }
  return byFile;
}

/** One status line: gate and count, as the CLI prints it. */
function summary(result) {
  if (result.nothingChanged) return 'Zelsis: no changed files';
  const n = result.findings?.length ?? 0;
  return `Zelsis ${result.gateStatus}: ${n} finding${n === 1 ? '' : 's'}`;
}

module.exports = { toProblems, summary };
