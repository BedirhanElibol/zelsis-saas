/**
 * Rules on the Python architecture graph (lib/scanner/iag/python.ts). FLOW-07 (29507): a signed-in user loads a
 * record by the id in the URL and nothing ties that record to them, so changing the id shows someone else's data.
 * The Python counterpart of the JS/TS IDOR rules (9106, AST 29301).
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner/types';
import { ownerScopedModels, pythonEntrypoints } from '../scanner/iag/python';
import { PUBLIC_READ_MODEL } from '../scanner/ast/flow';
import { SKIP } from './logic-gemini-rules';

export function evaluateIagPythonRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (!/\.py$/i.test(path) || SKIP.test(path) || !cleanContent || cleanContent.length > 400_000) return { findings, logs };

  const raw = (file.content || '').split('\n');
  const ts = new Date().toLocaleTimeString();
  // Only models the file itself scopes to the caller somewhere else can leak by id; shared records cannot
  const owned = ownerScopedModels(cleanContent);
  if (owned.size === 0) return { findings, logs };
  for (const ep of pythonEntrypoints(cleanContent, path)) {
    if (!ep.authed || ep.adminOnly || ep.ownerCheck) continue;
    const sink = ep.sinks.find((s) => owned.has(s.model) && !PUBLIC_READ_MODEL.test(s.model.charAt(0).toLowerCase() + s.model.slice(1)));
    if (!sink) continue;
    const lineNum = sink.line + 1;
    findings.push({
      id: `flow29507-${Date.now()}-${findingCounter.count++}`,
      ruleId: 29507,
      type: 'SECURITY',
      title: `FLOW-07: ${sink.model} Loaded by the Id in the URL Without an Ownership Check (Python)`,
      severity: 'HIGH',
      category: 'Broken Access Control',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[sink.line] || lines[sink.line] || '').trim(),
      reproductionSteps: [
        `Followed ${ep.name}() in ${file.path}:${ep.line + 1}: it requires a signed-in user, then loads ${sink.model} by ${sink.idParam} from the URL.`,
        `Other queries in this file filter ${sink.model} by the signed-in user, but this one does not compare the record's owner with the caller, so a signed-in user who changes ${sink.idParam} gets another user's ${sink.model}.`,
      ],
      remediationPrompt: sink.orm === 'django'
        ? `Scope the lookup to the caller: get_object_or_404(${sink.model}, pk=${sink.idParam}, owner=request.user), or filter the queryset by request.user. (${file.path}:${lineNum})`
        : `Scope the lookup to the caller: .filter(${sink.model}.id == ${sink.idParam}, ${sink.model}.user_id == current_user.id), and return 404 when nothing matches. (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Engineering',
      falsePositive: false,
    });
    logs.push(`[${ts}] [IAG-PY] HIGH: FLOW-07 ${sink.model} by URL id without ownership check at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
