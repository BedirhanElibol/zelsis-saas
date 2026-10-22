import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [32],
    name: 'SEC-32 dynamic code execution with user input vs safe non-dynamic eval signatures',
    detects: [
      ...f('src/api/eval.ts', 'export function handle(req: any) {\n  return eval(req.body.x);\n}\n'),
      ...f('src/api/func.ts', 'export function handle(req: any) {\n  return new Function(req.query.f)();\n}\n'),
      ...f('app/models/report.rb', 'def run_report\n  eval(@subdomain.analytics_report_frequency)\nend\n'),
    ],
    ignores: [
      ...f('src/math/vector.ts', 'export interface Evaluator {\n  eval(t: number): number;\n}\n'),
      ...f('src/constants.ts', 'export const fn = new Function("return 1;");\n'),
    ],
  },
];
