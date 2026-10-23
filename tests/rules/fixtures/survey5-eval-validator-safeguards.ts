import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [32],
    name: 'SEC-32 dynamic code execution vs validator string checks and regexes',
    detects: f(
      'src/server/executor.ts',
      `export function run(req: any) {
  const code = req.body.script;
  return eval(code);
}
`
    ),
    ignores: [
      ...f(
        'src/validators/code-security.ts',
        `export function validateCode(content: string): boolean {
  if (content.includes('eval(') || content.includes('eval ')) {
    throw new Error('Dynamic code execution forbidden');
  }
  return true;
}
`
      ),
      ...f(
        'src/linters/ast-check.ts',
        `export function checkSafety(code: string): boolean {
  const hasEval = /eval\\s*\\(/.test(code);
  const hasFunction = /new\\s+Function\\s*\\(/.test(code);
  return !hasEval && !hasFunction;
}
`
      ),
      ...f(
        'src/rules/forbidden-calls.ts',
        `const DANGEROUS = ['eval', 'Function', 'exec'];
export function checkCalls(method: string, line: string): boolean {
  if (line.indexOf('eval(') !== -1) return false;
  return !DANGEROUS.includes(method);
}
`
      ),
    ],
  },
];
