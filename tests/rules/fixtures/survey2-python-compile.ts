import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [8811], name: 'PY-SEC-11 eval/exec/compile(exec) vs re.compile or compile without exec/eval mode',
    detects: [
      ...f('app/api/calc.py', `from flask import request

def evaluate_expr():
    return eval(request.args["expr"])
`),
      ...f('app/instrumentation/hook.py', `def load_instrumented(source, namespace):
    code = compile(source, '<string>', 'exec', dont_inherit=True)
    exec(code, namespace)  # noqa: S102
`),
    ],
    ignores: [
      ...f('app/text/patterns.py', `from re import compile

NAME = compile(r"[^\\u4e00-\\u9fffA-Za-z0-9_]+")
`),
      ...f('app/text/builder.py', `def build_pattern(raw_pattern: str):
    return compile(raw_pattern)
`),
    ],
  },
];
