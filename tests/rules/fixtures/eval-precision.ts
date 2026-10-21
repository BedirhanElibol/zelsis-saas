import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [32], name: 'SEC-32 global eval and mathjs.eval on input vs Redis / engine / math methods named eval',
    detects: [
      ...f('src/calc.js', 'export function calc(req) {\n  return eval(req.query.expr);\n}\n'),
      ...f('core/appHandler.js', "const mathjs = require('mathjs');\nexports.calc = (req, res) => res.send(String(mathjs.eval(req.body.eqn)));\n"),
    ],
    ignores: [
      ...f('src/Adapter/TokenBucket/RedisCluster.php', '<?php\nclass RedisCluster {\n  public function run($script, $keys, $argv) {\n    return $this->redis->eval($script, [...$keys, ...$argv], \\count($keys));\n  }\n}\n'),
      ...f('apps/authentication/services/rdp_login.py', 'def consume(self, username, encoded):\n    return bool(self.client().eval(self.consume_script, 1, self.key(username), encoded))\n'),
      ...f('src/parametric/step.ts', 'export function midpoint(cv: Curve, t1: number, t2: number) {\n  return cv.eval((t1 + t2) / 2);\n}\n'),
      ...f('lib/react/server_rendering/exec_js_renderer.rb', 'class ExecJsRenderer\n  def render(js_code)\n    @context.eval(js_code)\n  end\nend\n'),
    ],
  },
];
