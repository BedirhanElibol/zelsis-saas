import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [33],
    name: 'SEC-33 a request value in taskkill or git is still caught; a numeric pid and internal git are not',
    detects: [
      ...f('src/api/kill.ts', "import { execSync } from 'child_process';\nexport function kill(req: any) {\n  execSync(`taskkill /pid ${req.query.pid}`);\n}\n"),
    ],
    ignores: [
      ...f('lib/utils/tree-kill.ts', "import { execSync } from 'child_process';\nexport function kill(pid: number) {\n  execSync('taskkill /pid ' + pid + ' /T /F');\n}\n"),
    ],
  },
  {
    ruleIds: [1],
    name: 'SEC-01 a real key in a comment is still caught; a word-only placeholder key is not',
    detects: f('lib/client.rb', "# config.openai_api_key = 'sk-proj-Ab3dEf9hIj2kLm5nOp8qRs1tUv4wXy7z'\nmodule Client; end\n"),
    ignores: f('lib/ruby_llm.rb', "# config.openai_api_key = 'sk-customer-specific-key'\nmodule RubyLLM; end\n"),
  },
];
