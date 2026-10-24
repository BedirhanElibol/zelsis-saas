import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [33], name: 'SEC-33 child_process exec with request input vs build configs, UPPER_CASE constants, and CLI literal lists',
    detects: [
      ...f('server/routes/convert.ts', `import { exec, execSync } from 'child_process';

export function convertFile(req: any) {
  exec(\`ping \${req.query.host}\`);
  execSync("convert " + req.body.file);
}
`),
    ],
    ignores: [
      ...f('vite.config.ts', `import { execSync } from 'child_process';
const sha = execSync(\`git rev-parse \${process.env.GIT_REF || 'HEAD'}\`).toString().trim();
export default { define: { __SHA__: JSON.stringify(sha) } };
`),
      ...f('src/setup/install.ts', `import { execSync } from 'child_process';
const AGENT_CLI_PKG = '@acme/agent-cli';
export function installAgent() {
  execSync(\`npm install -g \${AGENT_CLI_PKG}\`);
}
`),
      ...f('packages/cli/src/pm.ts', `import { exec } from 'child_process';
export function checkManagers() {
  for (const pkgManager of ['pnpm', 'yarn', 'npm']) {
    exec(\`\${pkgManager} -v\`);
  }
}
`),
    ],
  },
];
