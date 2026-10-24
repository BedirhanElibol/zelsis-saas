import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [8802],
    name: 'Rule 8802 PyYAML load without SafeLoader vs ruamel.yaml safe parser',
    detects: f('app/config.py', `import yaml

def load_data(raw):
    return yaml.load(raw)
`),
    ignores: f('app/parser.py', `from ruamel.yaml import YAML

yaml = YAML(typ="safe", pure=True)

def parse_doc(text):
    return yaml.load(text)
`),
  },
  {
    ruleIds: [12101],
    name: 'Rule 12101 Plaintext credentials in logs vs masked keys, boolean checks, and CLI/key utilities',
    detects: f('app/api/auth.ts', `export function handleLogin(req: any) {
  console.log("User submitted password:", req.body.password);
}
`),
    ignores: [
      {
        path: 'app/services/voice.ts',
        content: `export function connectVoice(humeApiKey: string) {
  console.log(\`Connecting to Hume with key "\${humeApiKey?.slice(0, 3)}..."\`);
}
`,
      },
      {
        path: 'app/controllers/auth.ts',
        content: `export function verify(passwordMatch: boolean) {
  console.log("test", passwordMatch);
}
`,
      },
      {
        path: 'server/commands/reset-admin-password.command.ts',
        content: `export function runCommand(tempPassword: string) {
  console.log("Temporary admin password: " + tempPassword);
}
`,
      },
      {
        path: 'docker/utils/add-new-auth-keys.sh',
        content: `#!/bin/bash
node -e 'console.log("SUPABASE_SECRET_KEY=" + process.env.SECRET)'
`,
      },
    ],
  },
];
