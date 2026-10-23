import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [12101],
    name: 'Rule 12101 AUDIT-01 plaintext credentials leaked in logs vs presence indicator ternaries',
    detects: f('src/server/auth.ts', `export function authenticate(user: any) {
  console.log("User password provided:", user.password);
}
`),
    ignores: f('src/server/telegram/setup-webhook.ts', `export function logSetupStatus(webhookSecret?: string, apiKey?: string) {
  console.log(\`Secret token: \${webhookSecret ? "(set)" : "(not set)"}\`);
  console.log("API Key status:", apiKey ? "present" : "missing");
  console.log(\`Webhook configured: \${webhookSecret ? true : false}\`);
}
`),
  },
];
