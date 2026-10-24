import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [12101],
    name: 'AUDIT-01 Plaintext Credentials Leaked in Logs vs boolean presence checks and registration scripts',
    detects: f('src/auth.ts', `export function login(user: any) {
  console.log("User secret token leaked:", user.password);
}
`),
    ignores: [
      ...f('frontend/src/components/system/SystemConfig.tsx', `export function SystemConfig() {
  console.log('LLM Config status:', {
    hasApiKey: !!llmConfig.llmApiKey,
  });
}
`),
      ...f('packages/stripe/stripe.register.ts', `export function registerWebhook(endpoint: any) {
  console.log("Webhook Secret: " + endpoint.secret);
}
`),
    ],
  },
  {
    ruleIds: [4003],
    name: 'Untrusted LLM Output Execution vs benchmark runners and docstrings',
    detects: f('src/ai/agent.ts', `export function runLlmCode(aiResponse: string) {
  eval(aiResponse);
}
`),
    ignores: f('headroom/evals/comprehensive_benchmark.py', `"""Comprehensive LLM Benchmarks using EleutherAI lm-evaluation-harness.
This module runs industry-standard benchmarks.
"""
def run_lm_eval(model: str = "openai-chat-completions"):
    pass
`),
  },
  {
    ruleIds: [29797],
    name: 'Login Checks a Hard-Coded Password vs error codes and documentation examples',
    detects: f('src/auth/login.ts', `export function checkPassword(password: string) {
  if (password === "secret123") {
    return true;
  }
}
`),
    ignores: [
      ...f('src/clerk/errors.ts', `export function checkError(passwordErrorCode: string) {
  if (passwordErrorCode === 'pwned') {
    return 'Password compromised';
  }
}
`),
      ...f('docs/examples/auth.mdx', `export function Example() {
  if (params.password === "123456") {
    return true;
  }
}
`),
    ],
  },
  {
    ruleIds: [8602],
    name: 'NEXT15-02 Client Component Props Exposing Server Secrets vs component tag and names',
    detects: f('components/Card.tsx', `'use client';
export function UserCard({ serviceRoleKey }: { serviceRoleKey: string }) {
  return <div>{serviceRoleKey}</div>;
}
`),
    ignores: f('editor/apps/site/app/(auth)/connect/supabase/page.tsx', `'use client';
export function ConnectServiceRoleKey() {
  return <div>Connect</div>;
}
export default function Page() {
  return <ConnectServiceRoleKey />;
}
`),
  },
  {
    ruleIds: [24106],
    name: 'CORE-06 File Inclusion include/require vs local glob foreach loops',
    detects: f('app/view.php', `<?php
$file = $_GET['template'];
require $file;
`),
    ignores: f('bootstrap/includeHelpers.php', `<?php
$files = glob(__DIR__.'/helpers/*.php');
foreach ($files as $file) {
    require $file;
}
`),
  },
];
