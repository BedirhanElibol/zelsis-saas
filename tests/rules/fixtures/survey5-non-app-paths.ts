import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [3001],
    name: 'INFRA-01 public table without RLS ignored in workbench fixture schemas',
    detects: f(
      'supabase/migrations/20261023_tenants.sql',
      `CREATE TABLE "public"."tenants" (
  id uuid PRIMARY KEY,
  name text NOT NULL
);
`
    ),
    ignores: [
      ...f(
        'experiments/workbench/fixture.sql',
        `CREATE TABLE "public"."bench_users" (
  id uuid PRIMARY KEY,
  name text NOT NULL
);
`
      ),
      ...f(
        'db/fixtures/test_tables.sql',
        `CREATE TABLE "public"."fixture_orders" (
  id uuid PRIMARY KEY,
  amount numeric NOT NULL
);
`
      ),
      ...f(
        'migrations/001_bench.sql',
        `-- SOMENTE BANCADA (bench/test only schema)
CREATE TABLE "public"."workbench_records" (
  id uuid PRIMARY KEY,
  payload jsonb
);
`
      ),
      ...f(
        'db/setup_fixture.sql',
        `-- experiments/fixture.sql
CREATE TABLE "public"."exp_samples" (
  id uuid PRIMARY KEY,
  data text
);
`
      ),
    ],
  },
  {
    ruleIds: [18043],
    name: 'FIREBASE-SEC-01 permissive rules ignored in global-setup and test files',
    detects: f(
      'firestore.rules',
      `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
`
    ),
    ignores: [
      ...f(
        'vitest.global-setup.ts',
        `export async function setup() {
  const emulatorRules = \`
    rules_version = '2';
    service cloud.firestore {
      match /{document=**} {
        allow read, write: if true;
      }
    }
  \`;
  await loadFirestoreRules(emulatorRules);
}
`
      ),
      ...f(
        'tests/setup/firebase.ts',
        `export const testRules = "allow read, write: if true;";
`
      ),
    ],
  },
  {
    ruleIds: [1],
    name: 'SEC-01 exposed OpenAI/Stripe key ignored in commented documentation examples',
    detects: f(
      'src/config/ai.ts',
      `export const OPENAI_KEY = "sk-proj-live-production-secret-token-1234567890";
`
    ),
    ignores: [
      ...f(
        'config/initializers/ruby_llm.rb',
        `# RubyLLM.configure do |config|
#   config.openai_api_key = "sk-proj-demo-placeholder-your-key-here"
# end
`
      ),
      ...f(
        'src/services/llm.py',
        `# Configuration example:
# openai.api_key = "sk-proj-your-api-key-here-12345"
# client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
`
      ),
    ],
  },
  {
    ruleIds: [8017],
    name: 'LLM-SEC-17 client LLM key ignored in shell setup scripts and echo instructions',
    detects: f(
      'src/components/AiChat.tsx',
      `const apiKey = process.env.NEXT_PUBLIC_OPENAI_API_KEY;
`
    ),
    ignores: [
      ...f(
        'setup.sh',
        `#!/bin/bash
echo "Please set NEXT_PUBLIC_OPENAI_API_KEY in your .env file"
printf "Example: export NEXT_PUBLIC_OPENAI_API_KEY=your_key\n"
`
      ),
      ...f(
        'scripts/init.sh',
        `#!/usr/bin/env bash
echo "Configuring NEXT_PUBLIC_ANTHROPIC_API_KEY for development..."
`
      ),
    ],
  },
  {
    ruleIds: [5017],
    name: 'SEC-SECRET-17 Google OAuth Client Secret ignored in placeholder and test values',
    detects: f(
      'src/server/google-auth.py',
      `client_id = "1234567890-example.apps.googleusercontent.com"
client_secret = "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210"
`
    ),
    ignores: [
      ...f(
        '.env.testing',
        `GOOGLE_CLIENT_ID="test-client-id"
client_secret="test_secret_gocspx_placeholder_123456"
`
      ),
      ...f(
        'tests/mocks/oauth.ts',
        `export const mockGoogle = {
  client_secret: "mock_client_secret_xyz1234567890"
};
`
      ),
    ],
  },
];
