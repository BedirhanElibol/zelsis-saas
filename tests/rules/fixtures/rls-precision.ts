import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

const SUPABASE_PACKAGE = '{ "dependencies": { "@supabase/supabase-js": "^2.45.0" } }\n';

export const CASES: RuleCase[] = [
  {
    ruleIds: [3001], name: 'INFRA-01 quoted table without RLS vs RLS enabled in a loop, SQLite / D1 files, comments and format() templates',
    detects: [
      ...f('package.json', SUPABASE_PACKAGE),
      ...f('supabase/migrations/20250428022740_tasks.sql', 'CREATE TABLE "task" (\n  "id" TEXT NOT NULL,\n  "title" TEXT NOT NULL\n);\n'),
    ],
    ignores: [
      ...f('package.json', SUPABASE_PACKAGE),
      ...f('supabase/migrations/20260920002000_catalog.sql', `-- account_plans and payment_methods; only the CREATE TABLE does not mention RLS
create table if not exists public.account_plans (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

do $$
declare t text;
begin
  foreach t in array array['account_plans'] loop
    execute format('alter table public.%I enable row level security', t);
  end loop;
end $$;
`),
      ...f('plugins/cloudflare/worker/migrations/0001_init.sql', 'CREATE TABLE IF NOT EXISTS "bundles" ("id" TEXT NOT NULL, "enabled" INTEGER NOT NULL);\n'),
      ...f('src/server/db/migrations/sqlite-initial.ts', 'export const up = `CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, message TEXT)`;\n'),
      ...f('supabase/migrations/20260109_audit.sql', `create or replace function create_audit_table(name text) returns void as $$
begin
  execute format('CREATE TABLE IF NOT EXISTS %I (id bigint primary key)', name);
  execute format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', name);
end $$ language plpgsql;
`),
    ],
  },
];
