import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [3001],
    name: 'INFRA-01 public Postgres table without RLS vs SQLite syntax or constant',
    detects: f(
      'supabase/migrations/20261022_profiles.sql',
      `CREATE TABLE "public"."profiles" (
  id uuid PRIMARY KEY,
  username text NOT NULL
);
`
    ),
    ignores: [
      ...f(
        'src/server/db/migrations/002-job-runs.ts',
        `export const SQLITE_JOB_RUNS = [
  \`CREATE TABLE IF NOT EXISTS job_runs (
     name TEXT PRIMARY KEY,
     started_at TEXT,
     finished_at TEXT,
     status TEXT
   )\`,
];
`
      ),
      ...f(
        'migrations/001_sqlite_init.ts',
        `export const init = \`
  CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
\`;
`
      ),
      ...f(
        'db/schema.sqlite.sql',
        `CREATE TABLE cache_entries (
  key TEXT PRIMARY KEY,
  value TEXT
);
`
      ),
    ],
  },
  {
    ruleIds: [6010],
    name: 'DB-PERF-10 public PostgreSQL table without RLS vs SQLite schema and autoincrement',
    detects: f(
      'supabase/migrations/20261022_accounts.sql',
      `CREATE TABLE public.accounts (
  id uuid PRIMARY KEY,
  balance numeric NOT NULL
);
`
    ),
    ignores: [
      ...f(
        'db/schema.sqlite.sql',
        `CREATE TABLE tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
`
      ),
      ...f(
        'src/db/sqlite_schema.sql',
        `CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  data TEXT
);
`
      ),
    ],
  },
];
