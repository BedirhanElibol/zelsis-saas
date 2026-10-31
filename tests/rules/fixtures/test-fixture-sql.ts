import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [3], name: 'SEC-03 open write policy on app data vs the same policy in a migration that only serves a test suite',
    detects: f('supabase/migrations/20250422_todos.sql', 'ALTER TABLE public.todos ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY "anyone writes" ON public.todos\n  FOR ALL TO anon\n  USING (true);\n'),
    ignores: f('supabase/migrations/20250422_todos.sql', 'ALTER TABLE public.todos ENABLE ROW LEVEL SECURITY;\n\n-- Allow anonymous writes so the integration tests can run without a login\nCREATE POLICY "anyone writes" ON public.todos\n  FOR ALL TO anon\n  USING (true);\n'),
  },
  {
    ruleIds: [28801], name: 'GAP-01 open update policy on app data vs the same policy in a migration written for tests',
    detects: f('supabase/migrations/20250422_todos.sql', 'ALTER TABLE public.todos ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY "anyone updates" ON public.todos\n  FOR UPDATE TO anon\n  USING (true);\n'),
    ignores: f('supabase/migrations/20250422_todos.sql', 'ALTER TABLE public.todos ENABLE ROW LEVEL SECURITY;\n\n-- Allow anonymous updates for the old integration tests\nCREATE POLICY "anyone updates" ON public.todos\n  FOR UPDATE TO anon\n  USING (true);\n'),
  },
  {
    ruleIds: [28005], name: 'NEXT-SB-05 storage policy for an app bucket vs a policy for the test bucket of a test suite',
    detects: f('supabase/migrations/20250424_storage.sql', "create policy \"anyone deletes\" on storage.objects\n  for delete to authenticated\n  using (bucket_id = 'documents');\n"),
    ignores: f('supabase/migrations/20250424_storage.sql', "-- Allow CRUD on test-bucket so the integration tests can exercise the storage SDK\ncreate policy \"anyone deletes\" on storage.objects\n  for delete to authenticated\n  using (bucket_id = 'test-bucket');\n"),
  },
];
