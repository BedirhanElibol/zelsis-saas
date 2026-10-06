import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

// False positives found by scanning Zelsis's own repository (2026-10-06).

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [3, 45], name: 'RLS USING (true): flagged for real roles, not for a TO service_role policy',
    detects: f('supabase/migrations/20261004120000_installs.sql', `CREATE POLICY "Anyone manages installs"
    ON public.github_installations
    FOR ALL
    USING (true)
    WITH CHECK (true);
`),
    ignores: f('supabase/migrations/20261004120000_installs.sql', `CREATE POLICY "Service role can manage all github installations"
    ON public.github_installations
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);
`),
  },
  {
    ruleIds: [3], name: 'RLS USING (true) quoted in a docs page is not a policy',
    detects: f('supabase/policies.sql', `CREATE POLICY "read all" ON public.notes FOR SELECT USING (true);
`),
    ignores: f('app/docs/boundaries/page.tsx', `export default function Page() {
  return <p>We flag policies such as <code>FOR SELECT USING (true)</code> on private tables.</p>;
}
`),
  },
  {
    ruleIds: [21], name: 'Secret name inside a log message string is not the secret',
    detects: f('lib/session.ts', `import { logger } from './logger';
export function debugSession(token: string) {
  logger.info('session token', token);
}
`),
    ignores: f('lib/session.ts', `import { logger } from './logger';
export function warnMissing() {
  logger.error('Rescan is not configured (database, INTERNAL_API_SECRET or NEXT_PUBLIC_APP_URL missing)');
}
`),
  },
  {
    ruleIds: [7215], name: 'GET handler that mutates: flagged unless gated on CRON_SECRET (Vercel Cron)',
    detects: f('app/api/cleanup/route.ts', `import { supabase } from '@/lib/db';
export async function GET() {
  await supabase.from('sessions').delete().lt('expires_at', new Date().toISOString());
  return Response.json({ ok: true });
}
`),
    ignores: f('app/api/cron/cleanup/route.ts', `import { supabase } from '@/lib/db';
export async function GET(req: Request) {
  if (req.headers.get('authorization') !== \`Bearer \${process.env.CRON_SECRET}\`) return new Response('Unauthorized', { status: 401 });
  await supabase.from('sessions').delete().lt('expires_at', new Date().toISOString());
  return Response.json({ ok: true });
}
`),
  },
];
