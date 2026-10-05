/**
 * Showcase cards for the landing page. Each `bad` snippet must trigger `ruleId` and each `good`
 * snippet must not: tests/unit/landing-checks.test.ts scans them, so the page never advertises a
 * check the engine does not actually perform.
 */
export interface LandingCheck {
  title: string;
  description: string;
  ruleId: number;
  code: string;
  path: string;
  bad: string;
  good: string;
}

export const LANDING_CHECKS: LandingCheck[] = [
  {
    title: 'Service-role key in a Server Action',
    description: 'A Server Action writes with the Supabase service-role client (which bypasses RLS) without checking who is calling.',
    ruleId: 28001,
    code: 'NEXT-SB-01',
    path: 'app/dashboard/projects/actions.ts',
    bad: `'use server';
import { createClient } from '@supabase/supabase-js';

const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function deleteProject(projectId: string) {
  await admin.from('projects').delete().eq('id', projectId);
}
`,
    good: `'use server';
import { createClient } from '@supabase/supabase-js';
import { createClient as createServerClient } from '@/utils/supabase/server';

const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function deleteProject(projectId: string) {
  const supabase = await createServerClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return;
  await admin.from('projects').delete().eq('id', projectId).eq('owner_id', user.id);
}
`,
  },
  {
    title: 'Cached data served to the wrong user',
    description: 'unstable_cache reads the signed-in user from the surrounding scope but keys the cache without it, so one user\'s data is served to everyone.',
    ruleId: 28751,
    code: 'NEXTAI-01',
    path: 'app/dashboard/orders/page.tsx',
    bad: `import { unstable_cache } from 'next/cache';
import { auth } from '@/auth';
import { db } from '@/lib/db';

export default async function OrdersPage() {
  const userId = (await auth())?.user?.id;
  const getOrders = unstable_cache(
    async () => db.order.findMany({ where: { userId } }),
    ['dashboard-orders']
  );
  return <OrderList orders={await getOrders()} />;
}
`,
    good: `import { unstable_cache } from 'next/cache';
import { auth } from '@/auth';
import { db } from '@/lib/db';

const getOrders = unstable_cache(
  async (userId: string) => db.order.findMany({ where: { userId } }),
  ['dashboard-orders']
);

export default async function OrdersPage() {
  const userId = (await auth())?.user?.id;
  return <OrderList orders={await getOrders(userId!)} />;
}
`,
  },
  {
    title: 'Webhook that pays out twice',
    description: 'Stripe and Polar retry deliveries. A handler that adds credits without recording the event id grants them again on every retry.',
    ruleId: 28702,
    code: 'SAAS3-02',
    path: 'app/api/stripe/webhook/route.ts',
    bad: `export async function POST(req: Request) {
  const evt = stripe.webhooks.constructEvent(await req.text(), sig, secret);
  if (evt.type === 'checkout.session.completed') {
    await prisma.user.update({
      where: { id: evt.data.object.metadata.userId },
      data: { credits: { increment: 100 } },
    });
  }
  return new Response('ok');
}
`,
    good: `export async function POST(req: Request) {
  const evt = stripe.webhooks.constructEvent(await req.text(), sig, secret);
  if (evt.type === 'checkout.session.completed') {
    await prisma.$transaction(async (tx) => {
      if (await tx.processedWebhook.findUnique({ where: { id: evt.id } })) return;
      await tx.processedWebhook.create({ data: { id: evt.id } });
      await tx.user.update({
        where: { id: evt.data.object.metadata.userId },
        data: { credits: { increment: 100 } },
      });
    });
  }
  return new Response('ok');
}
`,
  },
  {
    title: 'RLS that trusts user-editable metadata',
    description: 'user_metadata can be changed by the signed-in user, so a policy that grants admin access from it lets anyone make themselves admin.',
    ruleId: 28004,
    code: 'NEXT-SB-04',
    path: 'supabase/migrations/20250101_profiles.sql',
    bad: `create policy "Admins read all profiles" on public.profiles
  for select using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
`,
    good: `create policy "Admins read all profiles" on public.profiles
  for select using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
`,
  },
  {
    title: 'MCP server launched from a request',
    description: 'An endpoint that starts an MCP stdio server with a command taken from the request lets anyone run programs on your server.',
    ruleId: 28304,
    code: 'LLM-V2-04',
    path: 'server/mcp-proxy.ts',
    bad: `app.get('/connect', async (req, res) => {
  const transport = new StdioClientTransport({
    command: req.query.command as string,
    args: (req.query.args as string).split(' '),
  });
  await client.connect(transport);
});
`,
    good: `app.get('/connect', async (req, res) => {
  const server = SERVERS[String(req.query.server)];
  if (!server) return res.status(404).end();
  const transport = new StdioClientTransport({
    command: server.command,
    args: server.args,
  });
  await client.connect(transport);
});
`,
  },
  {
    title: 'Icon button screen readers cannot name',
    description: 'Beyond security: an icon-only button with no accessible name is announced as just "button" (WCAG 4.1.2).',
    ruleId: 28602,
    code: 'A11Y-02',
    path: 'components/settings-dialog.tsx',
    bad: `import { X } from 'lucide-react';

export function DialogHeader({ onClose }: { onClose: () => void }) {
  return (
    <button onClick={onClose} className="rounded p-1.5">
      <X size={18} />
    </button>
  );
}
`,
    good: `import { X } from 'lucide-react';

export function DialogHeader({ onClose }: { onClose: () => void }) {
  return (
    <button onClick={onClose} aria-label="Close settings" className="rounded p-1.5">
      <X size={18} aria-hidden="true" />
    </button>
  );
}
`,
  },
];
