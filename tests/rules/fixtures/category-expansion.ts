import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [30501], name: 'CAT-01 NOT NULL column added with no default vs with a default or on a table created in the same file',
    detects: f('supabase/migrations/20260101_add_plan.sql', 'ALTER TABLE public.accounts ADD COLUMN plan text NOT NULL;\n'),
    ignores: f('supabase/migrations/20260101_add_plan.sql', 'ALTER TABLE public.accounts ADD COLUMN plan text NOT NULL DEFAULT \'free\';\n\nCREATE TABLE public.invites (id uuid primary key);\nALTER TABLE public.invites ADD COLUMN email text NOT NULL;\n\nDELETE FROM public.sessions;\nALTER TABLE public.sessions ADD COLUMN actor_id uuid NOT NULL;\n\nALTER TABLE public.orgs ADD CONSTRAINT orgs_url_check CHECK (url IS NOT NULL);\n'),
  },
  {
    ruleIds: [30502], name: 'CAT-02 column renamed on an existing table vs a rename on a table created in the same file',
    detects: f('supabase/migrations/20260102_rename.sql', 'ALTER TABLE public.orders RENAME COLUMN total TO amount_cents;\n'),
    ignores: f('supabase/migrations/20260102_rename.sql', 'CREATE TABLE public.drafts (id uuid primary key, total int);\nALTER TABLE public.drafts RENAME COLUMN total TO amount_cents;\n'),
  },
  {
    ruleIds: [30503], name: 'CAT-03 server route that trusts getSession vs one that verifies with getUser',
    detects: f('app/api/me/route.ts', 'import { createServerClient } from "@supabase/ssr";\nexport async function GET() {\n  const supabase = createServerClient(URL, KEY, { cookies });\n  const { data: { session } } = await supabase.auth.getSession();\n  return Response.json({ id: session?.user.id });\n}\n'),
    ignores: f('app/api/me/route.ts', 'import { createServerClient } from "@supabase/ssr";\nexport async function GET() {\n  const supabase = createServerClient(URL, KEY, { cookies });\n  const { data: { user } } = await supabase.auth.getUser();\n  return Response.json({ id: user?.id });\n}\n'),
  },
  {
    ruleIds: [30504], name: 'CAT-04 fetch polled every 250 ms vs every 10 seconds',
    detects: f('src/Status.tsx', 'import { useEffect } from "react";\nexport function Status() {\n  useEffect(() => {\n    const t = setInterval(() => fetch("/api/status"), 250);\n    return () => clearInterval(t);\n  }, []);\n  return null;\n}\n'),
    ignores: f('src/Status.tsx', 'import { useEffect } from "react";\nexport function Status() {\n  useEffect(() => {\n    const t = setInterval(() => fetch("/api/status"), 10000);\n    return () => clearInterval(t);\n  }, []);\n  return null;\n}\n'),
  },
  {
    ruleIds: [30505], name: 'CAT-05 subscription webhook that only grants access vs one that also handles cancellation',
    detects: f('app/api/stripe/webhook/route.ts', 'import Stripe from "stripe";\nexport async function POST(req: Request) {\n  const event = stripe.webhooks.constructEvent(await req.text(), sig, secret);\n  switch (event.type) {\n    case "checkout.session.completed":\n      await db.update({ plan: "pro", subscription: event.data.object.subscription });\n      break;\n  }\n  return new Response("ok");\n}\n'),
    ignores: f('app/api/stripe/webhook/route.ts', 'import Stripe from "stripe";\nexport async function POST(req: Request) {\n  const event = stripe.webhooks.constructEvent(await req.text(), sig, secret);\n  switch (event.type) {\n    case "checkout.session.completed":\n      await db.update({ plan: "pro", subscription: event.data.object.subscription });\n      break;\n    case "customer.subscription.deleted":\n      await db.update({ plan: "free" });\n      break;\n  }\n  return new Response("ok");\n}\n'),
  },
  {
    ruleIds: [30506], name: 'CAT-06 analytics identify with the email vs with the internal user id',
    detects: f('src/analytics.ts', 'import posthog from "posthog-js";\nexport const track = (user: { email: string }) => posthog.identify(user.email);\n'),
    ignores: f('src/analytics.ts', 'import posthog from "posthog-js";\nexport const track = (user: { id: string }) => posthog.identify(user.id);\n'),
  },
  {
    ruleIds: [30507], name: 'CAT-07 aria-hidden on a reachable button vs on one taken out of the tab order',
    detects: f('src/Close.tsx', 'export const Close = () => <button aria-hidden="true" onClick={close}>x</button>;\n'),
    ignores: f('src/Close.tsx', 'export const Close = () => <button aria-hidden="true" tabIndex={-1} onClick={close}>x</button>;\n'),
  },
];
