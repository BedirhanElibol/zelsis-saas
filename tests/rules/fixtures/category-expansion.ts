import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [30502], name: 'CAT-02 column renamed on an existing table vs a rename on a table created in the same file',
    detects: f('supabase/migrations/20260102_rename.sql', 'ALTER TABLE public.orders RENAME COLUMN total TO amount_cents;\n'),
    ignores: f('supabase/migrations/20260102_rename.sql', 'CREATE TABLE public.drafts (id uuid primary key, total int);\nALTER TABLE public.drafts RENAME COLUMN total TO amount_cents;\n'),
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
    ruleIds: [30508], name: 'CAT-08 column type changed in place vs a widening to text',
    detects: f('supabase/migrations/20260103_type.sql', 'ALTER TABLE public.orders ALTER COLUMN total TYPE bigint USING total::bigint;\n'),
    ignores: f('supabase/migrations/20260103_type.sql', 'ALTER TABLE public.orders ALTER COLUMN note TYPE text;\n'),
  },
  {
    ruleIds: [30509], name: 'CAT-09 volatile default on a live table vs a constant default',
    detects: f('supabase/migrations/20260104_uuid.sql', 'ALTER TABLE public.orders ADD COLUMN public_id uuid DEFAULT gen_random_uuid();\n'),
    ignores: f('supabase/migrations/20260104_uuid.sql', 'ALTER TABLE public.orders ADD COLUMN status text DEFAULT \'new\';\nALTER TABLE public.orders ADD COLUMN created_at timestamptz DEFAULT now();\n'),
  },
  {
    ruleIds: [30510], name: 'CAT-10 UPDATE of every row vs UPDATE with a WHERE',
    detects: f('supabase/migrations/20260105_backfill.sql', 'UPDATE public.orders SET status = \'legacy\';\n'),
    ignores: f('supabase/migrations/20260105_backfill.sql', 'UPDATE public.orders SET status = \'legacy\' WHERE created_at < \'2025-01-01\';\n'),
  },
  {
    ruleIds: [30511], name: 'CAT-11 youtube.com embed vs youtube-nocookie.com',
    detects: f('src/Video.tsx', 'export const Video = () => <iframe title="demo" src="https://www.youtube.com/embed/abc123" />;\n'),
    ignores: f('src/Video.tsx', 'export const Video = () => <iframe title="demo" src="https://www.youtube-nocookie.com/embed/abc123" />;\n'),
  },
  {
    ruleIds: [30512], name: "CAT-12 sameSite none without secure vs with secure",
    detects: f('src/session.ts', "export const opts = { httpOnly: true, sameSite: 'none', path: '/' };\n"),
    ignores: f('src/session.ts', "export const opts = { httpOnly: true, secure: true, sameSite: 'none', path: '/' };\n"),
  },
  {
    ruleIds: [30513], name: 'CAT-13 two independent awaits vs a second call that needs the first',
    detects: f('app/dashboard/page.tsx', 'export default async function Page() {\n  const user = await getUser();\n  const posts = await listPosts();\n  return <div>{user.name}{posts.length}</div>;\n}\n'),
    ignores: f('app/dashboard/page.tsx', 'export default async function Page() {\n  const user = await getUser();\n  const posts = await listPosts(user.id);\n  const rows = await db.find({\n    where: posts.map((p) => p.id),\n  });\n  return <div>{user.name}{posts.length}{rows.length}</div>;\n}\n'),
  },
  {
    ruleIds: [30514], name: 'CAT-14 charges.create vs paymentIntents.create',
    detects: f('app/api/pay/route.ts', 'export async function POST() {\n  await stripe.charges.create({ amount: 1000, currency: "usd", source: tok });\n  return new Response("ok");\n}\n'),
    ignores: f('app/api/pay/route.ts', 'export async function POST() {\n  await stripe.paymentIntents.create({ amount: 1000, currency: "usd" });\n  return new Response("ok");\n}\n'),
  },
  {
    ruleIds: [30516], name: 'CAT-16 CORS methods wildcard vs a method list',
    detects: f('src/cors.ts', "import cors from 'cors';\nexport const handler = cors({ origin: 'https://app.example.com', methods: '*' });\n"),
    ignores: f('src/cors.ts', "import cors from 'cors';\nexport const handler = cors({ origin: 'https://app.example.com', methods: ['GET', 'POST'] });\n"),
  },
  {
    ruleIds: [30517], name: 'CAT-17 429 without Retry-After vs with it',
    detects: f('src/limit.ts', 'export function limited(res: Res) {\n  return res.status(429).json({ error: "slow down" });\n}\n'),
    ignores: f('src/limit.ts', 'export function limited(res: Res) {\n  res.set("Retry-After", "30");\n  return res.status(429).json({ error: "slow down" });\n}\nexport const page = (r: Res) => r.status(429).send("<p>Try again in an hour</p>");\n'),
  },
  {
    ruleIds: [30518], name: 'CAT-18 Go ListenAndServe with no timeouts vs a Server with read and idle timeouts',
    detects: f('cmd/api/main.go', 'package main\n\nimport "net/http"\n\nfunc main() {\n\thttp.ListenAndServe(":8080", nil)\n}\n'),
    ignores: f('cmd/api/main.go', 'package main\n\nimport (\n\t"net/http"\n\t"time"\n)\n\nfunc main() {\n\tsrv := &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute}\n\tsrv.ListenAndServe()\n}\n'),
  },
  {
    ruleIds: [30519], name: 'CAT-19 defer in a loop vs a per-round closure',
    detects: f('internal/files/read.go', 'package files\n\nimport "os"\n\nfunc ReadAll(paths []string) {\n\tfor _, p := range paths {\n\t\tf, err := os.Open(p)\n\t\tif err != nil {\n\t\t\tcontinue\n\t\t}\n\t\tdefer f.Close()\n\t}\n}\n'),
    ignores: f('internal/files/read.go', 'package files\n\nimport "os"\n\nfunc ReadAll(paths []string) {\n\tfor _, p := range paths {\n\t\tfunc() {\n\t\t\tf, err := os.Open(p)\n\t\t\tif err != nil {\n\t\t\t\treturn\n\t\t\t}\n\t\t\tdefer f.Close()\n\t\t}()\n\t}\n}\n'),
  },
  {
    ruleIds: [30521], name: 'CAT-21 java.util.Random for a token vs SecureRandom',
    detects: f('src/main/java/app/Tokens.java', 'import java.util.Random;\npublic class Tokens {\n  String resetToken() {\n    return Long.toHexString(new Random().nextLong());\n  }\n}\n'),
    ignores: f('src/main/java/app/Tokens.java', 'import java.security.SecureRandom;\npublic class Tokens {\n  String resetToken() {\n    byte[] b = new byte[32];\n    new SecureRandom().nextBytes(b);\n    return java.util.HexFormat.of().formatHex(b);\n  }\n}\n'),
  },
  {
    ruleIds: [30522], name: 'CAT-22 allowBackup true vs false',
    detects: f('app/src/main/AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n  <application android:allowBackup="true" android:label="App" />\n</manifest>\n'),
    ignores: f('app/src/main/AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n  <application android:allowBackup="false" android:label="App" />\n</manifest>\n'),
  },
  {
    ruleIds: [30523], name: 'CAT-23 empty catch vs a catch that logs',
    detects: f('src/main/java/app/Sync.java', 'public class Sync {\n  void run() {\n    try {\n      push();\n    } catch (Exception e) {\n    }\n  }\n}\n'),
    ignores: f('src/main/java/app/Sync.java', 'public class Sync {\n  void run() {\n    try {\n      push();\n    } catch (Exception e) {\n      log.warn("sync failed", e);\n    }\n  }\n}\n'),
  },
];
