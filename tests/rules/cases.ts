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
    ruleIds: [3002, 7004, 7005, 8314],
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
  }
];

export const KNOWN_GAPS: KnownGap[] = [];
