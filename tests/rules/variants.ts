import type { CodeFile } from '../../lib/scanner-engine';

/**
 * Breadth guard: vulnerable variants that each rule must catch on its own (one variant per scan).
 * When narrowing a rule to fix a false positive, every variant here must still fire.
 */
const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const ai = (body: string) => f('app/api/chat/route.ts', `export async function POST(req: Request) {\n  const { prompt } = await req.json();\n${body}\n}\n`);
const wf = (steps: string) => f('.github/workflows/ci.yml', `on: issues\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n${steps}`);
const rd = (line: string, extra = '') => f('app/api/go/route.ts', `import { redirect } from 'next/navigation';\nimport { NextResponse } from 'next/server';\nexport async function GET(req: Request) {\n  const next = new URL(req.url).searchParams.get('next')!;\n${extra}  ${line}\n}\n`);
export const VULNERABLE_VARIANTS: [ruleId: number, name: string, files: CodeFile[]][] = [
  // WAF-02: AI endpoints without rate limit
  [10402, 'openai via raw fetch', ai("  const r = await fetch('https://api.openai.com/v1/chat/completions', { method: 'POST', body: JSON.stringify({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }] }) });\n  return r;")],
  [10402, 'anthropic via raw fetch', ai("  return fetch('https://api.anthropic.com/v1/messages', { method: 'POST', body: JSON.stringify({ prompt }) });")],
  [10402, 'vercel ai sdk streamText', f('app/api/chat/route.ts', "import { streamText } from 'ai';\nimport { openai } from '@ai-sdk/openai';\nexport async function POST(req: Request) {\n  const { messages } = await req.json();\n  return streamText({ model: openai('gpt-4o'), messages }).toTextStreamResponse();\n}\n")],
  [7220, 'login route without rate limit (API-20)', f('app/api/login/route.ts', "export async function POST(req: Request) {\n  const { email, password } = await req.json();\n  return Response.json(await signIn(email, password));\n}\n")],
  // CICD-SEC-03
  [9503, 'multi-line run block', wf("      - run: |\n          echo start\n          echo \"${{ github.event.issue.title }}\"\n")],
  [9503, 'folded run block', wf("      - name: x\n        run: >\n          echo ${{ github.event.issue.title }}\n")],
  [9503, 'github-script injection', wf("      - run: echo hi\n      - uses: actions/github-script@v7\n        with:\n          script: |\n            console.log(\"${{ github.event.issue.title }}\")\n")],
  [9503, 'head_ref in run', wf("      - run: git checkout ${{ github.head_ref }}\n")],
  // SEC-41 open redirect
  [41, 'redirect(next)', rd('redirect(next);')],
  [41, 'redirect(next as string)', rd('redirect(next as string);')],
  [41, "redirect(next || '/')", rd("redirect(next || '/');")],
  [41, 'NextResponse.redirect(new URL(next, req.url))', rd('return NextResponse.redirect(new URL(next, req.url));')],
  [41, 'redirect template literal', rd('redirect(`${next}`);')],
  [41, 'unrelated startsWith guard elsewhere', rd('redirect(next);', "  const isProto = req.url.startsWith('//');\n  void isProto;\n")],
  [41, 'express res.redirect(req.query.url)', f('server/r.ts', "app.get('/go', (req, res) => {\n  res.redirect(req.query.url);\n});\n")],
  // THREAT-02
  [13602, 'exec', f('lib/run.ts', "import { exec } from 'child_process';\nexport const run = (c: string) => exec(c);\n")],
  [13602, "spawn('/bin/sh')", f('lib/run.ts', "import { spawn } from 'child_process';\nexport const run = (c: string) => spawn('/bin/sh', ['-c', c]);\n")],
  [13602, 'require child_process execSync', f('lib/run.js', "const cp = require('child_process');\nmodule.exports = (c) => cp.execSync(c);\n")],
  [13602, 'spawn shell:true', f('lib/run.ts', "import { spawn } from 'node:child_process';\nexport const run = (c: string) => spawn(c, { shell: true });\n")],
  // KERN-SEC-01
  [15701, 'k8s add SYS_ADMIN inline', f('k8s/deploy.yaml', "spec:\n  containers:\n    - name: app\n      securityContext:\n        capabilities:\n          add: [\"SYS_ADMIN\"]\n")],
  [15701, 'k8s add block list', f('k8s/deploy.yaml', "spec:\n  containers:\n    - name: app\n      securityContext:\n        capabilities:\n          add:\n            - NET_ADMIN\n            - SYS_ADMIN\n")],
  [15701, 'k8s privileged', f('k8s/pod.yaml', "spec:\n  containers:\n    - name: app\n      securityContext:\n        privileged: true\n")],
  [15701, 'compose privileged', f('docker-compose.yml', "services:\n  app:\n    image: x\n    privileged: true\n")],
  // CICD-SEC-02: unpinned actions in any form
  [9502, 'action on @main branch', wf("      - uses: some-org/deploy-action@main\n")],
  [9502, 'quoted uses with tag', wf("      - uses: 'actions/checkout@v4'\n")],
  [9502, 'semver tag', wf("      - uses: docker/login-action@v3.1.0\n")],
  // SAAS-01..08
  [23001, "auth.role() = 'authenticated'", f('supabase/migrations/a.sql', "CREATE POLICY \"r\" ON public.docs FOR SELECT USING (auth.role() = 'authenticated');\n")],
  [23001, 'wrapped select auth.uid()', f('supabase/migrations/a.sql', 'CREATE POLICY "r" ON public.docs FOR ALL USING ((select auth.uid()) IS NOT NULL);\n')],
  [23002, 'getSession in server action', f('app/actions/billing.ts', "'use server';\nexport async function cancelPlan() {\n  const { data } = await supabase.auth.getSession();\n  await cancel(data.session!.user.id);\n}\n")],
  [23002, 'getSession in middleware', f('middleware.ts', "export async function middleware(req) {\n  const { data } = await supabase.auth.getSession();\n  if (!data.session) return Response.redirect(new URL('/login', req.url));\n}\n")],
  [23003, 'plpgsql definer with dollar tag', f('supabase/migrations/b.sql', "CREATE FUNCTION public.grant_credits(uid uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $fn$\nBEGIN\n  UPDATE credits SET balance = balance + 10 WHERE user_id = uid;\nEND;\n$fn$;\n")],
  [23004, 'payment intent amount shorthand', f('app/api/pay/route.ts', "export async function POST(req: Request) {\n  const { amount } = await req.json();\n  const pi = await stripe.paymentIntents.create({ amount, currency: 'usd' });\n  return Response.json({ secret: pi.client_secret });\n}\n")],
  [23004, 'unit_amount from body object', f('app/api/pay/route.ts', "export async function POST(req: Request) {\n  const body = await req.json();\n  const s = await stripe.checkout.sessions.create({ line_items: [{ price_data: { currency: 'usd', unit_amount: body.total, product_data: { name: 'Pro' } }, quantity: 1 }] });\n  return Response.json(s);\n}\n")],
  [23004, 'aliased destructuring', f('app/api/checkout/route.ts', "export async function POST(request: Request) {\n  const { price: selected } = await request.json();\n  return Response.json(await stripe.checkout.sessions.create({ line_items: [{ price: selected, quantity: 1 }] }));\n}\n")],
  [23005, 'secret on the left side', f('app/api/hook/route.ts', "export async function POST(req: Request) {\n  if (process.env.WEBHOOK_SECRET !== req.headers.get('x-secret')) return new Response('no', { status: 401 });\n  return new Response('ok');\n}\n")],
  [23006, 'pages router cron', f('pages/api/cron/cleanup.ts', 'export default async function handler(req, res) {\n  await purgeOldData();\n  res.json({ ok: true });\n}\n')],
  [23007, 'AI SDK system option', f('app/api/chat/route.ts', "import { streamText } from 'ai';\nexport async function POST(req: Request) {\n  const { messages, role } = await req.json();\n  return streamText({ model, system: `Act as ${role}.`, messages }).toTextStreamResponse();\n}\n")],
  [23007, 'body field in system content', f('app/api/chat/route.ts', "export async function POST(req: Request) {\n  const body = await req.json();\n  return Response.json(await anthropic.messages.create({ model: 'claude', max_tokens: 200, system: `Company rules: ${body.rules}`, messages: body.messages }));\n}\n")],
  [23008, 'Next 14 pinned', f('package.json', '{ "dependencies": { "next": "14.2.10" } }\n')],
  [23008, 'Next 13 tilde range', f('package.json', '{ "devDependencies": { "next": "~13.4.0" } }\n')],
  // ZERO-AUTH-43
  [8143, 'webhook no verification', f('app/api/webhooks/github/route.ts', "export async function POST(req: Request) {\n  const event = await req.json();\n  await deploy(event);\n  return new Response('ok');\n}\n")],
  [8143, 'webhook defines fake validateEvent', f('app/api/webhooks/github/route.ts', "const validateEvent = (e: unknown) => e;\nexport async function POST(req: Request) {\n  const event = validateEvent(await req.json());\n  return new Response(String(event));\n}\n")],
];
