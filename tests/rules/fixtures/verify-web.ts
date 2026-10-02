/**
 * Fixture evidence for JS/TS web-area rules (zero-trust, api, graphql, security, modern-fullstack,
 * supply-chain, oauth, cache, multi-database). Each case: realistic vulnerable code vs. the idiomatic fix.
 */
import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const src = (...lines: string[]): string => lines.join('\n') + '\n';

export const CASES: RuleCase[] = [
  // ─── Zero-trust / auth ────────────────────────────────────────────────
  {
    ruleIds: [8104],
    name: 'middleware honours a debug auth-bypass header',
    detects: f('middleware.ts', src(
      "import { NextResponse, type NextRequest } from 'next/server';",
      'export function middleware(request: NextRequest) {',
      "  if (request.headers.get('x-bypass-auth') === 'true') {",
      '    return NextResponse.next();',
      '  }',
      "  const session = request.cookies.get('session');",
      "  if (!session) return NextResponse.redirect(new URL('/login', request.url));",
      '  return NextResponse.next();',
      '}'
    )),
    ignores: f('middleware.ts', src(
      "import { NextResponse, type NextRequest } from 'next/server';",
      'export function middleware(request: NextRequest) {',
      "  const session = request.cookies.get('session');",
      "  if (!session) return NextResponse.redirect(new URL('/login', request.url));",
      '  return NextResponse.next();',
      '}'
    ))
  },
  {
    ruleIds: [8105],
    name: 'express PATCH passes req.body straight into prisma update',
    detects: f('src/routes/users.ts', src(
      "router.patch('/users/:id', requireAuth, async (req, res) => {",
      '  const user = await prisma.user.update({',
      '    where: { id: req.params.id },',
      '    data: req.body,',
      '  });',
      '  res.json(user);',
      '});'
    )),
    ignores: f('src/routes/users.ts', src(
      "router.patch('/users/:id', requireAuth, async (req, res) => {",
      '  const data = updateProfileSchema.parse(req.body);',
      '  const user = await prisma.user.update({',
      '    where: { id: req.params.id },',
      '    data,',
      '  });',
      '  res.json(user);',
      '});'
    ))
  },
  {
    ruleIds: [8110],
    name: 'login route handler without any rate limiting',
    detects: f('app/api/auth/login/route.ts', src(
      "import bcrypt from 'bcryptjs';",
      "import { db } from '@/lib/db';",
      'export async function POST(req: Request) {',
      '  const { email, password } = await req.json();',
      '  const user = await db.user.findUnique({ where: { email } });',
      '  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {',
      "    return Response.json({ error: 'Invalid credentials' }, { status: 401 });",
      '  }',
      '  return Response.json({ ok: true });',
      '}'
    )),
    ignores: f('app/api/auth/login/route.ts', src(
      "import bcrypt from 'bcryptjs';",
      "import { Ratelimit } from '@upstash/ratelimit';",
      "import { db } from '@/lib/db';",
      "const limiter = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(5, '1 m') });",
      'export async function POST(req: Request) {',
      "  const ip = req.headers.get('x-real-ip') ?? 'anonymous';",
      '  const { success } = await limiter.limit(ip);',
      "  if (!success) return Response.json({ error: 'Too many attempts' }, { status: 429 });",
      '  const { email, password } = await req.json();',
      '  const user = await db.user.findUnique({ where: { email } });',
      '  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {',
      "    return Response.json({ error: 'Invalid credentials' }, { status: 401 });",
      '  }',
      '  return Response.json({ ok: true });',
      '}'
    ))
  },
  {
    ruleIds: [8111],
    name: 'API route accepts the access token from the query string',
    detects: f('app/api/export/route.ts', src(
      "import { type NextRequest } from 'next/server';",
      'export async function GET(request: NextRequest) {',
      "  const token = request.nextUrl.searchParams.get('access_token');",
      '  const user = await verifyAccessToken(token);',
      "  if (!user) return new Response('Unauthorized', { status: 401 });",
      '  return Response.json(await buildExport(user.id));',
      '}'
    )),
    ignores: f('app/api/export/route.ts', src(
      "import { type NextRequest } from 'next/server';",
      'export async function GET(request: NextRequest) {',
      "  const token = request.headers.get('authorization')?.replace(/^Bearer /, '');",
      '  const user = await verifyAccessToken(token);',
      "  if (!user) return new Response('Unauthorized', { status: 401 });",
      '  return Response.json(await buildExport(user.id));',
      '}'
    ))
  },
  {
    ruleIds: [8118],
    name: 'cookie-session DELETE handler without an Origin / CSRF check',
    detects: f('app/api/account/route.ts', src(
      "import { cookies } from 'next/headers';",
      'export async function DELETE() {',
      "  const sessionId = (await cookies()).get('session')?.value;",
      '  const session = await getSession(sessionId);',
      "  if (!session) return new Response('Unauthorized', { status: 401 });",
      '  await deleteAccount(session.userId);',
      '  return new Response(null, { status: 204 });',
      '}'
    )),
    ignores: f('app/api/account/route.ts', src(
      "import { cookies, headers } from 'next/headers';",
      'export async function DELETE() {',
      '  const requestHeaders = await headers();',
      "  if (requestHeaders.get('origin') !== process.env.APP_URL) return new Response('Forbidden', { status: 403 });",
      "  const sessionId = (await cookies()).get('session')?.value;",
      '  const session = await getSession(sessionId);',
      "  if (!session) return new Response('Unauthorized', { status: 401 });",
      '  await deleteAccount(session.userId);',
      '  return new Response(null, { status: 204 });',
      '}'
    ))
  },
  {
    ruleIds: [8120],
    name: 'OAuth authorize URL built without a state parameter',
    detects: f('lib/oauth/github.ts', src(
      "const REDIRECT_URI = `${process.env.APP_URL}/api/oauth/github/callback`;",
      'export function getGithubAuthUrl() {',
      '  const authUrl = `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=read:user`;',
      '  return authUrl;',
      '}'
    )),
    ignores: f('lib/oauth/github.ts', src(
      "import { randomBytes } from 'node:crypto';",
      "const REDIRECT_URI = `${process.env.APP_URL}/api/oauth/github/callback`;",
      'export function getGithubAuthUrl() {',
      "  const oauthState = randomBytes(16).toString('hex');",
      '  const authUrl = `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=read:user&state=${oauthState}`;',
      '  return { authUrl, oauthState };',
      '}'
    ))
  },
  {
    ruleIds: [8124],
    name: 'OAuth provider validates redirect_uri only by scheme prefix',
    detects: f('app/api/oauth/authorize/route.ts', src(
      "import { NextResponse, type NextRequest } from 'next/server';",
      'export async function GET(request: NextRequest) {',
      '  const { searchParams } = request.nextUrl;',
      "  const redirectUri = searchParams.get('redirect_uri') ?? '';",
      "  if (!redirectUri.startsWith('https://')) {",
      "    return NextResponse.json({ error: 'invalid_redirect_uri' }, { status: 400 });",
      '  }',
      "  const code = await issueAuthorizationCode(searchParams.get('client_id'));",
      '  return NextResponse.redirect(`${redirectUri}?code=${code}`);',
      '}'
    )),
    ignores: f('app/api/oauth/authorize/route.ts', src(
      "import { NextResponse, type NextRequest } from 'next/server';",
      'export async function GET(request: NextRequest) {',
      '  const { searchParams } = request.nextUrl;',
      "  const redirectUri = searchParams.get('redirect_uri') ?? '';",
      "  const client = await getOAuthClient(searchParams.get('client_id'));",
      '  if (!client || !client.redirectUris.includes(redirectUri)) {',
      "    return NextResponse.json({ error: 'invalid_redirect_uri' }, { status: 400 });",
      '  }',
      '  const code = await issueAuthorizationCode(client.id);',
      '  return NextResponse.redirect(`${redirectUri}?code=${code}`);',
      '}'
    ))
  },
  {
    ruleIds: [8139],
    name: 'Diffie-Hellman group generated with a 1024-bit prime',
    detects: f('lib/crypto/key-exchange.ts', src(
      "import crypto from 'node:crypto';",
      'export function createKeyExchange() {',
      '  const dh = crypto.createDiffieHellman(1024);',
      '  return { dh, publicKey: dh.generateKeys() };',
      '}'
    )),
    ignores: f('lib/crypto/key-exchange.ts', src(
      "import crypto from 'node:crypto';",
      'export function createKeyExchange() {',
      "  const ecdh = crypto.createECDH('prime256v1');",
      '  return { ecdh, publicKey: ecdh.generateKeys() };',
      '}'
    ))
  },
  {
    ruleIds: [8150],
    name: 'password reset token generated with Math.random()',
    detects: f('lib/auth/password-reset.ts', src(
      'export async function createResetToken(userId: string) {',
      '  const token = Math.random().toString(36).substring(2);',
      '  await db.passwordReset.create({ data: { userId, token, expiresAt: new Date(Date.now() + 3600_000) } });',
      '  return token;',
      '}'
    )),
    ignores: f('lib/auth/password-reset.ts', src(
      "import { randomBytes } from 'node:crypto';",
      'export async function createResetToken(userId: string) {',
      "  const token = randomBytes(32).toString('hex');",
      '  await db.passwordReset.create({ data: { userId, token, expiresAt: new Date(Date.now() + 3600_000) } });',
      '  return token;',
      '}'
    ))
  },
  {
    ruleIds: [8103],
    name: 'webhook HMAC signature compared with !==',
    detects: f('app/api/webhooks/github/route.ts', src(
      "import crypto from 'node:crypto';",
      'export async function POST(request: Request) {',
      "  const signature = request.headers.get('x-hub-signature-256');",
      '  const body = await request.text();',
      "  const expectedSignature = 'sha256=' + crypto.createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET!).update(body).digest('hex');",
      '  if (signature !== expectedSignature) {',
      "    return new Response('Invalid signature', { status: 401 });",
      '  }',
      '  await handleEvent(JSON.parse(body));',
      "  return new Response('ok');",
      '}'
    )),
    ignores: f('app/api/webhooks/github/route.ts', src(
      "import crypto from 'node:crypto';",
      'export async function POST(request: Request) {',
      "  const signature = request.headers.get('x-hub-signature-256') ?? '';",
      '  const body = await request.text();',
      "  const expectedSignature = 'sha256=' + crypto.createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET!).update(body).digest('hex');",
      '  const a = Buffer.from(signature);',
      '  const b = Buffer.from(expectedSignature);',
      '  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {',
      "    return new Response('Invalid signature', { status: 401 });",
      '  }',
      '  await handleEvent(JSON.parse(body));',
      "  return new Response('ok');",
      '}'
    ))
  },
  {
    ruleIds: [8109],
    name: 'express-session login keeps the pre-login session id (fixation)',
    detects: f('src/routes/auth.ts', src(
      "router.post('/login', async (req, res) => {",
      '  const user = await User.findOne({ email: req.body.email });',
      '  if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) {',
      "    return res.status(401).json({ error: 'Invalid credentials' });",
      '  }',
      '  req.session.userId = user.id;',
      '  res.json({ ok: true });',
      '});'
    )),
    ignores: f('src/routes/auth.ts', src(
      "router.post('/login', async (req, res, next) => {",
      '  const user = await User.findOne({ email: req.body.email });',
      '  if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) {',
      "    return res.status(401).json({ error: 'Invalid credentials' });",
      '  }',
      '  req.session.regenerate((err) => {',
      '    if (err) return next(err);',
      '    req.session.userId = user.id;',
      '    res.json({ ok: true });',
      '  });',
      '});'
    ))
  },
  {
    ruleIds: [8122],
    name: 'login compares the stored password column with ===',
    detects: f('lib/auth/credentials.ts', src(
      'export async function authorize(email: string, password: string) {',
      '  const user = await db.user.findUnique({ where: { email } });',
      '  if (!user || user.password !== password) {',
      "    throw new AuthError('Invalid credentials');",
      '  }',
      '  return { id: user.id, email: user.email };',
      '}'
    )),
    ignores: f('lib/auth/credentials.ts', src(
      "import bcrypt from 'bcryptjs';",
      'export async function authorize(email: string, password: string) {',
      '  const user = await db.user.findUnique({ where: { email } });',
      '  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {',
      "    throw new AuthError('Invalid credentials');",
      '  }',
      '  return { id: user.id, email: user.email };',
      '}'
    ))
  },

  // ─── API ──────────────────────────────────────────────────────────────
  {
    ruleIds: [7207],
    name: 'health endpoint echoes the environment',
    detects: f('app/api/health/route.ts', src(
      "import { NextResponse } from 'next/server';",
      'export async function GET() {',
      "  return NextResponse.json({ status: 'ok', env: process.env });",
      '}'
    )),
    ignores: f('app/api/health/route.ts', src(
      "import { NextResponse } from 'next/server';",
      'export async function GET() {',
      "  return NextResponse.json({ status: 'ok', version: process.env.VERCEL_GIT_COMMIT_SHA });",
      '}'
    ))
  },
  {
    ruleIds: [7213],
    name: 'POST handler casts the JSON body to any',
    detects: f('app/api/feedback/route.ts', src(
      'export async function POST(request: Request) {',
      '  const body = (await request.json()) as any;',
      '  await db.feedback.create({ data: { message: body.message, rating: body.rating } });',
      '  return Response.json({ ok: true });',
      '}'
    )),
    ignores: f('app/api/feedback/route.ts', src(
      "import { z } from 'zod';",
      'const feedbackSchema = z.object({ message: z.string().max(2000), rating: z.number().int().min(1).max(5) });',
      'export async function POST(request: Request) {',
      '  const body = feedbackSchema.parse(await request.json());',
      '  await db.feedback.create({ data: { message: body.message, rating: body.rating } });',
      '  return Response.json({ ok: true });',
      '}'
    ))
  },
  {
    ruleIds: [7221],
    name: '500 response returns the error stack',
    detects: f('app/api/orders/route.ts', src(
      "import { NextResponse } from 'next/server';",
      'export async function POST(request: Request) {',
      '  try {',
      '    const order = await createOrder(await request.json());',
      '    return NextResponse.json(order);',
      '  } catch (error: any) {',
      '    return NextResponse.json({ message: error.message, stack: error.stack }, { status: 500 });',
      '  }',
      '}'
    )),
    ignores: f('app/api/orders/route.ts', src(
      "import { NextResponse } from 'next/server';",
      'export async function POST(request: Request) {',
      '  try {',
      '    const order = await createOrder(await request.json());',
      '    return NextResponse.json(order);',
      '  } catch (error) {',
      "    console.error('createOrder failed', error);",
      "    return NextResponse.json({ message: 'Internal server error' }, { status: 500 });",
      '  }',
      '}'
    ))
  },
  {
    ruleIds: [7223],
    name: 'outbound webhook delivered without an HMAC signature',
    detects: f('lib/webhooks/deliver.ts', src(
      'export async function sendWebhook(endpoint: string, event: WebhookEvent) {',
      '  await fetch(endpoint, {',
      "    method: 'POST',",
      "    headers: { 'Content-Type': 'application/json' },",
      '    body: JSON.stringify(event),',
      '  });',
      '}'
    )),
    ignores: f('lib/webhooks/deliver.ts', src(
      "import { createHmac } from 'node:crypto';",
      'export async function sendWebhook(endpoint: string, secret: string, event: WebhookEvent) {',
      '  const body = JSON.stringify(event);',
      '  const timestamp = Math.floor(Date.now() / 1000);',
      "  const sig = createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');",
      '  await fetch(endpoint, {',
      "    method: 'POST',",
      "    headers: { 'Content-Type': 'application/json', 'X-Webhook-Timestamp': String(timestamp), 'X-Webhook-Signature': sig },",
      '    body,',
      '  });',
      '}'
    ))
  },
  {
    ruleIds: [7230],
    name: 'tRPC publicProcedure deletes a record without checking the caller',
    detects: f('src/server/api/routers/project.ts', src(
      "import { z } from 'zod';",
      "import { createTRPCRouter, publicProcedure, protectedProcedure } from '@/server/api/trpc';",
      'export const projectRouter = createTRPCRouter({',
      '  list: protectedProcedure.query(({ ctx }) => ctx.db.project.findMany({ where: { ownerId: ctx.session.user.id } })),',
      '  delete: publicProcedure',
      '    .input(z.object({ id: z.string() }))',
      '    .mutation(async ({ ctx, input }) => {',
      '      return ctx.db.project.delete({ where: { id: input.id } });',
      '    }),',
      '});'
    )),
    ignores: f('src/server/api/routers/project.ts', src(
      "import { z } from 'zod';",
      "import { createTRPCRouter, protectedProcedure } from '@/server/api/trpc';",
      'export const projectRouter = createTRPCRouter({',
      '  list: protectedProcedure.query(({ ctx }) => ctx.db.project.findMany({ where: { ownerId: ctx.session.user.id } })),',
      '  delete: protectedProcedure',
      '    .input(z.object({ id: z.string() }))',
      '    .mutation(async ({ ctx, input }) => {',
      '      return ctx.db.project.delete({ where: { id: input.id, ownerId: ctx.session.user.id } });',
      '    }),',
      '});'
    ))
  },
  {
    ruleIds: [7243],
    name: 'ws server without a maxPayload bound (default 100 MiB)',
    detects: f('server/realtime.ts', src(
      "import { WebSocketServer } from 'ws';",
      'const wss = new WebSocketServer({ port: 8080 });',
      "wss.on('connection', (socket) => {",
      "  socket.on('message', (data) => broadcast(data));",
      '});'
    )),
    ignores: f('server/realtime.ts', src(
      "import { WebSocketServer } from 'ws';",
      'const wss = new WebSocketServer({ port: 8080, maxPayload: 64 * 1024 });',
      "wss.on('connection', (socket) => {",
      "  socket.on('message', (data) => broadcast(data));",
      '});'
    ))
  },
  {
    ruleIds: [7246],
    name: 'internal API key compared with !==',
    detects: f('app/api/internal/sync/route.ts', src(
      'export async function POST(request: Request) {',
      "  const apiKey = request.headers.get('x-api-key');",
      '  if (apiKey !== process.env.INTERNAL_API_KEY) {',
      "    return new Response('Unauthorized', { status: 401 });",
      '  }',
      '  await runSync();',
      '  return Response.json({ ok: true });',
      '}'
    )),
    ignores: f('app/api/internal/sync/route.ts', src(
      "import { timingSafeEqual } from 'node:crypto';",
      'export async function POST(request: Request) {',
      "  const apiKey = Buffer.from(request.headers.get('x-api-key') ?? '');",
      "  const expected = Buffer.from(process.env.INTERNAL_API_KEY ?? '');",
      '  if (apiKey.length !== expected.length || !timingSafeEqual(apiKey, expected)) {',
      "    return new Response('Unauthorized', { status: 401 });",
      '  }',
      '  await runSync();',
      '  return Response.json({ ok: true });',
      '}'
    ))
  },
  {
    ruleIds: [7247],
    name: 'user endpoint returns the full row including password hash',
    detects: f('app/api/users/[id]/route.ts', src(
      "import { NextResponse } from 'next/server';",
      'export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {',
      '  const { id } = await params;',
      "  const { data: user } = await supabaseAdmin.from('users').select('id, email, full_name, password_hash, stripe_customer_id').eq('id', id).single();",
      '  return NextResponse.json(user);',
      '}'
    )),
    ignores: f('app/api/users/[id]/route.ts', src(
      "import { NextResponse } from 'next/server';",
      'export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {',
      '  const { id } = await params;',
      "  const { data: user } = await supabaseAdmin.from('users').select('id, full_name, avatar_url').eq('id', id).single();",
      '  return NextResponse.json(user);',
      '}'
    ))
  },
  {
    ruleIds: [7249],
    name: 'auth callback appends an unchecked ?next= to the origin',
    detects: f('app/auth/callback/route.ts', src(
      "import { NextResponse } from 'next/server';",
      "import { createClient } from '@/utils/supabase/server';",
      'export async function GET(request: Request) {',
      '  const { searchParams, origin } = new URL(request.url);',
      "  const code = searchParams.get('code');",
      "  const next = searchParams.get('next') ?? '/';",
      '  if (code) {',
      '    const supabase = await createClient();',
      '    const { error } = await supabase.auth.exchangeCodeForSession(code);',
      '    if (!error) return NextResponse.redirect(`${origin}${next}`);',
      '  }',
      '  return NextResponse.redirect(`${origin}/auth/auth-code-error`);',
      '}'
    )),
    ignores: f('app/auth/callback/route.ts', src(
      "import { NextResponse } from 'next/server';",
      "import { createClient } from '@/utils/supabase/server';",
      'export async function GET(request: Request) {',
      '  const { searchParams, origin } = new URL(request.url);',
      "  const code = searchParams.get('code');",
      "  let next = searchParams.get('next') ?? '/';",
      "  if (!next.startsWith('/')) next = '/';",
      '  if (code) {',
      '    const supabase = await createClient();',
      '    const { error } = await supabase.auth.exchangeCodeForSession(code);',
      '    if (!error) return NextResponse.redirect(`${origin}${next}`);',
      '  }',
      '  return NextResponse.redirect(`${origin}/auth/auth-code-error`);',
      '}'
    ))
  },
];
