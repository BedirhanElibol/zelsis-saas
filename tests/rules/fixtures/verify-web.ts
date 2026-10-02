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

  // ─── GraphQL ──────────────────────────────────────────────────────────
  {
    ruleIds: [26, 8501, 8503],
    name: 'Apollo server without depth or complexity limits',
    detects: f('src/graphql/server.ts', src(
      "import { ApolloServer } from '@apollo/server';",
      "import { startStandaloneServer } from '@apollo/server/standalone';",
      "import { typeDefs } from './schema';",
      "import { resolvers } from './resolvers';",
      'const server = new ApolloServer({ typeDefs, resolvers });',
      'await startStandaloneServer(server, { listen: { port: 4000 } });'
    )),
    ignores: f('src/graphql/server.ts', src(
      "import { ApolloServer } from '@apollo/server';",
      "import { startStandaloneServer } from '@apollo/server/standalone';",
      "import depthLimit from 'graphql-depth-limit';",
      "import { createComplexityLimitRule } from 'graphql-validation-complexity';",
      "import { typeDefs } from './schema';",
      "import { resolvers } from './resolvers';",
      'const server = new ApolloServer({',
      '  typeDefs,',
      '  resolvers,',
      '  validationRules: [depthLimit(8), createComplexityLimitRule(1000)],',
      '});',
      'await startStandaloneServer(server, { listen: { port: 4000 } });'
    ))
  },
  {
    ruleIds: [8502, 8504, 8510],
    name: 'Apollo server: introspection forced on, unbounded batching, CSRF prevention off',
    detects: f('src/graphql/server.ts', src(
      "import { ApolloServer } from '@apollo/server';",
      "import depthLimit from 'graphql-depth-limit';",
      'export const server = new ApolloServer({',
      '  typeDefs,',
      '  resolvers,',
      '  introspection: true,',
      '  allowBatchedHttpRequests: true,',
      '  csrfPrevention: false,',
      '  validationRules: [depthLimit(8)],',
      '});'
    )),
    ignores: f('src/graphql/server.ts', src(
      "import { ApolloServer } from '@apollo/server';",
      "import depthLimit from 'graphql-depth-limit';",
      'export const server = new ApolloServer({',
      '  typeDefs,',
      '  resolvers,',
      "  introspection: process.env.NODE_ENV !== 'production',",
      '  validationRules: [depthLimit(8)],',
      '});'
    ))
  },
  {
    ruleIds: [8506],
    name: 'GraphQL User type exposes passwordHash and stripeCustomerId',
    detects: f('src/graphql/schema.ts', src(
      "import { gql } from 'graphql-tag';",
      'export const typeDefs = gql`',
      '  type User {',
      '    id: ID!',
      '    email: String!',
      '    passwordHash: String',
      '    stripeCustomerId: String',
      '  }',
      '  type Query { me: User }',
      '`;'
    )),
    ignores: f('src/graphql/schema.ts', src(
      "import { gql } from 'graphql-tag';",
      'export const typeDefs = gql`',
      '  type User {',
      '    id: ID!',
      '    email: String!',
      '    name: String',
      '  }',
      '  type Query { me: User }',
      '`;'
    ))
  },
  {
    ruleIds: [8509],
    name: 'code-first list field passes client `first` straight to take',
    detects: f('src/graphql/fields/posts.ts', src(
      "import { GraphQLInt, GraphQLList } from 'graphql';",
      'export const postsField = {',
      '  type: new GraphQLList(PostType),',
      '  args: { first: { type: GraphQLInt } },',
      '  async resolve(_parent: unknown, args: { first?: number }, ctx: Context) {',
      "    return ctx.prisma.post.findMany({ take: args.first, orderBy: { createdAt: 'desc' } });",
      '  },',
      '};'
    )),
    ignores: f('src/graphql/fields/posts.ts', src(
      "import { GraphQLInt, GraphQLList } from 'graphql';",
      'export const postsField = {',
      '  type: new GraphQLList(PostType),',
      '  args: { first: { type: GraphQLInt } },',
      '  async resolve(_parent: unknown, args: { first?: number }, ctx: Context) {',
      "    return ctx.prisma.post.findMany({ take: Math.min(args.first ?? 20, 100), orderBy: { createdAt: 'desc' } });",
      '  },',
      '};'
    ))
  },
  {
    ruleIds: [8515],
    name: 'graphql-upload middleware without file size / count limits',
    detects: f('src/graphql/server.ts', src(
      "import express from 'express';",
      "import { ApolloServer } from '@apollo/server';",
      "import { expressMiddleware } from '@apollo/server/express4';",
      "import graphqlUploadExpress from 'graphql-upload/graphqlUploadExpress.mjs';",
      'const app = express();',
      'const server = new ApolloServer({ typeDefs, resolvers });',
      'await server.start();',
      "app.use('/graphql', graphqlUploadExpress(), express.json(), expressMiddleware(server));"
    )),
    ignores: f('src/graphql/server.ts', src(
      "import express from 'express';",
      "import { ApolloServer } from '@apollo/server';",
      "import { expressMiddleware } from '@apollo/server/express4';",
      "import graphqlUploadExpress from 'graphql-upload/graphqlUploadExpress.mjs';",
      'const app = express();',
      'const server = new ApolloServer({ typeDefs, resolvers });',
      'await server.start();',
      "app.use('/graphql', graphqlUploadExpress({ maxFileSize: 10_000_000, maxFiles: 5 }), express.json(), expressMiddleware(server));"
    ))
  },
  {
    ruleIds: [8516],
    name: 'GraphQL document built by interpolating request input',
    detects: f('app/api/search/route.ts', src(
      "import { gql } from 'graphql-request';",
      'export async function GET(req: Request) {',
      '  const { searchParams } = new URL(req.url);',
      '  const document = gql`',
      '    query {',
      '      products(filter: "${searchParams.get(\'q\')}") { id name }',
      '    }',
      '  `;',
      '  return Response.json(await shopify.request(document));',
      '}'
    )),
    ignores: f('app/api/search/route.ts', src(
      "import { gql } from 'graphql-request';",
      'const SEARCH = gql`',
      '  query Search($q: String!) {',
      '    products(filter: $q) { id name }',
      '  }',
      '`;',
      'export async function GET(req: Request) {',
      "  const term = new URL(req.url).searchParams.get('q') ?? '';",
      '  return Response.json(await shopify.request(SEARCH, { q: term }));',
      '}'
    ))
  },
  {
    ruleIds: [8517],
    name: 'resolver interpolates args into $queryRawUnsafe',
    detects: f('src/graphql/resolvers.ts', src(
      'export const resolvers = {',
      '  Query: {',
      '    userByEmail: async (_parent: unknown, args: { email: string }, ctx: Context) => {',
      '      const rows = await ctx.prisma.$queryRawUnsafe(`SELECT id, email FROM "User" WHERE email = \'${args.email}\'`);',
      '      return rows[0];',
      '    },',
      '  },',
      '};'
    )),
    ignores: f('src/graphql/resolvers.ts', src(
      'export const resolvers = {',
      '  Query: {',
      '    userByEmail: async (_parent: unknown, args: { email: string }, ctx: Context) => {',
      '      const rows = await ctx.prisma.$queryRaw`SELECT id, email FROM "User" WHERE email = ${args.email}`;',
      '      return rows[0];',
      '    },',
      '  },',
      '};'
    ))
  },

  // ─── Core security rules ──────────────────────────────────────────────
  {
    ruleIds: [23],
    name: 'profile PATCH spreads the raw JSON body into prisma update',
    detects: f('app/api/profile/route.ts', src(
      "import { auth } from '@/auth';",
      "import { prisma } from '@/lib/prisma';",
      'export async function PATCH(req: Request) {',
      '  const session = await auth();',
      "  if (!session?.user) return new Response('Unauthorized', { status: 401 });",
      '  const body = await req.json();',
      '  const user = await prisma.user.update({',
      '    where: { id: session.user.id },',
      '    data: body,',
      '  });',
      '  return Response.json(user);',
      '}'
    )),
    ignores: f('app/api/profile/route.ts', src(
      "import { auth } from '@/auth';",
      "import { prisma } from '@/lib/prisma';",
      "import { profileSchema } from '@/lib/validations';",
      'export async function PATCH(req: Request) {',
      '  const session = await auth();',
      "  if (!session?.user) return new Response('Unauthorized', { status: 401 });",
      '  const { name, bio } = profileSchema.parse(await req.json());',
      '  const user = await prisma.user.update({',
      '    where: { id: session.user.id },',
      '    data: { name, bio },',
      '  });',
      '  return Response.json(user);',
      '}'
    ))
  },
  {
    ruleIds: [27],
    name: 'regex with nested quantifier (star height 2) on user input',
    detects: f('lib/validation/display-name.ts', src(
      'const DISPLAY_NAME = /^(\\w+\\s?)*$/;',
      'export const isValidDisplayName = (value: string) => DISPLAY_NAME.test(value);'
    )),
    ignores: f('lib/validation/display-name.ts', src(
      'const DISPLAY_NAME = /^[\\w ]{1,64}$/;',
      'const ROLE = /^(admin|member|viewer)+$/;',
      'export const isValidDisplayName = (value: string) => DISPLAY_NAME.test(value);',
      'export const isRole = (value: string) => ROLE.test(value);'
    ))
  },

  // ─── Next.js App Router ───────────────────────────────────────────────
  {
    ruleIds: [8605],
    name: 'middleware forwards a tenant id taken from the query string',
    detects: f('middleware.ts', src(
      "import { NextResponse, type NextRequest } from 'next/server';",
      'export function middleware(request: NextRequest) {',
      '  const requestHeaders = new Headers(request.headers);',
      "  requestHeaders.set('x-tenant-id', request.nextUrl.searchParams.get('tenant') ?? '');",
      '  return NextResponse.next({ request: { headers: requestHeaders } });',
      '}'
    )),
    ignores: f('middleware.ts', src(
      "import { NextResponse, type NextRequest } from 'next/server';",
      'export function middleware(request: NextRequest) {',
      '  const requestHeaders = new Headers(request.headers);',
      "  requestHeaders.set('x-tenant-id', tenantFromHost(request.headers.get('host')));",
      '  return NextResponse.next({ request: { headers: requestHeaders } });',
      '}'
    ))
  },
  {
    ruleIds: [8606],
    name: 'public route handler revalidates any tag it is sent',
    detects: f('app/api/revalidate/route.ts', src(
      "import { revalidateTag } from 'next/cache';",
      "import type { NextRequest } from 'next/server';",
      'export async function POST(request: NextRequest) {',
      '  const { tag } = await request.json();',
      '  revalidateTag(tag);',
      '  return Response.json({ revalidated: true, now: Date.now() });',
      '}'
    )),
    ignores: f('app/api/revalidate/route.ts', src(
      "import { revalidateTag } from 'next/cache';",
      "import type { NextRequest } from 'next/server';",
      'export async function POST(request: NextRequest) {',
      "  if (request.headers.get('authorization') !== `Bearer ${process.env.REVALIDATE_SECRET}`) {",
      "    return new Response('Unauthorized', { status: 401 });",
      '  }',
      '  const { tag } = await request.json();',
      '  revalidateTag(tag);',
      '  return Response.json({ revalidated: true, now: Date.now() });',
      '}'
    ))
  },
  {
    ruleIds: [8607],
    name: '<Link> pointing at a deleting API route (prefetched as GET)',
    detects: f('app/projects/[id]/delete-button.tsx', src(
      "import Link from 'next/link';",
      'export function DeleteProject({ projectId }: { projectId: string }) {',
      '  return (',
      '    <Link href={`/api/projects/${projectId}/delete`} className="text-red-600">',
      '      Delete project',
      '    </Link>',
      '  );',
      '}'
    )),
    ignores: f('app/projects/[id]/delete-button.tsx', src(
      "import Link from 'next/link';",
      "import { deleteProject } from './actions';",
      'export function DeleteProject({ projectId }: { projectId: string }) {',
      '  return (',
      '    <form action={deleteProject.bind(null, projectId)}>',
      '      <button type="submit" className="text-red-600">Delete project</button>',
      '      <Link href="/settings/delete-account">Delete your whole account instead</Link>',
      '    </form>',
      '  );',
      '}'
    ))
  },

  // ─── Supply chain ─────────────────────────────────────────────────────
  {
    ruleIds: [7305, 7308, 7319, 7325, 7326],
    name: 'package.json: branch git dep, typo-squat, http tarball, vulnerable lodash/xml2js',
    detects: f('package.json', `{
  "name": "storefront",
  "private": true,
  "dependencies": {
    "@acme/ui-kit": "git+https://github.com/acme/ui-kit.git#main",
    "mongose": "^5.13.0",
    "legacy-charts": "http://downloads.example-vendor.com/legacy-charts-1.2.0.tgz",
    "lodash": "^4.17.15",
    "xml2js": "^0.4.19",
    "next": "15.1.0"
  }
}
`),
    ignores: f('package.json', `{
  "name": "storefront",
  "private": true,
  "dependencies": {
    "@acme/ui-kit": "git+https://github.com/acme/ui-kit.git#3f2c1a9d8e7b6c5a4f3e2d1c0b9a8f7e6d5c4b3a",
    "mongoose": "^8.9.0",
    "legacy-charts": "^1.2.0",
    "lodash": "^4.17.21",
    "xml2js": "^0.6.2",
    "next": "15.1.0"
  }
}
`)
  },
  {
    ruleIds: [7306],
    name: 'layout loads a CDN script without Subresource Integrity',
    detects: f('app/layout.tsx', src(
      'export default function RootLayout({ children }: { children: React.ReactNode }) {',
      '  return (',
      '    <html lang="en">',
      '      <head>',
      '        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>',
      '      </head>',
      '      <body>{children}</body>',
      '    </html>',
      '  );',
      '}'
    )),
    ignores: f('app/layout.tsx', src(
      'export default function RootLayout({ children }: { children: React.ReactNode }) {',
      '  return (',
      '    <html lang="en">',
      '      <head>',
      '        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" integrity="sha384-9nhczxUqK87bcKHh20fSQcTGD4qq5GhayNYSYWqwBkINBhOfQLg/P5HG5lF1urn4" crossOrigin="anonymous"></script>',
      '      </head>',
      '      <body>{children}</body>',
      '    </html>',
      '  );',
      '}'
    ))
  },
  {
    ruleIds: [7314],
    name: 'requirements.txt with unpinned packages',
    detects: f('requirements.txt', 'fastapi\nuvicorn\nsqlalchemy==2.0.30\n'),
    ignores: f('requirements.txt', 'fastapi==0.115.6\nuvicorn==0.32.1\nsqlalchemy==2.0.30\n')
  },
  {
    ruleIds: [7322, 7329, 7339],
    name: 'workflow: action on @main, write-all token, curl | bash installer',
    detects: f('.github/workflows/ci.yml', `name: CI
on:
  pull_request:
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: curl -fsSL https://get.example-tool.dev/install.sh | bash
      - run: npm ci && npm test
`),
    ignores: f('.github/workflows/ci.yml', `name: CI
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: |
          curl -fsSL -o install.sh https://get.example-tool.dev/install.sh
          echo "2f6b0e2a9c4d7e1f3a5b8c0d2e4f6a8b1c3d5e7f9a0b2c4d6e8f0a1b3c5d7e9f  install.sh" | sha256sum -c -
          bash install.sh
      - run: npm ci && npm test
`)
  },

  {
    ruleIds: [7323],
    name: 'pull_request_target checks out the PR head and runs its scripts',
    detects: f('.github/workflows/preview.yml', `name: Preview
on:
  pull_request_target:
    types: [opened, synchronize]
permissions:
  contents: read
  pull-requests: write
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm run build
      - run: npx vercel deploy --token \${{ secrets.VERCEL_TOKEN }}
`),
    ignores: f('.github/workflows/preview.yml', `name: Preview
on:
  pull_request_target:
    types: [opened, synchronize]
permissions:
  contents: read
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: node scripts/label-pr.mjs
`)
  },

  // ─── OAuth / OIDC ─────────────────────────────────────────────────────
  {
    ruleIds: [10903],
    name: 'passport Google strategy without the OAuth state parameter',
    detects: f('src/auth/google.ts', src(
      "import passport from 'passport';",
      "import { Strategy as GoogleStrategy } from 'passport-google-oauth20';",
      'passport.use(new GoogleStrategy({',
      '  clientID: process.env.GOOGLE_CLIENT_ID!,',
      '  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,',
      "  callbackURL: '/auth/google/callback',",
      '}, verifyGoogleUser));',
      "router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));",
      "router.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => res.redirect('/'));"
    )),
    ignores: f('src/auth/google.ts', src(
      "import passport from 'passport';",
      "import { Strategy as GoogleStrategy } from 'passport-google-oauth20';",
      'passport.use(new GoogleStrategy({',
      '  clientID: process.env.GOOGLE_CLIENT_ID!,',
      '  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,',
      "  callbackURL: '/auth/google/callback',",
      '  state: true,',
      '}, verifyGoogleUser));',
      "router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));",
      "router.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => res.redirect('/'));"
    ))
  },
  {
    ruleIds: [10905],
    name: 'app collects the user password and uses the ROPC grant',
    detects: f('lib/auth/keycloak.ts', src(
      'export async function signIn(username: string, password: string) {',
      '  const res = await fetch(`${process.env.KEYCLOAK_URL}/protocol/openid-connect/token`, {',
      "    method: 'POST',",
      "    body: new URLSearchParams({ grant_type: 'password', client_id: 'web', username, password }),",
      '  });',
      '  return res.json();',
      '}'
    )),
    ignores: f('lib/auth/keycloak.ts', src(
      'export async function exchangeCode(code: string, codeVerifier: string) {',
      '  const res = await fetch(`${process.env.KEYCLOAK_URL}/protocol/openid-connect/token`, {',
      "    method: 'POST',",
      "    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'web', code, code_verifier: codeVerifier, redirect_uri: REDIRECT_URI }),",
      '  });',
      '  return res.json();',
      '}'
    ))
  },

  // ─── Redis ────────────────────────────────────────────────────────────
  {
    ruleIds: [10703],
    name: 'redis.conf binds all interfaces without requirepass',
    detects: f('config/redis.conf', 'bind 0.0.0.0\nprotected-mode no\nport 6379\n# requirepass foobared\nappendonly yes\ndir /var/lib/redis\n'),
    ignores: f('config/redis.conf', 'bind 127.0.0.1 -::1\nprotected-mode yes\nport 6379\n# requirepass foobared\nappendonly yes\ndir /var/lib/redis\n')
  },
  {
    ruleIds: [10704],
    name: 'Lua script assembled with template interpolation',
    detects: f('lib/rate-limit.ts', src(
      'export async function hit(key: string, windowSeconds: number) {',
      "  return redis.eval(`local n = redis.call('INCR', '${key}') if n == 1 then redis.call('EXPIRE', '${key}', ${windowSeconds}) end return n`, 0);",
      '}'
    )),
    ignores: f('lib/rate-limit.ts', src(
      "const HIT = \"local n = redis.call('INCR', KEYS[1]) if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end return n\";",
      'export async function hit(key: string, windowSeconds: number) {',
      '  return redis.eval(HIT, 1, key, windowSeconds);',
      '}'
    ))
  },
  {
    ruleIds: [27241],
    name: 'docker-compose publishes Redis with protected mode off and no password',
    detects: f('docker-compose.yml', `services:
  redis:
    image: redis:7-alpine
    command: redis-server --protected-mode no
    ports:
      - "6379:6379"
`),
    ignores: f('docker-compose.yml', `services:
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass \${REDIS_PASSWORD}
    ports:
      - "127.0.0.1:6379:6379"
`)
  },

  // ─── Downgraded (precise, lower impact) ───────────────────────────────
  {
    ruleIds: [8113],
    name: 'CORS headers: credentials allowed with wildcard origin (MEDIUM)',
    detects: f('app/api/widgets/route.ts', src(
      'const corsHeaders = {',
      "  'Access-Control-Allow-Origin': '*',",
      "  'Access-Control-Allow-Credentials': 'true',",
      "  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',",
      '};',
      'export async function OPTIONS() {',
      '  return new Response(null, { headers: corsHeaders });',
      '}'
    )),
    ignores: f('app/api/widgets/route.ts', src(
      'const corsHeaders = {',
      "  'Access-Control-Allow-Origin': process.env.APP_URL!,",
      "  'Access-Control-Allow-Credentials': 'true',",
      "  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',",
      "  Vary: 'Origin',",
      '};',
      'export async function OPTIONS() {',
      '  return new Response(null, { headers: corsHeaders });',
      '}'
    ))
  },
  {
    ruleIds: [8131],
    name: 'access token persisted in localStorage (MEDIUM)',
    detects: f('lib/api-client.ts', src(
      'export async function login(email: string, password: string) {',
      "  const res = await fetch('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) });",
      '  const { accessToken } = await res.json();',
      "  localStorage.setItem('token', accessToken);",
      '}'
    )),
    ignores: f('lib/api-client.ts', src(
      'export async function login(email: string, password: string) {',
      "  await fetch('/api/login', { method: 'POST', credentials: 'include', body: JSON.stringify({ email, password }) });",
      '}'
    ))
  },
  {
    ruleIds: [7203],
    name: 'API route returns a whole table with findMany() (MEDIUM)',
    detects: f('app/api/orders/route.ts', src(
      'export async function GET() {',
      '  const orders = await prisma.order.findMany();',
      '  return Response.json(orders);',
      '}'
    )),
    ignores: f('app/api/orders/route.ts', src(
      'export async function GET(request: Request) {',
      "  const cursor = new URL(request.url).searchParams.get('cursor') ?? undefined;",
      '  const orders = await prisma.order.findMany({ take: 50, ...(cursor && { skip: 1, cursor: { id: cursor } }) });',
      '  return Response.json(orders);',
      '}'
    ))
  },
  {
    ruleIds: [7235],
    name: 'Content-Disposition filename concatenated unencoded (MEDIUM)',
    detects: f('app/api/files/[id]/route.ts', src(
      'export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {',
      '  const file = await getFile((await params).id);',
      '  const headers = new Headers();',
      "  headers.set('Content-Disposition', 'attachment; filename=' + file.name);",
      '  return new Response(file.body, { headers });',
      '}'
    )),
    ignores: f('app/api/files/[id]/route.ts', src(
      'export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {',
      '  const file = await getFile((await params).id);',
      '  const headers = new Headers();',
      "  headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(file.name)}`);",
      '  return new Response(file.body, { headers });',
      '}'
    ))
  },
  {
    ruleIds: [1023],
    name: 'shipped UI copy contains "As an AI language model" boilerplate (LOW)',
    detects: f('components/chat/empty-state.tsx', src(
      'export function EmptyState() {',
      '  return <p>As an AI language model, I can help you draft emails and summaries.</p>;',
      '}'
    )),
    ignores: f('components/chat/empty-state.tsx', src(
      'export function EmptyState() {',
      '  return <p>Ask me to draft an email or summarise a document.</p>;',
      '}'
    ))
  },
  {
    ruleIds: [6029],
    name: 'Supabase realtime subscribes to every change on a table (LOW)',
    detects: f('components/chat/use-messages.ts', src(
      'export function subscribeToRoom(roomId: string, onMessage: (m: Message) => void) {',
      '  return supabase',
      "    .channel('messages').on('postgres_changes', { event: '*', schema: 'public', table: 'messages' }, (payload) => onMessage(payload.new as Message))",
      '    .subscribe();',
      '}'
    )),
    ignores: f('components/chat/use-messages.ts', src(
      'export function subscribeToRoom(roomId: string, onMessage: (m: Message) => void) {',
      '  return supabase',
      "    .channel(`room-${roomId}`).on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'messages', filter: `room_id=eq.${roomId}` }, (payload) => onMessage(payload.new as Message))",
      '    .subscribe();',
      '}'
    ))
  },
  {
    ruleIds: [6034],
    name: 'loads the whole table then sorts in memory (MEDIUM)',
    detects: f('lib/leaderboard.ts', src(
      'export async function topPlayers() {',
      '  const players = await prisma.player.findMany();',
      '  return players.sort((a, b) => b.score - a.score).slice(0, 10);',
      '}'
    )),
    ignores: f('lib/leaderboard.ts', src(
      'export async function topPlayers() {',
      "  return prisma.player.findMany({ orderBy: { score: 'desc' }, take: 10 });",
      '}'
    ))
  },

  // ─── ASVS ─────────────────────────────────────────────────────────────
  {
    ruleIds: [13805],
    name: 'password hashing with a weak work factor (bcrypt cost 8, PBKDF2 1000 iterations)',
    detects: f('lib/auth/hash.ts', src(
      "import bcrypt from 'bcryptjs';",
      "import { pbkdf2Sync, randomBytes } from 'node:crypto';",
      'export const hashPassword = (password: string) => bcrypt.hash(password, 8);',
      'export function deriveKey(secret: string) {',
      '  const salt = randomBytes(16);',
      "  return pbkdf2Sync(secret, salt, 1000, 32, 'sha256');",
      '}'
    )),
    ignores: f('lib/auth/hash.ts', src(
      "import bcrypt from 'bcryptjs';",
      "import { pbkdf2Sync, randomBytes } from 'node:crypto';",
      'export const hashPassword = (password: string) => bcrypt.hash(password, 12);',
      'export function deriveKey(secret: string) {',
      '  const salt = randomBytes(16);',
      "  return pbkdf2Sync(secret, salt, 600_000, 32, 'sha256');",
      '}'
    ))
  },
];
