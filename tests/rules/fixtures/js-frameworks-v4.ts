import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const lit = (...parts: string[]) => parts.join('');

export const CASES: RuleCase[] = [
  {
    ruleIds: [28901], name: 'JSF-01 SvelteKit redirect to query target',
    detects: f('src/routes/login/+page.server.ts', `import { redirect } from '@sveltejs/kit';
export const actions = {
  default: async ({ url, cookies }) => {
    const target = url.searchParams.get('redirectTo') ?? '/';
    throw redirect(303, target);
  },
};
`),
    ignores: f('src/routes/login/+page.server.ts', `import { redirect } from '@sveltejs/kit';
export const actions = {
  default: async ({ url, cookies }) => {
    const target = url.searchParams.get('redirectTo') ?? '/';
    const safe = target.startsWith('/') && !target.startsWith('//') ? target : '/';
    throw redirect(303, safe);
  },
};
`),
  },
  {
    ruleIds: [28901], name: 'JSF-01 NextResponse.redirect(new URL(param, base))',
    detects: f('app/go/route.ts', `import { NextResponse, type NextRequest } from 'next/server';
export function GET(request: NextRequest) {
  const to = request.nextUrl.searchParams.get('to') ?? '/';
  return NextResponse.redirect(new URL(to, request.url));
}
`),
    ignores: f('app/go/route.ts', `import { NextResponse, type NextRequest } from 'next/server';
export function GET(request: NextRequest) {
  const to = request.nextUrl.searchParams.get('to') ?? '/';
  const dest = new URL(to, request.url);
  if (dest.origin !== request.nextUrl.origin) return NextResponse.redirect(new URL('/', request.url));
  return NextResponse.redirect(dest);
}
`),
  },
  {
    ruleIds: [28902], name: 'JSF-02 middleware rewrite SSRF',
    detects: f('middleware.ts', `import { NextResponse, type NextRequest } from 'next/server';
export function middleware(request: NextRequest) {
  const upstream = request.nextUrl.searchParams.get('upstream');
  return NextResponse.rewrite(new URL(upstream!));
}
`),
    ignores: f('middleware.ts', `import { NextResponse, type NextRequest } from 'next/server';
const UPSTREAMS: Record<string, string> = { eu: 'https://eu.api.example.com', us: 'https://us.api.example.com' };
export function middleware(request: NextRequest) {
  const region = request.nextUrl.searchParams.get('region') ?? 'eu';
  return NextResponse.rewrite(new URL(request.nextUrl.pathname, UPSTREAMS[region] ?? UPSTREAMS.eu));
}
`),
  },
  {
    ruleIds: [28903], name: 'JSF-03 reset link from Host header in route handler',
    detects: f('app/api/auth/forgot/route.ts', `export async function POST(request: Request) {
  const { email } = await request.json();
  const host = request.headers.get('host');
  const token = await createResetToken(email);
  await sendMail(email, \`https://\${host}/reset-password?token=\${token}\`);
  return Response.json({ ok: true });
}
`),
    ignores: f('app/api/auth/forgot/route.ts', `export async function POST(request: Request) {
  const { email } = await request.json();
  const token = await createResetToken(email);
  await sendMail(email, \`\${process.env.APP_URL}/reset-password?token=\${token}\`);
  return Response.json({ ok: true });
}
`),
  },
  {
    ruleIds: [28904], name: 'JSF-04 reflected XSS in text/html Response',
    detects: f('app/api/og/route.ts', `export async function GET(request: Request) {
  const title = new URL(request.url).searchParams.get('title');
  return new Response(\`<html><body><h1>\${title}</h1></body></html>\`, { headers: { 'Content-Type': 'text/html' } });
}
`),
    ignores: f('app/api/og/route.ts', `import escapeHtml from 'escape-html';
export async function GET(request: Request) {
  const title = new URL(request.url).searchParams.get('title') ?? '';
  return new Response(\`<html><body><h1>\${escapeHtml(title)}</h1></body></html>\`, { headers: { 'Content-Type': 'text/html' } });
}
`),
  },
  {
    ruleIds: [28905], name: 'JSF-05 JSON body used as Prisma where',
    detects: f('app/api/users/find/route.ts', `import { prisma } from '@/lib/db';
export async function POST(request: Request) {
  const filter = await request.json();
  const user = await prisma.user.findFirst({ where: filter });
  return Response.json({ id: user?.id });
}
`),
    ignores: f('app/api/users/find/route.ts', `import { prisma } from '@/lib/db';
import { z } from 'zod';
const Filter = z.object({ email: z.string().email() });
export async function POST(request: Request) {
  const { email } = Filter.parse(await request.json());
  const user = await prisma.user.findFirst({ where: { email } });
  return Response.json({ id: user?.id });
}
`),
  },
  {
    ruleIds: [28906], name: 'JSF-06 reset token lookup with object-capable body',
    detects: f('src/routes/auth.ts', `router.post('/reset', async (req, res) => {
  const user = await User.findOne({ resetToken: req.body.token });
  if (!user) return res.status(400).end();
  user.password = await bcrypt.hash(req.body.password, 12);
  await user.save();
  res.json({ ok: true });
});
`),
    ignores: f('src/routes/auth.ts', `router.post('/reset', async (req, res) => {
  const token = String(req.body.token ?? '');
  const user = await User.findOne({ resetToken: token });
  if (!user) return res.status(400).end();
  user.password = await bcrypt.hash(String(req.body.password), 12);
  await user.save();
  res.json({ ok: true });
});
`),
  },
  {
    ruleIds: [28907], name: 'JSF-07 RegExp from searchParams',
    detects: f('app/api/search/route.ts', `export async function GET(request: Request) {
  const q = new URL(request.url).searchParams.get('q') ?? '';
  const pattern = new RegExp(q, 'i');
  return Response.json(products.filter((p) => pattern.test(p.name)));
}
`),
    ignores: f('app/api/search/route.ts', `import escapeStringRegexp from 'escape-string-regexp';
export async function GET(request: Request) {
  const q = new URL(request.url).searchParams.get('q') ?? '';
  const pattern = new RegExp(escapeStringRegexp(q), 'i');
  return Response.json(products.filter((p) => pattern.test(p.name)));
}
`),
  },
  {
    ruleIds: [28908], name: 'JSF-08 DOM XSS via URLSearchParams into innerHTML',
    detects: f('src/banner.ts', `const params = new URLSearchParams(window.location.search);
const message = params.get('msg') ?? '';
document.getElementById('banner')!.innerHTML = \`<p>\${message}</p>\`;
`),
    ignores: f('src/banner.ts', `const params = new URLSearchParams(window.location.search);
const message = params.get('msg') ?? '';
document.getElementById('banner')!.textContent = message;
`),
  },
  {
    ruleIds: [28908], name: 'JSF-08 document.write of location.hash',
    detects: f('public/js/widget.js', `var name = decodeURIComponent(location.hash.slice(1));
document.write('<h2>Hello ' + name + '</h2>');
`),
    ignores: f('public/js/widget.js', `var name = decodeURIComponent(location.hash.slice(1));
var h = document.createElement('h2');
h.textContent = 'Hello ' + name;
document.body.appendChild(h);
`),
  },
  {
    ruleIds: [28909], name: 'JSF-09 location.href from ?next',
    detects: f('src/pages/login.ts', `export function afterLogin() {
  const next = new URLSearchParams(location.search).get('next') || '/';
  window.location.href = next;
}
`),
    ignores: f('src/pages/login.ts', `export function afterLogin() {
  const next = new URLSearchParams(location.search).get('next') || '/';
  window.location.href = next.startsWith('/') && !next.startsWith('//') ? next : '/';
}
`),
  },
  {
    ruleIds: [28910], name: 'JSF-10 v-html bound to route query',
    detects: f('src/components/Notice.vue', `<template>
  <div class="notice" v-html="$route.query.message"></div>
</template>
`),
    ignores: f('src/components/Notice.vue', `<template>
  <div class="notice">{{ $route.query.message }}</div>
</template>
`),
  },
  {
    ruleIds: [28910], name: 'JSF-10 dangerouslySetInnerHTML from useSearchParams',
    detects: f('app/welcome/page.tsx', `'use client';
import { useSearchParams } from 'next/navigation';
export default function Welcome() {
  const searchParams = useSearchParams();
  return <div dangerouslySetInnerHTML={{ __html: searchParams.get('msg') ?? '' }} />;
}
`),
    ignores: f('app/welcome/page.tsx', `'use client';
import { useSearchParams } from 'next/navigation';
export default function Welcome() {
  const searchParams = useSearchParams();
  return <div>{searchParams.get('msg') ?? ''}</div>;
}
`),
  },
  {
    ruleIds: [28911], name: 'JSF-11 trust proxy true',
    detects: f('src/server.ts', `import express from 'express';
import rateLimit from 'express-rate-limit';
const app = express();
app.set('trust proxy', true);
app.use(rateLimit({ windowMs: 60_000, limit: 100 }));
`),
    ignores: f('src/server.ts', `import express from 'express';
import rateLimit from 'express-rate-limit';
const app = express();
app.set('trust proxy', 1);
app.use(rateLimit({ windowMs: 60_000, limit: 100 }));
`),
  },
  {
    ruleIds: [28912], name: 'JSF-12 vite define process.env',
    detects: f('vite.config.ts', `import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({
  plugins: [react()],
  define: {
    'process.env': process.env,
  },
});
`),
    ignores: f('vite.config.ts', `import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version),
  },
});
`),
  },
  {
    ruleIds: [28912], name: 'JSF-12 Remix root loader returns process.env',
    detects: f('app/root.tsx', `import { json } from '@remix-run/node';
export async function loader() {
  return json({ ENV: process.env });
}
`),
    ignores: f('app/root.tsx', `import { json } from '@remix-run/node';
export async function loader() {
  return json({ ENV: { STRIPE_PUBLISHABLE_KEY: process.env.STRIPE_PUBLISHABLE_KEY } });
}
`),
  },
  {
    ruleIds: [28913], name: 'JSF-13 VITE_ secret',
    detects: f('src/lib/stripe.ts', `import Stripe from 'stripe';
export const stripe = new Stripe(import.meta.env.VITE_STRIPE_SECRET_KEY);
`),
    ignores: f('src/lib/stripe.ts', `import { loadStripe } from '@stripe/stripe-js';
export const stripePromise = loadStripe(import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY);
`),
  },
  {
    ruleIds: [28914], name: 'JSF-14 Nuxt public runtimeConfig secret',
    detects: f('nuxt.config.ts', `export default defineNuxtConfig({
  runtimeConfig: {
    public: {
      apiBase: '/api',
      stripeSecretKey: process.env.STRIPE_SECRET_KEY,
    },
  },
});
`),
    ignores: f('nuxt.config.ts', `export default defineNuxtConfig({
  runtimeConfig: {
    stripeSecretKey: process.env.STRIPE_SECRET_KEY,
    public: {
      apiBase: '/api',
    },
  },
});
`),
  },
  {
    ruleIds: [28915], name: 'JSF-15 SvelteKit csrf checkOrigin false',
    detects: f('svelte.config.js', `import adapter from '@sveltejs/adapter-node';
const config = {
  kit: {
    adapter: adapter(),
    csrf: { checkOrigin: false },
  },
};
export default config;
`),
    ignores: f('svelte.config.js', `import adapter from '@sveltejs/adapter-node';
const config = {
  kit: {
    adapter: adapter(),
  },
};
export default config;
`),
  },
  {
    ruleIds: [28916], name: 'JSF-16 Auth.js redirect callback returns url',
    detects: f('auth.ts', `import NextAuth from 'next-auth';
import GitHub from 'next-auth/providers/github';
export const { handlers, auth } = NextAuth({
  providers: [GitHub],
  callbacks: {
    async redirect({ url, baseUrl }) {
      return url;
    },
  },
});
`),
    ignores: f('auth.ts', `import NextAuth from 'next-auth';
import GitHub from 'next-auth/providers/github';
export const { handlers, auth } = NextAuth({
  providers: [GitHub],
  callbacks: {
    async redirect({ url, baseUrl }) {
      if (url.startsWith('/')) return \`\${baseUrl}\${url}\`;
      return new URL(url).origin === baseUrl ? url : baseUrl;
    },
  },
});
`),
  },
  {
    ruleIds: [28917], name: 'JSF-17 ignoreExpiration',
    detects: f('src/middleware/auth.ts', `import jwt from 'jsonwebtoken';
export function readUser(token: string) {
  return jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'], ignoreExpiration: true });
}
`),
    ignores: f('src/middleware/auth.ts', `import jwt from 'jsonwebtoken';
export function readUser(token: string) {
  return jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] });
}
`),
  },
  {
    ruleIds: [28918], name: 'JSF-18 nunjucks autoescape false',
    detects: f('src/app.ts', `import express from 'express';
import nunjucks from 'nunjucks';
const app = express();
nunjucks.configure('views', { autoescape: false, express: app });
app.get('/', (req, res) => res.render('index.njk', { q: req.query.q }));
`),
    ignores: f('src/app.ts', `import express from 'express';
import nunjucks from 'nunjucks';
const app = express();
nunjucks.configure('views', { autoescape: true, express: app });
app.get('/', (req, res) => res.render('index.njk', { q: req.query.q }));
`),
  },
  {
    ruleIds: [28919], name: 'JSF-19 recursive merge without proto guard',
    detects: f('src/utils/merge.ts', `export function deepMerge(target: any, source: any) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
`),
    ignores: f('src/utils/merge.ts', `export function deepMerge(target: any, source: any) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
`),
  },
  {
    ruleIds: [28920], name: 'JSF-20 server action delete without auth',
    detects: f('app/dashboard/actions.ts', `'use server';
import { prisma } from '@/lib/db';
import { revalidatePath } from 'next/cache';
export async function deleteProject(projectId: string) {
  await prisma.project.delete({ where: { id: projectId } });
  revalidatePath('/dashboard');
}
`),
    ignores: f('app/dashboard/actions.ts', `'use server';
import { prisma } from '@/lib/db';
import { auth } from '@/auth';
import { revalidatePath } from 'next/cache';
export async function deleteProject(projectId: string) {
  const session = await auth();
  if (!session?.user) throw new Error('Unauthorized');
  await prisma.project.delete({ where: { id: projectId, ownerId: session.user.id } });
  revalidatePath('/dashboard');
}
`),
  },
  {
    ruleIds: [28921], name: 'JSF-21 draft mode without secret',
    detects: f('app/api/draft/route.ts', `import { draftMode } from 'next/headers';
import { redirect } from 'next/navigation';
export async function GET(request: Request) {
  const slug = new URL(request.url).searchParams.get('slug') ?? '';
  (await draftMode()).enable();
  redirect('/posts/' + encodeURIComponent(slug));
}
`),
    ignores: f('app/api/draft/route.ts', `import { draftMode } from 'next/headers';
import { redirect } from 'next/navigation';
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  if (searchParams.get('secret') !== process.env.DRAFT_SECRET) return new Response('Invalid token', { status: 401 });
  (await draftMode()).enable();
  redirect('/posts/' + encodeURIComponent(searchParams.get('slug') ?? ''));
}
`),
  },
  {
    ruleIds: [28922], name: 'JSF-22 SSR state in inline script',
    detects: f('src/render.ts', `export function page(html: string, state: unknown) {
  return \`<!doctype html><div id="root">\${html}</div><script>window.__STATE__ = \${JSON.stringify(state)}</script>\`;
}
`),
    ignores: f('src/render.ts', `export function page(html: string, state: unknown) {
  return \`<!doctype html><div id="root">\${html}</div><script>window.__STATE__ = \${JSON.stringify(state).replace(/</g, '\\\\u003c')}</script>\`;
}
`),
  },
  {
    ruleIds: [28923], name: 'JSF-23 NestJS enableCors origin true with credentials',
    detects: f('src/main.ts', `import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({ origin: true, credentials: true });
  await app.listen(3000);
}
bootstrap();
`),
    ignores: f('src/main.ts', `import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({ origin: ['https://app.example.com'], credentials: true });
  await app.listen(3000);
}
bootstrap();
`),
  },
  {
    ruleIds: [28924], name: 'JSF-24 CORS origin endsWith without dot',
    detects: f('src/cors.ts', `import cors from 'cors';
export const corsMiddleware = cors({
  credentials: true,
  origin(origin, callback) {
    if (!origin || origin.endsWith('example.com')) return callback(null, true);
    callback(new Error('Not allowed'));
  },
});
`),
    ignores: f('src/cors.ts', `import cors from 'cors';
const ALLOWED = new Set(['https://example.com', 'https://app.example.com']);
export const corsMiddleware = cors({
  credentials: true,
  origin(origin, callback) {
    if (!origin || ALLOWED.has(origin)) return callback(null, true);
    callback(new Error('Not allowed'));
  },
});
`),
  },
  {
    ruleIds: [28924], name: 'JSF-24 unanchored CORS regex',
    detects: f('src/app.ts', `import cors from 'cors';
app.use(cors({ origin: [/example\\.com/], credentials: true }));
`),
    ignores: f('src/app.ts', `import cors from 'cors';
app.use(cors({ origin: [/^https:\\/\\/([a-z0-9-]+\\.)?example\\.com$/], credentials: true }));
`),
  },
  {
    ruleIds: [28925], name: 'JSF-25 hardcoded fastify jwt secret',
    detects: f('src/plugins/auth.ts', lit(`import fastifyJwt from '@fastify/jwt';
export default async function auth(fastify) {
  fastify.register(fastifyJwt, { secret: '`, 'super', 'secret', 'value', `' });
}
`)),
    ignores: f('src/plugins/auth.ts', `import fastifyJwt from '@fastify/jwt';
export default async function auth(fastify) {
  fastify.register(fastifyJwt, { secret: process.env.JWT_SECRET! });
}
`),
  },
  {
    ruleIds: [28926], name: 'JSF-26 middleware trusts decodeJwt',
    detects: f('middleware.ts', `import { decodeJwt } from 'jose';
import { NextResponse, type NextRequest } from 'next/server';
export function middleware(request: NextRequest) {
  const token = request.cookies.get('token')?.value;
  const claims = token ? decodeJwt(token) : null;
  if (claims?.role !== 'admin') return NextResponse.redirect(new URL('/login', request.url));
  return NextResponse.next();
}
`),
    ignores: f('middleware.ts', `import { jwtVerify } from 'jose';
import { NextResponse, type NextRequest } from 'next/server';
const key = new TextEncoder().encode(process.env.JWT_SECRET);
export async function middleware(request: NextRequest) {
  const token = request.cookies.get('token')?.value;
  const claims = token ? (await jwtVerify(token, key)).payload : null;
  if (claims?.role !== 'admin') return NextResponse.redirect(new URL('/login', request.url));
  return NextResponse.next();
}
`),
  },
  {
    ruleIds: [28927], name: 'JSF-27 Apollo csrfPrevention false',
    detects: f('src/server.ts', `import { ApolloServer } from '@apollo/server';
export const server = new ApolloServer({ typeDefs, resolvers, csrfPrevention: false });
`),
    ignores: f('src/server.ts', `import { ApolloServer } from '@apollo/server';
export const server = new ApolloServer({ typeDefs, resolvers });
`),
  },
  {
    ruleIds: [28928], name: 'JSF-28 TypeORM orderBy from query',
    detects: f('src/users.controller.ts', `import { DataSource } from 'typeorm';
app.get('/users', async (req, res) => {
  const users = await dataSource.getRepository(User).createQueryBuilder('user').orderBy(\`user.\${req.query.sort}\`).getMany();
  res.json(users);
});
`),
    ignores: f('src/users.controller.ts', `import { DataSource } from 'typeorm';
const SORTS: Record<string, string> = { name: 'user.name', created: 'user.createdAt' };
app.get('/users', async (req, res) => {
  const users = await dataSource.getRepository(User).createQueryBuilder('user').orderBy(SORTS[String(req.query.sort)] ?? 'user.id').getMany();
  res.json(users);
});
`),
  },
  {
    ruleIds: [28929, 28930], name: 'JSF-29/30 Electron insecure webPreferences',
    detects: f('src/main/index.ts', `import { app, BrowserWindow } from 'electron';
app.whenReady().then(() => {
  const win = new BrowserWindow({
    webPreferences: { nodeIntegration: true, contextIsolation: false, webSecurity: false },
  });
  win.loadURL('https://app.example.com');
});
`),
    ignores: f('src/main/index.ts', `import { app, BrowserWindow } from 'electron';
import path from 'node:path';
app.whenReady().then(() => {
  const win = new BrowserWindow({
    webPreferences: { preload: path.join(__dirname, 'preload.js'), sandbox: true },
  });
  win.loadURL('https://app.example.com');
});
`),
  },
  {
    ruleIds: [28931], name: 'JSF-31 NODE_TLS_REJECT_UNAUTHORIZED',
    detects: f('src/lib/http.ts', `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
export const api = (path: string) => fetch(\`https://billing.internal\${path}\`);
`),
    ignores: f('src/lib/http.ts', `export const api = (path: string) => fetch(\`https://billing.internal\${path}\`);
`),
  },
  {
    ruleIds: [28932], name: 'JSF-32 chmod 777',
    detects: f('src/storage.ts', `import fs from 'node:fs';
fs.mkdirSync('/var/app/uploads', { recursive: true });
fs.chmodSync('/var/app/uploads', 0o777);
`),
    ignores: f('src/storage.ts', `import fs from 'node:fs';
fs.mkdirSync('/var/app/uploads', { recursive: true });
fs.chmodSync('/var/app/uploads', 0o750);
`),
  },
  {
    ruleIds: [28933], name: 'JSF-33 srcdoc iframe with scripts and same-origin',
    detects: f('src/components/Preview.tsx', `export function Preview({ html }: { html: string }) {
  return <iframe title="preview" sandbox="allow-scripts allow-same-origin" srcDoc={html} />;
}
`),
    ignores: f('src/components/Preview.tsx', `export function Preview({ html }: { html: string }) {
  return <iframe title="preview" sandbox="allow-scripts" srcDoc={html} />;
}
`),
  },
  {
    ruleIds: [28934], name: 'JSF-34 CSP unsafe-inline without nonce',
    detects: f('next.config.js', `module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-inline'" }] }];
  },
};
`),
    ignores: f('next.config.js', `module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'" }] }];
  },
};
`),
  },
  {
    ruleIds: [28935], name: 'JSF-35 unawaited bcrypt.compare',
    detects: f('src/auth/login.ts', `import bcrypt from 'bcrypt';
export async function login(email: string, password: string) {
  const user = await db.user.findUnique({ where: { email } });
  if (!user || !bcrypt.compare(password, user.passwordHash)) throw new Error('Invalid credentials');
  return createSession(user.id);
}
`),
    ignores: f('src/auth/login.ts', `import bcrypt from 'bcrypt';
export async function login(email: string, password: string) {
  const user = await db.user.findUnique({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) throw new Error('Invalid credentials');
  return createSession(user.id);
}
`),
  },
  {
    ruleIds: [28936], name: 'JSF-36 token in document.cookie',
    detects: f('src/lib/session.ts', `export function saveSession(token: string) {
  document.cookie = \`access_token=\${token}; path=/; max-age=86400\`;
}
`),
    ignores: f('src/lib/session.ts', `export async function saveSession(token: string) {
  await fetch('/api/session', { method: 'POST', body: JSON.stringify({ token }) });
}
`),
  },
  {
    ruleIds: [28937], name: 'JSF-37 Socket.IO userId from handshake',
    detects: f('src/realtime.ts', `io.on('connection', (socket) => {
  const userId = socket.handshake.auth.userId;
  socket.join(\`user:\${userId}\`);
});
`),
    ignores: f('src/realtime.ts', `import jwt from 'jsonwebtoken';
io.on('connection', (socket) => {
  const { sub: userId } = jwt.verify(socket.handshake.auth.token, process.env.JWT_SECRET!) as { sub: string };
  socket.join(\`user:\${userId}\`);
});
`),
  },
  {
    ruleIds: [28938], name: 'JSF-38 user parsed from plain cookie',
    detects: f('src/hooks.server.ts', `export const handle = async ({ event, resolve }) => {
  const raw = event.cookies.get('user');
  event.locals.user = raw ? JSON.parse(event.cookies.get('user')!) : null;
  return resolve(event);
};
`),
    ignores: f('src/hooks.server.ts', `export const handle = async ({ event, resolve }) => {
  const sessionId = event.cookies.get('session_id');
  event.locals.user = sessionId ? await getUserBySession(sessionId) : null;
  return resolve(event);
};
`),
  },
];
