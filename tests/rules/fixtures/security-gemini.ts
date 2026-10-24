import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29900], name: 'SECG-01 Go upload saved under the client file name',
    detects: f('handlers/upload.go', `package handlers

import "github.com/gin-gonic/gin"

func Upload(c *gin.Context) {
	file, _ := c.FormFile("file")
	c.SaveUploadedFile(file, "./uploads/"+file.Filename)
}
`),
    ignores: f('handlers/upload.go', `package handlers

import (
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func Upload(c *gin.Context) {
	file, _ := c.FormFile("file")
	c.SaveUploadedFile(file, filepath.Join("./uploads", uuid.NewString()+filepath.Ext(filepath.Base(file.Filename))))
}
`),
  },
  {
    ruleIds: [29901], name: 'SECG-02 Go FileServer on the working directory',
    detects: f('main.go', `package main

import "net/http"

func main() {
	http.Handle("/", http.FileServer(http.Dir(".")))
	http.ListenAndServe(":8080", nil)
}
`),
    ignores: f('main.go', `package main

import "net/http"

func main() {
	http.Handle("/", http.FileServer(http.Dir("./public")))
	http.ListenAndServe(":8080", nil)
}
`),
  },
  {
    ruleIds: [29902], name: "SECG-03 express.static with dotfiles: 'allow'",
    detects: f('server/app.js', `const express = require('express');
const app = express();
app.use(express.static('public', { dotfiles: 'allow' }));
`),
    ignores: f('server/app.js', `const express = require('express');
const path = require('path');
const app = express();
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'deny' }));
`),
  },
  {
    ruleIds: [29903], name: 'SECG-04 qs allowPrototypes',
    detects: f('server/query.ts', `import qs from 'qs';
export const parseQuery = (raw: string) => qs.parse(raw, { allowPrototypes: true });
`),
    ignores: f('server/query.ts', `import qs from 'qs';
export const parseQuery = (raw: string) => qs.parse(raw, { depth: 2 });
`),
  },
  {
    ruleIds: [29905], name: 'SECG-06 PyJWT algorithm confusion',
    detects: f('app/auth.py', `import jwt

def verify(token: str, key: str):
    return jwt.decode(token, key, algorithms=["RS256", "HS256"])
`),
    ignores: f('app/auth.py', `import jwt

def verify(token: str, key: str):
    return jwt.decode(token, key, algorithms=["RS256"])
`),
  },
  {
    ruleIds: [29906], name: 'SECG-07 NestJS ValidationPipe without whitelist',
    detects: f('src/main.ts', `import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({ transform: true }));
  await app.listen(3000);
}
bootstrap();
`),
    ignores: f('src/main.ts', `import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
  await app.listen(3000);
}
bootstrap();
`),
  },
  {
    ruleIds: [29907], name: 'SECG-08 SAML signature checks disabled',
    detects: f('server/sso.ts', `import { SAML } from '@node-saml/node-saml';
export const saml = new SAML({
  callbackUrl: 'https://app.example.com/sso/callback',
  entryPoint: process.env.SAML_ENTRY!,
  issuer: 'app',
  idpCert: process.env.SAML_CERT!,
  wantAssertionsSigned: false,
});
`),
    ignores: f('server/sso.ts', `import { SAML } from '@node-saml/node-saml';
export const saml = new SAML({
  callbackUrl: 'https://app.example.com/sso/callback',
  entryPoint: process.env.SAML_ENTRY!,
  issuer: 'app',
  idpCert: process.env.SAML_CERT!,
  wantAssertionsSigned: true,
  wantAuthnResponseSigned: true,
});
`),
  },
  {
    ruleIds: [29908], name: 'SECG-09 Spring actuator exposes everything',
    detects: f('src/main/resources/application.properties', `server.port=8080
management.endpoints.web.exposure.include=*
`),
    ignores: f('src/main/resources/application.properties', `server.port=8080
management.endpoints.web.exposure.include=health,info
`),
  },
  {
    ruleIds: [29909], name: 'SECG-10 ASP.NET CORS any origin with credentials',
    detects: f('Program.cs', `var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.SetIsOriginAllowed(_ => true).AllowAnyHeader().AllowCredentials()));
var app = builder.Build();
app.UseCors();
app.Run();
`),
    ignores: f('Program.cs', `var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.WithOrigins("https://app.example.com").AllowAnyHeader().AllowCredentials()));
var app = builder.Build();
app.UseCors();
app.Run();
`),
  },
  {
    ruleIds: [29910], name: 'SECG-11 authenticated response cached publicly',
    detects: f('app/api/me/route.ts', `import { auth } from '@/auth';
export async function GET() {
  const session = await auth();
  return Response.json({ email: session?.user?.email }, { headers: { 'Cache-Control': 'public, s-maxage=600' } });
}
`),
    ignores: f('app/api/me/route.ts', `import { auth } from '@/auth';
export async function GET() {
  const session = await auth();
  return Response.json({ email: session?.user?.email }, { headers: { 'Cache-Control': 'private, no-store' } });
}
`),
  },
  {
    ruleIds: [29911], name: 'SECG-12 SQLAlchemy text() fragment from an f-string',
    detects: f('app/repo.py', `from sqlalchemy import text

def search(session, Item, sort: str):
    return session.query(Item).order_by(text(f"{sort} desc")).all()
`),
    ignores: f('app/repo.py', `from sqlalchemy import text

SORTS = {"name": Item.name, "date": Item.created_at}

def search(session, Item, name: str):
    return session.query(Item).filter(text("name = :name").bindparams(name=name)).all()
`),
  },
  {
    ruleIds: [29912], name: 'SECG-13 getPublicUrl on a private bucket',
    detects: f('lib/invoices.ts', `import { supabase } from './supabase';
export const invoiceLink = (path: string) => supabase.storage.from('invoices').getPublicUrl(path).data.publicUrl;
`),
    ignores: f('lib/invoices.ts', `import { supabase } from './supabase';
export const invoiceLink = (path: string) => supabase.storage.from('invoices').createSignedUrl(path, 60);
export const avatarLink = (path: string) => supabase.storage.from('avatars').getPublicUrl(path).data.publicUrl;
`),
  },
  {
    ruleIds: [29913], name: 'SECG-14 JWT kid used as a file path',
    detects: f('server/jwt.ts', `import fs from 'fs';
import jwt from 'jsonwebtoken';
export function verify(token: string) {
  const decoded = jwt.decode(token, { complete: true })!;
  const key = fs.readFileSync('./keys/' + decoded.header.kid);
  return jwt.verify(token, key);
}
`),
    ignores: f('server/jwt.ts', `import jwt from 'jsonwebtoken';
const KEYS: Record<string, string> = { main: process.env.JWT_PUBLIC_KEY! };
export function verify(token: string) {
  const decoded = jwt.decode(token, { complete: true })!;
  const key = KEYS[decoded.header.kid ?? ''];
  if (!key) throw new Error('unknown key');
  return jwt.verify(token, key, { algorithms: ['RS256'] });
}
`),
  },
  {
    ruleIds: [29914], name: 'SECG-15 invite token matched with ilike',
    detects: f('lib/invites.ts', `import { supabase } from './supabase';
export const findInvite = (token: string) => supabase.from('invites').select('*').ilike('token', token).single();
`),
    ignores: f('lib/invites.ts', `import { supabase } from './supabase';
export const findInvite = (token: string) => supabase.from('invites').select('*').eq('token', token).single();
export const searchUsers = (q: string) => supabase.from('users').select('*').ilike('name', \`%\${q}%\`);
`),
  },
  {
    ruleIds: [29916], name: 'SECG-17 JWT signed without an expiry',
    detects: f('server/token.ts', `import jwt from 'jsonwebtoken';
export const issue = (userId: string) => jwt.sign({ sub: userId }, process.env.JWT_SECRET!);
`),
    ignores: f('server/token.ts', `import jwt from 'jsonwebtoken';
export const issue = (userId: string) => jwt.sign({ sub: userId }, process.env.JWT_SECRET!, { expiresIn: '15m' });
`),
  },
  {
    ruleIds: [29917], name: 'SECG-18 request input as a git argument',
    detects: f('server/clone.ts', `import { spawn } from 'child_process';
export function clone(req: { body: { repo: string } }) {
  return spawn('git', ['clone', req.body.repo, '/tmp/work']);
}
`),
    ignores: f('server/clone.ts', `import { spawn } from 'child_process';
export function clone(req: { body: { repo: string } }) {
  if (!/^https:\\/\\/github\\.com\\/[\\w.-]+\\/[\\w.-]+$/.test(req.body.repo)) throw new Error('bad repo');
  return spawn('git', ['clone', '--', req.body.repo, '/tmp/work']);
}
`),
  },
  {
    ruleIds: [29918], name: 'SECG-19 reqwest with TLS checks off',
    detects: f('src/client.rs', `pub fn client() -> reqwest::Client {
    reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap()
}
`),
    ignores: f('src/client.rs', `pub fn client(ca: reqwest::Certificate) -> reqwest::Client {
    reqwest::Client::builder().add_root_certificate(ca).build().unwrap()
}
`),
  },
  {
    ruleIds: [29919], name: 'SECG-20 Python secret with a literal fallback',
    detects: f('app/config.py', `import os
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
`),
    ignores: f('app/config.py', `import os
SECRET_KEY = os.environ["SECRET_KEY"]
DEBUG = os.environ.get("DEBUG", "false") == "true"
`),
  },
  {
    ruleIds: [29920], name: 'SECG-21 Ruby open on params',
    detects: f('app/controllers/files_controller.rb', `class FilesController < ApplicationController
  def show
    data = open(params[:path]).read
    render plain: data
  end
end
`),
    ignores: f('app/controllers/files_controller.rb', `class FilesController < ApplicationController
  def show
    name = File.basename(params[:path].to_s)
    render plain: File.read(Rails.root.join("public", "docs", name))
  end
end
`),
  },
  {
    ruleIds: [29921], name: 'SECG-22 signedCookies without a cookie secret',
    detects: f('server/app.js', `const express = require('express');
const cookieParser = require('cookie-parser');
const app = express();
app.use(cookieParser());
app.get('/me', (req, res) => res.json({ id: req.signedCookies.uid }));
`),
    ignores: f('server/app.js', `const express = require('express');
const cookieParser = require('cookie-parser');
const app = express();
app.use(cookieParser(process.env.COOKIE_SECRET));
app.get('/me', (req, res) => res.json({ id: req.signedCookies.uid }));
`),
  },
  {
    ruleIds: [29922], name: 'SECG-23 serve-index directory listing',
    detects: f('server/app.js', `const express = require('express');
const serveIndex = require('serve-index');
const app = express();
app.use('/files', express.static('uploads'), serveIndex('uploads'));
`),
    ignores: f('server/app.js', `const express = require('express');
const app = express();
app.use('/files', express.static('uploads', { index: false }));
`),
  },
  {
    ruleIds: [29923], name: 'SECG-24 Content-Type taken from the query',
    detects: f('app/api/file/route.ts', `import { getFile } from '@/lib/storage';
export async function GET(req: Request) {
  const url = new URL(req.url);
  const body = await getFile(url.searchParams.get('id')!);
  return new Response(body, { headers: { 'Content-Type': url.searchParams.get('type') ?? 'text/plain' } });
}
`),
    ignores: f('app/api/file/route.ts', `import { getFile } from '@/lib/storage';
export async function GET(req: Request) {
  const url = new URL(req.url);
  const file = await getFile(url.searchParams.get('id')!);
  return new Response(file.body, { headers: { 'Content-Type': file.mime, 'X-Content-Type-Options': 'nosniff' } });
}
`),
  },
  {
    ruleIds: [29924], name: 'SECG-25 admin gate from localStorage',
    detects: f('src/components/AdminLink.tsx', `export function AdminLink() {
  if (localStorage.getItem('role') === 'admin') return <a href="/admin">Admin</a>;
  return null;
}
`),
    ignores: f('src/components/AdminLink.tsx', `export function AdminLink({ isAdmin }: { isAdmin: boolean }) {
  const label = localStorage.getItem('role');
  if (isAdmin) return <a href="/admin">Admin ({label})</a>;
  return null;
}
`),
  },
  {
    ruleIds: [29925], name: 'SECG-26 Stripe success_url from the request body',
    detects: f('app/api/checkout/route.ts', `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const body = await req.json();
  const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: [{ price: process.env.PRICE_ID, quantity: 1 }], success_url: body.successUrl, cancel_url: body.cancelUrl });
  return Response.json({ url: session.url });
}
`),
    ignores: f('app/api/checkout/route.ts', `import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
const APP = process.env.NEXT_PUBLIC_APP_URL!;
export async function POST(req: Request) {
  const body = await req.json();
  const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: [{ price: process.env.PRICE_ID, quantity: 1 }], success_url: APP + '/thanks', cancel_url: APP + '/pricing' });
  return Response.json({ url: session.url });
}
`),
  },
  {
    ruleIds: [29926], name: 'SECG-27 access token in the URL',
    detects: f('lib/export.ts', `import { supabase } from './supabase';
export async function exportUrl() {
  const { data: { session } } = await supabase.auth.getSession();
  return \`/api/export?access_token=\${session?.access_token}\`;
}
`),
    ignores: f('lib/export.ts', `import { supabase } from './supabase';
export async function exportCsv() {
  const { data: { session } } = await supabase.auth.getSession();
  return fetch('/api/export', { headers: { Authorization: \`Bearer \${session?.access_token}\` } });
}
`),
  },
  {
    ruleIds: [29927], name: 'SECG-28 MCP HTTP transport without DNS-rebinding protection',
    detects: f('server/mcp.ts', `import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
export const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
`),
    ignores: f('server/mcp.ts', `import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
export const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableDnsRebindingProtection: true, allowedHosts: ['127.0.0.1'] });
`),
  },
  {
    ruleIds: [29928], name: 'SECG-29 LLM decides authorization',
    detects: f('lib/authz.ts', `import { generateObject } from 'ai';
import { z } from 'zod';
export async function canRead(model: any, user: string, doc: string) {
  const { object } = await generateObject({ model, schema: z.object({ isAuthorized: z.boolean() }), prompt: user + doc });
  return object.isAuthorized;
}
`),
    ignores: f('lib/authz.ts', `import { generateObject } from 'ai';
import { z } from 'zod';
export async function classify(model: any, doc: string) {
  const { object } = await generateObject({ model, schema: z.object({ isSpam: z.boolean() }), prompt: doc });
  return object.isSpam;
}
`),
  },
  {
    ruleIds: [29929], name: 'SECG-30 read-only SQL by SELECT prefix',
    detects: f('lib/sql-tool.ts', `import { prisma } from './db';
export async function runSql(sql: string) {
  if (!sql.trim().toUpperCase().startsWith('SELECT')) throw new Error('read only');
  return prisma.$queryRawUnsafe(sql);
}
`),
    ignores: f('lib/sql-tool.ts', `import { readonlyPool } from './db';
export async function runSql(sql: string) {
  const client = await readonlyPool.connect();
  try { await client.query('SET TRANSACTION READ ONLY'); return await client.query(sql); } finally { client.release(); }
}
`),
  },
  {
    ruleIds: [29930], name: 'SECG-31 tool returns the whole environment',
    detects: f('lib/tools.ts', `import { tool } from 'ai';
import { z } from 'zod';
export const debug = tool({ description: 'debug info', parameters: z.object({}), execute: async () => process.env });
`),
    ignores: f('lib/tools.ts', `import { tool } from 'ai';
import { z } from 'zod';
export const debug = tool({ description: 'debug info', parameters: z.object({}), execute: async () => ({ region: process.env.VERCEL_REGION }) });
`),
  },
  {
    ruleIds: [29931], name: 'SECG-32 thinking budget from the request',
    detects: f('app/api/think/route.ts', `import Anthropic from '@anthropic-ai/sdk';
const a = new Anthropic();
export async function POST(req: Request) {
  const body = await req.json();
  const msg = await a.messages.create({ model: 'claude-opus-5-5', max_tokens: 32000, thinking: { type: 'enabled', budget_tokens: body.budget }, messages: [{ role: 'user', content: body.q }] });
  return Response.json({ text: msg.content });
}
`),
    ignores: f('app/api/think/route.ts', `import Anthropic from '@anthropic-ai/sdk';
const a = new Anthropic();
export async function POST(req: Request) {
  const body = await req.json();
  const msg = await a.messages.create({ model: 'claude-opus-5-5', max_tokens: 8000, thinking: { type: 'enabled', budget_tokens: 4000 }, messages: [{ role: 'user', content: body.q }] });
  return Response.json({ text: msg.content });
}
`),
  },
  {
    ruleIds: [29932], name: 'SECG-33 prompt template from user input',
    detects: f('lib/prompt.ts', `import { PromptTemplate } from '@langchain/core/prompts';
export const build = (body: { template: string }) => PromptTemplate.fromTemplate(body.template);
`),
    ignores: f('lib/prompt.ts', `import { PromptTemplate } from '@langchain/core/prompts';
const tpl = PromptTemplate.fromTemplate('Answer briefly: {question}');
export const build = (body: { question: string }) => tpl.format({ question: body.question });
`),
  },
  {
    ruleIds: [29933], name: 'SECG-34 LLM retry loop without a limit',
    detects: f('lib/fix.ts', `import { generateText } from 'ai';
export async function fix(model: any, code: string, check: (s: string) => boolean) {
  let ok = false; let out = code;
  while (!ok) {
    out = (await generateText({ model, prompt: out })).text;
    ok = check(out);
  }
  return out;
}
`),
    ignores: f('lib/fix.ts', `import { generateText } from 'ai';
export async function fix(model: any, code: string, check: (s: string) => boolean) {
  let out = code;
  for (let attempt = 0; attempt < 3; attempt++) {
    out = (await generateText({ model, prompt: out })).text;
    if (check(out)) return out;
  }
  throw new Error('could not fix');
}
`),
  },
  {
    ruleIds: [29934], name: 'SECG-35 tool sends the API key to a model-chosen URL',
    detects: f('lib/tools.ts', `import { tool } from 'ai';
import { z } from 'zod';
export const callApi = tool({
  description: 'call the API',
  parameters: z.object({ url: z.string() }),
  execute: async (args) => (await fetch(args.url, { headers: { Authorization: \`Bearer \${process.env.API_KEY}\` } })).json(),
});
`),
    ignores: f('lib/tools.ts', `import { tool } from 'ai';
import { z } from 'zod';
const BASE = 'https://api.example.com';
export const callApi = tool({
  description: 'call the API',
  parameters: z.object({ path: z.string() }),
  execute: async (args) => {
    const url = new URL(args.path, BASE);
    if (url.origin !== BASE) throw new Error('bad host');
    return (await fetch(url, { headers: { Authorization: \`Bearer \${process.env.API_KEY}\` } })).json();
  },
});
`),
  },
  {
    ruleIds: [29936], name: 'SECG-37 tool writes a model-chosen path',
    detects: f('lib/tools.ts', `import { tool } from 'ai';
import fs from 'fs/promises';
import { z } from 'zod';
export const write = tool({ description: 'write a file', parameters: z.object({ path: z.string(), content: z.string() }), execute: async (args) => fs.writeFile(args.path, args.content) });
`),
    ignores: f('lib/tools.ts', `import { tool } from 'ai';
import fs from 'fs/promises';
import path from 'path';
import { z } from 'zod';
const ROOT = path.resolve('workspace');
export const write = tool({ description: 'write a file', parameters: z.object({ path: z.string(), content: z.string() }), execute: async (args) => {
  const p = path.resolve(ROOT, args.path);
  if (!p.startsWith(ROOT + path.sep)) throw new Error('outside workspace');
  return fs.writeFile(p, args.content);
} });
`),
  },
  {
    ruleIds: [29938], name: 'SECG-39 full generateText result sent to the client',
    detects: f('app/api/ask/route.ts', `import { generateText } from 'ai';
import { openai } from '@ai-sdk/openai';
export async function POST(req: Request) {
  const { prompt } = await req.json();
  const result = await generateText({ model: openai('gpt-4o'), system: 'internal rules', prompt });
  return Response.json(result);
}
`),
    ignores: f('app/api/ask/route.ts', `import { generateText } from 'ai';
import { openai } from '@ai-sdk/openai';
export async function POST(req: Request) {
  const { prompt } = await req.json();
  const result = await generateText({ model: openai('gpt-4o'), system: 'internal rules', prompt });
  return Response.json({ text: result.text });
}
`),
  },
  {
    ruleIds: [29939], name: 'SECG-40 browser tool evaluates model script',
    detects: f('lib/browser-tool.ts', `import { tool } from 'ai';
import { z } from 'zod';
declare const page: { evaluate(s: string): Promise<unknown> };
export const js = tool({ description: 'run js in the page', parameters: z.object({ script: z.string() }), execute: async (args) => page.evaluate(args.script) });
`),
    ignores: f('lib/browser-tool.ts', `import { tool } from 'ai';
import { z } from 'zod';
declare const page: { evaluate(f: () => string): Promise<unknown> };
export const readTitle = tool({ description: 'read the page title', parameters: z.object({}), execute: async () => page.evaluate(() => document.title) });
`),
  },
  {
    ruleIds: [29940], name: 'SECG-41 MCP client URL from the request',
    detects: f('app/api/mcp/route.ts', `import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
export async function POST(req: Request) {
  const body = await req.json();
  const transport = new StreamableHTTPClientTransport(new URL(body.serverUrl));
  await new Client({ name: 'app', version: '1.0.0' }).connect(transport);
  return Response.json({ ok: true });
}
`),
    ignores: f('app/api/mcp/route.ts', `import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
const SERVERS: Record<string, string> = { docs: 'https://mcp.example.com/docs' };
export async function POST(req: Request) {
  const body = await req.json();
  const transport = new StreamableHTTPClientTransport(new URL(SERVERS[body.server] ?? SERVERS.docs));
  await new Client({ name: 'app', version: '1.0.0' }).connect(transport);
  return Response.json({ ok: true });
}
`),
  },
  {
    ruleIds: [29942], name: 'SECG-43 LangServe routes without auth',
    detects: f('app/server.py', `from fastapi import FastAPI
from langserve import add_routes
from app.chain import chain

app = FastAPI()
add_routes(app, chain, path="/chain")
`),
    ignores: f('app/server.py', `from fastapi import Depends, FastAPI
from langserve import add_routes
from app.chain import chain
from app.auth import verify_token

app = FastAPI()
add_routes(app, chain, path="/chain", dependencies=[Depends(verify_token)])
`),
  },
];
