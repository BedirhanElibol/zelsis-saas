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
];
