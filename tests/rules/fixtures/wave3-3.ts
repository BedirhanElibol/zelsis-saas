import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const src = (...lines: string[]) => lines.join('\n') + '\n';

/** Wave 3-3: builtin header / code-quality rules, cloud-native, frontend, security and infra rules kept after review. */
export const CASES: RuleCase[] = [
  // ─── Live deployment header checks (builtin-rules.ts) ─────────────────
  {
    ruleIds: [102, 103, 104],
    name: 'live site missing HSTS, X-Frame-Options and nosniff',
    detects: f('live-deployment/security-headers.json', JSON.stringify({
      targetUrl: 'https://shop.example.com',
      statusCode: 200,
      missingSecurityHeaders: ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options'],
      headers: { 'content-security-policy': "default-src 'self'" }
    })),
    ignores: f('live-deployment/security-headers.json', JSON.stringify({
      targetUrl: 'https://shop.example.com',
      statusCode: 200,
      missingSecurityHeaders: ['X-Frame-Options'],
      headers: { 'content-security-policy': "default-src 'self'; frame-ancestors 'self'" }
    }))
  },

  // ─── Builtin code-quality rules ───────────────────────────────────────
  {
    ruleIds: [61],
    name: 'RAG ingestion chunks documents with CharacterTextSplitter',
    detects: f('lib/rag/ingest.ts', src(
      "import { CharacterTextSplitter } from 'langchain/text_splitter';",
      '',
      'export async function chunk(text: string) {',
      '  const splitter = new CharacterTextSplitter({ chunkSize: 1000, chunkOverlap: 200 });',
      '  return splitter.splitText(text);',
      '}'
    )),
    ignores: f('lib/rag/ingest.ts', src(
      "import { RecursiveCharacterTextSplitter } from 'langchain/text_splitter';",
      '',
      'export async function chunk(text: string) {',
      '  const splitter = new RecursiveCharacterTextSplitter({ chunkSize: 1000, chunkOverlap: 200 });',
      '  return splitter.splitText(text);',
      '}'
    ))
  },
  {
    ruleIds: [106],
    name: 'empty catch swallows a draft parse failure',
    detects: f('lib/drafts.ts', src(
      'export function readDraft(raw: string | null) {',
      '  try {',
      "    return JSON.parse(raw ?? '');",
      '  } catch (err) {}',
      '  return null;',
      '}'
    )),
    ignores: f('lib/drafts.ts', src(
      'export function readDraft(raw: string | null) {',
      '  try {',
      "    return JSON.parse(raw ?? '');",
      '  } catch {',
      '    // no saved draft yet, or an old format: start from an empty editor',
      '  }',
      '  return null;',
      '}'
    ))
  },
  {
    ruleIds: [111],
    name: 'API client typed with any throughout',
    detects: f('lib/api/orders.ts', src(
      'export async function getOrders(client: any): Promise<any> {',
      "  const res: any = await client.get('/orders');",
      '  const rows = res.data as any;',
      '  return rows.map((row: any) => toOrder(row));',
      '}',
      'function toOrder(row: any): any {',
      '  return { id: row.id, total: row.total };',
      '}'
    )),
    ignores: f('lib/api/orders.ts', src(
      'type OrderRow = { id: string; total: number };',
      'type Client = { get: (url: string) => Promise<{ data: unknown }> };',
      'export async function getOrders(client: Client): Promise<OrderRow[]> {',
      "  const res = await client.get('/orders');",
      '  const rows = res.data as OrderRow[];',
      '  return rows.map((row) => toOrder(row));',
      '}',
      'function toOrder(row: OrderRow): OrderRow {',
      '  return { id: row.id, total: row.total };',
      '}'
    ))
  },
  {
    ruleIds: [117],
    name: 'resize listener registered in an effect without cleanup',
    detects: f('components/hooks/useWindowWidth.ts', src(
      "import { useEffect, useState } from 'react';",
      '',
      'export function useWindowWidth() {',
      '  const [width, setWidth] = useState(0);',
      '  useEffect(() => {',
      '    const onResize = () => setWidth(window.innerWidth);',
      "    window.addEventListener('resize', onResize);",
      '    onResize();',
      '  }, []);',
      '  return width;',
      '}'
    )),
    ignores: f('components/hooks/useWindowWidth.ts', src(
      "import { useEffect, useState } from 'react';",
      '',
      'export function useWindowWidth() {',
      '  const [width, setWidth] = useState(0);',
      '  useEffect(() => {',
      '    const onResize = () => setWidth(window.innerWidth);',
      "    window.addEventListener('resize', onResize);",
      '    onResize();',
      "    return () => window.removeEventListener('resize', onResize);",
      '  }, []);',
      '  return width;',
      '}'
    ))
  },

  // ─── Cloud native (cloud-native-rules.ts) ─────────────────────────────
  {
    ruleIds: [7006],
    name: 'database password baked into the image with ENV',
    detects: f('Dockerfile', src(
      'FROM node:20-alpine',
      'WORKDIR /app',
      'COPY . .',
      'ENV DATABASE_PASSWORD=Pr0dDbPassw0rd2024',
      'RUN npm ci --omit=dev',
      'USER node',
      'CMD ["node", "server.js"]'
    )),
    ignores: f('Dockerfile', src(
      'FROM node:20-alpine',
      'WORKDIR /app',
      'COPY . .',
      'ARG NEXT_PUBLIC_SUPABASE_ANON_KEY=public-anon-key-value',
      'RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci --omit=dev',
      'USER node',
      'CMD ["node", "server.js"]'
    ))
  },
  {
    ruleIds: [7007],
    name: 'single-stage image runs the build and ships the toolchain',
    detects: f('Dockerfile', src(
      'FROM node:20-alpine',
      'WORKDIR /app',
      'COPY . .',
      'RUN npm ci',
      'RUN npm run build',
      'USER node',
      'CMD ["npm", "start"]'
    )),
    ignores: f('Dockerfile', src(
      'FROM node:20-alpine AS deps',
      'WORKDIR /app',
      'COPY . .',
      'RUN npm ci',
      'RUN npm run build',
      'FROM node:20-alpine',
      'WORKDIR /app',
      'COPY --from=deps /app/.next/standalone ./',
      'USER node',
      'CMD ["node", "server.js"]'
    ))
  },
  {
    ruleIds: [7015],
    name: 'S3 client constructed inside the Lambda handler',
    detects: f('src/handlers/upload.ts', src(
      "import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';",
      '',
      'export const handler = async (event: { key: string; body: string }) => {',
      '  const s3 = new S3Client({});',
      '  await s3.send(new PutObjectCommand({ Bucket: process.env.BUCKET, Key: event.key, Body: event.body }));',
      '  return { statusCode: 200 };',
      '};'
    )),
    ignores: f('src/handlers/upload.ts', src(
      "import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';",
      '',
      'const s3 = new S3Client({});',
      '',
      'export const handler = async (event: { key: string; body: string }) => {',
      '  await s3.send(new PutObjectCommand({ Bucket: process.env.BUCKET, Key: event.key, Body: event.body }));',
      '  return { statusCode: 200 };',
      '};'
    ))
  },
  {
    ruleIds: [7029],
    name: 'CloudWatch log group that never expires',
    detects: f('infra/logs.tf', src(
      'resource "aws_cloudwatch_log_group" "api" {',
      '  name = "/aws/lambda/api"',
      '}'
    )),
    ignores: f('infra/logs.tf', src(
      'resource "aws_cloudwatch_log_group" "api" {',
      '  name              = "/aws/lambda/api"',
      '  retention_in_days = 30',
      '}'
    ))
  },
  {
    ruleIds: [7038],
    name: 'ECR repository with mutable image tags',
    detects: f('infra/ecr.tf', src(
      'resource "aws_ecr_repository" "api" {',
      '  name                 = "api"',
      '  image_tag_mutability = "MUTABLE"',
      '  image_scanning_configuration {',
      '    scan_on_push = true',
      '  }',
      '}'
    )),
    ignores: f('infra/ecr.tf', src(
      'resource "aws_ecr_repository" "api" {',
      '  name                 = "api"',
      '  image_tag_mutability = "IMMUTABLE"',
      '  image_scanning_configuration {',
      '    scan_on_push = true',
      '  }',
      '}'
    ))
  },
  {
    ruleIds: [7041],
    name: 'customer managed KMS key with rotation turned off',
    detects: f('infra/kms.tf', src(
      'resource "aws_kms_key" "data" {',
      '  description         = "application data"',
      '  enable_key_rotation = false',
      '}'
    )),
    ignores: f('infra/kms.tf', src(
      'resource "aws_kms_key" "data" {',
      '  description         = "application data"',
      '  enable_key_rotation = true',
      '}'
    ))
  },
  {
    ruleIds: [7049],
    name: 'worker pod mounts its service account token without needing the API',
    detects: f('k8s/worker-pod.yaml', src(
      'apiVersion: v1',
      'kind: Pod',
      'metadata:',
      '  name: worker',
      'spec:',
      '  automountServiceAccountToken: true',
      '  containers:',
      '    - name: worker',
      '      image: ghcr.io/acme/worker:2.3.1'
    )),
    ignores: f('k8s/worker-pod.yaml', src(
      'apiVersion: v1',
      'kind: Pod',
      'metadata:',
      '  name: worker',
      'spec:',
      '  automountServiceAccountToken: false',
      '  containers:',
      '    - name: worker',
      '      image: ghcr.io/acme/worker:2.3.1'
    ))
  },

  // ─── Frontend (frontend-rules.ts) ─────────────────────────────────────
  {
    ruleIds: [1026],
    name: 'button strips its focus outline with no replacement focus style',
    detects: f('components/SaveBar.tsx', src(
      'export function SaveBar({ onSave }: { onSave: () => void }) {',
      '  return (',
      '    <div className="flex justify-end">',
      '      <button type="button" className="rounded bg-black px-4 py-2 text-white outline-none" onClick={onSave}>',
      '        Save',
      '      </button>',
      '    </div>',
      '  );',
      '}'
    )),
    ignores: f('components/SaveBar.tsx', src(
      'export function SaveBar({ onSave }: { onSave: () => void }) {',
      '  return (',
      '    <div className="flex justify-end outline-none">',
      '      <button type="button" className="rounded bg-black px-4 py-2 text-white outline-none focus-visible:ring-2 focus-visible:ring-black" onClick={onSave}>',
      '        Save',
      '      </button>',
      '    </div>',
      '  );',
      '}'
    ))
  },
  {
    ruleIds: [1026],
    name: 'newsletter email input labelled only by its placeholder',
    detects: f('components/Newsletter.tsx', src(
      'export function Newsletter() {',
      '  return (',
      '    <form action="/api/subscribe" method="post">',
      '      <input type="email" name="email" placeholder="you@example.com" />',
      '      <button type="submit">Subscribe</button>',
      '    </form>',
      '  );',
      '}'
    )),
    ignores: f('components/Newsletter.tsx', src(
      'export function Newsletter() {',
      '  return (',
      '    <form action="/api/subscribe" method="post">',
      '      <label>',
      '        Email',
      '        <input type="email" name="email" placeholder="you@example.com" />',
      '      </label>',
      '      <button type="submit">Subscribe</button>',
      '    </form>',
      '  );',
      '}'
    ))
  },
  {
    ruleIds: [1029],
    name: 'clickable card div with no role or keyboard handler',
    detects: f('components/ProjectCard.tsx', src(
      'export function ProjectCard({ id, name, open }: { id: string; name: string; open: (id: string) => void }) {',
      '  return (',
      '    <div',
      '      className="rounded border p-4"',
      '      onClick={() => open(id)}',
      '    >',
      '      {name}',
      '    </div>',
      '  );',
      '}'
    )),
    ignores: f('components/ProjectCard.tsx', src(
      'export function ProjectCard({ id, name, open }: { id: string; name: string; open: (id: string) => void }) {',
      '  return (',
      '    <button',
      '      type="button"',
      '      className="rounded border p-4 text-left"',
      '      onClick={() => open(id)}',
      '    >',
      '      {name}',
      '    </button>',
      '  );',
      '}'
    ))
  },
  {
    ruleIds: [1030],
    name: 'list items rendered from data without a key',
    detects: f('components/TeamList.tsx', src(
      'export function TeamList({ members }: { members: { id: string; name: string }[] }) {',
      '  return (',
      '    <ul>',
      '      {members.map((member) => <li className="py-1">{member.name}</li>)}',
      '    </ul>',
      '  );',
      '}'
    )),
    ignores: f('components/TeamList.tsx', src(
      'export function TeamList({ members }: { members: { id: string; name: string }[] }) {',
      '  return (',
      '    <ul>',
      '      {members.map((member) => <li',
      '        className="py-1"',
      '        key={member.id}>{member.name}</li>)}',
      '    </ul>',
      '  );',
      '}'
    ))
  },
  {
    ruleIds: [1033],
    name: 'self-hosted font face without font-display',
    detects: f('app/fonts.css', src(
      '@font-face {',
      "  font-family: 'Inter';",
      "  src: url('/fonts/inter.woff2') format('woff2');",
      '  font-weight: 400;',
      '}'
    )),
    ignores: f('app/fonts.css', src(
      '@font-face {',
      "  font-family: 'Inter';",
      "  src: url('/fonts/inter.woff2') format('woff2');",
      '  font-weight: 400;',
      '  font-display: optional;',
      '}'
    ))
  },
  {
    ruleIds: [1034],
    name: 'parser-blocking third-party script in the root layout',
    detects: f('app/layout.tsx', src(
      'export default function RootLayout({ children }: { children: React.ReactNode }) {',
      '  return (',
      '    <html lang="en">',
      '      <head>',
      '        <script src="https://widget.example.com/chat.js"></script>',
      '      </head>',
      '      <body>{children}</body>',
      '    </html>',
      '  );',
      '}'
    )),
    ignores: f('app/layout.tsx', src(
      "import Script from 'next/script';",
      '',
      'export default function RootLayout({ children }: { children: React.ReactNode }) {',
      '  return (',
      '    <html lang="en">',
      '      <body>',
      '        {children}',
      '        <Script src="https://widget.example.com/chat.js" strategy="lazyOnload" />',
      '      </body>',
      '    </html>',
      '  );',
      '}'
    ))
  },
  {
    ruleIds: [1044],
    name: '16px close button with no padding',
    detects: f('components/Toast.tsx', src(
      'export function Toast({ onClose }: { onClose: () => void }) {',
      '  return (',
      '    <div role="status">',
      '      Saved',
      '      <button type="button" aria-label="Close" className="w-4 h-4 rounded" onClick={onClose}>x</button>',
      '    </div>',
      '  );',
      '}'
    )),
    ignores: f('components/Toast.tsx', src(
      'export function Toast({ onClose }: { onClose: () => void }) {',
      '  return (',
      '    <div role="status">',
      '      Saved',
      '      <button type="button" aria-label="Close" className="w-4 h-4 p-2 rounded" onClick={onClose}>x</button>',
      '    </div>',
      '  );',
      '}'
    ))
  },

  // ─── Security (security-rules.ts) ─────────────────────────────────────
  {
    ruleIds: [20],
    name: 'lodash pinned exactly to a prototype-pollution release',
    detects: f('package.json', JSON.stringify({ name: 'shop', dependencies: { lodash: '4.17.15', next: '15.1.0' } }, null, 2)),
    ignores: f('package.json', JSON.stringify({ name: 'shop', dependencies: { lodash: '^4.17.15', next: '15.1.0' } }, null, 2))
  },
  {
    ruleIds: [20],
    name: 'jsonwebtoken caret range capped below the 9.x fix',
    detects: f('package.json', JSON.stringify({ name: 'api', dependencies: { jsonwebtoken: '^8.5.1', express: '^4.21.2' } }, null, 2)),
    ignores: f('package.json', JSON.stringify({ name: 'api', dependencies: { jsonwebtoken: '^9.0.2', express: '^4.21.2', '@acme/ui': '*' } }, null, 2))
  },
  {
    ruleIds: [35],
    name: 'download route streams a file named by the query string',
    detects: f('src/server/downloads.ts', src(
      "import fs from 'fs';",
      "import path from 'path';",
      "import type { Request, Response } from 'express';",
      '',
      "const UPLOAD_DIR = path.resolve('uploads');",
      '',
      'export function download(req: Request, res: Response) {',
      '  const { name } = req.query as { name: string };',
      '  fs.createReadStream(path.join(UPLOAD_DIR, name)).pipe(res);',
      '}'
    )),
    ignores: f('src/server/downloads.ts', src(
      "import fs from 'fs';",
      "import path from 'path';",
      "import type { Request, Response } from 'express';",
      '',
      "const UPLOAD_DIR = path.resolve('uploads');",
      '',
      'export function download(req: Request, res: Response) {',
      '  const { name } = req.query as { name: string };',
      '  fs.createReadStream(path.join(UPLOAD_DIR, path.basename(name))).pipe(res);',
      '}'
    ))
  },
  {
    ruleIds: [38],
    name: 'team invite code generated with Math.random',
    detects: f('lib/invites.ts', src(
      'export function createInvite(teamId: string) {',
      '  const inviteCode = Math.random().toString(36).slice(2, 10);',
      '  return { teamId, inviteCode };',
      '}'
    )),
    ignores: f('lib/invites.ts', src(
      "import { randomBytes } from 'crypto';",
      '',
      'export function createInvite(teamId: string) {',
      "  const inviteCode = randomBytes(12).toString('base64url');",
      '  const tempId = Math.random().toString(36).slice(2);',
      '  return { teamId, inviteCode, tempId };',
      '}'
    ))
  },

  // ─── Infra (infra-rules.ts) ───────────────────────────────────────────
  {
    ruleIds: [3004],
    name: 'credentialed Express CORS config reflecting any origin',
    detects: f('src/server/cors.ts', src(
      "import cors from 'cors';",
      '',
      'export const corsMiddleware = cors({',
      '  origin: true,',
      '  credentials: true,',
      '});'
    )),
    ignores: f('src/server/cors.ts', src(
      "import cors from 'cors';",
      '',
      "export const publicCors = cors({ origin: '*' });",
      '',
      'export const sessionConfig = {',
      "  name: 'sid',",
      '  rolling: true,',
      '  resave: false,',
      '  saveUninitialized: false,',
      '  cookie: {',
      "    sameSite: 'lax' as const,",
      '    secure: true,',
      '  },',
      '  credentials: true,',
      '};'
    ))
  },
  {
    ruleIds: [3009],
    name: 'PrismaClient created per call inside a server action',
    detects: f('app/settings/actions.ts', src(
      "'use server';",
      "import { PrismaClient } from '@prisma/client';",
      '',
      'export async function saveName(userId: string, name: string) {',
      '  const prisma = new PrismaClient();',
      '  await prisma.user.update({ where: { id: userId }, data: { name } });',
      '}'
    )),
    ignores: [
      ...f('app/settings/actions.ts', src(
        "'use server';",
        "import { prisma } from '@/lib/prisma';",
        '',
        'export async function saveName(userId: string, name: string) {',
        '  await prisma.user.update({ where: { id: userId }, data: { name } });',
        '}'
      )),
      // one-off seed script: a single client in main() is fine
      ...f('prisma/seed.ts', src(
        "import { PrismaClient } from '@prisma/client';",
        '',
        'async function main() {',
        '  const prisma = new PrismaClient();',
        "  await prisma.user.create({ data: { email: 'admin@example.com' } });",
        '}',
        '',
        'main();'
      ))
    ]
  }
];
