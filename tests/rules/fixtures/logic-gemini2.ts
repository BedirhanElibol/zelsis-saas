import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

// Logic bugs from part 2 of the Gemini report. Each case keeps the bug and the correct version side by side.
export const CASES: RuleCase[] = [
  {
    ruleIds: [30101], name: 'BUG-223 http.request never ended vs ended',
    detects: f('server/notify.ts', `import https from 'https';
export function notify(body: string) {
  const req = https.request({ host: 'hooks.example.com', method: 'POST' }, (res) => res.resume());
  req.write(body);
}
`),
    ignores: f('server/notify.ts', `import https from 'https';
export function notify(body: string) {
  const req = https.request({ host: 'hooks.example.com', method: 'POST' }, (res) => res.resume());
  req.write(body);
  req.end();
}
`)
  },
  {
    ruleIds: [30102], name: 'BUG-224 uncaughtException handler that only logs vs one that exits',
    detects: f('server/index.ts', `process.on('uncaughtException', (err) => {
  console.error('uncaught', err);
});
`),
    ignores: f('server/index.ts', `process.on('uncaughtException', (err) => {
  console.error('uncaught', err);
  process.exit(1);
});
`)
  },
  {
    ruleIds: [30104], name: 'BUG-226 Object.values on a numeric enum vs a string enum',
    detects: f('lib/roles.ts', `export enum Role { Viewer, Editor, Admin }
export const ROLE_OPTIONS = Object.values(Role);
`),
    ignores: f('lib/roles.ts', `export enum Role { Viewer = 'viewer', Editor = 'editor', Admin = 'admin' }
export const ROLE_OPTIONS = Object.values(Role);
`)
  },
  {
    ruleIds: [30105], name: 'BUG-227 gunzip of the request body without a limit vs with maxOutputLength',
    detects: f('app/api/ingest/route.ts', `import zlib from 'zlib';
export async function POST(req: Request) {
  const data = zlib.gunzipSync(await req.arrayBuffer() as unknown as Buffer);
  return Response.json({ size: data.length });
}
`),
    ignores: f('app/api/ingest/route.ts', `import zlib from 'zlib';
export async function POST(req: Request) {
  const data = zlib.gunzipSync(await req.arrayBuffer() as unknown as Buffer, { maxOutputLength: 10 * 1024 * 1024 });
  return Response.json({ size: data.length });
}
`)
  },
  {
    ruleIds: [30106], name: 'BUG-228 module-level /g regex reused with test() vs without g',
    detects: f('lib/validate.ts', `const SLUG = /^[a-z0-9-]+$/g;
export const isSlug = (s: string) => SLUG.test(s);
`),
    ignores: f('lib/validate.ts', `const SLUG = /^[a-z0-9-]+$/;
export const isSlug = (s: string) => SLUG.test(s);
`)
  },
  {
    ruleIds: [30107], name: 'BUG-229 bcrypt.hashSync in a route vs await bcrypt.hash',
    detects: f('app/api/signup/route.ts', `import bcrypt from 'bcryptjs';
export async function POST(req: Request) {
  const { password } = await req.json();
  const hash = bcrypt.hashSync(password, 12);
  return Response.json({ ok: !!hash });
}
`),
    ignores: f('app/api/signup/route.ts', `import bcrypt from 'bcryptjs';
export async function POST(req: Request) {
  const { password } = await req.json();
  const hash = await bcrypt.hash(password, 12);
  return Response.json({ ok: !!hash });
}
`)
  },
  {
    ruleIds: [30108], name: 'BUG-230 middleware catch that only logs vs one that calls next(err)',
    detects: f('server/middleware/auth.ts', `export const loadUser = async (req, res, next) => {
  try {
    req.user = await users.find(req.headers.authorization);
    next();
  } catch (err) {
    console.error('auth failed', err);
  }
};
`),
    ignores: f('server/middleware/auth.ts', `export const loadUser = async (req, res, next) => {
  try {
    req.user = await users.find(req.headers.authorization);
    next();
  } catch (err) {
    next(err);
  }
};
`)
  },
  {
    ruleIds: [30109], name: 'BUG-231 cookies().set in a page vs in a server action',
    detects: f('app/welcome/page.tsx', `import { cookies } from 'next/headers';
export default async function Welcome() {
  const store = await cookies();
  store.set('seen_welcome', '1');
  return <h1>Welcome</h1>;
}
`),
    ignores: f('app/welcome/actions.ts', `'use server';
import { cookies } from 'next/headers';
export async function markSeen() {
  const store = await cookies();
  store.set('seen_welcome', '1');
}
`)
  },
  {
    ruleIds: [30110], name: 'BUG-232 sync.WaitGroup by value vs by pointer',
    detects: f('worker/pool.go', `package worker

import "sync"

func process(item string, wg sync.WaitGroup) {
	defer wg.Done()
	handle(item)
}
`),
    ignores: f('worker/pool.go', `package worker

import "sync"

func process(item string, wg *sync.WaitGroup) {
	defer wg.Done()
	handle(item)
}
`)
  },
  {
    ruleIds: [30251], name: 'SEC2-01 inspector on 0.0.0.0 in the production Dockerfile vs 127.0.0.1',
    detects: f('Dockerfile', `FROM node:22-alpine
WORKDIR /app
COPY . .
CMD ["node", "--inspect=0.0.0.0:9229", "server.js"]
`),
    ignores: f('Dockerfile', `FROM node:22-alpine
WORKDIR /app
COPY . .
CMD ["node", "--inspect=127.0.0.1:9229", "server.js"]
`)
  },
  {
    ruleIds: [30252], name: 'SEC2-02 dependency over http:// vs https://',
    detects: f('package.json', `{
  "name": "app",
  "dependencies": {
    "internal-ui": "http://packages.acme.dev/internal-ui-1.4.0.tgz"
  }
}
`),
    ignores: f('package.json', `{
  "name": "app",
  "dependencies": {
    "internal-ui": "https://packages.acme.dev/internal-ui-1.4.0.tgz"
  }
}
`)
  },
  {
    ruleIds: [30151], name: 'FAKE-16 export of an empty Blob vs the fetched rows',
    detects: f('components/AuditLogExport.tsx', `export function AuditLogExport() {
  const exportLogs = () => {
    const blob = new Blob([JSON.stringify([])], { type: 'application/x-ndjson' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'audit-log.ndjson';
    a.click();
  };
  return <button onClick={exportLogs}>Export</button>;
}
`),
    ignores: f('components/AuditLogExport.tsx', `export function AuditLogExport() {
  const exportLogs = async () => {
    const rows = await fetch('/api/audit-log').then((r) => r.json());
    const blob = new Blob([rows.map((r: unknown) => JSON.stringify(r)).join('\\n')], { type: 'application/x-ndjson' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'audit-log.ndjson';
    a.click();
  };
  return <button onClick={exportLogs}>Export</button>;
}
`)
  },
  {
    ruleIds: [30152], name: 'FAKE-17 hard-coded backup codes vs codes from the server',
    detects: f('components/TwoFactorSetup.tsx', `export function TwoFactorSetup() {
  const backupCodes = ['K7Q2-M9XA', 'P4ZR-8WLN', 'T3VB-6HJD', 'R8NC-2FQY'];
  return <ul>{backupCodes.map((c) => <li key={c}>{c}</li>)}</ul>;
}
`),
    ignores: f('components/TwoFactorSetup.tsx', `export function TwoFactorSetup({ backupCodes }: { backupCodes: string[] }) {
  return <ul>{backupCodes.map((c) => <li key={c}>{c}</li>)}</ul>;
}
`)
  },
  {
    ruleIds: [30201], name: 'AIX-01 agent loop without a step limit vs capped at MAX_STEPS',
    detects: f('lib/agent.ts', `export async function run(messages: Msg[]) {
  while (true) {
    const res = await openai.chat.completions.create({ model: 'gpt-4o', messages, tools });
    const call = res.choices[0].message.tool_calls?.[0];
    if (!call) return res.choices[0].message.content;
    messages.push(await runTool(call));
  }
}
`),
    ignores: f('lib/agent.ts', `const MAX_STEPS = 10;
export async function run(messages: Msg[]) {
  let step = 0;
  while (true) {
    if (step++ >= MAX_STEPS) return 'Stopped after too many steps.';
    const res = await openai.chat.completions.create({ model: 'gpt-4o', messages, tools });
    const call = res.choices[0].message.tool_calls?.[0];
    if (!call) return res.choices[0].message.content;
    messages.push(await runTool(call));
  }
}
`)
  },
  {
    ruleIds: [30202], name: 'AIX-02 agent tool reading a model-chosen path vs one checked against the base dir',
    detects: f('lib/tools.ts', `import fs from 'fs/promises';
export const readNote = tool({
  description: 'Read a note',
  parameters: z.object({ filePath: z.string() }),
  execute: async ({ filePath }) => {
    return fs.readFile(filePath, 'utf8');
  },
});
`),
    ignores: f('lib/tools.ts', `import fs from 'fs/promises';
import path from 'path';
const BASE = path.resolve('notes');
export const readNote = tool({
  description: 'Read a note',
  parameters: z.object({ filePath: z.string() }),
  execute: async ({ filePath }) => {
    const full = path.resolve(BASE, filePath);
    if (!full.startsWith(BASE + path.sep)) throw new Error('outside notes');
    return fs.readFile(full, 'utf8');
  },
});
`)
  }
];
