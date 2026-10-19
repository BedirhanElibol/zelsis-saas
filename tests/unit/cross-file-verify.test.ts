import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan } from '@/lib/scanner-engine';

// A Next.js route that mutates data and has no auth call of its own (fires rule 15)
const ROUTE = [
  "import { db } from '@/lib/db';",
  'export async function POST(req: Request) {',
  '  const body = await req.json();',
  '  await db.insert(body);',
  '  return Response.json({ ok: true });',
  '}',
].join('\n');

const scan = (extra: { path: string; content: string }[]) =>
  runStaticCodeScan([{ path: 'app/api/items/route.ts', content: ROUTE }, ...extra], 'xfile');

test('route without any guard is still reported', async () => {
  const r = await scan([]);
  assert.ok(r.findings.some((f) => f.ruleId === 15), 'rule 15 fires on an unguarded mutation route');
  assert.equal(r.crossFileVerified?.length ?? 0, 0);
});

test('middleware that authenticates /api drops the finding and says why', async () => {
  const middleware = [
    "import { NextResponse } from 'next/server';",
    "import { auth } from '@/auth';",
    'export async function middleware(req) {',
    '  const session = await auth();',
    "  if (!session) return NextResponse.redirect(new URL('/login', req.url));",
    '  return NextResponse.next();',
    '}',
    "export const config = { matcher: ['/api/:path*'] };",
  ].join('\n');
  const r = await scan([{ path: 'middleware.ts', content: middleware }]);
  assert.ok(!r.findings.some((f) => f.ruleId === 15 && f.filePath === 'app/api/items/route.ts'));
  const v = r.crossFileVerified?.find((x) => x.ruleId === 15);
  assert.ok(v, 'verification recorded');
  assert.match(v.reason, /middleware authenticates \/api\/items/);
});

test('middleware whose matcher skips the route does not hide the finding', async () => {
  const middleware = [
    "import { auth } from '@/auth';",
    'export async function middleware(req) { const s = await auth(); if (!s) return Response.redirect("/login"); }',
    "export const config = { matcher: ['/dashboard/:path*'] };",
  ].join('\n');
  const r = await scan([{ path: 'middleware.ts', content: middleware }]);
  assert.ok(r.findings.some((f) => f.ruleId === 15));
});
