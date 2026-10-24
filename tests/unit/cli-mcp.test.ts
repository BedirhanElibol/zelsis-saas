import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { isScannablePath, changedPaths, collectFiles, formatReport } from '../../packages/cli/lib.mjs';
import { handleMessage as rawHandleMessage, agentNote } from '../../packages/cli/mcp.mjs';
import { scanUploadedFiles } from '@/lib/scan-files';
import { ScanFilesRequestSchema } from '@/lib/validations/api-schemas';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const handleMessage = rawHandleMessage as (msg: unknown, ctx: unknown) => Promise<any>;

test('isScannablePath skips build folders, binaries and lockfiles', () => {
  assert.equal(isScannablePath('app/api/pay/route.ts'), true);
  assert.equal(isScannablePath('supabase/migrations/001.sql'), true);
  for (const p of ['node_modules/x/index.js', 'dist/app.js', '.next/server.js', 'logo.png', 'yarn.lock', 'app.min.js', 'a.js.map']) {
    assert.equal(isScannablePath(p), false, p);
  }
});

test('changedPaths and collectFiles: changed files first, rest as context, ignored files left out', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zelsis-cli-'));
  try {
    const g = (...a: string[]) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
    g('init', '-q');
    g('config', 'user.email', 't@t.t');
    g('config', 'user.name', 't');
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src/a.ts'), 'export const a = 1;\n');
    writeFileSync(join(dir, 'src/b.ts'), 'export const b = 1;\n');
    writeFileSync(join(dir, '.gitignore'), 'secret.txt\n');
    g('add', '.');
    g('commit', '-qm', 'init');
    writeFileSync(join(dir, 'src/b.ts'), 'export const b = 2;\n');
    writeFileSync(join(dir, 'src/new.ts'), 'export const n = 1;\n');
    writeFileSync(join(dir, 'secret.txt'), 'ignored');

    const changed = changedPaths(dir).sort();
    assert.deepEqual(changed, ['src/b.ts', 'src/new.ts']);
    const { files } = collectFiles(dir, { changed });
    assert.deepEqual(files.slice(0, 2).map((f: { path: string }) => f.path), changed);
    const paths = files.map((f: { path: string }) => f.path);
    assert.ok(paths.includes('src/a.ts'), 'unchanged files go along as context');
    assert.ok(!paths.includes('secret.txt'), 'gitignored files are never sent');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('scan-files request schema rejects absolute and parent paths', () => {
  const ok = ScanFilesRequestSchema.safeParse({ files: [{ path: 'src/a.ts', content: '' }] });
  assert.equal(ok.success, true);
  for (const path of ['/etc/passwd', '../x.ts', 'src/../../x.ts']) {
    assert.equal(ScanFilesRequestSchema.safeParse({ files: [{ path, content: '' }] }).success, false, path);
  }
});

test('scanUploadedFiles gates only on changed files and hides fixes without access', async () => {
  const pay = [
    "import Stripe from 'stripe';",
    'const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);',
    'export async function POST(req: Request) {',
    '  const body = await req.json();',
    '  const intent = await stripe.paymentIntents.create({ amount: body.amount, currency: "usd" });',
    '  return Response.json({ id: intent.id });',
    '}',
  ].join('\n');
  const files = () => [{ path: 'app/api/pay/route.ts', content: pay }, { path: 'src/ok.ts', content: 'export const ok = 1;\n' }];

  const hit = await scanUploadedFiles(files(), { changed: ['app/api/pay/route.ts'], canSeeFixes: false });
  assert.equal(hit.gateStatus, 'FAILED');
  const f = hit.findings.find((x) => x.ruleId === 23004);
  assert.ok(f, 'SAAS-04 reported');
  assert.ok(f.impact, 'impact sentence included');
  assert.match(f.fix ?? '', /Pro/);

  const miss = await scanUploadedFiles(files(), { changed: ['src/ok.ts'], canSeeFixes: true });
  assert.equal(miss.gateStatus, 'PASSED');
  assert.equal(miss.findings.length, 0);
  assert.ok(miss.otherFindings > 0, 'findings outside the change are counted, not gated');
});

test('MCP server: initialize, tools/list, tools/call and unknown methods', async () => {
  const env = { ZELSIS_API_KEY: 'k' };
  const check = async () => ({ gateStatus: 'FAILED', scope: 'changed', filesScanned: 2, findings: [
    { severity: 'CRITICAL', filePath: 'app/api/pay/route.ts', lineRange: 'L5', title: 'Payment Amount Controlled by the Client', impact: 'Anyone can pay any price.', fix: 'Look up the price on the server.' },
  ] });
  const init = await handleMessage({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }, { cwd: '.', env, check });
  assert.equal(init.result.serverInfo.name, 'zelsis');
  assert.equal(await handleMessage({ jsonrpc: '2.0', method: 'notifications/initialized' }, { cwd: '.', env, check }), null);
  const list = await handleMessage({ jsonrpc: '2.0', id: 2, method: 'tools/list' }, { cwd: '.', env, check });
  assert.deepEqual(list.result.tools.map((t: { name: string }) => t.name), ['zelsis_check']);
  const call = await handleMessage({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'zelsis_check', arguments: {} } }, { cwd: '.', env, check });
  assert.equal(call.result.isError, false);
  assert.match(call.result.content[0].text, /app\/api\/pay\/route\.ts:5[\s\S]*Anyone can pay any price[\s\S]*FAILED/);
  const bad = await handleMessage({ jsonrpc: '2.0', id: 4, method: 'nope' }, { cwd: '.', env, check });
  assert.equal(bad.error.code, -32601);
  const failing = await handleMessage({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'zelsis_check', arguments: {} } },
    { cwd: '.', env, check: async () => { throw new Error('Invalid API key.'); } });
  assert.equal(failing.result.isError, true);
});

test('agentNote tells the agent to fix blocking findings and ignores experimental ones', () => {
  assert.match(agentNote({ findings: [{ severity: 'HIGH' }] }), /Fix the 1 critical\/high finding/);
  assert.match(agentNote({ findings: [{ severity: 'HIGH', experimental: true }, { severity: 'MEDIUM' }] }), /You can finish/);
});

test('formatReport says when nothing changed', () => {
  assert.match(formatReport({ nothingChanged: true, findings: [] }), /--all/);
});
