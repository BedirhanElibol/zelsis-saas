import { test } from 'node:test';
import assert from 'node:assert/strict';
import type Anthropic from '@anthropic-ai/sdk';
import {
  acceptReplacement, AI_FIX_MAX_LINES, AI_FIX_MAX_PER_PR, buildAiFixComments, fixCandidates, parsesCleanly, verifyFix, type AiFix, type ScanFn,
} from '@/lib/ai-fix';
import type { Finding } from '@/data/schema';

const finding = (extra: Partial<Finding> = {}): Finding => ({
  id: 'f1', ruleId: 12304, type: 'SECURITY', title: 'TLS verification disabled', severity: 'HIGH', category: 'Transport',
  filePath: 'src/client.ts', lineRange: 'L3', snippet: '', reproductionSteps: [], remediationPrompt: '',
  status: 'OPEN', falsePositive: false, maturity: 'verified', ...extra,
});

const FILE = ['import https from "https";', '', 'const agent = new https.Agent({ rejectUnauthorized: false });', 'export default agent;', ''].join('\n');
const fix = (extra: Partial<AiFix> = {}): AiFix => ({ replacement: 'const agent = new https.Agent({ rejectUnauthorized: true });', explanation: 'Verify certificates.', confident: true, ...extra });

// a scanner stand-in: reports the rule while the line says rejectUnauthorized: false
const scan: ScanFn = async (files) => {
  const out: Awaited<ReturnType<ScanFn>> = [];
  files[0].content.split('\n').forEach((l, i) => {
    if (/rejectUnauthorized:\s*false/.test(l)) out.push({ ruleId: 12304, title: 'TLS verification disabled', severity: 'HIGH', lineRange: `L${i + 1}`, filePath: files[0].path });
    if (/eval\(/.test(l)) out.push({ ruleId: 32, title: 'eval', severity: 'CRITICAL', lineRange: `L${i + 1}`, filePath: files[0].path });
  });
  return out;
};

const clientReturning = (answer: AiFix | null): Anthropic =>
  ({ messages: { parse: async () => ({ stop_reason: 'end_turn', parsed_output: answer }) } }) as unknown as Anthropic;

test('acceptReplacement rejects unconfident, unchanged, fenced, long and suppressing replacements', () => {
  const original = 'x = 1;';
  assert.ok(acceptReplacement(original, fix({ replacement: 'x = 2;' })));
  assert.equal(acceptReplacement(original, fix({ confident: false })), null);
  assert.equal(acceptReplacement(original, fix({ replacement: original })), null);
  assert.equal(acceptReplacement(original, fix({ replacement: '```ts\nx = 2;\n```' })), null);
  assert.equal(acceptReplacement(original, fix({ replacement: 'x = 2; // eslint-disable-line' })), null);
  assert.equal(acceptReplacement(original, fix({ replacement: '// TODO fix this later' })), null);
  assert.equal(acceptReplacement(original, fix({ replacement: Array(AI_FIX_MAX_LINES + 1).fill('y();').join('\n') })), null);
  assert.equal(acceptReplacement(original, fix({ replacement: '   ' })), null);
});

test('parsesCleanly accepts valid TypeScript and rejects a syntax error', () => {
  assert.ok(parsesCleanly('a.ts', 'const a: number = 1;\nexport default a;\n'));
  assert.ok(parsesCleanly('a.tsx', 'export const A = () => <div />;\n'));
  assert.equal(parsesCleanly('a.ts', 'const a = ;\n'), false);
});

test('verifyFix passes a replacement the scanner no longer flags', async () => {
  const ok = await verifyFix(scan, finding(), FILE, 3, ['const agent = new https.Agent({ rejectUnauthorized: true });']);
  assert.ok(ok);
  assert.match(ok.patched, /rejectUnauthorized: true/);
});

test('verifyFix rejects a replacement that still triggers the rule, breaks the syntax, or adds a critical finding', async () => {
  assert.equal(await verifyFix(scan, finding(), FILE, 3, ['const agent = new https.Agent({ rejectUnauthorized: false });']), null);
  assert.equal(await verifyFix(scan, finding(), FILE, 3, ['const agent = new https.Agent({ rejectUnauthorized: true ;']), null);
  assert.equal(await verifyFix(scan, finding(), FILE, 3, ['const agent = eval("x");']), null);
});

test('verifyFix gives up when the scanner cannot reproduce the finding in a one-file scan', async () => {
  const blind: ScanFn = async () => [];
  assert.equal(await verifyFix(blind, finding(), FILE, 3, ['const agent = 1;']), null);
});

test('fixCandidates keeps open blocking findings on added lines of JS/TS files, most severe first, capped', () => {
  const content = new Map([['src/client.ts', FILE], ['app/main.py', 'x']]);
  const added = new Map([['src/client.ts', new Set([3, 4, 5, 6])], ['app/main.py', new Set([1])]]);
  const list = [
    finding({ id: 'a', severity: 'HIGH', lineRange: 'L3' }),
    finding({ id: 'b', severity: 'CRITICAL', lineRange: 'L4' }),
    finding({ id: 'c', severity: 'HIGH', lineRange: 'L5' }),
    finding({ id: 'd', severity: 'HIGH', lineRange: 'L6' }),
    finding({ id: 'e', severity: 'CRITICAL', filePath: 'app/main.py', lineRange: 'L1' }),
    finding({ id: 'f', severity: 'CRITICAL', lineRange: 'L1' }),
    finding({ id: 'g', severity: 'MEDIUM', lineRange: 'L4' }),
  ];
  const ids = fixCandidates(list, content, added, new Set()).map((c) => c.finding.id);
  assert.equal(ids.length, AI_FIX_MAX_PER_PR);
  assert.deepEqual(ids, ['b', 'a']);
  assert.deepEqual(fixCandidates(list, content, added, new Set(['src/client.ts:4'])).map((c) => c.finding.id), ['a', 'c']);
});

test('buildAiFixComments posts a labelled, verified suggestion and skips a bad one', async () => {
  const content = new Map([['src/client.ts', FILE]]);
  const cands = [{ finding: finding(), line: 3 }];
  const [comment] = await buildAiFixComments(clientReturning(fix()), scan, cands, content);
  assert.equal(comment.path, 'src/client.ts');
  assert.equal(comment.line, 3);
  assert.match(comment.body, /AI-suggested fix/);
  assert.match(comment.body, /```suggestion\nconst agent = new https\.Agent\(\{ rejectUnauthorized: true \}\);\n```/);
  assert.match(comment.body, /Read it before you commit/);
  assert.deepEqual(await buildAiFixComments(clientReturning(fix({ replacement: 'const agent = new https.Agent({ rejectUnauthorized: false });' })), scan, cands, content), []);
  assert.deepEqual(await buildAiFixComments(clientReturning(null), scan, cands, content), []);
  assert.deepEqual(await buildAiFixComments(clientReturning(fix({ confident: false })), scan, cands, content), []);
});
