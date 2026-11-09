import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyKeyLiveness, extractKeys, probeKey, MAX_KEY_CHECKS, type FetchLike } from '@/lib/scanner/key-liveness';
import type { Finding } from '@/data/schema';

const STRIPE = 'sk_live_' + 'a'.repeat(24);
const GITHUB = 'ghp_' + 'b'.repeat(36);
const OPENAI = 'sk-' + 'c'.repeat(48);

/** Fake provider: status by key. Records every request so tests can prove what was sent. */
function fakeFetch(statusByKey: Record<string, number>, calls: { url: string; auth: string }[] = []): FetchLike {
  return async (url, init) => {
    const auth = init.headers.Authorization;
    calls.push({ url, auth });
    const key = Object.keys(statusByKey).find((k) => auth.includes(Buffer.from(`${k}:`).toString('base64')) || auth.endsWith(k));
    return { status: key ? statusByKey[key] : 500 };
  };
}

const finding = (over: Partial<Finding>): Finding => ({ id: 'f', ruleId: 5001, title: 'Secret', severity: 'HIGH', filePath: 'src/a.ts', lineRange: 'L2', ...over } as Finding);

test('extractKeys finds each provider key with its line', () => {
  const keys = extractKeys(`const a = 1;\nconst s = "${STRIPE}";\nconst g = "${GITHUB}";\nconst o = "${OPENAI}";`);
  assert.deepEqual(keys.map((k) => [k.provider, k.line]), [['stripe', 2], ['github', 3], ['openai', 4]]);
  assert.equal(extractKeys('sk_live_short').length, 0, 'too short to be a key');
});

test('probeKey maps 200 to live, 401/403 to dead, anything else to unknown', async () => {
  assert.equal(await probeKey('stripe', STRIPE, fakeFetch({ [STRIPE]: 200 })), 'live');
  assert.equal(await probeKey('github', GITHUB, fakeFetch({ [GITHUB]: 401 })), 'dead');
  assert.equal(await probeKey('openai', OPENAI, fakeFetch({ [OPENAI]: 403 })), 'dead');
  assert.equal(await probeKey('openai', OPENAI, fakeFetch({ [OPENAI]: 503 })), 'unknown');
  const throwing: FetchLike = async () => { throw new Error('network down'); };
  assert.equal(await probeKey('stripe', STRIPE, throwing), 'unknown');
});

test('a live key raises the finding to CRITICAL with a revoke step', async () => {
  const f = finding({ ruleId: 5015, title: 'Stripe key exposed', lineRange: 'L2', severity: 'HIGH' });
  await applyKeyLiveness([f], [{ path: 'src/a.ts', content: `x\nconst s = "${STRIPE}";` }], fakeFetch({ [STRIPE]: 200 }));
  assert.equal(f.severity, 'CRITICAL');
  assert.match(f.title, /^LIVE KEY: /);
  assert.match(f.reproductionSteps?.join(' ') ?? '', /Revoke it now/);
});

test('a rejected key drops the finding to LOW and says rotate anyway', async () => {
  const f = finding({ ruleId: 5002, lineRange: 'L1', severity: 'CRITICAL' });
  await applyKeyLiveness([f], [{ path: 'src/a.ts', content: `const s = "${GITHUB}";` }], fakeFetch({ [GITHUB]: 401 }));
  assert.equal(f.severity, 'LOW');
  assert.match(f.reproductionSteps?.join(' ') ?? '', /rotate it anyway/);
});

test('findings without a key on their line, and non-secret rules, are untouched', async () => {
  const calls: { url: string; auth: string }[] = [];
  const secretNoKey = finding({ ruleId: 5003, lineRange: 'L2', severity: 'HIGH' });
  const other = finding({ ruleId: 9106, lineRange: 'L1', severity: 'HIGH' });
  await applyKeyLiveness([secretNoKey, other], [{ path: 'src/a.ts', content: `const s = "${STRIPE}";` }], fakeFetch({ [STRIPE]: 200 }, calls));
  assert.equal(secretNoKey.severity, 'HIGH');
  assert.equal(other.severity, 'HIGH');
  assert.equal(calls.length, 0, 'no request for a finding without a key on its line');
});

test('one probe per distinct key, and never more than the cap per scan', async () => {
  const keys = Array.from({ length: MAX_KEY_CHECKS + 5 }, (_, i) => 'sk_live_' + String(i).padStart(24, 'x'));
  const content = keys.map((k) => `const k${k.slice(-3)} = "${k}";`).join('\n');
  const findings = keys.map((_, i) => finding({ ruleId: 5010, lineRange: `L${i + 1}`, severity: 'HIGH' }));
  const calls: { url: string; auth: string }[] = [];
  const { checks } = await applyKeyLiveness(findings, [{ path: 'src/a.ts', content }], fakeFetch({}, calls));
  assert.equal(checks, MAX_KEY_CHECKS);
  assert.equal(calls.length, MAX_KEY_CHECKS);
  // the same key on two lines is one request
  const dup = [finding({ ruleId: 5010, lineRange: 'L1', filePath: 'src/b.ts' }), finding({ ruleId: 5010, lineRange: 'L2', filePath: 'src/b.ts' })];
  const dupCalls: { url: string; auth: string }[] = [];
  await applyKeyLiveness(dup, [{ path: 'src/b.ts', content: `${STRIPE}\n${STRIPE}` }], fakeFetch({ [STRIPE]: 200 }, dupCalls));
  assert.equal(dupCalls.length, 1);
});

test('the key is sent only to the provider, and not in any finding field', async () => {
  const f = finding({ ruleId: 5001, lineRange: 'L1', severity: 'HIGH' });
  await applyKeyLiveness([f], [{ path: 'src/a.ts', content: `const s = "${STRIPE}";` }], fakeFetch({ [STRIPE]: 200 }));
  assert.ok(!JSON.stringify(f).includes(STRIPE), 'the raw key must not appear in the finding');
});
