import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan } from '@/lib/scanner-engine';

const KEY = ['sk', 'live', '51Hx9QzKp3mR7tVw2LcN8bYd4FgJ6sA0eU1iO5'].join('_');
const stripe = async (path: string) => (await runStaticCodeScan([{ path, content: `export const key = "${KEY}";\n` }], 'x', { dependencyAudit: false }))
  .findings.filter((f) => f.ruleId === 1 || (f.ruleId >= 5001 && f.ruleId <= 5299));

test('a live-looking key in app code blocks the release', async () => {
  const f = await stripe('src/lib/billing.ts');
  assert.ok(f.length > 0 && f.some((x) => x.severity === 'CRITICAL' || x.severity === 'HIGH'));
});

test('the same key in a test or docs file is reported at MEDIUM', async () => {
  for (const path of ['src/lib/billing.test.ts', 'tests/fixtures/stripe.ts', 'docs_src/security/tutorial.ts']) {
    const f = await stripe(path);
    assert.ok(f.length > 0, path);
    assert.ok(f.every((x) => x.severity === 'MEDIUM'), path);
  }
});

test('a Firebase API key in GoogleService-Info.plist is not a secret', async () => {
  const content = '<plist><dict><key>API_KEY</key><string>AIzaSyD3x9QzKp3mR7tVw2LcN8bYd4FgJ6sA0eU</string></dict></plist>\n';
  const r = await runStaticCodeScan([{ path: 'ios/App/GoogleService-Info.plist', content }], 'x', { dependencyAudit: false });
  assert.equal(r.findings.filter((x) => /AIza/.test(String(x.snippet))).length, 0);
});
