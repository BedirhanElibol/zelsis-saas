import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createShareToken, displayTarget, isShareToken, toPublicReport } from '../../lib/report-share';

const finding = (over: Record<string, unknown>) => ({
  id: 'f', ruleId: 1, type: 'SECURITY', title: 'Leaked key', severity: 'HIGH', category: 'Secrets',
  filePath: 'lib/stripe.ts', lineRange: 'L4', snippet: 'const key = "sk_live_SECRET"', reproductionSteps: ['quote of code'],
  remediationPrompt: 'Rotate the key sk_live_SECRET', diffPatch: '- sk_live_SECRET', status: 'OPEN', falsePositive: false, ...over,
});

test('share tokens are 43 url-safe characters and unique', () => {
  const a = createShareToken();
  assert.ok(isShareToken(a));
  assert.notEqual(a, createShareToken());
  assert.equal(isShareToken('../etc/passwd'), false);
  assert.equal(isShareToken(a.slice(1)), false);
});

test('the public report keeps title, severity and location only, never code or fixes', () => {
  const r = toPublicReport({
    score: 62, gateStatus: 'FAILED',
    findings: [
      finding({ severity: 'MEDIUM', title: 'Open redirect' }),
      finding({}),
      finding({ title: 'Ignored', falsePositive: true }),
      finding({ title: 'Fixed', status: 'RESOLVED' }),
      finding({ title: 'Accepted', status: 'ACCEPTED_RISK' }),
      finding({ title: 'Experimental', maturity: 'experimental' }),
    ],
  }, 'https://github.com/acme/app', '2026-10-14T10:00:00Z');
  assert.ok(r);
  assert.equal(r.target, 'acme/app');
  assert.deepEqual(r.findings.map((f) => f.title), ['Leaked key', 'Open redirect'], 'open findings only, most severe first');
  assert.deepEqual(r.counts, { CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 0 });
  const json = JSON.stringify(r);
  assert.ok(!json.includes('sk_live_SECRET'), 'no snippet, steps, prompt or diff leaks into the public report');
  assert.deepEqual(Object.keys(r.findings[0]).sort(), ['category', 'filePath', 'lineRange', 'severity', 'title']);
});

test('invalid stored results produce no report', () => {
  assert.equal(toPublicReport(null, 'x', ''), null);
  assert.equal(toPublicReport({ score: 'high', gateStatus: 'FAILED' }, 'x', ''), null);
  assert.equal(toPublicReport({ score: 50, gateStatus: 'MAYBE' }, 'x', ''), null);
});

test('the shown target never echoes tokens or query strings', () => {
  assert.equal(displayTarget('https://x-access-token:ghp_abc@github.com/acme/app.git'), 'acme/app');
  assert.equal(displayTarget('https://shop.example.com/admin?key=secret'), 'shop.example.com');
});
