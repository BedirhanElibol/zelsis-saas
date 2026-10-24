import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isTrustSlug, toTrustSummary, trustSlug } from '@/lib/trust-page';

const NOW = Date.parse('2026-10-19T12:00:00Z');
const f = (severity: string, category: string, extra: Record<string, unknown> = {}) =>
  ({ ruleId: 1, severity, category, type: 'SECURITY', status: 'OPEN', ...extra });

test('trustSlug is readable, valid and unique per call', () => {
  const a = trustSlug('Acme Billing!');
  assert.match(a, /^acme-billing-[a-z0-9]{6}$/);
  assert.ok(isTrustSlug(a));
  assert.notEqual(trustSlug('Acme Billing!'), a);
  assert.ok(isTrustSlug(trustSlug('***')));
});

test('verified only with no open critical/high; experimental and dismissed findings do not count', () => {
  const clean = toTrustSummary({ score: 92, findings: [
    f('MEDIUM', 'Logic Bug'),
    f('HIGH', 'SQL Injection', { maturity: 'experimental' }),
    f('CRITICAL', 'SQL Injection', { falsePositive: true }),
    f('HIGH', 'SQL Injection', { status: 'ACCEPTED_RISK' }),
  ] }, '2026-10-18T10:00:00Z', NOW);
  assert.equal(clean?.status, 'verified');
  assert.equal(clean?.blockers, 0);
  assert.ok(clean?.areas.every((a) => a.open === 0));
});

test('open issues show as counts per risk area, never as findings', () => {
  const s = toTrustSummary({ score: 40, findings: [f('CRITICAL', 'SQL Injection'), f('HIGH', 'Revenue Protection')] }, '2026-10-18T10:00:00Z', NOW)!;
  assert.equal(s.status, 'issues-open');
  assert.equal(s.blockers, 2);
  assert.equal(s.areas.find((a) => a.kind === 'DATA_LEAK')?.open, 1);
  assert.equal(s.areas.find((a) => a.kind === 'FINANCIAL')?.open, 1);
  assert.ok(!JSON.stringify(s).includes('SQL Injection'), 'no titles or categories leak to the page');
});

test('a scan older than 30 days is stale, whatever it found', () => {
  assert.equal(toTrustSummary({ score: 100, findings: [] }, '2026-08-01T10:00:00Z', NOW)?.status, 'stale');
  assert.equal(toTrustSummary(null, '2026-10-18T10:00:00Z', NOW), null);
});
