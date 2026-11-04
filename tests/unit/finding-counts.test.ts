import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Finding } from '../../data/schema';
import { summarizeFindings, verifiedFindings } from '../../lib/finding-counts';
import { calculateGateStatus, calculateReadinessScore } from '../../lib/scanner/scoring';
import { runStaticCodeScan } from '../../lib/scanner-engine';

const finding = (over: Partial<Finding>): Finding => ({
  id: Math.random().toString(36).slice(2),
  ruleId: 1,
  type: 'SECURITY',
  title: 't',
  severity: 'HIGH',
  category: 'c',
  filePath: 'a.ts',
  lineRange: 'L1',
  snippet: '',
  reproductionSteps: [],
  remediationPrompt: '',
  status: 'OPEN',
  falsePositive: false,
  ...over,
} as Finding);

test('suggestions (experimental and unproven rules) are listed apart and never counted', () => {
  const findings = [
    finding({ severity: 'HIGH' }),
    finding({ severity: 'CRITICAL', maturity: 'unproven' }),
    finding({ severity: 'MEDIUM', maturity: 'experimental' }),
    finding({ severity: 'LOW', type: 'VIBEPOLISH' }),
    finding({ severity: 'CRITICAL', status: 'RESOLVED' }),
  ];
  const s = summarizeFindings(findings);
  assert.deepEqual(s.verified, { critical: 0, high: 1, medium: 0, low: 1, total: 2 });
  assert.equal(s.suggestions.total, 2);
  assert.equal(s.openRisks, 1);
  assert.equal(s.verifiedUi, 1);
});

test('a repo with only suggestions passes the gate and keeps a full score', () => {
  const findings = [finding({ severity: 'CRITICAL', maturity: 'unproven' }), finding({ severity: 'HIGH', maturity: 'experimental' })];
  assert.equal(calculateGateStatus(findings), 'PASSED');
  assert.equal(calculateReadinessScore(findings), 100);
});

test('the engine summary counts the same findings the dashboard counts', async () => {
  const res = await runStaticCodeScan([
    { path: 'worker/src/users.js', content: "export async function byName(env, name) {\n  return env.DB.prepare(`SELECT id FROM users WHERE name = '${name}'`).all();\n}\n" },
    { path: 'site/index.html', content: '<html><head><script src="/theme.js"></script></head><body><div aria-label="x">hi</div></body></html>\n' },
  ], 'counts');
  const s = summarizeFindings(res.findings);
  assert.equal(res.criticalCount, s.verified.critical);
  assert.equal(res.highCount, s.verified.high);
  assert.equal(res.mediumCount, s.verified.medium);
  assert.equal(res.lowCount, s.verified.low);
  assert.equal(calculateGateStatus(res.findings), calculateGateStatus(verifiedFindings(res.findings)));
});
