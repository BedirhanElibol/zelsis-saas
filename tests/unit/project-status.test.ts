import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withLiveStatus } from '../../lib/project-status';
import type { Finding, Project } from '../../data/schema';

const finding = (severity: Finding['severity'], type: Finding['type'] = 'SECURITY', extra: Partial<Finding> = {}): Finding => ({
  id: `f-${Math.random()}`, ruleId: 3, type, title: 't', severity, category: 'c', filePath: 'a.sql', lineRange: 'L1',
  snippet: '', reproductionSteps: [], remediationPrompt: '', status: 'OPEN', owner: 'Engineering', falsePositive: false, ...extra,
} as Finding);

const stale = (findings: Finding[]): Project => ({
  id: 'p1', name: 'app', repoUrl: 'https://github.com/a/b', framework: 'Next.js', providers: [], lastScanAt: 'x',
  readinessScore: 100, gateStatus: 'PASSED', criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, uiClicheCount: 0, findings,
} as unknown as Project);

test('stored PASSED / 100 is replaced by the status of the findings on screen', () => {
  const p = withLiveStatus(stale([finding('CRITICAL'), finding('CRITICAL'), finding('HIGH'), finding('LOW', 'VIBEPOLISH')]));
  assert.equal(p.gateStatus, 'FAILED');
  assert.ok(p.readinessScore < 100);
  assert.equal(p.criticalCount, 2);
  assert.equal(p.highCount, 1);
  assert.equal(p.uiClicheCount, 1);
});

test('dismissed findings do not count, and projects without loaded findings keep their stored values', () => {
  const p = withLiveStatus(stale([finding('CRITICAL', 'SECURITY', { status: 'ACCEPTED_RISK' })]));
  assert.equal(p.gateStatus, 'PASSED');
  assert.equal(p.criticalCount, 0);
  const empty = withLiveStatus(stale([]));
  assert.equal(empty.gateStatus, 'PASSED');
  assert.equal(empty.readinessScore, 100);
});
