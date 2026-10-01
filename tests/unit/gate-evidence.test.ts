import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Finding } from '@/data/schema';
import { calculateGateStatus, calculateReadinessScore, gateSeverity } from '@/lib/scanner/scoring';
import { canBlockRelease, ruleMaturity } from '@/lib/scanner/rule-maturity';
import evidence from '@/data/rule-evidence.generated.json';

const finding = (over: Partial<Finding>): Finding => ({
  id: 'f1', ruleId: 1, title: 't', description: 'd', severity: 'CRITICAL', type: 'SECURITY',
  status: 'OPEN', filePath: 'a.ts', lineNumber: 1, codeSnippet: '', fixSuggestion: '', ...over
} as Finding);

test('evidence-backed CRITICAL fails the gate', () => {
  assert.equal(calculateGateStatus([finding({ maturity: 'verified' })]), 'FAILED');
});

test('unproven CRITICAL only warns and scores as advisory', () => {
  const f = finding({ maturity: 'unproven' });
  assert.equal(gateSeverity(f), 'HIGH');
  assert.equal(calculateGateStatus([f]), 'WARNING');
  // Advisory: costs less than a proven HIGH, and no amount of unproven findings costs more than 10 points
  assert.ok(calculateReadinessScore([f]) > calculateReadinessScore([finding({ severity: 'HIGH', maturity: 'verified' })]));
  assert.ok(calculateReadinessScore(Array.from({ length: 50 }, () => finding({ maturity: 'unproven' }))) >= 90);
});

test('findings stored before the policy (no maturity) keep their severity', () => {
  assert.equal(calculateGateStatus([finding({})]), 'FAILED');
});

test('maturity tags follow the generated evidence list', () => {
  for (const id of evidence.canBlockRelease) {
    if (canBlockRelease(id)) assert.equal(ruleMaturity(id), 'verified');
  }
  assert.equal(ruleMaturity(999999), 'unproven');
});
