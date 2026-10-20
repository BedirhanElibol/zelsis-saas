import { test } from 'node:test';
import assert from 'node:assert/strict';
import { estimateCost, formatUsd } from '@/lib/cost-estimate';
import type { Finding } from '@/data/schema';

const finding = (ruleId: number, extra: Partial<Finding> = {}): Finding => ({
  id: `f${ruleId}`, ruleId, type: 'SECURITY', title: 't', severity: 'HIGH', category: 'c', filePath: 'a.ts', lineRange: 'L1',
  snippet: '', reproductionSteps: [], remediationPrompt: '', status: 'OPEN', falsePositive: false, ...extra,
});

test('no dollar figure without the user\'s own price and rate', () => {
  const est = estimateCost([finding(30312)], {});
  assert.equal(est.paidCallFindings.length, 1);
  assert.equal(est.perHour, null);
  assert.equal(est.perDay, null);
});

test('cost = price x requests per minute x 60, and x24 for a day', () => {
  const est = estimateCost([finding(30312)], { pricePerRequest: 0.05, requestsPerMinute: 100 });
  assert.equal(est.perHour, 300);
  assert.equal(est.perDay, 7200);
});

test('no paid-call finding means no cost, whatever the inputs', () => {
  const est = estimateCost([finding(9106, { risk: 'DATA_LEAK' })], { pricePerRequest: 1, requestsPerMinute: 1000, userCount: 5000 });
  assert.equal(est.perHour, null);
  assert.equal(est.usersAtRisk, 5000);
});

test('fixed, false-positive and low findings are ignored', () => {
  const est = estimateCost([
    finding(30312, { status: 'RESOLVED' }),
    finding(10402, { falsePositive: true }),
    finding(4001, { severity: 'LOW' }),
  ], { pricePerRequest: 1, requestsPerMinute: 1 });
  assert.equal(est.paidCallFindings.length, 0);
  assert.equal(est.perHour, null);
});

test('formatUsd keeps cents for small amounts only', () => {
  assert.equal(formatUsd(3.5), '$3.50');
  assert.equal(formatUsd(7200), '$7,200');
});
