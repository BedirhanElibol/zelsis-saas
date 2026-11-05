import { test } from 'node:test';
import assert from 'node:assert/strict';
import { activeDismissals, dismissalExpiry } from '@/lib/dismissals';

const now = new Date('2026-11-05T12:00:00Z');

test('expired acceptances stop counting, open-ended ones stay', () => {
  const rows = [
    { rule_id: 1, file_path: 'a.ts', expires_at: '2026-11-04T00:00:00Z' },
    { rule_id: 2, file_path: 'b.ts', expires_at: '2026-12-01T00:00:00Z' },
    { rule_id: 3, file_path: 'c.ts', expires_at: null },
    { rule_id: 4, file_path: 'd.ts' },
  ];
  assert.deepEqual(activeDismissals(rows, now).map((d) => d.ruleId), [2, 3, 4]);
  assert.deepEqual(activeDismissals(null, now), []);
});

test('accepted risks default to 90 days, other reasons have no end date', () => {
  assert.equal(dismissalExpiry('accepted_risk', undefined, now), '2027-02-03T12:00:00.000Z');
  assert.equal(dismissalExpiry('accepted_risk', 30, now), '2026-12-05T12:00:00.000Z');
  assert.equal(dismissalExpiry('accepted_risk', null, now), null);
  assert.equal(dismissalExpiry('false_positive', undefined, now), null);
});
