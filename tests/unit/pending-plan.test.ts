import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rememberPendingPlan, takePendingPlan } from '../../lib/pending-plan';

function memoryStorage() {
  const data = new Map<string, string>();
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
  };
}

const NOW = Date.parse('2026-10-27T12:00:00Z');

test('a remembered plan comes back once, then is forgotten', () => {
  const s = memoryStorage();
  rememberPendingPlan('zelsis-core', NOW, s);
  assert.equal(takePendingPlan(NOW + 60_000, s), 'zelsis-core');
  assert.equal(takePendingPlan(NOW + 61_000, s), null);
});

test('a plan older than an hour is dropped so an old click never redirects later', () => {
  const s = memoryStorage();
  rememberPendingPlan('vibecare', NOW, s);
  assert.equal(takePendingPlan(NOW + 61 * 60_000, s), null);
});

test('garbage or unknown plans are ignored', () => {
  const s = memoryStorage();
  s.setItem('zelsis_pending_plan', '{"plan":"hacker","at":1}');
  assert.equal(takePendingPlan(NOW, s), null);
  s.setItem('zelsis_pending_plan', 'not json');
  assert.equal(takePendingPlan(NOW, s), null);
  assert.equal(takePendingPlan(NOW, null), null);
});
