import { test } from 'node:test';
import assert from 'node:assert/strict';
import { measureRecall } from '../../scripts/benchmark/corpus-recall';

/** /docs/boundaries publishes these numbers; a rule change that lowers them must update the page, not hide it. */
const PUBLISHED = { total: 108, highCritical: 88, withMedium: 102 };

test('real-incident corpus recall is at least what /docs/boundaries publishes', async () => {
  const r = await measureRecall();
  assert.equal(r.total, PUBLISHED.total, 'corpus size changed: update /docs/boundaries');
  assert.ok(r.highCritical >= PUBLISHED.highCritical, `HIGH/CRITICAL recall fell to ${r.highCritical}/${r.total}; missed: ${r.missed.join(', ')}`);
  assert.ok(r.withMedium >= PUBLISHED.withMedium, `recall incl. MEDIUM fell to ${r.withMedium}/${r.total}`);
});
