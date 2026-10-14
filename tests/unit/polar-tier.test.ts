import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectPolarPlanTier } from '../../lib/polar';

test('Polar product names map to the plan they grant (the $49 plan is shown as Team)', () => {
  assert.equal(detectPolarPlanTier('Zelsis Pro'), 'Pro');
  assert.equal(detectPolarPlanTier('Zelsis Enterprise'), 'Enterprise');
  assert.equal(detectPolarPlanTier('Zelsis Team'), 'Enterprise');
  assert.equal(detectPolarPlanTier('zelsis team (10 seats)'), 'Enterprise');
  assert.equal(detectPolarPlanTier('Steam Pro'), 'Pro');
  assert.equal(detectPolarPlanTier(null), 'Pro');
});
