import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { PLAN_PRICES, ZELSIS_PRICING_PLANS } from '../../data/pricing-plans';
import { TIER_CONFIGS } from '../../lib/quota-manager';

const root = join(__dirname, '../..');

test('plan cards use the shared monthly prices', () => {
  const byId = Object.fromEntries(ZELSIS_PRICING_PLANS.map((p) => [p.id, p.priceMonthly]));
  assert.equal(byId['free'], PLAN_PRICES.Free);
  assert.equal(byId['zelsis-core'], PLAN_PRICES.Pro);
  assert.equal(byId['vibecare'], PLAN_PRICES.Enterprise);
  assert.equal(TIER_CONFIGS.Enterprise.priceMonthly, `$${PLAN_PRICES.Enterprise}/mo`);
});

function listSources(dir: string): string[] {
  return readdirSync(join(root, dir)).flatMap((name) => {
    const rel = `${dir}/${name}`;
    if (statSync(join(root, rel)).isDirectory()) return listSources(rel);
    return /\.tsx?$/.test(name) ? [rel] : [];
  });
}

test('no UI copy hard-codes a plan price or offers annual billing', () => {
  // Polar sells monthly plans only; prices come from PLAN_PRICES so copy cannot drift from checkout.
  const offenders = [...listSources('app'), ...listSources('components')].filter((file) => {
    const src = readFileSync(join(root, file), 'utf8');
    return /\$(19|49|99)(\b|\/mo| \/ mo)/.test(src) || /Save 20%|billed annually/i.test(src);
  });
  assert.deepEqual(offenders, []);
});
