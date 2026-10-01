import { it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { auditRules, summaryJson } from '../../scripts/rule-audit';

it('data/rule-inventory.generated.json matches the rule sources (run `npm run audit:rules`)', () => {
  const committed = JSON.parse(readFileSync(join(__dirname, '../../data/rule-inventory.generated.json'), 'utf8'));
  assert.deepEqual(committed, JSON.parse(JSON.stringify(auditRules())));
});

it('data/rule-summary.generated.json matches the inventory and maturity list', () => {
  const committed = readFileSync(join(__dirname, '../../data/rule-summary.generated.json'), 'utf8');
  assert.equal(committed, summaryJson(auditRules()));
});
