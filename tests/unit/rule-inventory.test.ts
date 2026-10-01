import { it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { auditRules } from '../../scripts/rule-audit';

it('data/rule-inventory.generated.json matches the rule sources (run `npm run audit:rules`)', () => {
  const committed = JSON.parse(readFileSync(join(__dirname, '../../data/rule-inventory.generated.json'), 'utf8'));
  assert.deepEqual(committed, JSON.parse(JSON.stringify(auditRules())));
});
