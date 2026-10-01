import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan } from '../../lib/scanner-engine';
import { RULE_CASES } from './cases';

const ruleIdsFor = async (files: Parameters<typeof runStaticCodeScan>[0]) =>
  new Set((await runStaticCodeScan(files, 'fixture')).findings.map((f) => f.ruleId));

describe('rule fixtures', () => {
  for (const c of RULE_CASES) {
    describe(`#${c.ruleId} ${c.name}`, () => {
      it('detects the vulnerable fixture', async () => {
        assert.ok((await ruleIdsFor(c.detects)).has(c.ruleId), `rule ${c.ruleId} did not fire`);
      });

      it('ignores the safe fixture (no false positive)', async () => {
        assert.ok(!(await ruleIdsFor(c.ignores)).has(c.ruleId), `rule ${c.ruleId} fired on safe code`);
      });
    });
  }
});
