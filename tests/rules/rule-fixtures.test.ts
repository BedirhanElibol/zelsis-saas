import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan, type CodeFile } from '../../lib/scanner-engine';
import { KNOWN_GAPS, RULE_CASES } from './cases';

const ruleIdsFor = async (files: CodeFile[]) =>
  new Set((await runStaticCodeScan(files, 'fixture')).findings.map((f) => f.ruleId));

describe('rule fixtures', () => {
  for (const c of RULE_CASES) {
    describe(`${c.name} (#${c.ruleIds.join(', #')})`, () => {
      it('detects the vulnerable fixture', async () => {
        const found = await ruleIdsFor(c.detects);
        const missing = c.ruleIds.filter((id) => !found.has(id));
        assert.deepEqual(missing, [], `rules did not fire: ${missing.join(', ')}`);
      });

      it('ignores the fixed fixture (no false positive)', async () => {
        const found = await ruleIdsFor(c.ignores);
        const fired = c.ruleIds.filter((id) => found.has(id));
        assert.deepEqual(fired, [], `rules fired on safe code: ${fired.join(', ')}`);
      });
    });
  }
});

describe('known scanner gaps', () => {
  for (const gap of KNOWN_GAPS) {
    it(`[${gap.kind}] ${gap.name}`, { todo: 'move to RULE_CASES once fixed' }, async () => {
      const found = await ruleIdsFor(gap.files);
      if (gap.kind === 'false-positive') {
        assert.ok(gap.ruleId !== null && !found.has(gap.ruleId), `rule ${gap.ruleId} still fires`);
      } else {
        const securityFindings = (await runStaticCodeScan(gap.files, 'gap')).findings.filter((f) => f.type === 'SECURITY');
        assert.ok(securityFindings.length > 0, 'no security finding reported');
      }
    });
  }
});
