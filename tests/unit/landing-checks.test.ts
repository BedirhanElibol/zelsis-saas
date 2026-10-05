import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan } from '../../lib/scanner-engine';
import { LANDING_CHECKS } from '../../data/landing-checks';

const firedRuleIds = async (path: string, content: string) =>
  new Set((await runStaticCodeScan([{ path, content }], 'landing')).findings.map((f) => f.ruleId));

describe('landing page showcase checks are real', () => {
  for (const check of LANDING_CHECKS) {
    it(`${check.code}: vulnerable snippet is caught`, async () => {
      assert.ok((await firedRuleIds(check.path, check.bad)).has(check.ruleId), `rule ${check.ruleId} did not fire on the advertised example`);
    });
    it(`${check.code}: fixed snippet is clean`, async () => {
      assert.ok(!(await firedRuleIds(check.path, check.good)).has(check.ruleId), `rule ${check.ruleId} fired on the advertised fix`);
    });
  }
});
