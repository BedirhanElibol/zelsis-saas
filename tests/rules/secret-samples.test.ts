import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan } from '../../lib/scanner-engine';
import { SECRET_SAMPLES } from './secret-samples.generated';

/**
 * Every secret rule must fire on a credential shaped like its own signature and stay silent when
 * the value comes from the environment. Regenerate samples with scripts/gen-secret-fixtures.ts.
 */
const asSource = (sample: string) =>
  /[=:]|-----/.test(sample) ? `${sample}\n` : `export const credential = "${sample}";\n`;

for (const [ruleId, sample] of SECRET_SAMPLES) {
  test(`secret rule ${ruleId} detects its signature and ignores env-based config`, async () => {
    const hit = await runStaticCodeScan([{ path: 'src/config/credentials.ts', content: asSource(sample) }], 'secret-detect');
    const finding = hit.findings.find((f) => f.ruleId === ruleId);
    assert.ok(finding, `rule ${ruleId} did not fire on its sample`);
    const longest = sample.split(/[\s"'=:]+/).sort((a, b) => b.length - a.length)[0];
    if (longest.length >= 16) assert.ok(!finding.snippet.includes(longest), `rule ${ruleId} leaks the secret in its snippet`);
    const clean = await runStaticCodeScan([{ path: 'src/config/credentials.ts', content: 'export const credential = process.env.SERVICE_CREDENTIAL;\n' }], 'secret-clean');
    assert.ok(!clean.findings.some((f) => f.ruleId === ruleId), `rule ${ruleId} fired on env-based config`);
  });
}
