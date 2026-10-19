import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lockFindingLocations, redactScanResultFixes, folderOf } from '@/lib/fix-gate';
import type { ScanResult } from '@/lib/scanner-engine';

const finding = (id: string, severity: string, filePath: string) => ({
  id, ruleId: 1, type: 'SECURITY', title: `t-${id}`, severity, category: 'Access Control', filePath,
  lineRange: 'L10', snippet: 'secret line', reproductionSteps: ['step'], remediationPrompt: 'fix it', status: 'OPEN', falsePositive: false,
});

const result = {
  score: 40, gateStatus: 'FAILED', criticalCount: 2, highCount: 1, mediumCount: 1, lowCount: 0, uiClicheCount: 0,
  findings: [
    finding('a', 'HIGH', 'app/api/a/route.ts'),
    finding('b', 'CRITICAL', 'app/api/pay/route.ts'),
    finding('c', 'MEDIUM', 'lib/x.ts'),
    finding('d', 'CRITICAL', 'supabase/migrations/001.sql'),
  ],
  logs: [], summary: '',
} as unknown as ScanResult;

test('folderOf keeps only the folder', () => {
  assert.equal(folderOf('app/api/pay/route.ts'), 'app/api/pay/');
  assert.equal(folderOf('README.md'), './');
});

test('Free private result: first critical stays whole, other serious findings lose file, line and snippet', () => {
  const { result: redacted, fixes } = redactScanResultFixes(result, 'job1');
  const { result: locked, lockedCount } = lockFindingLocations(redacted, fixes);
  assert.equal(lockedCount, 2);

  const [a, b, c, d] = locked.findings;
  assert.equal(b.filePath, 'app/api/pay/route.ts', 'most severe finding is shown in full');
  assert.equal(b.lockedLocation, undefined);
  assert.equal(c.filePath, 'lib/x.ts', 'medium findings are not locked');

  for (const f of [a, d]) {
    assert.equal(f.lockedLocation, true);
    assert.equal(f.lineRange, '');
    assert.equal(f.snippet, '');
    assert.deepEqual(f.reproductionSteps, []);
    assert.ok(f.filePath.endsWith('/'));
  }
  const snippetsLeft = JSON.stringify(locked.findings).split('secret line').length - 1;
  assert.equal(snippetsLeft, 2, 'only the open critical and the medium finding keep their snippet');
  assert.equal(fixes[d.lockedFix!.ref].location?.filePath, 'supabase/migrations/001.sql', 'location kept server-side');
});
