import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSoc2Mapping, mapFindingToControls, SOC2_CONTROLS } from '../../lib/soc2-mapping';
import type { Finding } from '../../data/schema';

const finding = (over: Partial<Finding>): Finding =>
  ({ id: 'f', ruleId: 1, type: 'SECURITY', title: '', severity: 'HIGH', category: '', filePath: 'a.ts', lineRange: 'L1', snippet: '', reproductionSteps: [], remediationPrompt: '', status: 'OPEN', ...over }) as Finding;

test('maps findings to the SOC 2 controls their category describes', () => {
  assert.ok(mapFindingToControls(finding({ category: 'Secrets', title: 'Hardcoded API key' })).includes('CC6.7'));
  assert.ok(mapFindingToControls(finding({ category: 'Database', title: 'Supabase table without RLS' })).includes('CC6.1'));
  assert.ok(mapFindingToControls(finding({ category: 'Network', title: 'SSRF via fetch(user url)' })).includes('CC6.6'));
});

test('unmatched security findings fall back to vulnerability management, UI findings map to nothing', () => {
  assert.deepEqual(mapFindingToControls(finding({ category: 'Misc', title: 'Something odd' })), ['CC7.1']);
  assert.deepEqual(mapFindingToControls(finding({ type: 'VIBEPOLISH', title: 'Purple gradient hero' })), []);
});

test('mapping lists every control and only counts open findings', () => {
  const rows = buildSoc2Mapping([
    finding({ title: 'Hardcoded secret token' }),
    finding({ title: 'Hardcoded secret token', status: 'RESOLVED' }),
  ]);
  assert.equal(rows.length, SOC2_CONTROLS.length);
  assert.equal(rows.find((r) => r.control.id === 'CC6.7')?.findings.length, 1);
});
