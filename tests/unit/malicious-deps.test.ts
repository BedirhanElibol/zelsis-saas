import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildDependencyFindings } from '../../lib/scanner/osv';
import type { Dependency } from '../../lib/scanner/dependencies';

const dep: Dependency = { ecosystem: 'npm', name: '@solana/web3.js', version: '1.95.6', file: 'package-lock.json', line: 7, dev: true };

test('a MAL- report becomes its own CRITICAL finding, even for a dev dependency', () => {
  const findings = buildDependencyFindings([dep], [[
    { id: 'MAL-2024-11183', aliases: [], summary: 'Malicious code in @solana/web3.js', severity: 'MEDIUM' as const },
    { id: 'GHSA-jcxm-7wvp-g6p5', aliases: [], summary: 'Backdoor', severity: 'HIGH' as const, fixed: '1.95.8' },
  ]], new Map());
  const mal = findings.find((f) => f.ruleId === 26002);
  const vuln = findings.find((f) => f.ruleId === 26001);
  assert.ok(mal, 'DEP-02 for the MAL- report');
  assert.equal(mal.severity, 'CRITICAL');
  assert.match(mal.remediationPrompt ?? '', /rotate every secret/);
  assert.ok(vuln, 'the GHSA advisory stays a DEP-01 finding');
  assert.ok(!/MAL-/.test(vuln.title), 'DEP-01 no longer lists the MAL- report');
});

test('a package with only a MAL- report gets no DEP-01 finding', () => {
  const findings = buildDependencyFindings([dep], [[{ id: 'MAL-2025-1', aliases: [], summary: 'm', severity: 'MEDIUM' as const }]], new Map());
  assert.deepEqual(findings.map((f) => f.ruleId), [26002]);
});
