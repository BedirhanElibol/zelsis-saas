import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { Finding } from '../../data/schema';
import { calculateGateStatus, calculateReadinessScore, runStaticCodeScan } from '../../lib/scanner-engine';
import { isExperimentalRule } from '../../lib/scanner/rule-maturity';

const finding = (over: Partial<Finding>): Finding => ({
  id: 'f', ruleId: 1, type: 'SECURITY', title: 't', severity: 'CRITICAL', category: 'c', filePath: 'a.ts', lineRange: 'L1',
  snippet: '', reproductionSteps: [], remediationPrompt: '', status: 'OPEN', falsePositive: false, ...over
});

describe('rule maturity', () => {
  it('experimental findings do not decide the gate or score', () => {
    const experimental = finding({ maturity: 'experimental' });
    assert.equal(calculateGateStatus([experimental]), 'PASSED');
    assert.equal(calculateReadinessScore([experimental]), 100);
    assert.equal(calculateGateStatus([experimental, finding({})]), 'FAILED');
  });

  it('tags findings from rules proven noisy on the clean benchmark corpus', async () => {
    assert.ok(isExperimentalRule(9101), 'TENANT-01 fires on clean repos and was not reviewed as a true positive');
    const result = await runStaticCodeScan([
      { path: 'app/api/docs/route.ts', content: 'export async function GET() {\n  return Response.json(await prisma.doc.findMany({ where: { id: 1 } }));\n}\n' }
    ], 'x');
    const tenant = result.findings.find((f) => f.ruleId === 9101);
    assert.ok(tenant, 'experimental findings are still reported');
    assert.equal(tenant.maturity, 'experimental');
    assert.equal(result.experimentalCount, result.findings.filter((f) => f.maturity === 'experimental').length);
  });

  it('keeps reviewed true-positive and fixture-proven rules gating', () => {
    for (const id of [1, 3, 32, 33, 34, 3021, 23004]) assert.equal(isExperimentalRule(id), false, `rule ${id}`);
  });
});
