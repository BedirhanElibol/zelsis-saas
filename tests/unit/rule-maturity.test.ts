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

  it('the formerly noisy rules were fixed instead of staying experimental', async () => {
    for (const id of [20, 8803, 27211]) assert.equal(isExperimentalRule(id), false, `rule ${id}`);
    // PY-SEC-03 is HIGH only where a web request can reach the shell command
    const scan = async (content: string) => (await runStaticCodeScan([{ path: 'app/services/backup.py', content }], 'x')).findings.find((f) => f.ruleId === 8803);
    const operator = await scan('import subprocess\n\n\ndef archive(dir):\n    subprocess.run(f"tar -czf /backups/a.tgz {dir}", shell=True, check=True)\n');
    const web = await scan('import subprocess\nfrom flask import request\n\n\ndef archive():\n    name = request.args["name"]\n    subprocess.run(f"tar -czf /backups/{name}.tgz /uploads", shell=True, check=True)\n');
    assert.equal(operator?.severity, 'MEDIUM');
    assert.equal(web?.severity, 'HIGH');
  });

  it('keeps reviewed true-positive and fixture-proven rules gating', () => {
    for (const id of [1, 3, 32, 33, 34, 3021, 23004]) assert.equal(isExperimentalRule(id), false, `rule ${id}`);
  });
});
