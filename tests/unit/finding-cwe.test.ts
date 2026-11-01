import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { cweForFinding, cweSarifTag, cweUrl } from '../../lib/finding-cwe';
import { generateSarifReport } from '../../lib/report-exporter';
import type { Project } from '../../data/schema';

const sec = (title: string, ruleId = 1) => cweForFinding({ type: 'SECURITY', title, ruleId });

describe('cweForFinding', () => {
  it('maps standard vulnerability names', () => {
    assert.equal(sec('SQL Injection: String Concatenation in Query'), 'CWE-89');
    assert.equal(sec('MongoDB NoSQL Injection via $where'), 'CWE-943');
    assert.equal(sec('Command Injection via Child Process'), 'CWE-78');
    assert.equal(sec('Direct InnerHTML Mutation (XSS Risk)'), 'CWE-79');
    assert.equal(sec('Hardcoded API Key in Source'), 'CWE-798');
  });

  it('uses the rule id for titles without a standard name', () => {
    assert.equal(sec('Struts Development Mode Enabled', 31008), 'CWE-489');
  });

  it('stays empty when nothing is certain', () => {
    assert.equal(sec('Public Bucket Lists Every File'), undefined);
    assert.equal(sec('Hardcoded Color Value'), undefined);
  });

  it('never tags findings that are not security findings', () => {
    assert.equal(cweForFinding({ type: 'VIBEPOLISH', title: 'XSS in a label', ruleId: 1 }), undefined);
  });

  it('builds the link and the SARIF tag', () => {
    assert.equal(cweUrl('CWE-89'), 'https://cwe.mitre.org/data/definitions/89.html');
    assert.equal(cweSarifTag('CWE-89'), 'external/cwe/cwe-89');
  });
});

describe('SARIF CWE tags', () => {
  const tags = (title: string): string[] => {
    const project = { findings: [{ id: 'a', ruleId: 1, type: 'SECURITY', title, category: 'Injection', severity: 'HIGH', filePath: 'a.ts', remediationPrompt: 'x' }] } as unknown as Project;
    return JSON.parse(generateSarifReport(project)).runs[0].tool.driver.rules[0].properties.tags;
  };

  it('adds the tag for a mapped finding only', () => {
    assert.ok(tags('SQL Injection in Query').includes('external/cwe/cwe-89'));
    assert.ok(!tags('Public Bucket Lists Every File').some((t) => t.startsWith('external/cwe/')));
  });
});
