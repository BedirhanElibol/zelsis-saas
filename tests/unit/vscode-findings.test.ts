import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { toProblems, summary } = require('../../packages/vscode/findings.js');

test('toProblems groups by file with 0-based lines and severity levels', () => {
  const byFile = toProblems({ findings: [
    { ruleId: 33, title: 'Command Injection', severity: 'CRITICAL', filePath: 'a.js', lineRange: 'L4', fix: 'Use execFile', cweId: 'CWE-78' },
    { ruleId: 7, title: 'Slow query', severity: 'MEDIUM', filePath: 'a.js' },
    { ruleId: 9, title: 'Note', severity: 'LOW', filePath: 'b.py', lineRange: 'L1-L3' },
  ] });
  const a = byFile.get('a.js');
  assert.equal(a.length, 2);
  assert.deepEqual(a[0], { line: 3, severity: 0, message: 'Command Injection\n\nUse execFile', code: 'ZLS-33', cweId: 'CWE-78' });
  assert.equal(a[1].line, 0);
  assert.equal(a[1].severity, 1);
  assert.equal(byFile.get('b.py')[0].severity, 2);
});

test('summary reports the gate and count', () => {
  assert.equal(summary({ gateStatus: 'FAILED', findings: [{}] }), 'Zelsis FAILED: 1 finding');
  assert.equal(summary({ nothingChanged: true, findings: [] }), 'Zelsis: no changed files');
});
