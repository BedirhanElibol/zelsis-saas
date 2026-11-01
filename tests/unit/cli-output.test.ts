import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { meetsThreshold, parseSeverity, toSarif } from '../../packages/cli/lib.mjs';

const finding = (severity: string, extra = {}) => ({ ruleId: 33, title: 'Command Injection', severity, filePath: 'a.js', lineRange: 'L4', fix: 'Use execFile', ...extra });

test('parseSeverity accepts any case and rejects other values', () => {
  assert.equal(parseSeverity('high'), 'HIGH');
  assert.equal(parseSeverity('urgent'), undefined);
  assert.equal(parseSeverity(undefined), undefined);
});

test('meetsThreshold is at or above the severity', () => {
  const result = { findings: [finding('MEDIUM')] };
  assert.equal(meetsThreshold(result, 'LOW'), true);
  assert.equal(meetsThreshold(result, 'MEDIUM'), true);
  assert.equal(meetsThreshold(result, 'HIGH'), false);
  assert.equal(meetsThreshold({ findings: [] }, 'LOW'), false);
});

test('toSarif maps level, location and the CWE tag', () => {
  const sarif = toSarif({ findings: [finding('HIGH', { cweId: 'CWE-78' }), finding('LOW', { ruleId: 7 })] });
  const run = sarif.runs[0];
  assert.equal(sarif.version, '2.1.0');
  assert.equal(run.results[0].level, 'error');
  assert.equal(run.results[1].level, 'note');
  assert.equal(run.results[0].locations[0].physicalLocation.region.startLine, 4);
  assert.deepEqual(run.tool.driver.rules[0].properties.tags, ['external/cwe/cwe-78']);
  assert.equal(run.tool.driver.rules[1].properties, undefined);
});

test('an invalid threshold exits 2 before any scan', () => {
  const r = spawnSync(process.execPath, [join('packages', 'cli', 'bin', 'zelsis.mjs'), 'check', '--severity-threshold=urgent'], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /severity-threshold/);
});
