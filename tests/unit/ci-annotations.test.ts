import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildWorkflowAnnotations, MAX_ANNOTATIONS_PER_LEVEL, parseLineRange } from '../../lib/ci-annotations';
import { buildGateWorkflow } from '../../lib/ci-gate-snippet';

test('parseLineRange reads the scanner formats', () => {
  assert.deepEqual(parseLineRange('L12'), [12, 12]);
  assert.deepEqual(parseLineRange('L12-L18'), [12, 18]);
  assert.deepEqual(parseLineRange('12-18'), [12, 18]);
  assert.equal(parseLineRange(''), null);
  assert.equal(parseLineRange(undefined), null);
});

test('findings become error/warning workflow commands on their line', () => {
  const lines = buildWorkflowAnnotations([
    { title: 'SQL injection', severity: 'CRITICAL', filePath: 'app/api/users/route.ts', lineRange: 'L14' },
    { title: 'Weak header', severity: 'MEDIUM', filePath: 'next.config.js', lineRange: 'L3-L5' },
    { title: 'Low thing', severity: 'LOW', filePath: 'a.ts', lineRange: 'L1' },
  ]);
  assert.deepEqual(lines, [
    '::error file=app/api/users/route.ts,line=14,title=Zelsis CRITICAL::SQL injection',
    '::warning file=next.config.js,line=3,endLine=5,title=Zelsis MEDIUM::Weak header',
  ]);
});

test('repository-controlled text cannot inject extra workflow commands', () => {
  const [line] = buildWorkflowAnnotations([
    { title: 'evil\n::add-mask::secret', severity: 'HIGH', filePath: 'a,b:c.ts', lineRange: 'L2' },
  ]);
  assert.equal(line, '::error file=a%2Cb%3Ac.ts,line=2,title=Zelsis HIGH::evil%0A::add-mask::secret');
  assert.ok(!line.includes('\n'));
});

test('critical first, experimental and line-less findings skipped, capped per level', () => {
  const many = Array.from({ length: 15 }, (_, i) => ({ title: `h${i}`, severity: 'HIGH', filePath: 'a.ts', lineRange: `L${i + 1}` }));
  const lines = buildWorkflowAnnotations([
    ...many,
    { title: 'crit', severity: 'CRITICAL', filePath: 'b.ts', lineRange: 'L9' },
    { title: 'exp', severity: 'CRITICAL', filePath: 'c.ts', lineRange: 'L1', maturity: 'experimental' },
    { title: 'nowhere', severity: 'CRITICAL', filePath: 'd.ts', lineRange: '' },
  ]);
  assert.equal(lines.length, MAX_ANNOTATIONS_PER_LEVEL);
  assert.match(lines[0], /::crit$/);
  assert.ok(!lines.some((l) => /exp$|nowhere$/.test(l)));
});

test('the customer workflow prints the annotations the gate returns', () => {
  assert.match(buildGateWorkflow({ appUrl: 'https://example.test' }), /jq -r '\.annotations\[\]\? \/\/ empty' zelsis-report\.json/);
});
