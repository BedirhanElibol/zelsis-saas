import { test } from 'node:test';
import assert from 'node:assert/strict';
import { addedLines, buildSuggestionComments, suggestedLine } from '@/lib/github/suggestions';
import { runStaticCodeScan } from '@/lib/scanner-engine';

test('addedLines maps added rows to new-side line numbers across hunks', () => {
  const patch = [
    '@@ -1,3 +1,4 @@',
    ' a',
    '-b',
    '+B',
    '+c',
    ' d',
    '@@ -10,2 +11,3 @@',
    ' x',
    '+y',
    ' z',
    '\\ No newline at end of file',
  ].join('\n');
  assert.deepEqual([...addedLines(patch)], [2, 3, 12]);
  assert.equal(addedLines(undefined).size, 0);
});

test('suggestedLine fixes only the flagged setting and skips lines it cannot fix safely', () => {
  assert.equal(suggestedLine(12304, '  agent: new https.Agent({ rejectUnauthorized: false }),'), '  agent: new https.Agent({ rejectUnauthorized: true }),');
  assert.equal(suggestedLine(9303, '<application android:usesCleartextTraffic="true">'), '<application android:usesCleartextTraffic="false">');
  assert.equal(suggestedLine(8802, 'cfg = yaml.load(f)'), 'cfg = yaml.safe_load(f)');
  assert.equal(suggestedLine(8802, 'cfg = yaml.load(f, Loader=yaml.Loader)'), null);
  assert.equal(suggestedLine(28813, "app.run(host='0.0.0.0', debug=True)"), "app.run(host='0.0.0.0', debug=False)");
  assert.equal(
    suggestedLine(1244, '<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">'),
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
  );
  assert.equal(suggestedLine(23004, 'amount: body.amount'), null);
});

test('scanner findings on added lines become suggested changes; untouched lines do not', async () => {
  const content = [
    "import https from 'https';",
    'export const agent = new https.Agent({ rejectUnauthorized: false });',
  ].join('\n');
  const files = [{ path: 'src/http.ts', content }];
  const contentByPath = new Map([['src/http.ts', content]]);
  const { findings } = await runStaticCodeScan(files, 'suggest');
  assert.ok(findings.some((f) => f.ruleId === 12304), 'TLS-04 should fire');

  const onDiff = buildSuggestionComments(findings, contentByPath, new Map([['src/http.ts', new Set([2])]]));
  assert.equal(onDiff.length, 1);
  assert.equal(onDiff[0].line, 2);
  assert.match(onDiff[0].body, /```suggestion\nexport const agent = new https\.Agent\(\{ rejectUnauthorized: true \}\);\n```/);

  assert.equal(buildSuggestionComments(findings, contentByPath, new Map([['src/http.ts', new Set([1])]])).length, 0);
});
