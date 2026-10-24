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
  assert.equal(suggestedLine(9010, '\tcfg := &tls.Config{InsecureSkipVerify: true}'), '\tcfg := &tls.Config{InsecureSkipVerify: false}');
  assert.equal(suggestedLine(8818, 'r = requests.get(url, verify=False)'), 'r = requests.get(url, verify=True)');
  assert.equal(suggestedLine(28517, '          allowPrivilegeEscalation: true'), '          allowPrivilegeEscalation: false');
});

test('new one-line fixes land on the line the scanner flags', async () => {
  const cases = [
    { path: 'net/client.go', ruleId: 9010, content: 'package net\n\nimport "crypto/tls"\n\nvar cfg = &tls.Config{InsecureSkipVerify: true}\n' },
    { path: 'app/fetch.py', ruleId: 8818, content: 'import requests\n\ndef get(url):\n    return requests.get(url, verify=False)\n' },
    {
      path: 'k8s/deploy.yaml',
      ruleId: 28517,
      content: 'apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: api\n          image: api:1\n          securityContext:\n            allowPrivilegeEscalation: true\n',
    },
  ];
  for (const c of cases) {
    const { findings } = await runStaticCodeScan([{ path: c.path, content: c.content }], 'suggest');
    const hit = findings.filter((f) => f.ruleId === c.ruleId);
    assert.ok(hit.length > 0, `${c.ruleId} should fire`);
    const allLines = new Set(c.content.split('\n').map((_, i) => i + 1));
    const comments = buildSuggestionComments(hit, new Map([[c.path, c.content]]), new Map([[c.path, allLines]]));
    assert.equal(comments.length, 1, `${c.ruleId} should get one suggestion`);
  }
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
