import { test } from 'node:test';
import assert from 'node:assert/strict';
import { alignPatches, lineDiff, patchFitsFile } from '@/lib/scanner/patches';
import { suggestedLine } from '@/lib/github/suggestions';
import { runStaticCodeScan } from '@/lib/scanner-engine';
import type { Finding } from '@/data/schema';

const finding = (over: Partial<Finding>): Finding => ({ id: 'f1', ruleId: 0, title: 't', severity: 'HIGH', filePath: 'a.ts', lineRange: 'L2', ...over } as Finding);

test('patchFitsFile accepts a patch whose removed lines are in the file', () => {
  const content = 'const a = 1;\njwt.verify(token, secret);\n';
  assert.equal(patchFitsFile('--- a/x\n+++ b/x\n@@ -2,1 +2,1 @@\n-jwt.verify(token, secret);\n+jwt.verify(token, secret, { algorithms: ["HS256"] });', content), true);
});

test('patchFitsFile rejects a sample patch for code the file does not have', () => {
  const content = 'const file = await readFile(input);\n';
  assert.equal(patchFitsFile('--- a/x\n+++ b/x\n@@ -1,2 +1,3 @@\n-const content = await fs.promises.readFile(req.query.file);\n+const safe = path.basename(req.query.file);', content), false);
});

test('patchFitsFile checks context lines when a patch only adds', () => {
  assert.equal(patchFitsFile('@@ -1,2 +1,3 @@\n FROM node:20-alpine AS runner\n+USER node', 'FROM python:3.12\n'), false);
  assert.equal(patchFitsFile('@@ -1,2 +1,3 @@\n FROM node:20-alpine AS runner\n+USER node', 'FROM node:20-alpine AS runner\n'), true);
});

test('alignPatches drops an unfitting patch and builds a real one-line diff', () => {
  const content = 'import x from "y";\nconst agent = new https.Agent({ rejectUnauthorized: false });\n';
  const sample = finding({ ruleId: 12304, diffPatch: '-something.else();\n+fixed();' });
  const noFix = finding({ ruleId: 999999, diffPatch: '-missing();\n+fixed();' });
  alignPatches([sample, noFix], 'a.ts', content);
  assert.equal(sample.diffPatch, lineDiff('a.ts', 2, 'const agent = new https.Agent({ rejectUnauthorized: false });', 'const agent = new https.Agent({ rejectUnauthorized: true });'));
  assert.equal(noFix.diffPatch, undefined);
});

test('XXE line fixes turn entity expansion off', () => {
  assert.equal(suggestedLine(24002, 'libxmljs.parseXml(body, { noent: true })'), 'libxmljs.parseXml(body, { noent: false })');
  assert.equal(suggestedLine(24104, 'parser = etree.XMLParser(resolve_entities=True)'), 'parser = etree.XMLParser(resolve_entities=False)');
  assert.equal(suggestedLine(24104, 'settings.DtdProcessing = DtdProcessing.Parse;'), 'settings.DtdProcessing = DtdProcessing.Prohibit;');
});

test('a scan gives a fixable finding a diff of its own line', async () => {
  const code = 'import https from "https";\nexport const agent = new https.Agent({ rejectUnauthorized: false });\n';
  const result = await runStaticCodeScan([{ path: 'src/agent.ts', content: code }], 'demo/repo');
  const f = result.findings.find((x) => x.ruleId === 12304);
  assert.ok(f, 'TLS-04 should fire');
  assert.match(f.diffPatch ?? '', /^-export const agent = new https\.Agent\(\{ rejectUnauthorized: false \}\);$/m);
  assert.match(f.diffPatch ?? '', /^\+export const agent = new https\.Agent\(\{ rejectUnauthorized: true \}\);$/m);
  for (const x of result.findings) if (x.diffPatch) assert.ok(patchFitsFile(x.diffPatch, code), `${x.ruleId} patch must fit the file`);
});
