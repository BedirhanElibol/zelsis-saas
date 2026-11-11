import { test } from 'node:test';
import assert from 'node:assert/strict';
import { previewDetail } from '@/lib/scanner/preview-detail';

test('the preview detail carries the file, line, impact and a trimmed fix', () => {
  const d = previewDetail({ filePath: 'app/api/webhook/route.ts', lineRange: 'L42', impact: 'Anyone can grant a plan.', remediationPrompt: 'Verify the signature first.' });
  assert.deepEqual(d, { filePath: 'app/api/webhook/route.ts', line: 42, impact: 'Anyone can grant a plan.', fix: 'Verify the signature first.' });
});

test('a long fix is cut to 400 characters and a missing line is left out', () => {
  const long = 'x'.repeat(600);
  const d = previewDetail({ filePath: 'a.ts', lineRange: '', remediationPrompt: long });
  assert.equal(d.line, undefined);
  assert.equal(d.fix.length, 401);
  assert.ok(d.fix.endsWith('…'));
});
