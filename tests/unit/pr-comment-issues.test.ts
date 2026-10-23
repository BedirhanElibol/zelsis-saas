import { test } from 'node:test';
import assert from 'node:assert/strict';
import { topIssuesSection } from '@/app/api/v1/github-app/webhook/route';

const finding = (severity: string, title: string, line = 3) => ({ severity, title, filePath: 'src/a.ts', lineRange: `${line}-${line}` });

test('PR comment names medium findings below the blocking ones', () => {
  const out = topIssuesSection([finding('MEDIUM', 'N+1 query', 7), finding('HIGH', 'Missing auth check')]);
  assert.match(out, /What needs a look/);
  assert.ok(out.indexOf('Missing auth check') < out.indexOf('**Medium**'));
  assert.match(out, /\*\*N\+1 query\*\* \(`src\/a\.ts:7`\)/);
});

test('PR comment lists medium findings when there is nothing blocking', () => {
  const out = topIssuesSection([finding('MEDIUM', 'Cookie banner without reject'), finding('LOW', 'Console log')]);
  assert.match(out, /Cookie banner without reject/);
  assert.doesNotMatch(out, /\*\*Medium\*\*/);
  assert.doesNotMatch(out, /Console log/);
});

test('PR comment caps medium findings at ten', () => {
  const out = topIssuesSection(Array.from({ length: 13 }, (_, i) => finding('MEDIUM', `Issue ${i}`)));
  assert.match(out, /Issue 9\*\*/);
  assert.doesNotMatch(out, /Issue 10\*\*/);
  assert.match(out, /and 3 more medium findings/);
});

test('PR comment section is empty with only low findings', () => {
  assert.equal(topIssuesSection([finding('LOW', 'Console log')]), '');
});

test('check run keeps its name so required status checks still match', async () => {
  const { CHECK_NAME, RELEASE_CHECK_TITLE } = await import('@/lib/github/app');
  assert.equal(CHECK_NAME, 'Zelsis Security Gate');
  assert.equal(RELEASE_CHECK_TITLE, 'Zelsis Release Check');
});
