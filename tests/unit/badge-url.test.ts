import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { badgeUrlFor } from '../../lib/badge-url';

const APP = 'https://app.test';

test('GitHub projects get a repo badge, saved projects an id badge, local-only projects none', () => {
  assert.equal(badgeUrlFor({ id: 'proj-import-1', repoUrl: 'https://github.com/expressjs/express' }, APP), `${APP}/api/v1/badge?repo=expressjs/express`);
  assert.equal(badgeUrlFor({ id: 'x', repoUrl: 'vercel/next.js.git' }, APP), `${APP}/api/v1/badge?repo=vercel/next.js`);
  const uuid = '5af6c548-7a9f-44f4-bd17-997559585873';
  assert.equal(badgeUrlFor({ id: uuid, repoUrl: 'local' }, APP), `${APP}/api/v1/badge?projectId=${uuid}`);
  assert.equal(badgeUrlFor({ id: 'proj-1', repoUrl: 'local' }, APP), null);
  assert.equal(badgeUrlFor(null, APP), null);
});

test('the badge never shows the caller-supplied status for a project it could not find', () => {
  const route = readFileSync(join(__dirname, '../../app/api/v1/badge/route.ts'), 'utf8');
  assert.match(route, /if \(!isVerified\) \{/);
  assert.match(route, /'NOT SCANNED'/);
  assert.match(route, /\.eq\('is_private', false\)/, 'repo lookups must be limited to public repositories');
});
