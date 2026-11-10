import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isTestFixturePath } from '@/lib/scanner/text';

test('test runner setup files are test code, including camelCase names', () => {
  for (const p of ['apps/web/vitestSetup.ts', 'src/setupTests.ts', 'jestSetup.js', 'vitest.setup.ts', 'test-setup.ts']) {
    assert.equal(isTestFixturePath(p), true, p);
  }
});

test('app setup files are not test code', () => {
  for (const p of ['src/db.setup.ts', 'lib/passport.setup.js', 'apps/web/setup.ts']) {
    assert.equal(isTestFixturePath(p), false, p);
  }
});
