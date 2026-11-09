import { test } from 'node:test';
import assert from 'node:assert/strict';
import { manifestForLockfile, parseUpgradeTarget, upgradeManifest } from '@/lib/github/manifest-upgrade';

test('parseUpgradeTarget reads the target written by the OSV finding', () => {
  const prompt = 'Upgrade lodash from 4.17.15 to 4.17.21 or later (the highest fixed version across its advisories), regenerate the lockfile, and re-run the tests.';
  assert.deepEqual(parseUpgradeTarget(prompt), { name: 'lodash', from: '4.17.15', to: '4.17.21' });
  assert.equal(parseUpgradeTarget('Remove foo@1.0.0 and rotate every secret.'), null);
  assert.equal(parseUpgradeTarget(undefined), null);
});

test('manifestForLockfile maps an npm lockfile to the package.json beside it', () => {
  assert.equal(manifestForLockfile('package-lock.json'), 'package.json');
  assert.equal(manifestForLockfile('apps/web/package-lock.json'), 'apps/web/package.json');
  assert.equal(manifestForLockfile('apps/web/package.json'), 'apps/web/package.json');
  assert.equal(manifestForLockfile('yarn.lock'), null, 'other lockfiles are not upgraded yet');
});

test('upgradeManifest bumps a direct dependency and keeps its range style', () => {
  const src = '{\n  "name": "app",\n  "dependencies": {\n    "lodash": "^4.17.15",\n    "left-pad": "~1.3.0"\n  },\n  "devDependencies": {\n    "mocha": "9.0.0"\n  }\n}\n';
  const out = upgradeManifest(src, 'lodash', '4.17.21');
  assert.ok(out);
  const parsed = JSON.parse(out);
  assert.equal(parsed.dependencies.lodash, '^4.17.21');
  assert.equal(parsed.dependencies['left-pad'], '~1.3.0');
  assert.equal(upgradeManifest(src, 'mocha', '9.0.1')?.includes('"mocha": "9.0.1"'), true, 'exact pins stay exact');
  assert.ok(out.startsWith('{\n  "name"'), 'two-space indent is kept');
});

test('upgradeManifest returns null for transitive or non-registry specs', () => {
  const src = JSON.stringify({ dependencies: { alias: 'npm:left-pad@1.0.0', tool: 'git+https://x/y.git' } }, null, 2);
  assert.equal(upgradeManifest(src, 'minimist', '1.2.6'), null, 'not a direct dependency');
  assert.equal(upgradeManifest(src, 'alias', '1.0.1'), null, 'alias specs are left alone');
  assert.equal(upgradeManifest(src, 'tool', '1.0.1'), null, 'git specs are left alone');
  assert.equal(upgradeManifest(src, 'constructor', '1.0.1'), null, 'inherited object keys are not dependencies');
});
