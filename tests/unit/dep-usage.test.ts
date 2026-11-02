import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectImports, describeUsage } from '../../lib/scanner/dep-usage';
import { buildDependencyFindings } from '../../lib/scanner/osv';
import type { Dependency } from '../../lib/scanner/dependencies';

const index = collectImports([
  { path: 'src/a.ts', content: "import x from './local';\nimport _ from 'lodash/fp';\nconst s = require('@scope/pkg/sub');\nconst fs = await import('node:fs');\n" },
  { path: 'app/views.py', content: "import os\nfrom flask_login import login_user\n" },
  { path: 'tests/a.test.ts', content: "import vi from 'vitest';\n" },
  { path: 'node_modules/z/index.js', content: "require('hidden');\n" },
]);

test('collectImports reads package names and skips local, test and vendored code', () => {
  assert.deepEqual([...index.npm.keys()].sort(), ['@scope/pkg', 'lodash']);
  assert.deepEqual(index.npm.get('lodash'), { file: 'src/a.ts', line: 2 });
  assert.equal(index.python.get('flask_login')?.line, 2);
});

test('describeUsage names the import site', () => {
  assert.match(describeUsage({ ecosystem: 'npm', name: 'lodash' }, index)!, /src\/a\.ts:2/);
  assert.match(describeUsage({ ecosystem: 'PyPI', name: 'Flask-Login' }, index)!, /app\/views\.py:2/);
});

test('an unimported npm package is not called safe', () => {
  const text = describeUsage({ ecosystem: 'npm', name: 'vitest' }, index)!;
  assert.match(text, /Not imported directly/);
  assert.match(text, /can still load/);
});

test('no claim where names cannot be matched', () => {
  assert.equal(describeUsage({ ecosystem: 'PyPI', name: 'pyyaml' }, index), undefined);
  assert.equal(describeUsage({ ecosystem: 'Go', name: 'github.com/a/b' }, index), undefined);
});

test('the finding carries the sentence and keeps its severity', () => {
  const dep: Dependency = { ecosystem: 'npm', name: 'left-pad', version: '1.0.0', file: 'package-lock.json', line: 1, dev: false };
  const advisory = { id: 'GHSA-1', aliases: [], summary: 's', severity: 'CRITICAL' as const };
  const [imported] = buildDependencyFindings([{ ...dep, name: 'lodash' }], [[advisory]], new Map(), index);
  const [unused] = buildDependencyFindings([dep], [[advisory]], new Map(), index);
  assert.match(imported.reproductionSteps[1], /Imported directly/);
  assert.match(unused.reproductionSteps[1], /Not imported directly/);
  assert.equal(imported.severity, unused.severity);
});
