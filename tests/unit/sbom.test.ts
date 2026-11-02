import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSbom, purlFor } from '../../lib/scanner/sbom';
import { extractDependencies, type Dependency } from '../../lib/scanner/dependencies';
import { isDependencyPath } from '../../packages/cli/lib.mjs';

const dep = (over: Partial<Dependency>): Dependency => ({ ecosystem: 'npm', name: 'lodash', version: '4.17.21', file: 'package-lock.json', line: 1, dev: false, ...over });

test('purlFor follows each ecosystem', () => {
  assert.equal(purlFor(dep({ name: '@babel/core', version: '7.0.0' })), 'pkg:npm/%40babel/core@7.0.0');
  assert.equal(purlFor(dep({ ecosystem: 'PyPI', name: 'Flask_Login', version: '1.0' })), 'pkg:pypi/flask-login@1.0');
  assert.equal(purlFor(dep({ ecosystem: 'Maven', name: 'org.apache:commons', version: '3.1' })), 'pkg:maven/org.apache/commons@3.1');
  assert.equal(purlFor(dep({ ecosystem: 'Go', name: 'github.com/a/b', version: 'v1.2.0' })), 'pkg:golang/github.com/a/b@v1.2.0');
});

test('CycloneDX merges duplicates and marks dev-only packages', () => {
  const bom = buildSbom([
    dep({ dev: true }),
    dep({ file: 'web/package-lock.json', dev: false }),
    dep({ name: 'vitest', version: '1.0.0', dev: true }),
  ], { format: 'cyclonedx', projectName: 'app' }) as { specVersion: string; components: { name: string; scope: string }[]; metadata: { component: { name: string } } };
  assert.equal(bom.specVersion, '1.6');
  assert.equal(bom.metadata.component.name, 'app');
  assert.deepEqual(bom.components.map((c) => [c.name, c.scope]), [['lodash', 'required'], ['vitest', 'excluded']]);
});

test('SPDX links every package and asserts no license', () => {
  const doc = buildSbom([dep({})], { format: 'spdx', projectName: 'my app' }) as { spdxVersion: string; packages: { licenseConcluded: string }[]; relationships: { relationshipType: string; relatedSpdxElement: string }[] };
  assert.equal(doc.spdxVersion, 'SPDX-2.3');
  assert.equal(doc.packages.length, 2);
  assert.ok(doc.packages.every((p) => p.licenseConcluded === 'NOASSERTION'));
  assert.ok(doc.relationships.some((r) => r.relationshipType === 'DEPENDS_ON' && r.relatedSpdxElement === 'SPDXRef-Package-1'));
});

test('a real lockfile becomes components', () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'x' }, 'node_modules/lodash': { version: '4.17.21' } } });
  const bom = buildSbom(extractDependencies([{ path: 'package-lock.json', content: lock }]), { format: 'cyclonedx' }) as { components: { purl: string }[] };
  assert.deepEqual(bom.components.map((c) => c.purl), ['pkg:npm/lodash@4.17.21']);
});

test('the CLI collects only dependency files', () => {
  for (const p of ['package-lock.json', 'web/yarn.lock', 'requirements-dev.txt', 'go.mod', 'pom.xml', 'Cargo.lock']) assert.ok(isDependencyPath(p), p);
  for (const p of ['src/index.ts', 'package.json', '.env']) assert.ok(!isDependencyPath(p), p);
});
