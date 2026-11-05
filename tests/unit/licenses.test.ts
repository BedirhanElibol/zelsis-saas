import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildLicenseFindings, licenseClass } from '../../lib/scanner/licenses';
import { extractDependencies } from '../../lib/scanner/dependencies';

test('licenseClass picks the strictest term you cannot avoid', () => {
  assert.equal(licenseClass('AGPL-3.0-only'), 'network-copyleft');
  assert.equal(licenseClass('SSPL-1.0'), 'network-copyleft');
  assert.equal(licenseClass('GPL-3.0-or-later'), 'copyleft');
  assert.equal(licenseClass('LGPL-2.1'), null, 'LGPL is weak copyleft');
  assert.equal(licenseClass('MIT'), null);
  assert.equal(licenseClass('(MIT OR GPL-3.0)'), null, 'you may pick MIT');
  assert.equal(licenseClass('(AGPL-3.0 OR GPL-2.0)'), 'copyleft', 'the softer alternative still binds');
  assert.equal(licenseClass('MIT AND AGPL-3.0'), 'network-copyleft', 'AND means both apply');
  assert.equal(licenseClass('GPL-2.0 WITH Classpath-exception-2.0'), 'copyleft');
  assert.equal(licenseClass(undefined), null);
});

test('package-lock and composer.lock licenses reach LIC-01/02, dev packages are skipped', () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: {
    '': { name: 'app', version: '1.0.0' },
    'node_modules/ghostscript-lib': { version: '2.0.0', license: 'AGPL-3.0' },
    'node_modules/readline-ish': { version: '1.0.0', license: 'GPL-3.0' },
    'node_modules/test-only-agpl': { version: '1.0.0', license: 'AGPL-3.0', dev: true },
    'node_modules/lodash': { version: '4.17.21', license: 'MIT' },
  } }, null, 2);
  const composer = JSON.stringify({ packages: [{ name: 'acme/pdf', version: 'v1.2.0', license: ['AGPL-3.0-or-later'] }, { name: 'acme/dual', version: '1.0.0', license: ['MIT', 'GPL-2.0'] }] }, null, 2);
  const deps = extractDependencies([{ path: 'package-lock.json', content: lock }, { path: 'composer.lock', content: composer }]);
  const findings = buildLicenseFindings(deps, new Map());
  assert.deepEqual(findings.map((f) => `${f.ruleId}:${f.title.split(':')[1].trim().split(' ')[0]}`).sort(), ['26003:acme/pdf', '26003:ghostscript-lib', '26004:readline-ish']);
  assert.ok(findings.every((f) => f.type === 'LEGAL_COMPLIANCE'));
});
