import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isNonAppPath } from '@/lib/scanner/text';
import { runStaticCodeScan } from '@/lib/scanner-engine';

test('isNonAppPath identifies documentation paths and markdown files', () => {
  assert.equal(isNonAppPath('docs/main.py'), true);
  assert.equal(isNonAppPath('docs_src/guide.py'), true);
  assert.equal(isNonAppPath('documentation/docs/intro.tsx'), true);
  assert.equal(isNonAppPath('README.md'), true);
  assert.equal(isNonAppPath('content/docs/quickstart.mdx'), true);
});

test('isNonAppPath identifies knowledge and teaching material paths', () => {
  assert.equal(isNonAppPath('backend/app/services/agent/knowledge/frameworks/flask.py'), true);
  assert.equal(isNonAppPath('cookbook/recipes/auth.py'), true);
  assert.equal(isNonAppPath('tutorials/intro.py'), true);
  assert.equal(isNonAppPath('courses/lesson1.py'), true);
  assert.equal(isNonAppPath('homework/assignment.py'), true);
});

test('isNonAppPath identifies seeders', () => {
  assert.equal(isNonAppPath('database/seeders/PrivateKeySeeder.php'), true);
  assert.equal(isNonAppPath('db/seeds/users.rb'), true);
  assert.equal(isNonAppPath('db/seeds.rb'), true);
  assert.equal(isNonAppPath('prisma/seed.ts'), true);
  assert.equal(isNonAppPath('database/seeders/UserSeeder.php'), true);
});

test('isNonAppPath identifies local and dev compose files but keeps production compose', () => {
  assert.equal(isNonAppPath('docker-compose.local.yml'), true);
  assert.equal(isNonAppPath('docker-compose.dev.yaml'), true);
  assert.equal(isNonAppPath('compose.local.yml'), true);
  assert.equal(isNonAppPath('docker-compose.test.yml'), true);
  assert.equal(isNonAppPath('docker-compose.sandbox.yaml'), true);

  // Production / plain docker-compose files stay app-level
  assert.equal(isNonAppPath('docker-compose.yml'), false);
  assert.equal(isNonAppPath('docker-compose.yaml'), false);
  assert.equal(isNonAppPath('compose.yml'), false);
});

test('isNonAppPath identifies repo root dev scripts and tooling', () => {
  assert.equal(isNonAppPath('run_mutmut.py'), true);
  assert.equal(isNonAppPath('scripts/deploy.py'), true);
  assert.equal(isNonAppPath('manage.py'), true);
  assert.equal(isNonAppPath('Makefile'), true);
  assert.equal(isNonAppPath('Rakefile'), true);
});

test('isNonAppPath keeps shipped application code blocking', () => {
  assert.equal(isNonAppPath('app/routes/auth.py'), false);
  assert.equal(isNonAppPath('src/controllers/payment.ts'), false);
  assert.equal(isNonAppPath('server/api/users.go'), false);
  assert.equal(isNonAppPath('api/checkout.rb'), false);
});

test('scanner engine lowers non-secret CRITICAL findings to MEDIUM in non-app paths', async () => {
  // Command injection in docs/main.py (exact inventree survey pattern)
  const pyCode = 'import subprocess\ndef invoke_commands(command: str = "--list"):\n    tasks = here.parent.joinpath("tasks.py")\n    command = f"invoke -f {tasks} {command}"\n    assert subprocess.call(command, shell=True) == 0\n';

  const docsScan = await runStaticCodeScan([{ path: 'docs/main.py', content: pyCode }], 'test-docs', { dependencyAudit: false });
  const docsFindings = docsScan.findings.filter((f) => f.ruleId === 24102 || /Command Injection/i.test(f.title));
  assert.ok(docsFindings.length > 0, 'finding should be present in docs');
  assert.ok(docsFindings.every((f) => f.severity === 'MEDIUM'), 'severity should be lowered to MEDIUM in docs');
  assert.ok(docsFindings.some((f) => f.reproductionSteps?.some((s) => s.includes('outside the shipped application'))));

  // Same code in shipped app code stays CRITICAL
  const appScan = await runStaticCodeScan([{ path: 'src/main.py', content: pyCode }], 'test-app', { dependencyAudit: false });
  const appFindings = appScan.findings.filter((f) => f.ruleId === 24102 || /Command Injection/i.test(f.title));
  assert.ok(appFindings.length > 0, 'finding should be present in app');
  assert.ok(appFindings.some((f) => f.severity === 'CRITICAL'), 'severity should stay CRITICAL in app path');
});
