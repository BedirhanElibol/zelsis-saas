import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildGateWorkflow } from '../../lib/ci-gate-snippet';

const root = join(__dirname, '../..');

test('the customer workflow calls the real gate endpoint with the auth it accepts', () => {
  const yaml = buildGateWorkflow({ appUrl: 'https://example.test' });
  assert.match(yaml, /https:\/\/example\.test\/api\/v1\/gate-check/);
  assert.match(yaml, /x-api-key: \$ZELSIS_API_KEY/);
  assert.match(yaml, /"githubToken"/);
  assert.match(yaml, /-ge 400 \] && \[ "\$HTTP_CODE" -lt 500/, '4xx must be reported as a rejected request, not a vulnerability');
  // the gate route reads exactly these fields and this header
  const route = readFileSync(join(root, 'app/api/v1/gate-check/route.ts'), 'utf8');
  for (const field of ['body.repoUrl', 'body.githubToken', 'body.ref', 'body.base', "'x-api-key'"]) assert.ok(route.includes(field), field);
});

test('docs and onboarding use the shared workflow, not hand-written snippets', () => {
  for (const file of ['app/docs/ci-gate/page.tsx', 'components/dashboard/OnboardingChecklist.tsx', 'components/CicdAutomationView.tsx']) {
    assert.ok(readFileSync(join(root, file), 'utf8').includes('buildGateWorkflow('), file);
  }
});

test('the gate accepts a GitHub Actions token longer than a classic PAT', async () => {
  const { GateCheckRequestSchema } = await import('../../lib/validations/api-schemas');
  const long = 'ghs_' + 'a'.repeat(1200);
  assert.ok(GateCheckRequestSchema.safeParse({ repoUrl: 'https://github.com/a/b', githubToken: long }).success);
});

test('a rejected gate request prints which field failed', () => {
  const yaml = buildGateWorkflow({ appUrl: 'https://example.test' });
  assert.match(yaml, /\.details\[\]\? \| \.field \+ ": " \+ \.message/);
});

test('the composite action calls the same endpoint with the same fields as the long workflow', () => {
  const action = readFileSync(join(root, 'actions/gate/action.yml'), 'utf8');
  assert.match(action, /using: composite/);
  assert.match(action, /\/api\/v1\/gate-check/);
  assert.match(action, /x-api-key: \$ZELSIS_API_KEY/);
  const route = readFileSync(join(root, 'app/api/v1/gate-check/route.ts'), 'utf8');
  for (const field of ['repoUrl', 'githubToken', 'ref', 'base']) {
    assert.ok(action.includes(`${field}: $`) || action.includes(`${field}:`), `payload carries ${field}`);
    assert.ok(route.includes(`body.${field}`), `route reads ${field}`);
  }
  // the pull request SHAs reach the script through env, never pasted into the command line
  assert.doesNotMatch(action.split('run: |')[1] ?? '', /\$\{\{/);
  // every third-party action is pinned to a full commit SHA
  for (const m of action.matchAll(/uses:\s*([^\s#]+)/g)) assert.match(m[1], /@[0-9a-f]{40}$/, m[1]);
});

test('the short workflow shown to customers points at the action in this repository', async () => {
  const { buildGateActionWorkflow, GATE_ACTION_REF } = await import('../../lib/ci-gate-snippet');
  const yaml = buildGateActionWorkflow();
  assert.ok(yaml.includes(`uses: ${GATE_ACTION_REF}`));
  assert.match(yaml, /api-key: \$\{\{ secrets\.ZELSIS_API_KEY \}\}/);
  assert.ok(existsSync(join(root, GATE_ACTION_REF.replace('BedirhanElibol/zelsis-saas/', '').replace(/@.*$/, ''), 'action.yml')));
});
