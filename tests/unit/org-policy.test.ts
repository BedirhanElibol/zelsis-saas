import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan, type CodeFile } from '../../lib/scanner-engine';
import { OrgPolicySchema } from '../../lib/validations/api-schemas';

// The engine frees file contents after a scan, so every test gets a fresh fixture
const vulnerableRoute = (): CodeFile => ({
  path: 'app/api/run/route.ts',
  content: `
    import { exec } from 'child_process';
    export async function GET(req: Request) {
      const host = new URL(req.url).searchParams.get('host');
      exec("ping " + host);
      eval(new URL(req.url).searchParams.get('code'));
      return Response.json({ ok: true });
    }
  `,
});

test('without an org policy a critical finding fails the gate', async () => {
  const result = await runStaticCodeScan([vulnerableRoute()], 'org-policy-fixture');
  assert.equal(result.gateStatus, 'FAILED');
});

test('an advisory org policy overrides the gate decision', async () => {
  const result = await runStaticCodeScan([vulnerableRoute()], 'org-policy-fixture', {
    orgPolicy: JSON.stringify({ failStrategy: 'advisory' }),
  });
  assert.equal(result.gateStatus, 'PASSED');
});

test('org policy strategy wins over the repository .zelsisrc.json', async () => {
  const repoRc: CodeFile = { path: '.zelsisrc.json', content: JSON.stringify({ failStrategy: 'advisory' }) };
  const result = await runStaticCodeScan([vulnerableRoute(), repoRc], 'org-policy-fixture', {
    orgPolicy: JSON.stringify({ failStrategy: 'strict', minScoreThreshold: 100 }),
  });
  assert.equal(result.gateStatus, 'FAILED');
});

test('org policy schema rejects unknown keys and path traversal', () => {
  assert.equal(OrgPolicySchema.safeParse({ failStrategy: 'strict', minScoreThreshold: 90 }).success, true);
  assert.equal(OrgPolicySchema.safeParse({ unknownKey: true }).success, false);
  assert.equal(OrgPolicySchema.safeParse({ ignoredPaths: ['../etc'] }).success, false);
  assert.equal(OrgPolicySchema.safeParse({ minScoreThreshold: 150 }).success, false);
});
