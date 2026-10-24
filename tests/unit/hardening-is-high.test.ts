import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan } from '../../lib/scanner-engine';
import { evaluateSecurityRules } from '../../lib/rules/security-rules';

test('Task S2: Rule 3017, 15701, 8901, 3002, 7004 are HIGH severity', async () => {
  // Rule 3017: Docker socket mount in compose
  const composeSocket = `
version: '3'
services:
  app:
    image: alpine
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`;
  const scan3017 = await runStaticCodeScan(
    [{ path: 'docker-compose.yml', content: composeSocket }],
    'test-3017',
    { dependencyAudit: false }
  );
  const f3017 = scan3017.findings.find((f) => f.ruleId === 3017);
  assert.ok(f3017, 'Rule 3017 should fire');
  assert.equal(f3017.severity, 'HIGH', 'Rule 3017 should be HIGH');

  // Rule 8901: K8s privileged container
  const k8sPrivileged = `
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
    - name: nginx
      image: nginx
      securityContext:
        privileged: true
`;
  const scan8901 = await runStaticCodeScan(
    [{ path: 'k8s/pod.yaml', content: k8sPrivileged }],
    'test-8901',
    { dependencyAudit: false }
  );
  const f8901 = scan8901.findings.find((f) => f.ruleId === 8901);
  assert.ok(f8901, 'Rule 8901 should fire');
  assert.equal(f8901.severity, 'HIGH', 'Rule 8901 should be HIGH');

  // Rule 15701: Linux kernel capabilities (CAP_SYS_ADMIN)
  const kernCap = `
services:
  runner:
    image: alpine
    cap_add:
      - SYS_ADMIN
`;
  const scan15701 = await runStaticCodeScan(
    [{ path: 'docker-compose.yml', content: kernCap }],
    'test-15701',
    { dependencyAudit: false }
  );
  const f15701 = scan15701.findings.find((f) => f.ruleId === 15701);
  assert.ok(f15701, 'Rule 15701 should fire');
  assert.equal(f15701.severity, 'HIGH', 'Rule 15701 should be HIGH');

  // Rule 3002 / 7004: Docker root execution
  const dockerfileNoUser = `
FROM node:20-alpine
WORKDIR /app
COPY . .
CMD ["node", "index.js"]
`;
  const scanRoot = await runStaticCodeScan(
    [{ path: 'Dockerfile', content: dockerfileNoUser }],
    'test-root',
    { dependencyAudit: false }
  );
  const fRoot = scanRoot.findings.find((f) => f.ruleId === 3002 || f.ruleId === 7004);
  assert.ok(fRoot, 'Rule 3002 or 7004 should fire');
  assert.equal(fRoot.severity, 'HIGH', 'Docker root user should be HIGH');
});

test('Task S2: Rule 45 RLS SELECT policies with USING (true) are HIGH, write policies are CRITICAL', async () => {
  const evaluate = (content: string, path = 'schema.sql') => {
    return evaluateSecurityRules(
      { path, content },
      content.split('\n'),
      content,
      { count: 0 }
    ).findings.filter((f) => f.ruleId === 45);
  };

  // 1. SELECT policy with USING (true) -> HIGH
  const selectOnlySql = `
ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Public posts are viewable by everyone" ON public.posts
  FOR SELECT
  USING (true);
`;
  const [fSelect] = evaluate(selectOnlySql);
  assert.ok(fSelect, 'Rule 45 should fire on SELECT policy');
  assert.equal(fSelect.severity, 'HIGH', 'SELECT policy with USING (true) must be HIGH');

  // 2. FOR ALL policy with USING (true) -> CRITICAL (allows writes)
  const allPolicySql = `
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Anyone can do anything" ON public.users
  FOR ALL
  USING (true);
`;
  const [fAll] = evaluate(allPolicySql);
  assert.ok(fAll, 'Rule 45 should fire on FOR ALL policy');
  assert.equal(fAll.severity, 'CRITICAL', 'FOR ALL policy with USING (true) must remain CRITICAL');

  // 3. WITH CHECK (true) policy -> CRITICAL (insert/update write bypass)
  const insertPolicySql = `
ALTER TABLE public.logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Anyone can insert logs" ON public.logs
  FOR INSERT
  WITH CHECK (true);
`;
  const [fInsert] = evaluate(insertPolicySql);
  assert.ok(fInsert, 'Rule 45 should fire on WITH CHECK policy');
  assert.equal(fInsert.severity, 'CRITICAL', 'WITH CHECK (true) policy must remain CRITICAL');

  // 4. Default policy without FOR (defaults to FOR ALL in PostgreSQL) -> CRITICAL
  const defaultPolicySql = `
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Open items" ON public.items
  USING (true);
`;
  const [fDefault] = evaluate(defaultPolicySql);
  assert.ok(fDefault, 'Rule 45 should fire on default policy');
  assert.equal(fDefault.severity, 'CRITICAL', 'Default policy (omitted FOR) allows writes and must remain CRITICAL');

  // 5. Mixed file: SELECT policy and write policy -> CRITICAL
  const mixedSql = `
ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Public view" ON public.products
  FOR SELECT
  USING (true);
CREATE POLICY "Public write" ON public.products
  FOR INSERT
  WITH CHECK (true);
`;
  const [fMixed] = evaluate(mixedSql);
  assert.ok(fMixed, 'Rule 45 should fire on mixed file');
  assert.equal(fMixed.severity, 'CRITICAL', 'File containing write policy bypass must be CRITICAL');
});
