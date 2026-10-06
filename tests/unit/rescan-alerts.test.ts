import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { diffNewFindings, type AlertFinding } from '../../lib/rescan-alerts';
import { sendNewFindingsAlertEmail } from '../../lib/email';

const f = (ruleId: number, severity: string, filePath = 'app/api/route.ts', extra: Partial<AlertFinding> = {}): AlertFinding => ({
  ruleId, severity, filePath, title: `Rule ${ruleId}`, ...extra,
});

test('only new CRITICAL/HIGH findings are reported, critical first', () => {
  const previous = [f(1, 'CRITICAL'), f(2, 'HIGH')];
  const current = [f(1, 'CRITICAL'), f(2, 'HIGH'), f(3, 'HIGH'), f(4, 'CRITICAL'), f(5, 'MEDIUM')];
  assert.deepEqual(diffNewFindings(previous, current).map((x) => x.ruleId), [4, 3]);
});

test('a finding that only moved lines is not new', () => {
  assert.equal(diffNewFindings([f(1, 'HIGH')], [f(1, 'HIGH')]).length, 0);
});

test('same rule in a new file is new', () => {
  assert.equal(diffNewFindings([f(1, 'HIGH', 'a.ts')], [f(1, 'HIGH', 'b.ts')]).length, 1);
});

test('experimental and resolved findings never alert; duplicates collapse', () => {
  const current = [
    f(1, 'CRITICAL', 'a.ts', { maturity: 'experimental' }),
    f(2, 'HIGH', 'a.ts', { status: 'RESOLVED' }),
    f(3, 'HIGH'),
    f(3, 'HIGH'),
  ];
  assert.deepEqual(diffNewFindings([], current).map((x) => x.ruleId), [3]);
});

test('alert email escapes repository-controlled text', async () => {
  const origKey = process.env.RESEND_API_KEY;
  process.env.RESEND_API_KEY = 're_test';
  let body = '';
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: unknown, init?: RequestInit) => {
    body = String(init?.body ?? '');
    return new Response(JSON.stringify({ id: 'x' }), { status: 200 });
  });
  try {
    const res = await sendNewFindingsAlertEmail({
      toEmail: 'owner@example.com',
      projectName: '<img src=x onerror=alert(1)>',
      repoUrl: 'https://github.com/a/b',
      newCritical: 1,
      newHigh: 0,
      findings: [{ title: '<script>x</script>', severity: 'CRITICAL', filePath: 'a.ts' }],
    });
    assert.equal(res.success, true);
    const html = JSON.parse(body).html as string;
    assert.ok(!html.includes('<script>x</script>'));
    assert.ok(!html.includes('<img src=x'));
    assert.ok(html.includes('&lt;script&gt;'));
  } finally {
    fetchMock.mock.restore();
    if (origKey === undefined) delete process.env.RESEND_API_KEY;
    else process.env.RESEND_API_KEY = origKey;
  }
});
