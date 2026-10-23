import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan } from '../../lib/scanner-engine';
import { hasUntrustedInput, isCriticalInjectionRule } from '../../lib/scanner/text';

test('hasUntrustedInput recognizes JS/TS, Go, Python and common request inputs', () => {
  // JS / TS Web & Next.js
  assert.equal(hasUntrustedInput('const body = await req.json();'), true);
  assert.equal(hasUntrustedInput('const q = searchParams.get("query");'), true);
  assert.equal(hasUntrustedInput('export async function GET(request: Request) {'), true);
  assert.equal(hasUntrustedInput('export default function Page({ searchParams }: PageProps) {'), true);
  assert.equal(hasUntrustedInput('const ctx_query = ctx.query.search;'), true);

  // Go net/http & Gin / Echo / Fiber
  assert.equal(hasUntrustedInput('id := r.URL.Query().Get("id")'), true);
  assert.equal(hasUntrustedInput('val := r.FormValue("name")'), true);
  assert.equal(hasUntrustedInput('val := c.Query("id")'), true);
  assert.equal(hasUntrustedInput('err := c.ShouldBindJSON(&body)'), true);

  // Negative / Clean code
  assert.equal(hasUntrustedInput('const sql = "SELECT * FROM users WHERE active = true";'), false);
  assert.equal(hasUntrustedInput('func query(db *sql.DB) { log.Println("running migration") }'), false);
});

test('scanner engine downgrades critical injection rules to HIGH when file has no untrusted input', async () => {
  // Internal SQL query builder without external input (e.g. migration, cron task)
  const noInputSqlCode = `
import { db } from './db';
export async function archiveOldRecords(tableName: string) {
  const query = "DELETE FROM " + tableName + " WHERE created_at < NOW() - INTERVAL '30 days'";
  return db.query(query);
}
`;
  const noInputScan = await runStaticCodeScan(
    [{ path: 'src/jobs/archive.ts', content: noInputSqlCode }],
    'test-no-input',
    { dependencyAudit: false }
  );
  const sqlFindings = noInputScan.findings.filter((f) => isCriticalInjectionRule(f.ruleId));
  assert.ok(sqlFindings.length > 0, 'injection finding should be detected');
  assert.equal(sqlFindings[0].severity, 'HIGH', 'should be downgraded from CRITICAL to HIGH');
  assert.ok(
    sqlFindings[0].reproductionSteps?.some((s) => s.includes('Downgraded from CRITICAL to HIGH')),
    'reproduction steps should explain the downgrade'
  );

  // Same injection in a file with untrusted request input stays CRITICAL
  const withInputSqlCode = `
import { db } from './db';
export async function handleRequest(req: Request) {
  const url = new URL(req.url);
  const tableName = url.searchParams.get("table");
  const query = "DELETE FROM " + tableName + " WHERE id = 1";
  return db.query(query);
}
`;
  const withInputScan = await runStaticCodeScan(
    [{ path: 'src/api/delete.ts', content: withInputSqlCode }],
    'test-with-input',
    { dependencyAudit: false }
  );
  const inputFindings = withInputScan.findings.filter((f) => isCriticalInjectionRule(f.ruleId));
  assert.ok(inputFindings.length > 0, 'injection finding should be detected');
  assert.equal(inputFindings[0].severity, 'CRITICAL', 'should remain CRITICAL when untrusted input is present');
});
