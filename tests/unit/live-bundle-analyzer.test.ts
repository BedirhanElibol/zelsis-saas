import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeBundles, lazyChunkUrls, sourceMapUrl } from '../../lib/live-bundle-analyzer';
import { evaluateLiveBundleRules } from '../../lib/rules/live-bundle-rules';

// Fake keys are built at runtime so secret scanners never see a literal
const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (role: string) => [b64({ alg: 'HS256', typ: 'JWT' }), b64({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role, iat: 1700000000 }), 'x'.repeat(43)].join('.');
const openai = ['sk', 'proj', 'A'.repeat(48)].join('-');
const pad = 'var a=1;'.repeat(60000); // ~480 KB, past the 250 KB the general rules read

test('finds a service_role key past 250 KB and ignores the public anon key', () => {
  const text = `${pad}createClient("https://abcdefghijklmnopqrst.supabase.co","${jwt('anon')}");const admin="${jwt('service_role')}";`;
  const r = analyzeBundles([{ url: 'https://app.example.com/assets/index-abc.js', text }]);
  assert.deepEqual(r.supabaseProjects, ['abcdefghijklmnopqrst']);
  assert.equal(r.secrets.length, 1);
  assert.equal(r.secrets[0].kind, 'Supabase service_role key');
  assert.ok(!r.secrets[0].preview.includes(jwt('service_role')), 'value is redacted');
});

test('flags paid API keys, only flags Google keys near Gemini usage', () => {
  const r = analyzeBundles([{ url: 'https://a.example.com/x.js', text: `const k="${openai}";const maps="AIza${'B'.repeat(35)}";` }]);
  assert.deepEqual(r.secrets.map((s) => s.kind), ['OpenAI API key']);
  const g = analyzeBundles([{ url: 'https://a.example.com/x.js', text: `new GoogleGenerativeAI("AIza${'C'.repeat(35)}")` }]);
  assert.deepEqual(g.secrets.map((s) => s.kind), ['Google Gemini API key']);
});

test('lazy chunks and source maps resolve against the site', () => {
  assert.deepEqual(lazyChunkUrls('import("/assets/Dashboard-9f2a.js");"assets/chart-1b.js"', 'https://app.example.com'),
    ['https://app.example.com/assets/Dashboard-9f2a.js', 'https://app.example.com/assets/chart-1b.js']);
  assert.equal(sourceMapUrl('code\n//# sourceMappingURL=index-abc.js.map', 'https://app.example.com/assets/index-abc.js'), 'https://app.example.com/assets/index-abc.js.map');
});

test('the summary becomes CRITICAL / MEDIUM findings', () => {
  const summary = { bundles: [], supabaseProjects: [], publicSourceMaps: ['https://app.example.com/assets/i.js.map'],
    secrets: [{ kind: 'Supabase service_role key', severity: 'CRITICAL', preview: 'eyJhbGci...abcd', bundle: 'https://app.example.com/assets/i.js' }] };
  const { findings } = evaluateLiveBundleRules({ path: 'live-deployment/bundle-analysis.json', content: JSON.stringify(summary) }, [], '', { count: 0 });
  assert.deepEqual(findings.map((f) => [f.ruleId, f.severity]), [[29805, 'CRITICAL'], [29807, 'MEDIUM']]);
});

test('credentials without a vendor prefix are found in bundles; placeholders are not', () => {
  const text = [
    'var e={url:"rediss://default:AbC123secretPw@eu1-keen-fox-30000.upstash.io:6379"};',
    'var u={hash:"$2b$10$abcdefghijklmnopqrstuuVwXyZ0123456789abcdefghijklmnopq"};',
    'var g={client_secret:"GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz12"};',
    'var s={NEXTAUTH_SECRET:"k8sJ2x9QmP4vL7nR3tY6wZ1bC5dF0gH8"};',
    'fetch("/api/admin",{headers:{"x-admin-secret":"Sup3rAdm1nK3y2024xyz"}});',
    'var doc="postgres://user:password@localhost:5432/db", tpl="DATABASE_URL=\\"postgresql://your_user:your_password@host/db\\"";',
  ].join('\n');
  const kinds = analyzeBundles([{ url: 'https://app.example.com/assets/index.js', text }]).secrets.map((s) => s.kind).sort();
  assert.deepEqual(kinds, ['Database / cache connection string with password', 'Google OAuth client secret', 'Internal admin header secret', 'Password hash', 'Server-only secret']);
  const all = JSON.stringify(analyzeBundles([{ url: 'https://app.example.com/assets/index.js', text }]));
  assert.doesNotMatch(all, /AbC123secretPw|k8sJ2x9QmP4vL7nR3tY6wZ1b|Sup3rAdm1nK3y2024/);
});
