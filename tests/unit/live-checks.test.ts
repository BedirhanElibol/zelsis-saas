import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildLiveFindings, findInsecureCookies, parseEnvBody, probeLiveSite, type LiveProbeResult, type TlsInfo } from '@/lib/scanner/live-checks';
import { runStaticCodeScan } from '@/lib/scanner-engine';

/** Evidence fixture for the rule audit: each LIVE rule fires on a broken site and stays silent on a healthy one. */
export const LIVE_CASE = { ruleIds: [27001, 27002, 27003, 27004, 27005, 27006, 27007], name: 'Live deployment probes' };

// Public IP literal: passes the SSRF guard without a DNS lookup.
const HOST = '93.184.215.14';
const NOW = new Date('2026-10-01T00:00:00Z');
const inDays = (d: number) => new Date(NOW.getTime() + d * 86400000).toISOString();

type Route = { status: number; body?: string; headers?: Record<string, string> };
function fakeSite(routes: Record<string, Route>, calls: string[] = []): typeof fetch {
  return (async (url: string | URL) => {
    const u = String(url);
    calls.push(u);
    const r = routes[u];
    // Unknown paths behave like an SPA: 200 with the index page (soft 404).
    if (!r) return new Response('<!doctype html><html><body>app</body></html>', { status: 200, headers: { 'content-type': 'text/html' } });
    return new Response(r.body ?? '', { status: r.status, headers: r.headers });
  }) as typeof fetch;
}
const goodTls = async (): Promise<TlsInfo> => ({ authorized: true, validTo: inDays(80) });
const redirectHttp: Record<string, Route> = { [`http://${HOST}/`]: { status: 301, headers: { location: `https://${HOST}/` } } };

test('parseEnvBody keeps names only and rejects HTML and prose', () => {
  assert.deepEqual(parseEnvBody('# prod\nDATABASE_URL=postgres://u:p@db/x\nexport STRIPE_SECRET_KEY="sk"\n'), ['DATABASE_URL', 'STRIPE_SECRET_KEY']);
  assert.equal(parseEnvBody('<!doctype html><title>404</title>'), null);
  assert.equal(parseEnvBody('Not found.\nPlease try again later.'), null);
  assert.equal(parseEnvBody(''), null);
});

test('healthy site: SPA soft 404s, valid TLS and HTTPS redirect produce no LIVE findings', async () => {
  const probe = await probeLiveSite(`https://${HOST}/`, ['session=abc; Path=/; Secure; HttpOnly; SameSite=Lax', 'theme=dark; Path=/'], {
    fetchImpl: fakeSite(redirectHttp),
    tlsInspect: goodTls
  });
  assert.deepEqual(probe.exposedFiles, []);
  assert.equal(probe.plainHttp, 'redirects-to-https');
  assert.deepEqual(buildLiveFindings(probe, NOW), []);
});

test('LIVE-01 / LIVE-02: exposed .env and .git are confirmed from the body without storing values', async () => {
  const calls: string[] = [];
  const probe = await probeLiveSite(`https://${HOST}/`, [], {
    fetchImpl: fakeSite({
      ...redirectHttp,
      [`https://${HOST}/.env`]: { status: 200, body: 'DATABASE_URL=postgres://admin:hunter2@db/prod\nOPENAI_API_KEY=sk-live-value\n', headers: { 'content-type': 'text/plain' } },
      [`https://${HOST}/.env.local`]: { status: 404 },
      [`https://${HOST}/.git/HEAD`]: { status: 200, body: 'ref: refs/heads/main\n', headers: { 'content-type': 'application/octet-stream' } },
      [`https://${HOST}/.git/config`]: { status: 302, headers: { location: '/login' } }
    }, calls),
    tlsInspect: goodTls
  });
  const findings = buildLiveFindings(probe, NOW);
  const env = findings.find((f) => f.ruleId === 27001);
  const git = findings.find((f) => f.ruleId === 27002);
  assert.equal(env?.severity, 'CRITICAL');
  assert.match(env!.snippet, /DATABASE_URL, OPENAI_API_KEY/);
  assert.doesNotMatch(JSON.stringify(findings), /hunter2|sk-live-value/);
  assert.equal(git?.severity, 'HIGH');
  assert.match(git!.title, /\.git\/HEAD/);
  assert.doesNotMatch(git!.title, /\.git\/config/, 'a redirect is not an exposure');
  assert.ok(calls.every((u) => u.startsWith(`https://${HOST}/`) || u === `http://${HOST}/`));
});

test('LIVE-03: no TLS on 443 while HTTP serves content', async () => {
  const probe = await probeLiveSite(`http://${HOST}/`, [], {
    fetchImpl: fakeSite({ [`http://${HOST}/`]: { status: 200, body: '<html></html>' } }),
    tlsInspect: async () => null
  });
  const ids = buildLiveFindings(probe, NOW).map((f) => f.ruleId);
  assert.deepEqual(ids, [27003]);

  // A slow handshake (timeout) is undetermined, not "no HTTPS".
  const slow = await probeLiveSite(`http://${HOST}/`, [], {
    fetchImpl: fakeSite({ [`http://${HOST}/`]: { status: 200, body: '<html></html>' } }),
    tlsInspect: async () => undefined
  });
  assert.equal('tls' in slow, false);
  assert.deepEqual(buildLiveFindings(slow, NOW), []);
});

test('LIVE-04: untrusted certificate; LIVE-05: certificate close to expiry', () => {
  const base: LiveProbeResult = { host: HOST, exposedFiles: [], tls: null, plainHttp: 'redirects-to-https', insecureCookies: [] };
  const bad = buildLiveFindings({ ...base, tls: { authorized: false, authorizationError: 'CERT_HAS_EXPIRED', validTo: inDays(-3) } }, NOW);
  assert.deepEqual(bad.map((f) => [f.ruleId, f.severity]), [[27004, 'CRITICAL']]);
  assert.match(bad[0].title, /CERT_HAS_EXPIRED/);

  const soon = buildLiveFindings({ ...base, tls: { authorized: true, validTo: inDays(5) } }, NOW);
  assert.deepEqual(soon.map((f) => [f.ruleId, f.severity]), [[27005, 'HIGH']]);
  assert.equal(buildLiveFindings({ ...base, tls: { authorized: true, validTo: inDays(15) } }, NOW)[0].severity, 'MEDIUM');
  assert.deepEqual(buildLiveFindings({ ...base, tls: { authorized: true, validTo: inDays(60) } }, NOW), []);
});

test('LIVE-06: HTTPS works but plain HTTP serves the page instead of redirecting', async () => {
  for (const http of [{ status: 200, body: '<html></html>' }, { status: 302, headers: { location: `http://${HOST}/home` } }]) {
    const probe = await probeLiveSite(`https://${HOST}/`, [], { fetchImpl: fakeSite({ [`http://${HOST}/`]: http }), tlsInspect: goodTls });
    assert.deepEqual(buildLiveFindings(probe, NOW).map((f) => f.ruleId), [27006]);
  }
});

test('LIVE-07: session cookies need Secure and HttpOnly; CSRF and Supabase SSR cookies may be JS-readable', () => {
  assert.deepEqual(findInsecureCookies(['connect.sid=s%3A1; Path=/', 'auth_token=x; Secure'], true), [
    { name: 'connect.sid', missing: ['Secure', 'HttpOnly'] },
    { name: 'auth_token', missing: ['HttpOnly'] }
  ]);
  assert.deepEqual(findInsecureCookies(['XSRF-TOKEN=a; Path=/; Secure', 'sb-abc-auth-token=b; Path=/; Secure', 'theme=dark'], true), []);
  assert.deepEqual(findInsecureCookies(['sessionid=1; HttpOnly'], false), [], 'Secure cannot be set on plain HTTP');

  const findings = buildLiveFindings({ host: HOST, exposedFiles: [], tls: { authorized: true, validTo: inDays(90) }, plainHttp: 'redirects-to-https', insecureCookies: findInsecureCookies(['connect.sid=1'], true) }, NOW);
  assert.deepEqual(findings.map((f) => [f.ruleId, f.severity]), [[27007, 'MEDIUM']]);
  assert.doesNotMatch(findings[0].snippet, /connect\.sid=1/);
});

test('scan engine turns liveProbe data in security-headers.json into findings', async () => {
  const liveProbe: LiveProbeResult = {
    host: HOST,
    exposedFiles: [{ path: '/.env', kind: 'env', evidence: '1 variable: SECRET (values not stored)' }],
    tls: { authorized: true, validTo: inDays(90) },
    plainHttp: 'redirects-to-https',
    insecureCookies: []
  };
  const headers = {
    targetUrl: `https://${HOST}/`, statusCode: 200, isHealthy: true, missingSecurityHeaders: [],
    headers: { 'content-security-policy': "default-src 'self'", 'strict-transport-security': 'max-age=63072000' },
    liveProbe
  };
  const result = await runStaticCodeScan([{ path: 'live-deployment/security-headers.json', content: JSON.stringify(headers) }], 'live');
  assert.ok(result.findings.some((f) => f.ruleId === 27001));
});
