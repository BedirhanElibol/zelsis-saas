import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildLiveFindings, findInsecureCookies, parseEnvBody, probeLiveSite, type LiveProbeResult, type TlsInfo } from '@/lib/scanner/live-checks';
import { runStaticCodeScan } from '@/lib/scanner-engine';

/** Evidence fixture for the rule audit: each LIVE rule fires on a broken site and stays silent on a healthy one. */
export const LIVE_CASE = { ruleIds: [27001, 27002, 27003, 27004, 27005, 27006, 27007, 27008, 27009, 27010, 27011, 27012, 27013], name: 'Live deployment probes' };

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

test('LIVE-08..12: deploy artifacts and admin consoles are confirmed from the body, values never stored', async () => {
  const t = (body: string, type = 'text/plain'): Route => ({ status: 200, body, headers: { 'content-type': type } });
  const probe = await probeLiveSite(`https://${HOST}/`, [], {
    fetchImpl: fakeSite({
      ...redirectHttp,
      [`https://${HOST}/backup.sql`]: t('-- PostgreSQL database dump\nCREATE TABLE users (email text);\nINSERT INTO users VALUES (\'a@b.co\');\n'),
      [`https://${HOST}/terraform.tfstate`]: t('{"version":4,"terraform_version":"1.9.0","resources":[{"type":"aws_db_instance","password":"tf-secret-pw"}]}', 'application/json'),
      [`https://${HOST}/.npmrc`]: t('//registry.npmjs.org/:_authToken=npm_SECRETVALUE123\n'),
      [`https://${HOST}/phpinfo.php`]: t('<html><title>PHP 8.3.1 - phpinfo()</title><h1>PHP Version 8.3.1</h1></html>', 'text/html'),
      [`https://${HOST}/_cluster/health`]: t('{"cluster_name":"prod","status":"green","number_of_nodes":3}', 'application/json'),
      [`https://${HOST}/Dockerfile`]: t('FROM node:22-alpine\nCOPY . .\nRUN npm ci\n'),
    }),
    tlsInspect: goodTls,
    deepProbes: true
  });
  const findings = buildLiveFindings(probe, NOW);
  const byId = (id: number) => findings.find((f) => f.ruleId === id);
  assert.equal(byId(27008)?.severity, 'CRITICAL');
  assert.match(byId(27009)!.title, /terraform\.tfstate, \/\.npmrc|\.npmrc, \/terraform\.tfstate/);
  assert.equal(byId(27010)?.severity, 'HIGH');
  assert.match(byId(27011)!.snippet, /Elasticsearch/);
  assert.equal(byId(27012)?.severity, 'MEDIUM');
  assert.doesNotMatch(JSON.stringify(findings), /tf-secret-pw|npm_SECRETVALUE123|a@b\.co/);
});

test('LIVE-08..12: SPA pages, HTML 404s and look-alike text do not count as artifacts', async () => {
  const probe = await probeLiveSite(`https://${HOST}/`, [], {
    fetchImpl: fakeSite({
      ...redirectHttp,
      [`https://${HOST}/dump.sql`]: { status: 200, body: 'Page not found', headers: { 'content-type': 'text/plain' } },
      [`https://${HOST}/terraform.tfstate`]: { status: 200, body: '{"error":"not found"}', headers: { 'content-type': 'application/json' } },
      [`https://${HOST}/Dockerfile`]: { status: 200, body: '<!doctype html><p>FROM our team</p><p>RUN fast</p>', headers: { 'content-type': 'text/html' } },
      [`https://${HOST}/adminer.php`]: { status: 404, body: '<title>Adminer</title>', headers: { 'content-type': 'text/html' } },
    }),
    tlsInspect: goodTls,
    deepProbes: true
  });
  assert.deepEqual(probe.exposedFiles, []);
  assert.deepEqual(buildLiveFindings(probe, NOW), []);
});

test('LIVE-08..12 paths are not requested unless the domain is verified (deepProbes)', async () => {
  const calls: string[] = [];
  const probe = await probeLiveSite(`https://${HOST}/`, [], {
    fetchImpl: fakeSite({ ...redirectHttp, [`https://${HOST}/backup.sql`]: { status: 200, body: '-- PostgreSQL database dump\n', headers: { 'content-type': 'text/plain' } } }, calls),
    tlsInspect: goodTls
  });
  assert.equal(probe.deepProbes, false);
  assert.ok(!calls.some((u) => /backup\.sql|terraform|adminer|phpinfo/.test(u)), 'no deep paths requested');
  assert.equal(buildLiveFindings(probe, NOW).some((f) => f.ruleId === 27008), false);
});

test('paced probes go one at a time and stop at the first challenge; LIVE-13 reports the gap', async () => {
  const calls: string[] = [];
  let inFlight = 0; let peak = 0;
  const base = fakeSite({ ...redirectHttp }, calls);
  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    inFlight++; peak = Math.max(peak, inFlight);
    try {
      if (u.endsWith('/dump.sql')) return new Response('<title>Vercel Security Checkpoint</title>', { status: 403, headers: { 'x-vercel-mitigated': 'challenge', 'content-type': 'text/html' } });
      return await base(url, init);
    } finally { inFlight--; }
  }) as typeof fetch;
  const probe = await probeLiveSite(`https://${HOST}/`, [], { fetchImpl, tlsInspect: goodTls, deepProbes: true, probeIntervalMs: 5 });
  const pathCalls = calls.filter((u) => !u.startsWith('http://'));
  assert.equal(pathCalls.length, 6, '.env x4 and .git x2 answered, nothing after /dump.sql');
  assert.ok(peak <= 2, `path probes were sequential (peak ${peak}, the plain-http check runs alongside)`);
  assert.deepEqual(probe.probeCoverage, { answered: 6, total: 26 });
  const gap = buildLiveFindings(probe, NOW).find((f) => f.ruleId === 27013);
  assert.equal(gap?.type, 'VIBEPOLISH');
  assert.match(gap!.title, /6\/26 paths checked/);
});

test('LIVE-13 stays silent when every exposure path was answered', async () => {
  const probe = await probeLiveSite(`https://${HOST}/`, [], { fetchImpl: fakeSite(redirectHttp), tlsInspect: goodTls, deepProbes: true, probeIntervalMs: 1 });
  assert.deepEqual(probe.probeCoverage, { answered: 26, total: 26 });
  assert.equal(buildLiveFindings(probe, NOW).some((f) => f.ruleId === 27013), false);
});
