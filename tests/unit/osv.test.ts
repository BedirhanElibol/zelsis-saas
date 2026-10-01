import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildDependencyFindings, compareVersions, cvss3BaseScore, queryOsv } from '@/lib/scanner/osv';
import { runStaticCodeScan } from '@/lib/scanner-engine';
import type { Dependency } from '@/lib/scanner/dependencies';

/** Evidence fixture for the rule audit: DEP-01 detects a vulnerable lockfile and ignores a patched one. */
export const OSV_CASE = { ruleIds: [26001], name: 'Known vulnerable dependency (OSV.dev)' };

const LODASH_ADVISORY = {
  id: 'GHSA-35jh-r3h4-6jhm',
  aliases: ['CVE-2021-23337'],
  summary: 'Command Injection in lodash',
  database_specific: { severity: 'HIGH' },
  affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }]
};
const MINIMIST_ADVISORY = {
  id: 'GHSA-xvch-5gv4-984h',
  aliases: ['CVE-2021-44906'],
  summary: 'Prototype Pollution in minimist',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [{ package: { ecosystem: 'npm', name: 'minimist' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '0.2.4' }, { introduced: '1.0.0' }, { fixed: '1.2.6' }] }] }]
};

/** Fake OSV.dev: lodash < 4.17.21 and minimist < 1.2.6 are vulnerable. */
function fakeOsv(calls: string[] = []): typeof fetch {
  return (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    calls.push(u);
    if (u.endsWith('/querybatch')) {
      const body = JSON.parse(String(init?.body)) as { queries: { package: { name: string }; version: string }[] };
      const results = body.queries.map((q) => {
        if (q.package.name === 'lodash' && compareVersions(q.version, '4.17.21') < 0) return { vulns: [{ id: LODASH_ADVISORY.id }] };
        if (q.package.name === 'minimist' && compareVersions(q.version, '1.2.6') < 0) return { vulns: [{ id: MINIMIST_ADVISORY.id }] };
        return {};
      });
      return new Response(JSON.stringify({ results }), { status: 200 });
    }
    const id = decodeURIComponent(u.slice(u.lastIndexOf('/') + 1));
    const adv = [LODASH_ADVISORY, MINIMIST_ADVISORY].find((a) => a.id === id);
    return new Response(JSON.stringify(adv ?? {}), { status: adv ? 200 : 404 });
  }) as typeof fetch;
}

const lockfile = (pkgs: Record<string, { version: string; dev?: boolean }>) =>
  JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'app' }, ...Object.fromEntries(Object.entries(pkgs).map(([n, v]) => [`node_modules/${n}`, v])) } }, null, 2);

test('CVSS v3 base scores match the specification examples', () => {
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(cvss3BaseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3BaseScore('CVSS:4.0/AV:N'), null);
});

test('queryOsv resolves advisories, severity and the fixed version per package', async () => {
  const deps: Dependency[] = [
    { ecosystem: 'npm', name: 'minimist', version: '1.2.5', file: 'package-lock.json', line: 3, dev: false },
    { ecosystem: 'npm', name: 'react', version: '18.2.0', file: 'package-lock.json', line: 4, dev: false }
  ];
  const res = await queryOsv(deps, { fetchImpl: fakeOsv() });
  assert.ok(res.ok);
  assert.equal(res.advisories[0][0].severity, 'CRITICAL');
  assert.equal(res.advisories[0][0].fixed, '1.2.6');
  assert.deepEqual(res.advisories[1], []);
});

test('queryOsv reports unavailability instead of a clean result', async () => {
  const down = (async () => { throw new Error('network down'); }) as unknown as typeof fetch;
  const res = await queryOsv([{ ecosystem: 'npm', name: 'x', version: '1.0.0', file: 'a', line: 1, dev: false }], { fetchImpl: down });
  assert.equal(res.ok, false);
});

test('dev-only packages are capped at MEDIUM', () => {
  const dep: Dependency = { ecosystem: 'npm', name: 'minimist', version: '1.2.5', file: 'package-lock.json', line: 1, dev: true };
  const [finding] = buildDependencyFindings([dep], [[{ id: 'X', aliases: [], summary: 's', severity: 'CRITICAL', fixed: '1.2.6' }]], new Map());
  assert.equal(finding.severity, 'MEDIUM');
});

test(`${OSV_CASE.name}: detects vulnerable lockfile and blocks the release`, async () => {
  const result = await runStaticCodeScan(
    [
      { path: 'package.json', content: '{"dependencies":{"lodash":"^4.17.15","minimist":"^1.2.0"}}' },
      { path: 'package-lock.json', content: lockfile({ lodash: { version: '4.17.15' }, minimist: { version: '1.2.5' } }) }
    ],
    'osv-detect',
    { dependencyAudit: { fetchImpl: fakeOsv() } }
  );
  const dep = result.findings.filter((f) => f.ruleId === 26001);
  assert.equal(dep.length, 2);
  assert.match(dep.find((f) => f.title.includes('minimist'))!.title, /CVE-2021-44906/);
  assert.equal(dep.find((f) => f.title.includes('lodash'))!.lineRange, 'L7');
  assert.equal(result.dependencyAudit?.status, 'ok');
  assert.equal(result.gateStatus, 'FAILED');
});

test(`${OSV_CASE.name}: ignores patched versions`, async () => {
  const result = await runStaticCodeScan(
    [{ path: 'package-lock.json', content: lockfile({ lodash: { version: '4.17.21' }, minimist: { version: '1.2.8' } }) }],
    'osv-clean',
    { dependencyAudit: { fetchImpl: fakeOsv() } }
  );
  assert.equal(result.findings.filter((f) => f.ruleId === 26001).length, 0);
  assert.deepEqual(result.dependencyAudit, { status: 'ok', packages: 2, vulnerablePackages: 0, advisories: 0 });
});

test('audit is skipped when disabled, suppressed, or OSV is down', async () => {
  const files = () => [{ path: 'package-lock.json', content: lockfile({ lodash: { version: '4.17.15' } }) }];
  const calls: string[] = [];
  assert.equal((await runStaticCodeScan(files(), 'off')).dependencyAudit?.status, 'disabled');
  const suppressed = await runStaticCodeScan([...files(), { path: '.zelsisignore', content: 'DEP-01\n' }], 'ignored', { dependencyAudit: { fetchImpl: fakeOsv(calls) } });
  assert.equal(suppressed.dependencyAudit?.status, 'disabled');
  assert.equal(calls.length, 0);
  const down = (async () => new Response('', { status: 503 })) as unknown as typeof fetch;
  const result = await runStaticCodeScan(files(), 'down', { dependencyAudit: { fetchImpl: down } });
  assert.equal(result.dependencyAudit?.status, 'unavailable');
  assert.ok(result.logs.some((l) => l.includes('NOT checked')));
});
