/**
 * Cloud, IaC, container, CI/CD and platform config security (CFG-xx, Rule IDs 29201-29299).
 * Each rule matches an explicit insecure setting on one line; see tests/rules/fixtures/config-v4.ts.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

/** Shared hosting suffixes where anyone can deploy a subdomain. */
const SHARED_HOSTS = String.raw`(?:vercel\.app|netlify\.app|pages\.dev|onrender\.com|herokuapp\.com|github\.io|web\.app|firebaseapp\.com|fly\.dev|railway\.app)`;

export function evaluateConfigV4Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.toLowerCase();
  const raw = (file.content || '').split('\n');
  const hits: Hit[] = [];

  // CFG-01: Firebase "test mode" rules left in place: everything is open until the date passes
  if (/(?:^|\/)(?:firestore|storage|database)?\.?rules$|\.rules$/.test(path)) {
    const idx = raw.findIndex((l) => /allow\s+[\w\s,]*\b(?:read|write)\b[^;]*:\s*if\s+request\.time\s*<\s*timestamp\.date\s*\(/.test(l));
    if (idx !== -1) hits.push({
      ruleId: 29201, code: 'CFG-01', severity: 'HIGH', category: 'Broken Access Control', lineIdx: idx,
      title: 'Firebase Test-Mode Rule: Anyone Can Read and Write Until the Date Passes',
      why: 'The test-mode template grants every unauthenticated client full access until the timestamp; apps routinely ship with it and leak or lose all data.',
      fix: 'Replace it with rules scoped to request.auth.uid (e.g. allow read, write: if request.auth != null && request.auth.uid == userId).'
    });
  }

  // CFG-02: nginx directory listing
  if (/nginx|\.conf$/.test(path) && /\bserver\s*\{|\blocation\b/.test(cleanContent)) {
    const idx = raw.findIndex((l) => /^\s*autoindex\s+on\s*;/.test(l));
    if (idx !== -1) hits.push({
      ruleId: 29202, code: 'CFG-02', severity: 'MEDIUM', category: 'Security Misconfiguration', lineIdx: idx,
      title: 'nginx Directory Listing Enabled (autoindex on)',
      why: 'autoindex lists every file in the directory, exposing backups, .env copies, source maps and uploads that were never linked.',
      fix: 'Remove "autoindex on;" (the default is off) and serve only explicit files.'
    });
  }

  // CFG-03: Supabase auth redirect allow-list with a wildcard on a shared hosting domain
  if (/(?:^|\/)supabase\/config\.toml$/.test(path)) {
    // Only a whole-label wildcard: "myapp-*-team.vercel.app" stays inside your own team's previews
    const wildcard = new RegExp(String.raw`https?://\*\*?\.${SHARED_HOSTS}`);
    const idx = raw.findIndex((l) => /^\s*(?:site_url|additional_redirect_urls)\s*=/.test(l) && wildcard.test(l));
    if (idx !== -1) hits.push({
      ruleId: 29203, code: 'CFG-03', severity: 'HIGH', category: 'Broken Authentication', lineIdx: idx,
      title: 'Supabase Auth Redirects Allowed to Any Subdomain of a Shared Hosting Domain',
      why: 'Anyone can deploy their own *.vercel.app (or similar) site, so a wildcard there lets an attacker receive magic-link and OAuth redirects with the victim\'s tokens.',
      fix: 'List exact URLs, or scope the wildcard to your own team prefix (https://myapp-*-myteam.vercel.app/**).'
    });
  }

  // CFG-04: nginx "off-by-slash": location without a trailing slash + alias with one
  if (/nginx|\.conf$/.test(path) && /\balias\b/.test(cleanContent)) {
    let open: string | null = null;
    let depth = 0;
    for (let i = 0; i < raw.length && !hits.some((h) => h.ruleId === 29204); i++) {
      const l = raw[i].replace(/#.*/, '');
      const loc = /^\s*location\s+(?:\^~\s+)?(\/[^\s{]*)\s*\{/.exec(l);
      if (loc) { open = loc[1]; depth = 0; }
      if (open !== null) {
        depth += (l.match(/\{/g) || []).length - (l.match(/\}/g) || []).length;
        if (!open.endsWith('/') && /^\s*alias\s+\S*\/\s*;/.test(l)) hits.push({
          ruleId: 29204, code: 'CFG-04', severity: 'MEDIUM', category: 'Path Traversal', lineIdx: i,
          title: `nginx alias Path Traversal (location ${open} without a trailing slash)`,
          why: `A request for ${open}../ maps to the parent of the alias directory, so files next to it (source, configs, backups) can be downloaded.`,
          fix: `End the location with a slash to match the alias (location ${open}/ { alias .../; }), or use root instead of alias.`
        });
        if (depth <= 0) open = null;
      }
    }
  }

  // CFG-05: MongoDB listening on all interfaces with access control off
  if (/(?:^|\/)mongod?[\w.-]*\.(?:conf|ya?ml)$/.test(path) && !/^\s*authorization\s*:\s*['"]?enabled/m.test(cleanContent)) {
    const idx = raw.findIndex((l) => /^\s*bindIp\s*:\s*[^#\n]*0\.0\.0\.0|^\s*bindIpAll\s*:\s*true\b/.test(l));
    if (idx !== -1) hits.push({
      ruleId: 29205, code: 'CFG-05', severity: 'HIGH', category: 'Broken Authentication', lineIdx: idx,
      title: 'MongoDB Bound to All Interfaces Without Authorization',
      why: 'mongod accepts unauthenticated clients unless security.authorization is enabled; listening on 0.0.0.0 makes every database readable and writable from the network (mass ransom wipes target exactly this).',
      fix: 'Add security: { authorization: enabled } with a user per app, and bind to 127.0.0.1 or a private interface.'
    });
  }

  // CFG-06: Elasticsearch security disabled on a node reachable from the network
  if (/(?:^|\/)elasticsearch\.ya?ml$/.test(path) && /^\s*network\.host\s*:\s*['"[]*\s*(?:0\.0\.0\.0|_site_|_global_)/m.test(cleanContent)) {
    const idx = raw.findIndex((l) => /^\s*xpack\.security\.enabled\s*:\s*['"]?false\b/.test(l));
    if (idx !== -1) hits.push({
      ruleId: 29206, code: 'CFG-06', severity: 'HIGH', category: 'Broken Authentication', lineIdx: idx,
      title: 'Elasticsearch Security Disabled on a Network-Reachable Node',
      why: 'With xpack.security.enabled: false there is no login or TLS, and network.host exposes the REST API, so anyone who reaches port 9200 can read or delete every index.',
      fix: 'Keep xpack.security.enabled: true (the default since 8.0) with passwords and TLS, or bind network.host to localhost.'
    });
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `cfg${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONFIG V4] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
