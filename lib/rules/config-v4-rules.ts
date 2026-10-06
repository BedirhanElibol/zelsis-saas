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
