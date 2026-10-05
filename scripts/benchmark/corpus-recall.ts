/**
 * Real-incident recall: scans each snippet in public/benchmark/real-incident-corpus.txt (served at /benchmark/real-incident-corpus.txt) on its own and checks whether a
 * security finding fires on the line marked `<<V` (within 3 lines). The corpus is drawn from public incidents and
 * advisories (Supabase/Lovable RLS exposure, Firebase rules, webhook mistakes, IDOR, SSRF, secrets, ...).
 *
 *   npx tsx scripts/benchmark/corpus-recall.ts            # summary
 *   npx tsx scripts/benchmark/corpus-recall.ts --verbose  # every snippet with its findings
 *
 * Snippet header format: `=== <id> | <path> | <source>`. Fake secrets are written as {{PLACEHOLDERS}} and assembled
 * here, so the corpus file itself never trips secret scanners.
 */
import { readFileSync } from 'fs';
import { join } from 'path';
import { runStaticCodeScan } from '../../lib/scanner-engine';

const PLACEHOLDERS: Record<string, string> = {
  FAKE_STRIPE_LIVE_KEY: ['sk', 'live', '51Hx9QzKp3mR7tVw2LcN8bYd4FgJ6sA0eU1iO5'].join('_'),
};

interface Snippet { id: string; path: string; content: string; line: number }

export function loadCorpus(file = join(__dirname, '../../public/benchmark/real-incident-corpus.txt')): Snippet[] {
  const raw = readFileSync(file, 'utf8').replace(/\r\n/g, '\n').replace(/\{\{(\w+)\}\}/g, (m, key: string) => PLACEHOLDERS[key] ?? m);
  return raw.split(/^=== /m).filter(Boolean).map((block) => {
    const [head, ...rest] = block.split('\n');
    const [id, path] = head.split(' | ').map((s) => s.trim());
    const lines = rest.join('\n').replace(/\n+$/, '\n').split('\n');
    const line = lines.findIndex((l) => /\s*<<V\s*$/.test(l)) + 1;
    return { id, path, content: lines.map((l) => l.replace(/\s*<<V\s*$/, '')).join('\n'), line };
  });
}

export async function measureRecall(snippets = loadCorpus()) {
  const lineOf = (r: string) => parseInt(r.replace(/^L/, ''), 10);
  const result = { total: snippets.length, highCritical: 0, withMedium: 0, missed: [] as string[] };
  for (const s of snippets) {
    const { findings } = await runStaticCodeScan([{ path: s.path, content: s.content }], 'corpus', { keepDuplicateRules: true });
    const security = findings.filter((f) => f.type === 'SECURITY' || /secur|inject|auth|secret|access/i.test(f.category || ''));
    const near = (sev: string[]) => security.some((f) => sev.includes(f.severity) && Math.abs(lineOf(f.lineRange) - s.line) <= 3);
    if (near(['HIGH', 'CRITICAL'])) { result.highCritical++; result.withMedium++; }
    else if (near(['MEDIUM'])) result.withMedium++;
    else result.missed.push(s.id);
  }
  return result;
}

if (require.main === module) {
  measureRecall().then((r) => {
    const pct = (n: number) => Math.round((100 * n) / r.total);
    console.log(`corpus=${r.total}  HIGH/CRITICAL on the marked line: ${r.highCritical} (${pct(r.highCritical)}%)  incl. MEDIUM: ${r.withMedium} (${pct(r.withMedium)}%)`);
    if (process.argv.includes('--verbose')) r.missed.forEach((id) => console.log('  missed:', id));
  });
}
