/**
 * Findings from the full-bundle analysis of a live site (LIVE-01.., Rule IDs 29805-29809).
 * lib/website-scanner.ts writes live-deployment/bundle-analysis.json (see lib/live-bundle-analyzer.ts); these rules
 * turn it into findings. Secret values are redacted before they reach this file.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import type { LiveBundleSummary } from '../live-bundle-analyzer';

export function evaluateLiveBundleRules(file: CodeFile, _lines: string[], _clean: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  if (file.path !== 'live-deployment/bundle-analysis.json') return { findings, logs };
  let summary: LiveBundleSummary;
  try {
    summary = JSON.parse(file.content) as LiveBundleSummary;
  } catch {
    return { findings, logs };
  }

  const push = (f: Omit<Finding, 'id' | 'status' | 'falsePositive' | 'filePath' | 'type'>) => {
    findings.push({ ...f, id: `live${f.ruleId}-${Date.now()}-${findingCounter.count++}`, type: 'SECURITY', filePath: file.path, status: 'OPEN', falsePositive: false });
    logs.push(`[${new Date().toLocaleTimeString()}] [LIVE] ${f.severity}: ${f.title}`);
  };

  for (const s of summary.secrets || []) {
    const where = (() => { try { return new URL(s.bundle).pathname; } catch { return s.bundle; } })();
    if (s.kind === 'Supabase service_role key' || s.kind === 'Supabase secret key') {
      push({
        ruleId: 29805,
        title: `LIVE-01: Supabase ${s.kind === 'Supabase secret key' ? 'Secret' : 'Service Role'} Key Is in Your Website's JavaScript`,
        severity: 'CRITICAL', category: 'Secret Exposure', lineRange: where, snippet: s.preview,
        reproductionSteps: [`Found in ${s.bundle} (served to every visitor).`, s.detail || ''],
        remediationPrompt: `Rotate the key now in Supabase (Project Settings -> API), remove it from frontend code and VITE_/NEXT_PUBLIC_ variables, and use only the anon / publishable key in the browser. Do privileged work in an Edge Function or server route. (${where})`,
        owner: 'Security Lead',
      });
    } else {
      push({
        ruleId: 29806,
        title: `LIVE-02: ${s.kind} Is in Your Website's JavaScript`,
        severity: s.severity, category: 'Secret Exposure', lineRange: where, snippet: s.preview,
        reproductionSteps: [`Found in ${s.bundle} (served to every visitor).`, s.detail || ''],
        remediationPrompt: `Revoke this ${s.kind} and create a new one, then call the provider from a server route or Edge Function that reads it from a server-only environment variable. Never put it in VITE_ / NEXT_PUBLIC_ / EXPO_PUBLIC_ variables. (${where})`,
        owner: 'Security Lead',
      });
    }
  }

  for (const map of summary.publicSourceMaps || []) {
    push({
      ruleId: 29807,
      title: 'LIVE-03: Source Maps Are Public, So Your Original Source Code Can Be Downloaded',
      severity: 'MEDIUM', category: 'Information Disclosure', lineRange: map, snippet: map,
      reproductionSteps: [`${map} is publicly reachable.`, 'Source maps contain your unminified source code, comments and file structure, which makes finding other weaknesses much easier.'],
      remediationPrompt: 'Turn off production source maps (Vite: build.sourcemap = false; Next.js: productionBrowserSourceMaps = false) or upload them only to your error tracker.',
      owner: 'Engineering',
    });
  }
  return { findings, logs };
}
