/**
 * Python framework security (Django, Flask, FastAPI, SQLAlchemy, Celery) (PYF-xx, Rule IDs 29001-29099).
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

export function evaluatePythonV4Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const hits: Hit[] = [];

  function add(h: Hit) {
    hits.push(h);
  }

  const isPython = file.path.endsWith('.py');
  if (!isPython) return { findings, logs };

  lines.forEach((l, i) => {
    if (/^\s*#/.test(l)) return;

    if (/\.extra\([^)]*(?:where|select|tables)\s*=\s*[^)]*(?:f['"]|['"][^'"]*['"]\s*\%|['"][^'"]*['"]\.format\()/.test(l)) {
      add({ ruleId: 29002, code: 'PYF-02', title: 'Django extra() SQL Injection', severity: 'CRITICAL', category: 'Injection', lineIdx: i, why: 'Formatting strings into extra() clauses allows SQL injection.', fix: 'Use parameters for variables, or migrate to .annotate() / .filter().' });
    }
    if (/\bmark_safe\(\s*(?:f['"]|['"][^'"]*['"]\s*\%|['"][^'"]*['"]\.format\(|[^)]*\+)/.test(l)) {
      add({ ruleId: 29003, code: 'PYF-03', title: 'Django mark_safe XSS', severity: 'HIGH', category: 'Cross-Site Scripting', lineIdx: i, why: 'Passing dynamic strings to mark_safe disables HTML escaping, causing XSS.', fix: 'Use format_html() which safely escapes arguments instead of mark_safe().' });
    }
    if (/\bHTMLResponse\(\s*(?:content\s*=\s*)?(?:f['"][^'"]*\{\s*request\.|request\.)/.test(l)) {
      add({ ruleId: 29014, code: 'PYF-14', title: 'FastAPI HTMLResponse XSS', severity: 'HIGH', category: 'Cross-Site Scripting', lineIdx: i, why: 'Injecting request input directly into HTMLResponse causes XSS.', fix: 'Escape the input before including it in the HTML, or use a templating engine like Jinja2 with autoescaping.' });
    }
    if (/\bHttpResponse\(\s*(?:f['"][^'"]*\{\s*request\.|request\.)/.test(l)) {
      add({ ruleId: 29015, code: 'PYF-15', title: 'Django HttpResponse XSS', severity: 'HIGH', category: 'Cross-Site Scripting', lineIdx: i, why: 'Injecting request input directly into HttpResponse without escaping causes XSS.', fix: 'Use format_html() or render a template.' });
    }
    if (/\bmake_response\(\s*(?:f['"][^'"]*\{\s*request\.|request\.)/.test(l)) {
      add({ ruleId: 29016, code: 'PYF-16', title: 'Flask make_response XSS', severity: 'HIGH', category: 'Cross-Site Scripting', lineIdx: i, why: 'Injecting request input directly into make_response without escaping causes XSS.', fix: 'Render a template with autoescaping.' });
    }
  });

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `pyf${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [PYTHON] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
