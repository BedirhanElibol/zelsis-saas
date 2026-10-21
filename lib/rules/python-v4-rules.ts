/**
 * Python framework security (Django, Flask, FastAPI, SQLAlchemy, Celery) (PYF-xx, Rule IDs 29001-29099).
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

const ESCAPED = /^\s*(?:escape|conditional_escape|format_html|escape_uri_path|urlencode|html\.escape)\s*\(/;

/**
 * Every value going into mark_safe is escaped first: mark_safe(f'<a href="{escape(url)}">{escape(name)}</a>') or
 * mark_safe('... "%s"' % escape(x)). A raw value next to escaped ones still counts.
 */
function markSafeAllEscaped(line: string): boolean {
  const fstr = /\bmark_safe\(\s*f(['"])(.*?)\1/.exec(line);
  if (fstr) {
    const values = [...fstr[2].matchAll(/\{([^{}]+)\}/g)].map((m) => m[1]);
    return values.length > 0 && values.every((v) => ESCAPED.test(v));
  }
  const pct = /\bmark_safe\(\s*(['"]).*?\1\s*%\s*(\(([^()]|\([^()]*\))*\)|[^)]+)/.exec(line);
  if (pct) {
    const args = pct[2].replace(/^\(|\)$/g, '').split(/,(?![^()]*\))/).map((a) => a.trim()).filter(Boolean);
    return args.length > 0 && args.every((a) => ESCAPED.test(a));
  }
  return false;
}

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

  const importsMarkup = /\bfrom\s+(?:markupsafe|jinja2|flask)\s+import\b[^\n]*\bMarkup\b|\b(?:markupsafe|jinja2|flask)\.Markup\b/.test(cleanContent);
  // django-cors-headers echoes the caller's Origin when allow-all is combined with credentials
  const corsCredentials = /^\s*CORS_ALLOW_CREDENTIALS\s*=\s*True\b/m.test(cleanContent);
  const devSettings = /(?:^|\/)(?:dev|local|test|tests|testing)[\w-]*\.py$|\/tests?\//.test(file.path.toLowerCase());

  lines.forEach((l, i) => {
    if (/^\s*#/.test(l)) return;

    if (corsCredentials && !devSettings && /^\s*CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True\b/.test(l)) {
      add({ ruleId: 29017, code: 'PYF-17', title: 'Django CORS Allows Every Origin With Credentials', severity: 'HIGH', category: 'Security Misconfiguration', lineIdx: i, why: 'With CORS_ALLOW_ALL_ORIGINS and CORS_ALLOW_CREDENTIALS both on, django-cors-headers reflects any Origin, so any website can make logged-in requests and read the responses.', fix: 'Set CORS_ALLOWED_ORIGINS to your exact front-end origins and keep CORS_ALLOW_ALL_ORIGINS = False.' });
    }
    // Markup("...").format(x) and Markup("%s") % x escape their arguments; formatting inside the call does not
    if (importsMarkup && /\bMarkup\(\s*(?:f['"][^'"]*\{|['"][^'"]*['"]\s*%|['"][^'"]*['"]\.format\(|[^)]*['"]\s*\+\s*\w)/.test(l) && !/\bescape\(/.test(l)) {
      add({ ruleId: 29018, code: 'PYF-18', title: 'Markup() Wraps an Already-Formatted String (XSS)', severity: 'HIGH', category: 'Cross-Site Scripting', lineIdx: i, why: 'Formatting the string before wrapping it in Markup marks the interpolated value as safe HTML, so Jinja renders it unescaped.', fix: 'Format through Markup so arguments are escaped: Markup("<b>{}</b>").format(name), or use markupsafe.escape(name).' });
    }

    if (/\.extra\([^)]*(?:where|select|tables)\s*=\s*[^)]*(?:f['"]|['"][^'"]*['"]\s*\%|['"][^'"]*['"]\.format\()/.test(l)) {
      add({ ruleId: 29002, code: 'PYF-02', title: 'Django extra() SQL Injection', severity: 'CRITICAL', category: 'Injection', lineIdx: i, why: 'Formatting strings into extra() clauses allows SQL injection.', fix: 'Use parameters for variables, or migrate to .annotate() / .filter().' });
    }
    if (/\bmark_safe\(\s*(?:f['"]|['"][^'"]*['"]\s*\%|['"][^'"]*['"]\.format\(|[^)]*\+)/.test(l) && !markSafeAllEscaped(l)) {
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
