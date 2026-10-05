/**
 * Go, Java/Spring/Kotlin, PHP/Laravel, Ruby/Rails security (BEF-xx, Rule IDs 29101-29199).
 * Each rule needs request input or an unsafe API on the matched line; see tests/rules/fixtures/backend-v4.ts.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

const PHP_INPUT = /\$_(?:GET|POST|REQUEST|COOKIE)\b|\$request->(?:input|get|query|post)\(|\brequest\(\s*['"]/;
const RAILS_PARAMS = /\bparams\[|\bparams\.(?:fetch|require|dig)\(/;

export function evaluateBackendV4Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.toLowerCase();
  const hits: Hit[] = [];
  const firstLine = (re: RegExp) => lines.findIndex((l) => re.test(l));

  if (/\.(?:java|kt)$/.test(path)) {
    // BEF-01: Jackson polymorphic typing for any class lets JSON choose the class to instantiate (gadget-chain RCE)
    const idx = firstLine(/\.enableDefaultTyping\s*\(|\.activateDefaultTyping\s*\([^)]*LaissezFaireSubTypeValidator|@JsonTypeInfo\s*\(\s*use\s*=\s*JsonTypeInfo\.Id\.CLASS/);
    if (idx !== -1) hits.push({
      ruleId: 29101, code: 'BEF-01', severity: 'HIGH', category: 'Insecure Deserialization', lineIdx: idx,
      title: 'Jackson Default Typing Lets JSON Pick the Class to Instantiate',
      why: 'With default typing (or Id.CLASS / a permissive validator) a JSON payload names the Java class to create, which known gadget chains turn into remote code execution.',
      fix: 'Remove default typing; for real polymorphism use @JsonTypeInfo(use = Id.NAME) with explicit @JsonSubTypes or a BasicPolymorphicTypeValidator allow-list.'
    });
  }

  if (path.endsWith('.go')) {
    // BEF-02: text/template does no HTML escaping; rendering it into an HTTP response is XSS
    if (/"text\/template"/.test(cleanContent) && /http\.ResponseWriter/.test(cleanContent)) {
      const idx = firstLine(/\.Execute(?:Template)?\s*\(\s*w\b/);
      if (idx !== -1) hits.push({
        ruleId: 29102, code: 'BEF-02', severity: 'HIGH', category: 'Cross-Site Scripting', lineIdx: idx,
        title: 'Go text/template Rendered Into an HTTP Response (No HTML Escaping)',
        why: 'text/template inserts values verbatim, so any user-controlled field in the data becomes HTML/JS in the page.',
        fix: 'Import "html/template" instead of "text/template" for anything written to an http.ResponseWriter.'
      });
    }
  }

  if (/\.blade\.php$/.test(path)) {
    // BEF-04: unescaped Blade output of request data
    const idx = lines.findIndex((l) => /\{!!/.test(l) && (PHP_INPUT.test(l) || /\bold\(\s*['"]/.test(l)));
    if (idx !== -1) hits.push({
      ruleId: 29104, code: 'BEF-04', severity: 'HIGH', category: 'Cross-Site Scripting', lineIdx: idx,
      title: 'Blade {!! !!} Prints Request Input Without Escaping',
      why: '{!! !!} disables Blade escaping, so request or old-input values render as HTML/JS (reflected XSS).',
      fix: 'Use {{ }} (escaped) for request values; reserve {!! !!} for HTML you produced and sanitized server-side.'
    });
  }

  if (/\.(?:rb|erb)$/.test(path)) {
    // BEF-05: request-chosen class or method (constantize / send)
    const idx = lines.findIndex((l) => RAILS_PARAMS.test(l) && /\.(?:safe_)?constantize\b|\b(?:public_)?send\s*\(\s*params|\.(?:public_)?send\s*\(\s*params/.test(l));
    if (idx !== -1) hits.push({
      ruleId: 29105, code: 'BEF-05', severity: 'CRITICAL', category: 'Injection', lineIdx: idx,
      title: 'Rails Request Input Chooses the Class or Method to Call',
      why: 'constantize/send on params lets the attacker instantiate any class or call any method (e.g. destroy, system), which can escalate to RCE.',
      fix: 'Map params to an explicit allow-list ({ "pdf" => PdfExporter }.fetch(params[:type])) instead of constantize/send.'
    });
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `bef${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
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
    logs.push(`[${ts}] [BACKEND V4] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
