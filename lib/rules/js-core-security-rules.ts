/**
 * JavaScript / Node.js core injection rules (JS-SEC-01..02, Rule IDs 24001-24002).
 * Classes other languages already covered (PHP, Python, Java, .NET, Go) but Node did not.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export interface JsCoreSecurityRuleResult {
  findings: Finding[];
  logs: string[];
}

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; lineIdx: number; why: string; fix: string }

export function evaluateJsCoreSecurityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): JsCoreSecurityRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];
  if (!/\.[cm]?[jt]sx?$/i.test(file.path) || /node_modules\//.test(file.path)) return { findings, logs };
  const hits: Hit[] = [];

  // JS-SEC-01: deserializers that revive functions (node-serialize, funcster, cryo) execute attacker code
  const unsafeDeserializer = /(?:require\(\s*['"](node-serialize|funcster|cryo)['"]\s*\)|from\s+['"](node-serialize|funcster|cryo)['"])/;
  const lib = cleanContent.match(unsafeDeserializer);
  if (lib) {
    const callIdx = lines.findIndex((l) => /\.(?:unserialize|deserialize|parse)\s*\(/.test(l) && !/^\s*(?:\/\/|\*)/.test(l));
    if (callIdx !== -1) {
      hits.push({
        ruleId: 24001, code: 'JS-SEC-01', severity: 'CRITICAL', lineIdx: callIdx,
        title: 'Insecure Deserialization With a Function-Reviving Library (RCE)',
        why: `${lib[1] || lib[2]} reconstructs functions from input (IIFE payloads run on unserialize), giving remote code execution on untrusted data.`,
        fix: 'Parse untrusted data with JSON.parse and validate it with a schema (e.g. zod); never revive functions from user input.'
      });
    }
  }

  // JS-SEC-02: XML parsed with external entity expansion enabled
  const xxeIdx = lines.findIndex((l) => /parseXml(?:String)?\s*\(|new\s+libxmljs|XmlDocument\.fromString|DOMParser|xml2js/i.test(l) && /noent\s*:\s*true|replaceEntities\s*:\s*true|processEntities\s*:\s*true/i.test(l));
  const xxeFileLevel = xxeIdx === -1 && /libxmljs|libxml/i.test(cleanContent) && /noent\s*:\s*true/i.test(cleanContent);
  if (xxeIdx !== -1 || xxeFileLevel) {
    const lineIdx = xxeIdx !== -1 ? xxeIdx : lines.findIndex((l) => /noent\s*:\s*true/i.test(l));
    hits.push({
      ruleId: 24002, code: 'JS-SEC-02', severity: 'HIGH', lineIdx,
      title: 'XML External Entity (XXE) Expansion Enabled',
      why: 'Entity substitution (noent: true) lets an uploaded XML document read local files (file:///etc/passwd) or reach internal URLs.',
      fix: 'Parse XML with entity expansion disabled (omit noent / set it false) and reject DOCTYPE declarations in untrusted input.'
    });
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `jssec${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: 'Injection',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [JS CORE] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
