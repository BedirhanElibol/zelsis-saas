import type { Finding } from '@/data/schema';
import type { CodeFile } from './types';
import { evaluateSecurityRules } from '../rules/security-rules';
import { buildLiveFindings } from './live-checks';

export interface BuiltinRuleContext {
  file: CodeFile;
  lines: string[];
  rawContent: string;
  cleanContent: string;
  findings: Finding[];
  logs: string[];
  addFinding: (finding: Finding) => void;
  /** Shared finding id counter; read on entry and written back on exit. */
  counter: { count: number };
}

/**
 * Built-in rules evaluated inline per file: core SEC rules, live-deployment header checks
 * and the VibePolish UI-xx heuristics. Runs before the modular RULE_ENGINES.
 */
export function evaluateBuiltinRules(ctx: BuiltinRuleContext): void {
  const { file, lines, rawContent, cleanContent, findings, logs, addFinding } = ctx;
  let findingCounter = ctx.counter.count;
  const lowerFilePath = (file?.path || '').toLowerCase();

  // Rule 1: Exposed Stripe/OpenAI API Keys (F-16: Scans comments, F-17: Masks secrets in snippet)
  const secretPattern = /sk_live_[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,}|api[_-]?key\s*=\s*["']sk-[a-zA-Z0-9_-]{20,}["']/i;
  if (secretPattern.test(rawContent)) {
    const matchLineIdx = lines.findIndex(l => secretPattern.test(l) && !/placeholder|EXAMPLE|dummy|test_key/i.test(l));
    if (matchLineIdx !== -1) {
      const lineNum = matchLineIdx + 1;
      const rawLine = lines[matchLineIdx] || '';
      const maskedSnippet = rawLine.replace(/sk-[a-zA-Z0-9_-]{16,}|sk_live_[a-zA-Z0-9]{16,}/gi, (m) => m.slice(0, 4) + '****' + m.slice(-2));

      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 1,
        type: 'SECURITY',
        title: 'Exposed Hardcoded API Key / Secret Token',
        severity: 'CRITICAL',
        category: 'Secret Isolation',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: maskedSnippet || '[REDACTED_SECRET]',
        reproductionSteps: [
          `Scanned file string content at ${file.path}:${lineNum}.`,
          'Detected live secret key prefix (sk_live_ / sk-proj-).'
        ],
        remediationPrompt: `Extract exposed API secret keys from ${file.path} into server-only environment variables and reference process.env.`,
        status: 'OPEN',
        owner: 'Security Lead',
        falsePositive: false
      });

      logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] SEC-01 Secret Exposure detected in ${file.path}:${lineNum}`);
    }
  }

  // Rule 3: Supabase Permissive Row Level Security (RLS)
  if (cleanContent.includes('USING (true)') || cleanContent.includes('FOR ALL USING (true)')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('--') && l.includes('USING (true)'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;

    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 3,
      type: 'SECURITY',
      title: 'Permissive Row Level Security (RLS) Policy (USING true)',
      severity: 'CRITICAL',
      category: 'Database',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'USING (true);',
      reproductionSteps: [
        `Scanned database migration SQL at ${file.path}:${lineNum}.`,
        'Detected default allow-all policy using (true).'
      ],
      remediationPrompt: `Replace permissive RLS policy in ${file.path}. Write strict auth.uid() = user_id checks.`,
      status: 'OPEN',
      owner: 'Backend Team',
      falsePositive: false
    });

    logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] SEC-03 Permissive RLS Policy in ${file.path}:${lineNum}`);
  }

  if (file.content.includes("origin: '*'") || file.content.includes('Access-Control-Allow-Origin: *')) {
    const matchLineIdx = lines.findIndex(l => l.includes("origin: '*'") || l.includes('Access-Control-Allow-Origin: *'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;

    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 8,
      type: 'SECURITY',
      title: 'Wildcard Access-Control-Allow-Origin (*) CORS Vulnerability',
      severity: 'HIGH',
      category: 'Network & CORS',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || "origin: '*'",
      reproductionSteps: [
        `Scanned API server setup at ${file.path}:${lineNum}.`,
        'Detected wildcard Access-Control-Allow-Origin header.'
      ],
      remediationPrompt: `Restrict CORS origin in ${file.path} to process.env.PRODUCTION_CLIENT_URL.`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });

    logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] SEC-08 Wildcard CORS configuration in ${file.path}:${lineNum}`);
  }

  // Rule 16: Dangerously Set Inner HTML (XSS)
  const isCompiledBundle = file.path.includes('live-deployment/bundle-') || file.path.includes('/vendor/') || file.path.includes('node_modules');
  const isSafeMdxOrJsonLd = isCompiledBundle || file.path.includes('mdx-components') || file.path.includes('syntax-highlight') || file.content.includes('application/ld+json');
  if (!isSafeMdxOrJsonLd && (cleanContent.includes('dangerouslySetInnerHTML') || cleanContent.includes('innerHTML ='))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && (l.includes('dangerouslySetInnerHTML') || l.includes('innerHTML')));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;

    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 16,
      type: 'SECURITY',
      title: 'Unsanitized Direct InnerHTML DOM Mutation (XSS Risk)',
      severity: 'HIGH',
      category: 'Input & Files',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'dangerouslySetInnerHTML={{ __html: content }}',
      reproductionSteps: [
        `Scanned frontend component rendering at ${file.path}:${lineNum}.`,
        'Detected unescaped DOM insertion susceptible to Cross-Site Scripting.'
      ],
      remediationPrompt: `Sanitize input in ${file.path} using DOMPurify before setting innerHTML.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });

    logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] SEC-16 Unsanitized innerHTML in ${file.path}:${lineNum}`);
  }

  // Advanced Option A Security Rules (SEC-SCA-01, SEC-LOG-01, SEC-LLM-01) & Modular Engine
  const secCounter = { count: findingCounter };
  const secResult = evaluateSecurityRules(file, lines, cleanContent, secCounter);
  findingCounter = secCounter.count;
  for (const sf of secResult.findings) {
    if (!findings.some((existing) => existing.ruleId === sf.ruleId && existing.filePath === sf.filePath && existing.lineRange === sf.lineRange)) {
      addFinding(sf);
    }
  }
  for (const logItem of secResult.logs) {
    if (!logs.includes(logItem)) logs.push(logItem);
  }

  // Live Web Deployment Security Header Rules: Parse missingSecurityHeaders from JSON
  if (file.path.includes('live-deployment/security-headers.json')) {
    try {
      const headerData = JSON.parse(file.content);
      const missing: string[] = headerData.missingSecurityHeaders || [];
      const statusCode: number = headerData.statusCode || 200;

      // Rule 100: Broken Link / Unhealthy Endpoint Detection
      if (statusCode === 404 || statusCode >= 500 || headerData.isHealthy === false) {
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 100,
          type: 'SECURITY',
          title: `SEC-WEB-00: Target Link Unhealthy / Broken Endpoint (HTTP ${statusCode})`,
          severity: 'HIGH',
          category: 'Link Health & Availability',
          filePath: 'Live Web Target (Endpoint Check)',
          lineRange: `HTTP ${statusCode}`,
          snippet: `HTTP Status Code: ${statusCode} ${headerData.linkStatusText || ''}`,
          reproductionSteps: [
            `Pinged live URL endpoint: ${headerData.targetUrl || 'Target Web Site'}.`,
            `Server returned status code HTTP ${statusCode} (Link is broken, dead, or misconfigured).`
          ],
          remediationPrompt: `Fix broken URL target link (${headerData.targetUrl}). Verify domain DNS records, SSL certificates, and web server deployment routing.`,
          status: 'OPEN',
          owner: 'DevOps & Infrastructure Lead',
          falsePositive: false
        });
        logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] SEC-WEB-00 Broken Link / Unhealthy Target Endpoint (HTTP ${statusCode})`);
      }

      // Rule 101: Missing Content-Security-Policy
      if (missing.some((h: string) => h.includes('Content-Security-Policy'))) {
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 101,
          type: 'SECURITY',
          title: 'SEC-WEB-01: Absence of Content-Security-Policy (CSP) Header',
          severity: 'MEDIUM',
          category: 'Network & Security Headers',
          filePath: 'Live Web Target (HTTP Headers)',
          lineRange: 'Header Deficit',
          snippet: 'Content-Security-Policy: [Missing]',
          reproductionSteps: [
            'Scanned live production HTTP headers.',
            'Detected missing Content-Security-Policy header. Site is vulnerable to XSS and data injection.'
          ],
          remediationPrompt: `Configure strict Content-Security-Policy header (default-src 'self'; script-src 'self' 'nonce-...') on production web server or Next.js headers config.`,
          status: 'OPEN',
          owner: 'Security Architect',
          falsePositive: false
        });
        logs.push(`[${new Date().toLocaleTimeString()}] [MEDIUM] SEC-WEB-01 Missing Content-Security-Policy Header on Live Web Deployment`);
      }

      // Rule 102: Missing HSTS Header
      if (missing.some((h: string) => h.includes('Strict-Transport-Security'))) {
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 102,
          type: 'SECURITY',
          title: 'SEC-WEB-02: Absence of HSTS Strict Transport Security Header',
          severity: 'MEDIUM',
          category: 'Network & TLS',
          filePath: 'Live Web Target (HTTP Headers)',
          lineRange: 'Header Deficit',
          snippet: 'Strict-Transport-Security: [Missing]',
          reproductionSteps: [
            'Scanned live HTTPS headers.',
            'Detected missing Strict-Transport-Security header, allowing HTTP downgrade attacks.'
          ],
          remediationPrompt: `Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' header to production CDN / Nginx / Vercel headers.`,
          status: 'OPEN',
          owner: 'DevOps Lead',
          falsePositive: false
        });
        logs.push(`[${new Date().toLocaleTimeString()}] [MEDIUM] SEC-WEB-02 Missing HSTS Header on Live Web Target`);
      }

      // Rule 103: Missing X-Frame-Options (Clickjacking)
      const hasCspFrameAncestors = (headerData.headers?.['content-security-policy'] || '').includes('frame-ancestors');
      if (!hasCspFrameAncestors && missing.some((h: string) => h.includes('X-Frame-Options'))) {
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 103,
          type: 'SECURITY',
          title: 'SEC-WEB-03: Clickjacking Exposure (Missing X-Frame-Options Header)',
          severity: 'MEDIUM',
          category: 'Frame Isolation',
          filePath: 'Live Web Target (HTTP Headers)',
          lineRange: 'Header Deficit',
          snippet: 'X-Frame-Options: [Missing]',
          reproductionSteps: [
            'Scanned HTTP headers.',
            'Detected missing X-Frame-Options header and absence of CSP frame-ancestors directive, allowing malicious framing/clickjacking.'
          ],
          remediationPrompt: `Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' header, or add 'frame-ancestors 'self'' to CSP in production server configuration.`,
          status: 'OPEN',
          owner: 'Security Architect',
          falsePositive: false
        });
        logs.push(`[${new Date().toLocaleTimeString()}] [MEDIUM] SEC-WEB-03 Clickjacking risk: Missing X-Frame-Options header`);
      }

      // Rule 104: Missing X-Content-Type-Options (MIME Sniffing)
      if (missing.some((h: string) => h.includes('X-Content-Type-Options'))) {
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 104,
          type: 'SECURITY',
          title: 'SEC-WEB-04: MIME Sniffing Vulnerability (Missing X-Content-Type-Options)',
          severity: 'LOW',
          category: 'Content Protection',
          filePath: 'Live Web Target (HTTP Headers)',
          lineRange: 'Header Deficit',
          snippet: 'X-Content-Type-Options: [Missing]',
          reproductionSteps: [
            'Scanned HTTP response headers.',
            'Detected missing X-Content-Type-Options header, leaving users vulnerable to MIME-confusion attacks.'
          ],
          remediationPrompt: `Set 'X-Content-Type-Options: nosniff' header across all production HTTP responses.`,
          status: 'OPEN',
          owner: 'DevOps Lead',
          falsePositive: false
        });
        logs.push(`[${new Date().toLocaleTimeString()}] [LOW] SEC-WEB-04 Missing X-Content-Type-Options: nosniff`);
      }

      // LIVE-01..07: exposed .env/.git, TLS, HTTP redirect, cookie flags (lib/scanner/live-checks.ts)
      if (headerData.liveProbe) {
        for (const lf of buildLiveFindings(headerData.liveProbe)) {
          addFinding(lf);
          logs.push(`[${new Date().toLocaleTimeString()}] [${lf.severity}] ${lf.title}`);
        }
      }
    } catch (parseErr) {
      // Not valid JSON, skip header analysis
    }
  }

  // Removed as unsound (ids are never reused):
  // 27251 file-level L1 tab-nabbing check (browsers imply rel=noopener for target=_blank);
  // 1001/1003/1004/1006/1008/1011/1021/1032 opinion / taste heuristics (codes clashed with ui-quality-rules UI-xx);
  // 1007, 1041, 115, 134, 160, 185 absence-of-X / file-level heuristics (made-up component names, line counts);
  // 48 any single-brace text in a file mentioning "template"; 27252 keyed on made-up agentRunner/executeAgent names;
  // 195 any top_p mention in a .tsx file; 197 two hard-coded model strings (aliases are a documented choice).

  // VibePolish UI-23: Robotic AI Apologies (As an AI language model...)
  if (file.content.includes('As an AI language model') || file.content.includes('As an AI assistant')) {
    const matchLineIdx = lines.findIndex(l => l.includes('As an AI'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1023,
      type: 'VIBEPOLISH',
      title: 'UI-23: Robotic Apology / Refusal Boilerplate',
      severity: 'LOW',
      category: 'Model Behavior',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'As an AI language model, I cannot fulfill this request.',
      reproductionSteps: [`Scanned error handlers/prompts in ${file.path}:${lineNum}.`, 'Detected robotic fallback text ("As an AI language model...").'],
      remediationPrompt: `Replace robotic refusal messages in ${file.path} with branded, natural fallback messages and direct actionable alternatives.`,
      status: 'OPEN',
      owner: 'Prompt Engineer',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-23: Robotic AI apology boilerplate detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-61: LangChain CharacterTextSplitter (single fixed separator). RecursiveCharacterTextSplitter,
  // the documented default for generic text, is not matched (the lookbehind rejects the "Recursive" prefix).
  const naiveSplitterRe = /(?<![A-Za-z0-9_])CharacterTextSplitter\s*\(/;
  const naiveSplitterIdx = lines.findIndex(l => naiveSplitterRe.test(l));
  if (naiveSplitterIdx !== -1) {
    const lineNum = naiveSplitterIdx + 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 61,
      type: 'VIBEPOLISH',
      title: 'UI-61: Naive Fixed-Character Text Splitter',
      severity: 'LOW',
      category: 'RAG Architecture',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[naiveSplitterIdx],
      reproductionSteps: [`Scanned RAG pipeline in ${file.path}:${lineNum}.`, 'Detected CharacterTextSplitter, which splits on one fixed separator and leaves oversized chunks unsplit instead of falling back to paragraph, sentence and word boundaries.'],
      remediationPrompt: `Replace CharacterTextSplitter in ${file.path} with RecursiveCharacterTextSplitter (or a structure-aware splitter for Markdown / code) so chunks respect paragraph and sentence boundaries.`,
      status: 'OPEN',
      owner: 'AI Architect',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-61: Naive text chunking detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-106: Empty Silent Catch Block. Checked on the raw source so a catch whose body is only an
  // explanatory comment (`catch { /* optional feature */ }`) counts as intentional and is not reported.
  const isJsSource = /\.(?:[cm]?[jt]sx?)$/.test(lowerFilePath) && !lowerFilePath.endsWith('.d.ts');
  const emptyCatch = !isCompiledBundle && isJsSource ? /\bcatch\s*(?:\(\s*[A-Za-z_$][\w$]*\s*(?::\s*\w+\s*)?\))?\s*\{\s*\}/.exec(rawContent) : null;
  if (emptyCatch) {
    const rawLines = rawContent.split('\n');
    const matchLineIdx = rawContent.slice(0, emptyCatch.index).split('\n').length - 1;
    const lineNum = matchLineIdx + 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 106,
      type: 'VIBEPOLISH',
      title: 'UI-106: Empty Silent Catch Block',
      severity: 'LOW',
      category: 'Code Quality & Refactoring',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (rawLines[matchLineIdx] || '').trim() || 'try { ... } catch (e) {}',
      reproductionSteps: [`Scanned try-catch blocks in ${file.path}:${lineNum}.`, 'Detected an empty catch block with no comment, log or rethrow: failures in the try block disappear silently.'],
      remediationPrompt: `Handle the error in ${file.path}:${lineNum}: log it with context, rethrow it, or add a comment explaining why ignoring it is safe.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [LOW] UI-106 Empty catch block detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-111: TypeScript Any Type Safety Escape (comment-stripped code, TypeScript sources only)
  const anyTypeRe = /:\s*any\b|\bas\s+any\b/;
  const anyMatches = /\.tsx?$/.test(lowerFilePath) && !lowerFilePath.endsWith('.d.ts') ? (cleanContent.match(new RegExp(anyTypeRe.source, 'g')) || []).length : 0;
  if (anyMatches > 5) {
    const matchLineIdx = cleanContent.split('\n').findIndex(l => anyTypeRe.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 111,
      type: 'VIBEPOLISH',
      title: 'UI-111: TypeScript "any" Type Escape',
      severity: 'LOW',
      category: 'TypeScript & Types',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'const data: any = await response.json();',
      reproductionSteps: [`Scanned TypeScript type annotations in ${file.path}:${lineNum}.`, `Detected ${anyMatches} explicit "any" annotations or casts bypassing type checking in this file.`],
      remediationPrompt: `Replace "any" types in ${file.path} with real interfaces, Zod-inferred types, or unknown plus a type guard.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-111: Excessive 'any' type usage detected (${file.path})`);
  }

  // VibePolish UI-117: global (window / document) listener added in a React effect and never removed.
  // Listeners on elements are collected with the element; `{ once: true }` and AbortSignal-based cleanup count as removal.
  const isVendorOrLib = isCompiledBundle || /(?:^|\/)(?:vendor|external|third_party|dist|bundles|node_modules)\//i.test(lowerFilePath);
  const globalListenerRe = /\b(?:window|document)\.addEventListener\s*\(/;
  const leakIdx = !isVendorOrLib && isJsSource && /\buseEffect\s*\(/.test(cleanContent) && !/removeEventListener\s*\(|\bAbortController\b|\bsignal\s*[:,}]/.test(cleanContent)
    ? cleanContent.split('\n').findIndex(l => globalListenerRe.test(l) && !/\bonce\s*:\s*true\b/.test(l))
    : -1;
  if (leakIdx !== -1) {
    const lineNum = leakIdx + 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 117,
      type: 'VIBEPOLISH',
      title: 'UI-117: Uncleaned Event Listener Memory Leak',
      severity: 'MEDIUM',
      category: 'Database & Performance',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[leakIdx],
      reproductionSteps: [`Scanned event listener bindings in ${file.path}:${lineNum}.`, 'Detected a window/document listener registered in a component effect with no removeEventListener or AbortSignal cleanup: every mount adds another handler that keeps the unmounted component alive.'],
      remediationPrompt: `Return a cleanup function from the useEffect in ${file.path} that calls removeEventListener with the same handler (or pass an AbortController signal and abort it).`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [MEDIUM] UI-117 Uncleaned event listener detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-141: Unbounded Token Usage Waste
  if (file.content.includes('chat.completions.create') && !file.content.includes('max_tokens') && !file.content.includes('maxTokens')) {
    const matchLineIdx = lines.findIndex(l => l.includes('chat.completions.create'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 141,
      type: 'VIBEPOLISH',
      title: 'UI-141: Unbounded Token Consumption (Missing max_tokens Limit)',
      severity: 'MEDIUM',
      category: 'Token Economy & Costs',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'await openai.chat.completions.create({ model: "gpt-4o", messages });',
      reproductionSteps: [`Scanned model completion call in ${file.path}:${lineNum}.`, 'Detected completion call without explicit max_tokens parameter (risks unbounded output token bills).'],
      remediationPrompt: `Add explicit max_tokens boundary in ${file.path} (e.g. max_tokens: 1500) and conciseness system rules to limit token bleed.`,
      status: 'OPEN',
      owner: 'Backend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-141: Unbounded max_tokens parameter detected (${file.path}:${lineNum})`);
  }


  ctx.counter.count = findingCounter;
}
