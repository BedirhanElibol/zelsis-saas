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
          severity: 'CRITICAL',
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
        logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] SEC-WEB-00 Broken Link / Unhealthy Target Endpoint (HTTP ${statusCode})`);
      }

      // Rule 101: Missing Content-Security-Policy
      if (missing.some((h: string) => h.includes('Content-Security-Policy'))) {
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 101,
          type: 'SECURITY',
          title: 'SEC-WEB-01: Absence of Content-Security-Policy (CSP) Header',
          severity: 'CRITICAL',
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
        logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] SEC-WEB-01 Missing Content-Security-Policy Header on Live Web Deployment`);
      }

      // Rule 102: Missing HSTS Header
      if (missing.some((h: string) => h.includes('Strict-Transport-Security'))) {
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 102,
          type: 'SECURITY',
          title: 'SEC-WEB-02: Absence of HSTS Strict Transport Security Header',
          severity: 'HIGH',
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
        logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] SEC-WEB-02 Missing HSTS Header on Live Web Target`);
      }

      // Rule 103: Missing X-Frame-Options (Clickjacking)
      const hasCspFrameAncestors = (headerData.headers?.['content-security-policy'] || '').includes('frame-ancestors');
      if (!hasCspFrameAncestors && missing.some((h: string) => h.includes('X-Frame-Options'))) {
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 103,
          type: 'SECURITY',
          title: 'SEC-WEB-03: Clickjacking Exposure (Missing X-Frame-Options Header)',
          severity: 'HIGH',
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
        logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] SEC-WEB-03 Clickjacking risk: Missing X-Frame-Options header`);
      }

      // Rule 104: Missing X-Content-Type-Options (MIME Sniffing)
      if (missing.some((h: string) => h.includes('X-Content-Type-Options'))) {
        addFinding({
          id: `real-find-${Date.now()}-${findingCounter++}`,
          ruleId: 104,
          type: 'SECURITY',
          title: 'SEC-WEB-04: MIME Sniffing Vulnerability (Missing X-Content-Type-Options)',
          severity: 'MEDIUM',
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
        logs.push(`[${new Date().toLocaleTimeString()}] [MEDIUM] SEC-WEB-04 Missing X-Content-Type-Options: nosniff`);
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

  // Live Web Deployment Security Rule 4: Insecure target="_blank" Link
  if (file.path.includes('live-deployment') && file.content.includes('target="_blank"') && !file.content.includes('rel="noopener')) {
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 104,
      type: 'SECURITY',
      title: 'SEC-WEB-04: Insecure External Link Target Blank (Tab-Nabbing Risk)',
      severity: 'MEDIUM',
      category: 'HTML Security',
      filePath: file.path,
      lineRange: 'L1',
      snippet: '<a href="..." target="_blank">',
      reproductionSteps: [
        'Scanned HTML links on target web page.',
        'Detected target="_blank" links missing rel="noopener noreferrer".'
      ],
      remediationPrompt: `Add rel="noopener noreferrer" to all target="_blank" links in HTML to prevent window.opener hijacking.`,
      status: 'OPEN',
      owner: 'Frontend Lead',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [MEDIUM] SEC-WEB-04 Insecure target="_blank" link detected`);
  }

  // VibePolish UI-01: Generic Purple-Blue Gradient Cliché
  if (/bg-gradient-to-[rblt]\s+from-(purple|violet|indigo)-[0-9]{3}/i.test(file.content) || file.content.includes('from-purple-600 to-blue-500')) {
    const matchLineIdx = lines.findIndex(l => /from-(purple|violet|indigo)/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1001,
      type: 'VIBEPOLISH',
      title: 'UI-01: Generic Purple-Blue Neon Gradient Cliché',
      severity: 'MEDIUM',
      category: 'Color & Background',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'bg-gradient-to-r from-purple-600 to-blue-500',
      reproductionSteps: [`Scanned CSS classes in ${file.path}:${lineNum}.`, 'Detected high-contrast raw purple/neon gradient.'],
      remediationPrompt: `Replace generic purple-blue linear gradients in ${file.path} with semantic flat color tokens (primary, destructive, muted) or subtle monochromatic dark surfaces.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-01: Purple-blue gradient detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-03: Sparkle / Magic Wand Icon Overuse
  if (file.content.includes('Sparkles') || file.content.includes('Wand2') || file.content.includes('✨')) {
    const matchLineIdx = lines.findIndex(l => l.includes('Sparkles') || l.includes('Wand2') || l.includes('✨'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1003,
      type: 'VIBEPOLISH',
      title: 'UI-03: Overused Sparkle / Magic Wand Icon Cliché',
      severity: 'LOW',
      category: 'Icons & Micro-copy',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<Sparkles className="w-4 h-4" />',
      reproductionSteps: [`Scanned component icons in ${file.path}:${lineNum}.`, 'Detected generic Sparkle icon placed on AI buttons/inputs.'],
      remediationPrompt: `Remove generic Sparkle/Magic Wand icons in ${file.path}. Replace with descriptive action micro-copy (e.g. "Summarize", "Filter", "Analyze").`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-03: Sparkle icon overuse detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-04: Absence of Empty State Component Fallback (Frontend components only, excluding persistent layout chrome)
  const isFrontendComponent = file.path.endsWith('.tsx') || file.path.endsWith('.jsx');
  const isStructuralChrome = /layout\.[tj]sx$|header\.[tj]sx$|nav\.[tj]sx$|navbar\.[tj]sx$|footer\.[tj]sx$|sidebar\.[tj]sx$/i.test(file.path);
  if (isFrontendComponent && !isStructuralChrome && file.content.includes('.map(') && !file.content.includes('.length === 0') && !file.content.includes('EmptyState') && !file.content.includes('no data') && !file.content.includes('isEmpty')) {
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1004,
      type: 'VIBEPOLISH',
      title: 'UI-04: Absence of Empty State Component Fallback',
      severity: 'MEDIUM',
      category: 'Layout & Onboarding',
      filePath: file.path,
      lineRange: 'L1-L50',
      snippet: 'items.map((item) => <Card key={item.id} ... />)',
      reproductionSteps: [`Scanned list rendering in ${file.path}.`, 'Detected list mapping without empty state / starter prompt fallback.'],
      remediationPrompt: `Add an Empty State component with starter prompts / demo data in ${file.path} when items array is empty.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-04: Missing Empty State component detected (${file.path})`);
  }

  // Note: VibePolish UI-05 is canonically evaluated via CLICHE-76 in evaluateAiClicheRules to prevent duplicate reporting.

  // VibePolish UI-06: Pulsating Status Dot & Glowing Badge Cliché (AI Slop Pattern)
  const hasPulsingDotSlop = /rounded-full\s+bg-emerald-[45]00[^"']*animate-pulse/i.test(file.content) ||
    /animate-pulse[^"']*rounded-full\s+bg-emerald-[45]00/i.test(file.content);
  const isLiveRunner = /ScanRunnerView|TerminalLogWindow/i.test(file.path);
  if (isFrontendComponent && !isLiveRunner && hasPulsingDotSlop) {
    const matchLineIdx = lines.findIndex(l => /animate-pulse/i.test(l) && /bg-emerald/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1006,
      type: 'VIBEPOLISH',
      title: 'UI-06: Pulsating Status Dot & Glowing Badge Cliché (AI Slop Anti-Pattern)',
      severity: 'LOW',
      category: 'Visual Polish & Motion',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />',
      reproductionSteps: [
        `Scanned status badges and header pills in ${file.path}:${lineNum}.`,
        'Detected pulsating green indicator dot inside static component or card.'
      ],
      remediationPrompt: `Remove distracting pulsating green animation dots in static badges in ${file.path}. Use static, high-contrast, monochromatic or muted status badges for a professional, distraction-free interface.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-06: Pulsing status dot cliché detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-08: Repetitive Checkmark Icon Flooding (AI Slop Pattern)
  const hasCheckmarkFlooding = /<(?:CheckCircle2|CheckCircle)\b[^>]*className="[^"]*text-emerald-400[^"]*shrink-0/i.test(file.content) &&
    /\.map\s*\(/.test(file.content) &&
    file.content.includes('<li');
  if (isFrontendComponent && hasCheckmarkFlooding) {
    const matchLineIdx = lines.findIndex(l => /<(?:CheckCircle2|CheckCircle)\b/i.test(l) && /<li/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1008,
      type: 'VIBEPOLISH',
      title: 'UI-08: Repetitive Checkmark Icon Flooding (AI Slop Anti-Pattern)',
      severity: 'LOW',
      category: 'Visual Hierarchy & Typography',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<CheckCircle2 size={16} className="text-emerald-400 shrink-0" />',
      reproductionSteps: [
        `Scanned feature list elements in ${file.path}:${lineNum}.`,
        'Detected repetitive CheckCircle icons prepended to every single list item.'
      ],
      remediationPrompt: `Replace repetitive CheckCircle icons in ${file.path} with clean typography dashes (e.g. "—"), subtle numbered steps, or distinct architectural micro-cards.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-08: Repetitive checkmark flooding detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-07: Conversational Chat-Wrapper Lock-In Trap
  if (file.content.includes('messages.map') && !file.content.includes('Canvas') && !file.content.includes('Artifact') && !file.content.includes('Table')) {
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1007,
      type: 'VIBEPOLISH',
      title: 'UI-07: Conversational Chat-Wrapper Lock-In Trap',
      severity: 'HIGH',
      category: 'UX Architecture',
      filePath: file.path,
      lineRange: 'L1-L80',
      snippet: '<div className="chat-messages">{messages.map(...)}</div>',
      reproductionSteps: [`Scanned interface structure in ${file.path}.`, 'Detected full chat wrapper without structured side canvas or inline editable tables.'],
      remediationPrompt: `Refactor ${file.path} into a hybrid layout: introduce a side Artifacts/Canvas view or inline structured tables alongside chat.`,
      status: 'OPEN',
      owner: 'UX Architect',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-07: Chat-wrapper lock-in detected (${file.path})`);
  }

  // VibePolish UI-11: Uninformative "AI Thinking..." Spinner
  if (file.content.includes('AI is thinking') || file.content.includes('Thinking...') || (file.content.includes('Spinner') && !file.content.includes('step'))) {
    const matchLineIdx = lines.findIndex(l => l.includes('thinking') || l.includes('Thinking'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1011,
      type: 'VIBEPOLISH',
      title: 'UI-11: Uninformative "AI Thinking..." Spinner',
      severity: 'MEDIUM',
      category: 'State & Feedback',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<span>AI is thinking...</span>',
      reproductionSteps: [`Scanned loading state in ${file.path}:${lineNum}.`, 'Detected vague "Thinking..." spinner without step-by-step agent status progress.'],
      remediationPrompt: `Replace vague "Thinking..." text in ${file.path} with a transparent Stepper component showing live agent execution steps (e.g. "Scanning database tables...", "Synthesizing audit findings...").`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-11: Vague AI spinner detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-21: Cliché Fluff & Filler Prefaces
  if (/in today'?s fast-paced/i.test(file.content) || /it'?s important to remember/i.test(file.content)) {
    const matchLineIdx = lines.findIndex(l => /fast-paced|important to remember/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1021,
      type: 'VIBEPOLISH',
      title: 'UI-21: Cliché Fluff & Filler Prefaces',
      severity: 'MEDIUM',
      category: 'Text & Copywriting',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || "In today's fast-paced digital world...",
      reproductionSteps: [`Scanned text prompts in ${file.path}:${lineNum}.`, 'Detected LLM fluff starter phrase ("In today\'s fast-paced...").'],
      remediationPrompt: `Add strict system prompt constraints in ${file.path} banning fluff intros ("In today's fast-paced digital world..."). Force direct-to-answer responses.`,
      status: 'OPEN',
      owner: 'Prompt Engineer',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-21: Cliché filler text detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-23: Robotic AI Apologies (As an AI language model...)
  if (file.content.includes('As an AI language model') || file.content.includes('As an AI assistant')) {
    const matchLineIdx = lines.findIndex(l => l.includes('As an AI'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1023,
      type: 'VIBEPOLISH',
      title: 'UI-23: Robotic Apology / Refusal Boilerplate',
      severity: 'HIGH',
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

  // VibePolish UI-32: Excessive Meta-Announcement Statements
  if (/below (you can find|is the response|is the analysis)/i.test(file.content) || /here is the requested/i.test(file.content)) {
    const matchLineIdx = lines.findIndex(l => /below|here is the/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1032,
      type: 'VIBEPOLISH',
      title: 'UI-32: Excessive Meta-Announcement Preface Cliché',
      severity: 'LOW',
      category: 'Text & Copywriting',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Here is the requested analysis below:',
      reproductionSteps: [`Scanned text templates in ${file.path}:${lineNum}.`, 'Detected meta-announcement prefix ("Below you can find...").'],
      remediationPrompt: `Strip meta-announcement intros in ${file.path} via system prompt rule or regex post-processor. Jump straight into payload data.`,
      status: 'OPEN',
      owner: 'Prompt Engineer',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-32: Meta-announcement text detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-39: Missing Structured Schema Validation
  if (file.content.includes('openai.chat.completions') && !file.content.includes('response_format') && !file.content.includes('zodResponseFormat') && !file.content.includes('pydantic')) {
    const matchLineIdx = lines.findIndex(l => l.includes('openai.chat.completions'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1039,
      type: 'VIBEPOLISH',
      title: 'UI-39: Unvalidated Dynamic Outputs (Missing Zod Schema)',
      severity: 'HIGH',
      category: 'Output Hygiene',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'await openai.chat.completions.create({ ... });',
      reproductionSteps: [`Scanned LLM API endpoint in ${file.path}:${lineNum}.`, 'Detected OpenAI completion call without response_format or Zod schema validation.'],
      remediationPrompt: `Enforce Structured Outputs in ${file.path} using Zod schema and response_format: zodResponseFormat(Schema, "result") to eliminate formatting drift.`,
      status: 'OPEN',
      owner: 'Backend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-39: Missing Structured Zod schema detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-41: Monolithic System Prompt Inflation
  if (file.content.includes('system') && file.content.length > 5000 && (file.content.match(/role:\s*['"]system['"]/g) || []).length === 1) {
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 1041,
      type: 'VIBEPOLISH',
      title: 'UI-41: Monolithic System Prompt Inflation',
      severity: 'MEDIUM',
      category: 'Prompt Architecture',
      filePath: file.path,
      lineRange: 'L1-L100',
      snippet: 'const systemPrompt = `DO NOT... DO NOT... ALWAYS... YOU ARE AN AI... (5000+ chars)`',
      reproductionSteps: [`Scanned prompt architecture in ${file.path}.`, 'Detected monolithic, bloated system prompt exceeding 5000 chars without step-based modular injection.'],
      remediationPrompt: `Refactor system prompt in ${file.path} into modular sub-prompts. Inject rules dynamically per execution step.`,
      status: 'OPEN',
      owner: 'Prompt Engineer',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-41: System prompt inflation detected (${file.path})`);
  }

  // VibePolish UI-48: Dynamic Variable Injection Failures (Exclude config files, dotfiles, test files, and non-JS/TS backend languages)
  const isConfigFileOrDotfile = lowerFilePath.includes('.vscode/') || lowerFilePath.includes('.github/') || lowerFilePath.endsWith('.json') || lowerFilePath.endsWith('.toml') || lowerFilePath.endsWith('.yaml') || lowerFilePath.endsWith('.yml');
  const isTestOrDocFile =
    lowerFilePath.includes('/test/') || lowerFilePath.includes('/tests/') || lowerFilePath.includes('/spec/') ||
    lowerFilePath.startsWith('test/') || lowerFilePath.startsWith('tests/') || lowerFilePath.startsWith('spec/') ||
    lowerFilePath.includes('__tests__/') || /\.(?:test|spec)\.[a-zA-Z0-9]+$/i.test(lowerFilePath) ||
    /(?:^|\/)(?:test_[^/]+|[^/]+_test)\.[a-zA-Z0-9]+$/i.test(lowerFilePath) ||
    lowerFilePath.endsWith('.md') || lowerFilePath.endsWith('.mdx');
  const isNonJsBackend = /\.(?:go|rs|c|cpp|cc|cxx|h|hpp|java|kt|kts|cs|swift|rb|sh|bash|zsh|ps1)$/i.test(lowerFilePath);
  const hasSingleBracePlaceholder = /(?<!\{)\{[a-zA-Z0-9_]+\}(?!\})/.test(file.content);
  if (!isConfigFileOrDotfile && !isTestOrDocFile && !isNonJsBackend && hasSingleBracePlaceholder && !file.content.includes('??') && file.content.includes('template')) {
    const matchLineIdx = lines.findIndex(l => /(?<!\{)\{[a-zA-Z0-9_]+\}(?!\})/.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 48,
      type: 'VIBEPOLISH',
      title: 'UI-48: Dynamic Variable Injection Missing Fallback',
      severity: 'HIGH',
      category: 'Variables & Templates',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Hello {username}, welcome to your account.',
      reproductionSteps: [`Scanned string template interpolation in ${file.path}:${lineNum}.`, 'Detected variable placeholder without fallback check (risk of printing {undefined} / {null}).'],
      remediationPrompt: `Add strict type validation or nullish coalescing (e.g. username ?? "User") to template interpolation in ${file.path}.`,
      status: 'OPEN',
      owner: 'Prompt Engineer',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-48: Variable injection missing fallback detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-57: High Temperature on Deterministic Tasks
  if (file.content.includes('temperature: 0.9') || file.content.includes('temperature: 0.8') || file.content.includes('temperature: 1')) {
    if (file.content.includes('json') || file.content.includes('schema') || file.content.includes('code')) {
      const matchLineIdx = lines.findIndex(l => l.includes('temperature'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 57,
        type: 'VIBEPOLISH',
        title: 'UI-57: Excessive Temperature Setting on Deterministic Task',
        severity: 'HIGH',
        category: 'Model Parameters',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'temperature: 0.9',
        reproductionSteps: [`Scanned model parameters in ${file.path}:${lineNum}.`, 'Detected high temperature (0.8-1.0) on structured code/JSON extraction task.'],
        remediationPrompt: `Lower temperature in ${file.path} to 0.0 - 0.2 for deterministic code and JSON schema extraction calls.`,
        status: 'OPEN',
        owner: 'Backend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-57: Excessive temperature parameter detected (${file.path}:${lineNum})`);
    }
  }

  // VibePolish UI-61: Naive Fixed-Character Chunking
  if (file.content.includes('CharacterTextSplitter') || (file.content.includes('chunkSize') && !file.content.includes('Semantic') && !file.content.includes('Recursive'))) {
    const matchLineIdx = lines.findIndex(l => l.includes('CharacterTextSplitter') || l.includes('chunkSize'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 61,
      type: 'VIBEPOLISH',
      title: 'UI-61: Naive Fixed-Character Text Splitter',
      severity: 'MEDIUM',
      category: 'RAG Architecture',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'new CharacterTextSplitter({ chunkSize: 1000, chunkOverlap: 200 })',
      reproductionSteps: [`Scanned RAG pipeline in ${file.path}:${lineNum}.`, 'Detected naive fixed-character text splitter slicing sentences/tables mid-word.'],
      remediationPrompt: `Replace naive CharacterTextSplitter in ${file.path} with SemanticChunking or RecursiveCharacterTextSplitter respecting document AST structure.`,
      status: 'OPEN',
      owner: 'AI Architect',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-61: Naive text chunking detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-75: Multi-Tenant RAG Data Leakage
  if ((file.content.includes('similaritySearch') || file.content.includes('match_documents') || file.content.includes('pinecone.query')) && !file.content.includes('tenant_id') && !file.content.includes('user_id')) {
    const matchLineIdx = lines.findIndex(l => l.includes('similaritySearch') || l.includes('match_documents') || l.includes('pinecone.query'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 75,
      type: 'VIBEPOLISH',
      title: 'UI-75: Unfiltered Multi-Tenant Vector Query',
      severity: 'CRITICAL',
      category: 'Metadata & Security',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'await vectorStore.similaritySearch(query, 5);',
      reproductionSteps: [`Scanned vector DB query in ${file.path}:${lineNum}.`, 'Detected vector similarity query executing without mandatory tenant_id / user_id metadata filter.'],
      remediationPrompt: `Enforce mandatory tenant_id and user_id metadata filtering in ${file.path} for vector database queries: vectorStore.similaritySearch(query, 5, { tenant_id: user.tenantId }).`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] UI-75 Unfiltered multi-tenant vector query detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-76: Context Hallucination Vulnerability
  if (file.content.includes('context') && file.content.includes('prompt') && !file.content.includes('not found') && !file.content.includes('information not found')) {
    if (file.content.includes('RAG') || file.content.includes('retrieval') || file.content.includes('vector')) {
      const matchLineIdx = lines.findIndex(l => l.includes('context'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 76,
        type: 'VIBEPOLISH',
        title: 'UI-76: Missing RAG Hallucination Guardrail',
        severity: 'HIGH',
        category: 'RAG Architecture',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'Answer the question based on context: {context}',
        reproductionSteps: [`Scanned RAG prompt template in ${file.path}:${lineNum}.`, 'Detected RAG prompt template without explicit fallback instruction ("If the context does not contain the answer, state \'Information not found\'").'],
        remediationPrompt: `Update RAG prompt template in ${file.path}. Add mandatory guardrail: "If the provided context does not contain sufficient information, explicitly respond with 'Information not found' without hallucinating."`,
        status: 'OPEN',
        owner: 'Prompt Engineer',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-76: Missing RAG guardrail detected (${file.path}:${lineNum})`);
    }
  }

  // VibePolish UI-85: Destructive Action Missing Human Approval
  if ((file.content.includes('deleteUser') || file.content.includes('dropTable') || file.content.includes('executePayment') || file.content.includes('sendEmail')) && !file.content.includes('confirm') && !file.content.includes('requireApproval')) {
    if (file.content.includes('agent') || file.content.includes('tool') || file.content.includes('functionCall')) {
      const matchLineIdx = lines.findIndex(l => /deleteUser|dropTable|executePayment|sendEmail/.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 85,
        type: 'VIBEPOLISH',
        title: 'UI-85: Destructive Agent Action Missing Human-in-the-Loop Approval',
        severity: 'CRITICAL',
        category: 'Security & Approvals',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'async function deleteUserTool(args) { await db.deleteUser(args.id); }',
        reproductionSteps: [`Scanned agent tool execution in ${file.path}:${lineNum}.`, 'Detected destructive action tool (delete/payment/email) executing without Human-in-the-Loop approval gate.'],
        remediationPrompt: `Enforce Human-in-the-Loop (HITL) confirmation step in ${file.path} before executing destructive tools (e.g. require explicit user token / approval UI trigger).`,
        status: 'OPEN',
        owner: 'Security Lead',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] UI-85 Human-in-the-loop approval step missing (${file.path}:${lineNum})`);
    }
  }

  // VibePolish UI-90: Sensitive Data Exposure in Tool Logs
  if ((file.content.includes('console.log(tool') || file.content.includes('logger.info(args)')) && !file.content.includes('redact') && !file.content.includes('mask')) {
    const matchLineIdx = lines.findIndex(l => l.includes('console.log') || l.includes('logger.info'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 90,
      type: 'VIBEPOLISH',
      title: 'UI-90: Unredacted Sensitive Data in Tool Logs',
      severity: 'HIGH',
      category: 'Security & Approvals',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'console.log("Tool Arguments:", args);',
      reproductionSteps: [`Scanned logging Statements in ${file.path}:${lineNum}.`, 'Detected unmasked tool argument logging potentially leaking API keys or user PII.'],
      remediationPrompt: `Add redaction proxy or masking middleware in ${file.path} before logging tool arguments and responses.`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] UI-90 Unredacted sensitive tool log detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-100: Missing User Request Abort Signal
  if ((file.content.includes('agentRunner') || file.content.includes('executeAgent')) && !file.content.includes('AbortController') && !file.content.includes('signal')) {
    const matchLineIdx = lines.findIndex(l => l.includes('agentRunner') || l.includes('executeAgent'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 100,
      type: 'VIBEPOLISH',
      title: 'UI-100: Missing Request AbortSignal Listener',
      severity: 'MEDIUM',
      category: 'Execution & Sandbox',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'export async function runAgent(prompt: string) { ... }',
      reproductionSteps: [`Scanned long-running agent execution route in ${file.path}:${lineNum}.`, 'Detected long-running agent handler without AbortSignal / AbortController cancellation handler.'],
      remediationPrompt: `Add AbortController / AbortSignal support to agent route in ${file.path} to allow instant user cancellation of runaway agent tasks.`,
      status: 'OPEN',
      owner: 'Backend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-100: Missing AbortController signal listener detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-106: Empty Silent Catch Block
  if (!isCompiledBundle && (/catch\s*\([a-zA-Z0-9_]*\)\s*\{\s*\}/.test(file.content) || file.content.includes('catch (e) {}') || file.content.includes('catch {}'))) {
    const matchLineIdx = lines.findIndex(l => /catch\s*\([a-zA-Z0-9_]*\)\s*\{\s*\}/.test(l) || l.includes('catch (e) {}') || l.includes('catch {}'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 106,
      type: 'VIBEPOLISH',
      title: 'UI-106: Empty Silent Catch Block',
      severity: 'HIGH',
      category: 'Code Quality & Refactoring',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'try { ... } catch (e) {}',
      reproductionSteps: [`Scanned try-catch blocks in ${file.path}:${lineNum}.`, 'Detected empty catch block swallowing runtime errors without logging or rethrowing.'],
      remediationPrompt: `Remove empty catch block in ${file.path}. Log caught error with context and error ID or rethrow to error handling boundary.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] UI-106 Empty catch block detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-111: TypeScript Any Type Safety Escape
  const anyMatches = (file.content.match(/:\s*any\b|as\s+any\b/g) || []).length;
  if (anyMatches > 5) {
    const matchLineIdx = lines.findIndex(l => /:\s*any\b|as\s+any\b/.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 111,
      type: 'VIBEPOLISH',
      title: 'UI-111: TypeScript "any" Type Escape',
      severity: 'MEDIUM',
      category: 'TypeScript & Types',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'const data: unknown = response.json();',
      reproductionSteps: [`Scanned TypeScript type definitions in ${file.path}.`, `Detected ${anyMatches} occurrences of "any" type bypassing type safety.`],
      remediationPrompt: `Replace "any" types in ${file.path} with strict Zod interfaces or unknown + type guard functions.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-111: Excessive 'any' type usage detected (${file.path})`);
  }

  // VibePolish UI-115: Monolithic File Overuse (>500 Lines for atomic components, >1200 Lines for composite views/pages)
  const isCompositeViewOrPage = /View\.[tj]sx$|page\.[tj]sx$|Modal\.[tj]sx$|Table\.[tj]sx$/i.test(file.path);
  const maxLinesAllowed = isCompositeViewOrPage ? 1200 : 500;
  if (lines.length > maxLinesAllowed && (file.path.endsWith('.tsx') || file.path.endsWith('.jsx'))) {
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 115,
      type: 'VIBEPOLISH',
      title: 'UI-115: Monolithic Overly Long Source File (>500 Lines)',
      severity: 'MEDIUM',
      category: 'Code Architecture',
      filePath: file.path,
      lineRange: `L1-L${lines.length}`,
      snippet: `// ${file.path} contains ${lines.length} lines of code`,
      reproductionSteps: [`Scanned file line count for ${file.path}.`, `Detected monolithic component containing ${lines.length} lines without sub-component extraction.`],
      remediationPrompt: `Decompose monolithic file ${file.path} (${lines.length} lines) into smaller modular sub-components (max 250 lines per file).`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-115: Monolithic long file detected (${file.path})`);
  }

  // VibePolish UI-117: Uncleaned Event Listener Memory Leaks (Focus on components/hooks, skip third-party vendor & bootstrap entry files)
  const isVendorOrLib = isCompiledBundle || /(?:^|\/)(?:vendor|libs?|external|third_party|dist|bundles|node_modules)\//i.test(lowerFilePath);
  const isBootstrapOrEntry = /(?:boot|client-app|main|index|entry|setup)\.[a-zA-Z0-9]+$/i.test(lowerFilePath);
  const isComponentOrHook = lowerFilePath.includes('/components/') || lowerFilePath.includes('/hooks/') || lowerFilePath.includes('/views/') || file.content.includes('useEffect') || file.content.includes('componentDidMount');
  if (!isVendorOrLib && !isBootstrapOrEntry && isComponentOrHook && file.content.includes('addEventListener(') && !file.content.includes('removeEventListener(')) {
    const matchLineIdx = lines.findIndex(l => l.includes('addEventListener('));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 117,
      type: 'VIBEPOLISH',
      title: 'UI-117: Uncleaned Event Listener Memory Leak',
      severity: 'HIGH',
      category: 'Database & Performance',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'window.addEventListener("resize", handleResize);',
      reproductionSteps: [`Scanned event listener bindings in ${file.path}:${lineNum}.`, 'Detected addEventListener call without matching removeEventListener in cleanup handler.'],
      remediationPrompt: `Add cleanup function returning removeEventListener in useEffect hook in ${file.path} to prevent memory leaks.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] UI-117 Uncleaned event listener detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-121: Synchronous Non-Streaming LLM Completion
  if (file.content.includes('chat.completions.create') && !file.content.includes('stream: true') && !file.content.includes('json') && !file.content.includes('response_format')) {
    const matchLineIdx = lines.findIndex(l => l.includes('chat.completions.create'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 121,
      type: 'VIBEPOLISH',
      title: 'UI-121: Synchronous Non-Streaming LLM Completion (Missing Stream: True)',
      severity: 'HIGH',
      category: 'Streaming & Latency',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'await openai.chat.completions.create({ model: "gpt-4o", messages });',
      reproductionSteps: [`Scanned LLM completion call in ${file.path}:${lineNum}.`, 'Detected synchronous text generation call without stream: true (causes high TTFT latency).'],
      remediationPrompt: `Enable stream: true and SSE (Server-Sent Events) streaming response in ${file.path} for instant 300ms Time-to-First-Token UI rendering.`,
      status: 'OPEN',
      owner: 'Backend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-121: Non-streaming synchronous LLM call detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-134: Unvirtualized Long List DOM Memory Leaks
  if (file.content.includes('messages.map') && !file.content.includes('virtual') && !file.content.includes('useVirtualizer')) {
    const matchLineIdx = lines.findIndex(l => l.includes('messages.map'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 134,
      type: 'VIBEPOLISH',
      title: 'UI-134: Unvirtualized Long List (Missing Virtual Scrolling)',
      severity: 'MEDIUM',
      category: 'Frontend Performance',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'messages.map(msg => <MessageCard key={msg.id} ... />)',
      reproductionSteps: [`Scanned chat list rendering in ${file.path}:${lineNum}.`, 'Detected unvirtualized message history list rendering all items simultaneously to DOM.'],
      remediationPrompt: `Implement Virtual Scrolling using @tanstack/react-virtual in ${file.path} to render only visible message items.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-134: Unvirtualized long list detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-139: Missing Request Abort Signal Listener
  if (file.content.includes('StreamingTextResponse') && !file.content.includes('signal') && !file.content.includes('aborted')) {
    const matchLineIdx = lines.findIndex(l => l.includes('StreamingTextResponse'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 139,
      type: 'VIBEPOLISH',
      title: 'UI-139: Missing Request Cancellation AbortSignal Listener',
      severity: 'HIGH',
      category: 'Streaming & Latency',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'return new StreamingTextResponse(stream);',
      reproductionSteps: [`Scanned streaming route handler in ${file.path}:${lineNum}.`, 'Detected streaming response without request.signal abort listener (backend continues burning tokens if client closes tab).'],
      remediationPrompt: `Listen to req.signal abort event in ${file.path} to instantly terminate backend model API calls when user closes tab.`,
      status: 'OPEN',
      owner: 'Backend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-139: Missing request cancellation listener detected (${file.path}:${lineNum})`);
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

  // VibePolish UI-143: Unmonitored Per-User Token Spend
  if (file.content.includes('/api/generate') && !file.content.includes('usage') && !file.content.includes('quota') && !file.content.includes('deductCredits')) {
    const matchLineIdx = lines.findIndex(l => l.includes('/api/generate') || l.includes('export async function POST'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 143,
      type: 'VIBEPOLISH',
      title: 'UI-143: Unmonitored Per-User Token Spend & Quota',
      severity: 'HIGH',
      category: 'User Quotas & Credits',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'export async function POST(req: Request) { ... }',
      reproductionSteps: [`Scanned AI endpoint in ${file.path}:${lineNum}.`, 'Detected completion route generating responses without tracking user-level token usage or deducting user credit quota.'],
      remediationPrompt: `Implement user-level token usage tracking and credit quota deduction in ${file.path} before returning model responses.`,
      status: 'OPEN',
      owner: 'Finance & Billing Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [HIGH] UI-143 Unmonitored user token usage detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-160: Missing Spend Circuit Breaker
  if (file.content.includes('OpenAI(') && !file.content.includes('budget') && !file.content.includes('circuitBreaker') && !file.content.includes('maxMonthlySpend')) {
    const matchLineIdx = lines.findIndex(l => l.includes('OpenAI('));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 160,
      type: 'VIBEPOLISH',
      title: 'UI-160: Missing Automated Budget Circuit Breaker',
      severity: 'CRITICAL',
      category: 'FinOps & Circuit Breakers',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });',
      reproductionSteps: [`Scanned AI SDK initialization in ${file.path}:${lineNum}.`, 'Detected LLM client initialization without hard budget limit circuit breaker or spending spike guardrails.'],
      remediationPrompt: `Add FinOps Circuit Breaker middleware in ${file.path} to instantly halt API calls if hourly/daily spending spikes exceed safety thresholds.`,
      status: 'OPEN',
      owner: 'DevOps / FinOps Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [CRITICAL] UI-160 Missing budget circuit breaker detected (${file.path}:${lineNum})`);
  }

  // VibePolish UI-185: Missing User Feedback Component
  if (file.content.includes('MessageCard') || file.content.includes('AIResponseView')) {
    if (!file.content.includes('onFeedback') && !file.content.includes('thumbsUp') && !file.content.includes('rateResponse')) {
      const matchLineIdx = lines.findIndex(l => l.includes('MessageCard') || l.includes('AIResponseView'));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 185,
        type: 'VIBEPOLISH',
        title: 'UI-185: Missing User Feedback Component',
        severity: 'MEDIUM',
        category: 'User Feedback & AB Testing',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || 'export function MessageCard({ content }: MessageCardProps) { ... }',
        reproductionSteps: [`Scanned AI output UI component in ${file.path}:${lineNum}.`, 'Detected response display component without Thumbs Up/Down or tagged feedback trigger.'],
        remediationPrompt: `Add 1-click feedback widget with tags ("Too long", "Inaccurate", "Incomplete") to ${file.path} to feed closed-loop evaluations.`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-185: Missing user feedback component detected (${file.path}:${lineNum})`);
    }
  }

  // VibePolish UI-195: Exposing Raw Model Parameters
  if (file.content.includes('top_p') || file.content.includes('presence_penalty') || file.content.includes('frequency_penalty')) {
    if (file.path.endsWith('.tsx') || file.path.endsWith('.jsx')) {
      const matchLineIdx = lines.findIndex(l => /top_p|presence_penalty|frequency_penalty/.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      addFinding({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 195,
        type: 'VIBEPOLISH',
        title: 'UI-195: Exposing Raw Hyper-parameters to End Users',
        severity: 'LOW',
        category: 'User Experience & Retention',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: lines[matchLineIdx] || '<input type="range" name="top_p" ... />',
        reproductionSteps: [`Scanned user settings UI in ${file.path}:${lineNum}.`, 'Detected raw LLM hyperparameters (top_p / presence_penalty) exposed directly to end-user UI.'],
        remediationPrompt: `Hide raw hyperparameter inputs in ${file.path} behind user-friendly presets ("Creative", "Precise", "Balanced").`,
        status: 'OPEN',
        owner: 'UX Team',
        falsePositive: false
      });
      logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-195: Raw hyper-parameter input detected (${file.path}:${lineNum})`);
    }
  }

  // VibePolish UI-197: Unpinned Generic Model Alias
  if (file.content.includes('model: "gpt-4o"') || file.content.includes('model: "claude-3-5-sonnet"')) {
    const matchLineIdx = lines.findIndex(l => l.includes('model: "gpt-4o"') || l.includes('model: "claude-3-5-sonnet"'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    addFinding({
      id: `real-find-${Date.now()}-${findingCounter++}`,
      ruleId: 197,
      type: 'VIBEPOLISH',
      title: 'UI-197: Unpinned Generic Model Tag (Missing Date-Pinned Model Version)',
      severity: 'MEDIUM',
      category: 'LLM Provider & Versioning',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'model: "gpt-4o"',
      reproductionSteps: [`Scanned model configuration in ${file.path}:${lineNum}.`, 'Detected unpinned generic model alias ("gpt-4o") vulnerable to silent breaking changes on upstream model updates.'],
      remediationPrompt: `Pin explicit snapshot version in ${file.path} (e.g. "gpt-4o-2024-08-06" or "claude-3-5-sonnet-20241022") to guarantee output consistency.`,
      status: 'OPEN',
      owner: 'Backend Team',
      falsePositive: false
    });
    logs.push(`[${new Date().toLocaleTimeString()}] [RULE] VIBEPOLISH UI-197: Unpinned model alias detected (${file.path}:${lineNum})`);
  }

  ctx.counter.count = findingCounter;
}
