import { evaluateAiCommentRules } from './rules/ai-comment-rules';
import { Finding } from '@/data/schema';
import type { CodeFile, ScanResult } from './scanner/types';
import { hasUntrustedInput, isCriticalInjectionRule, isMinifiedContent, isNonAppPath, isSecretPatternFixture, isSecretRuleId, isTestFixturePath, isVendoredPath, stripComments, yieldToMain } from './scanner/text';
import { parseZelsisIgnore } from './scanner/ignore-parser';
import { parseZelsisRc } from './scanner/rc-config';
import { calculateGateStatus, calculateReadinessScore, gateSeverity, gatingFindings } from './scanner/scoring';
import { ruleMaturity } from './scanner/rule-maturity';
import { ruleImpact } from '../data/rule-impact';
import { riskKind, RISK_FALLBACK_IMPACT } from './scanner/risk-kind';
import { guardElsewhere, type CrossFileVerification } from './scanner/cross-file-verify';

/** SAAS-08: next@ release affected by CVE-2025-29927. */
const NEXT_MIDDLEWARE_CVE_RULE_ID = 23008;

/** [kept, dropped] rule pairs that report the same issue (rule packs overlap). */
/** Adds maturity, the risk kind and an impact sentence (rule-specific, else by risk kind for CRITICAL/HIGH). */
function withImpact(f: Finding): Finding {
  const risk = f.risk ?? riskKind(f);
  const fallback = risk && (f.severity === 'CRITICAL' || f.severity === 'HIGH') ? RISK_FALLBACK_IMPACT[risk] : undefined;
  return { ...f, maturity: ruleMaturity(f.ruleId), risk, impact: f.impact ?? ruleImpact(f.ruleId) ?? fallback };
}

const SAME_ISSUE_RULES: ReadonlyArray<readonly [number, number]> = [
  [7004, 3002], // Dockerfile without USER: CLOUD-04 (reviewed true positive) over the infra-pack duplicate
  [8901, 7013], [8901, 12201], // privileged pod
  [8321, 12204], // hostNetwork
  [8301, 11003], [8301, 7040], // SSH open to the world
  [8329, 8909], // capabilities ALL
  [26, 8501], [26, 8503], // Apollo server config, same line
  [28251, 9501], [28251, 7323], [9501, 7323], // pull_request_target running PR-head code
  [3001, 6010], // public-schema table without RLS
  [3, 45], [3, 28801], // permissive USING (true) / WITH CHECK (true) policy
  // AST flow rules prove the path; keep them over the line-based rule in the same file
  [29301, 9106], [29302, 15], [29302, 28920], [29303, 3021], [29303, 6043], [29303, 18104], [29307, 41], [29308, 16],
  [23004, 10102], // client-supplied price: SAAS-04 over the e-commerce duplicate
  [9704, 8143], // webhook handler without signature verification
  [9704, 28002], // unsigned payment webhook: the missing signature check is the issue, not a missing user session
  [9502, 12605], // unpinned third-party GitHub Action
  [29623, 1208], [29632, 7135], [29636, 1211], // React logic rules prove the line: typeof window render, index key, double submit
];
import { RULE_ENGINES } from './scanner/rule-engines';
import { evaluateBuiltinRules } from './scanner/builtin-rules';
import { detectProjectDatabases } from './rules/multi-database-rules';
import { detectAppStack } from './scanner/stack-detect';
import { buildRepoContext } from './scanner/repo-context';
import { extractDependencies, isDependencyLockfile } from './scanner/dependencies';
import { buildDependencyFindings, OSV_RULE_ID, queryOsv, type DependencyAuditSummary, type OsvOptions } from './scanner/osv';

export type { CodeFile, ScanResult } from './scanner/types';
export type { ZelsisRcConfig } from './scanner/rc-config';
export { isSecretRuleId, isTestFixturePath, stripComments, yieldToMain, UNTRUSTED_INPUT, hasUntrustedInput, isCriticalInjectionRule, CRITICAL_INJECTION_RULES } from './scanner/text';
export { parseZelsisIgnore, parseShipguardIgnore } from './scanner/ignore-parser';
export { parseZelsisRc } from './scanner/rc-config';
export { calculateGateStatus, calculateReadinessScore, gatingFindings } from './scanner/scoring';
export { detectAppStack, UNDETECTED_FRAMEWORK } from './scanner/stack-detect';

/**
 * Static pattern-analysis engine (regex and heuristic rules, no full AST / data-flow analysis)
 * Scans provided source files against Security Rules and VibePolish & AI Anti-Pattern rules.
 * Implements cooperative streaming via yieldToMain() to prevent UI freeze on 1,000+ files.
 */
export interface ScanOptions {
  /** Look up resolved dependency versions in OSV.dev. Off by default so offline runs stay deterministic. */
  dependencyAudit?: OsvOptions | boolean;
  /**
   * Enterprise workspace policy (.zelsisrc.json content). Its strategy and threshold override the
   * repository's file; its ignored rules, paths and disabled gates are added to the repository's.
   */
  orgPolicy?: string | null;
  /** Report every rule that fired, without SAME_ISSUE_RULES dedupe. Rule fixtures use it to prove each rule on its own. */
  keepDuplicateRules?: boolean;
  /** Findings dismissed by the user, which should be marked as ACCEPTED_RISK and not fail the gate. */
  dismissals?: { ruleId: number; filePath: string }[];
}

export async function runStaticCodeScan(inputFiles: CodeFile[], repoName: string = 'Target Repository', options: ScanOptions = {}): Promise<ScanResult> {
  const scanStartedAt = Date.now();
  // Windows (CRLF) and old Mac (CR) line endings become \n once, here: a line ending in \r defeats every
  // rule that anchors on the end of a line (`.` does not match \r), so CRLF repos silently missed findings.
  const files = inputFiles.map((f) => (f && typeof f.content === 'string' && f.content.includes('\r')
    ? { ...f, content: f.content.replace(/\r\n?/g, '\n') }
    : f));
  const findings: Finding[] = [];
  /** Route findings dropped because another file guards the route (see cross-file-verify.ts). */
  const crossFileVerified: CrossFileVerification[] = [];
  const logs: string[] = [];

  // Parse .zelsisignore or .shipguardignore if present in file tree
  const ignoreFile = files.find(f => (f?.path || '').endsWith('.zelsisignore') || (f?.path || '').endsWith('.shipguardignore'));
  const { ignoredRuleIds, ignoredPaths } = parseZelsisIgnore(ignoreFile?.content || '');

  // F-43 Remediation: Parse Policy-as-Code .zelsisrc.json if present
  const rcFile = files.find(f => (f?.path || '').endsWith('.zelsisrc.json') || (f?.path || '').endsWith('.zelsisrc'));
  const { config: rcConfig, ignoredRuleIds: rcRuleIds, ignoredPaths: rcPaths, disabledPillars } = parseZelsisRc(rcFile?.content || '');
  rcRuleIds.forEach(id => ignoredRuleIds.add(id));
  rcPaths.forEach(p => ignoredPaths.push(p));

  const orgRc = parseZelsisRc(options.orgPolicy || '');
  orgRc.ignoredRuleIds.forEach(id => ignoredRuleIds.add(id));
  orgRc.ignoredPaths.forEach(p => ignoredPaths.push(p));
  orgRc.disabledPillars.forEach(p => disabledPillars.add(p));
  const effectiveRc = orgRc.config ? { ...(rcConfig || {}), ...orgRc.config } : rcConfig;

  // Pre-detect project database and ORM architecture before streaming loop cleans file memory
  const detectedStack = detectProjectDatabases(files);
  const detectedApp = detectAppStack(files);
  const repoContext = buildRepoContext(files);

  // Dependency audit: extract exact versions now (file buffers are released during the scan) and
  // query OSV.dev in parallel with the pattern rules.
  const dependencies = extractDependencies(files).filter((d) => !ignoredPaths.some((ip) => d.file.toLowerCase().includes(ip)));
  const dependencyFileLines = new Map<string, string[]>();
  for (const d of dependencies) {
    if (!dependencyFileLines.has(d.file)) dependencyFileLines.set(d.file, (files.find((f) => f.path === d.file)?.content || '').split('\n'));
  }
  const auditEnabled = Boolean(options.dependencyAudit) && !ignoredRuleIds.has(OSV_RULE_ID) && !disabledPillars.has('SECURITY');
  const osvPromise = auditEnabled && dependencies.length > 0
    ? queryOsv(dependencies, typeof options.dependencyAudit === 'object' ? options.dependencyAudit : {})
    : null;

  logs.push(`[${new Date().toLocaleTimeString()}] [INFO] Zelsis static pattern scan started (${RULE_ENGINES.length} rule modules plus built-in rules).`);
  logs.push(`[${new Date().toLocaleTimeString()}] [TARGET] Repository: ${repoName}`);

  if (detectedStack.databases.length > 0 || detectedStack.orms.length > 0) {
    logs.push(`[${new Date().toLocaleTimeString()}] [STACK] Multi-Database Stack Detected: ${[...detectedStack.databases, ...detectedStack.orms].join(', ')}`);
  }

  if (orgRc.config) {
    logs.push(`[${new Date().toLocaleTimeString()}] [CONFIG] Organization policy active (Strategy: ${effectiveRc?.failStrategy || 'smart'}, MinScore: ${effectiveRc?.minScoreThreshold ?? 85}).`);
  } else if (rcConfig) {
    logs.push(`[${new Date().toLocaleTimeString()}] [CONFIG] Policy-as-Code active: Loaded ${rcFile?.path || '.zelsisrc.json'} (Strategy: ${rcConfig.failStrategy || 'smart'}, MinScore: ${rcConfig.minScoreThreshold ?? 85}).`);
  }
  if (ignoredRuleIds.size > 0 || ignoredPaths.length > 0) {
    logs.push(`[${new Date().toLocaleTimeString()}] [CONFIG] Exclusion filter active: Suppressing ${ignoredRuleIds.size} rules & ${ignoredPaths.length} path patterns.`);
  }

  let skippedThirdParty = 0;
  const validFiles = files.filter((f) => {
    if (!f || typeof f.path !== 'string') return false;
    const lowerPath = (f.path || '').toLowerCase();
    if (
      lowerPath.startsWith('dist/') || lowerPath.includes('/dist/') ||
      lowerPath.startsWith('build/') || lowerPath.includes('/build/') ||
      lowerPath.startsWith('out/') || lowerPath.includes('/out/') ||
      lowerPath.startsWith('.next/') || lowerPath.includes('/.next/') ||
      lowerPath.includes('node_modules/') ||
      // committed Python virtualenvs are third-party packages, not the app
      /(?:^|\/)(?:\.?venv|env|\.tox|__pypackages__)\/(?:lib|lib64|scripts|bin|include)\/|(?:^|\/)site-packages\//.test(lowerPath) ||
      // F-39 Remediation: Skip minified bundles and third-party vendored assets to avoid noise
      lowerPath.endsWith('.min.js') ||
      lowerPath.endsWith('.min.css') ||
      lowerPath.endsWith('.bundle.js') ||
      lowerPath.endsWith('.map') ||
      lowerPath.includes('vendor/') ||
      lowerPath.includes('third_party/') ||
      lowerPath.includes('public/vendor/') ||
      lowerPath.includes('assets/vendor/') ||
      isDependencyLockfile(lowerPath) ||
      lowerPath.endsWith('.png') ||
      lowerPath.endsWith('.jpg') ||
      lowerPath.endsWith('.jpeg') ||
      lowerPath.endsWith('.svg') ||
      lowerPath.endsWith('.pdf') ||
      lowerPath.endsWith('.tsbuildinfo') ||
      lowerPath.endsWith('.md')
    ) {
      return false;
    }
    if (isVendoredPath(f.path) || isMinifiedContent(f.content || '')) {
      skippedThirdParty++;
      return false;
    }
    if (ignoredPaths.some(ip => lowerPath.includes(ip))) {
      return false;
    }
    return true;
  });

  const targetFiles = validFiles;
  let fileLimitWarning: string | undefined = undefined;

  logs.push(`[${new Date().toLocaleTimeString()}] [INFO] Repository tree loaded: ${targetFiles.length} total source files queued for file-by-file audit.`);
  if (skippedThirdParty > 0) {
    logs.push(`[${new Date().toLocaleTimeString()}] [INFO] Skipped ${skippedThirdParty} vendored or minified third-party file(s); dependencies are checked through their manifests instead.`);
  }
  logs.push(`[${new Date().toLocaleTimeString()}] --------------------------------------------------`);

  let findingCounter = 1;
  let testFixtureSkips = 0;
  let fileIndex = 1;

  for (let i = 0; i < targetFiles.length; i++) {
    // Cooperative event-loop slicing every 20 files to prevent browser thread freeze on 1,000+ file repositories
    if (i > 0 && i % 20 === 0) {
      await yieldToMain();
    }

    const file = targetFiles[i];
    let rawContent = file?.content || '';
    let lines = rawContent.split('\n');
    const startFindingsCount = findings.length;
    const lowerFilePath = (file?.path || '').toLowerCase();

    // File size guard (500 KB / 512,000 bytes)
    const MAX_FILE_SIZE_BYTES = 512000;
    const byteLength = typeof Buffer !== 'undefined'
      ? Buffer.byteLength(rawContent, 'utf8')
      : rawContent.length;

    if (byteLength > MAX_FILE_SIZE_BYTES) {
      const fileSizeKb = Math.round(byteLength / 1024);
      logs.push(`[${new Date().toLocaleTimeString()}] [WARN] PERF-OVERSIZE: File ${file.path} (${fileSizeKb}KB) exceeds maximum static scan size limit (500KB). Skipped to prevent regex event loop starvation.`);
      findings.push({
        id: `real-find-${Date.now()}-${findingCounter++}`,
        ruleId: 999,
        type: 'VIBEPOLISH',
        title: `[PERF-OVERSIZE] File ${file.path} (${fileSizeKb}KB) exceeds maximum static scan size limit (500KB). Skipped to prevent regex event loop starvation.`,
        severity: 'LOW',
        category: 'Performance & Scalability',
        filePath: file.path,
        lineRange: 'L1',
        snippet: `[File size: ${fileSizeKb}KB exceeds 500KB limit - regex evaluation bypassed to prevent event loop starvation]`,
        reproductionSteps: [
          `Scanned repository file ${file.path}.`,
          `Detected file size ${fileSizeKb}KB (> 500KB threshold).`,
          'Skipped static regex analysis to prevent regex event loop starvation.'
        ],
        remediationPrompt: `Refactor or split ${file.path}, or add it to .zelsisignore if it is a bundled/generated artifact.`,
        status: 'OPEN',
        owner: 'Engineering Lead',
        falsePositive: false
      });
      fileIndex++;
      continue;
    }

    const isTestFixture = isTestFixturePath(file?.path || '');

    // Helper to add finding unless suppressed or false-positive inside rule definition files
    const addFinding = (f: Finding) => {
      if (disabledPillars.has(f.type)) {
        return;
      }
      if (
        ignoredRuleIds.has(f.ruleId) ||
        (f.ruleId >= 1000 && ignoredRuleIds.has(f.ruleId - 1000)) ||
        (f.ruleId < 1000 && ignoredRuleIds.has(f.ruleId + 1000)) ||
        (f.ruleId >= 2001 && f.ruleId <= 2006 && ignoredRuleIds.has(f.ruleId - 2000))
      ) {
        return;
      }
      // Test code does not ship: only leaked secrets count there
      if (isTestFixture && !isSecretRuleId(f.ruleId)) {
        testFixtureSkips++;
        return;
      }
      // Secret-scanner configs and fake-key fixtures list credential shapes on purpose
      if (isSecretRuleId(f.ruleId) && isSecretPatternFixture(f.filePath)) {
        testFixtureSkips++;
        return;
      }
      // Firebase / Google client config ships its AIza API key to every app on purpose: it is not a secret
      if (isSecretRuleId(f.ruleId) && /(?:^|\/)(?:GoogleService-Info\.plist|google-services\.json|firebase(?:-config)?\.(?:json|[jt]s))$/i.test(f.filePath) && /AIza/.test(String(f.snippet ?? ''))) {
        testFixtureSkips++;
        return;
      }
      // A key in tests, fixtures, docs or examples is usually a dummy: keep it visible (a real one still leaks)
      // but do not block a release on it
      if (isSecretRuleId(f.ruleId) && (isTestFixture || /(?:^|\/)(?:docs?|docs_src|examples?|samples?)\//i.test(f.filePath))
          && (f.severity === 'CRITICAL' || f.severity === 'HIGH')) {
        f.severity = 'MEDIUM';
        f.reproductionSteps = [...(f.reproductionSteps ?? []), 'Found in a test, fixture or docs file, so it is most likely a dummy value. If it is a real key, revoke it: git history keeps it.'];
      }
      // Non-app paths (docs, knowledge, seeders, dev scripts, local compose):
      // do not block a release on code that is outside the shipped app. Secrets keep existing behaviour.
      if (!isSecretRuleId(f.ruleId) && isNonAppPath(f.filePath) && (f.severity === 'CRITICAL' || f.severity === 'HIGH')) {
        f.severity = 'MEDIUM';
        f.reproductionSteps = [
          ...(f.reproductionSteps ?? []),
          'Found outside the shipped application code (documentation, knowledge base, seeder, dev script or local dev environment).'
        ];
      }
      // Critical injection rules require external input to be release-blocking: without request/untrusted
      // input in the file, dynamic queries or commands are hardening concerns, not immediate CRITICAL blockers.
      if (f.severity === 'CRITICAL' && isCriticalInjectionRule(f.ruleId) && !hasUntrustedInput(rawContent)) {
        f.severity = 'HIGH';
        f.reproductionSteps = [
          ...(f.reproductionSteps ?? []),
          'Downgraded from CRITICAL to HIGH: No untrusted user input (HTTP request, parameters, body, or external stream) was detected in this file.'
        ];
      }
      // Feature: Dismiss Findings
      if (options.dismissals && options.dismissals.some(d => d.ruleId === f.ruleId && d.filePath === f.filePath)) {
        f.status = 'ACCEPTED_RISK';
      }
      // Deduplicate findings by fingerprint (same file, line, and rule title/family)
      const isDuplicate = findings.some(existing =>
        existing.filePath === f.filePath &&
        existing.lineRange === f.lineRange &&
        (
          existing.title === f.title ||
          existing.ruleId === f.ruleId ||
          (existing.title.includes('Eyebrow') && f.title.includes('Eyebrow'))
        )
      );
      if (isDuplicate) {
        return;
      }
      findings.push(withImpact(f));
    };

    // 0. AI Comment, Prompt Artifact & Boilerplate Inspector (Runs on raw unstripped content)
    const commentCounter = { count: findingCounter };
    const commentResult = evaluateAiCommentRules(file, lines, rawContent, commentCounter);
    findingCounter = commentCounter.count;
    for (const item of commentResult.findings) {
      if (!ignoredRuleIds.has(item.ruleId)) {
        addFinding(item);
      }
    }
    logs.push(...commentResult.logs);

    let cleanContent = stripComments(rawContent);

    logs.push(`[${new Date().toLocaleTimeString()}] [INSPECT] [File ${fileIndex}/${validFiles.length}] ${file.path} (${lines.length} lines)${isTestFixture ? ' · test/fixture file: secret rules only' : ''}`);

    // Built-in rules (lib/scanner/builtin-rules.ts)
    const builtinCounter = { count: findingCounter };
    evaluateBuiltinRules({ file, lines, rawContent, cleanContent, findings, logs, addFinding, counter: builtinCounter });
    findingCounter = builtinCounter.count;

    // Modular rule engines (see lib/scanner/rule-engines.ts for the ordered registry)
    for (const engine of RULE_ENGINES) {
      const engineCounter = { count: findingCounter };
      const engineResult = engine.evaluate(file, lines, engine.scanRawContent ? rawContent : cleanContent, engineCounter, repoContext);
      findingCounter = engineCounter.count;
      for (const item of engineResult.findings) {
        addFinding(item);
      }
      logs.push(...engineResult.logs);
    }

    // Second look before reporting a route as unauthenticated: middleware or an imported helper may guard it
    for (let k = findings.length - 1; k >= startFindingsCount; k--) {
      const reason = guardElsewhere(findings[k].ruleId, file.path, cleanContent, repoContext.crossFileAuth);
      if (!reason) continue;
      crossFileVerified.push({ ruleId: findings[k].ruleId, filePath: findings[k].filePath, reason });
      logs.push(`[${new Date().toLocaleTimeString()}]   [VERIFIED] ${file.path}: dropped "${findings[k].title}" (${reason}).`);
      findings.splice(k, 1);
    }

    const fileFindingsCount = findings.length - startFindingsCount;
    if (fileFindingsCount === 0) {
      logs.push(`[${new Date().toLocaleTimeString()}]   [PASS] ${file.path}: no findings.`);
    } else {
      logs.push(`[${new Date().toLocaleTimeString()}]   [WARN] ${file.path}: Detected ${fileFindingsCount} open finding(s)!`);
    }

    // Immediately discard raw file buffer strings after AST extraction to maintain heap memory < 85MB
    try {
      (file as any).content = '';
    } catch {
      // Ignore if immutable
    }
    rawContent = '';
    cleanContent = '';
    lines = [];

    fileIndex++;
  }

  let dependencyAudit: DependencyAuditSummary = {
    status: !auditEnabled ? 'disabled' : dependencies.length === 0 ? 'no-dependencies' : 'unavailable',
    packages: dependencies.length,
    vulnerablePackages: 0,
    advisories: 0
  };
  if (osvPromise) {
    const osv = await osvPromise;
    if (osv.ok) {
      const depFindings = buildDependencyFindings(dependencies, osv.advisories, dependencyFileLines);
      // Exact lockfile versions supersede the offline advisory list matched against manifest ranges
      const auditedDirs = new Set(dependencies.map((d) => d.file.slice(0, d.file.lastIndexOf('/') + 1)));
      for (let k = findings.length - 1; k >= 0; k--) {
        const f = findings[k];
        if (f.ruleId === 27211 && auditedDirs.has(f.filePath.slice(0, f.filePath.lastIndexOf('/') + 1))) findings.splice(k, 1);
      }
      for (const f of depFindings) findings.push(withImpact(f));
      dependencyAudit = {
        status: 'ok',
        packages: dependencies.length,
        vulnerablePackages: depFindings.length,
        advisories: osv.advisories.reduce((n, a) => n + a.length, 0)
      };
      logs.push(`[${new Date().toLocaleTimeString()}] [DEPENDENCIES] OSV.dev: ${dependencies.length} resolved package versions checked, ${depFindings.length} with known vulnerabilities.`);
    } else {
      dependencyAudit = { ...dependencyAudit, error: osv.error };
      logs.push(`[${new Date().toLocaleTimeString()}] [WARN] Dependency audit unavailable (${osv.error}). ${dependencies.length} package versions were NOT checked for known vulnerabilities.`);
    }
  } else if (auditEnabled) {
    logs.push(`[${new Date().toLocaleTimeString()}] [DEPENDENCIES] No lockfile or pinned manifest found: dependency versions could not be checked. Commit a lockfile to enable the check.`);
  }

  // Rule packs overlap: when two rules report the same issue in one file, keep the first of the pair
  for (const [keep, drop] of options.keepDuplicateRules ? [] : SAME_ISSUE_RULES) {
    const filesWithKeep = new Set(findings.filter((f) => f.ruleId === keep).map((f) => f.filePath));
    for (let k = findings.length - 1; k >= 0; k--) {
      if (findings[k].ruleId === drop && filesWithKeep.has(findings[k].filePath)) findings.splice(k, 1);
    }
  }
  // SAAS-08 only fires on next@ releases affected by CVE-2025-29927, which OSV then lists inside DEP-01 for next:
  // keep the one finding that carries every advisory (DEP-01 sits on the lockfile, so the file-based pairs above miss it)
  if (!options.keepDuplicateRules && findings.some((f) => f.ruleId === OSV_RULE_ID && /^DEP-\d+: next@/.test(f.title))) {
    for (let k = findings.length - 1; k >= 0; k--) {
      if (findings[k].ruleId === NEXT_MIDDLEWARE_CVE_RULE_ID) findings.splice(k, 1);
    }
  }

  logs.push(`[${new Date().toLocaleTimeString()}] --------------------------------------------------`);
  logs.push(`[${new Date().toLocaleTimeString()}] [SUMMARY] Scan complete: ${targetFiles.length} files, ${findings.length} findings (${findings.filter((f) => f.maturity === 'experimental').length} from experimental rules, not counted toward the gate).`);
  if (testFixtureSkips > 0) {
    logs.push(`[${new Date().toLocaleTimeString()}] [INFO] ${testFixtureSkips} non-secret finding(s) in test/fixture files were not counted (test code does not ship).`);
  }

  // Counts, score and gate only use findings from rules proven precise; experimental ones are reported separately.
  // Counts use the gate severity, so an unproven CRITICAL (which only warns) is counted as HIGH, like the gate does.
  const openFindings = gatingFindings(findings);
  const experimentalCount = findings.filter((f) => f.status === 'OPEN' && f.maturity === 'experimental').length;
  const criticalCount = openFindings.filter(f => gateSeverity(f) === 'CRITICAL').length;
  const highCount = openFindings.filter(f => gateSeverity(f) === 'HIGH').length;
  const mediumCount = openFindings.filter(f => gateSeverity(f) === 'MEDIUM').length;
  const lowCount = openFindings.filter(f => gateSeverity(f) === 'LOW').length;
  const uiClicheCount = openFindings.filter(f => f.type === 'VIBEPOLISH').length;

  const score = calculateReadinessScore(findings);
  let gateStatus = calculateGateStatus(findings);

  // Policy-as-Code strategy enforcement (F-43)
  if (effectiveRc) {
    if (effectiveRc.failStrategy === 'advisory') {
      gateStatus = 'PASSED';
      logs.push(`[${new Date().toLocaleTimeString()}] [CONFIG] Policy-as-Code: Advisory mode active — Release gate set to PASSED.`);
    } else if (effectiveRc.failStrategy === 'strict') {
      const minThreshold = typeof effectiveRc.minScoreThreshold === 'number' ? effectiveRc.minScoreThreshold : 85;
      if (score < minThreshold) {
        gateStatus = 'FAILED';
        logs.push(`[${new Date().toLocaleTimeString()}] [CONFIG] Policy-as-Code: Strict mode active — Score ${score} is below required ${minThreshold} threshold. Release gate BLOCKED.`);
      }
    }
  }

  logs.push(`[${new Date().toLocaleTimeString()}] [COMPLETE] Scan complete: Readiness Score = ${score}/100 | Gate Status = ${gateStatus}`);

  const defaultSummary = gateStatus === 'PASSED'
    ? 'Production Audit PASSED. All security and design compliance checks cleared.'
    : gateStatus === 'WARNING'
    ? `Release WARNING. Detected ${highCount} High and ${mediumCount} Medium findings. Review recommended before production deployment.`
    : `Release BLOCKED. Detected ${criticalCount} Critical blocker(s) requiring immediate remediation.`;

  const summary = fileLimitWarning ? `${defaultSummary} (${fileLimitWarning})` : defaultSummary;

  return {
    score,
    gateStatus,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    uiClicheCount,
    experimentalCount,
    crossFileVerified,
    durationMs: Date.now() - scanStartedAt,
    findings,
    logs,
    summary,
    detectedDatabases: detectedStack.databases,
    detectedOrms: detectedStack.orms,
    detectedFramework: detectedApp.framework ?? undefined,
    detectedProviders: detectedApp.providers,
    dependencyAudit
  };
}
