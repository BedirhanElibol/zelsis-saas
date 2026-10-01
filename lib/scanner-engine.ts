import { evaluateAiCommentRules } from './rules/ai-comment-rules';
import { Finding } from '@/data/schema';
import type { CodeFile, ScanResult } from './scanner/types';
import { isSecretRuleId, isTestFixturePath, stripComments, yieldToMain } from './scanner/text';
import { parseZelsisIgnore } from './scanner/ignore-parser';
import { parseZelsisRc } from './scanner/rc-config';
import { calculateGateStatus, calculateReadinessScore, gatingFindings } from './scanner/scoring';
import { isExperimentalRule } from './scanner/rule-maturity';
import { RULE_ENGINES } from './scanner/rule-engines';
import { evaluateBuiltinRules } from './scanner/builtin-rules';
import { detectProjectDatabases } from './rules/multi-database-rules';
import { detectAppStack } from './scanner/stack-detect';
import { buildRepoContext } from './scanner/repo-context';

export type { CodeFile, ScanResult } from './scanner/types';
export type { ZelsisRcConfig } from './scanner/rc-config';
export { isSecretRuleId, isTestFixturePath, stripComments, yieldToMain } from './scanner/text';
export { parseZelsisIgnore, parseShipguardIgnore } from './scanner/ignore-parser';
export { parseZelsisRc } from './scanner/rc-config';
export { calculateGateStatus, calculateReadinessScore, gatingFindings } from './scanner/scoring';
export { detectAppStack, UNDETECTED_FRAMEWORK } from './scanner/stack-detect';

/**
 * Static pattern-analysis engine (regex and heuristic rules, no full AST / data-flow analysis)
 * Scans provided source files against Security Rules and VibePolish & AI Anti-Pattern rules.
 * Implements cooperative streaming via yieldToMain() to prevent UI freeze on 1,000+ files.
 */
export async function runStaticCodeScan(files: CodeFile[], repoName: string = 'Target Repository'): Promise<ScanResult> {
  const scanStartedAt = Date.now();
  const findings: Finding[] = [];
  const logs: string[] = [];

  // Parse .zelsisignore or .shipguardignore if present in file tree
  const ignoreFile = files.find(f => (f?.path || '').endsWith('.zelsisignore') || (f?.path || '').endsWith('.shipguardignore'));
  const { ignoredRuleIds, ignoredPaths } = parseZelsisIgnore(ignoreFile?.content || '');

  // F-43 Remediation: Parse Policy-as-Code .zelsisrc.json if present
  const rcFile = files.find(f => (f?.path || '').endsWith('.zelsisrc.json') || (f?.path || '').endsWith('.zelsisrc'));
  const { config: rcConfig, ignoredRuleIds: rcRuleIds, ignoredPaths: rcPaths, disabledPillars } = parseZelsisRc(rcFile?.content || '');
  rcRuleIds.forEach(id => ignoredRuleIds.add(id));
  rcPaths.forEach(p => ignoredPaths.push(p));

  // Pre-detect project database and ORM architecture before streaming loop cleans file memory
  const detectedStack = detectProjectDatabases(files);
  const detectedApp = detectAppStack(files);
  const repoContext = buildRepoContext(files);

  logs.push(`[${new Date().toLocaleTimeString()}] [INFO] Zelsis static pattern scan started (${RULE_ENGINES.length} rule modules plus built-in rules).`);
  logs.push(`[${new Date().toLocaleTimeString()}] [TARGET] Repository: ${repoName}`);

  if (detectedStack.databases.length > 0 || detectedStack.orms.length > 0) {
    logs.push(`[${new Date().toLocaleTimeString()}] [STACK] Multi-Database Stack Detected: ${[...detectedStack.databases, ...detectedStack.orms].join(', ')}`);
  }

  if (rcConfig) {
    logs.push(`[${new Date().toLocaleTimeString()}] [CONFIG] Policy-as-Code active: Loaded ${rcFile?.path || '.zelsisrc.json'} (Strategy: ${rcConfig.failStrategy || 'smart'}, MinScore: ${rcConfig.minScoreThreshold ?? 85}).`);
  }
  if (ignoredRuleIds.size > 0 || ignoredPaths.length > 0) {
    logs.push(`[${new Date().toLocaleTimeString()}] [CONFIG] Exclusion filter active: Suppressing ${ignoredRuleIds.size} rules & ${ignoredPaths.length} path patterns.`);
  }

  const validFiles = files.filter((f) => {
    if (!f || typeof f.path !== 'string') return false;
    const lowerPath = (f.path || '').toLowerCase();
    if (
      lowerPath.startsWith('dist/') || lowerPath.includes('/dist/') ||
      lowerPath.startsWith('build/') || lowerPath.includes('/build/') ||
      lowerPath.startsWith('out/') || lowerPath.includes('/out/') ||
      lowerPath.startsWith('.next/') || lowerPath.includes('/.next/') ||
      lowerPath.includes('node_modules/') ||
      // F-39 Remediation: Skip minified bundles and third-party vendored assets to avoid noise
      lowerPath.endsWith('.min.js') ||
      lowerPath.endsWith('.min.css') ||
      lowerPath.endsWith('.bundle.js') ||
      lowerPath.endsWith('.map') ||
      lowerPath.includes('vendor/') ||
      lowerPath.includes('third_party/') ||
      lowerPath.includes('public/vendor/') ||
      lowerPath.includes('assets/vendor/') ||
      lowerPath.endsWith('package-lock.json') || lowerPath.endsWith('yarn.lock') || lowerPath.endsWith('pnpm-lock.yaml') ||
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
    if (ignoredPaths.some(ip => lowerPath.includes(ip))) {
      return false;
    }
    return true;
  });

  const targetFiles = validFiles;
  let fileLimitWarning: string | undefined = undefined;

  logs.push(`[${new Date().toLocaleTimeString()}] [INFO] Repository tree loaded: ${targetFiles.length} total source files queued for file-by-file audit.`);
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
      findings.push(isExperimentalRule(f.ruleId) ? { ...f, maturity: 'experimental' } : f);
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

  logs.push(`[${new Date().toLocaleTimeString()}] --------------------------------------------------`);
  logs.push(`[${new Date().toLocaleTimeString()}] [SUMMARY] Scan complete: ${targetFiles.length} files, ${findings.length} findings (${findings.filter((f) => f.maturity === 'experimental').length} from experimental rules, not counted toward the gate).`);
  if (testFixtureSkips > 0) {
    logs.push(`[${new Date().toLocaleTimeString()}] [INFO] ${testFixtureSkips} non-secret finding(s) in test/fixture files were not counted (test code does not ship).`);
  }

  // Counts, score and gate only use findings from rules proven precise; experimental ones are reported separately
  const openFindings = gatingFindings(findings);
  const experimentalCount = findings.filter((f) => f.status === 'OPEN' && f.maturity === 'experimental').length;
  const criticalCount = openFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = openFindings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = openFindings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = openFindings.filter(f => f.severity === 'LOW').length;
  const uiClicheCount = openFindings.filter(f => f.type === 'VIBEPOLISH').length;

  const score = calculateReadinessScore(findings);
  let gateStatus = calculateGateStatus(findings);

  // Policy-as-Code strategy enforcement (F-43)
  if (rcConfig) {
    if (rcConfig.failStrategy === 'advisory') {
      gateStatus = 'PASSED';
      logs.push(`[${new Date().toLocaleTimeString()}] [CONFIG] Policy-as-Code: Advisory mode active — Release gate set to PASSED.`);
    } else if (rcConfig.failStrategy === 'strict') {
      const minThreshold = typeof rcConfig.minScoreThreshold === 'number' ? rcConfig.minScoreThreshold : 85;
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
    durationMs: Date.now() - scanStartedAt,
    findings,
    logs,
    summary,
    detectedDatabases: detectedStack.databases,
    detectedOrms: detectedStack.orms,
    detectedFramework: detectedApp.framework ?? undefined,
    detectedProviders: detectedApp.providers
  };
}
