/**
 * Strips single-line (//), multi-line (/* ... *\/), and HTML (<!-- ... -->) comments
 * to prevent false positives in commented-out code snippets or documentation.
 */
export function stripComments(content: string): string {
  if (!content) return '';
  return content
    .replace(/\/\*[\s\S]*?\*\//g, (match) => {
      // F-12 Remediation: Preserve newlines so AST/regex line numbers do not drift
      const lineBreaks = match.split('\n').length - 1;
      return '\n'.repeat(lineBreaks);
    })
    .replace(/<!--[\s\S]*?-->/g, (match) => {
      const lineBreaks = match.split('\n').length - 1;
      return '\n'.repeat(lineBreaks);
    })
    .replace(/(?<!:)\/\/.*$/gm, '');   // Single-line JS/TS comments (preserves http:// and https:// URLs)
}

/**
 * Cooperative scheduling utility for streaming AST analysis.
 * Yields control back to the browser or Node.js event loop to prevent main thread freeze
 * on large (1,000+ files) codebases.
 */
export async function yieldToMain(): Promise<void> {
  if (typeof window !== 'undefined' && 'scheduler' in window && typeof (window as any).scheduler?.yield === 'function') {
    return (window as any).scheduler.yield();
  }
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/** Test, spec, fixture and seed files: their code never ships, but secrets committed in them still leak. */
export function isTestFixturePath(path: string): boolean {
  const p = path.toLowerCase().replace(/\\/g, '/');
  // examples / samples / demos: sample apps shipped with a library, not the product itself
  return /(?:^|\/)(?:tests?|unittests?|testing|testdata|testutils?|__tests__|__mocks__|__fixtures__|fixtures?|e2e|cypress|spec|seeds?|examples?|samples?|demos?)\//.test(p) ||
    /\.(?:test|spec|e2e)\.[cm]?[jt]sx?$/.test(p) ||
    /(?:^|\/)(?:test_[^/]+|tests|conftest)\.py$|_test\.(?:py|go)$|_spec\.rb$|Tests?\.(?:java|cs|kt)$/.test(p);
}

/**
 * Files whose job is to list credential shapes: secret-scanner configs (.gitleaks.toml, .secrets.baseline,
 * trufflehog / detect-secrets settings) and test fixtures or tests named fake / dummy keys or about redaction.
 */
export const isSecretPatternFixture = (path: string): boolean => {
  const p = (path || '').replace(/\\/g, '/').toLowerCase();
  return /(?:^|\/)(?:\.gitleaks\.toml|\.gitleaksignore|\.secrets\.baseline|\.trufflehog\w*\.ya?ml|\.detect-secrets\w*)$/.test(p)
    || /(?:^|\/)(?:tests?|unittests?|testdata|__tests__|spec|fixtures?)\/(?:.*\/)?[^/]*(?:fake|dummy|redact|scrub|mask|leak|secret[-_]?scan)[^/]*$/.test(p)
    // Redaction / scrubber modules list key headers as patterns wherever they live
    || /(?:^|\/)[^/]*(?:redact|scrubber|secret[-_]?scan)[^/]*\.\w+$/.test(p);
};

/** Hardcoded-secret rules stay active in test files. */
export const isSecretRuleId = (ruleId: number): boolean => ruleId === 1 || ruleId === 43 || (ruleId >= 5001 && ruleId <= 5299);

/** Third-party code copied into the repo (vendored libraries, bower/static lib folders, an embedded VS Code fork). */
export const isVendoredPath = (path: string): boolean =>
  /(?:^|\/)(?:vendor|third_party|bower_components|jspm_packages|static\/(?:js\/)?libs?|public\/(?:js\/)?libs?|assets\/(?:js\/)?(?:libs?|vendor)|wwwroot\/lib|code-oss|deps|externals?)\/|(?:^|\/)[a-z0-9_.-]+[-.]v?\d+\.\d+(?:\.\d+)?(?:[.-][a-z0-9_]+)*\.(?:[cm]?js|css)$|\.(?:min|bundle(?:\.min)?|slim(?:\.min)?)\.(?:[cm]?js|css)$/i.test(path.replace(/\\/g, '/'));

/** Minified / generated bundles: very long average line length. */
export function isMinifiedContent(content: string): boolean {
  if (!content || content.length < 5000) return false;
  const lineCount = content.split('\n').length;
  return content.length / lineCount > 400;
}
