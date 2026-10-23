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
  // .semgrep/ holds rule tests: code that is vulnerable on purpose
  return /(?:^|\/)(?:tests?|unittests?|testing|testdata|testutils?|\.semgrep|__tests__|__mocks__|__fixtures__|fixtures?|e2e|cypress|spec|seeds?|examples?|samples?|demos?)\//.test(p) ||
    // *.setup.ts alone is too broad (db.setup.ts, passport.setup.js are app code); only test runner setups
    /\.(?:test|spec|e2e|global-setup)\.[cm]?[jt]sx?$|(?:^|\/)(?:vitest|jest|playwright|test)\.setup\.[cm]?[jt]sx?$/.test(p) ||
    /(?:^|\/)(?:vitest|jest|playwright)\.config\.[cm]?[jt]sx?$/.test(p) ||
    /(?:^|\/)(?:global-setup|test-setup)\.[cm]?[jt]sx?$/.test(p) ||
    /(?:^|\/)[^/]*fixture[s]?\.(?:sql|[cm]?[jt]sx?|py|rb|json)$/i.test(p) ||
    /(?:^|\/)\.env\.(?:test|testing)\b/i.test(p) ||
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
  /(?:^|\/)(?:vendor|third_party|bower_components|jspm_packages|static\/(?:js\/)?libs?|public\/(?:js\/)?libs?|assets\/(?:js\/)?(?:libs?|vendor)|wwwroot\/lib|code-oss|deps|externals?)\/|(?:^|\/)static\/(?:[\w-]+\/){1,2}(?:js\/)?libs?\/|(?:^|\/)[a-z0-9_.-]+[-.]v?\d+\.\d+(?:\.\d+)?(?:[.-][a-z0-9_]+)*\.(?:[cm]?js|css)$|\.(?:min|slim(?:\.min)?)\.(?:[cm]?js|css)$/i.test(path.replace(/\\/g, '/'));

/** Minified / generated bundles: very long average line length. */
export function isMinifiedContent(content: string): boolean {
  if (!content || content.length < 5000) return false;
  const lineCount = content.split('\n').length;
  return content.length / lineCount > 400;
}

/**
 * Files that are not part of the shipped application (documentation, knowledge bases,
 * seeders, dev scripts, and local-only docker compose files).
 * Non-secret findings in these paths are lowered to MEDIUM so they do not block a release gate.
 * Secrets keep their existing behaviour.
 */
export function isNonAppPath(path: string): boolean {
  if (!path) return false;
  const p = path.replace(/\\/g, '/');

  // docs: docs/, docs_src/, documentation/, content folders with markdown/mdx
  // Keep blocking: API endpoints such as app/api/docs/route.ts are application routes, not documentation
  const isAppEndpoint = /(?:^|\/)(?:app|src|server)\/api\//i.test(p) || /(?:^|\/)api\//i.test(p);
  if (!isAppEndpoint && /(?:^|\/)(?:docs?|docs_src|documentation)\//i.test(p)) return true;
  if (/\.(?:md|mdx)$/i.test(p)) return true;
  if (/(?:^|\/)content\/(?:.*\/)?[^/]+\.(?:md|mdx)$/i.test(p)) return true;

  // knowledge or teaching material: knowledge/, cookbook/, tutorials?/, courses?/, homework/
  if (/(?:^|\/)(?:knowledge|cookbook|tutorials?|courses?|homework)\//i.test(p)) return true;

  // seeders: database/seeders/, db/seeds?/, *.seed.[jt]s, *Seeder.php
  if (/(?:^|\/)(?:database\/seeders|db\/seeds?)(?:\/|$|\.)/i.test(p)) return true;
  if (/(?:^|\/)(?:[a-z0-9_.]+\.)?seeds?\.[cm]?[jt]sx?$/i.test(p)) return true;
  if (/[a-z0-9_]*seeder\.php$/i.test(p)) return true;

  // local or dev infra: docker-compose.(local|dev|development|test|sandbox).ya?ml, compose.(local|dev).ya?ml, test environments
  if (/(?:^|\/)(?:docker-compose|compose)\.(?:local|dev|development|test|sandbox)\.ya?ml$/i.test(p)) return true;
  if (/(?:^|\/)\.env\.(?:test|testing)\b/i.test(p)) return true;

  // dev and setup scripts at repo root: setup.sh, run_*.py, Makefile-style helpers, scripts/
  if (/(?:^|\/)(?:setup|install|configure|bootstrap|init|deploy)\.sh$/i.test(p)) return true;
  if (/^run_[^/]+\.py$/i.test(p) || /(?:^|\/)run_[^/]+\.py$/i.test(p)) return true;
  if (/(?:^|\/)scripts\/(?:.*\/)?(?:build|dev|test|lint|bench|check|ci|gen|format|preview|release|audit|mock|seed|deploy|run|tool)/i.test(p)) return true;
  if (/^(?:Makefile|Rakefile|fabfile\.py|noxfile\.py|tasks\.py|manage\.py|setup\.py)$/i.test(p) || /(?:^|\/)(?:Rakefile|fabfile\.py|noxfile\.py)$/i.test(p)) return true;

  // workbench fixtures and test setups: experiments/, fixture.sql, global-setup
  if (/(?:^|\/)(?:experiments?)\//i.test(p)) return true;
  if (/(?:^|\/)[^/]*fixture[s]?\.sql$/i.test(p)) return true;
  if (/(?:^|\/)[^/]*global-setup\.[cm]?[jt]sx?$/i.test(p)) return true;

  return false;
}
/**
 * Untrusted user input pattern across supported languages and frameworks (HTTP requests, query strings,
 * route parameters, request bodies, headers, cookies, uploads, stdin and sockets).
 */
export const UNTRUSTED_INPUT = new RegExp([
  String.raw`\b(?:request|req)\.(?:body|data|args|form|values|files|json|params|query|query_params|path_params|cookies|headers|get_data|stream|raw_post|POST|GET|COOKIES|FILES|url|nextUrl|searchParams|getParameter|getInputStream|getReader|post|text|formData|blob|bytes|arrayBuffer)\b`,
  String.raw`\b(?:request|req)\s*:\s*(?:Next)?Request\b`,
  String.raw`\bsearchParams\.(?:get|getAll|has)\b`,
  String.raw`\bparams\[`,
  String.raw`\{[^\n}]*\b(?:params|searchParams)\b[^\n}]*\}[\s:]`,
  String.raw`\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b`,
  String.raw`\$request->`,
  String.raw`\bcookies\[`,
  String.raw`\brequest_body\b`,
  // Only the request variable itself: a prefix like [a-z]*r matched user.header, parser.body, buffer.form
  String.raw`\b(?:r|req|request)\.(?:URL|FormValue|PostFormValue|Form|PostForm|MultipartForm|Body|Header|Cookie|Cookies)\b`,
  String.raw`\b(?:c|ctx)\.(?:Query|DefaultQuery|Param|Params|PostForm|FormValue|FormFile|QueryParam|Bind|BindJSON|BindQuery|BindXML|BindYAML|BindHeader|BindUri|ShouldBind|ShouldBindJSON|ShouldBindQuery|ShouldBindXML|ShouldBindYAML|ShouldBindHeader|ShouldBindUri|ShouldBindBodyWith|GetHeader|GetRawData|BodyParser)\s*\(`,
  String.raw`\bhttp\.Request\b`,
  String.raw`\bHttpServletRequest\b`,
  String.raw`@(?:RequestBody|RequestParam|PathVariable|RequestHeader|CookieValue)\b`,
  String.raw`\bgetInputStream\s*\(`,
  String.raw`\[\s*From(?:Body|Query|Route|Header|Form)\s*\]`,
  String.raw`\bRequest\.(?:Query|Form|Body|Headers|Cookies)\b`,
  String.raw`\b(?:ctx|context)\.(?:req|request|query|body|params|header|headers)\b`,
  String.raw`\bAstro\.request\b`,
  String.raw`\b(?:getText|getIntent|getExtras|getQueryParameter)\s*\(`,
  String.raw`\brecv\s*\(`,
  String.raw`\bsys\.stdin\b`,
  String.raw`\bSTDIN\b`,
  String.raw`\bupload\b`,
].join('|'), 'i');

export function hasUntrustedInput(content: string): boolean {
  if (!content) return false;
  return UNTRUSTED_INPUT.test(content);
}

/**
 * Injection rules that represent injection/execution vulnerability classes
 * where lack of external user input in the file downgrades the finding from CRITICAL to HIGH.
 */
export const CRITICAL_INJECTION_RULES = new Set<number>([
  32, 33, 42,
  8811,
  24106,
  3020, 3021,
  6043,
  8516, 8517,
  8810, 8830,
  9001, 9002,
  9605,
  12002, 12503,
  18001, 18003, 18011, 18021, 18031, 18033, 18041, 18101, 18102, 18104,
  24101, 24102,
  29002,
]);

export function isCriticalInjectionRule(ruleId: number): boolean {
  return CRITICAL_INJECTION_RULES.has(ruleId);
}
