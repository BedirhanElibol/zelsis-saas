/**
 * Security defects from the Gemini rule report that no existing rule caught (SECG-01.., Rule IDs 29900-29999).
 * Each proposal was re-checked against the current scanner and rewritten so the finding rests on a configuration
 * value or call shape that is unsafe in every context (no taint guessing): path traversal through upload file names,
 * source trees served over HTTP, prototype pollution switches, disabled SAML signatures, algorithm confusion,
 * shared-cache leaks of authenticated responses, wildcard token lookups and similar.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; cwe: string; lineIdx: number; why: string; fix: string }
type Add = (h: Hit) => void;

const SKIP = /\.d\.ts$|(?:^|\/)node_modules\/|(?:^|\/)vendor\/|\.min\.js$|(?:^|\/)(?:tests?|__tests__|e2e|__mocks__|fixtures?|testdata)\/|\.(?:test|spec)\.[jt]sx?$|_test\.(?:go|py)$|(?:^|\/)test_\w+\.py$/i;
const lineAt = (c: string, off: number) => { let n = 0; for (let i = 0; i < off && i < c.length; i++) if (c.charCodeAt(i) === 10) n++; return n; };
const PRIVATE_BUCKET = /(?:^|[-_])(?:invoices?|receipts?|documents?|docs|private|contracts?|kyc|identity|ids|passports?|licen[cs]es?|medical|health|statements?|attachments?|backups?|exports?|payslips?|tax(?:es)?|secure|confidential|user[-_]?files)(?:$|[-_])/i;

function evaluateJs(path: string, c: string, add: Add) {
  const at = (off: number) => lineAt(c, off);

  // SECG-03: express.static serving dotfiles (.env, .git)
  for (const m of c.matchAll(/\b(?:express\.static|serveStatic|serve-static)\b[^;\n]*\bdotfiles\s*:\s*['"]allow['"]/g)) {
    add({ ruleId: 29902, code: 'SECG-03', severity: 'HIGH', category: 'Sensitive Data Exposure', cwe: 'CWE-538', lineIdx: at(m.index!),
      title: "Static Server Allows Dotfiles (dotfiles: 'allow')",
      why: 'With dotfiles allowed, files such as .env, .git/config or .npmrc inside the served folder can be downloaded by anyone, exposing secrets and source history.',
      fix: "Remove the option (the default ignores dotfiles) or set dotfiles: 'deny', and keep secrets outside the static directory." });
  }

  // SECG-04: qs / body parser with allowPrototypes
  for (const m of c.matchAll(/\ballowPrototypes\s*:\s*true\b/g)) {
    add({ ruleId: 29903, code: 'SECG-04', severity: 'HIGH', category: 'Prototype Pollution', cwe: 'CWE-1321', lineIdx: at(m.index!),
      title: 'Query Parser Configured With allowPrototypes: true',
      why: 'allowPrototypes lets a query string such as ?hasOwnProperty=x or ?toString=… override Object.prototype keys on the parsed object, which breaks property checks and can bypass authorization logic.',
      fix: 'Remove allowPrototypes (default false) and validate the parsed query with a schema.' });
  }

  // SECG-07: NestJS global ValidationPipe without whitelist
  for (const m of c.matchAll(/\buseGlobalPipes\(\s*new\s+ValidationPipe\(([^)]*)\)/g)) {
    if (/\bwhitelist\s*:\s*true/.test(m[1])) continue;
    add({ ruleId: 29906, code: 'SECG-07', severity: 'MEDIUM', category: 'Mass Assignment', cwe: 'CWE-915', lineIdx: at(m.index!),
      title: 'Global ValidationPipe Without whitelist: true',
      why: 'Without whitelist, properties not declared in the DTO pass through to your handlers, so a client can add role, isAdmin or ownerId and have them saved by spread or ORM calls.',
      fix: 'Use new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }).' });
  }

  // SECG-08: SAML response / assertion signature checks disabled
  if (/saml/i.test(c)) {
    for (const m of c.matchAll(/\b(wantAssertionsSigned|wantAuthnResponseSigned|validateSignature|checkSignature)\s*:\s*false\b/g)) {
      add({ ruleId: 29907, code: 'SECG-08', severity: 'CRITICAL', category: 'Authentication', cwe: 'CWE-347', lineIdx: at(m.index!),
        title: `SAML ${m[1]}: false`,
        why: 'With signature checks off, anyone can forge a SAML response for any email or user id and sign in as that user, including administrators of any tenant using SSO.',
        fix: `Set ${m[1]}: true (both response and assertion signatures) and pin the IdP certificate (idpCert / cert).` });
    }
  }

  // SECG-11: authenticated response marked cacheable by shared caches
  const isHandler = /(?:^|\/)(?:route|middleware)\.[cm]?[jt]s$|(?:^|\/)(?:api|server|routes)\//i.test(path);
  if (isHandler && /\b(?:auth\(\)|getServerSession\(|getSession\(|auth\.getUser\(|getUser\(|currentUser\(|cookies\(\)|req\.user\b|req\.session\b|verifyToken\(|getToken\()/.test(c)) {
    for (const m of c.matchAll(/['"]?Cache-Control['"]?\s*[:,]\s*['"`]([^'"`]*\b(?:public|s-maxage)\b[^'"`]*)['"`]/gi)) {
      if (/\b(?:private|no-store)\b/i.test(m[1])) continue;
      add({ ruleId: 29910, code: 'SECG-11', severity: 'HIGH', category: 'Sensitive Data Exposure', cwe: 'CWE-524', lineIdx: at(m.index!),
        title: `Authenticated Response Sent With Cache-Control "${m[1].slice(0, 40)}"`,
        why: 'This handler reads the user session, but the response is marked cacheable by CDNs and proxies, so one user\'s data can be stored and served to the next visitor of the same URL.',
        fix: "Use Cache-Control: private, no-store for per-user responses (and add Vary: Cookie / Authorization where caching is required)." });
    }
  }

  // SECG-13: public URL generated for a private Supabase bucket
  for (const m of c.matchAll(/\.from\(\s*['"]([\w-]+)['"]\s*\)\s*\.getPublicUrl\(/g)) {
    if (!PRIVATE_BUCKET.test(m[1])) continue;
    add({ ruleId: 29912, code: 'SECG-13', severity: 'HIGH', category: 'Broken Access Control', cwe: 'CWE-200', lineIdx: at(m.index!),
      title: `getPublicUrl() on the Private "${m[1]}" Bucket`,
      why: `Public URLs never expire and need no auth: if "${m[1]}" is public they are guessable permanent links to every file, and if it is private the links do not work at all.`,
      fix: `Keep "${m[1]}" private and hand out short-lived links with createSignedUrl(path, 60) after checking the user owns the file.` });
  }

  // SECG-14: JWT kid header used to build a file path
  for (const m of c.matchAll(/\b(?:readFileSync|readFile|join|resolve)\(\s*[^)]*\b(?:header|decoded\.header|protectedHeader|\w+Header)\??\.kid\b/g)) {
    add({ ruleId: 29913, code: 'SECG-14', severity: 'CRITICAL', category: 'Authentication', cwe: 'CWE-22', lineIdx: at(m.index!),
      title: 'JWT kid Header Used to Load the Verification Key From Disk',
      why: 'kid comes from the unverified token, so "../../../dev/null" or any known file selects a key the attacker controls or knows, letting them sign tokens that pass verification.',
      fix: 'Look kid up in a fixed map of allowed key ids (or a JWKS) and reject unknown values; never put it in a path.' });
  }

  // SECG-15: LIKE / ILIKE used to look up a secret token
  for (const m of c.matchAll(/\.(i?like)\(\s*['"](\w*(?:token|code|secret|invite\w*|api_?key|otp|nonce))['"]\s*,\s*(?!['"`][^%]*['"`]\s*\))/gi)) {
    add({ ruleId: 29914, code: 'SECG-15', severity: 'HIGH', category: 'Authentication', cwe: 'CWE-155', lineIdx: at(m.index!),
      title: `Secret Token Matched by Pattern: ${m[2]} via .${m[1]}()`,
      why: `LIKE treats % and _ as wildcards, so a submitted value of "%" matches any ${m[2]}: an attacker can redeem someone else's invite, reset or API token without knowing it.`,
      fix: `Compare exactly: .eq('${m[2]}', value) (and store tokens hashed).` });
  }
  for (const m of c.matchAll(/\b(\w*(?:token|Token|code|Code|secret|Secret|inviteCode|apiKey|otp))\s*:\s*\{\s*(contains|startsWith|endsWith)\s*:/g)) {
    add({ ruleId: 29914, code: 'SECG-15', severity: 'HIGH', category: 'Authentication', cwe: 'CWE-155', lineIdx: at(m.index!),
      title: `Secret Token Matched by Pattern: ${m[1]} via Prisma ${m[2]}`,
      why: `${m[2]} is a partial match, so a short or empty value matches existing ${m[1]}s: tokens can be redeemed without knowing them.`,
      fix: `Use an exact match: where: { ${m[1]}: value }.` });
  }

  // SECG-17: JWT issued without an expiry
  if (/['"]jsonwebtoken['"]/.test(c)) {
    for (const m of c.matchAll(/\bjwt\.sign\(/g)) {
      // Split the top-level arguments: (payload, secret[, options[, callback]])
      const s = m.index! + m[0].length - 1;
      const args: string[] = []; let depth = 0; let from = s + 1; let end = -1;
      for (let i = s; i < c.length; i++) {
        const ch = c[i];
        if (ch === '"' || ch === "'" || ch === '`') { for (i++; i < c.length && c[i] !== ch; i++) if (c[i] === '\\') i++; continue; }
        if ('([{'.includes(ch)) depth++;
        else if (')]}'.includes(ch)) { depth--; if (depth === 0) { args.push(c.slice(from, i)); end = i; break; } }
        else if (ch === ',' && depth === 1) { args.push(c.slice(from, i)); from = i + 1; }
      }
      if (end < 0 || args.length < 2) continue;
      const payload = args[0]; const options = args[2]?.trim() ?? '';
      // exp may be set in the payload; options passed as a variable cannot be checked
      if (/\bexp\s*:|\bexpiresIn\b/.test(payload) || (options && !options.startsWith('{')) || /\bexpiresIn\b|\.\.\./.test(options)) continue;
      {
        add({ ruleId: 29916, code: 'SECG-17', severity: 'MEDIUM', category: 'Session Management', cwe: 'CWE-613', lineIdx: at(m.index!),
          title: 'JWT Signed Without an Expiry',
          why: 'Without expiresIn (or an exp claim) the token is valid forever: a leaked token cannot be revoked by waiting, and logout does nothing for it.',
          fix: "Pass an expiry: jwt.sign(payload, secret, { expiresIn: '15m' }) and refresh tokens server-side." });
      }
    }
  }
  for (const m of c.matchAll(/\bnew\s+SignJWT\(/g)) {
    const chain = c.slice(m.index!, c.indexOf('.sign(', m.index!) + 6);
    if (chain.length > 6 && chain.length < 1500 && !/setExpirationTime\(/.test(chain) && !/\bexp\s*:/.test(chain)) {
      add({ ruleId: 29916, code: 'SECG-17', severity: 'MEDIUM', category: 'Session Management', cwe: 'CWE-613', lineIdx: at(m.index!),
        title: 'JWT Signed Without an Expiry',
        why: 'The jose SignJWT chain sets no exp claim, so the token never expires and cannot be invalidated by time.',
        fix: "Add .setExpirationTime('15m') to the SignJWT chain." });
    }
  }

  // SECG-18: request input passed as an argument to git / curl / ssh … without "--"
  for (const m of c.matchAll(/\b(?:spawn|execFile|spawnSync|execFileSync)\(\s*['"](git|curl|wget|ssh|scp|rsync|tar|zip|unzip|ffmpeg|convert|magick|psql|mysql)['"]\s*,\s*\[([^\]]*)\]/g)) {
    if (/['"]--['"]/.test(m[2]) || !/\b(?:req\.(?:body|query|params)|body\.\w+|searchParams\.get\(|formData\.get\(|params\.\w+|input\.\w+)/.test(m[2])) continue;
    add({ ruleId: 29917, code: 'SECG-18', severity: 'HIGH', category: 'Command Injection', cwe: 'CWE-88', lineIdx: at(m.index!),
      title: `Request Input Passed as an Argument to ${m[1]}`,
      why: `Even without a shell, a value starting with "-" is read by ${m[1]} as an option (for example --upload-pack=… for git or -o for curl), which can run commands or write files.`,
      fix: `Validate the value (allow-list or a strict regex), and put "--" before positional arguments: ['clone', '--', url].` });
  }
}

function evaluatePy(lines: string[], add: Add) {
  lines.forEach((l, i) => {
    if (/^\s*#/.test(l)) return;
    // SECG-06: PyJWT accepting both asymmetric and HMAC algorithms
    const a = /\bjwt\.decode\([^)]*algorithms\s*=\s*\[([^\]]*)\]/.exec(l);
    if (a && /['"](?:RS|ES|PS)\d{3}['"]/.test(a[1]) && /['"]HS\d{3}['"]/.test(a[1])) add({ ruleId: 29905, code: 'SECG-06', severity: 'CRITICAL', category: 'Authentication', cwe: 'CWE-327', lineIdx: i,
      title: 'jwt.decode Accepts Both RSA/EC and HMAC Algorithms',
      why: 'Allowing HS256 next to RS256 lets an attacker sign a token with HMAC using your public key as the secret, which then verifies: full authentication bypass (algorithm confusion).',
      fix: "Accept one algorithm family per key: algorithms=['RS256'] for public keys, ['HS256'] only with a shared secret." });

    // SECG-12: SQLAlchemy text() fragment built with an f-string / format
    const t = /\b(?:sa\.|sqlalchemy\.)?text\(\s*(?:[fF]['"][^'"]*\{|['"][^'"]*['"]\s*\.format\(|['"][^'"]*['"]\s*%\s*)/.exec(l);
    if (t && !/\b(?:SELECT|INSERT|UPDATE|DELETE)\b/i.test(l)) add({ ruleId: 29911, code: 'SECG-12', severity: 'HIGH', category: 'SQL Injection', cwe: 'CWE-89', lineIdx: i,
      title: 'SQLAlchemy text() Fragment Built From an f-string',
      why: 'text() sends the string to the database as raw SQL; interpolating a filter, sort column or search term into it lets a request inject SQL (read other tenants, bypass filters).',
      fix: 'Use bound parameters: text("name = :name").bindparams(name=value), and map sort columns through an allow-list.' });
  });
}

function evaluateGo(lines: string[], add: Add) {
  lines.forEach((l, i) => {
    if (/^\s*\/\//.test(l)) return;
    // SECG-01: uploaded file saved under its client-supplied name
    if (/\bSave(?:Uploaded)?File\([^)]*\b\w+\.Filename\b/.test(l) && !/filepath\.Base\(|path\.Base\(|uuid|sanitize/i.test(l)) add({ ruleId: 29900, code: 'SECG-01', severity: 'HIGH', category: 'Path Traversal', cwe: 'CWE-22', lineIdx: i,
      title: 'Upload Saved Using the Client File Name',
      why: 'file.Filename is sent by the client; a name like "../../app/main.go" or "../.ssh/authorized_keys" writes outside the upload folder and can overwrite code or credentials.',
      fix: 'Generate the name on the server (uuid + allowed extension), or at least use filepath.Base(file.Filename) and check the result stays inside the upload directory.' });
    // SECG-02: the working directory served as static files
    if (/\bhttp\.FileServer\(\s*http\.Dir\(\s*"(?:\.|\.\/|\/)?"\s*\)\s*\)/.test(l)) add({ ruleId: 29901, code: 'SECG-02', severity: 'HIGH', category: 'Sensitive Data Exposure', cwe: 'CWE-538', lineIdx: i,
      title: 'http.FileServer Serves the Working Directory',
      why: 'Serving "." publishes the source code, go.mod, .env files and any credentials next to the binary to anyone who requests them.',
      fix: 'Serve a dedicated folder (http.Dir("./public")) that contains only public assets.' });
  });
}

function evaluateConfig(path: string, lines: string[], add: Add) {
  // SECG-09: Spring Boot actuator endpoints all exposed over HTTP
  if (/(?:^|\/)application[\w-]*\.(?:properties|ya?ml)$/i.test(path)) {
    lines.forEach((l, i) => {
      const prop = /management\.endpoints\.web\.exposure\.include\s*[=:]\s*['"]?(\*|[^'"\s#]*\b(?:env|heapdump|configprops|threaddump|loggers|shutdown)\b)/.exec(l);
      const yml = /^\s*include\s*:\s*['"]?\*['"]?\s*$/.test(l) && lines.slice(Math.max(0, i - 3), i).some((p) => /^\s*exposure\s*:/.test(p));
      if (prop || yml) add({ ruleId: 29908, code: 'SECG-09', severity: 'HIGH', category: 'Sensitive Data Exposure', cwe: 'CWE-215', lineIdx: i,
        title: `Spring Boot Actuator Exposes ${prop ? prop[1] : '*'}`,
        why: 'Actuator endpoints such as /actuator/env and /actuator/heapdump return environment variables, credentials and in-memory secrets; /actuator/loggers and /shutdown change the running app.',
        fix: 'Expose only health and info (management.endpoints.web.exposure.include=health,info) and protect any other endpoint with authentication on a separate port.' });
    });
  }
}

function evaluateCs(c: string, add: Add) {
  // SECG-10: ASP.NET Core CORS reflecting every origin with credentials
  const m = /\.SetIsOriginAllowed\(\s*\(?\s*_?\w*\s*\)?\s*=>\s*true\s*\)/.exec(c);
  if (m && /\.AllowCredentials\(\)/.test(c)) add({ ruleId: 29909, code: 'SECG-10', severity: 'HIGH', category: 'CORS Misconfiguration', cwe: 'CWE-942', lineIdx: lineAt(c, m.index),
    title: 'CORS Allows Any Origin With Credentials',
    why: 'SetIsOriginAllowed(_ => true) with AllowCredentials() lets any website send authenticated requests with the user\'s cookies and read the responses, so a malicious page can act as the signed-in user.',
    fix: 'List the allowed origins explicitly: policy.WithOrigins("https://app.example.com").AllowCredentials().' });
}

export function evaluateSecurityGeminiRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (SKIP.test(path)) return { findings, logs };
  const c = cleanContent;
  if (!c || c.length > 400_000) return { findings, logs };

  const hits: Hit[] = [];
  const add: Add = (h) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  const pl = c.replace(/\r/g, '').split('\n');
  if (/\.[cm]?[jt]sx?$/i.test(path)) evaluateJs(path, c, add);
  else if (/\.py$/i.test(path)) evaluatePy(pl, add);
  else if (/\.go$/i.test(path)) evaluateGo(pl, add);
  else if (/\.cs$/i.test(path)) evaluateCs(c, add);
  else if (/\.(?:properties|ya?ml)$/i.test(path)) evaluateConfig(path, pl, add);
  else return { findings, logs };

  const raw = file.content.split('\n');
  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `secg${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, `${h.cwe}: ${h.why}`],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] [SEC] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
