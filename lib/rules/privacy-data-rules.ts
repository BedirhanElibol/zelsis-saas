/**
 * Personal data exposure, GDPR/KVKK-relevant code patterns (PRIV-xx, Rule IDs 28401-28499).
 * Each rule keys on a concrete code defect that leaks credentials or personal data (CWE-200 / 359 / 532,
 * GDPR Art. 32 "security of processing"), never on the absence of a process or policy.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; lineIdx: number; category: string; why: string; fix: string }

const JS_FILE = /\.[cm]?[jt]sx?$/i;
const PY_FILE = /\.py$/i;
const isCommentLine = (l: string): boolean => /^\s*(?:\/\/|\*|\/\*|#)/.test(l);

/** Text of the call whose opening parenthesis is at or after `col` on line `start`, up to 15 lines. */
function callText(lines: string[], start: number, col: number): { text: string; end: number } {
  let depth = 0;
  let opened = false;
  let text = '';
  for (let i = start; i < Math.min(lines.length, start + 15); i++) {
    const seg = i === start ? lines[i].slice(col) : lines[i];
    for (let c = 0; c < seg.length; c++) {
      const ch = seg[c];
      text += ch;
      if (ch === '(') { depth++; opened = true; } else if (ch === ')') {
        depth--;
        if (opened && depth === 0) return { text, end: i };
      }
    }
    text += '\n';
  }
  return { text, end: Math.min(lines.length - 1, start + 14) };
}

const LOG_SINK = /\b(?:console\.(?:log|info|debug|warn|error|dir)|logger\.(?:log|info|debug|warn|warning|error|trace)|log\.(?:info|debug|warn|error|Printf|Println)|logging\.(?:info|debug|warning|error)|print|fmt\.Print(?:f|ln)?|Sentry\.(?:setExtra|setContext|addBreadcrumb|captureMessage))\s*\(/;
const REDACTED = /redact|mask|sanitiz|omit\(|scrub/i;

const ANALYTICS_SINK = /\b(?:posthog\.(?:capture|identify|people\.set|register|setPersonProperties)|mixpanel\.(?:track|identify|register|people\.set)|analytics\.(?:track|identify|page)|amplitude\.(?:track|logEvent|setUserProperties)|heap\.(?:track|identify|addUserProperties)|gtag|(?:window\.)?dataLayer\.push|Sentry\.(?:setUser|setExtra|setContext|setTag)|FS\.(?:identify|setUserVars)|LogRocket\.(?:identify|track)|Intercom|umami\.track|plausible)\s*\(/;
const SENSITIVE_NAMES = '(?:password|passwd|new_?password|current_?password|old_?password|ssn|social_?security_?(?:number)?|tckn|tc_?kimlik(?:_?no)?|national_?id(?:_?number)?|passport_?(?:no|number)|card_?number|cc_?number|cvv|cvc|iban|access_?token|refresh_?token)';
/** A sensitive name used as an object key (quoted or not) or as a shorthand property, never as a string value. */
const SENSITIVE_KEY = new RegExp(`(?:^|[{,\\s(])(?:['"]${SENSITIVE_NAMES}['"]\\s*:|${SENSITIVE_NAMES}\\s*(?::|,|\\}))`, 'i');

export function evaluatePrivacyDataRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (/(?:^|\/)node_modules\//.test(path)) return { findings, logs };
  const isJs = JS_FILE.test(path);
  const isPy = PY_FILE.test(path);
  const isPhp = /\.php$/i.test(path);
  const isGo = /\.go$/i.test(path);
  const hits: Hit[] = [];
  const claimed = new Set<number>();

  // PRIV-13: request logger that writes every request body (signup / login passwords included) to the logs
  if (isJs) {
    let lineIdx = -1;
    const tokenRe = /morgan\.token\(\s*['"]([\w-]+)['"]/;
    for (let i = 0; i < lines.length && lineIdx === -1; i++) {
      const m = lines[i].match(tokenRe);
      if (!m || isCommentLine(lines[i])) continue;
      const { text } = callText(lines, i, lines[i].indexOf('morgan.token'));
      if (/\breq\.body\b(?!\s*(?:\.|\?\.|\[))/.test(text) && !REDACTED.test(text) && cleanContent.includes(`:${m[1]}`)) lineIdx = i;
    }
    if (lineIdx === -1) {
      for (let i = 0; i < lines.length && lineIdx === -1; i++) {
        if (!/\b(?:app|router|server)\.use\(\s*(?:async\s*)?\(?\s*req\b/.test(lines[i])) continue;
        for (let j = i + 1; j < Math.min(lines.length, i + 6); j++) {
          if (LOG_SINK.test(lines[j]) && /\breq\.body\b(?!\s*(?:\.|\?\.|\[))/.test(lines[j]) && !REDACTED.test(lines[j]) && !isCommentLine(lines[j])) { lineIdx = j; break; }
        }
      }
    }
    if (lineIdx !== -1) {
      claimed.add(lineIdx);
      hits.push({
        ruleId: 28413, code: 'PRIV-13', severity: 'MEDIUM', lineIdx, category: 'Sensitive Data Logging',
        title: 'Request Logger Writes Every Request Body to the Logs',
        why: 'A global logger that serializes req.body records the plaintext passwords, tokens and personal data of every signup, login and profile request (CWE-532), and log stores are rarely access-controlled like the database.',
        fix: 'Do not log request bodies globally. Log method, path, status and a request id; if a body is needed for debugging, log an allow-listed subset or use a logger with redact paths (pino redact).'
      });
    }
  }

  // PRIV-01: authentication handler logs the raw request body (plaintext password)
  if (isJs || isPy) {
    const authPath = /(?:^|\/)(?:login|log-in|signin|sign-in|signup|sign-up|register|registration|reset-password|forgot-password|change-password|password)(?:\/|\.|$)|(?:^|\/)auth\/[^/]*\.(?:[cm]?[jt]sx?|py)$|(?:^|\/)auth(?:entication)?\.(?:[cm]?[jt]sx?|py)$/i.test(path);
    const authCode = /\bpassword\b/i.test(cleanContent) && /\b(?:bcrypt|argon2|signInWithPassword|signUp\s*\(|check_password|verify_password|authenticate\s*\(|hashPassword|hash_password|createUserWithEmailAndPassword|pwd_context|scrypt)\b/.test(cleanContent);
    if (authPath || authCode) {
      const bodyVars = new Set<string>();
      for (const m of cleanContent.matchAll(/\b(?:const|let|var)\s+(\w+)\s*(?::\s*[\w<>[\]]+\s*)?=\s*(?:await\s+)?(?:\w+\.(?:json|formData)\(\)|Object\.fromEntries\()/g)) bodyVars.add(m[1]);
      for (const m of cleanContent.matchAll(/^\s*(\w+)\s*=\s*(?:await\s+)?request\.(?:json\(\)|get_json\([^)]*\)|form|POST|data|body\(\))\s*$/gm)) bodyVars.add(m[1]);
      if (/\(\s*(?:\w+\s*:\s*[^,)]+,\s*)?formData\s*:\s*FormData\b/.test(cleanContent)) bodyVars.add('formData');
      const varRe = bodyVars.size ? new RegExp(`(?:\\(|,|\\{|\\s)\\.{0,3}(?:${[...bodyVars].join('|')})\\b(?!\\s*(?:\\.|\\?\\.|\\[))`) : null;
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        if (claimed.has(i) || isCommentLine(l) || !LOG_SINK.test(l) || REDACTED.test(l)) continue;
        const args = l.slice(l.search(LOG_SINK));
        const rawBody = /\b(?:req|request|ctx\.request)\.body\b(?!\s*(?:\.|\?\.|\[|\())/.test(args) ||
          (isPy && /\brequest\.(?:json|data|POST|form|get_json\(\))(?!\s*(?:\.|\[|\(|\w))/.test(args));
        if (rawBody || (varRe && varRe.test(args.replace(LOG_SINK, '(')))) {
          hits.push({
            ruleId: 28401, code: 'PRIV-01', severity: 'HIGH', lineIdx: i, category: 'Sensitive Data Logging',
            title: 'Authentication Handler Logs the Raw Request Body (Plaintext Password)',
            why: 'This handler processes passwords, and the log call serializes the whole request body, so every user password is written in plaintext to stdout / the log provider (CWE-532, GDPR Art. 32).',
            fix: 'Remove the log line or log only non-sensitive fields (e.g. the email domain or user id). Never log request bodies of authentication endpoints.'
          });
          break;
        }
      }
    }
  }

  // PRIV-05: full request headers / cookies written to logs (Authorization bearer tokens, session cookies)
  if (isJs || isPy || isGo) {
    let lineIdx = -1;
    for (let i = 0; i < lines.length && lineIdx === -1; i++) {
      const l = lines[i];
      if (isCommentLine(l) || !LOG_SINK.test(l) || REDACTED.test(l)) continue;
      const args = l.slice(l.search(LOG_SINK));
      if (/\b(?:req|request|ctx|ctx\.request|event)\.(?:headers|cookies|COOKIES|META)\b(?!\s*(?:\.|\?\.|\[|\())/.test(args) ||
        /\b(?:headers|cookies)\(\)(?!\s*(?:\.get\b|\.has\b|\?\.get\b))(?:\.getAll\(\))?\s*[),}]/.test(args)) lineIdx = i;
    }
    if (lineIdx === -1 && isGo) {
      const dump = cleanContent.match(/\b(\w+)\s*,\s*\w+\s*:?=\s*httputil\.DumpRequest(?:Out)?\([^,]+,\s*true\s*\)/);
      if (dump) lineIdx = lines.findIndex((l) => /\b(?:log\.\w+|fmt\.Print\w*|logger\.\w+|slog\.\w+)\s*\(/.test(l) && new RegExp(`\\b${dump[1]}\\b`).test(l));
    }
    if (lineIdx !== -1) {
      hits.push({
        ruleId: 28405, code: 'PRIV-05', severity: 'MEDIUM', lineIdx, category: 'Sensitive Data Logging',
        title: 'Full Request Headers or Cookies Written to Logs',
        why: 'Logging the whole header / cookie set records Authorization bearer tokens and session cookies, so anyone with log access can replay a user session (CWE-532).',
        fix: 'Log only the specific non-secret headers you need (user-agent, request id), or use a logger with redact paths for authorization and cookie.'
      });
    }
  }

  // PRIV-02: credentials, government IDs or card data sent to analytics / error tracking vendors
  // PRIV-03: e-mail address used as the Google Analytics user_id
  if (isJs) {
    let sensitiveIdx = -1;
    let gaIdx = -1;
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (isCommentLine(l)) continue;
      const pos = l.search(ANALYTICS_SINK);
      if (pos === -1) continue;
      const { text } = callText(lines, i, pos);
      if (sensitiveIdx === -1 && SENSITIVE_KEY.test(text)) {
        const rel = lines.slice(i, i + 15).findIndex((x) => SENSITIVE_KEY.test(x));
        sensitiveIdx = i + Math.max(0, rel);
      }
      if (gaIdx === -1 && /^(?:gtag|(?:window\.)?dataLayer\.push)\b/.test(l.slice(pos)) && !/user_data|enhanced_conversion|sha256|hash/i.test(text) &&
        /\buser_?id['"]?\s*:\s*[\w.?!]*\bemail\b/i.test(text)) {
        const rel = lines.slice(i, i + 15).findIndex((x) => /\buser_?id['"]?\s*:/i.test(x));
        gaIdx = i + Math.max(0, rel);
      }
      if (gaIdx === -1 && /\bga\(\s*['"]set['"]\s*,\s*['"]userId['"]\s*,\s*[\w.?!]*\bemail\b/.test(l)) gaIdx = i;
    }
    for (let i = 0; i < lines.length && gaIdx === -1; i++) {
      if (/\bga\(\s*['"]set['"]\s*,\s*['"]userId['"]\s*,\s*[\w.?!]*\bemail\b/.test(lines[i]) && !isCommentLine(lines[i])) gaIdx = i;
    }
    if (sensitiveIdx !== -1) {
      hits.push({
        ruleId: 28402, code: 'PRIV-02', severity: 'HIGH', lineIdx: sensitiveIdx, category: 'Third-Party Data Sharing',
        title: 'Password, Government ID or Card Data Sent to an Analytics / Monitoring Vendor',
        why: 'The event or user properties sent to a third-party analytics / error-tracking SDK include a password, token, national ID or card field. The vendor stores it indefinitely and shows it to everyone with dashboard access (CWE-359, GDPR Art. 28/32).',
        fix: 'Remove the sensitive field from the tracked payload. Send only a stable internal user id and non-sensitive event properties.'
      });
    }
    if (gaIdx !== -1) {
      hits.push({
        ruleId: 28403, code: 'PRIV-03', severity: 'MEDIUM', lineIdx: gaIdx, category: 'Third-Party Data Sharing',
        title: 'E-mail Address Used as the Google Analytics User ID',
        why: 'Google Analytics terms forbid sending personally identifiable information; using the e-mail address as user_id ships it to Google on every hit and into every report and export.',
        fix: 'Use an opaque internal identifier (database uuid) as user_id. For Google Ads enhanced conversions use the user_data field, which gtag hashes.'
      });
    }
  }

  // PRIV-04: login / signup handler returns the user record including the password hash
  if (isJs) {
    const userVars = new Set<string>();
    const hashField = '(\\w+)\\??\\.(?:password|passwordHash|password_hash|hashedPassword|hashed_password)\\b';
    for (const m of cleanContent.matchAll(new RegExp(`\\b(?:bcrypt|bcryptjs)\\.(?:compare|compareSync)\\s*\\([^,)]+,\\s*${hashField}`, 'g'))) userVars.add(m[1]);
    for (const m of cleanContent.matchAll(new RegExp(`\\bargon2\\.verify\\s*\\(\\s*${hashField}`, 'g'))) userVars.add(m[1]);
    for (const m of cleanContent.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*await\s+(?:prisma|db|this\.prisma)\.user\.create\(/g)) {
      const at = cleanContent.indexOf(m[0]);
      const window = cleanContent.slice(at, at + 600);
      if (/\bpassword\w*\s*[:,]/i.test(window) && !/\b(?:select|omit)\s*:/.test(window)) userVars.add(m[1]);
    }
    if (userVars.size) {
      const names = [...userVars].filter((v) => !new RegExp(`delete\\s+${v}\\.password|${v}\\.password\\w*\\s*=\\s*(?:undefined|null)|\\{\\s*password\\w*(?:\\s*:\\s*\\w+)?\\s*,\\s*\\.\\.\\.\\w+\\s*\\}\\s*=\\s*${v}\\b|\\b(?:omit|exclude|sanitize\\w*|toPublic\\w*|serialize\\w*)\\(\\s*${v}\\b`, 'i').test(cleanContent));
      if (names.length) {
        const respRe = new RegExp(`(?:\\bres(?:\\.status\\(\\d+\\))?\\.(?:json|send)|NextResponse\\.json|Response\\.json|\\bc\\.json|reply(?:\\.code\\(\\d+\\))?\\.send|ctx\\.body\\s*=)\\s*\\(?[^;]*?(?:\\(|\\{|,|\\s|\\.\\.\\.)(?:${names.join('|')})\\b(?!\\s*(?:\\.|\\?\\.|\\[|:))`);
        const lineIdx = lines.findIndex((l) => !isCommentLine(l) && respRe.test(l));
        if (lineIdx !== -1) {
          hits.push({
            ruleId: 28404, code: 'PRIV-04', severity: 'HIGH', lineIdx, category: 'Excessive Data Exposure',
            title: 'Auth Handler Returns the User Record Including the Password Hash',
            why: 'The user object loaded for password verification (or just created with a hashed password) is serialized whole into the HTTP response, sending the password hash and every other column to the client (CWE-200, OWASP API3:2023).',
            fix: 'Return an explicit DTO ({ id, email, name }) or strip the hash first: const { password, ...safeUser } = user. With Prisma, use select / omit on the query.'
          });
        }
      }
    }
  }

  // PRIV-06 / PRIV-07: Django / DRF serializing the User model wholesale (password hash, is_superuser)
  if (isPy) {
    const classStarts = lines.map((l, i) => (/^class\s+\w+\s*\(/.test(l) ? i : -1)).filter((i) => i !== -1);
    for (const start of classStarts) {
      if (!/\((?:serializers\.)?(?:Hyperlinked)?ModelSerializer\)/.test(lines[start])) continue;
      const next = classStarts.find((i) => i > start) ?? lines.length;
      const block = lines.slice(start, next);
      if (!block.some((l) => /^\s+model\s*=\s*(?:User|get_user_model\(\)|CustomUser|AuthUser)\s*$/.test(l))) continue;
      const rel = block.findIndex((l) => /^\s+fields\s*=\s*['"]__all__['"]/.test(l));
      if (rel !== -1) {
        hits.push({
          ruleId: 28406, code: 'PRIV-06', severity: 'HIGH', lineIdx: start + rel, category: 'Excessive Data Exposure',
          title: "DRF Serializer Exposes Every User Field (fields = '__all__')",
          why: "A ModelSerializer over the User model with fields = '__all__' returns the password hash, is_staff / is_superuser and permission columns, and makes them writable on create/update (CWE-200 / CWE-915).",
          fix: "List the fields explicitly (fields = ['id', 'username', 'email']) and mark password as write_only in extra_kwargs."
        });
        break;
      }
    }

    const djangoUser = /django\.contrib\.auth|get_user_model|request\.user/.test(cleanContent);
    const responds = /JsonResponse|HttpResponse|\bResponse\(/.test(cleanContent);
    if (djangoUser && responds) {
      const lineIdx = lines.findIndex((l) => !isCommentLine(l) && (
        /\b(?:User|get_user_model\(\))\.objects\b[^\n#]*\.values(?:_list)?\(\s*\)/.test(l) ||
        (/serializers\.serialize\(\s*['"](?:json|xml|yaml|python)['"]\s*,\s*(?:User|get_user_model\(\))\.objects/.test(l) && !/\bfields\s*=/.test(l)) ||
        /\bmodel_to_dict\(\s*(?:request\.user|\w*user)\s*\)/.test(l)));
      if (lineIdx !== -1) {
        hits.push({
          ruleId: 28407, code: 'PRIV-07', severity: 'HIGH', lineIdx, category: 'Excessive Data Exposure',
          title: 'Django User Rows Serialized Without a Field List (Password Hash Exposed)',
          why: 'values() / serializers.serialize() / model_to_dict() without a field list includes every column of auth_user, so the response carries password hashes, is_superuser and last_login for each user (CWE-200).',
          fix: "Pass an explicit field list: User.objects.values('id', 'username', 'email'), serialize(..., fields=('username', 'email')), model_to_dict(user, fields=[...])."
        });
      }
    }
  }

  // PRIV-12: FastAPI route returns an ORM user object with no response_model (hashed_password serialized)
  if (isPy && /\bfrom\s+fastapi\b|\bAPIRouter\(|\bFastAPI\(/.test(cleanContent) && /\b(?:hashed_password|password_hash|hashed_pw|password_digest)\b/.test(cleanContent)) {
    const userName = '(?:current_user|user|db_user|new_user|created_user|existing_user|updated_user|user_obj|user_db|user_in_db)';
    const retRe = new RegExp(`^\\s*return\\s+(?:${userName}\\s*$|\\{[^}]*['"]\\w+['"]\\s*:\\s*${userName}\\s*[,}])`);
    for (let i = 0; i < lines.length; i++) {
      const dec = lines[i].match(/^(\s*)@\w+\.(?:get|post|put|patch|api_route)\(/);
      if (!dec) continue;
      const { text: decText, end: decEnd } = callText(lines, i, lines[i].indexOf('('));
      if (/response_model|response_class|include_in_schema\s*=\s*False/.test(decText)) continue;
      let d = decEnd + 1;
      while (d < lines.length && /^\s*@/.test(lines[d])) d++;
      if (d >= lines.length || !/^\s*(?:async\s+)?def\s+\w+/.test(lines[d])) continue;
      let sigEnd = d;
      let sig = lines[d];
      while (!/:\s*$/.test(lines[sigEnd]) && sigEnd < d + 15 && sigEnd + 1 < lines.length) { sigEnd++; sig += lines[sigEnd]; }
      if (/\)\s*->/.test(sig)) continue;
      const defIndent = (lines[d].match(/^\s*/) || [''])[0].length;
      for (let b = sigEnd + 1; b < lines.length; b++) {
        const l = lines[b];
        if (l.trim() && (l.match(/^\s*/) || [''])[0].length <= defIndent) break;
        if (retRe.test(l)) {
          hits.push({
            ruleId: 28412, code: 'PRIV-12', severity: 'HIGH', lineIdx: b, category: 'Excessive Data Exposure',
            title: 'FastAPI Route Returns the User ORM Object Without a response_model',
            why: 'Without response_model or a return annotation, FastAPI serializes the returned ORM object with jsonable_encoder, which includes every column, so hashed_password reaches the client (CWE-200, OWASP API3:2023).',
            fix: 'Declare a public schema and set response_model=UserPublic (or annotate the return type -> UserPublic) so only whitelisted fields are serialized.'
          });
          i = lines.length;
          break;
        }
      }
    }
  }

  // PRIV-08: Laravel User model that does not hide the password hash from JSON / Inertia serialization
  if (isPhp && /\bclass\s+User\s+extends\s+(?:Authenticatable|Model)\b/.test(cleanContent) && /['"]password['"]/.test(cleanContent)) {
    const hidden = /\$hidden\s*=\s*\[[^\]]*['"]password['"]/.test(cleanContent) || /#\[\s*Hidden\(\s*\[[^\]]*['"]password['"]/.test(cleanContent) ||
      /\$visible\s*=/.test(cleanContent) || /#\[\s*Visible\(/.test(cleanContent) || /function\s+(?:toArray|jsonSerialize)\s*\(/.test(cleanContent);
    if (!hidden) {
      let lineIdx = lines.findIndex((l) => /\$hidden\s*=/.test(l));
      if (lineIdx === -1) lineIdx = lines.findIndex((l) => /\bclass\s+User\s+extends\b/.test(l));
      hits.push({
        ruleId: 28408, code: 'PRIV-08', severity: 'HIGH', lineIdx, category: 'Excessive Data Exposure',
        title: 'Laravel User Model Does Not Hide the Password Hash',
        why: "The User model has a password attribute but 'password' is not in $hidden, so return $user, response()->json($user) and Inertia shared auth props serialize the bcrypt hash (and remember_token) to the browser.",
        fix: "Add protected $hidden = ['password', 'remember_token']; (or the #[Hidden] attribute) to the User model."
      });
    }
  }

  // PRIV-09: passwords or card data persisted in browser storage / readable cookies
  if (isJs) {
    const keyRe = /^(?:[\w-]*[_-])?(?:password|passwd|pwd|userPassword|savedPassword|rememberedPassword|ssn|card_?number|cardNumber|cvv|cvc|credit_?card(?:_?number)?|creditCard(?:Number)?)$/i;
    let lineIdx = -1;
    for (let i = 0; i < lines.length && lineIdx === -1; i++) {
      const l = lines[i];
      if (isCommentLine(l)) continue;
      const set = l.match(/\b(?:localStorage|sessionStorage)\.setItem\(\s*['"`]([^'"`]+)['"`]\s*,\s*([^)]*)/);
      if (set && keyRe.test(set[1]) && !/^\s*(?:true|false|['"`](?:true|false|1|0)['"`])\s*$/.test(set[2])) lineIdx = i;
      else if (/\b(?:localStorage|sessionStorage)\.setItem\([^,]+,\s*JSON\.stringify\(\s*\{[^}]*\b(?:password|cvv|cvc|cardNumber|card_number)\b\s*[:,}]/i.test(l)) lineIdx = i;
      else if (/\b(?:localStorage|sessionStorage)(?:\.(?:password|cardNumber|cvv)|\[\s*['"](?:password|cardNumber|card_number|cvv)['"]\s*\])\s*=[^=]/.test(l)) lineIdx = i;
      else if (/document\.cookie\s*=\s*[`'"][^`'"]*\b(?:password|passwd|cvv|card_?number)=/i.test(l)) lineIdx = i;
    }
    if (lineIdx !== -1) {
      hits.push({
        ruleId: 28409, code: 'PRIV-09', severity: 'HIGH', lineIdx, category: 'Insecure Client Storage',
        title: 'Password or Card Data Stored in Browser Storage',
        why: 'localStorage / sessionStorage / script-readable cookies are plaintext, persist on shared devices and are readable by any script on the origin, so one XSS or browser extension exfiltrates the stored password or card data (CWE-922 / CWE-312).',
        fix: 'Never persist passwords or card data client-side. Keep the session in an HttpOnly cookie, let the browser password manager handle "remember me", and tokenize cards with the payment provider.'
      });
    }
  }

  // PRIV-10: database dump uploaded with a public ACL
  if (/\b(?:pg_dump|pg_dumpall|mysqldump|mariadb-dump|mongodump)\b/.test(cleanContent)) {
    const publicRe = /--acl[\s=]+['"]?public-read|\bACL['"]?\s*[:=]\s*['"]public-read|\bacl\s*=\s*['"]public-read|\bAllUsers:R\b|\ballUsers:(?:objectViewer|R)\b|\bmake_public\(\)|--public-access\s+(?:blob|container)|predefinedAcl['"]?\s*[:=]\s*['"]publicRead/;
    const lineIdx = lines.findIndex((l) => !isCommentLine(l) && publicRe.test(l));
    if (lineIdx !== -1) {
      hits.push({
        ruleId: 28410, code: 'PRIV-10', severity: 'HIGH', lineIdx, category: 'Data Breach Exposure',
        title: 'Database Dump Uploaded With a Public ACL',
        why: 'This script dumps the database and uploads the result world-readable. Anyone who learns or guesses the object URL downloads every user record; exposed backups are one of the most common causes of reportable breaches (GDPR Art. 33).',
        fix: 'Upload backups to a private bucket (no public ACL, Block Public Access on), encrypt them (SSE-KMS or gpg before upload) and share only via short-lived signed URLs.'
      });
    }
  }

  // PRIV-11: Supabase storage bucket for identity / medical / financial documents made public
  {
    const sensitiveName = /(?:^|[-_./])(?:kyc|identity|identities|passports?|selfies?|medical|health|patients?|prescriptions?|invoices?|receipts?|payslips?|paystubs?|tax|taxes|contracts?|private|confidential|resumes?|cvs?|verifications?|id)(?:$|[-_./])/i;
    let lineIdx = -1;
    if (isJs) {
      for (let i = 0; i < lines.length && lineIdx === -1; i++) {
        const m = lines[i].match(/\.(?:createBucket|updateBucket)\(\s*['"`]([^'"`]+)['"`]/);
        if (!m || isCommentLine(lines[i]) || !sensitiveName.test(m[1])) continue;
        const { text } = callText(lines, i, lines[i].indexOf(m[0]) + m[0].indexOf('('));
        if (/\bpublic\s*:\s*true\b/.test(text)) lineIdx = i;
      }
    }
    if (lineIdx === -1 && /\.sql$/i.test(path)) {
      for (let i = 0; i < lines.length && lineIdx === -1; i++) {
        const l = lines[i];
        const ins = l.match(/insert\s+into\s+storage\.buckets\s*\(([^)]*)\)\s*values\s*\(([^)]*)\)/i);
        if (ins) {
          const cols = ins[1].split(',').map((c) => c.trim().toLowerCase());
          const vals = ins[2].split(',').map((v) => v.trim().toLowerCase());
          const p = cols.indexOf('public');
          const nameIdx = cols.indexOf('id') !== -1 ? cols.indexOf('id') : cols.indexOf('name');
          if (p !== -1 && vals[p] === 'true' && nameIdx !== -1 && sensitiveName.test((vals[nameIdx] || '').replace(/'/g, ''))) lineIdx = i;
        }
        const upd = l.match(/update\s+storage\.buckets\s+set\s+public\s*=\s*true\s+where\s+(?:id|name)\s*=\s*'([^']+)'/i);
        if (upd && sensitiveName.test(upd[1])) lineIdx = i;
      }
    }
    if (lineIdx !== -1) {
      hits.push({
        ruleId: 28411, code: 'PRIV-11', severity: 'HIGH', lineIdx, category: 'Data Breach Exposure',
        title: 'Storage Bucket for Identity, Medical or Financial Documents Is Public',
        why: 'A public Supabase bucket serves every object without authentication or RLS; ID scans, invoices or medical files in it are readable by anyone holding (or enumerating) the URL. These are special-category / high-risk personal data under GDPR Art. 9 and KVKK Art. 6.',
        fix: 'Make the bucket private (public: false), add storage.objects RLS policies scoped to the owner (auth.uid()), and serve files through createSignedUrl with a short expiry.'
      });
    }
  }

  // PRIV-14: Sentry session replay with text masking disabled and no replacement mask
  if (isJs) {
    for (let i = 0; i < lines.length; i++) {
      const pos = lines[i].search(/\b(?:replayIntegration|Sentry\.Replay|new\s+Replay)\s*\(/);
      if (pos === -1 || isCommentLine(lines[i])) continue;
      const { text } = callText(lines, i, pos);
      if (/\bmaskAllText\s*:\s*false\b/.test(text) && !/\b(?:mask|maskFn|block)\s*:/.test(text)) {
        const rel = lines.slice(i, i + 15).findIndex((x) => /\bmaskAllText\s*:\s*false/.test(x));
        hits.push({
          ruleId: 28414, code: 'PRIV-14', severity: 'MEDIUM', lineIdx: i + Math.max(0, rel), category: 'Third-Party Data Sharing',
          title: 'Session Replay Records Unmasked Page Text',
          why: 'With maskAllText: false and no mask selectors, Sentry Replay uploads the rendered text of every page (names, e-mails, addresses, account data) to the vendor for every recorded session.',
          fix: "Keep maskAllText: true (the default) and unmask only known-safe elements with unmask: ['.public-copy'], or add mask selectors for every element that renders personal data."
        });
        break;
      }
    }
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `priv${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
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
    logs.push(`[${ts}] [PRIVACY] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
