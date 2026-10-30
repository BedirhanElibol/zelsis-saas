/**
 * Privacy leaks and database correctness / performance defects from the Gemini rule report that no existing rule
 * caught (PRV-01.., DBG-01.., Rule IDs 29974-29999). Privacy findings are SECURITY; database findings are reliability
 * (VIBECARE) because they break or slow the app rather than expose data. Each keys on a statement that is wrong
 * wherever it appears: SET NULL on a NOT NULL column, NOT IN over a subquery, self-updating triggers, KEYS * in Redis,
 * counting rows by loading them, reset tokens stored as issued, user lists in the To: header and similar.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; type: Finding['type']; category: string; lineIdx: number; why: string; fix: string }
type Add = (h: Hit) => void;

const SKIP = /\.d\.ts$|(?:^|\/)node_modules\/|(?:^|\/)vendor\/|(?:^|\/)(?:tests?|__tests__|e2e|__mocks__|fixtures?|testdata|seeds?)\/|\.(?:test|spec)\.[jt]sx?$|_test\.(?:go|py)$/i;
const lineAt = (c: string, off: number) => { let n = 0; for (let i = 0; i < off && i < c.length; i++) if (c.charCodeAt(i) === 10) n++; return n; };
const PII_KEY = /\b(email|e_mail|phone|phoneNumber|phone_number|fullName|full_name|firstName|lastName|address|dateOfBirth|dob|ssn|tckn|nationalId)\s*:/;

function code(path: string, c: string, add: Add) {
  const at = (off: number) => lineAt(c, off);

  // PRV-01: raw PII in analytics event properties
  for (const m of c.matchAll(/\b(posthog|mixpanel|amplitude|analytics|segment|gtag|fbq|plausible|umami)\.?(capture|track|logEvent|event)?\(\s*(?:['"`][^'"`]*['"`]\s*,\s*)?(?:['"`][^'"`]*['"`]\s*,\s*)?\{/g)) {
    if (m[1] !== 'gtag' && m[1] !== 'fbq' && !m[2]) continue;
    const end = c.indexOf('}', m.index! + m[0].length);
    const props = c.slice(m.index! + m[0].length - 1, end + 1);
    const k = PII_KEY.exec(props);
    if (!k || /sha256|hash|digest/i.test(props)) continue;
    add({ ruleId: 29974, code: 'PRV-01', severity: 'MEDIUM', type: 'SECURITY', category: 'Privacy', lineIdx: at(m.index! + m[0].length - 1 + k.index),
      title: `Raw ${k[1]} Sent in an Analytics Event`,
      why: `${k[1]} is attached to an event, so it is copied to the analytics vendor, stored with every event and visible to everyone with dashboard access; Google Analytics forbids PII outright and GDPR requires a legal basis and DPA.`,
      fix: 'Send a stable internal user id (or a salted hash) instead, and set personal traits only through identify() on a vendor you have a DPA with.' });
  }

  // PRV-02: national ID or health data placed in a URL
  for (const m of c.matchAll(/[?&](tckn|ssn|nationalId|national_id|taxId|tax_id|diagnosis|mrn|patientName|patient_name|prescription|iban)=\$\{/gi)) {
    add({ ruleId: 29975, code: 'PRV-02', severity: 'HIGH', type: 'SECURITY', category: 'Privacy', lineIdx: at(m.index!),
      title: `${m[1]} Sent in a URL Query String`,
      why: 'URLs are written to server, CDN and proxy logs, browser history and Referer headers sent to third parties, so this regulated identifier leaks far beyond the request.',
      fix: `Send ${m[1]} in a POST body (or look it up server-side from an opaque id) and never log it.` });
  }

  // PRV-03: one email with every recipient in To / Cc
  for (const m of c.matchAll(/\b(to|cc)\s*:\s*(?:[\w.]+\.map\(\s*\(?\s*\w+\s*\)?\s*=>\s*\w+\.email\s*\)|[\w.]*(?:emails|recipients|subscribers|members|users)(?:\.join\([^)]*\))?)\s*[,}]/g)) {
    if (!/\b(?:sendMail|emails\.send|send\(|sgMail|mailgun|postmark|sendEmail|transporter)\b/.test(c)) continue;
    add({ ruleId: 29976, code: 'PRV-03', severity: 'HIGH', type: 'SECURITY', category: 'Privacy', lineIdx: at(m.index!),
      title: `Every Recipient Put in the ${m[1] === 'to' ? 'To' : 'Cc'} Header`,
      why: 'All addresses are visible to every recipient, so one email discloses your whole customer or member list (a reportable personal-data breach under GDPR).',
      fix: 'Send one email per recipient (or use the provider batch API), or put the list in bcc with a neutral To address.' });
  }

  // PRV-04: refresh token persisted in localStorage
  for (const m of c.matchAll(/\b(?:localStorage|sessionStorage)\.setItem\(\s*['"`]([\w-]*refresh[\w-]*token[\w-]*)['"`]/gi)) {
    add({ ruleId: 29977, code: 'PRV-04', severity: 'HIGH', type: 'SECURITY', category: 'Session Management', lineIdx: at(m.index!),
      title: `Refresh Token Stored in Web Storage (${m[1]})`,
      why: 'Any script on the page (an XSS, a compromised npm package, a browser extension) can read web storage, and a refresh token lets the attacker mint new sessions for weeks.',
      fix: 'Keep the refresh token in an httpOnly, secure, SameSite cookie set by the server and rotate it on use.' });
  }

  // PRV-05: password-reset / verification token stored exactly as issued
  if (!/createHash\(|\bhash(?:Token|Secret)?\(|bcrypt|argon2|scrypt|sha256/i.test(c)) {
    const gen = new Set([...c.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*(?:await\s+)?(?:crypto\.)?(?:randomBytes\([^)]*\)\.toString\([^)]*\)|randomUUID\(\)|nanoid\([^)]*\)|createId\(\)|uuidv4\(\))/g)].map((m) => m[1]));
    for (const n of gen) {
      for (const m of c.matchAll(new RegExp(`\\b(\\w*(?:reset|verification|verify|magic|invite|recovery|confirm)\\w*(?:Token|_token|Code|_code))\\s*:\\s*${n}\\b`, 'gi'))) {
        add({ ruleId: 29978, code: 'PRV-05', severity: 'HIGH', type: 'SECURITY', category: 'Authentication', lineIdx: at(m.index!),
          title: `${m[1]} Saved in Plain Text`,
          why: `The database holds the same ${m[1]} that is emailed, so anyone who reads the table (backup, SQL injection, support tool, leaked dump) can reset passwords or confirm accounts for any user.`,
          fix: `Store only a hash: ${m[1]}: createHash('sha256').update(${n}).digest('hex'), and compare hashes when the link is used (with an expiry).` });
      }
    }
  }

  // DBG-07: Redis KEYS with a pattern in application code
  if (/\b(?:redis|ioredis|upstash|createClient|Redis)\b/.test(c)) {
    for (const m of c.matchAll(/\b(\w*(?:redis|client|cache|kv)\w*)\.keys\(\s*['"`][^'"`]*\*/gi)) {
      add({ ruleId: 29986, code: 'DBG-07', severity: 'HIGH', type: 'VIBECARE', category: 'Database Performance', lineIdx: at(m.index!),
        title: 'Redis KEYS Pattern Scan in Application Code',
        why: 'KEYS walks the entire keyspace in one blocking call; with production data it freezes Redis for every other request (sessions, rate limits, queues) until it finishes.',
        fix: 'Use SCAN with MATCH and COUNT (scanStream / scanIterator), or keep the ids you need in a set.' });
    }
  }

  // DBG-08: counting rows by loading them
  for (const m of c.matchAll(/\(\s*await\s+[\w.]+\.(findMany|findAll|find)\(\s*(?:\{[^{}]*\})?\s*\)\s*\)\.length\b/g)) {
    add({ ruleId: 29987, code: 'DBG-08', severity: 'HIGH', type: 'VIBECARE', category: 'Database Performance', lineIdx: at(m.index!),
      title: `Row Count Computed by Loading Every Row (${m[1]}().length)`,
      why: 'Every matching row is transferred and turned into objects just to count them; as the table grows this becomes slow, memory-heavy and eventually times out.',
      fix: 'Use the database count: prisma.model.count({ where }) / db.select({ n: count() }) / Model.countDocuments().' });
  }

  // DBG-09: whole table loaded, then filtered in JavaScript
  for (const m of c.matchAll(/\(\s*await\s+[\w.]+\.findMany\(\s*\)\s*\)\.filter\(/g)) {
    add({ ruleId: 29988, code: 'DBG-09', severity: 'MEDIUM', type: 'VIBECARE', category: 'Database Performance', lineIdx: at(m.index!),
      title: 'Entire Table Loaded, Then Filtered in JavaScript',
      why: 'findMany() without where returns every row; the filter runs after the transfer, so the request gets slower with every new row and can exhaust memory.',
      fix: 'Move the condition into the query: findMany({ where: { … } }).' });
  }
  void path;
}

/** Text between $$ … $$ (function bodies) with their offsets. */
function dollarBodies(sql: string): { s: number; e: number }[] {
  const out: { s: number; e: number }[] = [];
  const re = /\$(\w*)\$/g; let open: { tag: string; at: number } | null = null; let m: RegExpExecArray | null;
  while ((m = re.exec(sql))) {
    if (!open) open = { tag: m[1], at: m.index + m[0].length };
    else if (m[1] === open.tag) { out.push({ s: open.at, e: m.index }); open = null; }
  }
  return out;
}

function sql(src: string, add: Add) {
  const at = (off: number) => lineAt(src, off);
  const bodies = dollarBodies(src);
  const inBody = (off: number) => bodies.some((b) => off >= b.s && off < b.e);

  // DBG-01: ON DELETE SET NULL on a NOT NULL column
  for (const m of src.matchAll(/^\s*"?(\w+)"?\s+[\w ()]+?\bNOT\s+NULL\b[^,\n]*\bREFERENCES\b[^,\n]*\bON\s+DELETE\s+SET\s+NULL\b/gim)) {
    add({ ruleId: 29980, code: 'DBG-01', severity: 'HIGH', type: 'VIBECARE', category: 'Database Integrity', lineIdx: at(m.index!),
      title: `ON DELETE SET NULL on NOT NULL Column ${m[1]}`,
      why: `Deleting the parent tries to set ${m[1]} to NULL, which the NOT NULL constraint rejects, so the parent row can never be deleted (account deletion and cleanup jobs fail with a constraint error).`,
      fix: `Pick one: make ${m[1]} nullable, or use ON DELETE CASCADE / RESTRICT.` });
  }

  // DBG-02: NOT IN over a subquery
  for (const m of src.matchAll(/\bNOT\s+IN\s*\(\s*SELECT\b/gi)) {
    add({ ruleId: 29981, code: 'DBG-02', severity: 'MEDIUM', type: 'VIBECARE', category: 'Database Integrity', lineIdx: at(m.index!),
      title: 'NOT IN (SELECT …) Returns No Rows When the Subquery Has a NULL',
      why: 'If the subquery yields a single NULL, x NOT IN (…) is NULL for every row, so the query silently returns nothing; it also plans poorly on large tables.',
      fix: 'Use NOT EXISTS (SELECT 1 FROM … WHERE … = outer.id) or a LEFT JOIN … WHERE right.id IS NULL.' });
  }

  // DBG-03: UPDATE trigger whose function updates the same table (infinite recursion)
  for (const t of src.matchAll(/\bCREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\s+\w+\s+(?:BEFORE|AFTER)\s+[\w\s]*\bUPDATE\b[\w\s,]*\bON\s+(?:public\.)?"?(\w+)"?[\s\S]*?\bEXECUTE\s+(?:FUNCTION|PROCEDURE)\s+(?:public\.)?"?(\w+)"?\s*\(/gi)) {
    const table = t[1]; const fn = t[2];
    const def = new RegExp(`\\bCREATE\\s+(?:OR\\s+REPLACE\\s+)?FUNCTION\\s+(?:public\\.)?"?${fn}"?\\s*\\(`, 'i').exec(src);
    if (!def) continue;
    const body = bodies.find((b) => b.s > def.index);
    if (!body) continue;
    const text = src.slice(body.s, body.e);
    if (!new RegExp(`\\bUPDATE\\s+(?:public\\.)?"?${table}"?\\b`, 'i').test(text) || /pg_trigger_depth\(\)/i.test(text) || /\bWHEN\s*\(/i.test(t[0])) continue;
    add({ ruleId: 29982, code: 'DBG-03', severity: 'HIGH', type: 'VIBECARE', category: 'Database Integrity', lineIdx: at(t.index!),
      title: `Trigger on ${table} Updates ${table} Again (Infinite Recursion)`,
      why: `${fn}() runs UPDATE ${table}, which fires the same trigger again, until Postgres aborts with "stack depth limit exceeded": every update to ${table} fails.`,
      fix: `Use a BEFORE UPDATE trigger that sets NEW.column instead of running UPDATE, or guard with IF pg_trigger_depth() > 1 THEN RETURN NEW; END IF.` });
  }

  // DBG-04: blocking REFRESH MATERIALIZED VIEW inside a function / scheduled job
  for (const m of src.matchAll(/\bREFRESH\s+MATERIALIZED\s+VIEW\s+(?!CONCURRENTLY)/gi)) {
    if (!inBody(m.index!) && !/cron\.schedule/i.test(src)) continue;
    add({ ruleId: 29983, code: 'DBG-04', severity: 'MEDIUM', type: 'VIBECARE', category: 'Database Performance', lineIdx: at(m.index!),
      title: 'REFRESH MATERIALIZED VIEW Without CONCURRENTLY',
      why: 'A plain refresh takes an exclusive lock, so every query reading the view waits until the refresh finishes: dashboards hang each time the job runs.',
      fix: 'Add a UNIQUE index on the view and use REFRESH MATERIALIZED VIEW CONCURRENTLY.' });
  }

  // DBG-05: pg_notify with the whole row as payload
  for (const m of src.matchAll(/\bpg_notify\s*\([^;]*?row_to_json\s*\(\s*(?:NEW|OLD)\s*\)/gi)) {
    add({ ruleId: 29984, code: 'DBG-05', severity: 'MEDIUM', type: 'VIBECARE', category: 'Database Integrity', lineIdx: at(m.index!),
      title: 'pg_notify Sends the Whole Row as Payload',
      why: 'NOTIFY payloads are limited to 8000 bytes; as soon as a row has a long text or JSON column the trigger raises "payload string too long" and the INSERT / UPDATE itself fails.',
      fix: "Send only the id (pg_notify('channel', NEW.id::text)) and let the listener fetch the row." });
  }

  // DBG-06: 32-bit serial key on an append-heavy table
  for (const m of src.matchAll(/\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?"?(\w+)"?\s*\(\s*"?id"?\s+(SERIAL|INT|INTEGER|INT4)\b/gi)) {
    // The append-heavy noun must be the whole name, a snake_case segment or a CamelCase suffix (not "course_reviews")
    if (!/(?:^|_)(?:events?|logs?|messages?|clicks?|page_?views?|impressions|audit(?:_\w+)?|notifications?|analytics|metrics|pings)$/i.test(m[1])
      && !/[a-z](?:Events?|Logs?|Messages?|Clicks?|PageViews?|Impressions|Notifications?|Metrics)$/.test(m[1])) continue;
    add({ ruleId: 29985, code: 'DBG-06', severity: 'MEDIUM', type: 'VIBECARE', category: 'Database Integrity', lineIdx: at(m.index!),
      title: `${m[1]}.id Is a 32-bit ${m[2].toUpperCase()}`,
      why: `${m[1]} grows with every user action; at about 2.1 billion rows INSERTs start failing with "integer out of range" and converting the key later locks and rewrites the table.`,
      fix: 'Use bigint GENERATED ALWAYS AS IDENTITY (or uuid) for the primary key.' });
  }

  // PRV-06: postgres_fdw user mapping with a password in the migration
  for (const m of src.matchAll(/\bCREATE\s+USER\s+MAPPING\b[^;]*\bpassword\s+'([^']+)'/gi)) {
    if (/^\$|^\{\{|current_setting/.test(m[1])) continue;
    add({ ruleId: 29979, code: 'PRV-06', severity: 'HIGH', type: 'SECURITY', category: 'Secrets Management', lineIdx: at(m.index!),
      title: 'Foreign Server Password Committed in a Migration',
      why: 'The remote database password is in the repository and readable in pg_user_mappings by the mapping owner; anyone with repo access can connect to the remote server directly.',
      fix: 'Create the user mapping outside version control (or from a secret at deploy time) and rotate this password.' });
  }
}

export function evaluatePrivacyDbGeminiRules(file: CodeFile, _lines: string[], cleanContent: string, findingCounter: {
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
  if (/\.[cm]?[jt]sx?$/i.test(path)) code(path, c, add);
  else if (/\.sql$/i.test(path)) sql(c, add);
  else return { findings, logs };

  const raw = file.content.split('\n');
  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `pdb${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: h.type,
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[h.lineIdx] || '').trim().slice(0, 300),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: h.type === 'SECURITY' ? 'Security Architect' : 'Engineering',
      falsePositive: false
    });
    logs.push(`[${ts}] [PRIV/DB] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
