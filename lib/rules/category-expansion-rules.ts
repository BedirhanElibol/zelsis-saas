/**
 * One group of provable mistakes per content category (CAT-01..14, Rule IDs 30501-30514; CAT-08..14 are listed after CAT-07). Each pattern fails or leaks
 * on its own, from a single file, so none of them needs repo context:
 *   database      CAT-01 ADD COLUMN ... NOT NULL with no default, CAT-02 RENAME COLUMN / TABLE on a live app
 *   security      CAT-03 Supabase auth.getSession() trusted on the server
 *   performance   CAT-04 a timer under one second that calls the network
 *   payments      CAT-05 a subscription webhook that grants access but never revokes it
 *   privacy       CAT-06 an analytics identify() keyed on an email address
 *   accessibility CAT-07 aria-hidden on something a keyboard can still reach
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner/types';
import { SKIP, lineAt, closeOf } from './logic-gemini-rules';

interface Hit {
  ruleId: number; code: string; title: string; severity: Finding['severity']; type: Finding['type']; category: string;
  lineIdx: number; why: string; fix: string;
}

const bare = (t: string) => t.replace(/"/g, '').split('.').pop()!.toLowerCase();
const stripSqlComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' ')).replace(/--[^\n]*/g, (m) => ' '.repeat(m.length));

export function evaluateCategoryExpansionRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  const c = cleanContent;
  if (!c || c.length > 400_000 || SKIP.test(path)) return { findings, logs };
  const hits: Hit[] = [];
  const isJs = /\.[cm]?[jt]sx?$/i.test(path);
  const isSql = /\.sql$/i.test(path);

  if (isSql) {
    const sql = stripSqlComments(file.content || c);
    // CAT-01: a NOT NULL column with no default cannot be added to a table that already has rows
    // A table this file creates is empty, so anything added to it is safe: those names are skipped
    const created = new Set([...sql.matchAll(/\bCREATE\s+(?:UNLOGGED\s+|TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w."]+)/gi)].map((t) => bare(t[1])));
    // ... and so is one this file empties first (DELETE with no WHERE, TRUNCATE)
    const emptied = new Set([...sql.matchAll(/\bDELETE\s+FROM\s+([\w."]+)\s*;|\bTRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?([\w."]+)/gi)].map((t) => bare(t[1] ?? t[2])));
    for (const m of sql.matchAll(/\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([\w."]+)\s+ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(?!(?:CONSTRAINT|CHECK|PRIMARY|UNIQUE|FOREIGN|EXCLUDE)\b)"?\w+"?\s+[^;,]*?\bNOT\s+NULL\b[^;,]*/gi)) {
      if (/\bDEFAULT\b|\bGENERATED\b|\bSERIAL\b|\bIDENTITY\b|\bPRIMARY\s+KEY\b/i.test(m[0]) || created.has(bare(m[1])) || emptied.has(bare(m[1]))) continue;
      hits.push({
        ruleId: 30501, code: 'CAT-01', title: 'NOT NULL Column Added With No Default', severity: 'MEDIUM', type: 'INFRA_DATABASE', category: 'Database Migrations',
        lineIdx: lineAt(sql, m.index!),
        why: 'Postgres rejects ADD COLUMN ... NOT NULL without a default when the table has any rows ("column contains null values"), so the migration fails on production data and the deploy stops halfway.',
        fix: 'Add the column as nullable (or with a DEFAULT), backfill it in batches, then SET NOT NULL in a later migration (use a CHECK (col IS NOT NULL) NOT VALID plus VALIDATE to avoid a long lock).',
      });
    }
    // CAT-02: renaming a column or table breaks the old version of the app that is still running during the deploy
    for (const m of sql.matchAll(/\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([\w."]+)\s+RENAME\s+(?:COLUMN\s+"?\w+"?\s+TO\b|TO\b)/gi)) {
      // RENAME CONSTRAINT and index renames are not matched; a table this file creates has no running reader yet
      if (created.has(bare(m[1]))) continue;
      hits.push({
        ruleId: 30502, code: 'CAT-02', title: 'Column or Table Renamed in Place', severity: 'MEDIUM', type: 'INFRA_DATABASE', category: 'Database Migrations',
        lineIdx: lineAt(sql, m.index!),
        why: 'During a rolling deploy the previous version of the app is still running and still queries the old name, so every request that touches it fails until the new version is everywhere (and a rollback fails the other way round).',
        fix: 'Expand and contract: add the new column, write to both, backfill, switch reads, and drop the old one in a later release. If the table is idle, say so in the migration and ship it in a maintenance window.',
      });
    }
  }

  if (isSql) {
    const sql = stripSqlComments(file.content || c);
    const created = new Set([...sql.matchAll(/\bCREATE\s+(?:UNLOGGED\s+|TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w."]+)/gi)].map((t) => bare(t[1])));
    const emptied = new Set([...sql.matchAll(/\bDELETE\s+FROM\s+([\w."]+)\s*;|\bTRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?([\w."]+)/gi)].map((t) => bare(t[1] ?? t[2])));
    const fresh = (t: string) => created.has(bare(t)) || emptied.has(bare(t));
    // CAT-08: most column type changes rewrite the whole table while holding an ACCESS EXCLUSIVE lock
    for (const m of sql.matchAll(/\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([\w."]+)\s+ALTER\s+(?:COLUMN\s+)?"?\w+"?\s+(?:SET\s+DATA\s+)?TYPE\s+([^;,\n]+)/gi)) {
      // text and an unlimited varchar are the usual cheap widenings
      if (fresh(m[1]) || /^\s*(?:text|varchar|character\s+varying)\s*(?:USING|$)/i.test(m[2])) continue;
      hits.push({
        ruleId: 30508, code: 'CAT-08', title: 'Column Type Changed in Place', severity: 'MEDIUM', type: 'INFRA_DATABASE', category: 'Database Migrations',
        lineIdx: lineAt(sql, m.index!),
        why: 'Unless the new type is binary-coercible, Postgres rewrites every row while holding an ACCESS EXCLUSIVE lock, so reads and writes on the table wait for as long as the rewrite takes. On a large table that is a visible outage.',
        fix: 'Add a new column of the target type, backfill it in batches, switch the code over and drop the old one. Run a plain in-place change only on a table that is small or idle, and say so in the migration.',
      });
    }
    // CAT-09: a volatile default makes ADD COLUMN rewrite the table (a constant default does not)
    for (const m of sql.matchAll(/\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([\w."]+)\s+ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(?!(?:CONSTRAINT|CHECK|PRIMARY|UNIQUE|FOREIGN|EXCLUDE)\b)"?\w+"?\s+[^;,]*?\bDEFAULT\s+(?:gen_random_uuid\s*\(|uuid_generate_v[14]\s*\(|random\s*\(|clock_timestamp\s*\(|nextval\s*\()/gi)) {
      if (fresh(m[1])) continue;
      hits.push({
        ruleId: 30509, code: 'CAT-09', title: 'Column Added With a Volatile Default', severity: 'MEDIUM', type: 'INFRA_DATABASE', category: 'Database Migrations',
        lineIdx: lineAt(sql, m.index!),
        why: 'A default that changes per row (gen_random_uuid(), random(), nextval()) cannot be stored once, so Postgres rewrites the whole table under an ACCESS EXCLUSIVE lock. A constant default or now() is applied without a rewrite.',
        fix: 'Add the column nullable with no default, set the default for new rows (ALTER COLUMN ... SET DEFAULT gen_random_uuid()), backfill existing rows in batches, then add NOT NULL.',
      });
    }
    // CAT-10: an UPDATE with no WHERE in a migration touches every row in one transaction
    for (const m of sql.matchAll(/(?:^|;)\s*(UPDATE\s+(?:ONLY\s+)?([\w."]+)\s+SET\b[^;]*)/gi)) {
      if (/\bWHERE\b/i.test(m[1]) || fresh(m[2]) || /\bFROM\b/i.test(m[1])) continue;
      hits.push({
        ruleId: 30510, code: 'CAT-10', title: 'UPDATE Without WHERE in a Migration', severity: 'LOW', type: 'INFRA_DATABASE', category: 'Database Migrations',
        lineIdx: lineAt(sql, m.index! + m[0].indexOf(m[1])),
        why: 'The statement rewrites every row in one transaction: row locks held for the whole run, a table-sized burst of dead rows and WAL, and a long wait for anything that writes to the table at the same time.',
        fix: 'Backfill in batches (WHERE id BETWEEN ... or a loop of LIMIT 5000), commit between batches, and run it outside the deploy when the table is large.',
      });
    }
  }

  if (isJs) {
    // CAT-03: getSession() reads the session from the cookie without asking Supabase Auth to verify it
    const serverFile = /(?:^|\/)(?:route|middleware|actions?)\.[cm]?[jt]sx?$/i.test(path) || /^\s*['"]use server['"]/m.test(c) || /\bcreateServerClient\s*\(/.test(c);
    if (serverFile && !/^\s*['"]use client['"]/m.test(c) && /\.auth\s*\.\s*getSession\s*\(\s*\)/.test(c) && !/\.auth\s*\.\s*(?:getUser|getClaims)\s*\(/.test(c)) {
      for (const m of c.matchAll(/\.auth\s*\.\s*getSession\s*\(\s*\)/g)) {
        // only when the session's user (or its id) is then used as the caller's identity
        const after = c.slice(m.index!, m.index! + 600);
        if (!/\bsession\b[\s\S]{0,200}\buser\b|\bsession\s*\??\.\s*user\b|\buser\s*[:=][^;]{0,40}\bsession\b/.test(after)) continue;
        hits.push({
          ruleId: 30503, code: 'CAT-03', title: 'Supabase getSession() Trusted on the Server', severity: 'MEDIUM', type: 'SECURITY', category: 'Authentication',
          lineIdx: lineAt(c, m.index!),
          why: 'On the server getSession() returns whatever the cookie holds without checking it with Supabase Auth, so a forged or expired cookie can pass as a signed-in user. Supabase documents getUser() (or getClaims()) for anything that authorises a request.',
          fix: 'Call supabase.auth.getUser() on the server and use the user it returns; keep getSession() for client code that only needs the token.',
        });
        break;
      }
    }

    // CAT-04: a timer under one second that calls the network hammers the API from every open tab
    for (const m of c.matchAll(/\bsetInterval\s*\(/g)) {
      const end = closeOf(c, m.index! + m[0].length - 1);
      if (end < 0) continue;
      const call = c.slice(m.index!, end);
      const ms = /,\s*(\d{2,4})\s*\)\s*$/.exec(call);
      if (!ms || Number(ms[1]) >= 1000 || Number(ms[1]) < 50) continue;
      if (!/\b(?:fetch|axios(?:\.\w+)?|\$fetch|supabase\s*\.\s*(?:from|rpc))\s*\(/.test(call)) continue;
      hits.push({
        ruleId: 30504, code: 'CAT-04', title: `Network Call Polled Every ${ms[1]} ms`, severity: 'MEDIUM', type: 'VIBECARE', category: 'Performance',
        lineIdx: lineAt(c, m.index!),
        why: 'Each open tab sends several requests a second to your API and database for as long as it stays open. A few hundred visitors turn into thousands of requests a second, and mobile users pay in battery and data.',
        fix: 'Poll every 5 to 30 seconds with backoff, pause while the tab is hidden (document.visibilityState), or push updates with WebSockets / Supabase Realtime / Server-Sent Events.',
      });
    }

    // CAT-05: a Stripe webhook that grants access on payment but never revokes it when the subscription ends
    if (/\bconstructEvent(?:Async)?\s*\(/.test(c) && /subscription/i.test(c)) {
      const types = [...c.matchAll(/(?:\bcase\s+|\.type\s*===?\s*|\btype\s*===?\s*)['"]([a-z_]+(?:\.[a-z_]+)+)['"]/g)];
      const grants = types.find((t) => /^(?:checkout\.session\.completed|customer\.subscription\.created|invoice\.(?:paid|payment_succeeded))$/.test(t[1]));
      const ends = types.some((t) => /^customer\.subscription\.(?:deleted|updated)$|^invoice\.payment_failed$/.test(t[1]));
      if (grants && !ends) {
        hits.push({
          ruleId: 30505, code: 'CAT-05', title: 'Subscription Webhook Never Handles Cancellation or Failed Payment', severity: 'MEDIUM', type: 'VIBECARE', category: 'Payments',
          lineIdx: lineAt(c, grants.index!),
          why: 'The handler turns access on when a payment succeeds but no event in this file turns it off. A customer who cancels, or whose card keeps failing, stays a paying-tier user forever, and you only find out from the revenue report.',
          fix: 'Handle customer.subscription.deleted, customer.subscription.updated (status past_due / canceled / unpaid) and invoice.payment_failed: revoke or downgrade access, and email the customer.',
        });
      }
    }

    // CAT-06: an email address as the analytics identity sends it to a third party
    for (const m of c.matchAll(/\b(?:posthog|mixpanel|amplitude|analytics|segment|heap|plausible|rudderanalytics)\s*\.\s*identify\s*\(\s*([^,)]*)/gi)) {
      const id = m[1];
      if (!/\bemail\b|['"`][^'"`]*@/i.test(id) || /hash|sha\d*|md5|digest|encrypt/i.test(id)) continue;
      hits.push({
        ruleId: 30506, code: 'CAT-06', title: 'Email Address Used as the Analytics User ID', severity: 'MEDIUM', type: 'LEGAL_COMPLIANCE', category: 'Privacy',
        lineIdx: lineAt(c, m.index!),
        why: 'The email becomes the person\'s identity in a third-party analytics tool: it is stored there, shown in dashboards and exports, and has to be found and deleted from that tool for every erasure request.',
        fix: 'Identify with your own internal user ID (the database primary key). Send an email only if the privacy policy says so and the user agreed.',
      });
    }
  }

  if (isJs || /\.(?:html?|vue|svelte|astro)$/i.test(path)) {
    // CAT-11: the standard YouTube embed sets Google cookies as soon as the page loads
    for (const m of c.matchAll(/<iframe\b[^>]*\bsrc\s*=\s*(?:\{\s*)?["'`]https?:\/\/(?:www\.)?youtube\.com\/embed\//gi)) {
      hits.push({
        ruleId: 30511, code: 'CAT-11', title: 'YouTube Embed Sets Cookies Before Consent', severity: 'LOW', type: 'LEGAL_COMPLIANCE', category: 'Privacy',
        lineIdx: lineAt(c, m.index!),
        why: 'The player at youtube.com/embed loads Google scripts and sets cookies for every visitor on page load, before anyone has played the video or agreed to anything, which cookie rules in the EU treat as needing consent.',
        fix: 'Use https://www.youtube-nocookie.com/embed/... (no cookies until the video is played), or load the embed only after the visitor clicks a placeholder.',
      });
    }
  }

  if (isJs) {
    // CAT-12: SameSite=None is only accepted together with Secure; without it the browser drops the cookie
    for (const m of c.matchAll(/\bsameSite\s*:\s*['"]none['"]/gi)) {
      const around = c.slice(Math.max(0, m.index! - 300), m.index! + 300);
      if (/\bsecure\s*:/i.test(around)) continue;
      hits.push({
        ruleId: 30512, code: 'CAT-12', title: "Cookie With sameSite: 'none' and No secure", severity: 'MEDIUM', type: 'VIBECARE', category: 'Authentication',
        lineIdx: lineAt(c, m.index!),
        why: 'Chrome, Firefox and Safari reject a SameSite=None cookie that is not marked Secure, so the cookie is silently dropped and the login or session it carries never sticks (it works on localhost over http and breaks in production).',
        fix: "Set secure: true next to sameSite: 'none' (HTTPS only), or use sameSite: 'lax' if the cookie does not need to be sent from another site.",
      });
    }
    // CAT-13: two independent awaits in a row run one after the other
    {
      const awaitLine = /^\s*(?:const|let)\s+(\{[^}]*\}|\[[^\]]*\]|\w+)\s*=\s*await\s+([^;]+?);?\s*$/;
      const NET = /\b(?:fetch|axios\.\w+|get\w*|find\w*|select|load\w*|list\w*|count\w*|query|rpc)\s*\(|\.(?:findMany|findFirst|findUnique|from)\s*\(/;
      const names = (v: string) => v.replace(/[{}\[\]]/g, ' ').split(/[,\s:=]+/).filter((n) => /^[A-Za-z_$][\w$]*$/.test(n));
      for (let i = 0; i < lines.length - 1; i++) {
        const a = awaitLine.exec(lines[i]);
        const b = awaitLine.exec(lines[i + 1]);
        if (!a || !b || !NET.test(a[2]) || !NET.test(b[2]) || /\bawait\b|=>/.test(a[2] + b[2])) continue;
        // a statement that runs on to the next line (an open bracket) may use the first result there, so only one-line pairs count
        const open = (s: string) => (s.match(/[([{]/g) ?? []).length - (s.match(/[)\]}]/g) ?? []).length;
        if (open(a[2]) !== 0 || open(b[2]) !== 0) continue;
        if (names(a[1]).some((n) => new RegExp(`\\b${n.replace(/\$/g, '\\$')}\\b`).test(b[2]))) continue;
        hits.push({
          ruleId: 30513, code: 'CAT-13', title: 'Independent Awaits Run One After the Other', severity: 'LOW', type: 'VIBECARE', category: 'Performance',
          lineIdx: i,
          why: 'The second call does not use the first result, yet it waits for it, so the request takes the sum of the two latencies instead of the longer of the two. On a page that makes several such calls it is the slowest part.',
          fix: 'Start both and wait together: const [a, b] = await Promise.all([first(), second()]). Keep them sequential only when the order matters.',
        });
        break;
      }
    }
    // CAT-15: a network call inside a database transaction holds the locks and the connection while it waits
    for (const m of c.matchAll(/(?:\$transaction|\.transaction)\s*\(\s*async\s*(?:\([^)]*\)|\w+)\s*=>\s*\{/g)) {
      const open = m.index! + m[0].length - 1;
      const end = closeOf(c, open);
      if (end < 0) continue;
      const body = c.slice(open, end);
      const call = /\bawait\s+(?:fetch|axios(?:\.\w+)?|got|stripe\.\w+\.\w+|resend\.\w+\.\w+|sgMail\.\w+|transporter\.sendMail|openai\.\w+\.\w+\.\w+)\s*\(/.exec(body);
      if (!call) continue;
      hits.push({
        ruleId: 30515, code: 'CAT-15', title: 'Network Call Inside a Database Transaction', severity: 'MEDIUM', type: 'VIBECARE', category: 'Reliability',
        lineIdx: lineAt(c, open + call.index),
        why: 'The transaction keeps its row locks and a pooled connection open while the request to the outside service runs. When that service is slow or hangs, the locks and connections pile up until the pool is empty and the whole app stops answering.',
        fix: 'Do the database work in the transaction, commit, then make the network call (or record an outbox row in the transaction and let a worker send it). If the call must come first, run it before the transaction starts.',
      });
    }
    // CAT-16: a wildcard in the allowed methods lets any permitted origin use PUT, PATCH and DELETE
    for (const m of c.matchAll(/(?:\bmethods\s*:\s*|Access-Control-Allow-Methods['"]?\s*[:,]\s*)['"]\*['"]/gi)) {
      hits.push({
        ruleId: 30516, code: 'CAT-16', title: 'CORS Allows Every HTTP Method', severity: 'LOW', type: 'SECURITY', category: 'Access Control',
        lineIdx: lineAt(c, m.index!),
        why: 'A wildcard in Access-Control-Allow-Methods allows PUT, PATCH and DELETE from every origin the policy admits, not just the GET and POST the browser clients use.',
        fix: "List the methods the API serves to browsers: methods: ['GET', 'POST', 'OPTIONS'].",
      });
    }
    // CAT-17: a 429 with no Retry-After leaves well-behaved clients guessing, so they retry at once
    if (!/retry-after/i.test(c) && !/(?:ratelimit|rate-limit|rate_limit|ratelimiter|throttl)/i.test(c.replace(/status\s*[:(]\s*429/g, ''))) {
      const m = /\.status\s*\(\s*429\s*\)|\bstatus\s*:\s*429\b|\bStatusTooManyRequests\b/.exec(c);
      // Retry-After is for API clients: an HTML page that tells a person to try again later is not one
      if (m && /json/i.test(c.slice(Math.max(0, m.index - 200), m.index + 300))) {
        hits.push({
          ruleId: 30517, code: 'CAT-17', title: '429 Response Without Retry-After', severity: 'LOW', type: 'VIBECARE', category: 'API Design',
          lineIdx: lineAt(c, m.index),
          why: 'Without Retry-After a client has no way to know when to come back, so SDKs and browsers retry immediately or on a short fixed timer, which keeps the limit tripped and adds load.',
          fix: "Send the header with the response: res.set('Retry-After', String(secondsUntilReset)) (and RateLimit-Reset if you use the IETF headers).",
        });
      }
    }
    // CAT-14: the legacy Charges API cannot run 3D Secure (SCA)
    for (const m of c.matchAll(/\bstripe\w*\s*\.\s*charges\s*\.\s*create\s*\(/gi)) {
      hits.push({
        ruleId: 30514, code: 'CAT-14', title: 'Legacy Stripe Charges API in Use', severity: 'MEDIUM', type: 'VIBECARE', category: 'Payments',
        lineIdx: lineAt(c, m.index!),
        why: 'charges.create takes a card in one step and has no way to ask the customer for 3D Secure, so European cards that need strong customer authentication are declined and the sale is lost without an error you can act on.',
        fix: 'Create a PaymentIntent (or a Checkout Session) and confirm it on the client with Stripe.js, which handles 3D Secure and other authentication.',
      });
    }
  }

  if (/\.go$/i.test(path) && !/_test\.go$/i.test(path) && !/(?:^|\/)(?:_?examples?|samples?|demos?)\//i.test(path)) {
    // CAT-18: a Go HTTP server with no timeouts keeps every slow or stalled connection open for good
    for (const m of c.matchAll(/\bhttp\s*\.\s*ListenAndServe(?:TLS)?\s*\(/g)) {
      hits.push({
        ruleId: 30518, code: 'CAT-18', title: 'Go HTTP Server Without Read Timeouts', severity: 'MEDIUM', type: 'VIBECARE', category: 'Reliability',
        lineIdx: lineAt(c, m.index!),
        why: 'http.ListenAndServe builds a Server with every timeout at zero. A client that connects and then sends bytes slowly (or never) holds a goroutine and a file descriptor indefinitely, so a few hundred idle connections can exhaust the process.',
        fix: 'Build the server yourself: srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}; srv.ListenAndServe().',
      });
    }
    for (const m of c.matchAll(/&?\bhttp\s*\.\s*Server\s*\{/g)) {
      const end = closeOf(c, m.index! + m[0].length - 1);
      if (end < 0) continue;
      if (/\b(?:ReadHeaderTimeout|ReadTimeout)\s*:/.test(c.slice(m.index!, end))) continue;
      hits.push({
        ruleId: 30518, code: 'CAT-18', title: 'Go HTTP Server Without Read Timeouts', severity: 'MEDIUM', type: 'VIBECARE', category: 'Reliability',
        lineIdx: lineAt(c, m.index!),
        why: 'Without ReadHeaderTimeout or ReadTimeout a client that connects and sends its request slowly (or never) holds a goroutine and a file descriptor indefinitely, so a few hundred idle connections can exhaust the process.',
        fix: 'Set ReadHeaderTimeout (a few seconds) and ReadTimeout / WriteTimeout / IdleTimeout on the Server.',
      });
    }
    // CAT-19: defer inside a loop runs when the function returns, not at the end of each round
    for (const m of c.matchAll(/(?:^|\n)[ \t]*for\b[^{\n]*\{/g)) {
      const open = m.index! + m[0].length - 1;
      const end = closeOf(c, open);
      if (end < 0) continue;
      const body = c.slice(open, end);
      // a closure inside the loop (func() { defer ... }()) is the correct fix, so any func literal skips it
      // a loop that breaks out after the first success (try each variant until one opens) holds one handle, not many
      if (/\bfunc\s*\(/.test(body) || /\bbreak\b/.test(body)) continue;
      const d = /\n[ \t]*defer\s+[\w.]+\.(?:Close|Unlock|Done|Release|Stop|Cancel)\s*\(\s*\)/.exec(body);
      if (!d) continue;
      hits.push({
        ruleId: 30519, code: 'CAT-19', title: 'defer Inside a Loop', severity: 'MEDIUM', type: 'VIBECARE', category: 'Reliability',
        lineIdx: lineAt(c, open + d.index + 1),
        why: 'Every defer waits until the whole function returns. In a loop over files, rows or requests, all the handles or locks stay open until the loop is done, which runs out of file descriptors or connections on a long list (and a deferred Unlock can deadlock the next round).',
        fix: 'Move the loop body into its own function so the defer runs each round, or call Close() / Unlock() directly at the end of the round.',
      });
    }
  }

  // CAT-07: aria-hidden removes an element from the accessibility tree but leaves it in the tab order
  if (/\.[jt]sx$|\.(?:html?|vue|svelte|astro)$/i.test(path) && /aria-hidden\s*=\s*(?:\{?\s*)?["']?true/i.test(c)) {
    for (const m of c.matchAll(/<(button|a|input|select|textarea)\b([^<>]*?)aria-hidden\s*=\s*(?:\{\s*)?["']?true["']?(?:\s*\})?([^<>]*)>/gi)) {
      const attrs = `${m[2]} ${m[3]}`;
      // a tabIndex of -1 or a disabled control is out of the tab order, so nothing is hidden-but-reachable
      if (/tabindex\s*=\s*(?:\{\s*)?["']?-1|\bdisabled\b|\bhidden\b|type\s*=\s*["']hidden["']/i.test(attrs)) continue;
      if (m[1].toLowerCase() === 'a' && !/\bhref\b/i.test(attrs)) continue;
      hits.push({
        ruleId: 30507, code: 'CAT-07', title: `aria-hidden on a Focusable <${m[1].toLowerCase()}>`, severity: 'MEDIUM', type: 'VIBEPOLISH', category: 'Accessibility',
        lineIdx: lineAt(c, m.index!),
        why: 'A keyboard user can still Tab onto the element, but a screen reader announces nothing, so focus lands on silence. WCAG 4.1.2 and the ARIA spec forbid aria-hidden on focusable elements.',
        fix: 'Remove aria-hidden, or take the element out of the tab order as well (tabIndex={-1}, disabled, or hidden / inert) when it is meant to be invisible.',
      });
    }
  }

  const raw = (file.content || '').split('\n');
  const ts = new Date().toLocaleTimeString();
  const seen = new Set<string>();
  for (const h of hits) {
    const key = `${h.ruleId}:${h.lineIdx}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `cat${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: h.type,
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[h.lineIdx] || lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Read ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Engineering',
      falsePositive: false,
    });
    logs.push(`[${ts}] [CATEGORY] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
