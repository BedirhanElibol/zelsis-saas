/**
 * Unfinished and fake features in AI-built apps (FAKE-01.., BUG-144.., Rule IDs 29791-29819; FAKE-10.., 29861-29869).
 *
 * Found by reviewing 30 real Lovable / Bolt apps (.cache/vibe-review.md, quotes verified line by line): the most common
 * user-facing problem was not a vulnerability but a feature that looks finished and does nothing. Forms that show
 * "sent" without sending, upgrade buttons that set isPremium locally, API calls commented out before a success toast,
 * placeholder keys, buttons and links with no target, mock logins. Plus a few runtime bugs from the same review.
 *
 * Reliability findings (type VIBECARE) except hard-coded login passwords (SECURITY). Every rule points at one line.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import type { RepoContext } from '../scanner/repo-context';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; type?: Finding['type']; lineIdx: number; why: string; fix: string }

const SKIP = /\.d\.ts$|(?:^|\/)node_modules\/|\.min\.js$|(?:^|\/)(?:tests?|__tests__|e2e|stories|__mocks__|fixtures?|mocks?|demo|examples?|storybook|scripts)\/|\.(?:test|spec|stories)\.[jt]sx?$|(?:^|\/)components\/ui\//i;
const lineAt = (c: string, off: number) => { let n = 0; for (let i = 0; i < off && i < c.length; i++) if (c.charCodeAt(i) === 10) n++; return n; };
const CAT = 'Unfinished Feature';

function closeOf(c: string, open: number): number {
  const pair: Record<string, string> = { '(': ')', '{': '}', '[': ']' };
  const stack: string[] = [];
  for (let i = open; i < c.length; i++) {
    const ch = c[i];
    if (ch === '"' || ch === "'" || ch === '`') { for (i++; i < c.length && c[i] !== ch; i++) if (c[i] === '\\') i++; continue; }
    if (pair[ch]) stack.push(pair[ch]);
    else if (ch === stack[stack.length - 1]) { stack.pop(); if (!stack.length) return i + 1; }
  }
  return -1;
}

/** Named functions (declarations, const arrows, methods) with their body text. */
function functions(c: string): { name: string; at: number; body: string; bodyAt: number }[] {
  const out: { name: string; at: number; body: string; bodyAt: number }[] = [];
  for (const x of c.matchAll(/(?:function\s+(\w+)\s*\(|(?:const|let)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*(?::[^=>{]+)?=>\s*\{|^\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*(?::[^{]+)?\{)/gm)) {
    const name = x[1] || x[2] || x[3];
    if (!name || /^(?:if|for|while|switch|catch|return)$/.test(name)) continue;
    let open: number;
    if (x[1]) { const pe = closeOf(c, x.index! + x[0].length - 1); if (pe < 0) continue; open = c.indexOf('{', pe); }
    else open = x.index! + x[0].length - 1;
    const end = open < 0 ? -1 : closeOf(c, open);
    if (end > open) out.push({ name, at: x.index!, body: c.slice(open, end), bodyAt: open });
  }
  return out;
}

const SENDS = /\bawait\s+(?!new\s+Promise)|\bfetch\s*\(|\baxios\b|\bsupabase\b|\.(?:mutate|mutateAsync|invoke|insert|upsert|update|rpc|post|put|send|sendForm|submit)\s*\(|\bemailjs\b|\bapi\.|\bdispatch\s*\(|\bwindow\.open\s*\(|\blocation\.(?:href|assign)|\bnavigator\.sendBeacon|\btrpc\b|\bstartTransition\s*\(|\b(?:props\.)?on[A-Z]\w*\s*(?:\?\.)?\(|\bmailto:|\bwa\.me|\bformAction\b|\buse(?:Mutation|Action)\b|\bmutation\b/;
const SUCCESS = /\bset(?:Is)?(?:Submitted|Success|Sent|Done|Complete|Completed|Booked|Subscribed|Premium|Paid|Upgraded|Registered)\s*\(\s*true\s*\)|\bisPremium\s*:\s*true|\b(?:plan|tier)\s*:\s*['"](?:pro|premium|enterprise|paid)['"]|\btoast(?:\.success)?\s*\(\s*(?:\{[^}]*?)?['"`][^'"`]*(?:success|sent|submitted|thank|received|booked|confirmed|upgraded|welcome)/i;

function evaluate(path: string, raw: string, c: string, add: (h: Hit) => void, context?: RepoContext) {
  const at = (off: number) => lineAt(c, off);
  const isJsx = /\.[jt]sx$/i.test(path);

  // FAKE-01: placeholder credential / config value left in code
  for (const x of c.matchAll(/\b(\w*(?:key|Key|KEY|secret|Secret|SECRET|token|Token|TOKEN|ServiceId|TemplateId|serviceId|templateId|service_id|template_id|clientId|client_id|merchantId|PublicKey|publicKey|phone|Phone|whatsapp|WHATSAPP|PHONE)\w*)\s*[:=]\s*(['"`])((?:your[_\- ]|YOUR_|<your|REPLACE|replace[_-]?me|xxx|changeme|insert[_-]?your|enter[_-]?your|TODO|PASTE)[^'"`]*|[^'"`]*_HERE)\2/g)) {
    add({ ruleId: 29791, code: 'FAKE-01', severity: 'HIGH', category: CAT, lineIdx: at(x.index!),
      title: `${x[1]} Is Still a Placeholder ("${x[3].slice(0, 30)}")`,
      why: `The value was never filled in, so every call that uses ${x[1]} fails: the payment modal, email form or API request errors for every user, while it looked finished in the editor.`,
      fix: `Read it from configuration (import.meta.env.VITE_... / process.env...) and set the real value in your hosting provider's environment variables.` });
  }
  for (const x of c.matchAll(/(['"`])((?:rzp_test_|pk_test_)[A-Za-z0-9]{8,})\1/g)) {
    if (/\.env|README|\.md$/i.test(path)) continue;
    add({ ruleId: 29803, code: 'FAKE-08', severity: 'MEDIUM', category: CAT, lineIdx: at(x.index!),
      title: `Test-Mode Payment Key Hard-Coded (${x[2].slice(0, 9)}...)`,
      why: 'A test key in the code keeps checkout in test mode after you launch: customers "pay" with no money moving, and switching to live keys needs a code change.',
      fix: 'Load the publishable key from an environment variable (VITE_RAZORPAY_KEY_ID / NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY) with different values for test and production.' });
  }

  const fns = functions(c);
  for (const fn of fns) {
    // FAKE-02: simulated backend: an artificial delay stands in for the real request
    const delay = /await\s+new\s+Promise\s*\(\s*\(?\s*(\w+)\s*\)?\s*=>\s*setTimeout\s*\(\s*\1\s*,\s*\d+\s*\)\s*\)/.exec(fn.body);
    const bodyNoDelay = delay ? fn.body.replace(delay[0], '') : fn.body;
    if (delay && SUCCESS.test(fn.body) && !SENDS.test(bodyNoDelay)) {
      add({ ruleId: 29792, code: 'FAKE-02', severity: 'HIGH', category: CAT, lineIdx: at(fn.bodyAt + delay.index),
        title: `${fn.name}() Fakes the Request With a Timer`,
        why: 'The function waits on setTimeout and then reports success, but nothing is sent anywhere: users see "done" (an upgrade, a booking, a sent message) and the data is lost.',
        fix: `Replace the delay with the real call (fetch / supabase / your API) and only show success when it resolves without an error.` });
      continue;
    }
    // FAKE-04: submit / upgrade handler that never sends anything but reports success
    if (/^(?:handle\w*(?:Submit|Send|Book|Booking|Contact|Upgrade|Checkout|Payment|Purchase|Subscribe|Apply|Register|Signup|SignUp)\w*|on\w*Submit\w*|submit\w*|upgrade\w*|purchase\w*|subscribe\w*|sendMessage|bookAppointment)$/.test(fn.name) &&
        SUCCESS.test(fn.body) && !SENDS.test(fn.body) && fn.body.length < 3000 &&
        !/\bset[A-Z]\w*\s*\(\s*(?:\{|\[|\.\.\.|prev\b|\(?\s*\w+\s*\)?\s*=>)|\bdispatch\b|\.(?:push|set)\s*\(/.test(fn.body)) {
      add({ ruleId: 29794, code: 'FAKE-04', severity: 'HIGH', category: CAT, lineIdx: at(fn.at),
        title: `${fn.name}() Shows Success Without Sending Anything`,
        why: `The handler only updates local state (and maybe a toast). No request, database write or email is made, so every submission (message, booking, application, upgrade) is silently lost while the user is told it worked.`,
        fix: 'Send the data (fetch to your API, supabase.from(...).insert(...), EmailJS/Formspree, a server action) and show success only after it succeeds; show an error otherwise.' });
    }
  }

  // FAKE-03: API call commented out, success still reported (comments are only in the raw source)
  const rawLines = raw.split('\n');
  rawLines.forEach((l, i) => {
    if (!/^\s*\/\/\s*(?:const\s+\w+\s*=\s*)?(?:await\s+)?(?:fetch|axios|supabase|api\w*|\w*(?:Service|Api|API|Client))?[\w.]*\s*\([^)]*\)?/.test(l) || !/\/\/\s*(?:const\s+\w+\s*=\s*)?await\s|\/\/\s*(?:fetch|axios|supabase)\b|\/\/\s*\w+\.(?:post|put|insert|send|create|submit)\(/.test(l)) return;
    for (let k = i + 1; k < Math.min(rawLines.length, i + 6); k++) {
      const n = rawLines[k];
      if (/^\s*\/\//.test(n) || !n.trim()) continue;
      if (SUCCESS.test(n) || /\bset(?:Is)?(?:Submitted|Success|Sent|Done)\s*\(\s*true/.test(n)) {
        add({ ruleId: 29793, code: 'FAKE-03', severity: 'HIGH', category: CAT, lineIdx: i,
          title: 'The Real Request Is Commented Out, but Success Is Still Shown',
          why: 'The line that sends the data is a comment, and the next statements report success. Users get a confirmation while nothing is saved or sent.',
          fix: 'Restore the call (and await it inside try), or remove the form until the backend exists.' });
        break;
      }
      if (!/^\s*(?:console\.|\}|try|const|let)/.test(n)) break;
    }
  });

  if (isJsx) {
    // FAKE-05: action button with no handler, outside any form
    const indirect = /\basChild\b|Trigger\b|<form\b|<Form\b|\bonSelect\b|\buseForm\b|render=\{/.test(c) || /(?:^|\/)(?:registry|blocks|cards|showcase|examples?|demos?|templates?|playground|styles)\)?\//.test(path.replace(/\/\(/g, '/'));
    for (const x of indirect ? [] : c.matchAll(/<(button|Button)\b/g)) {
      let te = x.index! + x[0].length;
      for (; te < c.length && c[te] !== '>'; te++) { if (c[te] === '{') { const e = closeOf(c, te); if (e < 0) break; te = e - 1; } }
      const attrs = c.slice(x.index! + x[0].length, te);
      if (/=\s*\{\s*\(?\s*$/.test(c.slice(Math.max(0, x.index! - 40), x.index!))) continue; // passed as a prop (trigger={<Button>})
      // direct child of a custom component (<DeleteDialog><Button/>, <Popover><button/>): the wrapper usually makes it the trigger
      const prev = c.slice(Math.max(0, x.index! - 2000), x.index!);
      if (prev.trimEnd().endsWith('>')) {
        const opens = [...prev.matchAll(/<([A-Z][\w.]*)\b/g)].reverse();
        const parent = opens.find((o) => !prev.slice(o.index!).includes(`</${o[1]}>`));
        const lastLower = prev.lastIndexOf('<');
        if (parent && !/^<[a-z]/.test(prev.slice(lastLower)) && !/\/>\s*$/.test(prev)) continue;
      }
      if (/\bonClick\b|\btype\s*=\s*["']submit|\bform\s*=|\basChild\b|\{\s*\.\.\.|\bdisabled\b|\bonMouseDown\b|\bonPointerDown\b|\bhref\s*=/.test(attrs)) continue;
      const close = c.indexOf(`</${x[1]}>`, te);
      if (close < 0 || close - x.index! > 600) continue;
      const label = c.slice(te + 1, close).replace(/<[^>]*>|\{[^}]*\}/g, ' ').replace(/\s+/g, ' ').trim();
      const title = /\btitle\s*=\s*["']([^"']+)["']|aria-label\s*=\s*["']([^"']+)["']/.exec(attrs);
      const text = `${label} ${title?.[1] ?? title?.[2] ?? ''}`;
      if (!/\b(?:download|export|add|create|save|delete|remove|edit|view|upload|send|book|buy|checkout|subscribe|apply|share|print|invite|pay|upgrade|import)\b/i.test(text)) continue;
      const before = c.slice(Math.max(0, x.index! - 160), x.index!);
      if (/asChild[^<]*>\s*$|<(?:Link|a|label|form)\b[^>]*>\s*$/.test(before)) continue;
      const opens = (c.slice(0, x.index!).match(/<form\b/g) ?? []).length;
      const closes = (c.slice(0, x.index!).match(/<\/form>/g) ?? []).length;
      if (opens > closes) continue; // inside a form: it submits
      add({ ruleId: 29795, code: 'FAKE-05', severity: 'MEDIUM', category: CAT, lineIdx: at(x.index!),
        title: `"${text.trim().slice(0, 30)}" Button Does Nothing`,
        why: 'The button has no onClick, is not a submit button in a form and is not wrapped by a link or trigger, so clicking it has no effect.',
        fix: 'Wire it up (onClick handler, a <Link>, or a Dialog/Sheet trigger with asChild), or hide it until the feature exists.' });
    }

    // FAKE-06: link that goes nowhere
    const gallery = /(?:^|\/)(?:registry|blocks|cards|showcase|examples?|demos?|templates?|playground)\//.test(path);
    for (const x of gallery ? [] : c.matchAll(/<(a|Link)\b([^>]*?)\bhref\s*=\s*(?:\{\s*)?["']#["']\s*\}?([^>]*)>/g)) {
      if (/\bonClick\b|role\s*=\s*["']button|\{\s*\.\.\./.test(x[2] + x[3])) continue;
      add({ ruleId: 29796, code: 'FAKE-06', severity: 'LOW', category: CAT, lineIdx: at(x.index!),
        title: 'Link Points to "#" and Goes Nowhere',
        why: 'href="#" only jumps to the top of the page: users who click this (often a social profile, a document or a "learn more" link) never reach the content.',
        fix: 'Point it at the real URL, render a <button> with a handler for actions, or remove it until the page exists.' });
    }
  }

  // FAKE-07: mock login left in the app (hard-coded password comparison / fake tokens)
  if (!/(?:^|\/)(?:seed|mock|fixtures?|docs?|documentation|examples?|tutorials?)\w*\.[jt]sx?$/i.test(path) && !/(?:^|\/)(?:docs?|documentation|examples?|tutorials?)\//i.test(path) && !/\.mdx?$/i.test(path)) {
    for (const x of c.matchAll(/\b(\w*[pP]assword\w*)\s*===?\s*(['"`])([^'"`]{3,40})\2|(['"`])([^'"`]{3,40})\4\s*===?\s*(\w*[pP]assword\w*)\b/g)) {
      const idName = x[1] ?? x[6];
      if (/(?:[eE]rror(?:[cC]ode)?|[sS]tatus|[pP]olicy|[sS]trength|[vV]alidation)$/.test(idName)) continue;
      const val = x[3] ?? x[5];
      if (/^(?:password|text|hidden|new-password|current-password|object|string|undefined|null|number|boolean|function|pwned)$/i.test(val)) continue; // input type, autocomplete, typeof, error code
      if (/typeof\s+[\w.]*$/.test(c.slice(Math.max(0, x.index! - 40), x.index!))) continue;
      add({ ruleId: 29797, code: 'FAKE-07', severity: 'CRITICAL', category: 'Hardcoded Credentials', type: 'SECURITY', lineIdx: at(x.index!),
        title: 'Login Checks a Hard-Coded Password',
        why: `The password "${val}" is in the source (and in the browser bundle for client code), so anyone can read it and sign in, and every real user is checked against a constant instead of their own credentials.`,
        fix: 'Authenticate against your auth provider (Supabase Auth, NextAuth, your API) and delete the hard-coded check and demo accounts.' });
    }
    for (const x of c.matchAll(/\b(?:token|accessToken|access_token|jwt)\s*:\s*(['"`])((?:mock|fake|dummy|test|demo|sample)[-_][^'"`]*)\1/gi)) {
      add({ ruleId: 29804, code: 'FAKE-09', severity: 'HIGH', category: CAT, lineIdx: at(x.index!),
        title: `Auth Returns a Fake Token ("${x[2].slice(0, 24)}")`,
        why: 'Sign-up / login returns a hard-coded token instead of the server response, so accounts are never really created or verified and every protected API call fails.',
        fix: 'Return the token / session from the real auth response and handle its errors.' });
    }
  }

  // BUG-144: removeEventListener with a new inline function never removes the listener
  for (const x of c.matchAll(/\.removeEventListener\s*\(\s*(['"`][\w:-]+['"`])\s*,\s*(?:\([^)]*\)|\w+)\s*=>/g)) {
    add({ ruleId: 29798, code: 'BUG-144', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index!),
      title: `removeEventListener(${x[1]}) Gets a New Function, So Nothing Is Removed`,
      why: 'Listeners are removed by reference. A fresh arrow function never matches the one that was added, so the old listener stays: handlers pile up on every mount and run several times.',
      fix: 'Keep the handler in a variable: const onPop = () => {...}; window.addEventListener("popstate", onPop); return () => window.removeEventListener("popstate", onPop);' });
  }

  // BUG-145: process.env in a Vite browser app (process is not defined in the browser)
  // Electron's main and preload code runs in Node, where process.env is real
  if (context && context.packageMajors.has('vite') && !context.packageMajors.has('next') && /^(?:src|app|client|frontend\/src)\//.test(path) && !/(?:^|\/)(?:server|functions|scripts|electron)\/|^api\/|\.config\.[cm]?[jt]s$/.test(path)
    && !(context.packageMajors.has('electron') && /(?:^|\/)src\/(?:main|preload)\//.test(path))) {
    for (const x of c.matchAll(/\bprocess\.env\.([A-Z][A-Z0-9_]*)\b/g)) {
      if (x[1] === 'NODE_ENV') continue;
      add({ ruleId: 29799, code: 'BUG-145', severity: 'HIGH', category: 'Deployment Bug', lineIdx: at(x.index!),
        title: `process.env.${x[1]} in a Vite App Is Undefined in the Browser`,
        why: `Vite only exposes variables through import.meta.env with the VITE_ prefix. process does not exist in the browser, so this throws "process is not defined" (or reads undefined after a polyfill) and the feature breaks in production.`,
        fix: `Rename the variable to VITE_${x[1].replace(/^VITE_/, '')} and read import.meta.env.VITE_${x[1].replace(/^VITE_/, '')} (only for values that are safe to ship to the browser).` });
    }
  }

  // BUG-146: long setTimeout in a serverless handler (the instance stops long before it fires)
  if (/^\s*(['"])use server\1/.test(c) || /(?:^|\/)(?:app\/.*route|pages\/api\/.*|supabase\/functions\/.*|netlify\/functions\/.*)|^api\/[\w/-]+\.[jt]s$/.test(path)) {
    for (const x of c.matchAll(/\bsetTimeout\s*\(/g)) {
      const end = closeOf(c, x.index! + x[0].length - 1);
      if (end < 0) continue;
      const args = c.slice(x.index! + x[0].length, end - 1);
      const delay = args.slice(args.lastIndexOf(',') + 1).trim();
      let ms = NaN;
      if (/^[\d_\s*]+$/.test(delay)) { try { ms = delay.replace(/_/g, '').split('*').reduce((a, b) => a * Number(b.trim()), 1); } catch { /* ignore */ } }
      if (!(ms >= 60_000)) continue;
      add({ ruleId: 29800, code: 'BUG-146', severity: 'HIGH', category: 'Deployment Bug', lineIdx: at(x.index!),
        title: `setTimeout of ${Math.round(ms / 60000)} min in a Serverless Function Never Fires`,
        why: 'Serverless and edge functions are frozen or shut down shortly after the response is sent, so a timer scheduled for minutes or days never runs: the cleanup, reminder or deletion silently never happens.',
        fix: 'Schedule it durably: a cron job (Vercel Cron, Supabase pg_cron), a queue with delayed delivery, or store a due date and process it from a scheduled job.' });
    }
  }

  // BUG-147: ternary whose two branches are identical
  for (const x of c.matchAll(/\?\s*((['"`])[^'"`\n]{2,120}\2|-?\d+(?:\.\d+)?|[\w$.]+)\s*:\s*((['"`])[^'"`\n]{2,120}\4|-?\d+(?:\.\d+)?|[\w$.]+)(?=[ \t]*[;,)\]}]|[ \t]*\r?\n\s*[;,)\]}<]|[ \t]*\r?$)(?![ \t]*\r?\n\s*(?:\?\?|\|\||&&|[.?]))/gm)) {
    if (x[1] !== x[3] || /^(?:true|false|null|undefined)$/.test(x[1])) continue;
    const before = c.slice(Math.max(0, x.index! - 120), x.index!);
    if (!/[=(,:]\s*[^=(,:]*$/.test(before) || /\?\.?$/.test(before)) continue;
    add({ ruleId: 29801, code: 'BUG-147', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index!),
      title: `Both Branches of the Ternary Are ${x[1].slice(0, 40)}`,
      why: 'The condition has no effect because both sides return the same value. Usually one branch was meant to differ (the production URL, the other label), so one environment or state silently gets the wrong value.',
      fix: 'Put the intended value in one of the branches, or drop the condition.' });
  }

  // BUG-148: row inserted with user?.id (null owner when the session is missing)
  for (const x of c.matchAll(/\.(?:insert|upsert)\s*\(/g)) {
    const end = closeOf(c, x.index! + x[0].length - 1);
    if (end < 0) continue;
    const arg = c.slice(x.index!, end);
    const m = /\b(\w*user_?id|owner_?id|created_by|author_?id)\s*:\s*((?:user|session\??\.user|currentUser|authUser)\?\.id)\b(?!\s*(?:!|\?\?|\|\|))/i.exec(arg);
    if (!m) continue;
    const before = c.slice(Math.max(0, x.index! - 1500), x.index!);
    if (/if\s*\(\s*!\s*(?:user|session|currentUser|authUser)\b|(?:user|session|currentUser|authUser)\s*&&|throw\s+new\s+Error\([^)]*(?:auth|log|sign)/i.test(before)) continue;
    add({ ruleId: 29802, code: 'BUG-148', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index! + arg.indexOf(m[0])),
      title: `Row Saved With ${m[1]}: ${m[2]} (null When Signed Out)`,
      why: `If the session expired or the user is not loaded yet, ${m[2]} is undefined: the row is saved without an owner (or the insert fails on RLS), so the user's data disappears from their list.`,
      fix: `Check first: if (!user) { redirect to sign-in / show an error; return; } then insert with ${m[1]}: user.id.` });
  }

  // The rules below come from the Gemini rule report (FAKE-10.., Rule IDs 29861-29869), re-checked on real repos.
  const isClient = /\.[jt]sx$/i.test(path) || /^\s*['"]use client['"]/m.test(c);

  // FAKE-10: high-stakes account / billing / security action that only edits local state
  const LOCAL_ONLY_CALL = /^(?:set[A-Z]\w*|toast|alert|confirm|console|log|warn|error|success|info|filter|map|find|findIndex|some|every|includes|indexOf|push|concat|slice|splice|reduce|forEach|sort|keys|values|entries|from|now|random|floor|ceil|round|toString|toISOString|toLocaleString|toLocaleDateString|String|Number|Boolean|Date|stringify|parse|randomUUID|trim|toLowerCase|toUpperCase|replace|split|join|startsWith|endsWith|preventDefault|stopPropagation|close\w*|open\w*|reset|t)$/;
  for (const fn of fns) {
    if (!isClient || fn.body.length > 2500) continue;
    const act = /^(?:handle|on|confirm)?(Delete|Remove|Revoke|Refund|Cancel|Change|Update|Invite|Connect|Disconnect|Enable|Disable|Verify|Publish|Deploy|Restore|Withdraw|Approve|Rotate|Regenerate|Request|Issue|Merge|Transfer|Promote|Demote|Ban|Suspend)(\w*?)(Account|Refund|Sessions?|Role|Members?|Payouts?|Withdrawal|Subscription|Domain|Integration|Slack|Github|GitHub|Notion|Jira|TwoFactor|2fa|2FA|Mfa|MFA|Totp|TOTP|Backup|Deployment|Site|ApiKeys?|Webhooks?|Order|Ownership|User)s?$/.exec(fn.name);
    // Must rewrite the data itself (filter / map / status), not just open a confirm dialog
    if (!act || SENDS.test(fn.body) || !/\bset[A-Z]\w*\s*\([^;]*(?:\.(?:filter|map)\(|\bstatus\s*:|\.\.\.)/.test(fn.body)) continue;
    const calls = [...fn.body.matchAll(/(?<![\w$.])(?:[\w$]+\.)*([\w$]+)\s*\(/g)].map((m) => m[1]).filter((n) => !/^(?:if|for|while|switch|catch|return|function|typeof|await|new)$/.test(n));
    if (calls.some((n) => !LOCAL_ONLY_CALL.test(n))) continue;
    add({ ruleId: 29861, code: 'FAKE-10', severity: 'HIGH', category: CAT, lineIdx: at(fn.at),
      title: `${fn.name}() Only Changes Local State`,
      why: `"${act[1]} ${act[3]}" is never sent to a server: the screen updates, but after a reload the ${act[3].toLowerCase()} is unchanged, and nothing was actually ${act[1].toLowerCase()}d / applied for the user.`,
      fix: 'Call the real backend (API route, server action, Supabase, Stripe) and update the UI only after it succeeds; show an error when it fails.' });
  }

  if (isClient) {
    // FAKE-11: coupon / promo code checked against a constant in browser code
    for (const x of c.matchAll(/\b(\w*(?:coupon|promo|discount|voucher)\w*)\s*(?:\.\w+\(\))?\s*===?\s*(['"`])([A-Za-z0-9_-]{3,24})\2/gi)) {
      if (!/coupon|promo|voucher|discount\w*code/i.test(x[1]) || /(?:Id|Type|Status|Mode|State|Kind)$/.test(x[1])) continue;
      if (/^(?:percent|fixed|amount|none|active|expired|string|number)$/i.test(x[3])) continue;
      add({ ruleId: 29862, code: 'FAKE-11', severity: 'HIGH', category: CAT, lineIdx: at(x.index!),
        title: `Discount Code "${x[3]}" Validated in the Browser`,
        why: 'The valid code ships in the JavaScript bundle and the discount is applied client-side, so anyone can read the code, and the server-side charge never sees the discount (or trusts a client price).',
        fix: 'Validate codes on the server (Stripe promotion codes or your API) and compute the final price there.' });
    }

    // FAKE-12: one-time code "verified" by length or against a constant
    for (const x of c.matchAll(/\b(\w*(?:otp|totp|mfa|twoFactor|2fa|verificationCode|verifyCode|code|pin)\w*)\s*(?:\.length\s*===?\s*6\b|===?\s*(['"`])\d{4,8}\2)/gi)) {
      const fn = fns.find((f) => x.index! >= f.bodyAt && x.index! < f.bodyAt + f.body.length);
      if (!fn || SENDS.test(fn.body) || !/\bset\w*(?:Verified|Enabled|Authenticated|Success|Step|TwoFactor|Mfa|2fa)\w*\s*\(|\bset\w*\s*\(\s*true\s*\)/i.test(fn.body)) continue;
      add({ ruleId: 29863, code: 'FAKE-12', severity: 'CRITICAL', category: 'Authentication', type: 'SECURITY', lineIdx: at(x.index!),
        title: `${fn.name}() Accepts the Code Without Checking It on a Server`,
        why: 'The code is only checked for its length or against a constant in the browser, so any 6 digits (or the code visible in the bundle) pass: two-factor or email verification protects nothing.',
        fix: 'Send the code to the server and verify it there (TOTP secret / provider verify API); mark the step done only on a successful response.' });
    }

    // FAKE-13: live metrics simulated with setInterval + Math.random
    for (const x of c.matchAll(/\bsetInterval\s*\(/g)) {
      const end = closeOf(c, x.index! + x[0].length - 1);
      if (end < 0) continue;
      const body = c.slice(x.index!, end);
      const m = /\bset(\w*(?:Cpu|CPU|Memory|Ram|RAM|Latency|Uptime|Requests|Visitors|Online|Users|Traffic|Revenue|Sales|Load|Bandwidth|Throughput|Metrics|Stats))\s*\([^)]*Math\.random\(\)/.exec(body);
      if (m && !SENDS.test(body)) add({ ruleId: 29864, code: 'FAKE-13', severity: 'MEDIUM', category: CAT, lineIdx: at(x.index!),
        title: `"Live" ${m[1]} Is Random Numbers`,
        why: `${m[1]} is updated every few seconds with Math.random(), not from real data, so the dashboard shows invented activity that users may act on.`,
        fix: 'Fetch the real metric (your API, analytics, a realtime channel) or label the widget as sample data.' });
    }

    // FAKE-14: recovery / backup codes generated in the browser and never stored
    for (const fn of fns) {
      if (!/^(?:handle|on)?(?:Generate|Create|Regenerate|Show)\w*(?:Recovery|Backup)\w*Codes?$/i.test(fn.name)) continue;
      if (/Math\.random\(|crypto\.getRandomValues\(|randomUUID\(/.test(fn.body) && !SENDS.test(fn.body)) add({ ruleId: 29865, code: 'FAKE-14', severity: 'HIGH', category: 'Authentication', type: 'SECURITY', lineIdx: at(fn.at),
        title: `${fn.name}() Creates Recovery Codes Only in the Browser`,
        why: 'The codes are random strings in page memory and are never saved (hashed) on the server, so they cannot be used to recover the account: the user is locked out when they lose their device.',
        fix: 'Generate and store hashed recovery codes on the server, return them once, and verify them server-side at sign-in.' });
    }
  }

  // FAKE-15: "PDF" download that is plain text or JSON in a Blob
  for (const x of c.matchAll(/new\s+Blob\s*\(\s*\[([^\]]*)\]\s*,\s*\{\s*type\s*:\s*['"]application\/pdf['"]/g)) {
    if (!/^\s*(?:JSON\.stringify\(|['"`])/.test(x[1])) continue;
    if (/\b(?:jsPDF|pdf-lib|PDFDocument|@react-pdf|pdfmake|html2pdf|output\(|arrayBuffer|Uint8Array|base64)/.test(c)) continue;
    add({ ruleId: 29866, code: 'FAKE-15', severity: 'HIGH', category: CAT, lineIdx: at(x.index!),
      title: 'Text Saved With a PDF Content Type',
      why: 'Labelling a string or JSON as application/pdf does not make a PDF: the downloaded invoice or report fails to open ("file is damaged").',
      fix: 'Generate a real PDF (pdf-lib, @react-pdf/renderer, jsPDF, or on the server) or download it as .txt / .csv / .json.' });
  }
}

export function evaluateLogicFakeRules(file: CodeFile, _lines: string[], cleanContent: string, findingCounter: {
  count: number;
}, context?: RepoContext): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (!/\.[cm]?[jt]sx?$/i.test(path) || SKIP.test(path)) return { findings, logs };
  const c = cleanContent;
  if (!c || c.length > 400_000) return { findings, logs };

  const hits: Hit[] = [];
  const add = (h: Hit) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  evaluate(path, file.content || '', c, add, context);

  const raw = (file.content || '').split('\n');
  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `bug${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: h.type ?? 'VIBECARE',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Engineering',
      falsePositive: false
    });
    logs.push(`[${ts}] [BUG] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
