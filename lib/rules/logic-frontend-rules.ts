/**
 * Frontend logic and UI bugs in AI-written apps (BUG-107..124, Rule IDs 29740-29757): Tailwind, shadcn/Radix, React 19
 * forms, Next.js 15/16 request APIs, client data fetching, mobile Safari, Stripe redirect URLs, Vue and React Native.
 *
 * Reliability findings (type VIBECARE): they cost score points but never fail the release gate. Each rule matches a
 * specific, documented mistake on the reported line; candidates came from .cache/rule-research-fullapp.md and were
 * kept only when one file proves the bug.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import type { RepoContext } from '../scanner/repo-context';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category?: string; lineIdx: number; why: string; fix: string }

const SKIP = /\.d\.ts$|(?:^|\/)node_modules\/|\.min\.js$|(?:^|\/)(?:tests?|__tests__|e2e|stories|__mocks__|fixtures?)\/|\.(?:test|spec|stories)\.[jt]sx?$/i;

const lineAt = (c: string, off: number) => { let n = 0; for (let i = 0; i < off && i < c.length; i++) if (c.charCodeAt(i) === 10) n++; return n; };

/** Index just past the bracket closing the one at `open`, skipping strings and template literals. */
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

/** End of the JSX opening tag that starts at `lt` ('<'), honouring {...} attribute expressions and strings. */
function tagEnd(c: string, lt: number): number {
  for (let i = lt + 1; i < c.length; i++) {
    const ch = c[i];
    if (ch === '{') { const e = closeOf(c, i); if (e < 0) return -1; i = e - 1; continue; }
    if (ch === '"' || ch === "'") { for (i++; i < c.length && c[i] !== ch; i++); continue; }
    if (ch === '>') return i + 1;
  }
  return -1;
}

/** Offset of the matching closing tag `</Name>` for an opening tag at `lt` (same-name nesting aware), or -1. */
function closingTag(c: string, lt: number, name: string): number {
  const re = new RegExp(String.raw`<(/?)${name.replace('.', '\\.')}(?=[\s>/])`, 'g');
  re.lastIndex = lt + 1;
  let depth = 1;
  for (let x = re.exec(c); x; x = re.exec(c)) {
    const end = tagEnd(c, x.index);
    if (end < 0) return -1;
    if (x[1]) { if (--depth === 0) return x.index; }
    else if (c[end - 2] !== '/') depth++;
    re.lastIndex = end;
  }
  return -1;
}

/** Class string literals / template literals passed as className / class / cn() / clsx() / cva() arguments. */
function classStrings(c: string): { text: string; at: number; tpl: boolean }[] {
  const out: { text: string; at: number; tpl: boolean }[] = [];
  for (const x of c.matchAll(/\b(?:className|class)\s*=\s*(?:\{\s*)?(["'`])/g)) {
    const q = x[1]; const s = x.index! + x[0].length;
    const e = c.indexOf(q, s);
    if (e > s) out.push({ text: c.slice(s, e), at: s, tpl: q === '`' });
  }
  for (const x of c.matchAll(/\b(?:cn|clsx|classNames|twMerge|cva|tw)\s*\(/g)) {
    const open = x.index! + x[0].length - 1;
    const end = closeOf(c, open);
    if (end < 0) continue;
    for (const s of c.slice(open, end).matchAll(/(["'`])((?:(?!\1)[^\\]|\\.)*)\1/g)) out.push({ text: s[2], at: open + s.index! + 1, tpl: s[1] === '`' });
  }
  return out;
}

const TW_PREFIX = 'bg|text|border|ring|from|via|to|fill|stroke|outline|decoration|divide|placeholder|accent|caret|shadow|w|h|min-w|min-h|max-w|max-h|p|px|py|pt|pb|pl|pr|m|mx|my|mt|mb|ml|mr|gap|space-x|space-y|grid-cols|col-span|row-span|top|left|right|bottom|inset|z|opacity|rounded|translate-x|translate-y|scale|rotate|order|basis|leading|tracking|font|columns';

function evaluate(path: string, c: string, add: (h: Hit) => void, context?: RepoContext) {
  const at = (off: number) => lineAt(c, off);
  const isJsx = /\.[jt]sx$/i.test(path) || /<[A-Za-z][\w.]*[\s>/]/.test(c);
  const isClient = /^\s*(['"])use client\1/.test(c);

  // BUG-107: Tailwind class built from a dynamic fragment (`bg-${color}-500`) is never generated
  if (isJsx) {
    const seen = new Set<number>();
    for (const s of classStrings(c)) {
      if (!s.tpl) continue;
      for (const x of s.text.matchAll(new RegExp(String.raw`(?:^|[\s:])(-?(?:${TW_PREFIX}))-\$\{`, 'g'))) {
        const line = at(s.at + x.index!);
        if (seen.has(line)) continue;
        seen.add(line);
        add({ ruleId: 29740, code: 'BUG-107', severity: 'MEDIUM', category: 'UI Bug', lineIdx: line,
          title: `Tailwind Class Built at Runtime (${x[1]}-\${...}) Is Never Generated`,
          why: 'Tailwind only generates classes it finds as complete strings in your source. A class assembled from a variable (bg-${color}-500) is missing from the CSS bundle, so the color/size silently does not apply in production.',
          fix: 'Map values to full class names: const colors = { red: "bg-red-500", green: "bg-green-500" }; className={colors[color]} (or add them to the safelist).' });
      }
    }
  }

  // BUG-108: Next.js 15+/16 params / searchParams read without await
  if (/(?:^|\/)app\/(?:.*\/)?(?:page|layout|route|default|template|opengraph-image|twitter-image|icon)\.[jt]sx?$/.test(path) && (context?.nextMajorVersion ?? 0) >= 15) {
    for (const x of c.matchAll(/\{\s*(?:params|searchParams)(?:\s*,\s*(?:params|searchParams))?\s*\}\s*:\s*\{\s*(params|searchParams)\s*:\s*\{/g)) {
      const name = x[1];
      if (new RegExp(String.raw`\bawait\s+(?:props\.)?${name}\b|\buse\(\s*${name}\s*\)`).test(c)) continue;
      if (!new RegExp(String.raw`\b${name}\s*\.\s*\w+|\b${name}\s*\[`).test(c.slice(x.index! + x[0].length))) continue;
      add({ ruleId: 29741, code: 'BUG-108', severity: (context?.nextMajorVersion ?? 0) >= 16 ? 'HIGH' : 'MEDIUM', lineIdx: at(x.index!),
        title: `${name} Typed and Read Synchronously (Next.js ${context?.nextMajorVersion}+)`,
        why: `Since Next.js 15 ${name} is a Promise. Reading ${name}.x synchronously warns in 15 and returns undefined in 16, so the page renders the wrong record or a 404.`,
        fix: `Type it as a Promise and await it: { ${name} }: { ${name}: Promise<{ ... }> } then const { ... } = await ${name}; (npx @next/codemod@latest next-async-request-api .)` });
    }
  }

  if (isJsx) {
    // BUG-109: text input smaller than 16px on mobile (iOS Safari zooms the page on focus)
    for (const x of c.matchAll(/<(input|textarea|select|Input|Textarea|SelectTrigger)\b/g)) {
      const end = tagEnd(c, x.index!);
      if (end < 0) continue;
      const tag = c.slice(x.index!, end);
      if (/\btype\s*=\s*["'](?:checkbox|radio|range|color|file|submit|button|hidden|image|reset)["']/.test(tag)) continue;
      const cls = /className\s*=\s*(?:\{\s*)?(?:cn\(\s*)?["'`]([^"'`]*)["'`]/.exec(tag);
      if (!cls) continue;
      const base = cls[1].split(/\s+/).filter((t) => !t.includes(':'));
      const small = base.find((t) => /^text-(?:xs|\[(?:1[0-2]|[0-9])px\]|\[0?\.[0-7]\d*rem\])$/.test(t));
      if (!small) continue;
      // a larger size at a breakpoint means the small one is desktop-only; small on mobile is the bug
      if (cls[1].split(/\s+/).some((t) => /^(?:max-sm|max-md):text-(?:base|lg|xl|\[1[6-9]px\]|\[[2-9]\dpx\])$/.test(t))) continue;
      add({ ruleId: 29742, code: 'BUG-109', severity: 'LOW', category: 'UI Bug', lineIdx: at(x.index!),
        title: `Form Field Uses ${small} on Mobile: iOS Zooms In on Focus`,
        why: 'Mobile Safari zooms the whole page when a focused input has a font size under 16px, and does not zoom back out, so the layout is cut off after typing.',
        fix: `Use 16px on small screens and the smaller size from a breakpoint: "text-base md:${small.replace(/^text-/, 'text-')}" (shadcn's Input does exactly this).` });
    }

    // BUG-110: useFormStatus in the same component that renders the <form>
    if (/\buseFormStatus\s*\(/.test(c)) {
      for (const x of c.matchAll(/\buseFormStatus\s*\(/g)) {
        // enclosing component: nearest preceding "function Name(" or "const Name = (...) =>"
        const before = c.slice(0, x.index!);
        const decl = [...before.matchAll(/(?:function\s+([A-Z]\w*)\s*\(|(?:const|let)\s+([A-Z]\w*)\s*=\s*(?:\([^)]*\)|\w+)\s*=>)/g)].pop();
        if (!decl) continue;
        // skip the parameter list (it may destructure props with braces) before looking for the body
        const paramsEnd = decl[1] ? closeOf(c, decl.index! + decl[0].length - 1) : decl.index! + decl[0].length;
        const open = paramsEnd < 0 ? -1 : c.indexOf('{', paramsEnd);
        const end = open < 0 ? -1 : closeOf(c, open);
        if (end < 0 || end < x.index!) continue;
        const body = c.slice(open, end);
        if (!/<form\b/.test(body)) continue;
        add({ ruleId: 29743, code: 'BUG-110', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index!),
          title: `useFormStatus() Called in ${decl[1] || decl[2]}, Which Renders the <form> Itself`,
          why: 'useFormStatus only reports a parent <form>. Called in the component that renders the form, pending is always false, so the submit button never disables or shows a spinner and users submit twice.',
          fix: 'Move the button into its own component rendered inside the form: function SubmitButton() { const { pending } = useFormStatus(); return <button disabled={pending}>...</button>; }' });
      }
    }

    // BUG-111: Radix / shadcn dialog content without a title (console error, screen readers announce nothing)
    for (const x of c.matchAll(/<((?:Alert)?Dialog(?:Primitive\.)?Content|SheetContent|DrawerContent|(?:AlertDialog|Dialog)Primitive\.Content)\b/g)) {
      const close = closingTag(c, x.index!, x[1]);
      if (close < 0) continue;
      const inner = c.slice(x.index!, close);
      if (/<(?:\w+\.)?(?:Alert)?(?:Dialog|Sheet|Drawer)(?:Primitive\.)?Title\b|<\w*Title\b|aria-label(?:ledby)?\s*=|VisuallyHidden/.test(inner)) continue;
      if (/\{\s*(?:children|props\.children)\s*\}/.test(inner) && !/<h[1-6]\b/.test(inner)) continue; // wrapper component; the caller supplies the title
      add({ ruleId: 29744, code: 'BUG-111', severity: 'LOW', category: 'UI Bug', lineIdx: at(x.index!),
        title: `${x[1]} Has No Title`,
        why: 'Radix requires a Title inside dialog content: without it the console shows "DialogContent requires a DialogTitle" and screen-reader users hear an unnamed dialog.',
        fix: `Add <${x[1].replace(/Content$/, 'Title')}>...</${x[1].replace(/Content$/, 'Title')}> (wrap it in <VisuallyHidden> if it should not be visible).` });
    }

    // BUG-113: next/image fill inside a parent that is not positioned
    if (/from\s+['"]next\/image['"]/.test(c)) {
      for (const x of c.matchAll(/<Image\b/g)) {
        const end = tagEnd(c, x.index!);
        if (end < 0 || !/\bfill\b(?!\s*=\s*\{?\s*false)/.test(c.slice(x.index!, end))) continue;
        // nearest enclosing JSX element = last unclosed opening tag before the Image
        const before = c.slice(0, x.index!);
        let parent: { name: string; tag: string } | null = null;
        const stack: { name: string; tag: string }[] = [];
        for (const t of before.matchAll(/<(\/?)([A-Za-z][\w.]*)?/g)) {
          if (t[2] === undefined && !t[1]) continue;
          const name = t[2] ?? '';
          if (t[1]) { const i = stack.map((s) => s.name).lastIndexOf(name); if (i >= 0) stack.length = i; continue; }
          const e = tagEnd(c, t.index!);
          if (e < 0 || e > x.index!) continue;
          if (c[e - 2] === '/') continue;
          stack.push({ name, tag: c.slice(t.index!, e) });
        }
        parent = stack[stack.length - 1] ?? null;
        if (!parent || !/^[a-z]/.test(parent.name)) continue; // custom component: its own styles are unknown
        const pc = /className\s*=\s*(?:\{\s*)?["'`]([^"'`]*)["'`]/.exec(parent.tag);
        if (!pc && /className|style/.test(parent.tag)) continue; // dynamic class or inline style: cannot tell
        if (pc && /(?:^|\s)(?:[\w-]+:)?(?:relative|absolute|fixed|sticky)(?:\s|$)/.test(pc[1])) continue;
        if (/position\s*:/.test(parent.tag)) continue;
        add({ ruleId: 29746, code: 'BUG-113', severity: 'MEDIUM', category: 'UI Bug', lineIdx: at(x.index!),
          title: '<Image fill> Inside a Parent Without position: relative',
          why: 'A fill image is absolutely positioned against its nearest positioned ancestor. Without relative/absolute/fixed on the parent it stretches over a larger area (often the whole page) and Next.js warns "has fill and parent element with invalid position".',
          fix: 'Add relative (and a size) to the parent: <div className="relative h-64 w-full"><Image fill ... /></div>.' });
      }
    }

    // BUG-114: content revealed only on hover (touch and keyboard users cannot open it)
    for (const s of classStrings(c)) {
      const tokens = s.text.split(/\s+/);
      const hidden = tokens.some((t) => /^(?:hidden|invisible|opacity-0|scale-0|pointer-events-none)$/.test(t));
      const shown = tokens.find((t) => /^(?:group-hover|peer-hover|hover):(?:block|flex|grid|inline-block|inline-flex|visible|opacity-100|scale-100|pointer-events-auto)$/.test(t));
      if (!hidden || !shown) continue;
      const lt = c.lastIndexOf('<', s.at);
      const te = lt < 0 ? -1 : tagEnd(c, lt);
      if (te < s.at) continue;
      const tag = c.slice(lt, te);
      if (!/^<(?:button|a|Button|Link|input|select|DropdownMenuTrigger|IconButton)\b/.test(tag) && !/\bonClick\s*=/.test(tag)) continue;
      if (tokens.some((t) => /^(?:group-focus-within|group-focus|focus-within|focus|focus-visible|peer-focus|group-data-\[|data-\[|group-aria-|aria-|peer-checked|group-open|open):/.test(t) || /^(?:sm|md|lg|xl)?:?(?:\w+:)*(?:block|flex)$/.test(t) && t.includes(':') && !/hover/.test(t))) continue;
      add({ ruleId: 29747, code: 'BUG-114', severity: 'LOW', category: 'UI Bug', lineIdx: at(s.at),
        title: `Element Only Appears on Hover (${shown})`,
        why: 'Touch screens have no hover and keyboard users never trigger it, so menus, delete buttons or actions hidden this way are unreachable on phones and for keyboard users.',
        fix: `Also show it on focus and keep it visible on touch: add ${shown.replace(/^(?:group-hover|hover|peer-hover)/, shown.startsWith('group') ? 'group-focus-within' : 'focus-within')}, or show it by default below md (md:hidden md:group-hover:flex).` });
    }

    // BUG-117: asChild with more than one child element (React.Children.only throws)
    for (const x of c.matchAll(/<([A-Z][\w.]*)\b[^<>]*?\basChild\b/g)) {
      const end = tagEnd(c, x.index!);
      if (end < 0 || c[end - 2] === '/') continue;
      const close = closingTag(c, x.index!, x[1]);
      if (close < 0) continue;
      const inner = c.slice(end, close);
      // count top-level children: elements and {expressions}, ignoring whitespace
      let n = 0;
      for (let i = 0; i < inner.length; i++) {
        const ch = inner[i];
        if (/\s/.test(ch)) continue;
        if (ch === '{') { const e = closeOf(inner, i); if (e < 0) break; if (!/^\{\s*\/\*/.test(inner.slice(i, e))) n++; i = e - 1; continue; }
        if (ch === '<') {
          const nm = /^<([A-Za-z][\w.]*)?/.exec(inner.slice(i));
          const te = tagEnd(inner, i);
          if (te < 0) break;
          n++;
          if (inner[te - 2] !== '/' && nm?.[1]) { const ce = closingTag(inner, i, nm[1]); if (ce < 0) break; i = inner.indexOf('>', ce); }
          else if (!nm?.[1]) { const ce = inner.indexOf('</>', te); if (ce < 0) break; i = ce + 2; }
          else i = te - 1;
          continue;
        }
        n++; // bare text
        while (i < inner.length && inner[i] !== '<' && inner[i] !== '{') i++;
        i--;
      }
      if (n <= 1) continue;
      add({ ruleId: 29750, code: 'BUG-117', severity: 'HIGH', category: 'UI Bug', lineIdx: at(x.index!),
        title: `<${x[1]} asChild> Has ${n} Children`,
        why: 'asChild merges props into exactly one child element (Radix Slot uses React.Children.only). With several children it throws "React.Children.only expected to receive a single React element child" and the whole component tree crashes.',
        fix: `Wrap the children in one element: <${x[1]} asChild><Link href="...">{icon} Label</Link></${x[1]}>.` });
    }

    // BUG-118: next-themes provider but <html> without suppressHydrationWarning
    if (/from\s+['"]next-themes['"]/.test(c) || /<ThemeProvider\b[^>]*attribute\s*=/.test(c)) {
      const h = /<html\b[^>]*>/.exec(c);
      if (h && !/suppressHydrationWarning/.test(h[0]) && /<ThemeProvider\b/.test(c)) {
        add({ ruleId: 29751, code: 'BUG-118', severity: 'LOW', category: 'UI Bug', lineIdx: at(h.index),
          title: '<html> Lacks suppressHydrationWarning With next-themes',
          why: 'next-themes sets the theme class on <html> before React hydrates, so React reports a hydration mismatch on every page load (and in some setups re-renders the tree, causing a theme flash).',
          fix: 'Add it to the html tag: <html lang="en" suppressHydrationWarning>.' });
      }
    }
  }

  // BUG-112: JSON.parse of a storage value outside try (a corrupted value crashes the app on every load)
  for (const x of c.matchAll(/JSON\.parse\(\s*(?:window\.)?(?:localStorage|sessionStorage)\.getItem\(/g)) {
    const before = c.slice(Math.max(0, x.index! - 4000), x.index!);
    // inside a try block: an unclosed "try {" before us in the same function
    const tryAt = before.lastIndexOf('try');
    if (tryAt >= 0 && /^try\s*\{/.test(before.slice(tryAt))) {
      const open = before.indexOf('{', tryAt) + Math.max(0, x.index! - 4000);
      const end = closeOf(c, open);
      if (end < 0 || end > x.index!) continue;
    }
    if (/\.catch\s*\(|catch\s*\(/.test(c.slice(x.index!, x.index! + 200)) && /try/.test(c.slice(Math.max(0, x.index! - 300), x.index!))) continue;
    add({ ruleId: 29745, code: 'BUG-112', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index!),
      title: 'JSON.parse(localStorage...) Without try/catch',
      why: 'Stored values can be corrupted, edited by the user, written by an older version of the app or set to "undefined". JSON.parse then throws, and because this runs on load the page crashes every time until the user clears site data.',
      fix: 'Wrap it: function read(key, fallback) { try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch { return fallback; } }' });
  }

  // BUG-115: Edge runtime route importing a Node-only module
  if (/export\s+const\s+runtime\s*=\s*['"]edge['"]/.test(c)) {
    for (const x of c.matchAll(/(?:from\s+|require\(\s*)['"](node:[\w/]+|fs|fs\/promises|path|child_process|net|tls|dns|os|crypto|zlib|worker_threads|bcrypt|argon2|sharp|pg|mysql2|mongoose|nodemailer|@prisma\/client|puppeteer|canvas|better-sqlite3|jsonwebtoken)['"]/g)) {
      if (x[1] === 'crypto' && !/\bcrypto\.(?:createHash|createHmac|randomBytes|createCipheriv|scrypt|pbkdf2|timingSafeEqual)\b/.test(c)) continue;
      add({ ruleId: 29748, code: 'BUG-115', severity: 'HIGH', category: 'Deployment Bug', lineIdx: at(x.index!),
        title: `Edge Runtime Route Imports Node-Only "${x[1]}"`,
        why: `This file sets runtime = 'edge', but ${x[1]} needs Node.js APIs the Edge runtime does not have. The build fails ("Module not found" / "The edge runtime does not support Node.js 'X' module") or the route crashes at request time.`,
        fix: `Remove export const runtime = 'edge' (the Node.js runtime is the default), or swap ${x[1]} for a Web-API / edge-compatible alternative (Web Crypto, jose, fetch-based drivers).` });
    }
  }

  // BUG-116: middleware matcher that also runs on _next/static assets and images
  if (/(?:^|\/)(?:src\/)?(?:middleware|proxy)\.[jt]s$/.test(path)) {
    const mm = /matcher\s*:\s*(\[[\s\S]*?\]|['"][^'"]*['"])/.exec(c);
    if (mm && /['"](?:\/:path\*|\/\(\.\*\)|\/\.\*|\/:path\(\.\*\))['"]/.test(mm[1]) && !/_next|\\\.\w|\.\(\?:|api\|/.test(mm[1])) {
      add({ ruleId: 29749, code: 'BUG-116', severity: 'LOW', category: 'Deployment Bug', lineIdx: at(mm.index),
        title: 'Middleware Matcher Also Runs on _next/static Assets and Images',
        why: 'The matcher catches every path, so middleware runs for each JS chunk, CSS file and image. Auth redirects then block stylesheets on the login page (unstyled page), and every asset request costs an extra function invocation.',
        fix: "Exclude static files: matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)']" });
    }
  }

  // BUG-119: fetch in an effect keyed by input, with no abort / ignore flag (old responses overwrite new ones)
  if (isClient || /\buseEffect\s*\(/.test(c)) {
    for (const x of c.matchAll(/\buseEffect\s*\(/g)) {
      const open = x.index! + x[0].length - 1;
      const end = closeOf(c, open);
      if (end < 0) continue;
      const call = c.slice(open, end);
      const deps = /,\s*\[([^\]]*)\]\s*\)$/.exec(call);
      if (!deps || !/\b(?:query|search|q|term|keyword|filter|searchTerm|debouncedQuery|debouncedSearch|input|text)\b/i.test(deps[1])) continue;
      if (!/\bfetch\s*\(|axios\.|\.from\(\s*['"]\w+['"]\s*\)\s*\.select\(/.test(call)) continue;
      if (!/\bset[A-Z]\w*\b/.test(call)) continue;
      if (/AbortController|signal\s*[:,]|\b(?:ignore|cancelled|canceled|active|isMounted|stale|current)\b\s*=|\blatest\w*\b|requestId|reqId/.test(call)) continue;
      add({ ruleId: 29752, code: 'BUG-119', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index!),
        title: 'Search Request in useEffect Can Show Results for an Old Query',
        why: `The effect refetches whenever ${deps[1].trim()} changes but never cancels the previous request. Responses arrive out of order, so a slow reply for "ab" overwrites the results for "abc" and the list no longer matches the input.`,
        fix: 'Cancel or ignore stale requests: const ctrl = new AbortController(); fetch(url, { signal: ctrl.signal })...; return () => ctrl.abort(); (or use an ignore flag, or React Query / SWR keyed by the query).' });
    }
  }

  // BUG-120: React Query mutation that never refreshes any query (UI stays stale after saving)
  if (/from\s+['"]@tanstack\/react-query['"]/.test(c) && /\buseQuery\s*\(/.test(c) && !/invalidateQueries|setQueryData|refetch\w*\s*\(|resetQueries|removeQueries|refetchQueries|optimistic|onMutate/.test(c)) {
    for (const x of c.matchAll(/\buseMutation\s*\(/g)) {
      add({ ruleId: 29753, code: 'BUG-120', severity: 'LOW', category: 'Logic Bug', lineIdx: at(x.index!),
        title: 'useMutation Never Invalidates the Queries This File Shows',
        why: 'The mutation succeeds on the server, but nothing tells React Query that the cached useQuery data changed, so the list keeps showing the old data until a manual reload.',
        fix: "Invalidate on success: const qc = useQueryClient(); useMutation({ mutationFn, onSuccess: () => qc.invalidateQueries({ queryKey: ['todos'] }) })." });
    }
  }

  // BUG-121 (29754) retired before release: "no revalidate in the file" fired on apps that refresh client-side (SWR, next-safe-action).

  // BUG-122: Stripe redirect URL that is relative (Stripe requires an absolute URL)
  if (/\bstripe\b/i.test(c)) {
    for (const x of c.matchAll(/\b(success_url|cancel_url|return_url|refresh_url)\s*:\s*(['"`])(\/[^'"`]*)\2/g)) {
      add({ ruleId: 29755, code: 'BUG-122', severity: 'HIGH', category: 'Logic Bug', lineIdx: at(x.index!),
        title: `Stripe ${x[1]} Is a Relative Path (${x[3]})`,
        why: `Stripe needs an absolute URL for ${x[1]}; a relative path is rejected with "Not a valid URL", so checkout or the billing portal never opens for the customer.`,
        fix: `Prefix your site URL: ${x[1]}: \`\${process.env.NEXT_PUBLIC_SITE_URL}${x[3]}\`` });
    }
  }

  // BUG-123: Vue reactivity lost by destructuring reactive() / setup props
  if (/\.vue$/.test(path) || /from\s+['"]vue['"]/.test(c)) {
    for (const x of c.matchAll(/(?:const|let)\s+\{[^}]+\}\s*=\s*(reactive\s*\(|props\b(?!\s*\.)|useStore\(\)|store\b(?!\s*\.))/g)) {
      if (/^props/.test(x[1]) && !/setup\s*\(\s*props\b/.test(c)) continue; // <script setup> defineProps destructure is reactive in Vue 3.5
      if (/^(?:store|useStore)/.test(x[1]) && !/from\s+['"]pinia['"]/.test(c)) continue;
      add({ ruleId: 29756, code: 'BUG-123', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index!),
        title: 'Destructuring a Reactive Object Loses Reactivity',
        why: 'Destructuring copies the current values out of the reactive proxy, so the variables never update when the state changes and the template shows stale values.',
        fix: /^(?:store|useStore)/.test(x[1]) ? 'Use storeToRefs: const { count } = storeToRefs(store).' : 'Use toRefs: const { a, b } = toRefs(state) (or access state.a directly).' });
    }
  }

  // BUG-124: React Native Platform.OS compared with a value it never has
  for (const x of c.matchAll(/Platform\.OS\s*[!=]==?\s*['"]([^'"]+)['"]/g)) {
    if (/^(?:ios|android|web|windows|macos|native)$/.test(x[1])) continue;
    add({ ruleId: 29757, code: 'BUG-124', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index!),
      title: `Platform.OS Compared With "${x[1]}"`,
      why: `Platform.OS is always lowercase: "ios", "android", "web", "windows" or "macos". Comparing with "${x[1]}" is never true, so the platform-specific branch never runs.`,
      fix: `Use the exact value, e.g. Platform.OS === '${x[1].toLowerCase().includes('io') || /iphone|apple/i.test(x[1]) ? 'ios' : x[1].toLowerCase()}' (or Platform.select({ ios, android })).` });
  }
}

export function evaluateLogicFrontendRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}, context?: RepoContext): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (!/\.(?:[cm]?[jt]sx?|vue)$/i.test(path) || SKIP.test(path)) return { findings, logs };
  const c = cleanContent;
  if (!c || c.length > 400_000) return { findings, logs };

  const hits: Hit[] = [];
  const add = (h: Hit) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  evaluate(path, c, add, context);

  const raw = file.content.split('\n');
  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `bug${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'VIBECARE',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category ?? 'Logic Bug',
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
