/**
 * Frontend bugs that need more than one file to prove (BUG-125.., Rule IDs 29758-29779): imports that only resolve on
 * case-insensitive disks, links to pages that do not exist, next/image hosts missing from next.config, static export
 * with server features, useSearchParams without a Suspense boundary, Zustand v5 selectors, Expo env vars, React 19
 * defaultProps. Candidates came from .cache/rule-research-fullapp-2.md.
 *
 * Reliability findings (type VIBECARE). Each rule reads the repo context (file list, package.json majors, next.config)
 * and stays quiet when that context is missing, so single-file and partial scans never guess.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import type { RepoContext } from '../scanner/repo-context';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

const SKIP = /\.d\.ts$|(?:^|\/)node_modules\/|\.min\.js$|(?:^|\/)(?:tests?|__tests__|e2e|stories|__mocks__|fixtures?)\/|\.(?:test|spec|stories)\.[jt]sx?$/i;
const CODE_EXT = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];
const lineAt = (c: string, off: number) => { let n = 0; for (let i = 0; i < off && i < c.length; i++) if (c.charCodeAt(i) === 10) n++; return n; };

const dirOf = (p: string) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
function joinPath(base: string, rel: string): string {
  const out = base ? base.split('/') : [];
  for (const part of rel.split('/')) {
    if (part === '.' || part === '') continue;
    if (part === '..') { if (!out.length) return '\0'; out.pop(); } else out.push(part);
  }
  return out.join('/');
}

/** Route patterns from app/**\/page.* and pages/** (route groups and parallel slots removed), as regexes. */
function routePatterns(paths: Set<string>): { app: boolean; patterns: RegExp[] } {
  const patterns: RegExp[] = [];
  let app = false;
  for (const p of paths) {
    let m = /^(?:src\/)?app\/(.*?)\/?page\.(?:[jt]sx?|mdx?)$/.exec(p) ?? /^(?:src\/)?app\/()page\.(?:[jt]sx?|mdx?)$/.exec(p);
    let segs: string[];
    if (m) { app = true; segs = m[1].split('/').filter(Boolean); }
    else if ((m = /^(?:src\/)?pages\/(.+)\.(?:[jt]sx?|mdx?)$/.exec(p)) && !/^(?:api\/|_)/.test(m[1])) segs = m[1].replace(/(?:^|\/)index$/, '').split('/').filter(Boolean);
    else continue;
    let re = '';
    let optionalTail = false;
    for (const s of segs) {
      if (/^\(.*\)$/.test(s) || s.startsWith('@')) continue; // route group / parallel route
      if (/^\[\[\.\.\..+\]\]$/.test(s)) { optionalTail = true; break; }
      if (/^\[\.\.\..+\]$/.test(s)) { re += '/.+'; break; }
      re += /^\[.+\]$/.test(s) ? '/[^/]+' : '/' + s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
    patterns.push(new RegExp(`^${re}${optionalTail ? '(?:/.*)?' : ''}/?$`, 'i'));
  }
  return { app, patterns };
}

function hostAllowed(host: string, allowed: string[]): boolean {
  return allowed.some((a) => {
    if (a === host) return true;
    if (a.startsWith('**.')) return host.endsWith(a.slice(2)) || host === a.slice(3);
    if (a.startsWith('*.')) { const rest = a.slice(2); return host.endsWith('.' + rest) && host.slice(0, -rest.length - 1).indexOf('.') === -1; }
    return false;
  });
}

function evaluate(path: string, c: string, ctx: RepoContext, add: (h: Hit) => void) {
  const at = (off: number) => lineAt(c, off);
  const paths = ctx.filePaths;
  const lower = new Map<string, string>();
  for (const p of paths) lower.set(p.toLowerCase(), p);
  const srcRoot = [...paths].some((p) => p.startsWith('src/app/') || p.startsWith('src/components/')) ? 'src/' : '';

  // BUG-125: import whose path only matches a file with different letter case (works on macOS/Windows, fails on Linux/Vercel)
  for (const x of c.matchAll(/(?:\bfrom\s+|\bimport\s*\(\s*|\brequire\s*\(\s*|^\s*import\s+)(['"])((?:\.{1,2}\/|@\/|~\/)[^'"]+)\1/gm)) {
    const spec = x[2];
    const rel = spec.startsWith('@/') || spec.startsWith('~/') ? joinPath(srcRoot.replace(/\/$/, ''), spec.slice(2)) : joinPath(dirOf(path), spec);
    if (rel === '\0') continue;
    const candidates = /\.\w+$/.test(rel) ? [rel] : [...CODE_EXT.map((e) => rel + e), ...CODE_EXT.map((e) => `${rel}/index${e}`)];
    if (candidates.some((k) => paths.has(k))) continue;
    const wrong = candidates.map((k) => lower.get(k.toLowerCase())).find(Boolean);
    if (!wrong) continue; // file not in the scan (asset, alias, generated): unknown, stay quiet
    add({ ruleId: 29758, code: 'BUG-125', severity: 'HIGH', category: 'Deployment Bug', lineIdx: at(x.index!),
      title: `Import "${spec}" Matches ${wrong} Only by Ignoring Case`,
      why: 'macOS and Windows file systems ignore letter case, so this import works locally. Vercel and most CI run Linux, where it is a different path: the build fails with "Module not found: Can\'t resolve".',
      fix: `Match the file name exactly (${wrong}), or rename the file with git mv so the import and the file agree.` });
  }

  const isAppFile = /^(?:src\/)?(?:app|components|lib|hooks|features|ui|pages)\//.test(path) || /\.(?:jsx|tsx)$/.test(path);

  // BUG-126: internal link to a route that has no page
  if (isAppFile && ctx.nextConfig && !ctx.nextConfig.remapsRoutes && ![...paths].some((p) => /(?:^|\/)(?:middleware|proxy)\.[jt]s$/.test(p))) {
    const { app, patterns } = routePatterns(paths);
    if (app && patterns.length >= 2) {
      for (const x of c.matchAll(/(?:<Link\b[^>]*?\bhref\s*=\s*(?:\{\s*)?|\brouter\.(?:push|replace)\(\s*|\bredirect\(\s*)(['"`])(\/[^'"`?#\s$]*)\1/g)) {
        const href = x[2];
        if (href === '/' || /\.\w{2,5}$/.test(href) || /^\/(?:api|_next|static|public|auth\/callback)\b/.test(href)) continue;
        if (patterns.some((re) => re.test(href))) continue;
        if ([...paths].some((p) => p === `public${href}` || p.startsWith(`public${href}/`))) continue;
        add({ ruleId: 29759, code: 'BUG-126', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index!),
          title: `Link to ${href}, but No Page Exists at That Route`,
          why: `No app/**/page or pages/** file serves ${href}, so users who follow this link get a 404 page.`,
          fix: `Point the link at an existing route, or add app${href}/page.tsx.` });
      }
    }
  }

  // BUG-127: next/image with a remote host that next.config does not allow
  if (ctx.nextConfig?.imageHosts && /from\s+['"]next\/image['"]/.test(c)) {
    const allowed = ctx.nextConfig.imageHosts;
    for (const x of c.matchAll(/<Image\b[^>]*?\bsrc\s*=\s*(?:\{\s*)?(['"`])https?:\/\/([^/'"`$:]+)/g)) {
      const host = x[2].toLowerCase();
      if (hostAllowed(host, allowed)) continue;
      add({ ruleId: 29760, code: 'BUG-127', severity: 'HIGH', category: 'UI Bug', lineIdx: at(x.index!),
        title: `next/image Loads ${host}, Which next.config Does Not Allow`,
        why: `next/image only optimizes hosts listed in images.remotePatterns. ${host} is not listed, so the component throws "Invalid src prop ... hostname is not configured" and the page errors (or the image is blocked in production).`,
        fix: `Add it to next.config: images: { remotePatterns: [{ protocol: 'https', hostname: '${host}' }] }.` });
    }
  }

  // BUG-128: static export with features that need a server
  if (ctx.nextConfig?.outputExport) {
    const checks: [RegExp, string][] = [
      [/^\s*(['"])use server\1/m, 'a Server Action ("use server")'],
      [/\b(?:cookies|headers|draftMode)\s*\(\s*\)/, 'cookies() / headers()'],
      [/export\s+const\s+dynamic\s*=\s*['"]force-dynamic['"]/, "dynamic = 'force-dynamic'"],
      [/export\s+const\s+revalidate\s*=\s*\d/, 'ISR (export const revalidate)'],
    ];
    if (/(?:^|\/)(?:src\/)?(?:middleware|proxy)\.[jt]s$/.test(path)) checks.unshift([/export\s+(?:async\s+)?function\s+(?:middleware|proxy)|export\s+default/, 'middleware']);
    if (/(?:^|\/)app\/.*route\.[jt]s$/.test(path)) checks.unshift([/export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\b/, 'a POST/PUT/PATCH/DELETE route handler']);
    for (const [re, what] of checks) {
      const x = re.exec(c);
      if (!x) continue;
      add({ ruleId: 29761, code: 'BUG-128', severity: 'HIGH', category: 'Deployment Bug', lineIdx: at(x.index),
        title: `${what} in an App Built With output: 'export'`,
        why: `next.config sets output: 'export', which produces static HTML with no server. ${what} needs a server, so next build fails (or the feature silently does nothing on the static host).`,
        fix: "Remove output: 'export' to deploy with a server (Vercel, Node), or move this logic to the client / an external API." });
      break;
    }
  }

  // BUG-129: useSearchParams in a client page with no Suspense boundary (build error since Next.js 15)
  if ((ctx.nextMajorVersion ?? 0) >= 15 && /^(?:src\/)?app\/(?:.*\/)?page\.[jt]sx?$/.test(path) && /^\s*(['"])use client\1/.test(c) && /\buseSearchParams\s*\(/.test(c) &&
      !/export\s+const\s+dynamic\s*=\s*['"]force-dynamic['"]/.test(c)) {
    let dir = dirOf(path);
    let hasLoading = false;
    while (dir && /app/.test(dir)) {
      if (CODE_EXT.some((e) => paths.has(`${dir}/loading${e}`))) { hasLoading = true; break; }
      dir = dirOf(dir);
    }
    if (!hasLoading) {
      const x = /\buseSearchParams\s*\(/.exec(c)!;
      add({ ruleId: 29762, code: 'BUG-129', severity: 'HIGH', category: 'Deployment Bug', lineIdx: at(x.index),
        title: 'useSearchParams() in a Client Page Without a Suspense Boundary',
        why: 'During next build the page is prerendered, and useSearchParams() without a <Suspense> boundary above it fails the build: "useSearchParams() should be wrapped in a suspense boundary at page ...".',
        fix: 'Move the part that reads search params into its own component and render it as <Suspense fallback={...}><Filters /></Suspense> from a server page.tsx, or add a loading.tsx to this route.' });
    }
  }

  // BUG-130: Zustand v5 selector that returns a new object / array every time (infinite render loop)
  if ((ctx.packageMajors.get('zustand') ?? 0) >= 5) {
    for (const x of c.matchAll(/\b(use[A-Z]\w*)\(\s*\(?\s*(\w+)\s*\)?\s*=>\s*(\(\s*\{|\[)/g)) {
      if (!new RegExp(`\\b${x[1]}\\s*=\\s*create\\b|import\\s*\\{[^}]*\\b${x[1]}\\b[^}]*\\}\\s*from\\s*['"][^'"]*(?:store|state)[^'"]*['"]|\\b${x[1]}\\b[^\\n]*from\\s*['"][^'"]*(?:store|state)`, 'i').test(c) && !/Store$|State$/.test(x[1])) continue;
      const before = c.slice(Math.max(0, x.index! - 20), x.index!);
      if (/useShallow\(\s*$/.test(before)) continue;
      const open = c.indexOf('(', x.index!);
      const tail = c.slice(open, open + 600);
      if (/,\s*(?:shallow|useShallow|Object\.is|\(\s*a\s*,\s*b\s*\)\s*=>)/.test(tail.split(/\)\s*;/)[0])) continue;
      add({ ruleId: 29763, code: 'BUG-130', severity: 'HIGH', category: 'Logic Bug', lineIdx: at(x.index!),
        title: `${x[1]} Selector Returns a New ${x[3].startsWith('[') ? 'Array' : 'Object'} on Every Call (Zustand v5)`,
        why: 'Zustand v5 compares selector results with Object.is. A selector that builds a new object/array each time always looks changed, so the component re-renders forever: "Maximum update depth exceeded" crashes the page.',
        fix: `Wrap it with useShallow: ${x[1]}(useShallow((s) => ({ ... }))) (import { useShallow } from 'zustand/react/shallow'), or select each field separately.` });
    }
  }

  // BUG-131: Expo app code reads an env var without the EXPO_PUBLIC_ prefix (undefined in the app)
  // the file's own package (nearest package.json) must be the Expo app; monorepos also hold Next.js apps
  const pkgDirs = [...paths].filter((p) => /(?:^|\/)package\.json$/.test(p) && !/node_modules\//.test(p)).map((p) => dirOf(p));
  const ownPkg = pkgDirs.filter((d) => d === '' || path.startsWith(d + '/')).sort((a, b) => b.length - a.length)[0];
  if (ownPkg !== undefined && ctx.expoPackageDirs.has(ownPkg) && !/(?:^|\/)(?:app|metro|babel|eas|jest)\.config\.[jt]s$|\+api\.[jt]sx?$|(?:^|\/)(?:scripts|server|api|functions|supabase)\//.test(path)) {
    for (const x of c.matchAll(/\bprocess\.env\.([A-Z][A-Z0-9_]*)\b/g)) {
      if (/^(?:EXPO_PUBLIC_|NODE_ENV$|EXPO_OS$|EXPO_ROUTER_|EXPO_)/.test(x[1])) continue;
      add({ ruleId: 29764, code: 'BUG-131', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index!),
        title: `process.env.${x[1]} Is Undefined in the Expo App`,
        why: 'Expo only inlines environment variables that start with EXPO_PUBLIC_ into the app bundle. Others are undefined on the device, so API calls go to "undefined/..." and the feature fails only in the built app.',
        fix: `Rename it to EXPO_PUBLIC_${x[1]} (only for values that are safe to ship in the app), or read it in app.config.js and pass it through extra.` });
    }
  }

  // BUG-132: defaultProps on a function component (ignored since React 19)
  if ((ctx.packageMajors.get('react') ?? 0) >= 19) {
    for (const x of c.matchAll(/^\s*([A-Z]\w*)\.defaultProps\s*=/gm)) {
      const name = x[1];
      if (new RegExp(`class\\s+${name}\\b`).test(c)) continue;
      if (!new RegExp(`function\\s+${name}\\s*\\(|(?:const|let)\\s+${name}\\s*(?::[^=]+)?=\\s*(?:React\\.)?(?:memo\\(|forwardRef\\(|\\(|async\\s*\\(|\\w+\\s*=>)`).test(c)) continue;
      add({ ruleId: 29765, code: 'BUG-132', severity: 'MEDIUM', category: 'Logic Bug', lineIdx: at(x.index!),
        title: `${name}.defaultProps Is Ignored in React 19`,
        why: 'React 19 removed defaultProps for function components. The defaults are no longer applied, so props that relied on them are undefined and the component renders wrong or crashes.',
        fix: `Use default parameter values: function ${name}({ size = "md", ...props }) { ... }` });
    }
  }
}

export function evaluateLogicCrossFileRules(file: CodeFile, _lines: string[], cleanContent: string, findingCounter: {
  count: number;
}, context?: RepoContext): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/').replace(/^\.\//, '');
  if (!context || context.filePaths.size < 2 || !/\.[cm]?[jt]sx?$/i.test(path) || SKIP.test(path)) return { findings, logs };
  const c = cleanContent;
  if (!c || c.length > 400_000) return { findings, logs };

  const hits: Hit[] = [];
  const add = (h: Hit) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  evaluate(path, c, context, add);

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
