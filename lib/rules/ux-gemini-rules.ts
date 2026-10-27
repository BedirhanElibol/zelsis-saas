/**
 * Accessibility and front-end performance defects from the Gemini rule report that no existing rule caught
 * (UXG-01.., Rule IDs 30000-30099). Findings are VIBEPOLISH (never gate a release) except a raw stack trace rendered
 * to users, which is SECURITY. Each rule matches markup or an import that is wrong in every context: aria-label that
 * hides the visible label, links wrapping buttons, carousels that cannot be paused, whole-library imports in client
 * bundles, priority images inside lists, formatters rebuilt for every row.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; type: Finding['type']; category: string; lineIdx: number; why: string; fix: string }
type Add = (h: Hit) => void;

const SKIP = /\.d\.ts$|(?:^|\/)node_modules\/|(?:^|\/)vendor\/|\.min\.js$|(?:^|\/)(?:tests?|__tests__|e2e|stories|__mocks__|fixtures?)\/|\.(?:test|spec|stories)\.[jt]sx?$/i;
const lineAt = (c: string, off: number) => { let n = 0; for (let i = 0; i < off && i < c.length; i++) if (c.charCodeAt(i) === 10) n++; return n; };

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

function evaluate(path: string, c: string, add: Add) {
  const at = (off: number) => lineAt(c, off);
  const isJsx = /\.[jt]sx$/i.test(path);
  const isClient = isJsx || /^\s*['"]use client['"]/m.test(c) || /\.(?:vue|svelte)$/i.test(path);

  if (isJsx) {
    // UXG-01: aria-label replaces the visible text (WCAG 2.5.3 Label in Name)
    for (const m of c.matchAll(/<(button|a|Link|Button)\b[^>]*\baria-label=["']([^"']+)["'][^>]*>\s*([^<{}\n]{2,40}?)\s*<\/\1>/g)) {
      const visible = m[3].trim().toLowerCase();
      if (!/[a-z]/i.test(visible) || m[2].toLowerCase().includes(visible)) continue;
      add({ ruleId: 30000, code: 'UXG-01', severity: 'MEDIUM', type: 'VIBEPOLISH', category: 'Accessibility', lineIdx: at(m.index!),
        title: `aria-label "${m[2].slice(0, 30)}" Hides the Visible Text "${m[3].trim().slice(0, 20)}"`,
        why: 'Screen readers announce the aria-label instead of the visible text, and voice-control users who say what they see ("click Cancel") cannot activate the control (WCAG 2.5.3).',
        fix: `Remove the aria-label, or make it start with the visible text: aria-label="${m[3].trim()} …".` });
    }

    // UXG-02: choosing an option in a <select> navigates or submits immediately
    for (const m of c.matchAll(/<select\b[^>]*\bonChange=\{/g)) {
      const end = closeOf(c, m.index! + m[0].length - 1);
      const handler = c.slice(m.index!, end);
      if (!/\b(?:router\.(?:push|replace)|navigate\(|location\.(?:href|assign)|window\.location|\.submit\(|requestSubmit\()/.test(handler)) continue;
      add({ ruleId: 30001, code: 'UXG-02', severity: 'MEDIUM', type: 'VIBEPOLISH', category: 'Accessibility', lineIdx: at(m.index!),
        title: '<select> Navigates or Submits on Change',
        why: 'Keyboard users move through options with the arrow keys, which fires onChange on every step, so they are sent to a new page before reaching the option they want (WCAG 3.2.2).',
        fix: 'Apply the choice with a separate Go / Apply button, or use a menu of links instead of a <select>.' });
    }

    // UXG-03: third-party analytics / chat loaded with beforeInteractive
    for (const m of c.matchAll(/<Script\b[^>]*\bstrategy=["']beforeInteractive["'][^>]*>/g)) {
      if (!/googletagmanager|google-analytics|gtag|hotjar|clarity\.ms|intercom|crisp|tawk|segment|posthog|mixpanel|facebook|fbevents|hubspot|plausible|umami|tiktok/i.test(m[0])) continue;
      add({ ruleId: 30002, code: 'UXG-03', severity: 'MEDIUM', type: 'VIBEPOLISH', category: 'Web Performance', lineIdx: at(m.index!),
        title: 'Analytics / Chat Script Loaded With strategy="beforeInteractive"',
        why: 'beforeInteractive scripts load and run before the page hydrates, so a tracking or chat widget delays first input and LCP for every visitor.',
        fix: 'Use strategy="afterInteractive" (or "lazyOnload" for chat widgets).' });
    }

    // UXG-06: priority image inside a list
    for (const m of c.matchAll(/\.map\(\s*\(?[^)]*\)?\s*=>/g)) {
      const end = closeOf(c, m.index! + 4);
      if (end < 0) continue;
      const body = c.slice(m.index!, end);
      const p = /<Image\b[^>]*\s(?:priority(?:=\{true\})?|fetchPriority=["']high["'])(?=[\s/>])[^>]*>/.exec(body);
      if (p) add({ ruleId: 30005, code: 'UXG-06', severity: 'MEDIUM', type: 'VIBEPOLISH', category: 'Web Performance', lineIdx: at(m.index! + p.index),
        title: 'priority on Every Image Rendered by .map()',
        why: 'Each image in the list is preloaded with high priority, so they compete with the real LCP image and the page paints later (and loads images that are off-screen).',
        fix: 'Mark only the first visible image: priority={index === 0}.' });
    }

    // UXG-08: interactive element nested inside a link or button
    for (const m of c.matchAll(/<(a|Link|button|Button)\b(?:[^>"']|"[^"]*"|'[^']*'|\{[^}]*\})*>/g)) {
      // asChild (Radix Slot) renders the child as the element itself: <Button asChild><Link/></Button> is one control
      if (m[0].endsWith('/>') || /\basChild\b/.test(m[0])) continue;
      const tag = m[1];
      const close = c.indexOf(`</${tag}>`, m.index! + m[0].length);
      if (close < 0) continue;
      const inner = c.slice(m.index! + m[0].length, close);
      if (inner.length > 1500 || new RegExp(`<${tag}\\b`).test(inner)) continue;
      // Native controls only: a custom <Button> / <Link> may not render a real button or anchor
      const n = /<(button|a|input|select|textarea)\b(?![^>]*\b(?:asChild|type=["'](?:hidden|file)["']|hidden\b|getInputProps))/.exec(inner);
      if (!n) continue;
      add({ ruleId: 30007, code: 'UXG-08', severity: 'MEDIUM', type: 'VIBEPOLISH', category: 'Accessibility', lineIdx: at(m.index! + m[0].length + n.index),
        title: `<${n[1]}> Nested Inside <${tag}>`,
        why: 'Interactive elements inside a link or button are invalid HTML: clicking the inner control also triggers the outer one (navigating away instead of deleting), and screen readers announce a confusing merged control.',
        fix: `Move the inner control outside the <${tag}> (for example, a card with a stretched link and a separate button).` });
    }

    // UXG-10: tooltip / popover that opens only on mouse hover (non-focusable elements; buttons can still be clicked)
    // The tag is read past arrow handlers (onMouseLeave={() => ...}) so an onFocus after them still counts
    for (const m of c.matchAll(/<(?:div|span|aside|li|p|img|section|td|tr|svg|label)\b(?:=>|[^>])*?\bonMouseEnter=\{[^}]*\bset\w+\(\s*true\s*\)[^}]*\}(?:=>|[^>])*>/g)) {
      if (/\bonFocus=|\bonClick=|\bonKeyDown=|\bonPointerDown=/.test(m[0])) continue;
      add({ ruleId: 30009, code: 'UXG-10', severity: 'MEDIUM', type: 'VIBEPOLISH', category: 'Accessibility', lineIdx: at(m.index!),
        title: 'Content Revealed Only on Mouse Hover',
        why: 'Keyboard and touch users never trigger onMouseEnter, so the tooltip or menu it opens is unreachable for them (WCAG 1.4.13 / 2.1.1).',
        fix: 'Also open it on focus (onFocus / onBlur) or click, or use an accessible Tooltip / Popover primitive (Radix, Headless UI).' });
    }

    // UXG-12: raw stack trace rendered to users
    for (const m of c.matchAll(/\{\s*(?:error|err|e)\??\.stack\s*\}/g)) {
      add({ ruleId: 30011, code: 'UXG-12', severity: 'MEDIUM', type: 'SECURITY', category: 'Information Disclosure', lineIdx: at(m.index!),
        title: 'Error Stack Trace Rendered in the UI',
        why: 'Stack traces reveal file paths, library versions and internal function names that help attackers, and show users a wall of code instead of a way forward.',
        fix: 'Show a short message with a retry action; log the stack (Sentry / console) and render it only when process.env.NODE_ENV === "development".' });
    }
  }

  if (isClient) {
    // UXG-04: icon library namespace import with dynamic lookup
    for (const m of c.matchAll(/\bimport\s+\*\s+as\s+(\w+)\s+from\s+['"](lucide-react|react-icons\/\w+|@heroicons\/react\/[\w/]+|@tabler\/icons-react|react-feather|@phosphor-icons\/react|@radix-ui\/react-icons)['"]/g)) {
      if (!new RegExp(`\\b${m[1]}\\s*(?:as\\s+[^)\\]]+\\))?\\s*\\[|\\(\\s*${m[1]}\\s+as\\s+[^)]+\\)\\s*\\[|Object\\.(?:keys|values|entries)\\(\\s*${m[1]}\\b`).test(c)) continue;
      add({ ruleId: 30003, code: 'UXG-04', severity: 'HIGH', type: 'VIBEPOLISH', category: 'Web Performance', lineIdx: at(m.index!),
        title: `Every Icon in ${m[2]} Bundled (Dynamic ${m[1]}[name] Lookup)`,
        why: `Looking icons up by name defeats tree-shaking, so the whole ${m[2]} set (hundreds of KB to MB) ships to every visitor and slows first load.`,
        fix: 'Import the icons you use by name and map them: const ICONS = { home: Home, user: User }.' });
    }

    // UXG-05: full lodash in client code
    for (const m of c.matchAll(/\bimport\s+(?:_|lodash|\*\s+as\s+_)\s+from\s+['"]lodash['"]|\brequire\(\s*['"]lodash['"]\s*\)/g)) {
      if (!/\.[jt]sx$|\.(?:vue|svelte)$/i.test(path) && !/^\s*['"]use client['"]/m.test(c)) continue;
      add({ ruleId: 30004, code: 'UXG-05', severity: 'MEDIUM', type: 'VIBEPOLISH', category: 'Web Performance', lineIdx: at(m.index!),
        title: 'Whole lodash Imported in Client Code',
        why: 'The default lodash import is CommonJS and pulls the entire library (~70 KB min) into the browser bundle even if you use one function.',
        fix: "Import single functions (import debounce from 'lodash/debounce'), use lodash-es, or native methods." });
    }

    // UXG-07: auto-advancing carousel that cannot be paused
    for (const m of c.matchAll(/\bsetInterval\(\s*\(\)\s*=>\s*\{?\s*set(?:Current|Active|Slide|Index|Carousel|Banner|Testimonial|Hero|Image|Selected)\w*\(\s*\(?\s*(\w+)\s*\)?\s*=>\s*\(?\s*\1\s*\+\s*1\s*\)?\s*%/g)) {
      if (/\b(?:paused|isPaused|setPaused|pause|isHover\w*|isPlaying|setPlaying|autoplay\s*=\s*false|onMouseEnter|stopAutoplay)\b/i.test(c)) continue;
      add({ ruleId: 30006, code: 'UXG-07', severity: 'MEDIUM', type: 'VIBEPOLISH', category: 'Accessibility', lineIdx: at(m.index!),
        title: 'Auto-Advancing Carousel Without a Pause Control',
        why: 'Content that moves on its own for more than 5 seconds must be pausable: slides change while people are still reading, and screen-reader and keyboard users lose their place (WCAG 2.2.2).',
        fix: 'Add a visible pause / play button, pause on hover and focus, and respect prefers-reduced-motion.' });
    }

    // UXG-11: Intl formatter constructed for every list item
    for (const m of c.matchAll(/\.map\(\s*\(?[^)]*\)?\s*=>/g)) {
      const end = closeOf(c, m.index! + 4);
      if (end < 0) continue;
      const body = c.slice(m.index!, end);
      const f = /\bnew\s+Intl\.(NumberFormat|DateTimeFormat|RelativeTimeFormat|Collator|PluralRules)\(/.exec(body);
      if (f) add({ ruleId: 30010, code: 'UXG-11', severity: 'MEDIUM', type: 'VIBEPOLISH', category: 'Web Performance', lineIdx: at(m.index! + f.index),
        title: `new Intl.${f[1]}() Created for Every Item`,
        why: `Building an Intl.${f[1]} loads locale data and is far slower than formatting; doing it per row makes long tables and lists janky (slow INP).`,
        fix: `Create the formatter once at module level (const fmt = new Intl.${f[1]}(…)) and call fmt.format(value) in the loop.` });
    }
  }
}

export function evaluateUxGeminiRules(file: CodeFile, _lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (SKIP.test(path) || !/\.(?:[cm]?[jt]sx?|vue|svelte)$/i.test(path)) return { findings, logs };
  const c = cleanContent;
  if (!c || c.length > 400_000) return { findings, logs };

  const hits: Hit[] = [];
  const add: Add = (h) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  evaluate(path, c, add);

  const raw = file.content.split('\n');
  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `uxg${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
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
      owner: 'Frontend Engineering',
      falsePositive: false
    });
    logs.push(`[${ts}] [UX] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
