/**
 * Measurable UI quality: WCAG 2.2 accessibility and UX defects detectable in JSX/HTML (A11Y-01.., Rule IDs 28601-28699).
 *
 * Every rule maps to a WCAG 2.2 success criterion and to an established checker (axe-core, eslint-plugin-jsx-a11y,
 * Lighthouse). Each fires on one concrete element, never on a whole-file absence. Elements with spread props
 * ({...props}) are skipped by every rule that depends on an attribute being missing.
 *
 * A11Y-13 (28613, heading level skipped) was dropped: axe classes heading-order as best practice, not a WCAG failure,
 * and it fired ~26 times across maintained benchmark repos.
 *
 * Deliberately NOT here because a surviving rule already covers it: <html> without lang (7138), viewport zoom lock
 * (1244), <video autoPlay> without muted (1232), autoFocus (1204), target=_blank without rel (274),
 * <div onClick> without role/tabIndex (1029), unlabelled <input> and outline-none (1026), tiny touch targets (1044).
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; offset: number; why: string; fix: string; wcag: string }

interface Attr { raw: string; str?: string }
interface Tag { name: string; start: number; end: number; selfClosing: boolean; attrs: Map<string, Attr>; spread: boolean }

const UI_FILE = /\.(?:tsx|jsx|html?|vue|svelte|astro)$/i;

/** Reads a JSX/HTML opening tag at `start` (pointing at '<'), balancing quotes and {expressions}. */
function readTag(src: string, start: number): Tag | null {
  const m = /^<([A-Za-z][\w.:-]*)/.exec(src.slice(start, start + 80));
  if (!m) return null;
  const name = m[1];
  let i = start + m[0].length;
  const limit = Math.min(src.length, start + 4000);
  let depth = 0;
  let quote = '';
  for (; i < limit; i++) {
    const ch = src[i];
    if (quote) {
      if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '{') depth++;
    else if (ch === '}') depth--;
    else if (ch === '<' && depth === 0) return null;
    else if (ch === '>' && depth === 0) {
      const attrStr = src.slice(start + m[0].length, i);
      const selfClosing = /\/\s*$/.test(attrStr);
      const { attrs, spread } = parseAttrs(selfClosing ? attrStr.replace(/\/\s*$/, '') : attrStr);
      return { name, start, end: i + 1, selfClosing, attrs, spread };
    }
  }
  return null;
}

function readBalanced(s: string, i: number): number {
  let depth = 0;
  let quote = '';
  for (; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') quote = ch;
    else if (ch === '{') depth++;
    else if (ch === '}' && --depth === 0) return i + 1;
  }
  return s.length;
}

function parseAttrs(s: string): { attrs: Map<string, Attr>; spread: boolean } {
  const attrs = new Map<string, Attr>();
  let spread = false;
  let i = 0;
  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (i >= s.length) break;
    if (s[i] === '{') {
      const e = readBalanced(s, i);
      if (/^\{\s*\.\.\./.test(s.slice(i, e))) spread = true;
      i = e;
      continue;
    }
    const nm = /^[^\s=/>{]+/.exec(s.slice(i));
    if (!nm) { i++; continue; }
    // Normalise framework binding syntax: Vue :x / v-bind:x / @click, Angular [x] / [attr.x] / (click), Svelte on:click.
    const name = nm[0].toLowerCase()
      .replace(/^(?:v-bind)?:/, '')
      .replace(/^\[(?:attr\.)?([^\]]+)\]$/, '$1')
      .replace(/^(?:@|on:|\()([a-z]+)(?:[.|][\w.|]+)?\)?$/, 'on$1');
    i += nm[0].length;
    while (i < s.length && /\s/.test(s[i])) i++;
    if (s[i] !== '=') { attrs.set(name, { raw: '', str: 'true' }); continue; }
    i++;
    while (i < s.length && /\s/.test(s[i])) i++;
    const q = s[i];
    if (q === '"' || q === "'") {
      const e = s.indexOf(q, i + 1);
      const end = e === -1 ? s.length : e;
      attrs.set(name, { raw: s.slice(i, end + 1), str: s.slice(i + 1, end) });
      i = end + 1;
    } else if (q === '{') {
      const e = readBalanced(s, i);
      const raw = s.slice(i, e);
      const inner = raw.slice(1, -1).trim();
      const lit = /^(["'`])([^"'`$]*)\1$/.exec(inner);
      const str = lit ? lit[2] : /^(?:-?\d+|true|false)$/.test(inner) ? inner : undefined;
      attrs.set(name, { raw, str });
      i = e;
    } else {
      const v = /^[^\s>]+/.exec(s.slice(i));
      attrs.set(name, { raw: v ? v[0] : '', str: v ? v[0] : '' });
      i += v ? v[0].length : 1;
    }
  }
  return { attrs, spread };
}

/** All opening tags whose name matches `nameRe` (prev char must not be an identifier char, which rules out TS generics). */
function findTags(src: string, nameRe: RegExp): Tag[] {
  const out: Tag[] = [];
  const re = /<([A-Za-z][\w.:-]*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    if (!nameRe.test(m[1])) continue;
    const prev = m.index > 0 ? src[m.index - 1] : ' ';
    if (/[\w$.)\]]/.test(prev)) continue;
    const t = readTag(src, m.index);
    if (t) out.push(t);
  }
  return out;
}

/** Inner content of an element (between its opening tag and matching close tag), or null if not found. */
function innerOf(src: string, tag: Tag): string | null {
  if (tag.selfClosing) return '';
  const esc = tag.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`<${esc}(?![\\w.:-])|<\\/${esc}\\s*>`, 'g');
  re.lastIndex = tag.end;
  let depth = 1;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    if (m.index - tag.end > 6000) return null;
    if (m[0].startsWith('</')) {
      if (--depth === 0) return src.slice(tag.end, m.index);
    } else {
      const t = readTag(src, m.index);
      if (t && !t.selfClosing) depth++;
    }
  }
  return null;
}

const has = (t: Tag, ...names: string[]) => names.some((n) => t.attrs.has(n));
const strOf = (t: Tag, n: string) => t.attrs.get(n)?.str;
const rawOf = (t: Tag, n: string) => t.attrs.get(n)?.raw ?? '';
const isTrue = (t: Tag, n: string) => t.attrs.has(n) && /^(?:true|)$/.test(strOf(t, n) ?? 'x');
const hasName = (t: Tag) => has(t, 'aria-label', 'aria-labelledby', 'title');

const ARIA_ATTRS = new Set(('activedescendant atomic autocomplete braillelabel brailleroledescription busy checked colcount colindex ' +
  'colindextext colspan controls current describedby description details disabled dropeffect errormessage expanded flowto ' +
  'grabbed haspopup hidden invalid keyshortcuts label labelledby level live modal multiline multiselectable orientation owns ' +
  'placeholder posinset pressed readonly relevant required roledescription rowcount rowindex rowindextext rowspan selected ' +
  'setsize sort valuemax valuemin valuenow valuetext').split(' '));

const ROLES = new Set(('alert alertdialog application article banner blockquote button caption cell checkbox code columnheader ' +
  'combobox comment complementary contentinfo definition deletion dialog directory document emphasis feed figure form generic ' +
  'grid gridcell group heading image img insertion link list listbox listitem log main mark marquee math menu menubar menuitem ' +
  'menuitemcheckbox menuitemradio meter navigation none note option paragraph presentation progressbar radio radiogroup region ' +
  'row rowgroup rowheader scrollbar search searchbox sectionfooter sectionheader separator slider spinbutton status strong ' +
  'subscript suggestion superscript switch tab table tablist tabpanel term textbox time timer toolbar tooltip tree treegrid ' +
  'treeitem graphics-document graphics-object graphics-symbol').split(' '));
const ABSTRACT_ROLES = new Set('command composite input landmark range roletype section sectionhead select structure widget window'.split(' '));

const AUTOCOMPLETE_FIELDS = new Set(('name honorific-prefix given-name additional-name family-name honorific-suffix nickname username ' +
  'new-password current-password one-time-code organization-title organization street-address address-line1 address-line2 ' +
  'address-line3 address-level4 address-level3 address-level2 address-level1 country country-name postal-code cc-name ' +
  'cc-given-name cc-additional-name cc-family-name cc-number cc-exp cc-exp-month cc-exp-year cc-csc cc-type ' +
  'transaction-currency transaction-amount language bday bday-day bday-month bday-year sex url photo tel tel-country-code ' +
  'tel-national tel-area-code tel-local tel-local-prefix tel-local-suffix tel-extension email impp webauthn shipping billing ' +
  'home work mobile fax pager').split(' '));
/** Deliberate autofill-disabling values: invalid per spec but intentional, so not reported as typos. */
const AUTOCOMPLETE_DISABLE_HACKS = new Set(['nope', 'none', 'chrome-off', 'false', 'disabled', 'no', 'off', 'on']);

const ICON_LIB = /^(?:lucide-react|@heroicons\/react(?:\/.*)?|react-icons(?:\/.*)?|@radix-ui\/react-icons|@tabler\/icons-react|@phosphor-icons\/react|phosphor-react|@mui\/icons-material(?:\/.*)?|react-feather)$/;

function iconNames(src: string): Set<string> {
  const names = new Set<string>();
  for (const m of src.matchAll(/import\s+(?:type\s+)?([\w$]+)?\s*,?\s*(?:\{([^}]*)\})?\s*from\s*['"]([^'"]+)['"]/g)) {
    if (!ICON_LIB.test(m[3])) continue;
    if (m[1]) names.add(m[1]);
    for (const part of (m[2] || '').split(',')) {
      const local = part.trim().split(/\s+as\s+/).pop()?.trim();
      if (local) names.add(local);
    }
  }
  return names;
}

/** True when the content is nothing but one or more unlabelled icon elements (svg or icon-library components). */
function iconOnly(inner: string, icons: Set<string>): boolean {
  let s = inner.trim();
  let count = 0;
  while (s.length) {
    if (/^<svg\b/.test(s)) {
      const close = s.indexOf('</svg>');
      if (close === -1) return false;
      const svg = s.slice(0, close);
      if (/<title\b|aria-label/.test(svg)) return false;
      s = s.slice(close + 6).trim();
    } else {
      const t = readTag(s, 0);
      if (!t || !t.selfClosing || t.spread || hasName(t)) return false;
      if (!icons.has(t.name) && !/^Icons\.\w+$/.test(t.name)) return false;
      s = s.slice(t.end).trim();
    }
    count++;
  }
  return count > 0;
}

const FOCUSABLE_NATIVE = /^(?:button|select|textarea|summary)$/;
const STATIC_ELEMENT = /^(?:div|span|li|p|td|section|article|img|i|svg|header|footer|main|aside|figure|label|ul|ol|nav|h[1-6])$/;
const WIDGET_ROLES = /^(?:button|link|checkbox|switch)$/;

export function evaluateUiQualityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (!UI_FILE.test(path) || /(?:^|\/)node_modules\//.test(path)) return { findings, logs };
  const src = cleanContent;
  if (!/<[A-Za-z]/.test(src)) return { findings, logs };

  const hits: Hit[] = [];
  const counts = new Map<number, number>();
  const add = (h: Hit) => {
    counts.set(h.ruleId, (counts.get(h.ruleId) ?? 0) + 1);
    if (!hits.some((x) => x.ruleId === h.ruleId)) hits.push(h);
  };

  const allTags = findTags(src, /^[A-Za-z]/);
  const icons = iconNames(src);

  for (const t of allTags) {
    const native = /^[a-z][a-z0-9-]*$/.test(t.name);
    const n = t.name;

    // A11Y-01: <img> without alt (WCAG 1.1.1, axe image-alt, jsx-a11y alt-text)
    if (n === 'img' && !t.spread && !has(t, 'alt', 'aria-label', 'aria-labelledby') && !/^(?:presentation|none)$/.test(strOf(t, 'role') ?? '')) {
      add({ ruleId: 28601, code: 'A11Y-01', severity: 'MEDIUM', offset: t.start, wcag: '1.1.1 Non-text Content',
        title: 'Image Missing alt Text',
        why: 'An <img> without an alt attribute is announced by screen readers as its file name (or skipped with no context).',
        fix: 'Add alt="<what the image shows>" for meaningful images, or alt="" for purely decorative ones.' });
    }

    // A11Y-02: button / link with no accessible name (empty, or only an unlabelled icon)
    const isButton = n === 'button' || (n === 'Button' && !has(t, 'aschild'));
    const isLink = (n === 'a' && has(t, 'href')) || (n === 'Link' && has(t, 'href', 'to'));
    if ((isButton || isLink) && !t.spread && !hasName(t) && !has(t, 'children', 'dangerouslysetinnerhtml')) {
      if (!(t.selfClosing && !native)) {
        const inner = innerOf(src, t);
        if (inner !== null && (inner.trim() === '' || iconOnly(inner, icons))) {
          add({ ruleId: 28602, code: 'A11Y-02', severity: 'MEDIUM', offset: t.start, wcag: '4.1.2 Name, Role, Value / 2.4.4 Link Purpose',
            title: 'Button or Link Without an Accessible Name (Icon-Only or Empty)',
            why: `This ${isButton ? 'button' : 'link'} contains no text, only an icon or nothing, and has no aria-label, so screen readers announce just "${isButton ? 'button' : 'link'}".`,
            fix: 'Add aria-label="<action>" to the element, or a visually hidden label (<span className="sr-only">Close</span>) next to the icon, and mark the icon aria-hidden.' });
        }
      }
    }

    // A11Y-03: positive tabIndex (WCAG 2.4.3, axe tabindex, jsx-a11y tabindex-no-positive)
    const tabIdx = strOf(t, 'tabindex');
    if (tabIdx !== undefined && /^\d+$/.test(tabIdx) && Number(tabIdx) > 0) {
      add({ ruleId: 28603, code: 'A11Y-03', severity: 'LOW', offset: t.start, wcag: '2.4.3 Focus Order',
        title: 'Positive tabIndex Overrides Natural Focus Order',
        why: `tabIndex=${tabIdx} moves this element ahead of every other control on the page, so keyboard focus jumps out of reading order.`,
        fix: 'Use tabIndex={0} (or no tabIndex on native controls) and order the DOM to match the visual order.' });
    }

    // A11Y-04: aria-hidden on a focusable element (axe aria-hidden-focus, jsx-a11y no-aria-hidden-on-focusable)
    if (native && isTrue(t, 'aria-hidden')) {
      const negTab = tabIdx !== undefined && /^-\d+$/.test(tabIdx);
      const focusable = (FOCUSABLE_NATIVE.test(n) || (n === 'a' && has(t, 'href')) || (n === 'input' && strOf(t, 'type') !== 'hidden') ||
        (tabIdx !== undefined && /^\d+$/.test(tabIdx))) && !negTab && !has(t, 'disabled', 'hidden', 'inert');
      if (focusable) {
        add({ ruleId: 28604, code: 'A11Y-04', severity: 'MEDIUM', offset: t.start, wcag: '4.1.2 Name, Role, Value',
          title: 'aria-hidden on a Focusable Element',
          why: `<${n} aria-hidden="true"> can still receive keyboard focus, but screen readers announce nothing for it: a silent, "ghost" tab stop.`,
          fix: 'Remove aria-hidden, or also take the element out of the tab order (tabIndex={-1}, disabled, or inert) if it is truly decorative.' });
      }
    }

    // A11Y-05: misspelled / non-existent aria-* attribute (axe aria-valid-attr, jsx-a11y aria-props)
    for (const name of t.attrs.keys()) {
      if (!name.startsWith('aria-')) continue;
      if (!ARIA_ATTRS.has(name.slice(5))) {
        add({ ruleId: 28605, code: 'A11Y-05', severity: 'MEDIUM', offset: t.start, wcag: '4.1.2 Name, Role, Value',
          title: 'Invalid ARIA Attribute Name',
          why: `"${name}" is not an ARIA attribute${name === 'aria-labeledby' ? ' (the spec spelling is aria-labelledby)' : ''}, so browsers ignore it and the element loses the label or state it was meant to have.`,
          fix: `Correct the attribute to a valid ARIA 1.2 name${name === 'aria-labeledby' ? ' (aria-labelledby)' : ''}.` });
        break;
      }
    }

    // A11Y-06: invalid or abstract ARIA role on a native element (axe aria-roles, jsx-a11y aria-role)
    const role = native ? strOf(t, 'role') : undefined;
    if (role !== undefined && role.trim() !== '') {
      const tokens = role.trim().toLowerCase().split(/\s+/);
      if (!tokens.some((r) => ROLES.has(r) || r.startsWith('doc-'))) {
        const abstract = tokens.find((r) => ABSTRACT_ROLES.has(r));
        add({ ruleId: 28606, code: 'A11Y-06', severity: 'MEDIUM', offset: t.start, wcag: '4.1.2 Name, Role, Value',
          title: 'Invalid or Abstract ARIA Role',
          why: abstract
            ? `role="${role}" is an abstract ARIA role; authors must not use it and assistive technology ignores it.`
            : `role="${role}" is not an ARIA role, so the element is exposed with no (or the wrong) semantics.`,
          fix: 'Use a concrete role from the WAI-ARIA 1.2 role list (e.g. button, dialog, navigation), or prefer the native element.' });
      }
    }

    // A11Y-07: <a> used as a button (axe/jsx-a11y anchor-is-valid)
    if (n === 'a' && has(t, 'onclick') && !t.spread && !has(t, 'routerlink', 'to', 'xlink:href')) {
      const href = strOf(t, 'href');
      const hrefRaw = rawOf(t, 'href');
      const bad = !has(t, 'href') || href === '#' || /^["'{`\s]*javascript:/i.test(hrefRaw) || /^javascript:/i.test(href ?? '');
      if (bad) {
        add({ ruleId: 28607, code: 'A11Y-07', severity: 'MEDIUM', offset: t.start, wcag: '2.1.1 Keyboard / 4.1.2 Name, Role, Value',
          title: 'Anchor Used as a Button (onClick With No Real href)',
          why: !has(t, 'href')
            ? 'An <a> without href is not focusable, so keyboard users can never trigger this onClick.'
            : `href="${href ?? hrefRaw}" with an onClick handler is announced as a link but acts as a button; Space does not activate it and it pollutes history / scroll position.`,
          fix: 'Render a <button type="button"> for actions, or give the link a real destination URL.' });
      }
    }

    // A11Y-08: <iframe> without title (axe frame-title, jsx-a11y iframe-has-title)
    if (n === 'iframe' && !t.spread && !hasName(t) && !isTrue(t, 'aria-hidden') && !has(t, 'hidden')) {
      add({ ruleId: 28608, code: 'A11Y-08', severity: 'MEDIUM', offset: t.start, wcag: '4.1.2 Name, Role, Value',
        title: 'iframe Missing title',
        why: 'Screen readers list frames by title; an untitled <iframe> is announced only as "frame" with no hint of its content.',
        fix: 'Add title="<short description>" (e.g. title="Product demo video") to the iframe.' });
    }

    // A11Y-09: autocomplete="off" on a password field (WCAG 3.3.8 Accessible Authentication)
    if ((n === 'input' || n === 'Input') && strOf(t, 'type') === 'password' && strOf(t, 'autocomplete') === 'off') {
      add({ ruleId: 28609, code: 'A11Y-09', severity: 'LOW', offset: t.start, wcag: '3.3.8 Accessible Authentication (Minimum)',
        title: 'Password Field Disables Password Managers (autocomplete="off")',
        why: 'autocomplete="off" on a password field tells password managers not to fill it, forcing users to memorise or retype the password.',
        fix: 'Use autoComplete="current-password" on sign-in and autoComplete="new-password" on sign-up / change-password fields.' });
    }

    // A11Y-10: paste blocked on an input (WCAG 3.3.8; blocks password managers and copy-paste of codes)
    if (/^(?:input|Input|textarea|Textarea)$/.test(n) && /preventDefault\s*\(|return\s+false/.test(rawOf(t, 'onpaste'))) {
      add({ ruleId: 28610, code: 'A11Y-10', severity: 'MEDIUM', offset: t.start, wcag: '3.3.8 Accessible Authentication (Minimum)',
        title: 'Paste Blocked on Input Field',
        why: 'An onPaste handler that calls preventDefault stops users pasting passwords, one-time codes or emails, breaking password managers and assistive input.',
        fix: 'Remove the onPaste handler; validate the value after input instead of blocking paste.' });
    }

    // A11Y-11: <marquee> / <blink> (WCAG 2.2.2, axe marquee/blink, jsx-a11y no-distracting-elements)
    if (n === 'marquee' || n === 'blink') {
      add({ ruleId: 28611, code: 'A11Y-11', severity: 'LOW', offset: t.start, wcag: '2.2.2 Pause, Stop, Hide',
        title: 'Deprecated Moving Content Element (<marquee> / <blink>)',
        why: `<${n}> moves or flashes content with no way to pause it, which distracts users and is unreadable for many low-vision users.`,
        fix: 'Replace it with static content (or a CSS animation that respects prefers-reduced-motion and has a pause control).' });
    }

    // A11Y-12: <label> not associated with any control (jsx-a11y label-has-associated-control)
    if (n === 'label' && !t.spread && !has(t, 'htmlfor', 'for', 'id')) {
      const inner = innerOf(src, t);
      if (inner !== null && inner.trim() !== '' && !/children|\{\s*\.\.\./.test(inner)) {
        const tagNames = [...inner.matchAll(/<([A-Za-z][\w.]*)/g)].map((m) => m[1]);
        if (tagNames.every((x) => /^(?:span|strong|b|em|i|small|abbr|br|sup|sub|code)$/.test(x)) && !/\{[^}]*</.test(inner)) {
          add({ ruleId: 28612, code: 'A11Y-12', severity: 'LOW', offset: t.start, wcag: '1.3.1 Info and Relationships / 3.3.2 Labels or Instructions',
            title: '<label> Not Associated With a Form Control',
            why: 'This <label> has no htmlFor and wraps no control, so its text is not the accessible name of any input and clicking it does nothing.',
            fix: 'Add htmlFor="<input id>" pointing at the control (and give the control that id), or wrap the control inside the label.' });
        }
      }
    }

    // A11Y-14 / A11Y-15: widget role on a static element that is not keyboard operable
    const sRole = native && STATIC_ELEMENT.test(n) ? (strOf(t, 'role') ?? '').toLowerCase() : '';
    if (WIDGET_ROLES.test(sRole) && !t.spread && strOf(t, 'aria-disabled') !== 'true' && !isTrue(t, 'aria-hidden') && !has(t, 'contenteditable')) {
      if (!has(t, 'tabindex')) {
        add({ ruleId: 28614, code: 'A11Y-14', severity: 'MEDIUM', offset: t.start, wcag: '2.1.1 Keyboard',
          title: 'Widget Role on an Element That Cannot Receive Focus',
          why: `<${n} role="${sRole}"> is announced as a ${sRole} but has no tabIndex, so keyboard users cannot reach or activate it.`,
          fix: `Use a native ${sRole === 'link' ? '<a href>' : '<button type="button">'} instead, or add tabIndex={0} plus Enter/Space key handling.` });
      } else if (has(t, 'onclick') && !has(t, 'onkeydown', 'onkeyup', 'onkeypress') && (sRole === 'button' || sRole === 'link')) {
        add({ ruleId: 28615, code: 'A11Y-15', severity: 'MEDIUM', offset: t.start, wcag: '2.1.1 Keyboard',
          title: 'Custom Button or Link Handles Click but Not Keyboard',
          why: `<${n} role="${sRole}"> is focusable and clickable, but without a key handler Enter${sRole === 'button' ? '/Space do' : ' does'} nothing for keyboard users.`,
          fix: `Use a native ${sRole === 'link' ? '<a href>' : '<button type="button">'}, or add onKeyDown handling Enter${sRole === 'button' ? ' and Space' : ''}.` });
      }
    }

    // A11Y-16: <svg role="img"> with no accessible name (axe svg-img-alt)
    if (n === 'svg' && (strOf(t, 'role') ?? '') === 'img' && !t.spread && !hasName(t) && !isTrue(t, 'aria-hidden')) {
      const inner = innerOf(src, t);
      if (inner !== null && !/<title\b/.test(inner)) {
        add({ ruleId: 28616, code: 'A11Y-16', severity: 'LOW', offset: t.start, wcag: '1.1.1 Non-text Content',
          title: 'SVG Image Missing an Accessible Name',
          why: '<svg role="img"> is exposed as an image but has no aria-label, aria-labelledby or <title>, so it is announced as an unnamed graphic.',
          fix: 'Add aria-label="<description>" or a <title> as the first child; if decorative, drop role="img" and set aria-hidden="true".' });
      }
    }

    // A11Y-17: invalid autocomplete token (WCAG 1.3.5, axe autocomplete-valid, jsx-a11y autocomplete-valid)
    const ac = /^(?:input|Input|select|textarea)$/.test(n) ? strOf(t, 'autocomplete') : undefined;
    if (ac !== undefined && ac.trim() !== '' && !AUTOCOMPLETE_DISABLE_HACKS.has(ac.trim().toLowerCase())) {
      const tokens = ac.trim().toLowerCase().split(/\s+/);
      if (!tokens.every((x) => AUTOCOMPLETE_FIELDS.has(x) || /^section-\S+$/.test(x))) {
        add({ ruleId: 28617, code: 'A11Y-17', severity: 'LOW', offset: t.start, wcag: '1.3.5 Identify Input Purpose',
          title: 'Invalid autocomplete Token',
          why: `autocomplete="${ac}" is not a value from the HTML autofill list, so browsers, password managers and assistive tech cannot identify the field's purpose.`,
          fix: 'Use a standard token such as email, username, current-password, new-password, one-time-code, given-name, tel or postal-code.' });
      }
    }

    // A11Y-18: <meta http-equiv="refresh"> with a delay (WCAG 2.2.1, axe meta-refresh)
    if (n === 'meta' && /^refresh$/i.test(strOf(t, 'http-equiv') ?? strOf(t, 'httpequiv') ?? '')) {
      const delay = /^\s*(\d+)/.exec(strOf(t, 'content') ?? '');
      if (delay && Number(delay[1]) > 0) {
        add({ ruleId: 28618, code: 'A11Y-18', severity: 'MEDIUM', offset: t.start, wcag: '2.2.1 Timing Adjustable',
          title: 'Timed Page Refresh / Redirect via meta refresh',
          why: `The page reloads or redirects after ${delay[1]}s with no way to stop it, interrupting screen-reader users and anyone still reading.`,
          fix: 'Redirect server-side (HTTP 301/302 or Next.js redirect()), or let the user trigger the refresh.' });
      }
    }

    // A11Y-19: ambiguous link text (WCAG 2.4.4, jsx-a11y anchor-ambiguous-text)
    if (isLink && !hasName(t) && !t.selfClosing) {
      const inner = innerOf(src, t);
      if (inner !== null && /^(?:click here|here|link|a link)$/i.test(inner.replace(/<[^>]*>/g, '').trim().replace(/[.!:]+$/, ''))) {
        add({ ruleId: 28619, code: 'A11Y-19', severity: 'LOW', offset: t.start, wcag: '2.4.4 Link Purpose (In Context)',
          title: 'Ambiguous Link Text ("click here")',
          why: 'Screen-reader users often navigate by a list of links; "click here" / "here" / "link" says nothing about where the link goes.',
          fix: 'Make the link text describe its destination (e.g. "Read the pricing FAQ"), or add an aria-label that does.' });
      }
    }

    // A11Y-20: aria-label on a generic <div>/<span> with no role (ARIA 1.2 prohibits naming generic; axe aria-prohibited-attr)
    if ((n === 'div' || n === 'span') && has(t, 'aria-label') && !has(t, 'role', 'tabindex') && !t.spread) {
      add({ ruleId: 28620, code: 'A11Y-20', severity: 'LOW', offset: t.start, wcag: '4.1.2 Name, Role, Value',
        title: 'aria-label on a Generic Element Is Ignored',
        why: `ARIA 1.2 prohibits naming a role-less <${n}>; most screen readers do not announce this aria-label at all.`,
        fix: 'Put the text in visible or sr-only content, or give the element a role that supports naming (e.g. role="img", role="group", role="region").' });
    }

    // A11Y-21: <audio autoPlay> without controls or muted (WCAG 1.4.2 Audio Control)
    if (n === 'audio' && has(t, 'autoplay') && strOf(t, 'autoplay') !== 'false' && !has(t, 'controls', 'muted')) {
      add({ ruleId: 28621, code: 'A11Y-21', severity: 'MEDIUM', offset: t.start, wcag: '1.4.2 Audio Control',
        title: 'Auto-Playing Audio Without Controls',
        why: 'Audio that starts on load with no visible controls drowns out screen-reader speech and cannot be paused or muted independently.',
        fix: 'Remove autoPlay, or add controls (and start muted) so users can stop the audio.' });
    }

    // A11Y-22: invalid <html lang> value (WCAG 3.1.1, axe html-lang-valid, jsx-a11y lang)
    if (n === 'html') {
      const lang = strOf(t, 'lang');
      if (lang !== undefined && !/[{%<$]/.test(lang) && !/^[a-z]{2,3}(?:-[a-z0-9]{1,8})*$/i.test(lang.trim())) {
        add({ ruleId: 28622, code: 'A11Y-22', severity: 'LOW', offset: t.start, wcag: '3.1.1 Language of Page',
          title: 'Invalid lang Value on <html>',
          why: `lang="${lang}" is not a BCP 47 language tag, so screen readers fall back to a default voice and mispronounce the page.`,
          fix: 'Use a valid language tag such as lang="en", lang="en-US" or lang="tr".' });
      }
    }

    // A11Y-23: onBlur handler that pulls focus back to the element (WCAG 2.1.2 No Keyboard Trap)
    if (/(?:\b(?:e|ev|evt|event)\.(?:target|currentTarget)|\bthis)\.focus\s*\(/.test(rawOf(t, 'onblur'))) {
      add({ ruleId: 28623, code: 'A11Y-23', severity: 'HIGH', offset: t.start, wcag: '2.1.2 No Keyboard Trap',
        title: 'Keyboard Trap: onBlur Forces Focus Back Into the Field',
        why: 'Refocusing the element in its own blur handler makes it impossible to Tab away, trapping keyboard and screen-reader users on the page.',
        fix: 'Show the validation message and mark the field aria-invalid instead of re-focusing it; let focus move on.' });
    }
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineIdx = src.slice(0, h.offset).split('\n').length - 1;
    const lineNum = lineIdx + 1;
    const n = counts.get(h.ruleId) ?? 1;
    findings.push({
      id: `uiq${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'VIBEPOLISH',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: 'UI Accessibility',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (lines[lineIdx] || '').trim(),
      reproductionSteps: [
        `Scanned ${file.path}:${lineNum}${n > 1 ? ` (${n} occurrences in this file)` : ''}.`,
        h.why,
        `WCAG 2.2: ${h.wcag}.`
      ],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${ts}] [UI QUALITY] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
