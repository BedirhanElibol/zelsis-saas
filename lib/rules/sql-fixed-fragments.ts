/**
 * SQL built only from constant fragments is not injectable. These helpers decide, for a `${name}` inside a JS/TS
 * template, whether `name` holds fixed SQL text, so the injection rules can treat it like a literal:
 * - a string or template literal with no interpolation (`const inForce = "org_id = ? AND ..."`)
 * - a template whose interpolations are all fixed names, `?` placeholder lists or calls to fixed helpers
 * - an arrow function that returns such a template (`const IS_ONE_OF = (roles) => \`... IN (${...})\``)
 * - a parameter (plain or destructured with a default) whose every same-file call passes a fixed value
 * A name resolves to its nearest declaration before the use, so a `where` in one function does not vouch
 * for a `where` in another. The values themselves still go through bind parameters; only SQL text is checked.
 */

/** `${list.map(() => "?").join(", ")}` and `${Array(n).fill("?").join(",")}`: placeholders only. */
// Also row tuples such as "(?, ?, ?)" and an empty-list fallback: `${ids.map(() => "?").join(",") || "NULL"}`.
const PLACEHOLDERS = String.raw`\(?\s*\?(?:\s*,\s*\?)*\s*\)?`;
const PLACEHOLDER_LIST = new RegExp(
  String.raw`\$\{\s*(?:[\w.]+\.map\(\s*\(\s*\w*\s*\)\s*=>\s*(['"])` + PLACEHOLDERS + String.raw`\1\s*\)|(?:new\s+)?Array\(\s*[\w.]+\s*\)\.fill\(\s*(['"])` + PLACEHOLDERS + String.raw`\2\s*\))\.join\(\s*(['"])[^'"]*\3\s*\)(?:\s*\|\|\s*(['"])(?:NULL)?\4)?\s*\}`,
  'g'
);

export function normalizePlaceholderLists(s: string): string {
  return s.replace(PLACEHOLDER_LIST, 'CONST');
}

const NAME = String.raw`[A-Za-z_$][\w$]*`;

/** Every `${...}` inside one template body, or null when a nested template makes the split unreliable. */
function interpolations(body: string): string[] | null {
  const out: string[] = [];
  let i = 0;
  while ((i = body.indexOf('${', i)) !== -1) {
    let depth = 1;
    let j = i + 2;
    for (; j < body.length && depth > 0; j++) {
      if (body[j] === '`') return null;
      if (body[j] === '{') depth++;
      else if (body[j] === '}') depth--;
    }
    if (depth !== 0) return null;
    out.push(body.slice(i + 2, j - 1).trim());
    i = j;
  }
  return out;
}

/** Splits on commas outside (), [], {} and string literals. */
export function splitTopLevel(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote = '';
  let cur = '';
  for (const ch of s) {
    if (quote) { cur += ch; if (ch === quote) quote = ''; continue; }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; cur += ch; continue; }
    if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) { out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** The argument lists of every `fn(...)` call in the file (balanced parentheses, strings skipped). */
export function callArgs(content: string, fn: string): { index: number; args: string[] }[] {
  const out: { index: number; args: string[] }[] = [];
  const comments = [...content.matchAll(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g)].map((c) => [c.index, c.index + c[0].length] as const);
  for (const m of content.matchAll(new RegExp(String.raw`(?<![\w$.])${fn}\s*\(`, 'g'))) {
    if (/function\s*$/.test(content.slice(Math.max(0, m.index - 10), m.index))) continue;
    if (comments.some(([a, b]) => m.index >= a && m.index < b)) continue;
    let depth = 1;
    let quote = '';
    let j = m.index + m[0].length;
    for (; j < content.length && depth > 0; j++) {
      const ch = content[j];
      if (quote) { if (ch === quote && content[j - 1] !== '\\') quote = ''; continue; }
      if (ch === '"' || ch === "'" || ch === '`') quote = ch;
      else if (ch === '(') depth++;
      else if (ch === ')') depth--;
    }
    if (depth === 0) out.push({ index: m.index, args: splitTopLevel(content.slice(m.index + m[0].length, j - 1)) });
  }
  return out;
}

type Decl = { name: string; index: number; kind: 'literal' | 'template' | 'fn' | 'param' | 'other'; body?: string; fixed: boolean };

/** Returns `isFixed(name, offset)`: whether `name`, used at `offset`, holds fixed SQL text. */
export function fixedSqlResolver(content: string): (name: string, offset: number) => boolean {
  const decls: Decl[] = [];
  const seen = new Set<number>();
  const add = (d: Omit<Decl, 'fixed'>) => { if (!seen.has(d.index)) { seen.add(d.index); decls.push({ ...d, fixed: d.kind === 'literal' }); } };

  for (const m of content.matchAll(new RegExp(String.raw`\b(?:const|let|var)\s+(${NAME})\s*=\s*(?:"([^"\\\n]*)"|'([^'\\\n]*)'|\x60([^\x60\\]*)\x60)\s*[;\n),]`, 'g'))) {
    const at = m.index + m[0].indexOf(m[1]);
    add(m[4] !== undefined && m[4].includes('${') ? { name: m[1], index: at, kind: 'template', body: m[4] } : { name: m[1], index: at, kind: 'literal' });
  }
  for (const m of content.matchAll(new RegExp(String.raw`\b(?:const|let|var)\s+(${NAME})\s*=\s*(?:\([^)]*\)|${NAME})\s*=>\s*\x60([^\x60\\]*)\x60`, 'g'))) {
    add({ name: m[1], index: m.index + m[0].indexOf(m[1]), kind: 'fn', body: m[2] });
  }
  // function name(table: string) { return `UPDATE ${table} ...`; }: a helper whose whole body returns one template
  for (const m of content.matchAll(new RegExp(String.raw`\bfunction\s+(${NAME})\s*\([^)]*\)\s*(?::\s*[^{]+)?\{\s*return\s*\x60([^\x60\\]*)\x60\s*;?\s*\}`, 'g'))) {
    add({ name: m[1], index: m.index + m[0].indexOf(m[1]), kind: 'fn', body: m[2] });
  }
  const params: { fn: string; index: number; slot?: number; raw: string; pos: number; field?: string; dflt?: string }[] = [];
  const paramLists: [number, number][] = [];
  const fnDecls = [...content.matchAll(new RegExp(String.raw`(?:function\s+(${NAME})\s*\(([^)]*)\)|\b(?:const|let)\s+(${NAME})\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>)`, 'g'))];
  for (const m of fnDecls) paramLists.push([m.index, m.index + m[0].length]);
  // Any other assignment shadows the name with something unknown (defaults inside parameter lists excepted)
  for (const m of content.matchAll(new RegExp(String.raw`\b(?:(?:const|let|var)\s+)?(${NAME})\s*=(?!=|>)`, 'g'))) {
    const at = m.index + m[0].indexOf(m[1]);
    if (!seen.has(at) && !paramLists.some(([a, b]) => at > a && at < b)) add({ name: m[1], index: at, kind: 'other' });
  }
  for (const m of fnDecls) {
    const fn = m[1] ?? m[3];
    splitTopLevel(m[2] ?? m[4]).forEach((raw, pos) => {
      // TypeScript parameters carry a type (`table: string`, `limit?: number`); the type never changes the value
      const plain = new RegExp(String.raw`^(${NAME})\??(?:\s*:\s*[^=]+?)?(?:\s*=\s*([\s\S]+))?$`).exec(raw.trim());
      if (plain) { params.push({ fn, index: m.index, raw: plain[1], pos, dflt: plain[2]?.trim() }); return; }
      const pattern = /^\{([\s\S]*)\}$/.exec(raw.trim());
      if (!pattern) return;
      for (const field of splitTopLevel(pattern[1])) {
        const fm = new RegExp(String.raw`^(${NAME})(?:\s*=\s*([\s\S]+))?$`).exec(field);
        if (fm) params.push({ fn, index: m.index, raw: fm[1], pos, field: fm[1], dflt: fm[2]?.trim() });
      }
    });
  }
  // Each parameter gets its own slot just after the function start, so they sort before the body and never collide
  params.forEach((p, k) => { p.slot = p.index + (k + 1) / 1000; add({ name: p.raw, index: p.slot, kind: "param" }); });
  decls.sort((a, b) => a.index - b.index);

  const resolve = (name: string, offset: number): Decl | undefined => {
    let best: Decl | undefined;
    for (const d of decls) if (d.name === name && d.index <= offset) best = d;
    return best ?? decls.find((d) => d.name === name);
  };
  const isFixedExpr = (e: string, offset: number): boolean => {
    if (new RegExp(String.raw`^${NAME}$`).test(e)) return resolve(e, offset)?.fixed ?? false;
    if (/^(['"])[^'"]*\1$/.test(e)) return true;
    if (normalizePlaceholderLists('${' + e + '}') === 'CONST') return true;
    const call = new RegExp(String.raw`^(${NAME})\s*\(`).exec(e);
    const d = call ? resolve(call[1], offset) : undefined;
    return Boolean(d && d.kind === 'fn' && d.fixed);
  };

  for (let pass = 0; pass < 8; pass++) {
    let grew = false;
    for (const d of decls) {
      if (d.fixed || (d.kind !== 'template' && d.kind !== 'fn')) continue;
      if (interpolations(d.body ?? '')?.every((p) => isFixedExpr(p, d.index))) { d.fixed = true; grew = true; }
    }
    for (const p of params) {
      const d = decls.find((x) => x.index === p.slot && x.kind === "param");
      if (!d || d.fixed) continue;
      const calls = callArgs(content, p.fn).filter((c) => c.index !== p.index);
      if (!calls.length) continue;
      const ok = calls.every((c) => {
        const arg = (c.args[p.pos] ?? '').trim();
        // A missing argument takes the default
        if (!p.field) return arg ? isFixedExpr(arg, c.index) : p.dflt !== undefined && isFixedExpr(p.dflt, c.index);
        if (!arg.startsWith('{')) return false;
        const given = splitTopLevel(arg.slice(1, -1)).find((kv) => kv === p.field || new RegExp(String.raw`^${p.field}\s*:`).test(kv));
        if (given === p.field) return isFixedExpr(p.field, c.index);
        if (given) return isFixedExpr(given.replace(new RegExp(String.raw`^${p.field}\s*:\s*`), ''), c.index);
        return p.dflt === undefined || isFixedExpr(p.dflt, c.index);
      });
      if (ok) { d.fixed = true; grew = true; }
    }
    if (!grew) break;
  }
  return (name, offset) => resolve(name, offset)?.fixed ?? false;
}
