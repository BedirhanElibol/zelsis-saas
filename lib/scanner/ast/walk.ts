/**
 * Minimal Babel AST helpers (no @babel/traverse): child iteration and small node predicates.
 */

export interface AstNode {
  type: string;
  start?: number | null;
  end?: number | null;
  loc?: { start: { line: number; column: number }; end: { line: number; column: number } } | null;
  // Babel nodes carry many shape-specific fields; the rules read them defensively
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

/** Keys that never hold runtime code (positions, comments, type annotations). */
const SKIP_KEYS = new Set([
  'type', 'start', 'end', 'loc', 'range', 'extra', 'leadingComments', 'trailingComments', 'innerComments',
  'typeAnnotation', 'returnType', 'typeParameters', 'typeArguments', 'superTypeParameters', 'implements',
  'decorators', 'predicate', 'errors', 'tokens', 'comments',
]);

export function isNode(v: unknown): v is AstNode {
  return !!v && typeof v === 'object' && typeof (v as AstNode).type === 'string';
}

/** Direct children of a node, in source order, with the key they hang off. */
export function children(node: AstNode): { key: string; child: AstNode }[] {
  const out: { key: string; child: AstNode }[] = [];
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const v = node[key];
    if (Array.isArray(v)) {
      for (const item of v) if (isNode(item)) out.push({ key, child: item });
    } else if (isNode(v)) {
      out.push({ key, child: v });
    }
  }
  return out;
}

/** Depth-first visit; return false from fn to skip a subtree. */
export function walk(node: AstNode, fn: (n: AstNode) => boolean | void): void {
  if (fn(node) === false) return;
  for (const { child } of children(node)) walk(child, fn);
}

export const FUNCTION_TYPES = new Set([
  'FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod', 'ClassPrivateMethod',
]);

export const isFunction = (n: AstNode | null | undefined): boolean => !!n && FUNCTION_TYPES.has(n.type);
export const isMember = (n: AstNode | null | undefined): boolean => !!n && (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression');
export const isCall = (n: AstNode | null | undefined): boolean => !!n && (n.type === 'CallExpression' || n.type === 'OptionalCallExpression');

const WRAPPERS = new Set(['TSAsExpression', 'TSSatisfiesExpression', 'TSNonNullExpression', 'TSTypeAssertion', 'ParenthesizedExpression', 'TypeCastExpression', 'TSInstantiationExpression']);

/** Strips type casts, `!` and parentheses. */
export function unwrap(n: AstNode): AstNode {
  let cur = n;
  while (cur && WRAPPERS.has(cur.type) && cur.expression) cur = cur.expression;
  return cur;
}

/** Strips casts and `await`. */
export function unwrapAwait(n: AstNode): AstNode {
  let cur = unwrap(n);
  while (cur && cur.type === 'AwaitExpression' && cur.argument) cur = unwrap(cur.argument);
  return cur;
}

/** Static property name of a member expression (`a.b`, `a['b']`), else null. */
export function propName(m: AstNode): string | null {
  if (!isMember(m)) return null;
  const p = m.property;
  if (!m.computed && p?.type === 'Identifier') return p.name;
  if (p?.type === 'StringLiteral') return p.value;
  return null;
}

/** Key name of an object property / pattern property, else null. */
export function keyName(p: AstNode): string | null {
  if (!p || (p.type !== 'ObjectProperty' && p.type !== 'ObjectMethod')) return null;
  const k = p.key;
  if (!p.computed && k?.type === 'Identifier') return k.name;
  if (k?.type === 'StringLiteral') return k.value;
  return null;
}

/** Name of the called function: `foo()` -> foo, `a.b.foo()` -> foo. */
export function calleeName(call: AstNode): string | null {
  const c = unwrap(call.callee);
  if (c?.type === 'Identifier') return c.name;
  if (isMember(c)) return propName(c);
  return null;
}

/** Dotted path of a member chain rooted at an identifier (`ctx.db.user` -> ['ctx','db','user']), else null. */
export function memberPath(n: AstNode): string[] | null {
  const parts: string[] = [];
  let cur = unwrap(n);
  while (isMember(cur)) {
    const p = propName(cur);
    if (p === null) return null;
    parts.unshift(p);
    cur = unwrap(cur.object);
  }
  if (cur?.type === 'Identifier') { parts.unshift(cur.name); return parts; }
  if (cur?.type === 'ThisExpression') { parts.unshift('this'); return parts; }
  return null;
}

export const lineOf = (n: AstNode | null | undefined): number => n?.loc?.start.line ?? 1;

export function stringValue(n: AstNode | null | undefined): string | null {
  if (!n) return null;
  const u = unwrap(n);
  if (u.type === 'StringLiteral') return u.value;
  if (u.type === 'TemplateLiteral' && u.expressions.length === 0) return u.quasis.map((q: AstNode) => q.value.cooked ?? q.value.raw).join('');
  return null;
}

export const within = (inner: AstNode, outer: AstNode): boolean =>
  inner.start != null && outer.start != null && inner.end != null && outer.end != null && inner.start >= outer.start && inner.end <= outer.end;
