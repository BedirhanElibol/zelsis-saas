/**
 * Python adapter for the architecture graph (IAG): entrypoints, guards and data sinks of one file, the same node
 * kinds lib/scanner/ast/flow.ts builds for JavaScript/TypeScript. Line based (no Python parser in this runtime), so
 * it only claims what the source shows plainly; rules built on it stay conservative.
 *
 *   Entrypoint  FastAPI / Flask route functions and Django / DRF views, with the ids taken from the URL
 *   Guard       a signed-in user is required (Depends(get_current_user), @login_required, request.user ...),
 *               and whether the route is admin-only
 *   DataSink    an ORM lookup of one record (SQLAlchemy, SQLModel, Django) and whether it is scoped to the caller
 */

export interface PyEntrypoint {
  name: string;
  /** 0-based line of the `def`. */
  line: number;
  framework: 'fastapi' | 'flask' | 'django';
  /** Parameters that come from the URL path and look like record ids. */
  idParams: string[];
  /** A signed-in user is required to reach the body. */
  authed: boolean;
  /** Admin / staff only: such routes may read any record. */
  adminOnly: boolean;
  sinks: PyDataSink[];
  /** The function body mentions the caller next to a record (owner filter or an explicit ownership check). */
  ownerCheck: boolean;
}

export interface PyDataSink {
  line: number;
  model: string;
  /** The URL id parameter used to pick the record. */
  idParam: string;
  orm: 'sqlalchemy' | 'django';
}

const ROUTE_DECORATOR = /^\s*@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|api_route)\s*\(\s*(?:path\s*=\s*)?['"]([^'"]*)['"]/;
const IDISH = /^(?:id|pk|uuid|\w+_id|\w+_pk|\w+_uuid)$/;

/** Caller identity is required: FastAPI dependency, Flask-Login / JWT decorators, Django login checks. */
const AUTH_SIGNAL = /Depends\(\s*(?:get_current_\w*|current_\w*user\w*|require_\w*|auth\w*|verify_\w*token\w*|get_user\w*)\b|\bcurrent_user\b|@login_required|@jwt_required|@auth\.login_required|@permission_required|\brequest\.user\b|IsAuthenticated|LoginRequiredMixin|get_jwt_identity\s*\(/;
const ADMIN_SIGNAL = /\b(?:is_superuser|is_staff|is_admin|IsAdminUser|admin_required|require_admin|get_current_\w*(?:admin|superuser)\w*|superuser_required|staff_member_required)\b|role\s*==\s*['"]admin['"]/;
/**
 * The caller appears next to the record: owner filter (user_id == current_user.id, owner=request.user, filter_by
 * (user=...)), tenant scoping, or a check after loading (if obj.owner_id != current_user.id: raise).
 */
const CALLER = String.raw`(?:current_user|request\.user|user|g\.user)`;
const OWNER_SIGNAL = new RegExp([
  // any record field compared with the caller: booking.tutor_id != current_user.id, Invoice.owner_id == current_user.id
  String.raw`\.\w*(?:_id|user|owner|author|creator|created_by)\s*(?:==|!=)\s*${CALLER}\b`,
  String.raw`\b${CALLER}(?:\.id)?\s*(?:==|!=)\s*\w+\.\w*(?:_id|user|owner|author|creator|created_by)\b`,
  // keyword filters: owner=request.user, user_id=current_user.id
  String.raw`\b\w*(?:_id|user|owner|author|creator|created_by)\s*=\s*${CALLER}\b`,
  // querysets reached through the caller: request.user.post_set, current_user.invoices
  String.raw`\b${CALLER}\.\w+(?:_set|s)\b`,
  String.raw`has_object_permission|check_object_permissions|get_queryset\s*\(`,
].join('|'));

/**
 * Models this file itself treats as belonging to a user: some query filters them by the caller. Only these can be
 * an IDOR when another route loads them by id without that filter; shared records (tabs, events, analytics) cannot.
 */
export function ownerScopedModels(content: string): Set<string> {
  const models = new Set<string>();
  const add = (m: string | undefined) => { if (m && /^[A-Z]/.test(m)) models.add(m); };
  for (const m of content.matchAll(new RegExp(String.raw`\b([A-Z]\w*)\.\w*(?:_id|user|owner|author|creator|created_by)\s*==\s*${CALLER}\b`, 'g'))) add(m[1]);
  for (const m of content.matchAll(new RegExp(String.raw`\b([A-Z]\w*)\.(?:objects\.filter|query\.filter_by)\([^)]*\b\w*(?:_id|user|owner|author|creator|created_by)\s*=\s*${CALLER}\b`, 'g'))) add(m[1]);
  for (const m of content.matchAll(/\brequest\.user\.(\w+)_set\b/g)) add(m[1].charAt(0).toUpperCase() + m[1].slice(1).replace(/_(\w)/g, (_, c: string) => c.toUpperCase()));
  return models;
}

function idParamsOf(route: string, params: string[]): string[] {
  const fromPath = [...route.matchAll(/\{(\w+)(?::[^}]*)?\}|<(?:\w+:)?(\w+)>/g)].map((m) => m[1] ?? m[2]);
  return [...new Set([...fromPath, ...params.filter((p) => IDISH.test(p))])].filter((p) => IDISH.test(p));
}

/** One-record lookups by a given id variable. */
function findSinks(body: string[], startLine: number, idParams: string[]): PyDataSink[] {
  const sinks: PyDataSink[] = [];
  const id = idParams.map((p) => p.replace(/\W/g, '')).join('|');
  if (!id) return sinks;
  const patterns: { re: RegExp; orm: PyDataSink['orm'] }[] = [
    // db.query(Invoice).filter(Invoice.id == invoice_id).first() / .filter_by(id=invoice_id)
    { re: new RegExp(String.raw`\.query\(\s*(\w+)\s*\)[^\n]*?\.(?:filter\(\s*\1\.(?:id|pk|uuid)\s*==\s*(${id})\b|filter_by\(\s*(?:id|pk|uuid)\s*=\s*(${id})\b|get\(\s*(${id})\s*\))`), orm: 'sqlalchemy' },
    // Flask-SQLAlchemy: Note.query.get(note_id) / .get_or_404(note_id) / .filter_by(id=note_id)
    { re: new RegExp(String.raw`\b(\w+)\.query\.(?:get(?:_or_404)?\(\s*(${id})\s*\)|filter_by\(\s*(?:id|pk|uuid)\s*=\s*(${id})\b)`), orm: 'sqlalchemy' },
    // session.get(Invoice, invoice_id) / db.get(Invoice, invoice_id)
    { re: new RegExp(String.raw`\b(?:session|db|database|s)\.get\(\s*(\w+)\s*,\s*(${id})\b`), orm: 'sqlalchemy' },
    // select(Invoice).where(Invoice.id == invoice_id)
    { re: new RegExp(String.raw`\bselect\(\s*(\w+)\s*\)[^\n]*?\.where\(\s*\1\.(?:id|pk|uuid)\s*==\s*(${id})\b`), orm: 'sqlalchemy' },
    // Invoice.objects.get(pk=pk) / .filter(id=pk).first()
    { re: new RegExp(String.raw`\b(\w+)\.objects\.(?:get|filter)\(\s*(?:id|pk|uuid)\s*=\s*(${id})\s*\)`), orm: 'django' },
    // get_object_or_404(Invoice, pk=pk)
    { re: new RegExp(String.raw`\bget_object_or_404\(\s*(\w+)\s*,\s*(?:id|pk|uuid)\s*=\s*(${id})\s*\)`), orm: 'django' },
  ];
  body.forEach((l, i) => {
    for (const { re, orm } of patterns) {
      const m = re.exec(l);
      if (!m) continue;
      const idParam = m.slice(2).find(Boolean) ?? '';
      sinks.push({ line: startLine + i, model: m[1], idParam, orm });
      break;
    }
  });
  return sinks;
}

/** Entrypoints of a Python file with their guards and sinks. Empty for non-web code. */
export function pythonEntrypoints(content: string, path: string): PyEntrypoint[] {
  const lines = content.split('\n');
  const out: PyEntrypoint[] = [];
  const isDjangoViews = /(?:^|\/)views(?:\/\w+)?\.py$|(?:^|\/)viewsets?\.py$|(?:^|\/)api\.py$/i.test(path);
  const fileAuth = /permission_classes\s*=\s*\[[^\]]*IsAuthenticated|LoginRequiredMixin/.test(content);

  lines.forEach((l, i) => {
    const m = /^(\s*)(?:async\s+)?def\s+(\w+)\s*\((.*)/.exec(l);
    if (!m) return;
    const indent = m[1].length;
    let sig = m[3];
    let j = i;
    while (!/\)\s*(?:->[^:]*)?:\s*(?:#.*)?$/.test(sig) && j + 1 < lines.length && j - i < 15) sig += ' ' + lines[++j];
    let end = j + 1;
    while (end < lines.length && (!lines[end].trim() || lines[end].length - lines[end].trimStart().length > indent)) end++;

    const decorators: string[] = [];
    for (let k = i - 1; k >= 0 && /^\s*@/.test(lines[k]); k--) decorators.unshift(lines[k]);
    const routeDecorator = decorators.map((d) => ROUTE_DECORATOR.exec(d)).find(Boolean);
    const rawParams = sig.slice(0, sig.lastIndexOf(')')).split(',').map((p) => p.trim()).filter(Boolean);
    const paramNames = rawParams.map((p) => p.replace(/^\*+/, '').split(/[:=]/)[0].trim());
    // Django / DRF view: first argument (after self) is the request
    const firstArg = paramNames[0] === 'self' ? paramNames[1] : paramNames[0];
    const djangoView = isDjangoViews && firstArg === 'request';
    if (!routeDecorator && !djangoView) return;

    const framework: PyEntrypoint['framework'] = routeDecorator ? (/\.route\s*\(/.test(routeDecorator[0]) ? 'flask' : 'fastapi') : 'django';
    const body = lines.slice(j + 1, end);
    const sigAndDecorators = [...decorators, sig].join('\n');
    const bodyText = body.join('\n');
    const idParams = idParamsOf(routeDecorator?.[1] ?? '', paramNames);
    out.push({
      name: m[2],
      line: i,
      framework,
      idParams,
      authed: AUTH_SIGNAL.test(sigAndDecorators) || AUTH_SIGNAL.test(bodyText) || fileAuth,
      adminOnly: ADMIN_SIGNAL.test(sigAndDecorators) || ADMIN_SIGNAL.test(bodyText),
      sinks: findSinks(body, j + 1, idParams),
      ownerCheck: OWNER_SIGNAL.test(bodyText) || OWNER_SIGNAL.test(sigAndDecorators),
    });
  });
  return out;
}
