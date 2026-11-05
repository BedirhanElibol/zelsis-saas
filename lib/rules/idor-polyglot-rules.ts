/**
 * IDOR for Rails, Laravel, Spring and ASP.NET (FLOW-08..11, Rule IDs 33013-33016): a signed-in user loads a
 * record by the id in the URL and nothing ties it to them, so changing the id shows someone else's data.
 * Same idea as the Python rule FLOW-07: a model only counts as owned when this file scopes it to the caller
 * somewhere else (current_user.orders, where user_id = auth id, findByUser...), so shared records do not fire.
 * Suggestions until the benchmark proves them.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { PUBLIC_READ_MODEL } from '../scanner/ast/flow';
import type { RepoContext } from '../scanner/repo-context';

type Lang = 'ruby' | 'php' | 'jvm' | 'csharp';

/** Written out per rule so the rule inventory (scripts/rule-audit.ts) picks each one up. */
const RULES: Record<Lang, { ruleId: number; title: string; severity: 'HIGH' }> = {
  ruby: { ruleId: 33013, title: 'FLOW-08: Record Loaded by the Id in the URL Without an Ownership Check (Rails)', severity: 'HIGH' },
  php: { ruleId: 33014, title: 'FLOW-09: Record Loaded by the Id in the URL Without an Ownership Check (Laravel)', severity: 'HIGH' },
  jvm: { ruleId: 33015, title: 'FLOW-10: Record Loaded by the Id in the URL Without an Ownership Check (Spring)', severity: 'HIGH' },
  csharp: { ruleId: 33016, title: 'FLOW-11: Record Loaded by the Id in the URL Without an Ownership Check (ASP.NET)', severity: 'HIGH' },
};

const LANG: Record<Lang, RegExp> = { ruby: /\.rb$/i, php: /\.php$/i, jvm: /\.(?:java|kt)$/i, csharp: /\.cs$/i };
const SKIP_PATH = /(?:^|\/)(?:tests?|spec|specs|__tests__|fixtures?|mocks?|src\/test|vendor|node_modules|db\/migrate|database\/migrations)\/|(?:^|\/)admin\/|(?:^|\/)admin\w*_controller\.rb$|(?:^|\/)Admin\w*Controller\.(?:php|java|kt|cs)$|(?:Tests?|Spec)\.(?:java|kt|cs|php)$|_spec\.rb$|_test\.rb$/i;
/** Admin-only code: an admin is meant to open any record. */
const ADMIN_ONLY = /before_action\s+:(?:admin\w*|require_admin\w*|administrative|is_admin\w*|ensure_admin\w*)|->middleware\(\s*['"](?:admin|can:)|@PreAuthorize\(\s*["']hasRole\(\s*'ADMIN|\[Authorize\(\s*Roles\s*=\s*"Admin/i;

/** A signed-in request: without one, loading by id is ordinary public data. */
const SIGNED_IN: Record<Lang, RegExp> = {
  ruby: /\bcurrent_user\b|authenticate_user!/,
  php: /auth\(\)->|Auth::(?:user|id)\(|\$request->user\(\)|->middleware\(\s*['"]auth/,
  jvm: /\bPrincipal\b|@AuthenticationPrincipal|SecurityContextHolder|\bAuthentication\s+\w+/,
  csharp: /\[Authorize\b|\bUser\.(?:Identity|FindFirst|Claims)\b/,
};
/** Authorization the framework applies on top: then the lookup is checked even if it is not scoped. */
const AUTHORIZED: Record<Lang, RegExp> = {
  ruby: /\bauthorize\b|policy_scope|load_and_authorize_resource|authorize_resource|\bcan\?|Pundit|CanCan|before_action\s+:(?:authorize|check_owner|require_owner|ensure_owner)\w*/,
  php: /->authorize\(|\$this->authorize\(|Gate::|->can\(|->cannot\(|authorizeResource\(|abort_if\([^)]*user_id|abort_unless\([^)]*user_id/,
  jvm: /@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed|hasPermission\(/,
  csharp: /AuthorizeAsync\(|\[Authorize\(\s*Policy|IsInRole\(/,
};

const singular = (w: string): string => {
  const s = w.toLowerCase();
  if (s.endsWith('ies')) return s.slice(0, -3) + 'y';
  if (/(?:ss|sh|ch|x|z)es$/.test(s)) return s.slice(0, -2);
  if (s.endsWith('s') && !s.endsWith('ss')) return s.slice(0, -1);
  return s;
};
const key = (model: string) => singular(model.replace(/Repository$/, ''));

/** Models this file scopes to the signed-in user somewhere, keyed by lowercase singular name. */
function ownedModels(lang: Lang, c: string): Set<string> {
  const out = new Set<string>();
  const add = (re: RegExp, g = 1) => { for (const m of c.matchAll(re)) out.add(key(m[g])); };
  if (lang === 'ruby') {
    add(/\bcurrent_user\.(\w+)\b(?!\?)/g);
    add(/\b([A-Z]\w+)\.where\(\s*(?:user|owner|account)(?:_id)?:\s*current_user/g);
  }
  if (lang === 'php') {
    add(/(?:auth\(\)->user\(\)|Auth::user\(\)|\$request->user\(\))->(\w+)\(\)/g);
    add(/\b([A-Z]\w+)::where\(\s*['"](?:user|owner)_id['"]\s*,\s*(?:auth\(\)->id\(\)|Auth::id\(\)|\$request->user\(\)->id)/g);
  }
  if (lang === 'jvm') add(/\b(\w+)Repository\.findBy\w*(?:User|Owner|Account)\w*\s*\(/g);
  if (lang === 'csharp') add(/\.(\w+)\.Where\(\s*(\w+)\s*=>\s*\2\.(?:UserId|OwnerId|AccountId)\s*==/g);
  return out;
}

/** First lookup by a URL id of an owned model: [line index, model]. */
function findSink(lang: Lang, lines: string[], owned: Set<string>, content: string): [number, string] | null {
  const pathIds = new Set<string>();
  if (lang === 'jvm') for (const m of content.matchAll(/@PathVariable(?:\([^)]*\))?\s+(?:final\s+)?(?:\w+\s+)?(\w+)\s*[,)]|@PathVariable(?:\([^)]*\))?\s+(\w+)\s*:/g)) pathIds.add(m[1] ?? m[2]);
  const sinks: Record<Lang, RegExp> = {
    ruby: /\b([A-Z]\w+)\.(?:find\(\s*params\[:(?:\w+_)?id\]\s*\)|find_by!?\(\s*id:\s*params\[:(?:\w+_)?id\])/,
    php: /\b([A-Z]\w+)::(?:find|findOrFail)\(\s*(?:\$\w*id\b|\$request->(?:input\(\s*['"]\w*id['"]|route\(\s*['"]\w*id['"]|\w*id\b))/i,
    jvm: pathIds.size ? new RegExp(String.raw`\b(\w+)Repository\.(?:findById|getById|getReferenceById)\(\s*(?:${[...pathIds].join('|')})\s*\)`) : /$^/,
    csharp: /\.(\w+)\.(?:FindAsync|Find)\(\s*id\s*\)|\.(\w+)\.(?:FirstOrDefault|SingleOrDefault|First|Single)(?:Async)?\(\s*(\w+)\s*=>\s*\3\.Id\s*==\s*id\s*\)/,
  };
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(sinks[lang]);
    const model = m && (m[1] ?? m[2]);
    if (!model || !owned.has(key(model))) continue;
    if (PUBLIC_READ_MODEL.test(key(model))) continue;
    // The same statement already narrows by the caller (current_user.orders.find, where('user_id', ...)->find)
    if (/current_user|user_id|owner_id|UserId|OwnerId|auth\(\)|Auth::|getUser|principal/i.test(lines[i].replace(m[0], ''))) continue;
    return [i, model];
  }
  return null;
}

export function evaluateIdorPolyglotRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}, context?: RepoContext): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  const lang = (Object.keys(LANG) as Lang[]).find((l) => LANG[l].test(path));
  if (!lang || SKIP_PATH.test(path) || !cleanContent || cleanContent.length > 400_000) return { findings, logs };
  // Rails: ApplicationController can require sign-in for every controller that inherits it
  const inheritsSignIn = lang === 'ruby' && Boolean(context?.railsAuthenticatedBase)
    && /<\s*ApplicationController\b/.test(cleanContent) && !/skip_before_action\s+:(?:authenticate\w*!?|authenticated|require_\w+)/.test(cleanContent);
  const signedIn = SIGNED_IN[lang].test(cleanContent) || inheritsSignIn;
  if (!signedIn || AUTHORIZED[lang].test(cleanContent) || ADMIN_ONLY.test(cleanContent)) return { findings, logs };
  const owned = ownedModels(lang, cleanContent);
  // In a signed-in Rails controller the User record belongs to the caller; profile pages are often public, so skip those
  if (lang === 'ruby' && !/(?:^|\/)(?:users|profiles?|members?|people|authors?)_controller\.rb$/.test(path)) owned.add('user');
  if (owned.size === 0) return { findings, logs };
  const sink = findSink(lang, lines, owned, cleanContent);
  if (!sink) return { findings, logs };

  const [idx, model] = sink;
  const lineNum = idx + 1;
  const rule = RULES[lang];
  const fix: Record<Lang, string> = {
    ruby: `Load it through the caller: current_user.${singular(model)}s.find(params[:id]) (or authorize it with your policy).`,
    php: `Load it through the caller: $request->user()->${singular(model)}s()->findOrFail($id), or $this->authorize('view', $${singular(model)}).`,
    jvm: `Load it with the caller in the query (e.g. ${model.charAt(0).toLowerCase() + model.slice(1)}Repository.findByIdAndOwner(id, principal)) or check the owner before returning it.`,
    csharp: `Filter by the caller in the same query (e.g. .FirstOrDefaultAsync(x => x.Id == id && x.UserId == userId)) or use an authorization handler.`,
  };
  findings.push({
    id: `flow${rule.ruleId}-${Date.now()}-${findingCounter.count++}`,
    ruleId: rule.ruleId,
    type: 'SECURITY',
    title: rule.title,
    severity: rule.severity,
    category: 'Broken Access Control',
    filePath: file.path,
    lineRange: `L${lineNum}`,
    snippet: (lines[idx] || '').trim(),
    reproductionSteps: [
      `${file.path}:${lineNum} loads ${model} by the id from the request in code that requires a signed-in user.`,
      `Elsewhere this file narrows ${model} to the signed-in user, but this lookup does not, so a signed-in user who changes the id in the URL gets someone else's ${singular(model)}.`,
    ],
    remediationPrompt: `${fix[lang]} (${file.path}:${lineNum})`,
    status: 'OPEN',
    falsePositive: false
  });
  logs.push(`[${new Date().toLocaleTimeString()}] [IDOR] HIGH: ${rule.title} at ${file.path}:${lineNum}`);
  return { findings, logs };
}
