/**
 * Cross-layer rules (XL-01.., Rule IDs 30301-30399): bugs that only show when two layers of the same repository
 * are read together: code vs deploy config, code vs database migrations, frontend vs backend, app vs proxy.
 * Each rule fires only when the layer it compares against exists in the repo, so a missing file never
 * turns into a finding. Repo-wide facts come from lib/scanner/infra-facts.ts via the RepoContext.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner/types';
import { emptyRepoContext, type RepoContext } from '../scanner/repo-context';
import { DOWN_MIGRATION, parseSize } from '../scanner/infra-facts';
import { SKIP, lineAt } from './logic-gemini-rules';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; lineIdx: number; why: string; fix: string; type: Finding['type']; category: string }
type Add = (h: Hit) => void;

const JS = /\.[cm]?[jt]sx?$/i;
const PY = /\.py$/i;
const GO = /\.go$/i;
const RB = /\.rb$/i;

/** Variables the platform or tooling sets; never expected in an env template. */
const PLATFORM_ENV = /^(?:NODE_ENV|NODE_OPTIONS|PORT|HOST|HOSTNAME|HOME|PATH|PWD|TZ|LANG|LC_\w+|USER|SHELL|TMPDIR|TEMP|CI|DEBUG|TERM|npm_\w+|NEXT_RUNTIME|NEXT_PHASE|NEXT_TELEMETRY_DISABLED|__NEXT\w*|ANALYZE|VERCEL\w*|NETLIFY\w*|CONTEXT|DEPLOY_\w+|URL|RENDER\w*|FLY_\w+|RAILWAY_\w+|HEROKU_\w+|DYNO|AWS_LAMBDA_\w+|AWS_EXECUTION_ENV|AWS_REGION|AWS_DEFAULT_REGION|LAMBDA_TASK_ROOT|K_SERVICE|K_REVISION|GOOGLE_CLOUD_PROJECT|FUNCTION_\w+|GITHUB_\w+|RUNNER_\w+|GITLAB_\w+|CF_PAGES\w*|EXPO_\w+|JEST_WORKER_ID|VITEST\w*|PLAYWRIGHT_\w+|PYTHONPATH|VIRTUAL_ENV|GOPATH|GOOS|GOARCH|RAILS_ENV|RACK_ENV|DJANGO_SETTINGS_MODULE|FLASK_APP|FLASK_ENV|MODE|DEV|PROD|SSR|BASE_URL)$/;

// ---------------------------------------------------------------------------------------------------------------
// XL-01: env var read by the code but declared nowhere (env template, compose, k8s, Dockerfile, CI, host config)
// Host-injected names that Next.js / Vite expose under a public prefix (NEXT_PUBLIC_VERCEL_URL etc.)
const PUBLIC_PLATFORM_ENV = /^(?:NEXT_PUBLIC_|VITE_|PUBLIC_|EXPO_PUBLIC_)(?:VERCEL|NETLIFY|RENDER|RAILWAY)\w*$/;
// Developer tooling and tests do not ship with the app, so a missing template entry cannot break a deploy
const NOT_DEPLOYED = /(?:^|\/)(?:scripts?|tools|bin|e2e|tests?|__tests__|spec|fixtures|examples?|benchmarks?)\/|\.(?:test|spec|stories)\.\w+$|_test\.go$|(?:^|\/)test_[^/]+\.py$/i;

/**
 * True when the file also treats the variable as optional: a presence check, `X && ...`, a ternary or a comparison.
 * `if (!process.env.X) throw ...` is the opposite (the app refuses to start without it), so it does not count.
 */
function readOptionally(name: string, c: string): boolean {
  const ref = String.raw`(?:process\??\.env\??\.${name}\b|process\.env\[\s*['"]${name}['"]\s*\]|import\.meta\.env\.${name}\b)`;
  for (const m of c.matchAll(new RegExp(String.raw`(?:!\s*|\bif\s*\(\s*|\bBoolean\(\s*)${ref}|${ref}\s*(?:&&|\?(?!\.)|[!=]==?)`, 'g'))) {
    if (/^!/.test(m[0]) && /\b(?:throw|process\.exit)\b/.test(c.slice(m.index!, m.index! + 160))) continue;
    return true;
  }
  return false;
}

function envReads(path: string, c: string): { name: string; idx: number }[] {
  const out: { name: string; idx: number }[] = [];
  const push = (name: string, idx: number) => { if (!PLATFORM_ENV.test(name) && !PUBLIC_PLATFORM_ENV.test(name)) out.push({ name, idx }); };
  if (NOT_DEPLOYED.test(path)) return out;
  if (JS.test(path)) {
    for (const m of c.matchAll(/\b(?:process\??\.env\??|import\.meta\.env)(?:\.([A-Z][A-Z0-9_]*)|\[\s*['"]([A-Z][A-Z0-9_]*)['"]\s*\])/g)) {
      if (readOptionally(m[1] ?? m[2], c)) continue;
      const after = c.slice(m.index! + m[0].length, m.index! + m[0].length + 6);
      if (/^\s*(?:\|\||\?\?|\?)/.test(after)) continue; // has a default
      const before = c.slice(Math.max(0, m.index! - 30), m.index!);
      if (/\bif\s*\(\s*!?\s*$|typeof\s+$/.test(before)) continue; // presence check, not a hard read
      push(m[1] ?? m[2], m.index!);
    }
  } else if (PY.test(path)) {
    for (const m of c.matchAll(/\bos\.environ\[\s*['"]([A-Z][A-Z0-9_]*)['"]\s*\]/g)) push(m[1], m.index!);
  } else if (GO.test(path)) {
    for (const m of c.matchAll(/\bos\.(?:Getenv|LookupEnv)\(\s*"([A-Z][A-Z0-9_]*)"\s*\)/g)) {
      const line = c.slice(m.index!, c.indexOf('\n', m.index!));
      if (/LookupEnv/.test(m[0]) || /==\s*""/.test(line)) continue; // checked by the caller
      // `v := os.Getenv("X")` followed by `if v == "" { ... default ... }`
      const assigned = c.slice(Math.max(0, m.index! - 60), m.index!).match(/(\w+)\s*:?=\s*$/)?.[1];
      if (assigned && new RegExp(String.raw`\b${assigned}\s*[!=]=\s*""`).test(c.slice(m.index!))) continue;
      push(m[1], m.index!);
    }
  } else if (RB.test(path)) {
    for (const m of c.matchAll(/\bENV\.fetch\(\s*['"]([A-Z][A-Z0-9_]*)['"]\s*\)(?!\s*\{)/g)) push(m[1], m.index!);
  }
  return out;
}

function checkEnv(path: string, c: string, ctx: RepoContext, add: Add) {
  const declared = ctx.infra.declaredEnv;
  if (!declared) return;
  const seen = new Set<string>();
  for (const { name, idx } of envReads(path, c)) {
    if (declared.has(name) || seen.has(name)) continue;
    seen.add(name);
    add({ ruleId: 30301, code: 'XL-01', severity: 'MEDIUM', lineIdx: lineAt(c, idx), type: 'VIBECARE', category: 'Deployment Bug',
      title: `${name} Is Read by the Code but Declared in No Env Template or Deploy Config`,
      why: `The code reads ${name} without a default, but it appears in none of the env templates, compose files, Kubernetes manifests, Dockerfiles or CI config in this repository. A fresh deploy or a new teammate will start without it, and this code fails at runtime.`,
      fix: `Add ${name} to .env.example (and to the deploy config that sets the others), or give it a safe default if it is optional.` });
  }
}

// ---------------------------------------------------------------------------------------------------------------
// XL-02: Dockerfile builds on an older Node than package.json engines allows
function checkDockerNode(path: string, c: string, ctx: RepoContext, add: Add) {
  if (!/(?:^|\/)dockerfile(?:\.[\w-]+)?$/i.test(path)) return;
  const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/') + 1) : '';
  const engines = ctx.infra.enginesNodeMin.find((e) => e.path === `${dir}package.json`) ?? ctx.infra.enginesNodeMin.find((e) => e.path === 'package.json');
  if (!engines) return;
  for (const d of ctx.infra.dockerNodeMajors.filter((x) => x.path === path)) {
    if (d.major >= engines.major) continue;
    add({ ruleId: 30302, code: 'XL-02', severity: 'MEDIUM', lineIdx: d.line, type: 'VIBECARE', category: 'Deployment Bug',
      title: `Dockerfile Uses Node ${d.major}, but ${engines.path} Requires Node ${engines.major}+`,
      why: `package.json "engines" asks for Node ${engines.major} or newer, while this image runs Node ${d.major}. Installs can refuse to run (engine-strict), and code that relies on newer Node APIs breaks only in the container.`,
      fix: `Use a node:${engines.major} (or newer) base image, or lower "engines" if the app really supports Node ${d.major}.` });
  }
}

// ---------------------------------------------------------------------------------------------------------------
// XL-03: app accepts bigger request bodies than the proxy in front of it
function checkBodyLimit(path: string, c: string, ctx: RepoContext, add: Add) {
  const proxy = ctx.infra.proxyBodyLimit;
  if (!proxy || !(JS.test(path) || PY.test(path))) return;
  const patterns: RegExp[] = [
    /\b(?:fileSize|maxFileSize)\s*:\s*(\d[\d_]*(?:\s*\*\s*\d+)*)/g, // multer / formidable limits (bytes)
    /\blimit\s*:\s*['"](\d+(?:\.\d+)?\s*[kmg]b?)['"]/gi, // express.json / body-parser
    /\bbodySizeLimit\s*:\s*['"](\d+(?:\.\d+)?\s*[kmg]b?)['"]/gi, // Next.js serverActions
    /\bMAX_CONTENT_LENGTH\s*=\s*(\d[\d_]*(?:\s*\*\s*\d+)*)/g, // Flask
  ];
  for (const re of patterns) {
    for (const m of c.matchAll(re)) {
      const raw = m[1].replace(/_/g, '');
      const bytes = /[kmg]/i.test(raw) ? parseSize(raw) : raw.split('*').reduce((n, p) => n * Number(p.trim()), 1);
      if (!bytes || bytes <= proxy.bytes * 1.05) continue;
      const mb = (n: number) => `${Math.round((n / 1024 / 1024) * 10) / 10} MB`;
      add({ ruleId: 30303, code: 'XL-03', severity: 'MEDIUM', lineIdx: lineAt(c, m.index!), type: 'VIBECARE', category: 'Deployment Bug',
        title: `App Accepts ${mb(bytes)} Uploads, but ${proxy.path} Stops Requests at ${mb(proxy.bytes)}`,
        why: `The proxy rejects any request body over ${mb(proxy.bytes)} with 413 before it reaches the app, so uploads between ${mb(proxy.bytes)} and ${mb(bytes)} fail in production even though they work locally.`,
        fix: `Raise client_max_body_size / proxy-body-size in ${proxy.path} to at least ${mb(bytes)}, or lower the app limit to match.` });
      return;
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------
// XL-04 / XL-05: Supabase queries against tables created in this repo's migrations
const SUPABASE_FROM = /\.from\(\s*['"`](\w+)['"`]\s*\)/g;
const isBrowserCode = (path: string, c: string) =>
  /^\s*['"]use client['"]/m.test(c) || /\bcreateBrowserClient\s*\(/.test(c)
  || (/(?:^|\/)(?:components|hooks)\//.test(path) && /\bcreateClient\s*\(/.test(c) && /ANON|PUBLISHABLE/i.test(c));

function checkSupabaseTables(path: string, c: string, ctx: RepoContext, add: Add) {
  if (!JS.test(path) || !c.includes('.from(')) return;
  const { createdTables, indexedColumns } = ctx.infra;
  if (createdTables.size === 0) return;
  const browser = isBrowserCode(path, c);
  const reportedRls = new Set<string>();
  for (const m of c.matchAll(SUPABASE_FROM)) {
    const table = m[1].toLowerCase();
    if (!createdTables.has(table)) continue;

    if (browser && ctx.exposesDatabaseToClients && !ctx.rlsEnabledTables.has(table) && !reportedRls.has(table)) {
      reportedRls.add(table);
      add({ ruleId: 30305, code: 'XL-05', severity: 'HIGH', lineIdx: lineAt(c, m.index!), type: 'SECURITY', category: 'Broken Access Control',
        title: `Browser Code Queries "${table}", a Table With Row Level Security Off in the Migrations`,
        why: `This file runs in the browser with the public anon key, and no migration enables RLS on "${table}". Anyone who opens devtools can query the whole table with the same key, not just the rows this page shows.`,
        fix: `Add "ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;" with policies that limit rows to their owner, or move this query to server code.` });
    }

    // XL-04: filter columns of this query chain without any index that starts with one of them
    const chain = c.slice(m.index!, c.indexOf(';', m.index!) > 0 ? c.indexOf(';', m.index!) : m.index! + 400).slice(0, 600);
    if (!/\.select\s*\(/.test(chain)) continue;
    const filters = [...chain.matchAll(/\.(?:eq|in|gt|gte|lt|lte|ilike|like|match)\(\s*['"`](\w+)['"`]/g)].map((f) => f[1].toLowerCase());
    // Flags and statuses have a few distinct values: an index on them rarely helps, so they are not reported
    const LOW_CARDINALITY = /^(?:is_\w+|has_\w+|published|active|enabled|disabled|deleted|archived|visible|hidden|status|state|type|kind|role|level|verified|approved|public|private|draft|featured)$/;
    if (filters.length === 0 || filters.some((f) => f === 'id') || filters.every((f) => LOW_CARDINALITY.test(f))) continue;
    const indexes = indexedColumns.get(table) ?? [];
    if (indexes.some((cols) => filters.includes(cols[0]))) continue;
    add({ ruleId: 30304, code: 'XL-04', severity: 'LOW', lineIdx: lineAt(c, m.index!), type: 'VIBECARE', category: 'Database Performance',
      title: `Query Filters "${table}" by ${filters.join(', ')}, but No Migration Indexes ${filters.length > 1 ? 'These Columns' : 'That Column'}`,
      why: `Every call scans the whole "${table}" table. It is fast with test data and slows down, then times out, as the table grows.`,
      fix: `Add an index in a migration: CREATE INDEX ON ${table} (${filters.join(', ')});` });
  }
}

// ---------------------------------------------------------------------------------------------------------------
// XL-06: Go HTTP calls with the default client (no timeout): one slow dependency hangs every request
function checkGoTimeout(path: string, c: string, add: Add) {
  if (!GO.test(path)) return;
  for (const m of c.matchAll(/\bhttp\.(?:Get|Post|PostForm|Head)\(/g)) {
    add({ ruleId: 30306, code: 'XL-06', severity: 'MEDIUM', lineIdx: lineAt(c, m.index!), type: 'VIBECARE', category: 'Reliability',
      title: 'Outbound HTTP Call Without a Timeout (Go)',
      why: 'http.Get / http.Post use http.DefaultClient, whose Timeout is zero (wait forever). If the other service stops answering, these calls pile up and the service runs out of goroutines and connections.',
      fix: 'Use a shared client with a timeout: var client = &http.Client{Timeout: 10 * time.Second}, then client.Get(...).' });
    return;
  }
  for (const m of c.matchAll(/&http\.Client\s*\{([^}]*)\}/g)) {
    if (/\bTimeout\s*:/.test(m[1])) continue;
    add({ ruleId: 30306, code: 'XL-06', severity: 'MEDIUM', lineIdx: lineAt(c, m.index!), type: 'VIBECARE', category: 'Reliability',
      title: 'Outbound HTTP Call Without a Timeout (Go)',
      why: 'A client without Timeout waits forever for a slow or stuck service, so one bad dependency hangs the requests that call it.',
      fix: 'Set Timeout on the client, e.g. &http.Client{Timeout: 10 * time.Second}.' });
    return;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// XL-07: balance / credits / stock updated by read-modify-write without a transaction or atomic update
const MONEYISH = /\b(balance|credits?|wallet|points|stock|inventory|quantity|seats|quota|remaining\w*|available\w*)\b/i;

function checkReadModifyWrite(path: string, c: string, add: Add) {
  if (JS.test(path) && /\bprisma\b|\bdb\.\w+\.(?:findUnique|findFirst)/.test(c) && !/\$transaction|\bincrement\s*:|\bdecrement\s*:|FOR\s+UPDATE/i.test(c)) {
    for (const m of c.matchAll(/\bdata\s*:\s*\{[^}]*?\b(\w+)\s*:\s*(\w+)\.(\w+)\s*([-+])\s*[\w.]+/g)) {
      const [, field, obj, prop] = m;
      if (field !== prop || !MONEYISH.test(field)) continue;
      if (!new RegExp(String.raw`\b${obj}\s*=\s*await\s+[\w.]+\.(?:findUnique|findFirst|findUniqueOrThrow|findFirstOrThrow)\(`).test(c)) continue;
      add({ ruleId: 30307, code: 'XL-07', severity: 'HIGH', lineIdx: lineAt(c, m.index!), type: 'SECURITY', category: 'Race Condition',
        title: 'Balance or Stock Is Read, Changed in Code, Then Saved Without a Lock',
        why: `Two requests that arrive together both read the same ${field}, both subtract (or add), and the second write overwrites the first. Someone who sends requests in parallel can spend the same ${field} twice.`,
        fix: `Update atomically: data: { ${field}: { decrement: amount } } with a where clause that checks the ${field} is still enough, or wrap the read and write in prisma.$transaction with a row lock.` });
      return;
    }
  }
  if (PY.test(path) && !/select_for_update|\bF\(\s*['"]/.test(c)) {
    for (const m of c.matchAll(/\b(\w+)\.(\w+)\s*(?:-=|\+=|=\s*\1\.\2\s*[-+])\s*[\w.()]+[^\n]*\n(?:[^\n]*\n){0,4}?\s*\1\.save\(/g)) {
      if (!MONEYISH.test(m[2])) continue;
      add({ ruleId: 30307, code: 'XL-07', severity: 'HIGH', lineIdx: lineAt(c, m.index!), type: 'SECURITY', category: 'Race Condition',
        title: 'Balance or Stock Is Read, Changed in Code, Then Saved Without a Lock',
        why: `Two requests at the same time both load the same ${m[2]}, both change it and both save: one change is lost, so the same ${m[2]} can be spent twice.`,
        fix: `Use an atomic update: Model.objects.filter(pk=..., ${m[2]}__gte=amount).update(${m[2]}=F('${m[2]}') - amount), or load the row with select_for_update() inside transaction.atomic().` });
      return;
    }
  }
}

/**
 * XL-07 for JPA/Hibernate, GORM, Eloquent and ActiveRecord: a balance-like field changed in code and saved a few
 * lines later, in a file with no row lock and no atomic update. Raw SQL SELECT-then-UPDATE is not covered yet.
 */
const JVM = /\.(?:java|kt)$/i;
const PHP_FILE = /\.php$/i;

interface OrmRmw { lang: RegExp; safe: RegExp; pattern: RegExp; field: (m: RegExpMatchArray) => string; fix: (field: string) => string }

const ORM_RMW: OrmRmw[] = [
  {
    // order.setBalance(order.getBalance() - amount); ... repository.save(order)
    lang: JVM,
    safe: /@Lock\s*\(|PESSIMISTIC_(?:WRITE|READ)|LockModeType|FOR\s+UPDATE|@Modifying|@Version\b/,
    pattern: /\b(\w+)\.set(\w+)\(\s*\1\.get\2\(\)\s*[-+]\s*[^;]+;[^\n]*\n(?:[^\n]*\n){0,5}?[^\n]*\.save(?:AndFlush)?\(\s*\1\s*\)/g,
    field: (m) => m[2],
    fix: (f) => `Lock the row (@Lock(LockModeType.PESSIMISTIC_WRITE) on the repository finder) inside @Transactional, or use an atomic @Modifying query: UPDATE ... SET ${f.toLowerCase()} = ${f.toLowerCase()} - :amount WHERE id = :id AND ${f.toLowerCase()} >= :amount.`,
  },
  {
    // wallet.Balance -= amount ... db.Save(&wallet)
    lang: GO,
    safe: /clause\.Locking|FOR\s+UPDATE|gorm\.Expr\(/i,
    pattern: /\b(\w+)\.(\w+)\s*(?:-=|\+=|=\s*\1\.\2\s*[-+])[^\n]*\n(?:[^\n]*\n){0,5}?[^\n]*\.Save\(\s*&?\1\s*\)/g,
    field: (m) => m[2],
    fix: (f) => `Update atomically: db.Model(&x).Where("${f.toLowerCase()} >= ?", amount).Update("${f.toLowerCase()}", gorm.Expr("${f.toLowerCase()} - ?", amount)), or read the row with clause.Locking{Strength: "UPDATE"} inside a transaction.`,
  },
  {
    // $wallet->balance -= $amount; ... $wallet->save();
    lang: PHP_FILE,
    safe: /lockForUpdate\s*\(|sharedLock\s*\(|->(?:de|in)crement\s*\(|FOR\s+UPDATE/i,
    pattern: /(\$\w+)->(\w+)\s*(?:-=|\+=|=\s*\1->\2\s*[-+])[^\n]*\n(?:[^\n]*\n){0,5}?[^\n]*\1->save\(\s*\)/g,
    field: (m) => m[2],
    fix: (f) => `Update atomically with ->decrement('${f}', $amount) on a query that checks ->where('${f}', '>=', $amount), or load the row with ->lockForUpdate() inside DB::transaction().`,
  },
  {
    // account.balance -= amount ... account.save!
    lang: RB,
    safe: /\.lock!|\bwith_lock\b|\.lock\.find|update_counters|update_all|FOR\s+UPDATE/i,
    pattern: /\b(\w+)\.(\w+)\s*(?:-=|\+=|=\s*\1\.\2\s*[-+])[^\n]*\n(?:[^\n]*\n){0,5}?\s*\1\.save!?\b/g,
    field: (m) => m[2],
    fix: (f) => `Wrap the change in record.with_lock { ... }, or update atomically: Model.where(id: id).where("${f} >= ?", amount).update_all(["${f} = ${f} - ?", amount]).`,
  },
];

/** Model methods: `self.credits -= amount` / `$this->balance -= $x` with a bare save elsewhere in the same model file. */
const MODEL_RMW: { lang: RegExp; safe: RegExp; change: RegExp; save: RegExp; fix: (f: string) => string }[] = [
  { lang: RB, safe: ORM_RMW[3].safe, change: /\bself\.(\w+)\s*(?:-=|\+=|=\s*self\.\1\s*[-+])/g, save: /^\s*(?:self\.)?save!?\b/m, fix: ORM_RMW[3].fix },
  { lang: PHP_FILE, safe: ORM_RMW[2].safe, change: /\$this->(\w+)\s*(?:-=|\+=|=\s*\$this->\1\s*[-+])/g, save: /\$this->save\(\s*\)/, fix: ORM_RMW[2].fix },
];

function checkOrmReadModifyWrite(path: string, c: string, add: Add) {
  for (const model of MODEL_RMW) {
    if (!model.lang.test(path) || model.safe.test(c) || !model.save.test(c)) continue;
    for (const m of c.matchAll(model.change)) {
      if (!MONEYISH.test(m[1])) continue;
      add({ ruleId: 30307, code: 'XL-07', severity: 'HIGH', lineIdx: lineAt(c, m.index!), type: 'SECURITY', category: 'Race Condition',
        title: 'Balance or Stock Is Read, Changed in Code, Then Saved Without a Lock',
        why: `This model changes ${m[1]} in memory and saves the whole row. Two requests at the same time both start from the same ${m[1]}, and the second save overwrites the first, so the same ${m[1]} can be spent twice.`,
        fix: model.fix(m[1]) });
      return;
    }
  }
  for (const orm of ORM_RMW) {
    if (!orm.lang.test(path) || orm.safe.test(c)) continue;
    for (const m of c.matchAll(orm.pattern)) {
      const field = orm.field(m);
      if (!MONEYISH.test(field)) continue;
      add({ ruleId: 30307, code: 'XL-07', severity: 'HIGH', lineIdx: lineAt(c, m.index!), type: 'SECURITY', category: 'Race Condition',
        title: 'Balance or Stock Is Read, Changed in Code, Then Saved Without a Lock',
        why: `Two requests at the same time both load the same ${field}, both change it in memory and both save: one change is lost, so the same ${field} can be spent twice.`,
        fix: orm.fix(field) });
      return;
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------
// XL-08: per-user data cached under a key that does not include the user
function checkSharedCacheKey(path: string, c: string, add: Add) {
  if (!JS.test(path) && !PY.test(path)) return;
  for (const m of c.matchAll(/\b(?:redis|cache|client|kv|memcached?)\.(?:set|setex|setEx|put|hset)\(\s*['"`]([\w:.-]+)['"`]\s*,\s*(?:\d+\s*,\s*)?(?:JSON\.stringify\(\s*|json\.dumps\(\s*)?(\w+)/g)) {
    const [, key, value] = m;
    if (!/^(?:user|me|profile|session|account|currentUser|current_user|cart|orders?|billing|subscription)$/i.test(value)) continue;
    add({ ruleId: 30308, code: 'XL-08', severity: 'HIGH', lineIdx: lineAt(c, m.index!), type: 'SECURITY', category: 'Information Disclosure',
      title: `Per-User Data "${value}" Cached Under the Fixed Key "${key}"`,
      why: `Every user reads and writes the same cache entry, so the next visitor gets the previous user's ${value}.`,
      fix: `Put the user in the key, e.g. \`${key}:\${userId}\`, or do not cache per-user data in a shared cache.` });
    return;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// XL-09: background jobs that retry forever
function checkInfiniteRetry(path: string, c: string, add: Add) {
  const hits: [RegExp, string][] = [
    [/\bmax_retries\s*=\s*None\b/g, 'Celery task retries forever (max_retries=None)'],
    [/\battempts\s*:\s*(?:Infinity|Number\.MAX_SAFE_INTEGER|Number\.POSITIVE_INFINITY)\b/g, 'Queue job retries forever (attempts: Infinity)'],
    [/\bretry\s*:\s*Float::INFINITY\b/g, 'Sidekiq job retries forever'],
  ];
  for (const [re, title] of hits) {
    for (const m of c.matchAll(re)) {
      add({ ruleId: 30309, code: 'XL-09', severity: 'MEDIUM', lineIdx: lineAt(c, m.index!), type: 'VIBECARE', category: 'Reliability',
        title,
        why: 'A job that can never succeed (bad input, a deleted record, a revoked key) keeps running and fails again forever, filling the queue and burning worker time and any paid API it calls.',
        fix: 'Set a finite retry count with backoff (e.g. max_retries=5, attempts: 5 with exponential backoff) and send jobs that run out of retries to a dead-letter queue.' });
      return;
    }
  }
  void path;
}

// ---------------------------------------------------------------------------------------------------------------
// XL-10: frontend posts a body to an API route in this repo without a field the route reads
function checkBodyContract(path: string, c: string, ctx: RepoContext, add: Add) {
  if (!JS.test(path) || ctx.infra.routeBodyFields.size === 0 || !/\bfetch\s*\(/.test(c)) return;
  for (const m of c.matchAll(/\bfetch\(\s*['"`](\/api\/[\w/-]+)['"`]\s*,\s*\{/g)) {
    const route = ctx.infra.routeBodyFields.get(m[1].replace(/\/$/, ''));
    if (!route || route.path === path) continue;
    const options = c.slice(m.index! + m[0].length, m.index! + m[0].length + 400);
    const body = /^[^;]*?body\s*:\s*JSON\.stringify\(\s*\{([^{}]*)\}\s*\)/.exec(options);
    if (!body || /\.\.\./.test(body[1])) continue;
    const sent = new Set(body[1].split(',').map((p) => p.trim().split(':')[0].trim()).filter(Boolean));
    const missing = route.fields.filter((f) => !sent.has(f));
    if (missing.length === 0) continue;
    add({ ruleId: 30310, code: 'XL-10', severity: 'MEDIUM', lineIdx: lineAt(c, m.index!), type: 'VIBECARE', category: 'Logic Bug',
      title: `Request to ${m[1]} Leaves Out ${missing.join(', ')}, Which the Route Reads`,
      why: `${route.path} reads ${route.fields.join(', ')} from the request body, but this call only sends ${[...sent].join(', ') || 'nothing'}. On the server ${missing.join(', ')} ${missing.length === 1 ? 'is' : 'are'} undefined, so the request fails or saves incomplete data.`,
      fix: `Send ${missing.join(', ')} in the body, or update the route if ${missing.length === 1 ? 'that field was' : 'those fields were'} renamed.` });
  }
}

// ---------------------------------------------------------------------------------------------------------------
// XL-11: payment webhook that credits the account without remembering which events it already handled
function checkWebhookDedupe(path: string, c: string, add: Add) {
  if (!JS.test(path) && !PY.test(path)) return;
  if (!/constructEvent|construct_event|webhooks\.(?:verify|unwrap)|stripe-signature|Stripe-Signature/.test(c)) return;
  const credit = /\b(?:balance|credits?|tokens?|points|wallet)\b\s*[:=]\s*[^;\n]*[+]|\bincrement\s*:\s*|\bF\(\s*['"](?:balance|credits?)['"]\)\s*\+|\.(?:increment|incrBy|incrby)\(/i.exec(c);
  if (!credit) return;
  if (/\bevent\.id\b|event\[['"]id['"]\]|processed_?events|webhook_?events|idempoten|already\s+(?:processed|handled)|ON\s+CONFLICT|upsert|unique/i.test(c)) return;
  add({ ruleId: 30311, code: 'XL-11', severity: 'HIGH', lineIdx: lineAt(c, credit.index), type: 'SECURITY', category: 'Revenue Protection',
    title: 'Payment Webhook Adds Credit Without Recording Which Events It Already Handled',
    why: 'Stripe and other providers deliver the same event more than once (retries, timeouts, replays from the dashboard). This handler adds the credit every time, so one payment can top up the balance several times.',
    fix: 'Store event.id in a table with a unique constraint before applying the change, and skip events that are already there (or make the update idempotent on the payment id).' });
}

// ---------------------------------------------------------------------------------------------------------------
// XL-12: SMS / OTP send endpoint without any rate limit (paid per message)
function checkSmsRateLimit(path: string, c: string, add: Add) {
  if (!JS.test(path) && !PY.test(path)) return;
  const send = /\b(?:messages|verifications)\.create\s*\(|\bsns\.publish\s*\(|\bvonage\.(?:sms|message)s?\.send|\bsendSms\w*\s*\(|\bsend_sms\w*\s*\(/.exec(c);
  if (!send) return;
  if (!/twilio|vonage|nexmo|messagebird|plivo|sns|sms|otp/i.test(c)) return;
  const isEndpoint = /\bexport\s+(?:async\s+)?function\s+(?:POST|GET)\b|['"]use server['"]|\b(?:app|router)\.(?:post|get)\s*\(|@(?:app|router)\.(?:post|route)|def\s+\w+\(\s*request\b/.test(c);
  if (!isEndpoint) return;
  if (/rate[-_ ]?limit|ratelimit|limiter|throttl|slowDown|Ratelimit|upstash|captcha|turnstile|recaptcha|hcaptcha|cooldown|attempts?\s*[<>]=?/i.test(c)) return;
  add({ ruleId: 30312, code: 'XL-12', severity: 'HIGH', lineIdx: lineAt(c, send.index), type: 'SECURITY', category: 'Abuse & Cost Control',
    title: 'Endpoint Sends SMS Without a Rate Limit',
    why: 'Each SMS is billed to you. Without a limit per phone number and per IP, a script can call this endpoint in a loop and send thousands of messages (SMS pumping), on your bill.',
    fix: 'Limit sends per phone number and per IP (e.g. 3 per 10 minutes), add a CAPTCHA before the first send, and block premium-rate country codes you do not serve.' });
}

// ---------------------------------------------------------------------------------------------------------------
// XL-13: one query on a model skips the tenant filter every other query on that model uses
function checkTenantFilter(path: string, c: string, add: Add) {
  if (!JS.test(path)) return;
  const TENANT = /\b(organizationId|orgId|tenantId|workspaceId|teamId|companyId|accountId)\b/;
  const calls = [...c.matchAll(/\b(?:prisma|db|tx)\.(\w+)\.(findMany|findFirst|updateMany|deleteMany|count)\(\s*\{([\s\S]{0,400}?)\}\s*\)/g)];
  const byModel = new Map<string, { idx: number; scoped: boolean }[]>();
  for (const m of calls) {
    const list = byModel.get(m[1]) ?? [];
    // A spread or a where built elsewhere may carry the tenant filter: only literal where objects are judged
    if (/\.\.\.\w|where\s*:\s*\w+\s*[,}]/.test(m[3])) continue;
    list.push({ idx: m.index!, scoped: TENANT.test(m[3]) });
    byModel.set(m[1], list);
  }
  for (const [model, list] of byModel) {
    const scoped = list.filter((x) => x.scoped).length;
    const unscoped = list.filter((x) => !x.scoped);
    if (scoped < 2 || unscoped.length !== 1) continue;
    add({ ruleId: 30313, code: 'XL-13', severity: 'HIGH', lineIdx: lineAt(c, unscoped[0].idx), type: 'SECURITY', category: 'Broken Access Control',
      title: `This ${model} Query Skips the Tenant Filter the Other ${model} Queries in This File Use`,
      why: `${scoped} other queries on ${model} here filter by the organization or workspace; this one does not, so it reads or changes rows from every customer, not just the caller's.`,
      fix: `Add the same tenant condition (e.g. where: { organizationId: session.orgId, ... }) to this query.` });
  }
}

// ---------------------------------------------------------------------------------------------------------------
// XL-15: a cascading foreign key (ON DELETE CASCADE / SET NULL) on a column no migration indexes. Postgres does not
// index foreign keys by itself, so deleting a parent row scans the whole child table. Indexes from every migration in
// the repo count (repo-wide index facts), including primary keys, UNIQUE constraints and composite indexes that start
// with the column. Same check as Supabase's "unindexed foreign keys" advisor, before the migration ships.
const sqlTable = (name: string) => name.replace(/"/g, '').toLowerCase().split('.').pop() ?? '';

function checkCascadeForeignKeyIndex(path: string, c: string, ctx: RepoContext, add: Add) {
  if (!/\.sql$/i.test(path) || DOWN_MIGRATION.test(path)) return;
  const indexed =(table: string, col: string) => (ctx.infra.indexedColumns.get(table) ?? []).some((cols) => cols[0] === col);
  const fks: { table: string; col: string; idx: number }[] = [];
  for (const t of c.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w."]+)\s*\(([\s\S]*?)\);/gi)) {
    const table = sqlTable(t[1]);
    const bodyStart = t.index! + t[0].indexOf('(') + 1;
    // Inline: user_id uuid not null references auth.users (id) on delete cascade
    for (const m of t[2].matchAll(/^\s*"?(\w+)"?\s+[\w ()]+?\bREFERENCES\s+[\w."]+(?:\s*\([^)]*\))?[^,\n]*?\bON\s+DELETE\s+(?:CASCADE|SET\s+NULL)/gim)) {
      fks.push({ table, col: m[1].toLowerCase(), idx: bodyStart + m.index! });
    }
    // Table level: foreign key (team_id) references teams (id) on delete cascade
    for (const m of t[2].matchAll(/FOREIGN\s+KEY\s*\(\s*"?(\w+)"?\s*\)\s*REFERENCES\s+[\w."]+(?:\s*\([^)]*\))?[^,]*?\bON\s+DELETE\s+(?:CASCADE|SET\s+NULL)/gi)) {
      fks.push({ table, col: m[1].toLowerCase(), idx: bodyStart + m.index! });
    }
  }
  for (const m of c.matchAll(/ALTER\s+TABLE\s+(?:ONLY\s+)?([\w."]+)\s+ADD\s+(?:CONSTRAINT\s+[\w"]+\s+)?FOREIGN\s+KEY\s*\(\s*"?(\w+)"?\s*\)\s*REFERENCES\s+[\w."]+(?:\s*\([^)]*\))?[^;]*?\bON\s+DELETE\s+(?:CASCADE|SET\s+NULL)/gi)) {
    fks.push({ table: sqlTable(m[1]), col: m[2].toLowerCase(), idx: m.index! });
  }
  for (const fk of fks) {
    if (/^(?:id|constraint|primary|foreign|unique|check)$/i.test(fk.col) || indexed(fk.table, fk.col)) continue;
    // A later migration renamed the column or the table: the old name no longer exists, so its index status is moot
    if (ctx.infra.renamedAway.has(fk.table) || ctx.infra.renamedAway.has(`${fk.table}.${fk.col}`)) continue;
    add({ ruleId: 30315, code: 'XL-15', severity: 'LOW', lineIdx: lineAt(c, fk.idx), type: 'INFRA_DATABASE', category: 'Schema Optimization',
      title: `${fk.table}.${fk.col} Cascades on Delete but No Migration Indexes It`,
      why: `Postgres does not index foreign key columns on its own. When a parent row is deleted, the database looks for matching ${fk.table} rows by ${fk.col}; without an index that is a full scan of ${fk.table}, which gets slow and holds locks as the table grows.`,
      fix: `Add an index in a migration: CREATE INDEX ON ${fk.table} (${fk.col});` });
  }
}

// ---------------------------------------------------------------------------------------------------------------
export function evaluateCrossLayerRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}, context: RepoContext = emptyRepoContext()): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  const c = cleanContent;
  if (!c || c.length > 400_000 || SKIP.test(path)) return { findings, logs };
  const hits: Hit[] = [];
  const add: Add = (h) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };

  checkEnv(path, c, context, add);
  checkDockerNode(path, c, context, add);
  checkBodyLimit(path, c, context, add);
  checkSupabaseTables(path, c, context, add);
  checkGoTimeout(path, c, add);
  checkReadModifyWrite(path, c, add);
  checkOrmReadModifyWrite(path, c, add);
  checkSharedCacheKey(path, c, add);
  checkInfiniteRetry(path, c, add);
  checkBodyContract(path, c, context, add);
  checkWebhookDedupe(path, c, add);
  checkSmsRateLimit(path, c, add);
  checkTenantFilter(path, c, add);
  checkCascadeForeignKeyIndex(path, c, context, add);

  const raw = (file.content || '').split('\n');
  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `xl${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: h.type,
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (raw[h.lineIdx] || lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum} against the rest of the repository.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Engineering',
      falsePositive: false,
    });
    logs.push(`[${ts}] [CROSS-LAYER] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
