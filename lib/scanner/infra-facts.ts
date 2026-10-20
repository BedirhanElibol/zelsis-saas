/**
 * Repository-wide facts for the cross-layer rules (lib/rules/cross-layer-rules.ts): what the deploy and
 * database layers declare, so a rule can compare them with what the application code does.
 * Every fact is "declared somewhere in the repo"; a rule only fires when the declaring layer exists at all.
 */
import type { CodeFile } from './types';
import { routePathOf } from './ast/cross-file';

export interface InfraFacts {
  /** Env var names declared for deployment; null when the repo has no env template (.env.example etc.). */
  declaredEnv: Set<string> | null;
  /** Node majors from Dockerfile `FROM node:<major>` lines. */
  dockerNodeMajors: { path: string; major: number; line: number }[];
  /** Lowest Node major allowed by package.json engines.node, per package.json. */
  enginesNodeMin: { path: string; major: number }[];
  /** Smallest request body limit (bytes) set at the proxy: nginx client_max_body_size, ingress proxy-body-size. */
  proxyBodyLimit: { path: string; bytes: number } | null;
  /** Tables created in SQL migrations (normalized names). */
  createdTables: Set<string>;
  /** Indexed column lists per table: `orders` -> [['user_id'], ['status','created_at']]; includes primary keys and unique constraints. */
  indexedColumns: Map<string, string[][]>;
  /** Tables and table.column names that some migration renames away (old names), so checks on the old name are moot. */
  renamedAway: Set<string>;
  /** Static Next.js API routes -> body fields the handler destructures from req.json() without a default. */
  routeBodyFields: Map<string, { path: string; fields: string[] }>;
}

export const emptyInfraFacts = (): InfraFacts => ({
  declaredEnv: null, dockerNodeMajors: [], enginesNodeMin: [], proxyBodyLimit: null, createdTables: new Set(), indexedColumns: new Map(), renamedAway: new Set(), routeBodyFields: new Map(),
});

/** Down / rollback migrations: they undo their own up migration, so they say nothing about the final schema. */
export const DOWN_MIGRATION = /(?:^|\/)down\.sql$|[._-]down\.sql$|(?:^|\/)rollbacks?\//i;

const ENV_TEMPLATE = /(?:^|\/)\.env\.(?:example|sample|template|dist|defaults?|local\.example|development\.example|production\.example)$|(?:^|\/)(?:example|sample)\.env$|(?:^|\/)env\.example$/i;
const sqlName = (name: string) => name.replace(/"/g, '').toLowerCase().split('.').pop() ?? '';

/** `10m` / `1M` / `512k` / `1g` / `0` (nginx: unlimited) -> bytes; null when it cannot be read. */
export function parseSize(value: string): number | null {
  const m = /^\s*['"]?(\d+(?:\.\d+)?)\s*([kmg]?)b?['"]?\s*$/i.exec(value);
  if (!m) return null;
  const n = Number(m[1]);
  const unit = m[2].toLowerCase();
  return Math.round(n * (unit === 'g' ? 1024 ** 3 : unit === 'm' ? 1024 ** 2 : unit === 'k' ? 1024 : 1));
}

/** Lowest major a semver range allows: `>=18` -> 18, `^20.11` -> 20, `18.x || 20.x` -> 18. */
export function minNodeMajor(range: string): number | null {
  const majors = [...range.matchAll(/(?:^|[\s|>=^~v])(\d{1,2})(?=\.|\s|$|\b)/g)].map((m) => Number(m[1])).filter((n) => n >= 4 && n <= 40);
  return majors.length ? Math.min(...majors) : null;
}

export function collectInfraFacts(files: CodeFile[]): InfraFacts {
  const facts = emptyInfraFacts();
  const declared = new Set<string>();
  let hasTemplate = false;

  for (const file of files) {
    const path = (file.path || '').replace(/\\/g, '/');
    const content = file.content || '';
    const lower = path.toLowerCase();

    if (ENV_TEMPLATE.test(path)) {
      hasTemplate = true;
      for (const m of content.matchAll(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/gm)) declared.add(m[1]);
    }
    if (/(?:^|\/)(?:docker-)?compose[\w.-]*\.ya?ml$/i.test(path)) {
      for (const m of content.matchAll(/^\s*-\s*['"]?([A-Za-z_][A-Za-z0-9_]*)(?:=|['"]?\s*$)/gm)) declared.add(m[1]);
      for (const m of content.matchAll(/^\s+([A-Z][A-Z0-9_]*)\s*:/gm)) declared.add(m[1]);
      for (const m of content.matchAll(/\$\{([A-Za-z_][A-Za-z0-9_]*)/g)) declared.add(m[1]);
    }
    if (/\.ya?ml$/i.test(path) && /\bkind:\s*(?:Deployment|StatefulSet|DaemonSet|CronJob|Job|Pod|ConfigMap|Secret)\b/.test(content)) {
      for (const m of content.matchAll(/-\s*name:\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*\n\s*(?:value|valueFrom)\s*:/g)) declared.add(m[1]);
      for (const m of content.matchAll(/^\s{2,}([A-Z][A-Z0-9_]*)\s*:/gm)) declared.add(m[1]);
    }
    if (/(?:^|\/)dockerfile(?:\.[\w-]+)?$/i.test(path)) {
      for (const m of content.matchAll(/^\s*(?:ENV|ARG)\s+([A-Za-z_][A-Za-z0-9_]*)/gim)) declared.add(m[1]);
      for (const m of content.matchAll(/^\s*ENV\s+(?:[A-Za-z_]\w*=\S*\s+)*([A-Za-z_]\w*)=/gim)) declared.add(m[1]);
      const lines = content.split('\n');
      lines.forEach((l, i) => {
        const from = /^\s*FROM\s+(?:--platform=\S+\s+)?(?:[\w.-]+\/)*node:(\d{1,2})\b/i.exec(l);
        if (from) facts.dockerNodeMajors.push({ path, major: Number(from[1]), line: i });
      });
    }
    if (/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(path) || /(?:^|\/)(?:fly\.toml|render\.ya?ml|netlify\.toml|app\.ya?ml|railway\.json|vercel\.json|serverless\.ya?ml)$/i.test(path)) {
      for (const m of content.matchAll(/^\s+([A-Z][A-Z0-9_]*)\s*[:=]/gm)) declared.add(m[1]);
      for (const m of content.matchAll(/(?:key|name)\s*:\s*['"]?([A-Z][A-Z0-9_]*)['"]?/g)) declared.add(m[1]);
      for (const m of content.matchAll(/"([A-Z][A-Z0-9_]*)"\s*:/g)) declared.add(m[1]);
    }
    if (/(?:^|\/)package\.json$/.test(path) && !/node_modules\//.test(path)) {
      const engines = /"engines"\s*:\s*\{[^}]*"node"\s*:\s*"([^"]+)"/.exec(content);
      const major = engines ? minNodeMajor(engines[1]) : null;
      if (major !== null) facts.enginesNodeMin.push({ path, major });
    }
    if (/nginx|\.conf$/i.test(lower) || /\.ya?ml$/i.test(path)) {
      for (const m of content.matchAll(/client_max_body_size\s+([\w.]+)\s*;|proxy-body-size["']?\s*:\s*["']?([\w.]+)/gi)) {
        const bytes = parseSize(m[1] ?? m[2]);
        if (bytes && (!facts.proxyBodyLimit || bytes < facts.proxyBodyLimit.bytes)) facts.proxyBodyLimit = { path, bytes };
      }
    }
    if (/\.sql$/i.test(path)) {
      for (const m of content.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w."]+)\s*\(([\s\S]*?)\);/gi)) {
        const table = sqlName(m[1]);
        facts.createdTables.add(table);
        const cols = facts.indexedColumns.get(table) ?? [];
        for (const line of m[2].split('\n')) {
          const col = /^\s*"?(\w+)"?\s+\w+[^,]*\b(?:PRIMARY\s+KEY|UNIQUE)\b/i.exec(line);
          if (col) cols.push([col[1].toLowerCase()]);
        }
        for (const pk of m[2].matchAll(/(?:PRIMARY\s+KEY|UNIQUE)\s*\(([^)]+)\)/gi)) cols.push(pk[1].split(',').map((c) => c.replace(/"/g, '').trim().toLowerCase()));
        facts.indexedColumns.set(table, cols);
      }
      for (const m of content.matchAll(/CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(?:[\w"]+\s+)?ON\s+(?:ONLY\s+)?([\w."]+)\s*(?:USING\s+\w+\s*)?\(([^;]+?)\)\s*(?:WHERE|INCLUDE|;|$)/gim)) {
        const table = sqlName(m[1]);
        const cols = facts.indexedColumns.get(table) ?? [];
        cols.push(m[2].split(',').map((c) => c.replace(/"/g, '').replace(/\s+(?:ASC|DESC|NULLS\s+\w+)\b/gi, '').trim().toLowerCase()));
        facts.indexedColumns.set(table, cols);
      }
      // Names that stop existing in forward migrations: RENAME COLUMN a TO b, RENAME TO u, DROP COLUMN a, DROP TABLE t.
      // Down migrations (down.sql) undo their own up.sql and would erase every table, so they are not read for this.
      if (!DOWN_MIGRATION.test(path)) {
        for (const m of content.matchAll(/ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([\w."]+)\s+RENAME\s+(?:(?:COLUMN\s+)?([\w"]+)\s+)?TO\b/gi)) {
          const table = sqlName(m[1]);
          facts.renamedAway.add(m[2] && !/^column$/i.test(m[2]) ? `${table}.${m[2].replace(/"/g, '').toLowerCase()}` : table);
        }
        for (const m of content.matchAll(/ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([\w."]+)\s+DROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?([\w"]+)/gi)) {
          if (!/^(?:constraint|default|not)$/i.test(m[2])) facts.renamedAway.add(`${sqlName(m[1])}.${m[2].replace(/"/g, '').toLowerCase()}`);
        }
        for (const m of content.matchAll(/DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([\w.", ]+?)\s*(?:CASCADE|RESTRICT)?\s*;/gi)) {
          for (const t of m[1].split(',')) facts.renamedAway.add(sqlName(t.trim()));
        }
      }
      for (const m of content.matchAll(/ALTER\s+TABLE\s+(?:ONLY\s+)?([\w."]+)\s+ADD\s+(?:CONSTRAINT\s+\w+\s+)?(?:PRIMARY\s+KEY|UNIQUE)\s*\(([^)]+)\)/gi)) {
        const table = sqlName(m[1]);
        const cols = facts.indexedColumns.get(table) ?? [];
        cols.push(m[2].split(',').map((c) => c.replace(/"/g, '').trim().toLowerCase()));
        facts.indexedColumns.set(table, cols);
      }
    }
  }
  for (const file of files) {
    const path = (file.path || '').replace(/\\/g, '/');
    const route = routePathOf(path);
    if (!route || /\[/.test(path)) continue;
    const m = /const\s*\{([^}]*)\}\s*=\s*await\s+(?:req|request)\.json\(\)/.exec(file.content || '');
    if (!m || /\.\.\./.test(m[1])) continue;
    const fields = m[1].split(',').map((p) => p.trim()).filter((p) => p && !p.includes('=')).map((p) => p.split(':')[0].trim()).filter((p) => /^\w+$/.test(p));
    if (fields.length) facts.routeBodyFields.set(route, { path, fields });
  }
  facts.declaredEnv = hasTemplate ? declared : null;
  return facts;
}
