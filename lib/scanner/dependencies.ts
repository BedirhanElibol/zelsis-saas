/**
 * Resolved dependency extraction from lockfiles and pinned manifests, for OSV.dev lookups.
 * Only exact versions are extracted: ranges in package.json and similar are not versions.
 */

export type OsvEcosystem = 'npm' | 'PyPI' | 'Go' | 'RubyGems' | 'Packagist' | 'crates.io' | 'Maven';

export interface Dependency {
  ecosystem: OsvEcosystem;
  name: string;
  version: string;
  /** Lockfile or manifest the version was read from. */
  file: string;
  /** 1-based line of the entry in that file (1 when it cannot be located). */
  line: number;
  /** Development-only dependency (not shipped to production) when the lockfile says so. */
  dev: boolean;
}

/** Pure lockfiles: dependency data only, never evaluated by pattern rules. */
const LOCKFILE_RE = /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|pipfile\.lock|uv\.lock|gemfile\.lock|composer\.lock|cargo\.lock|go\.sum)$/i;
/** Manifests that may pin exact versions (also evaluated by pattern rules). */
const PINNED_MANIFEST_RE = /(?:^|\/)(?:requirements[\w.-]*\.txt|go\.mod|pom\.xml)$/i;

export const isDependencyLockfile = (path: string): boolean => LOCKFILE_RE.test(path);
export const isDependencyFile = (path: string): boolean => LOCKFILE_RE.test(path) || PINNED_MANIFEST_RE.test(path);

const MAX_DEPENDENCIES = 5000;

function lineOf(lines: string[], ...needles: string[]): number {
  const idx = lines.findIndex((l) => needles.every((n) => l.includes(n)));
  if (idx !== -1) return idx + 1;
  const first = lines.findIndex((l) => l.includes(needles[0]));
  return first !== -1 ? first + 1 : 1;
}

function parsePackageLock(path: string, content: string, lines: string[]): Dependency[] {
  const out: Dependency[] = [];
  let json: { packages?: Record<string, { name?: string; version?: string; dev?: boolean; link?: boolean }>; dependencies?: Record<string, unknown> };
  try { json = JSON.parse(content); } catch { return out; }
  if (json.packages) {
    for (const [key, pkg] of Object.entries(json.packages)) {
      if (!key || pkg.link || !pkg.version) continue;
      const name = pkg.name ?? key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      if (!name || !/^\d/.test(pkg.version)) continue;
      out.push({ ecosystem: 'npm', name, version: pkg.version, file: path, line: lineOf(lines, `"${key}"`), dev: Boolean(pkg.dev) });
    }
    return out;
  }
  const walk = (deps: Record<string, unknown> | undefined) => {
    for (const [name, raw] of Object.entries(deps ?? {})) {
      const dep = raw as { version?: string; dev?: boolean; dependencies?: Record<string, unknown> };
      if (dep.version && /^\d/.test(dep.version)) {
        out.push({ ecosystem: 'npm', name, version: dep.version, file: path, line: lineOf(lines, `"${name}"`), dev: Boolean(dep.dev) });
      }
      walk(dep.dependencies);
    }
  };
  walk(json.dependencies);
  return out;
}

function parseYarnLock(path: string, lines: string[]): Dependency[] {
  const out: Dependency[] = [];
  let current: { name: string; line: number } | null = null;
  lines.forEach((l, i) => {
    if (l && !/^\s/.test(l) && l.trimEnd().endsWith(':') && !l.startsWith('#')) {
      const spec = l.replace(/:$/, '').split(',')[0].trim().replace(/^"|"$/g, '');
      const at = spec.lastIndexOf('@');
      current = at > 0 ? { name: spec.slice(0, at).replace(/@npm$/, ''), line: i + 1 } : null;
      if (current && spec.includes('@npm:')) current.name = spec.slice(0, spec.indexOf('@npm:'));
      if (current?.name === '__metadata') current = null;
      return;
    }
    const v = l.match(/^\s+version:?\s+"?([^"\s]+)"?/);
    if (v && current) {
      if (/^\d/.test(v[1]) && !v[1].includes('use.local')) {
        out.push({ ecosystem: 'npm', name: current.name, version: v[1], file: path, line: current.line, dev: false });
      }
      current = null;
    }
  });
  return out;
}

function parsePnpmLock(path: string, lines: string[]): Dependency[] {
  const out: Dependency[] = [];
  let inPackages = false;
  lines.forEach((l, i) => {
    if (/^\S/.test(l)) { inPackages = /^packages:\s*$/.test(l); return; }
    if (!inPackages) return;
    const m = l.match(/^ {2}['"]?\/?((?:@[^/@\s'"]+\/)?[^/@\s'"(]+)[@/](\d[^(:'"\s]*)/);
    if (m) out.push({ ecosystem: 'npm', name: m[1], version: m[2], file: path, line: i + 1, dev: false });
  });
  return out;
}

function parseRequirements(path: string, lines: string[]): Dependency[] {
  const out: Dependency[] = [];
  lines.forEach((l, i) => {
    const m = l.split('#')[0].split(';')[0].trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s,]*)$/);
    if (m) out.push({ ecosystem: 'PyPI', name: m[1], version: m[2], file: path, line: i + 1, dev: /dev|test/i.test(path) });
  });
  return out;
}

function parsePipfileLock(path: string, content: string, lines: string[]): Dependency[] {
  const out: Dependency[] = [];
  let json: Record<string, Record<string, { version?: string }>>;
  try { json = JSON.parse(content); } catch { return out; }
  for (const section of ['default', 'develop']) {
    for (const [name, dep] of Object.entries(json[section] ?? {})) {
      const version = dep?.version?.replace(/^==/, '');
      if (version && /^\d/.test(version)) {
        out.push({ ecosystem: 'PyPI', name, version, file: path, line: lineOf(lines, `"${name}"`), dev: section === 'develop' });
      }
    }
  }
  return out;
}

/** poetry.lock, uv.lock, Cargo.lock: TOML [[package]] tables with name/version keys. */
function parseTomlPackages(path: string, lines: string[], ecosystem: OsvEcosystem): Dependency[] {
  const out: Dependency[] = [];
  let pkg: { name?: string; version?: string; line: number; dev: boolean } | null = null;
  const flush = () => {
    if (pkg?.name && pkg.version && /^\d/.test(pkg.version)) {
      out.push({ ecosystem, name: pkg.name, version: pkg.version, file: path, line: pkg.line, dev: pkg.dev });
    }
  };
  lines.forEach((l, i) => {
    if (/^\[\[package\]\]/.test(l)) { flush(); pkg = { line: i + 1, dev: false }; return; }
    if (/^\[/.test(l)) { flush(); pkg = null; return; }
    if (!pkg) return;
    const kv = l.match(/^(name|version|category)\s*=\s*"([^"]*)"/);
    if (kv?.[1] === 'name') pkg.name = kv[2];
    else if (kv?.[1] === 'version') pkg.version = kv[2];
    else if (kv?.[1] === 'category') pkg.dev = kv[2] === 'dev';
  });
  flush();
  return out;
}

function parseGemfileLock(path: string, lines: string[]): Dependency[] {
  const out: Dependency[] = [];
  let inSpecs = false;
  lines.forEach((l, i) => {
    if (/^\S/.test(l)) { inSpecs = false; return; }
    if (/^ {2}specs:/.test(l)) { inSpecs = true; return; }
    if (!inSpecs) return;
    const m = l.match(/^ {4}([A-Za-z0-9_.-]+) \(([0-9][^)\s]*)\)/);
    if (m) out.push({ ecosystem: 'RubyGems', name: m[1], version: m[2].replace(/-(?:x86|x64|arm|aarch|java|universal|mingw|darwin|linux).*$/, ''), file: path, line: i + 1, dev: false });
  });
  return out;
}

function parseComposerLock(path: string, content: string, lines: string[]): Dependency[] {
  const out: Dependency[] = [];
  let json: Record<string, Array<{ name?: string; version?: string }>>;
  try { json = JSON.parse(content); } catch { return out; }
  for (const section of ['packages', 'packages-dev']) {
    for (const pkg of json[section] ?? []) {
      const version = pkg.version?.replace(/^v/, '');
      if (pkg.name && version && /^\d/.test(version)) {
        out.push({ ecosystem: 'Packagist', name: pkg.name, version, file: path, line: lineOf(lines, `"${pkg.name}"`), dev: section === 'packages-dev' });
      }
    }
  }
  return out;
}

function parseGoMod(path: string, lines: string[]): Dependency[] {
  const out: Dependency[] = [];
  let inRequire = false;
  lines.forEach((l, i) => {
    const t = l.trim();
    if (/^require\s*\($/.test(t)) { inRequire = true; return; }
    if (inRequire && t === ')') { inRequire = false; return; }
    const body = inRequire ? t : /^require\s/.test(t) ? t.replace(/^require\s+/, '') : '';
    const m = body.match(/^([\w.-]+\.[\w.-]+\/\S+)\s+v(\d[^\s]*)/);
    if (m) {
      out.push({ ecosystem: 'Go', name: m[1], version: m[2].replace(/\+incompatible$/, ''), file: path, line: i + 1, dev: false });
    }
  });
  return out;
}

function parseGoSum(path: string, lines: string[]): Dependency[] {
  const out: Dependency[] = [];
  lines.forEach((l, i) => {
    const m = l.match(/^(\S+) v(\d[^\s/]*)(?:\/go\.mod)? h1:/);
    if (m) out.push({ ecosystem: 'Go', name: m[1], version: m[2].replace(/\+incompatible$/, ''), file: path, line: i + 1, dev: false });
  });
  return out;
}

function parsePom(path: string, content: string, lines: string[]): Dependency[] {
  const out: Dependency[] = [];
  for (const block of content.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const tag = (t: string) => block[1].match(new RegExp(`<${t}>\\s*([^<\\s]+)\\s*</${t}>`))?.[1];
    const group = tag('groupId');
    const artifact = tag('artifactId');
    const version = tag('version');
    if (!group || !artifact || !version || !/^\d/.test(version)) continue;
    out.push({ ecosystem: 'Maven', name: `${group}:${artifact}`, version, file: path, line: lineOf(lines, `<artifactId>${artifact}</artifactId>`), dev: tag('scope') === 'test' });
  }
  return out;
}

function parseFile(path: string, content: string): Dependency[] {
  const lower = path.toLowerCase();
  const base = lower.slice(lower.lastIndexOf('/') + 1);
  const lines = content.split('\n');
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') return parsePackageLock(path, content, lines);
  if (base === 'yarn.lock') return parseYarnLock(path, lines);
  if (base === 'pnpm-lock.yaml') return parsePnpmLock(path, lines);
  if (/^requirements[\w.-]*\.txt$/.test(base)) return parseRequirements(path, lines);
  if (base === 'pipfile.lock') return parsePipfileLock(path, content, lines);
  if (base === 'poetry.lock' || base === 'uv.lock') return parseTomlPackages(path, lines, 'PyPI');
  if (base === 'cargo.lock') return parseTomlPackages(path, lines, 'crates.io');
  if (base === 'gemfile.lock') return parseGemfileLock(path, lines);
  if (base === 'composer.lock') return parseComposerLock(path, content, lines);
  if (base === 'go.mod') return parseGoMod(path, lines);
  if (base === 'go.sum') return parseGoSum(path, lines);
  if (base === 'pom.xml') return parsePom(path, content, lines);
  return [];
}

/**
 * Extracts exact dependency versions from every lockfile / pinned manifest in the repository.
 * A package is listed once per (ecosystem, name, version), at the first file and line it appears.
 * go.sum is used only when the module has no go.mod in the same directory.
 */
export function extractDependencies(files: { path: string; content: string }[]): Dependency[] {
  const goModDirs = new Set(files.filter((f) => /(?:^|\/)go\.mod$/i.test(f.path)).map((f) => f.path.replace(/go\.mod$/i, '')));
  const seen = new Map<string, Dependency>();
  for (const f of files) {
    if (!f?.path || !isDependencyFile(f.path) || !f.content) continue;
    if (/(?:^|\/)go\.sum$/i.test(f.path) && goModDirs.has(f.path.replace(/go\.sum$/i, ''))) continue;
    for (const dep of parseFile(f.path, f.content)) {
      const key = `${dep.ecosystem}|${dep.name}|${dep.version}`;
      const prev = seen.get(key);
      if (!prev) seen.set(key, dep);
      else if (prev.dev && !dep.dev) seen.set(key, { ...prev, dev: false });
      if (seen.size >= MAX_DEPENDENCIES) return [...seen.values()];
    }
  }
  return [...seen.values()];
}
