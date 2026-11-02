import type { Dependency } from './dependencies';

export interface ImportSite {
  file: string;
  line: number;
}

export interface ImportIndex {
  npm: Map<string, ImportSite>;
  python: Map<string, ImportSite>;
}

/** Files that do not run in production, or are generated: an import there says nothing about what ships. */
const NOT_APP_CODE = /(?:^|\/)(?:node_modules|dist|build|\.next|out|vendor|coverage|venv|\.venv|tests?|__tests__|spec|e2e|fixtures?|examples?)\/|\.(?:test|spec|stories|min)\.\w+$|(?:^|\/)test_[^/]+\.py$|_test\.py$/i;

const JS_MODULE = /(?:\bfrom\s+|\bimport\s+|\bimport\s*\(\s*|\brequire\(\s*)['"]([^'"\n]+)['"]/g;
const PY_MODULE = /^[ \t]*(?:from|import)[ \t]+([A-Za-z_]\w*)/gm;

/** `@scope/pkg/sub` -> `@scope/pkg`, `pkg/sub` -> `pkg`. Relative paths, aliases and node builtins return null. */
function npmPackageName(spec: string): string | null {
  if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('@/') || spec.startsWith('~') || spec.startsWith('node:')) return null;
  const parts = spec.split('/');
  return spec.startsWith('@') ? (parts.length > 1 ? `${parts[0]}/${parts[1]}` : null) : parts[0];
}

const normalizePython = (name: string) => name.toLowerCase().replace(/[-_.]+/g, '_');

const lineAt = (content: string, offset: number) => content.slice(0, offset).split('\n').length;

/** First production import of each package. Must run before the scanner empties file contents. */
export function collectImports(files: { path: string; content: string }[]): ImportIndex {
  const index: ImportIndex = { npm: new Map(), python: new Map() };
  for (const { path, content } of files) {
    if (!content || NOT_APP_CODE.test(path.replace(/\\/g, '/'))) continue;
    if (/\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/i.test(path)) {
      for (const m of content.matchAll(JS_MODULE)) {
        const name = npmPackageName(m[1]);
        if (name && !index.npm.has(name)) index.npm.set(name, { file: path, line: lineAt(content, m.index) });
      }
    } else if (/\.py$/i.test(path)) {
      for (const m of content.matchAll(PY_MODULE)) {
        const name = normalizePython(m[1]);
        if (!index.python.has(name)) index.python.set(name, { file: path, line: lineAt(content, m.index) });
      }
    }
  }
  return index;
}

/**
 * One sentence on whether the scanned code imports the package, or undefined when nothing can be said.
 * This is package level: it does not show that the vulnerable function is called, and an unimported package
 * can still load through another package, so it informs the reader and never changes severity.
 * PyPI names often differ from module names (pyyaml, yaml), so only a match is reported there.
 */
export function describeUsage(dep: Pick<Dependency, 'ecosystem' | 'name'>, index: ImportIndex): string | undefined {
  if (dep.ecosystem === 'npm') {
    const site = index.npm.get(dep.name);
    return site
      ? `Imported directly in ${site.file}:${site.line}, so check this one first.`
      : 'Not imported directly in the scanned code. It may be a transitive or build-time package, and it can still load through another package.';
  }
  if (dep.ecosystem === 'PyPI') {
    const site = index.python.get(normalizePython(dep.name));
    return site ? `Imported directly in ${site.file}:${site.line}, so check this one first.` : undefined;
  }
  return undefined;
}
