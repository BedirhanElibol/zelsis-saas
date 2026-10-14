import { isDependencyFile } from './dependencies';

/** Source, config and infrastructure files the rule engines read (CI workflows, Terraform, server configs included). */
const SCANNABLE_FILE = /\.(?:ts|tsx|js|jsx|json|css|sql|html|py|yml|yaml|toml|sh|ps1|c|cpp|cc|cxx|h|hpp|java|kt|kts|go|rs|php|cs|rb|swift|m|mm|dart|scala|ex|exs|vue|svelte|astro|erb|cshtml|razor|jsp|twig|jinja2?|j2|xml|plist|gradle|md|mdx|tf|tfvars|hcl|conf|properties|zelsisignore|shipguardignore)$|\.env(?:\.[a-zA-Z0-9_-]+)?$|(?:^|\/)(?:dockerfile(?:\.[\w-]+)?|makefile|podfile|\.npmrc|\.yarnrc|\.gitmodules|\.dockerignore)$/i;

/** Generated, vendored and tool folders that never hold the app's own code. `.git/` only: `.github/` must stay. */
const SKIPPED_DIR = /(?:^|\/)(?:node_modules|\.next|\.git|dist|build|vendor|\.agent|\.antigravity|venv|\.venv|__pycache__|site-packages)\/|artifacts|(?:^|\/)\.?venv\/(?:lib|Lib|lib64|Scripts|bin|include)\//;

/** Whether a repository tree entry should be downloaded and scanned. */
export function isScannableTreePath(path: string): boolean {
  return (isDependencyFile(path) || SCANNABLE_FILE.test(path)) && !SKIPPED_DIR.test(path);
}

/**
 * Files that must never sit in a folder the host serves as-is (public/ in Next.js, Vite, Astro; static/ in SvelteKit,
 * Django): env files, SQL dumps, Terraform state, private keys, backups, logs. Example env files are meant to be shared.
 */
export const PUBLIC_ARTIFACT = /(?:^|\/)(?:public|static)\/(?:[^/]+\/)*(?:\.env(?:\.(?!(?:example|sample|template|dist|defaults?)$)[\w-]+)?|[^/]+\.(?:sql|dump|sql\.gz|tfstate|tfstate\.backup|p12|pfx|bak|backup|log)|[^/]*priv[^/]*\.pem|id_(?:rsa|ed25519|ecdsa)|\.npmrc|sftp\.json|docker-compose\.ya?ml)$/i;

/**
 * Path-only entries for PUBLIC_ARTIFACT files the fetch skipped (a type it does not download, or too large): the
 * rule needs the location, not the content, and a 50 MB dump in public/ is exactly the file worth reporting.
 */
export function withPublicArtifactPaths<F extends { path: string; content: string }>(tree: Array<{ type: string; path: string }>, files: F[]): Array<F | { path: string; content: string }> {
  const have = new Set(files.map((f) => f.path));
  const extra = tree.filter((t) => t.type === 'blob' && PUBLIC_ARTIFACT.test(t.path) && !SKIPPED_DIR.test(t.path) && !have.has(t.path));
  return extra.length ? [...files, ...extra.map((t) => ({ path: t.path, content: '' }))] : files;
}
