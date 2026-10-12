import { isDependencyFile } from './dependencies';

/** Source, config and infrastructure files the rule engines read (CI workflows, Terraform, server configs included). */
const SCANNABLE_FILE = /\.(?:ts|tsx|js|jsx|json|css|sql|html|py|yml|yaml|toml|sh|ps1|c|cpp|cc|cxx|h|hpp|java|kt|kts|go|rs|php|cs|rb|swift|xml|plist|gradle|md|mdx|tf|tfvars|hcl|conf|properties|zelsisignore|shipguardignore)$|\.env(?:\.[a-zA-Z0-9_-]+)?$|(?:^|\/)(?:dockerfile(?:\.[\w-]+)?|makefile|podfile|\.npmrc|\.yarnrc|\.gitmodules|\.dockerignore)$/i;

/** Generated, vendored and tool folders that never hold the app's own code. `.git/` only: `.github/` must stay. */
const SKIPPED_DIR = /(?:^|\/)(?:node_modules|\.next|\.git|dist|build|vendor|\.agent|\.antigravity|venv|\.venv|__pycache__|site-packages)\/|artifacts|(?:^|\/)\.?venv\/(?:lib|Lib|lib64|Scripts|bin|include)\//;

/** Whether a repository tree entry should be downloaded and scanned. */
export function isScannableTreePath(path: string): boolean {
  return (isDependencyFile(path) || SCANNABLE_FILE.test(path)) && !SKIPPED_DIR.test(path);
}
