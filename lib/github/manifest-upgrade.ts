/**
 * Deterministic npm upgrade for the auto-fix PR. No AI: the target comes from the finding's remediationPrompt,
 * which buildDependencyFindings writes as "Upgrade <name> from <old> to <new> or later ...".
 * Only the manifest (package.json) is rewritten. Lockfile entries carry integrity hashes that cannot be
 * recomputed here, so the PR body tells the owner to refresh the lockfile.
 */

const UPGRADE_RE = /^Upgrade (\S+) from (\S+) to (\S+) or later\b/;

export interface UpgradeTarget { name: string; from: string; to: string }

export function parseUpgradeTarget(remediationPrompt: string | undefined): UpgradeTarget | null {
  const m = UPGRADE_RE.exec(remediationPrompt ?? '');
  return m ? { name: m[1], from: m[2], to: m[3] } : null;
}

/** Maps an npm lockfile to the package.json in the same folder. Returns null for other lockfiles. */
export function manifestForLockfile(path: string): string | null {
  if (/(^|\/)package\.json$/i.test(path)) return path;
  const m = /^(.*\/)?(?:package-lock\.json|npm-shrinkwrap\.json)$/i.exec(path);
  if (!m) return null;
  return `${m[1] ?? ''}package.json`;
}

/**
 * Sets a direct dependency to the fixed version, keeping its range style (^, ~ or exact).
 * Returns null when the package is not a direct dependency with a plain registry version (aliases, git and file specs are left alone).
 */
export function upgradeManifest(content: string, name: string, to: string): string | null {
  const parsed = JSON.parse(content) as Record<string, unknown>;
  const indent = /^[ \t]+(?=")/m.exec(content)?.[0] ?? 2;
  let changed = false;
  for (const key of ['dependencies', 'devDependencies'] as const) {
    const section = parsed[key];
    if (!section || typeof section !== 'object' || !Object.prototype.hasOwnProperty.call(section, name)) continue;
    const deps = section as Record<string, unknown>;
    const spec = deps[name];
    if (typeof spec !== 'string' || !/^[\^~]?\d/.test(spec)) continue;
    const prefix = /^[\^~]/.test(spec) ? spec[0] : '';
    deps[name] = `${prefix}${to}`;
    changed = true;
  }
  if (!changed) return null;
  return JSON.stringify(parsed, null, indent) + '\n';
}
