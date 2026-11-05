import { runStaticCodeScan, type CodeFile } from '@/lib/scanner-engine';

/** Rule, file and the flagged code: line numbers move when a PR edits lines above a finding, so they are left out. */
export interface BaselineFinding { ruleId: number; filePath: string; snippet?: string; title?: string }

export function findingKey(f: BaselineFinding): string {
  return `${f.ruleId}|${f.filePath}|${String(f.snippet ?? f.title ?? '').replace(/\s+/g, ' ').trim()}`;
}

/**
 * Splits a PR scan into findings the PR introduced and ones that were already there.
 * Without a baseline every finding in a changed file counts as new (the old behaviour). With the base
 * versions of the changed files scanned, a finding whose rule and code already existed there is
 * pre-existing, so touching one line of a large file no longer reports its old issues as new.
 * Counts are kept per key: a vulnerable line copied a second time is still new.
 */
export function splitByBaseline<T extends BaselineFinding>(findings: T[], changedFiles: string[], baseFindings?: BaselineFinding[] | null) {
  const changed = new Set(changedFiles);
  const remaining = new Map<string, number>();
  for (const b of baseFindings ?? []) remaining.set(findingKey(b), (remaining.get(findingKey(b)) ?? 0) + 1);
  const newFindings: T[] = [];
  const existingFindings: T[] = [];
  for (const f of findings) {
    if (!changed.has(f.filePath)) { existingFindings.push(f); continue; }
    const key = findingKey(f);
    const left = remaining.get(key) ?? 0;
    if (left > 0) { remaining.set(key, left - 1); existingFindings.push(f); } else newFindings.push(f);
  }
  return { newFindings, existingFindings };
}

/** Above this many changed files the base scan is skipped and every finding in a changed file counts as new. */
export const MAX_BASELINE_FILES = 40;

/**
 * Scans the base-branch versions of the files a PR changed. Files that did not exist at the base
 * (added or renamed) are skipped, so all their findings stay new. Returns null when skipped.
 */
export async function scanBaseVersions(
  changedFiles: string[],
  readBase: (path: string) => Promise<string | null>,
  repoName: string,
  options: Parameters<typeof runStaticCodeScan>[2] = {},
): Promise<BaselineFinding[] | null> {
  if (changedFiles.length === 0 || changedFiles.length > MAX_BASELINE_FILES) return null;
  const contents = await Promise.all(changedFiles.map((path) => readBase(path).catch(() => null)));
  const files: CodeFile[] = changedFiles.flatMap((path, i) => (contents[i] ? [{ path, content: contents[i] as string }] : []));
  if (files.length === 0) return [];
  const result = await runStaticCodeScan(files, repoName, { ...options, dependencyAudit: false });
  return result.findings;
}
