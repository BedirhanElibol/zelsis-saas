import { parseLineRange } from '@/lib/ci-annotations';
import { suggestedLine } from '@/lib/github/suggestions';
import type { Finding } from '@/data/schema';

/** A one-hunk unified diff that swaps one line of the file for its fixed version. */
export function lineDiff(path: string, lineNo: number, original: string, fixed: string): string {
  return `--- a/${path}\n+++ b/${path}\n@@ -${lineNo},1 +${lineNo},1 @@\n-${original}\n+${fixed}`;
}

const norm = (s: string) => s.trim().replace(/\s+/g, ' ');

/**
 * True when the lines a patch removes (or, for a patch that only adds, its context lines) exist in the file.
 * Some rules ship a sample patch written for a typical project; shown next to someone else's code it reads
 * as a fix for lines they do not have, so those patches are dropped and the written guidance stays.
 */
export function patchFitsFile(patch: string, content: string): boolean {
  const fileLines = new Set(content.split(/\r?\n/).map(norm).filter(Boolean));
  const body = patch.split('\n').filter((l) => !/^(?:---|\+\+\+|@@)/.test(l));
  const removed = body.filter((l) => l.startsWith('-')).map((l) => norm(l.slice(1))).filter(Boolean);
  const context = body.filter((l) => l.startsWith(' ')).map((l) => norm(l.slice(1))).filter((l) => l && l !== '...');
  const anchors = removed.length > 0 ? removed : context;
  return anchors.length > 0 && anchors.every((l) => fileLines.has(l));
}

/**
 * Gives each finding a patch that matches the scanned file: keeps a rule's own patch only when it fits the
 * file, and builds a real one-line diff for rules with a safe line fix (lib/github/suggestions.ts).
 */
export function alignPatches(findings: Finding[], path: string, content: string): void {
  const lines = content.split(/\r?\n/);
  for (const f of findings) {
    if (f.diffPatch && !patchFitsFile(f.diffPatch, content)) delete f.diffPatch;
    if (f.diffPatch) continue;
    const lineNo = parseLineRange(f.lineRange)?.[0];
    const original = lineNo ? lines[lineNo - 1] : undefined;
    if (!lineNo || original === undefined) continue;
    const fixed = suggestedLine(f.ruleId, original);
    if (fixed !== null) f.diffPatch = lineDiff(path, lineNo, original, fixed);
  }
}
