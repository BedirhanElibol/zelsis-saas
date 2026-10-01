/**
 * Finds the line a file-level rule should point at: the first code line matching one of the
 * rule's own trigger patterns. Falls back to the first code line when the trigger spans lines.
 */
export function locateMatchLine(lines: string[], patterns: RegExp[], isCode: (l: string) => boolean): number {
  const perLine = patterns.map((p) => new RegExp(p.source, p.flags.replace(/[gy]/g, '')));
  const hit = lines.findIndex((l) => isCode(l) && perLine.some((p) => p.test(l)));
  return hit !== -1 ? hit : lines.findIndex(isCode);
}
