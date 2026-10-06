/** Next.js releases fixing CVE-2025-29927 (middleware bypass via x-middleware-subrequest). */
const NEXT_MIDDLEWARE_FIXED: Record<number, [number, number]> = { 12: [3, 5], 13: [5, 9], 14: [2, 25], 15: [2, 3] };

/** True when this `next` version (or the lowest version a spec allows) lets a request skip middleware. */
export function isVulnerableNext(version: string): boolean {
  const m = version.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return false;
  const [major, minor, patch] = m.slice(1).map(Number);
  if (major === 11) return minor > 1 || (minor === 1 && patch >= 4);
  const fixed = NEXT_MIDDLEWARE_FIXED[major];
  if (!fixed) return false;
  return minor < fixed[0] || (minor === fixed[0] && patch < fixed[1]);
}

/** A `^` range can resolve to a patched release; an exact or `~` pin cannot leave the vulnerable line. */
export const isPinnedSpec = (spec: string): boolean => !/^\s*\^/.test(spec);
