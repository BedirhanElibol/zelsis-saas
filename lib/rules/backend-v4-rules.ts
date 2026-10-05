/**
 * Go, Java/Spring/Kotlin, PHP/Laravel/Symfony, Ruby/Rails, C#/.NET security (BEF-xx, Rule IDs 29101-29199).
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

export function evaluateBackendV4Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  return { findings, logs };
}
