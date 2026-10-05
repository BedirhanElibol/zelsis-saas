/**
 * Cloud, IaC, container, CI/CD and platform config security (Terraform, K8s, Docker, GitHub Actions, Vercel, Firebase, Supabase) (CFG-xx, Rule IDs 29201-29299).
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

export function evaluateConfigV4Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  return { findings, logs };
}
