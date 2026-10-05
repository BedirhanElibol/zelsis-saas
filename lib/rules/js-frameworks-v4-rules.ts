/**
 * JS/TS framework security (Express, NestJS, Next.js, Remix, SvelteKit, Nuxt, Hono, Fastify) (JSF-xx, Rule IDs 28901-28999).
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

export function evaluateJsFrameworksV4Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  return { findings, logs };
}
