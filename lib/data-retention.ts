// Enforced by public.purge_expired_code_snippets() (migration 20261003120000), scheduled daily via pg_cron.
// Keep this number and the interval in that migration in sync; tests/unit/data-retention.test.ts checks it.
export const CODE_SNIPPET_RETENTION_DAYS = 90;

/** One-line form for badges and trust rows; the full statement belongs where there is room to read it. */
export const CODE_RETENTION_SHORT = `Code never stored · snippets deleted after ${CODE_SNIPPET_RETENTION_DAYS} days`;

export const CODE_RETENTION_STATEMENT =
  `Your code is scanned in memory and never stored. We keep findings plus a short snippet around each one; snippets are erased after ${CODE_SNIPPET_RETENTION_DAYS} days.`;
