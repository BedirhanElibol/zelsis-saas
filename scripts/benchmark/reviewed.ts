/**
 * Rules that fire HIGH/CRITICAL on the clean corpus and were reviewed as true positives
 * (the flagged code really has the issue). Everything else that fires there becomes experimental.
 */
export const REVIEWED_TRUE_POSITIVES: Record<number, string> = {
  3: 'USING (true) policy in supabase-js example migration: genuinely public table',
  45: 'Same USING (true) policy, reported by the RLS bypass rule',
  14: "node-express realworld: process.env.JWT_SECRET || 'superSecret' signs tokens with a guessable key when unset",
  16: 'dangerouslySetInnerHTML with renderer output; flagged for review by design',
  3001: 'Supabase project tables without RLS in client-exposed schema',
  3002: 'Dockerfile without USER: container runs as root',
  3019: 'docker-compose publishes the Postgres port on all interfaces',
  5099: 'Hardcoded JWT secret committed to the repo (secret rules apply to test files)',
  6051: 'Index created without CONCURRENTLY on an existing table',
  7004: 'Dockerfile without USER: container runs as root',
  9502: 'GitHub Actions referenced by mutable tag instead of commit SHA',
  12605: 'Third-party GitHub Action referenced by mutable tag',
  23003: 'nextjs-subscription-payments: SECURITY DEFINER handle_new_user() without search_path',
  23008: 'nextjs-subscription-payments pins next 14.2.3, affected by CVE-2025-29927'
};
