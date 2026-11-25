export const GUIDE_CATEGORIES = [
  { value: 'payments', label: 'Payments' },
  { value: 'database', label: 'Database' },
  { value: 'security', label: 'Security' },
  { value: 'accessibility', label: 'Accessibility' },
  { value: 'comparisons', label: 'Comparisons' },
  { value: 'buying', label: 'Buying a SaaS' },
] as const;

export type GuideCategory = (typeof GUIDE_CATEGORIES)[number]['value'];

export interface GuideEntry {
  slug: string;
  category: GuideCategory;
  title: string;
  summary: string;
  /** ISO date the guide first shipped (from git history); omitted when not known. */
  published?: string;
  /** ISO date of the last content change (from git history). */
  updated?: string;
}

export const GUIDES: GuideEntry[] = [
  {
    slug: 'ai-code-merge-checklist',
    published: '2026-11-25',
    updated: '2026-11-25',
    category: 'security',
    title: '5 checks before you merge code an AI wrote',
    summary:
      'Exposed secrets, open tables, raw SQL, table-locking migrations and open CORS. What to look for in a pull request, with the flagged code and the fix for each.',
  },
  {
    slug: 'stripe-double-charge',
    published: '2026-10-26',
    updated: '2026-10-26',
    category: 'payments',
    title: 'How to stop charging customers twice with Stripe',
    summary:
      'Double clicks, retries after a timeout and repeated webhooks. Idempotency keys, a disabled pay button and webhook de-duplication, with a test.',
  },
  {
    slug: 'n-plus-one-queries',
    published: '2026-10-26',
    updated: '2026-10-26',
    category: 'database',
    title: 'How to find and fix N+1 queries',
    summary:
      'One query per row is fast with ten rows and times out with ten thousand. The fix in Prisma, Django, Rails, Laravel and SQL, and how to count queries in a test.',
  },
  {
    slug: 'postgres-migration-locks',
    published: '2026-10-26',
    updated: '2026-10-26',
    category: 'database',
    title: 'Postgres migrations that lock your tables',
    summary:
      'CREATE INDEX without CONCURRENTLY, SET NOT NULL on a big table and the lock queue: why a deploy can freeze checkout, and the safe versions.',
  },
  {
    slug: 'snyk-alternative',
    category: 'comparisons',
    title: 'Snyk alternative for teams that ship every week',
    summary:
      'A release check on every pull request, at one flat price per account. Price and focus side by side with Snyk, and when to stay with it.',
  },
  {
    slug: 'semgrep-alternative',
    category: 'comparisons',
    title: 'Semgrep alternative for teams that ship every week',
    summary:
      'A release check on every pull request, at one flat price per account. Price and focus side by side with Semgrep, and when to stay with it.',
  },
  {
    slug: 'aikido-alternative',
    category: 'comparisons',
    title: 'Aikido alternative for teams that ship every week',
    summary:
      'A release check on every pull request, at one flat price per account. Price and focus side by side with Aikido, and when to stay with it.',
  },
  {
    slug: 'github-advanced-security-alternative',
    category: 'comparisons',
    title: 'GitHub Advanced Security alternative for teams that ship every week',
    summary:
      'A release check on every pull request, at one flat price per account instead of per committer. Price and focus side by side with GitHub Code Security and Secret Protection, and when to stay with them.',
  },
  {
    slug: 'zelsis-vs-coderabbit',
    published: '2026-10-23',
    updated: '2026-10-23',
    category: 'comparisons',
    title: 'Zelsis vs CodeRabbit: five pull requests with planted flaws',
    summary:
      'Both tools reviewed the same five pull requests, each with one flaw written down in advance. What each found, what each missed, and how a reviewer differs from a release check.',
  },
  {
    slug: 'zelsis-vs-snyk',
    published: '2026-11-11',
    updated: '2026-11-11',
    category: 'comparisons',
    title: 'Zelsis vs Snyk: what each checks before a pull request merges',
    summary:
      'Snyk covers dependencies, containers, infrastructure and code. Zelsis is a deterministic release check for payment and access mistakes. Where each one fits.',
  },
  {
    slug: 'supabase-rls-testing',
    published: '2026-10-09',
    updated: '2026-10-09',
    category: 'database',
    title: 'How to test Supabase RLS before you ship',
    summary:
      'Five Row Level Security mistakes that leak or block data, each with a bad and a fixed version and a quick manual test using the anon key.',
  },
  {
    slug: 'supabase-user-delete-foreign-key',
    published: '2026-10-09',
    updated: '2026-10-09',
    category: 'database',
    title: "Supabase: can't delete user (foreign key violation)",
    summary:
      'Why deleting a user fails with "Database error deleting user", and the migration that fixes it with ON DELETE CASCADE or SET NULL.',
  },
  {
    slug: 'stripe-amount-cents',
    published: '2026-10-09',
    updated: '2026-10-09',
    category: 'payments',
    title: 'Stripe charges 100x less: amount must be in cents',
    summary:
      'Stripe amounts are integers in the smallest currency unit. How to convert prices safely and which currencies have no decimals.',
  },
  {
    slug: 'stripe-webhook-signature',
    published: '2026-11-03',
    updated: '2026-11-03',
    category: 'payments',
    title: 'Stripe webhook: "No signatures found matching the expected signature"',
    summary:
      'Signature checks fail when the body was parsed first or the secret is wrong. The raw-body fix for Next.js and Express, and why skipping the check lets anyone fake a payment.',
  },
  {
    slug: 'next-public-secrets',
    published: '2026-11-03',
    updated: '2026-11-03',
    category: 'security',
    title: 'A NEXT_PUBLIC_ variable is not a secret',
    summary:
      'Next.js, Vite and Expo copy public-prefixed variables into the browser bundle. Which keys are safe there, how to move a secret to the server and rotate it.',
  },
  {
    slug: 'clickable-div-keyboard',
    published: '2026-11-03',
    updated: '2026-11-03',
    category: 'accessibility',
    title: 'A div with onClick is not a button',
    summary:
      'Keyboard and screen reader users cannot reach or press a clickable div. The <button> fix, the role="button" fallback and a keyboard-only test.',
  },
  {
    slug: 'code-due-diligence',
    published: '2026-10-19',
    updated: '2026-10-19',
    category: 'buying',
    title: 'Check the code before you buy a SaaS app',
    summary:
      'How to get access to the repository, which findings cost you money after the sale, and what to verify by hand before you pay.',
  },
];
