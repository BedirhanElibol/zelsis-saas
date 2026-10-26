export interface GuideEntry {
  slug: string;
  title: string;
  summary: string;
}

export const GUIDES: GuideEntry[] = [
  {
    slug: 'stripe-double-charge',
    title: 'How to stop charging customers twice with Stripe',
    summary:
      'Double clicks, retries after a timeout and repeated webhooks. Idempotency keys, a disabled pay button and webhook de-duplication, with a test.',
  },
  {
    slug: 'n-plus-one-queries',
    title: 'How to find and fix N+1 queries',
    summary:
      'One query per row is fast with ten rows and times out with ten thousand. The fix in Prisma, Django, Rails, Laravel and SQL, and how to count queries in a test.',
  },
  {
    slug: 'postgres-migration-locks',
    title: 'Postgres migrations that lock your tables',
    summary:
      'CREATE INDEX without CONCURRENTLY, SET NOT NULL on a big table and the lock queue: why a deploy can freeze checkout, and the safe versions.',
  },
  {
    slug: 'snyk-alternative',
    title: 'Snyk alternative for teams that ship every week',
    summary:
      'A release check on every pull request, at one flat price per account. Price and focus side by side with Snyk, and when to stay with it.',
  },
  {
    slug: 'semgrep-alternative',
    title: 'Semgrep alternative for teams that ship every week',
    summary:
      'A release check on every pull request, at one flat price per account. Price and focus side by side with Semgrep, and when to stay with it.',
  },
  {
    slug: 'aikido-alternative',
    title: 'Aikido alternative for teams that ship every week',
    summary:
      'A release check on every pull request, at one flat price per account. Price and focus side by side with Aikido, and when to stay with it.',
  },
  {
    slug: 'zelsis-vs-coderabbit',
    title: 'Zelsis vs CodeRabbit: five pull requests with planted flaws',
    summary:
      'Both tools reviewed the same five pull requests, each with one flaw written down in advance. What each found, what each missed, and how a reviewer differs from a release check.',
  },
  {
    slug: 'supabase-rls-testing',
    title: 'How to test Supabase RLS before you ship',
    summary:
      'Five Row Level Security mistakes that leak or block data, each with a bad and a fixed version and a quick manual test using the anon key.',
  },
  {
    slug: 'supabase-user-delete-foreign-key',
    title: "Supabase: can't delete user (foreign key violation)",
    summary:
      'Why deleting a user fails with "Database error deleting user", and the migration that fixes it with ON DELETE CASCADE or SET NULL.',
  },
  {
    slug: 'stripe-amount-cents',
    title: 'Stripe charges 100x less: amount must be in cents',
    summary:
      'Stripe amounts are integers in the smallest currency unit. How to convert prices safely and which currencies have no decimals.',
  },
  {
    slug: 'code-due-diligence',
    title: 'Check the code before you buy a SaaS app',
    summary:
      'How to get access to the repository, which findings cost you money after the sale, and what to verify by hand before you pay.',
  },
];
