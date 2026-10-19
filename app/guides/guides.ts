export interface GuideEntry {
  slug: string;
  title: string;
  summary: string;
}

export const GUIDES: GuideEntry[] = [
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
