import type { LandingCategory } from './landing-checks';

/**
 * One page per bug category (/checks/<slug>). Every line in `checks` names a rule that exists in lib/rules;
 * code examples come from LANDING_CHECKS, which tests/unit/landing-checks.test.ts scans on every run.
 */
export interface CategoryPage {
  slug: string;
  name: string;
  landing?: LandingCategory;
  title: string;
  description: string;
  lead: string;
  checks: string[];
}

export const CATEGORY_PAGES: CategoryPage[] = [
  {
    slug: 'payments',
    name: 'Payments',
    landing: 'Payments',
    title: 'Payment bugs Zelsis catches before they charge a customer',
    description: 'Double charges, amounts off by a cent, prices taken from the browser, webhooks applied twice. What Zelsis checks in payment code on every pull request.',
    lead: 'A payment bug reaches customers as a wrong charge, a refund request and a bad review. Zelsis reads checkout and webhook code for the mistakes behind those.',
    checks: [
      'Webhooks that grant credits or orders twice when the provider retries the delivery',
      'Pay buttons that stay clickable while the charge is pending',
      'Amounts rounded to whole units, or multiplied by 100 without rounding, before they reach Stripe',
      'Prices, discounts or quantities taken from the request instead of the server',
      'checkout.session.completed fulfilled without checking payment_status',
      'Payment calls with no idempotency key',
      'Stock sold twice because two orders read it at the same time',
    ],
  },
  {
    slug: 'security',
    name: 'Security',
    landing: 'Security',
    title: 'Security checks on every pull request',
    description: 'Leaked keys, routes that skip the owner check, SQL built from input, open cloud settings and vulnerable packages. What Zelsis checks for security on every pull request.',
    lead: 'Zelsis covers the security checks you would expect from a code scanner, and only proven critical findings block a merge.',
    checks: [
      'Secret keys in client code, logs or committed config',
      'Routes and records loaded by id without checking who owns them',
      'Database access rules that let any signed-in user read or change every row',
      'SQL and shell commands built from request input',
      'CORS that allows any origin together with credentials',
      'Package versions with a published advisory, and the version that fixes it',
      'Public buckets, firewalls open to the internet and containers running with too many rights',
      'TLS certificate checks turned off',
    ],
  },
  {
    slug: 'performance',
    name: 'Performance',
    landing: 'Performance',
    title: 'Performance problems Zelsis catches before users feel them',
    description: 'One query per list item, deep pagination, unbounded sorts and migrations that lock busy tables. What Zelsis checks for speed on every pull request.',
    lead: 'Slow pages rarely come from one big mistake. They come from a loop that queries the database, or a migration that holds a lock during a deploy.',
    checks: [
      'A database query run once per item in a list (N+1)',
      'Deep offset pagination and unbounded in-memory sorting',
      'Migrations that take a blocking lock on an existing table',
      'A new formatter (Intl) created for every row of a table',
      'Lists keyed by array index',
      'Images that download at full screen width',
    ],
  },
  {
    slug: 'screens',
    name: 'Screens',
    landing: 'Screens',
    title: 'Screens that break, on a phone or for keyboard users',
    description: 'Dialogs keyboard users cannot leave, unlabeled buttons, pages wider than the phone and lists with no loading or error state. What Zelsis checks in the UI.',
    lead: 'People notice a broken screen before anything else. Zelsis checks the patterns that lock out keyboard and screen reader users, or that fall apart on a phone.',
    checks: [
      'Dialogs that do not keep focus inside, and fields that trap the keyboard',
      'Buttons and links with no accessible name',
      'Pages wider than the phone, and pages that block zooming',
      'Inputs small enough that iOS zooms in when they are tapped',
      'Content that only opens on mouse hover',
      'Lists loaded in the browser with no loading, error or empty state',
    ],
  },
  {
    slug: 'ai-features',
    name: 'AI features',
    landing: 'AI features',
    title: 'AI features that can be abused or run up the bill',
    description: 'Visitor text in the system prompt, model output used as trusted input, calls with no token limit and agent loops that never stop. What Zelsis checks in AI features.',
    lead: 'An AI feature can be talked into ignoring its instructions, or loop until the invoice arrives. Zelsis checks the code around the model call.',
    checks: [
      'Request data written into the system prompt',
      'Model output rendered as HTML, run as code or used for an access decision',
      'Model calls with no max_tokens limit',
      'Agent loops with no step limit, and retries with no backoff',
      'MCP servers launched from a request',
    ],
  },
  {
    slug: 'app-store',
    name: 'App store review',
    title: 'What App Store and Google Play reviews reject',
    description: 'Template app ids, empty iOS permission prompts, an old Android target SDK and Play restricted permissions. What Zelsis checks before you submit a mobile app.',
    lead: 'A store rejection costs days. Zelsis reads Gradle, Expo, Xcode and manifest settings for what the reviewers send back.',
    checks: [
      'A starter template application id (com.example, com.yourcompany, org.reactjs.native.example)',
      'iOS permission prompts that are empty or a placeholder',
      'An Android targetSdk below what Google Play accepts',
      'Permissions Google Play only allows with a declaration: SMS, call log, all files, background location',
      'Manifests marked debuggable, cleartext traffic allowed, App Transport Security turned off',
    ],
  },
  {
    slug: 'looks-unfinished',
    name: 'Looks unfinished',
    landing: 'Looks unfinished',
    title: 'Pages that look unfinished or invented',
    description: 'Template page titles, lorem ipsum, typed-in "10,000+ users", stars with no reviews behind them and testimonials from John Doe. What Zelsis checks so your app does not read as rushed.',
    lead: 'Visitors decide in seconds whether an app is real. Template leftovers and invented proof tell them it is not.',
    checks: [
      'The starter page title (Create Next App, React App) and lorem ipsum',
      'Placeholder copy such as a "your company name" heading',
      'Round user counts or uptime figures typed into the page with no source',
      'Star ratings with no review count or review site',
      '"Active now" indicators not tied to real data',
      'Testimonials from placeholder people or companies, and logos of companies that do not exist',
      'Countdowns that restart for every visitor, and launch badges with no listing behind them',
    ],
  },
];

export const categoryBySlug = (slug: string) => CATEGORY_PAGES.find((c) => c.slug === slug);
export const slugForLanding = (c: LandingCategory) => CATEGORY_PAGES.find((p) => p.landing === c)?.slug;
