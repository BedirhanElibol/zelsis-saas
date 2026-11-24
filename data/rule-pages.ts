/**
 * One page per rule. Every entry has a real fixture in tests/rules/cases.ts
 * (flagged code and the fixed version), so no page ships without proof.
 */
export interface RulePage {
  slug: string;
  ruleId: number;
  code: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  title: string;
  description: string;
  /** What the user or the business loses, in plain words. */
  consequence: string;
  path: string;
  bad: string;
  good: string;
  fix: string;
  /** Slug of the matching /checks/ page. */
  category: 'security' | 'performance' | 'screens';
}

export const RULE_PAGES: RulePage[] = [
  {
    slug: 'supabase-service-role-key-in-client',
    ruleId: 28834,
    code: 'RULE-28834',
    severity: 'CRITICAL',
    title: 'Supabase service role key in a client component',
    description: 'A service role key in a use client file ships to every browser and bypasses all row level security.',
    consequence: 'Anyone who opens the browser dev tools can read, change or delete every row in your database, including other customers’ data.',
    path: 'app/billing/client.tsx',
    bad: "'use client';\nimport { createClient } from '@supabase/supabase-js';\nexport const admin = createClient(\n  process.env.NEXT_PUBLIC_SUPABASE_URL!,\n  process.env.SUPABASE_SERVICE_ROLE_KEY!\n);",
    good: "import 'server-only';\nimport { createClient } from '@supabase/supabase-js';\nexport const admin = createClient(\n  process.env.NEXT_PUBLIC_SUPABASE_URL!,\n  process.env.SUPABASE_SERVICE_ROLE_KEY!\n);",
    fix: 'Keep the service role client in a server-only module and call it from server actions or route handlers. Rotate the key if it was ever bundled.',
    category: 'security',
  },
  {
    slug: 'secret-in-next-public-variable',
    ruleId: 36,
    code: 'RULE-36',
    severity: 'CRITICAL',
    title: 'Backend secret exposed through a NEXT_PUBLIC_ variable',
    description: 'Variables that start with NEXT_PUBLIC_ are inlined into the browser bundle, so a secret stored there is public.',
    consequence: 'A stranger can copy your payment or API secret from the page source and use it on your account.',
    path: 'components/Pay.tsx',
    bad: "'use client';\nconst key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\nexport default function Pay() {\n  return <div>{key}</div>;\n}",
    good: "// server only, never prefixed with NEXT_PUBLIC_\nimport 'server-only';\nconst key = process.env.STRIPE_SECRET_KEY;",
    fix: 'Rename the variable without the NEXT_PUBLIC_ prefix, read it only on the server, and rotate the exposed key.',
    category: 'security',
  },
  {
    slug: 'supabase-table-without-rls',
    ruleId: 3001,
    code: 'RULE-3001',
    severity: 'CRITICAL',
    title: 'Supabase table created without Row Level Security',
    description: 'A table in the public schema with RLS off is readable and writable by anyone holding the public anon key.',
    consequence: 'Customers can see each other’s invoices or orders, and the public key in your frontend is enough to do it.',
    path: 'supabase/migrations/20240101_init.sql',
    bad: 'CREATE TABLE public.invoices (\n  id uuid primary key,\n  user_id uuid\n);',
    good: 'CREATE TABLE public.invoices (\n  id uuid primary key,\n  user_id uuid\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "own rows" ON public.invoices\n  FOR SELECT USING (auth.uid() = user_id);',
    fix: 'Enable RLS in the same migration that creates the table and add a policy for each operation you allow.',
    category: 'security',
  },
  {
    slug: 'sql-injection-template-literal',
    ruleId: 3021,
    code: 'RULE-3021',
    severity: 'CRITICAL',
    title: 'SQL injection through a template literal',
    description: 'Request input placed straight into a query string lets an attacker change the query.',
    consequence: 'A single crafted URL can dump your users table or delete data.',
    path: 'app/api/users/route.ts',
    bad: "const id = new URL(req.url).searchParams.get('id');\nconst rows = await db.query(\n  `SELECT * FROM users WHERE id = ${id}`\n);",
    good: "const id = new URL(req.url).searchParams.get('id');\nconst rows = await db.query(\n  'SELECT * FROM users WHERE id = $1',\n  [id]\n);",
    fix: 'Pass values as query parameters instead of building the string yourself.',
    category: 'security',
  },
  {
    slug: 'migration-locks-existing-table',
    ruleId: 6051,
    code: 'DB-PERF-51',
    severity: 'MEDIUM',
    title: 'Migration that takes a blocking lock on an existing table',
    description: 'Adding a NOT NULL column without a default or creating an index without CONCURRENTLY blocks writes while it runs.',
    consequence: 'During the deploy, checkouts and signups hang or fail until the migration finishes.',
    path: 'supabase/migrations/003.sql',
    bad: 'ALTER TABLE orders ADD COLUMN region text NOT NULL;\nCREATE INDEX idx_orders_user ON orders(user_id);',
    good: "ALTER TABLE orders ADD COLUMN region text NOT NULL DEFAULT 'eu';\nCREATE INDEX CONCURRENTLY idx_orders_user ON orders(user_id);",
    fix: 'Give the new column a default and build indexes with CONCURRENTLY on tables that already hold data.',
    category: 'performance',
  },
  {
    slug: 'vercel-url-without-https',
    ruleId: 29702,
    code: 'RULE-29702',
    severity: 'MEDIUM',
    title: 'VERCEL_URL used as a full URL',
    description: 'VERCEL_URL has no https:// prefix and changes on every deployment, so it breaks callbacks and links.',
    consequence: 'Sign-in links and payment return URLs point to a broken address after deploy.',
    path: 'lib/site-url.ts',
    bad: "export const siteUrl = process.env.VERCEL_URL;\nexport const callback = new URL('/auth/callback', siteUrl);",
    good: "const vercelUrl = process.env.VERCEL_URL;\nexport const siteUrl = vercelUrl\n  ? `https://${vercelUrl}`\n  : 'http://localhost:3000';",
    fix: 'Add the https:// scheme, and use a fixed production domain variable for callbacks that must not change.',
    category: 'screens',
  },
  {
    slug: 'password-written-to-logs',
    ruleId: 8201,
    code: 'PRIVACY-01',
    severity: 'HIGH',
    title: 'Password or personal data written to the console',
    description: 'Values logged with console.log end up in log storage that many people and tools can read.',
    consequence: 'User passwords sit in plain text in your logs, which is a breach and a compliance problem.',
    path: 'src/services/auth.ts',
    bad: "export async function login(email: string, password: string) {\n  console.log('login attempt', email, password);\n}",
    good: "export async function login(email: string) {\n  console.log('login attempt', { email });\n}",
    fix: 'Log an identifier, never the secret or the full personal record.',
    category: 'security',
  },
  {
    slug: 'use-search-params-without-suspense',
    ruleId: 29762,
    code: 'RULE-29762',
    severity: 'HIGH',
    title: 'useSearchParams in a page without a Suspense boundary',
    description: 'In Next.js a page that reads useSearchParams outside Suspense can fail the production build.',
    consequence: 'The deploy fails at build time, or the whole page renders only on the client.',
    path: 'app/search/page.tsx',
    bad: "'use client';\nimport { useSearchParams } from 'next/navigation';\nexport default function SearchPage() {\n  const q = useSearchParams().get('q');\n  return <p>{q}</p>;\n}",
    good: "'use client';\nimport { Suspense } from 'react';\nimport { useSearchParams } from 'next/navigation';\nexport default function SearchPage() {\n  return (\n    <Suspense fallback={null}>\n      <Results />\n    </Suspense>\n  );\n}\nfunction Results() {\n  const q = useSearchParams().get('q');\n  return <p>{q}</p>;\n}",
    fix: 'Move the hook into a child component and wrap it in Suspense.',
    category: 'screens',
  },
  {
    slug: 'local-storage-during-server-render',
    ruleId: 29622,
    code: 'RULE-29622',
    severity: 'HIGH',
    title: 'localStorage read while a Next.js page renders',
    description: 'localStorage does not exist on the server, so reading it during render crashes server rendering.',
    consequence: 'The page shows an error to every visitor instead of the dashboard.',
    path: 'pages/dashboard.tsx',
    bad: "export default function Dashboard() {\n  const user = localStorage.getItem('user');\n  return <p>{user}</p>;\n}",
    good: "import { useEffect, useState } from 'react';\nexport default function Dashboard() {\n  const [user, setUser] = useState<string | null>(null);\n  useEffect(() => setUser(localStorage.getItem('user')), []);\n  return <p>{user}</p>;\n}",
    fix: 'Read browser storage inside useEffect, after the page has mounted.',
    category: 'screens',
  },
  {
    slug: 'cors-wildcard-with-credentials',
    ruleId: 28835,
    code: 'RULE-28835',
    severity: 'MEDIUM',
    title: 'CORS allows any origin together with credentials',
    description: 'A wildcard origin combined with Allow-Credentials lets any website call your API as the signed-in user.',
    consequence: 'A malicious page can act on behalf of your logged-in customers.',
    path: 'next.config.js',
    bad: "headers: [\n  { key: 'Access-Control-Allow-Credentials', value: 'true' },\n  { key: 'Access-Control-Allow-Origin', value: '*' },\n]",
    good: "headers: [\n  { key: 'Access-Control-Allow-Credentials', value: 'true' },\n  { key: 'Access-Control-Allow-Origin', value: 'https://app.example.com' },\n]",
    fix: 'Name the exact origin that needs access instead of using a wildcard.',
    category: 'security',
  },
];

export const ruleBySlug = (slug: string) => RULE_PAGES.find((r) => r.slug === slug);
