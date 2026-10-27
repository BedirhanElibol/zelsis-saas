/**
 * Public changelog (/changelog). One entry per release week, newest first, written for users:
 * what changed in what Zelsis finds or how it works, not internal refactors.
 */
export type ChangeKind = 'New' | 'Improved' | 'Fixed';

export interface ChangelogEntry {
  date: string;
  title: string;
  changes: { kind: ChangeKind; text: string }[];
}

export const CHANGELOG: ChangelogEntry[] = [
  {
    date: '2026-10-27',
    title: 'Mobile apps: what App Store and Google Play reviews reject',
    changes: [
      { kind: 'New', text: 'A starter template application id (com.example, com.yourcompany, org.reactjs.native.example) in Gradle, Expo or Xcode settings is reported before the first upload.' },
      { kind: 'New', text: 'Permissions Google Play only allows with a declaration (SMS, call log, all files, all packages, background location, install packages) are reported.' },
      { kind: 'New', text: 'An Android targetSdk below the level Google Play requires, and an empty or placeholder iOS permission prompt, are reported.' },
      { kind: 'New', text: 'Each scan and each pull request comment now answers two questions separately: Security, and Ready for users.' },
    ],
  },
  {
    date: '2026-10-27',
    title: 'Three more signs of an unfinished or invented page',
    changes: [
      { kind: 'New', text: 'Placeholder copy is reported: lorem ipsum, "Your Company Name" style text, and the starter template page title (for example "Create Next App").' },
      { kind: 'New', text: 'An urgency countdown whose deadline is computed from the current time, so it restarts for every visitor, is reported.' },
      { kind: 'New', text: 'A "#1 Product of the Day" claim typed into the page without a link to a Product Hunt listing is reported.' },
    ],
  },
  {
    date: '2026-10-26',
    title: 'Benchmark folders and in-process base URLs are not reported',
    changes: [
      { kind: 'Fixed', text: 'Code in benchmarks/ and bench/ folders is treated as outside the shipped app, so its findings are medium and do not fail the check.' },
      { kind: 'Fixed', text: 'A bare localhost base URL used only for in-process requests (app.request, new Request) is no longer reported as a hardcoded localhost API call; a file that calls fetch, axios, ky or got with it still is.' },
    ],
  },
  {
    date: '2026-10-24',
    title: 'PDF reports now include findings digest and scope page',
    changes: [
      { kind: 'New', text: 'PDF reports include a SHA-256 data digest on the final page so anyone can re-run the scan at the same commit and compare results.' },
      { kind: 'New', text: 'A dedicated Scope and Limits page details the repository, commit, file count, and pillars analyzed, clarifying what static analysis inspects and what requires runtime observation.' },
      { kind: 'New', text: 'Optional OWASP Top 10 breakdown table summarizes findings for rules carrying documented OWASP classifications.' },
    ],
  },
  {
    date: '2026-10-24',
    title: 'Finer precision for webhooks, RLS checks, and common build patterns',
    changes: [
      { kind: 'Fixed', text: 'Payment webhook verification rules are scoped to payment provider webhooks, recognizing signature adapters and secret headers while skipping non-payment events like issue trackers and chat bots.' },
      { kind: 'Fixed', text: 'Database Row Level Security rules now focus strictly on client-exposed databases, ignoring commented-out SQL and SQLite table definitions.' },
      { kind: 'Fixed', text: 'Safe YAML loaders like ruamel.yaml and commands using escapeshellarg are recognized as safe when no unescaped request input is present.' },
      { kind: 'Fixed', text: 'Secret fallbacks in local, dev, mock or test files and non-auth cookies are reported at medium instead of failing the gate. Network requests starting with a fixed config or environment URL are not reported as SSRF.' },
      { kind: 'Improved', text: 'SQL queries loading local files through DuckDB read_parquet or using table name constants alongside parameter placeholders are recognized as non-injections, keeping raw user input in query values strictly caught.' },
    ],
  },
  {
    date: '2026-10-23',
    title: 'Only proven rules can fail the release gate',
    changes: [
      { kind: 'Improved', text: 'A critical finding fails the gate only when its rule has caught a documented flaw in the benchmark or has a reviewed true positive, or when it is a published advisory for a dependency version. Findings from other rules are still reported, as high, so they show up in the pull request without blocking the merge on their own.' },
    ],
  },
  {
    date: '2026-10-23',
    title: 'Critical injection findings need outside input',
    changes: [
      { kind: 'Improved', text: 'SQL, command and code injection findings (eval included) stay critical only when the file reads outside input, such as a request body, query string, route parameter, form, cookie or upload. Without it they are reported as high: still visible, but they no longer fail the gate on their own. eval of a stored database field stays critical.' },
      { kind: 'Improved', text: 'Docker socket mounts, privileged containers and CAP_SYS_ADMIN are high instead of critical. An RLS policy with USING (true) is critical only when it allows writes; a read-only one is high, because public read is often intended.' },
    ],
  },
  {
    date: '2026-10-23',
    title: 'Fewer false alarms on internal commands, quoted SQL and test setups',
    changes: [
      { kind: 'Fixed', text: 'Command injection checks skip numeric process ids (taskkill, ps), read-only git commands and arguments passed through escapeshellarg, as long as no request value is on the line.' },
      { kind: 'Fixed', text: 'SQL built with quoted identifiers or upper-case constants next to bound parameters is not reported as injection, and Go log messages that contain the word "update" are no longer read as SQL.' },
      { kind: 'Fixed', text: 'Logging whether a secret is set, such as secret ? "(set)" : "(not set)", is not reported as a leaked value, and code that only searches text for "eval(" is not reported as calling eval.' },
      { kind: 'Improved', text: 'Test runner setups, experiment folders, fixture SQL and .env.test files are treated as non-app code. Placeholder keys made of words in comments are ignored; a real key in a comment is still reported.' },
    ],
  },
  {
    date: '2026-10-22',
    title: 'Docs, seeders and dev files no longer block a release',
    changes: [
      { kind: 'Improved', text: 'Findings in documentation, knowledge-base examples, seeders, local docker-compose files and dev scripts are reported at medium with a note, so they no longer fail the gate. The same code in the app itself still does. Leaked secrets keep their own handling.' },
      { kind: 'Fixed', text: 'Masked values such as "******" or "<your-secret>" are not reported as secrets, and a session secret fallback is only reported when it is a real value.' },
      { kind: 'Fixed', text: 'eval marked as reviewed with oxlint or Biome comments stays at medium, like eslint-disable, and so does new Function compiling MDX when no request input reaches it.' },
      { kind: 'Fixed', text: 'jwt.decode without verification is not reported when the same function verifies the token afterwards (the usual read-the-key-id-first pattern).' },
      { kind: 'Fixed', text: 'Missing-RLS checks skip SQLite tables recognised by their syntax or constant names.' },
      { kind: 'Improved', text: 'Raw SQL built from schema enum values, constants, column names, escaped identifiers, record ids or query-builder clauses is not reported as injection in Drizzle, Ruby, Go and Rust code. Request values still are.' },
      { kind: 'Fixed', text: 'Fewer reports on error codes compared with a password field, UI component names, PHP helper loaders, LLM evaluation scripts and log lines that only mention a secret. Third-party scripts without SRI on payment pages and old TLS versions are now high instead of critical.' },
    ],
  },
  {
    date: '2026-10-21',
    title: 'Fewer critical false alarms, retry storms and ORM indexes',
    changes: [
      { kind: 'Improved', text: 'SQL injection is only reported as critical when a value is placed into the query (inside quotes, after = or LIKE, or concatenated in). Queries the code assembles from its own pieces, such as column lists, table names, conditions or ORM-generated SQL, are now medium advice, and numbers, record ids and constants are not treated as input.' },
      { kind: 'Fixed', text: 'Missing-RLS checks understand RLS enabled in a loop over a list of tables, skip SQLite and Cloudflare D1 schemas and SQL in docs or examples, and no longer read table names from comments or format() templates.' },
      { kind: 'Fixed', text: 'eval checks no longer report methods that happen to be called eval (Redis Lua scripts, math libraries, an embedded JavaScript engine), typed method signatures or fixed strings; lines the developer marked as reviewed (nosemgrep, eslint-disable no-eval, nosec) stay reported at medium.' },
      { kind: 'New', text: 'Retries that hammer a failing service (advice only): a fetch, axios or requests call retried in a loop with no wait between attempts, and axios-retry set up without retryDelay, which retries instantly by default.' },
      { kind: 'Improved', text: 'Command injection checks skip database methods named exec, backticks inside strings and documentation, escaped arguments and argument lists that run no shell. Deserialization is only critical when the file reads outside input (requests, cookies, uploads, sockets); deep copies, YAML.load on current Ruby, safe PyYAML loaders and allow-listed unserialize are not reported.' },
      { kind: 'Improved', text: 'Keys found in test, fixture or docs files are reported at medium instead of blocking the release, since they are usually dummies (a real one still needs revoking), and Firebase API keys in GoogleService-Info.plist or google-services.json are not reported: they are public by design.' },
      { kind: 'New', text: 'PDF reports show a fix size for each finding (small, medium or large, with the kind of change it needs). It is a class by finding type, not an hours estimate: the team that knows the code sets that.' },
      { kind: 'Fixed', text: 'MD5 / SHA-1 is only reported when it protects a password, token, signature or session, not for checksums, cache keys or BitTorrent info hashes. Django mark_safe with every value passed through escape() is not XSS, FastAPI routes covered by include_router(..., dependencies=[...]) or FastAPI(dependencies=[...]) count as authenticated, and generated parsers and one-off scripts are skipped by the log-leak check.' },
      { kind: 'New', text: 'Missing foreign key indexes are now found in TypeORM entities (@ManyToOne with onDelete CASCADE or SET NULL) and JPA / Hibernate entities (@OnDelete), not only in SQL migrations. Only reported for Postgres apps, since MySQL indexes foreign keys itself, and an @Index on the relation, a class-level index or a migration index all count.' },
    ],
  },
  {
    date: '2026-10-20',
    title: 'Races in more languages, poison messages and fewer false alarms',
    changes: [
      { kind: 'New', text: 'Python IDOR: FastAPI, Flask and Django routes that need a signed-in user, then load a record by the id in the URL without checking it belongs to that user. Only reported for records the same file filters by the user somewhere else, so shared data (tabs, events, catalogues) and routes that check the owner, admin-only routes and DRF object permissions stay quiet.' },
      { kind: 'New', text: 'Lost-update races on balances, credits and stock now also in Java/Kotlin (JPA), Go (GORM), PHP (Eloquent) and Ruby (ActiveRecord), including model methods that do self.credits -= amount and save later without a lock.' },
      { kind: 'New', text: 'Queue consumers that put a failed message straight back with nack() / reject() / basic_nack() from the error handler. The message comes back forever and blocks the worker; consumers that check redelivery or a retry counter are not reported.' },
      { kind: 'New', text: 'Foreign keys with ON DELETE CASCADE or SET NULL that no migration indexes (low severity, advice only). Postgres does not index them for you, so deleting a parent row scans the whole child table. Indexes from every migration count, and columns or tables a later migration renames or drops are skipped. ORMs such as Prisma do not add these indexes on Postgres either.' },
      { kind: 'Fixed', text: 'Fewer false alarms: .env.local.example and other multi-part env templates are now read, optional env vars (if (process.env.X), X === "1", Boolean(process.env.X)), host-injected NEXT_PUBLIC_VERCEL_* and scripts/ are not reported as missing, and Server Actions or route handlers that call a helper which checks the user (in the same file or imported) are not reported as unauthenticated.' },
      { kind: 'Fixed', text: 'Mass-assignment checks now follow the request body into imported controllers or services and stay quiet when the callee validates the input against a strict Joi or Zod schema before saving.' },
      { kind: 'Fixed', text: 'More findings from scanning public apps: Kubernetes checks skip third-party Helm charts bundled inside a chart and PodSecurityPolicy definitions, GraphQL $where variables are not read as MongoDB $where, command checks skip build tool configs and commands built only from constants, re.compile() is not code execution (eval / exec marked noqa or nosec stay reported at medium), raw SQL checks treat table names and validated id lists as safe and skip migrations, and the Docker root-user finding points at the final FROM line.' },
      { kind: 'Fixed', text: 'SQL checks only treat text() as SQLAlchemy when it comes from SQLAlchemy, and skip scripts, migrations and placeholder lists; setattr loops over a serializer\'s validated data are not mass assignment; routes guarded by helpers such as requireAdmin() and public sign-in, sign-up and password-reset routes are not reported as unauthenticated.' },
      { kind: 'Fixed', text: 'XSS checks on innerHTML and dangerouslySetInnerHTML now skip versioned and bundled third-party scripts (such as jquery-3.6.0.slim.js and bootstrap.bundle.min.js) and syntax-highlighted code blocks rendered with Shiki, Prism or highlight.js.' },
      { kind: 'Fixed', text: 'Python pickle checks skip apps loading their own local model files, cache and queue codecs that unpickle values they pickled themselves, course and notebook folders, and prompts or docstrings that mention pickle.loads in text.' },
      { kind: 'Fixed', text: 'Ruby SQL injection checks now skip interpolations that cannot carry raw input (numeric casts such as .to_i, .to_f and Integer(), constants, and values escaped with connection.quote or sanitize_sql) as well as migrations, rake tasks and maintenance scripts.' },
      { kind: 'Fixed', text: 'Rails constantize / send on a request value is not reported when the value was checked against an allow-list just before (TYPES.include?, .in?, case ... when "Tag", ALLOWED.detect, a *_valid? guard).' },
      { kind: 'Fixed', text: 'Signing salts that are plain namespaces ("sentry-slack-integration") are not reported as hardcoded keys, CREATE / DROP DATABASE in setup helpers and seed scripts is not reported as SQL injection, log checks skip docs, API collections and dev scripts, and testutil/ folders count as test code.' },
      { kind: 'Fixed', text: 'Database passwords in Compose files, CI workflows and deploy templates that point at a service name (db, mysql) are no longer reported as leaked credentials. Node SQL concatenation needs a real query shape (SELECT ... FROM, INSERT INTO, UPDATE ... SET, DELETE FROM), skips migrations, seeds and scripts, and now points at the query call instead of line 1.' },
      { kind: 'Fixed', text: 'PHP deserialization checks skip Serializable::unserialize() methods and allowed_classes => false, private key headers used as a pattern or prefix check (startswith, regex, scrubber modules) are not reported as leaked keys, unittests/ and testdata/ folders count as test code, and maintenance scripts that load the repo\'s own pickle or YAML files are left alone.' },
      { kind: 'Fixed', text: 'Missing-RLS checks in monorepos: a supabase-js dependency in one package (an example app, say) no longer marks the Prisma migrations of every other package as exposed to clients. A supabase/ folder, PostgREST config or grants to anon still cover the whole repository. Ruby backticks inside strings, as in error messages, are no longer read as shell commands.' },
      { kind: 'Fixed', text: 'Python dependency checks read the whole package name (django-extensions and requests-oauthlib are not Django or Requests) and only judge pinned versions or upper bounds: Django>=4.2,<6 installs the newest release, not 4.2.0. Privileged-container checks skip PodSecurityPolicies, scan reports and locale keys such as description_add.' },
      { kind: 'Fixed', text: 'Webhook checks follow the handler into other files: a Stripe route that hands the body and signature to a service which calls constructEvent is no longer reported, and routes that sign in their caller (session, API key, team access) are treated as webhook settings screens rather than receivers.' },
      { kind: 'Fixed', text: 'SQL injection checks no longer read UI text such as "Select at most {n} items" as a query (SELECT now needs a FROM), skip Python {UPPER_CASE} module constants, and leave migrations and maintenance scripts alone. Python SSRF is only reported in web handlers that read request input and never check the host, not in jobs and scripts that fetch their own configured URLs.' },
      { kind: 'Fixed', text: 'Fewer false alarms found by scanning public apps: Redis Lua calls (redis.eval), tensor evaluation (mx.eval), methods named eval and Java / Go code are no longer reported as eval code execution, and innerHTML set from an icon or svg helper call is not reported as XSS.' },
      { kind: 'Fixed', text: 'Scans no longer stall on generated JavaScript with many comment blocks (protobuf.js output and similar): one check took time that doubled with every pair of comments.' },
      { kind: 'Improved', text: 'The public benchmark now shows the median scan time and, for each clean project that fails the gate, the hand-reviewed reason.' },
      { kind: 'New', text: '"What could this cost?" above the findings: for issues that let someone run up paid SMS or AI calls, enter your price per request and how many requests get through a minute, and see the cost of an hour and a day of abuse. For data leaks, enter how many users you store. Nothing is shown in dollars until you give your own numbers, and they stay in your browser.' },
      { kind: 'New', text: 'Findings that match a well-documented public incident now say so, with a link to the source: documents opened by changing a number in the URL (First American, 2019), apps shipped without Row Level Security (CVE-2025-48757), an open storage bucket of ID photos (Tea, 2025), an access key left in a public repository (Toyota, 2022), a gift-card balance spent twice by racing requests (Starbucks, 2015) and bot-triggered SMS codes (Twitter, 2023).' },
    ],
  },
  {
    date: '2026-10-19',
    title: 'Bugs between layers and home-made token checks',
    changes: [
      { kind: 'New', text: 'Hand-written token helpers: a parseToken() or getUserFromToken() that splits a JWT, base64-decodes the payload and trusts the user id or role without ever checking the signature. Zelsis follows the helper into its body, and stays quiet when the file verifies the token (jose, jsonwebtoken, an HMAC check) or only reads the expiry to refresh it.' },
      { kind: 'New', text: 'Bugs that show up only where two layers meet: an env var the code needs but no template or deploy config declares, a Dockerfile on an older Node than package.json asks for, an upload limit above the nginx or ingress body limit, queries on columns no migration indexes, balance or stock updates without a lock, per-user data under a shared cache key, jobs that retry forever, request bodies the frontend and backend disagree on, webhooks processed twice, SMS endpoints without a rate limit and queries missing the tenant filter.' },
    ],
  },
  {
    date: '2026-10-15',
    title: 'Keys for newer SaaS tools, hung requests and agent tools',
    changes: [
      { kind: 'New', text: 'Leaked keys for newer SaaS tools: Langfuse, Helicone, LangSmith, Pinecone, Convex, Inngest, Trigger.dev, Unkey, Dub, PostHog personal keys, Axiom, Neon, Tinybird, PlanetScale service tokens, OneSignal, LaunchDarkly server keys, Flagsmith server keys and more. Keys without a fixed prefix are only reported when they sit in the provider\'s own variable name.' },
      { kind: 'New', text: 'Bugs that hang or break requests: an http.request() that is never ended, async Express middleware whose catch never calls next(err), cookies().set() in a page or layout, a /g regex reused with .test(), sync bcrypt hashing inside a route, and Object.values() on a numeric enum.' },
      { kind: 'New', text: 'AI agents that loop with no step limit, and agent tools that read or write a file path the model picked without checking it stays inside the intended folder.' },
      { kind: 'New', text: 'Node inspectors exposed on 0.0.0.0 in production Dockerfiles and start commands, dependencies installed over http:// or git://, sync.WaitGroup or Mutex passed by value in Go, gunzip on request data without a size limit, export buttons that download an empty file, and 2FA backup codes written into the source.' },
      { kind: 'Fixed', text: 'Fewer false alarms: Map / Set / cookies().delete() in a Drizzle file is not a query without .where(), BigInt literals with separators (10_000_000n) are not mixed with numbers, and FastAPI routes that call require_operator(request) at the top count as authenticated.' },
    ],
  },
  {
    date: '2026-10-14',
    title: 'Mobile apps, shareable reports and fewer missed bugs',
    changes: [
      { kind: 'Fixed', text: 'Fewer false alarms on newly launched apps: SQL migrations and parameterised sql`` templates are no longer reported as Cypher injection, PDO and SQLite exec() calls are not shell commands, a method named exec is not eval, xxxx placeholders are not secrets, a scroll amount is not a payment amount, PHP values from functions declared `: int` are safe in SQL, apps bound to 127.0.0.1 are not treated as public APIs, and an embedded VS Code fork is skipped as third-party code.' },
      { kind: 'Improved', text: 'A Flutter app and a Rust web service join the public benchmark. Fewer false alarms there: Rust format! calls are only treated as SQL when the string really is a query, certificate checks are not reported as off when the app pins the certificate itself or only talks to localhost, placeholder passwords in CI and dev scripts are not reported as leaked, a private key header with no key after it is not a leaked key, and Dockerfiles that switch to USER $NAME count as non-root.' },
      { kind: 'New', text: 'Checks for iOS, Android and React Native apps: certificate checks turned off, WebViews that read local files, deep links opened in a WebView, ECB / DES encryption, secrets in device logs, tokens in AsyncStorage, debuggable release builds and credentials saved to plain files.' },
      { kind: 'Improved', text: 'The real-incident test set grows to 118 cases (IDOR, NoSQL login bypass, CORS checks a look-alike domain passes, client-set payment amounts and more): 86% are flagged HIGH or CRITICAL, 99% at MEDIUM or above. Supabase policies that let users change their own role are now caught in one-line table definitions, and admin-only policies are no longer flagged.' },
      { kind: 'New', text: 'Share a read-only report link from the dashboard. It shows the score and findings, never your code or fix instructions, and you can turn it off at any time.' },
      { kind: 'Improved', text: 'Three checks now report HIGH when the flaw is clearly exploitable: database functions anyone can call, roles users pick for themselves at sign-up, and admin checks on a header nothing in the app sets.' },
      { kind: 'Fixed', text: 'Files saved with Windows line endings no longer hide findings from some rules.' },
      { kind: 'Fixed', text: 'Fewer false alarms on Next.js and Supabase code: edits to a new URL(...).searchParams copy, writes whose result is checked before use, OAuth callbacks that verify state, and pages that already wrap useSearchParams in Suspense.' },
      { kind: 'Fixed', text: 'SECURITY DEFINER functions revoked from clients in a later migration, VERCEL_URL values given https:// further down, and timingSafeEqual calls inside try / catch are no longer reported.' },
      { kind: 'Fixed', text: 'Measured on 30 AI-built apps: log messages that only mention the word "password" and Vite / React Router pages (which never render on a server) are no longer flagged, and open RLS policies now point at their USING (true) line instead of line 1.' },
      { kind: 'Fixed', text: 'Localhost URLs used only as a fallback after an environment value, and dev / static servers without shutdown handlers, are no longer flagged.' },
      { kind: 'Fixed', text: 'Form fields made 16px on phones by a stylesheet and hand-written dialog focus traps are recognised, so they no longer raise mobile-zoom or focus-trap findings.' },
      { kind: 'Fixed', text: 'Next.js 16 proxy.ts (the renamed middleware.ts) and Auth.js v5 `export { auth as proxy }` count as route protection, so routes they cover are no longer reported as unauthenticated.' },
      { kind: 'Improved', text: 'The public benchmark now covers 26 projects, including six Android and iOS apps: 43 of 43 documented flaws are found, and every finding on the clean projects was reviewed.' },
      { kind: 'Fixed', text: 'Java and Kotlin deserialization checks no longer flag streams behind a class allowlist, deep copies or files only the app itself can write; untrusted input is still caught.' },
      { kind: 'Fixed', text: 'Plan limits are the same everywhere on the site and match what the app enforces.' },
    ],
  },
  {
    date: '2026-10-13',
    title: 'Bugs from real incidents, files in public folders',
    changes: [
      { kind: 'New', text: 'Five checks for flaws behind public incidents: the Supabase service role key in browser code, FastAPI delete and update routes with no login check, CORS that allows any site with cookies, user-supplied links without a scheme check and request bodies merged into settings.' },
      { kind: 'New', text: 'Env files, SQL dumps, Terraform state and private keys inside public/ or static/ are flagged, even when they are too large to download.' },
      { kind: 'Improved', text: 'Live site scans pace their checks and say plainly when bot protection stopped some of them, instead of reporting a clean result.' },
      { kind: 'Improved', text: 'Verified site owners can let Zelsis checks through their firewall with a private header.' },
    ],
  },
  {
    date: '2026-10-12',
    title: 'Live site checks and about 180 new rules',
    changes: [
      { kind: 'New', text: 'Live checks for exposed deploy files, admin consoles and keys inside JavaScript bundles. The deeper checks run only on domains you have verified.' },
      { kind: 'New', text: 'About 180 new rules: logic bugs, LLM and agent security, CI/CD, containers, Kubernetes and Terraform, privacy and database access, accessibility and front-end performance.' },
      { kind: 'Fixed', text: 'GitHub Actions workflows and infrastructure files in GitHub repositories are now scanned; they were skipped before.' },
      { kind: 'Improved', text: 'Team invites only work for the e-mail address they were sent to.' },
    ],
  },
  {
    date: '2026-10-10',
    title: 'Connect GitHub without a token',
    changes: [
      { kind: 'New', text: 'Connect private repositories through the Zelsis GitHub App: read-only, only the repositories you pick, no token to copy.' },
      { kind: 'New', text: 'A help launcher (Ctrl / Cmd + K) and a short dashboard tour for first-time users.' },
      { kind: 'New', text: 'The dashboard warns when a result comes from a scan older than the current rules.' },
    ],
  },
  {
    date: '2026-10-09',
    title: 'Logic bugs',
    changes: [
      { kind: 'New', text: 'A Logic Bugs category: mistakes in React and Next.js state, data handling, async code and money calculations that security scanners do not look for.' },
      { kind: 'New', text: 'Checks for features that only look finished in AI-built apps: submit handlers that send nothing but report success, fake delays standing in for real requests and placeholder credentials left in code.' },
      { kind: 'New', text: 'A page of real bugs Zelsis found in popular open-source projects, plus fix guides for Supabase and Stripe.' },
    ],
  },
  {
    date: '2026-10-07',
    title: 'Findings in the pull request, weekly rescans',
    changes: [
      { kind: 'New', text: 'The CI gate shows each finding on its line in the pull request diff.' },
      { kind: 'New', text: 'API keys for the CI gate and weekly rescans that e-mail you when a new finding appears.' },
      { kind: 'New', text: 'Data-flow checks for Python and Go handlers: request input reaching shell commands, outgoing requests and file paths.' },
      { kind: 'Improved', text: 'A precision pass on well-maintained open-source projects cut HIGH and CRITICAL false alarms from 80 to 23.' },
    ],
  },
  {
    date: '2026-10-03',
    title: 'Accepted risks and PR-aware gating',
    changes: [
      { kind: 'New', text: 'Dismiss a finding or mark it as an accepted risk; the gate stops counting it.' },
      { kind: 'New', text: 'On pull requests the gate decides on findings in the files the pull request changed, and lists older findings separately.' },
    ],
  },
];
