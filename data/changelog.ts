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
    date: '2026-10-14',
    title: 'Mobile apps, shareable reports and fewer missed bugs',
    changes: [
      { kind: 'New', text: 'Checks for iOS, Android and React Native apps: certificate checks turned off, WebViews that read local files, deep links opened in a WebView, ECB / DES encryption, secrets in device logs, tokens in AsyncStorage, debuggable release builds and credentials saved to plain files.' },
      { kind: 'New', text: 'Share a read-only report link from the dashboard. It shows the score and findings, never your code or fix instructions, and you can turn it off at any time.' },
      { kind: 'Improved', text: 'Three checks now report HIGH when the flaw is clearly exploitable: database functions anyone can call, roles users pick for themselves at sign-up, and admin checks on a header nothing in the app sets.' },
      { kind: 'Fixed', text: 'Files saved with Windows line endings no longer hide findings from some rules.' },
      { kind: 'Fixed', text: 'Fewer false alarms on Next.js and Supabase code: edits to a new URL(...).searchParams copy, writes whose result is checked before use, OAuth callbacks that verify state, and pages that already wrap useSearchParams in Suspense.' },
      { kind: 'Fixed', text: 'SECURITY DEFINER functions revoked from clients in a later migration, VERCEL_URL values given https:// further down, and timingSafeEqual calls inside try / catch are no longer reported.' },
      { kind: 'Fixed', text: 'Measured on 30 AI-built apps: log messages that only mention the word "password" and Vite / React Router pages (which never render on a server) are no longer flagged, and open RLS policies now point at their USING (true) line instead of line 1.' },
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
