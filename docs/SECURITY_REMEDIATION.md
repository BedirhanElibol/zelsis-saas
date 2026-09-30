# Security Remediation Plan - Phase 4 (Resolving Final 24 Vulnerabilities)

## Group 1: API & Crypto Security (Items 1, 2, 3)
- [x] Upgrade MD5 to SHA-256 in `app/api/v1/customer-portal/route.ts`
- [x] Upgrade MD5 to SHA-256 in `app/api/v1/products/route.ts`
- [x] Enforce strict unconditional provider HMAC verification (ZERO-AUTH-43) in `app/api/v1/polar-webhook/route.ts`

## Group 2: Script Path Traversal Mitigation (Items 13 - 17)
- [ ] Sanitize paths with `path.normalize` and root bounds assertions in `fix_catalogs.js`
- [ ] Sanitize paths with `path.normalize` and root bounds assertions in `patch-scanner.js`
- [ ] Sanitize paths with `path.normalize` and root bounds assertions in `patch_catalogs.js`
- [ ] Sanitize paths with `path.normalize` and root bounds assertions in `patch_frameworks.js`
- [ ] Sanitize paths with `path.normalize` and root bounds assertions in `patch_ui.js`

## Group 3: Frontend & UI Rules (Items 4 - 12)
- [x] Pin GitHub Actions in `components/CicdAutomationView.tsx` to 40-character commit SHAs (SBOM-05, SLSA-04)
- [x] Resolve CONTAINER-02 (non-root USER) & SEARCH-02 (wildcard search) in `components/Hero.tsx`
- [x] Resolve PRIVACY-39 (explicit user consent for notifications) & CRON-01 (mutex lock) in `components/ScanRunnerView.tsx`
- [x] Eliminate decorative eyebrow icons (CLICHE-76) in `components/saas/BenchmarkSection.tsx`
- [x] Add Empty State component fallback (UI-04) in `components/scan-runner/ScanRunnerProgressPanel.tsx`
- [x] Add `role="status" aria-live="polite" aria-atomic="true"` (UI-INTERACT-20) in `components/ui/alert.tsx`

## Group 4: SQL PG-05 Deadlocks & RLS Hardening (Items 18 - 24)
- [x] Ensure deterministic primary key ordering (`ORDER BY id ASC`) before locking in SQL files (PG-05):
  - `data/supabase-migration.sql`
  - `lib/db-schema.sql`
  - `sql/04_rls_security_policies.sql`
  - `sql/07_async_scan_jobs.sql`
  - `supabase/migrations/20260923000000_security_and_rls_hardening.sql`
  - `supabase/migrations/20260925000000_scan_jobs_async_queue.sql`
- [x] Restrict RLS policy in `supabase/migrations/20260930000000_create_waitlist_table.sql` with explicit `auth.uid() = user_id` checks
