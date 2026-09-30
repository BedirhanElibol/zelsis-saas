# Security Remediation Plan

This document outlines the phased remediation of the 51 security, performance, and accessibility vulnerabilities identified in the audit.

## Phase 1: Critical Security & Authentication (Completed)
- [x] **Path Traversal Mitigation:** Sanitize paths in `check.js`, `check_dupes.js`, `cleanup-duplicates.js` using `path.normalize` and root directory assertions.
- [x] **Webhook Security:** Implement HMAC signature verification and 300s timestamp replay protection in `app/api/v1/polar-webhook/route.ts`.
- [x] **API Auth & Validation:** Add auth guards and `application/json` content-type validation to `app/api/v1/waitlist/route.ts`.
- [x] **Secret Exposure & DB SSL:** Remove `NEXT_PUBLIC_` from backend secrets and append `?sslmode=require` to DB connections in `app/reports/[framework]/page.tsx`.

## Phase 2: Caching & Performance (Completed)
- [x] Implement ETags and `Cache-Control` revalidation in `app/api/og/scan-result/route.tsx`, `app/api/v1/customer-portal/route.ts`, `app/api/v1/products/route.ts`.
- [x] Remove `force-dynamic` where static rendering is appropriate (`app/api/v1/github-proxy/route.ts`, `app/api/v1/scans/process-job/route.ts`).
- [x] Configure Edge Rate Limiting (WAF) for high-cost inference routes.

## Phase 3: UI & Accessibility / WCAG 2.2 AA (Completed)
- [x] Add `aria-label` and fix `outline-none` -> `focus-visible:ring-2` in `components/CicdAutomationView.tsx`, `components/OverviewView.tsx`, `components/dashboard/DashboardView.tsx`, etc.
- [x] Add explicit privacy consent disclosures and double-submit mutation guards (`disabled={isPending}`).
- [x] Replace raster `<img>` tags with optimized `next/image` components.
- [x] Resolve monolithic files (e.g. `components/ScanRunnerView.tsx` > 1200 lines).
