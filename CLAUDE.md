# 1. Project & Stack Map
- Stack: Next.js (App Router), TypeScript (strict), Tailwind CSS, Supabase (Auth/Postgres/RLS).
- App Root: `app/` (pages, layouts, server actions).
- Shared: `components/ui/` (shadcn/radix), `lib/` (utilities, supabase clients), `data/schema.ts` (app types).
- Deep Reference: DB schema in `supabase/migrations/` (applied to Supabase) and `sql/`; request schemas in `lib/validations/api-schemas.ts` (read on demand only).

# 2. Exact Verification Commands
- Typecheck: `npx tsc --noEmit`
- Linter: `npm run lint` (ESLint 9 flat config; runs on TS 6 API via `scripts/eslint-ts6.cjs` until typescript-eslint supports TS 7)
- E2E: `npm run test:e2e` (Playwright, `tests/e2e/`; set `PLAYWRIGHT_CHROMIUM_PATH` to reuse a local Chromium)
- Tests: `npm test` (legacy `tests/test_suite.ts` + `node:test` files in `tests/unit/`, `tests/rules/`). Add rule fixtures to `tests/rules/cases.ts`.
- Sync Types: `npx supabase gen types typescript --project-id ... > types/supabase.ts`

# 3. Non-Obvious Conventions
- Data Mutations: Use Server Actions with `useActionState` and Zod validation. No raw route handlers unless external webhook.
- Component Scope: Default to Server Components. Add `'use client'` strictly when using React hooks or browser listeners.
- Icons: Exclusively `lucide-react`. Never generate inline SVGs if Lucide has an equivalent.
- Error Handling: Never throw or return untyped string exceptions.

# 4. Hard Constraints & Safety
- Database: Every new table needs RLS policies. Never drop tables/columns.
- Secrets: Never access, output, or modify `.env*` files.
- Keys: Never expose `SUPABASE_SERVICE_ROLE_KEY` to client components or public bundles.
- Packages: Do not run `npm install` for new dependencies without explicit user confirmation.
- Scope: Modify only files relevant to the active prompt. Do not reformat adjacent untouched code.

# 5. Git & GitHub Protocol
- Push: Push verified commits to the active feature branch without asking, and merge verified PRs into `main` without asking.
- Branches: Work on a feature branch (e.g., `feat/...`, `fix/...`) and reach `main` through a PR.
- Atomic Commits: Do not commit after every single file edit. Stage and commit only when a logical milestone is fully implemented and verified.
- Commit Style: Use Conventional Commits (`feat(auth): ...`, `fix(ui): ...`). Keep commit descriptions under 72 characters.
- Secret Prevention: Always check `git status` before committing to ensure no `.env` or sensitive credentials are inadvertently staged.

# 6. Execution Protocol
- Plan: For changes spanning >= 2 files, state a 3-bullet plan before editing.
- Verify: Run `npx tsc --noEmit` (whole project) before reporting task completion.
- Tone: Be terse. Output git diff summaries and verification status; omit pleasantries.

<!-- BEGIN:nextjs-agent-rules -->

# 7. Token Budget
- Output: report in 5 lines or fewer (done, result, next). Bot comments on a PR (Vercel, Zelsis) and "nothing to fix" events get one line.
- Reading: never dump a whole file, diff, log or result list. Use `Grep` with a path and `head_limit`, `Read` with `offset`/`limit`, `git diff --stat`, or `| tail -5`. A tool result saved to a file is sliced by character range, not re-read.
- Verifying: run `npm test`, `npm run lint` and `npm run benchmark -- --check` once before a PR, filtered (`| grep -E "^ℹ (pass|fail)"`, `| tail -2`). Do not re-run them after a copy or text change; `npx tsc --noEmit` is enough.
- Waiting: one `gh pr checks <n> --watch` call, never a loop of status checks. Merge when green.
- Searching: skip `.cache/`, `.claude/worktrees/` and `marketing-assets/` unless the task is about them (see `.ignore`). Never `du` or `find` across the whole repo root.
- Media: no videos, stills or screenshots unless asked. One contact sheet beats ten images; use scale 0.5.
- Questions: do not ask about anything that does not change what gets built or sold. Pick the default, say which in one line.
- Handoffs: no agents or other sessions for work that fits in this one. Keep the state in the project memory file, not in a recap.
- Long output from CI logs: `gh run view <id> --log-failed | grep -E "Error|✖|not ok" | head`.

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->
