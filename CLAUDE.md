# 1. Project & Stack Map
- Stack: Next.js (App Router), TypeScript (strict), Tailwind CSS, Supabase (Auth/Postgres/RLS).
- App Root: `app/` (pages, layouts, server actions).
- Shared: `components/ui/` (shadcn/radix), `lib/` (utilities, supabase clients), `data/schema.ts` (app types).
- Deep Reference: DB schema in `supabase/migrations/` (applied to Supabase) and `sql/`; request schemas in `lib/validations/api-schemas.ts` (read on demand only).

# 2. Exact Verification Commands
- Typecheck: `npx tsc --noEmit`
- Linter: none configured (`npm run lint` is an alias of the typecheck)
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
- Push: Push verified commits to the active feature branch without asking. Never push to `main`/`master`.
- Branch Protection: Don't commit directly to `main` or `master`; work on a feature branch (e.g., `feat/...`, `fix/...`).
- Atomic Commits: Do not commit after every single file edit. Stage and commit only when a logical milestone is fully implemented and verified.
- Commit Style: Use Conventional Commits (`feat(auth): ...`, `fix(ui): ...`). Keep commit descriptions under 72 characters.
- Secret Prevention: Always check `git status` before committing to ensure no `.env` or sensitive credentials are inadvertently staged.

# 6. Execution Protocol
- Plan: For changes spanning >= 2 files, state a 3-bullet plan before editing.
- Verify: Run `npx tsc --noEmit` (whole project) before reporting task completion.
- Tone: Be terse. Output git diff summaries and verification status; omit pleasantries.