<!-- Claude Code: this file is NOT auto-loaded. Import it from CLAUDE.md with @.claude/agent-kit/rules/KIT_RULES.md to enable it. -->

# KIT_RULES.md - Antigravity Kit

> This file defines how the AI behaves in this workspace.
>
> **PRECEDENCE:** This file overrides `CLAUDE.md` wherever they conflict. The only exception is the **Hard Constraints** list in Project Rules, which nothing overrides.

---

## CRITICAL: AGENT & SKILL PROTOCOL (START HERE)

> **MANDATORY:** You MUST read the appropriate agent file and its skills BEFORE performing any implementation. This is the highest priority rule.

### 1. Modular Skill Loading Protocol

Agent activated → Check frontmatter "skills:" → Read SKILL.md (INDEX) → Read specific sections.

- **Selective Reading:** DO NOT read ALL files in a skill folder. Read `SKILL.md` first, then only read sections matching the user's request.
- **Rule Priority:** P0 (KIT_RULES.md) > P1 (Agent .md) > P2 (SKILL.md). All rules are binding.

### 2. Enforcement Protocol

1. **When agent is activated:**
    - ✅ Activate: Read Rules → Check Frontmatter → Load SKILL.md → Apply All.
2. **Forbidden:** Never skip reading agent rules or skill instructions. "Read → Understand → Apply" is mandatory.

---

## 📥 REQUEST CLASSIFIER (STEP 1)

**Before ANY action, classify the request:**

| Request Type     | Trigger Keywords                           | Active Tiers                   | Result                      |
| ---------------- | ------------------------------------------ | ------------------------------ | --------------------------- |
| **QUESTION**     | "what is", "how does", "explain"           | TIER 0 only                    | Text Response               |
| **SURVEY/INTEL** | "analyze", "list files", "overview"        | TIER 0 + Explorer              | Session Intel (No File)     |
| **SIMPLE CODE**  | "fix", "add", "change" (single file)       | TIER 0 + TIER 1 (lite)         | Inline Edit                 |
| **COMPLEX CODE** | "build", "create", "implement", "refactor" | TIER 0 + TIER 1 (full) + Agent | **{task-slug}.md Required** |
| **DESIGN/UI**    | "design", "UI", "page", "dashboard"        | TIER 0 + TIER 1 + Agent        | **{task-slug}.md Required** |
| **SLASH CMD**    | /ag-create, /ag-orchestrate, /ag-debug              | Command-specific flow          | Variable                    |

---

## 🤖 INTELLIGENT AGENT ROUTING (STEP 2 - AUTO)

**ALWAYS ACTIVE: Before responding to ANY request, automatically analyze and select the best agent(s).**

> 🔴 **MANDATORY:** You MUST follow the protocol defined in `.claude/skills/intelligent-routing/SKILL.md`.

### Auto-Selection Protocol

1. **Analyze (Silent)**: Detect domains (Frontend, Backend, Security, etc.) from user request.
2. **Select Agent(s)**: Choose the most appropriate specialist(s).
3. **Inform User**: Concisely state which expertise is being applied.
4. **Apply**: Generate response using the selected agent's persona and rules.

### Response Format (MANDATORY)

When auto-applying an agent, inform the user:

```markdown
🤖 **Applying knowledge of `@[agent-name]`...**

[Continue with specialized response]
```

**Rules:**

1. **Silent Analysis**: No verbose meta-commentary ("I am analyzing...").
2. **Respect Overrides**: If user mentions `@agent`, use it.
3. **Complex Tasks**: For multi-domain requests, use `orchestrator` and ask Socratic questions first.

---

## 🏗️ PROJECT RULES: Zelsis (merged from CLAUDE.md)

> These project facts and constraints apply on top of every tier below. Where CLAUDE.md said something different about process, the adapted version here is the one to follow.

### Stack & Map

- **Stack:** Next.js (App Router), TypeScript (strict), Tailwind CSS, Supabase (Auth/Postgres/RLS).
- **App root:** `app/` (pages, layouts, server actions).
- **Shared:** `components/ui/` (shadcn/radix), `lib/` (utilities, supabase clients), `data/schema.ts` (app types).
- **Deep reference (read on demand only):** DB schema in `supabase/migrations/` and `sql/`; request schemas in `lib/validations/api-schemas.ts`.
- **Next.js version:** This version has breaking changes vs. training data. Read the relevant guide in `node_modules/next/dist/docs/` before writing Next.js code; heed deprecation notices.

### Agent Routing for This Project

| Area | Agent | Skills |
| --- | --- | --- |
| Pages, components, server actions UI | `frontend-specialist` | frontend-design, nextjs-app-router-patterns, nextjs-best-practices |
| Server actions, Supabase queries, auth | `backend-specialist` | api-patterns, database-design |
| Migrations, RLS policies, schema | `database-architect` | database-design |
| Auth, RLS review, secrets, OWASP | `security-auditor` | vulnerability-scanner |
| Playwright / `node:test` | `test-engineer` | testing-patterns, webapp-testing |

### Code Conventions

- **Mutations:** Server Actions with `useActionState` + Zod validation. No raw route handlers unless it is an external webhook.
- **Components:** Default to Server Components. Add `'use client'` only for React hooks or browser listeners.
- **Icons:** Only `lucide-react`. No inline SVGs when Lucide has an equivalent.
- **Errors:** Never throw or return untyped string exceptions.
- **Scope:** Modify only files relevant to the request. Do not reformat untouched adjacent code.

### Hard Constraints (non-negotiable, no rule in this file overrides these)

- **Database:** Every new table needs RLS policies. Never drop tables or columns.
- **Secrets:** Never access, output, or modify `.env*` files.
- **Keys:** Never expose `SUPABASE_SERVICE_ROLE_KEY` to client components or public bundles.
- **Packages:** No `npm install` of new dependencies without explicit user confirmation.
- **Auto-push:** Never run `.claude/agent-kit/scripts/watch_push.js`.

### Git Protocol

- Never commit or push to `main`/`master`; work on `feat/...` or `fix/...` branches.
- Push verified commits to the active feature branch without asking.
- Commit only at verified logical milestones, not after every file edit.
- Conventional Commits (`feat(auth): ...`, `fix(ui): ...`), description under 72 characters.
- Run `git status` before committing; make sure no `.env` or credentials are staged.

### Verification Commands

| Check | Command |
| --- | --- |
| Typecheck | `npx tsc --noEmit` |
| Lint | `npm run lint` (ESLint 9 flat config via `scripts/eslint-ts6.cjs`) |
| Unit / rules tests | `npm test` (rule fixtures go in `tests/rules/cases.ts`) |
| E2E | `npm run test:e2e` (Playwright, `tests/e2e/`; `PLAYWRIGHT_CHROMIUM_PATH` reuses a local Chromium) |
| Supabase types | `npx supabase gen types typescript --project-id ... > types/supabase.ts` |

**Definition of done (replaces CLAUDE.md "Verify"):** `npx tsc --noEmit` passes **and** the Final Checklist Protocol below passes for the affected areas. Report the results.

---

## TIER 0: UNIVERSAL RULES (Always Active)

### 🌐 Language Handling

When user's prompt is NOT in English:

1. **Internally translate** for better comprehension
2. **Respond in user's language** - match their communication
3. **Code comments/variables** remain in English

### 🧹 Clean Code (Global Mandatory)

**ALL code MUST follow `.claude/skills/clean-code/SKILL.md` rules. No exceptions.**

- **Code**: Concise, direct, no over-engineering. Self-documenting.
- **Testing**: Mandatory. Pyramid (Unit > Int > E2E) + AAA Pattern.
- **Performance**: Measure first. Adhere to 2025 standards (Core Web Vitals).
- **Infra/Safety**: 5-Phase Deployment. Verify secrets security.

### 📁 File Dependency Awareness

**Before modifying ANY file:**

1. Check `CODEBASE.md` → File Dependencies
2. Identify dependent files
3. Update ALL affected files together

### 🗺️ System Map Read

> 🔴 **MANDATORY:** Read `ARCHITECTURE.md` at session start to understand Agents, Skills, and Scripts.

**Path Awareness:**

- Agents: `.claude/agents/` (Project)
- Skills: `.claude/skills/` (Project)
- Runtime Scripts: `.claude/skills/<skill>/scripts/`

### 🧠 Read → Understand → Apply

```
❌ WRONG: Read agent file → Start coding
✅ CORRECT: Read → Understand WHY → Apply PRINCIPLES → Code
```

**Before coding, answer:**

1. What is the GOAL of this agent/skill?
2. What PRINCIPLES must I apply?
3. How does this DIFFER from generic output?

---

## TIER 1: CODE RULES (When Writing Code)

### 📱 Project Type Routing

| Project Type                           | Primary Agent         | Skills                        |
| -------------------------------------- | --------------------- | ----------------------------- |
| **MOBILE** (iOS, Android, RN, Flutter) | `mobile-developer`    | mobile-design                 |
| **WEB** (Next.js, React web)           | `frontend-specialist` | frontend-design               |
| **BACKEND** (API, server, DB)          | `backend-specialist`  | api-patterns, database-design |

> 🔴 **Mobile + frontend-specialist = WRONG.** Mobile = mobile-developer ONLY.

### 🛑 Socratic Gate

**For complex requests, STOP and ASK first:**

### 🛑 GLOBAL SOCRATIC GATE (TIER 0)

**MANDATORY: Every user request must pass through the Socratic Gate before ANY tool use or implementation.**

| Request Type            | Strategy       | Required Action                                                   |
| ----------------------- | -------------- | ----------------------------------------------------------------- |
| **New Feature / Build** | Deep Discovery | ASK minimum 3 strategic questions                                 |
| **Code Edit / Bug Fix** | Context Check  | Confirm understanding + ask impact questions                      |
| **Vague / Simple**      | Clarification  | Ask Purpose, Users, and Scope                                     |
| **Full Orchestration**  | Gatekeeper     | **STOP** subagents until user confirms plan details               |
| **Direct "Proceed"**    | Validation     | **STOP** → Even if answers are given, ask 2 "Edge Case" questions |

**Protocol:**

1. **Never Assume:** If even 1% is unclear, ASK.
2. **Handle Spec-heavy Requests:** When user gives a list (Answers 1, 2, 3...), do NOT skip the gate. Instead, ask about **Trade-offs** or **Edge Cases** (e.g., "LocalStorage confirmed, but should we handle data clearing or versioning?") before starting.
3. **Wait:** Do NOT invoke subagents or write code until the user clears the Gate.
4. **Reference:** Full protocol in `.claude/skills/brainstorming/SKILL.md`.

### 🏁 Final Checklist Protocol

**Trigger:** When the user says "son kontrolleri yap", "final checks", "çalıştır tüm testleri", or similar phrases.

| Task Stage       | Command                                            | Purpose                        |
| ---------------- | -------------------------------------------------- | ------------------------------ |
| **Manual Audit** | `python .claude/agent-kit/scripts/checklist.py .`             | Priority-based project audit   |
| **Pre-Deploy**   | `python .claude/agent-kit/scripts/checklist.py . --url <URL>` | Full Suite + Performance + E2E |

**Priority Execution Order:**

1. **Security** → 2. **Lint** → 3. **Schema** → 4. **Tests** → 5. **UX** → 6. **Seo** → 7. **Lighthouse/E2E**

**Rules:**

- **Completion:** A task is NOT finished until `checklist.py` returns success. `npx tsc --noEmit` must also pass.
- **Reporting:** If it fails, fix the **Critical** blockers first (Security/Lint).

**Available Scripts (12 total):**

| Script                     | Skill                 | When to Use         |
| -------------------------- | --------------------- | ------------------- |
| `security_scan.py`         | vulnerability-scanner | Always on deploy    |
| `dependency_analyzer.py`   | vulnerability-scanner | Weekly / Deploy     |
| `lint_runner.py`           | lint-and-validate     | Every code change   |
| `test_runner.py`           | testing-patterns      | After logic change  |
| `schema_validator.py`      | database-design       | After DB change     |
| `ux_audit.py`              | frontend-design       | After UI change     |
| `accessibility_checker.py` | frontend-design       | After UI change     |
| `seo_checker.py`           | seo-fundamentals      | After page change   |
| `bundle_analyzer.py`       | performance-profiling | Before deploy       |
| `mobile_audit.py`          | mobile-design         | After mobile change |
| `lighthouse_audit.py`      | performance-profiling | Before deploy       |
| `playwright_runner.py`     | webapp-testing        | Before deploy       |

> 🔴 **Agents & Skills can invoke ANY script** via `python .claude/skills/<skill>/scripts/<script>.py`

### 🎭 Gemini Mode Mapping

| Mode     | Agent             | Behavior                                     |
| -------- | ----------------- | -------------------------------------------- |
| **plan** | `project-planner` | 4-phase methodology. NO CODE before Phase 4. |
| **ask**  | -                 | Focus on understanding. Ask questions.       |
| **edit** | `orchestrator`    | Execute. Check `{task-slug}.md` first.       |

**Plan Mode (4-Phase):**

1. ANALYSIS → Research, questions
2. PLANNING → `{task-slug}.md`, task breakdown
3. SOLUTIONING → Architecture, design (NO CODE!)
4. IMPLEMENTATION → Code + tests

> 🔴 **Edit mode:** If multi-file or structural change → Offer to create `{task-slug}.md`. For single-file fixes → Proceed directly.

---

## TIER 2: DESIGN RULES (Reference)

> **Design rules are in the specialist agents, NOT here.**

| Task         | Read                            |
| ------------ | ------------------------------- |
| Web UI/UX    | `.claude/agents/frontend-specialist.md` |
| Mobile UI/UX | `.claude/agents/mobile-developer.md`    |

**These agents contain:**

- Purple Ban (no violet/purple colors)
- Template Ban (no standard layouts)
- Anti-cliché rules
- Deep Design Thinking protocol

> 🔴 **For design work:** Open and READ the agent file. Rules are there.

---

## 📁 QUICK REFERENCE

### Agents & Skills

- **Masters**: `orchestrator`, `project-planner`, `security-auditor` (Cyber/Audit), `backend-specialist` (API/DB), `frontend-specialist` (UI/UX), `mobile-developer`, `debugger`, `game-developer`
- **Key Skills**: `clean-code`, `brainstorming`, `app-builder`, `frontend-design`, `mobile-design`, `plan-writing`, `behavioral-modes`

### Key Scripts

- **Verify**: `.claude/agent-kit/scripts/verify_all.py`, `.claude/agent-kit/scripts/checklist.py`
- **Scanners**: `security_scan.py`, `dependency_analyzer.py`
- **Audits**: `ux_audit.py`, `mobile_audit.py`, `lighthouse_audit.py`, `seo_checker.py`
- **Test**: `playwright_runner.py`, `test_runner.py`

---
