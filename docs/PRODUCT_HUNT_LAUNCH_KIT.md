# Zelsis Product Hunt & Hacker News Launch Kit (v1.0.0)
## Senior Developer Growth & Go-To-Market Playbook

> **Target:** #1 Product of the Day on Product Hunt & Front Page "Show HN" on Hacker News  
> **Platform:** Zelsis (https://zelsis.com)  
> **Core Value:** The sub-3.5s universal pre-deployment release gate & code health scanner.

---

## 1. Product Hunt Listing Assets

### 1.1 Product Metadata
- **Product Name:** Zelsis
- **Tagline (Under 60 chars):** Pre-deployment security gate & release readiness scanner
- **Primary Category:** Developer Tools, Engineering, SaaS, Productivity
- **Topics:** Developer Tools, Security, GitHub, Open Source, Next.js
- **Pricing:** Free tier available / $19/mo Pro Tier
- **Website URL:** `https://zelsis.com`

---

### 1.2 Maker's First Comment (The Launch Story)

```markdown
Hey Product Hunt community! 👋

I'm Bedirhan, creator of **Zelsis**.

Like many developers, I've lived through the anxiety of the "Friday 5:00 PM git push":
- Did someone accidentally commit a raw Supabase service role key?
- Is there an unauthenticated Next.js 15 Server Action mutating production records?
- Did a dependency update pull an unvetted copyleft AGPL library?
- Will this release pass our SOC 2 / ISO 27001 audit requirements?

Existing enterprise tools like Snyk or SonarQube charge $98+/dev/month, take 5–10 minutes to run in CI, require tedious sales calls, and upload your proprietary source code to external servers.

I built **Zelsis** to fix this:
⚡ **Sub-3.5 Second Scans:** Scans entire full-stack repositories in-memory before code ships.
🔒 **Zero-Retention Privacy:** Code is evaluated completely in-memory — zero code stored on disks.
🛡️ **Modern Stack Native:** 7,850+ calibrated AST rules built specifically for Next.js 15, React 19, Supabase RLS, Docker, and WCAG 2.2 AA.
📄 **Executive CISO Audit PDF:** Generate board-ready, SOC 2 aligned certification PDFs with cryptographic verification hashes in 1 click.
🤖 **PR Bot & CI/CD Gate:** Drop a 10-line GitHub Actions workflow to automatically block vulnerable pull requests with clear remediation diffs.

We have a functional, frictionless free tier — you can paste any public repo URL or test a demo repository right in your browser with zero sign-up.

I'd love to hear your brutally honest feedback on the scan speed, rule accuracy, and report design!

Happy shipping,
Bedirhan & the Zelsis Team
```

---

## 2. Hacker News "Show HN" Launch Template

* **Posting Window:** Tuesday or Wednesday between 8:00 AM and 9:30 AM EST (optimal front-page traction).
* **Title:** `Show HN: Zelsis – Fast in-memory release gate and code security auditor`
* **Target Tone:** Technical, humble, transparent, zero marketing adjectives.

### Raw Submission Text:

```markdown
Hi HN,

I built Zelsis (https://zelsis.com), a client-side release gate and code scanner that audits repositories for security risks, configuration errors, and accessibility flaws before deployment.

### Why I built it
Traditional SAST and SCA tools (Snyk, SonarQube) add significant latency to CI/CD pipelines (often 4–8 minutes per build) and upload code to third-party databases. For solo engineers and agile teams, waiting on heavy enterprise scanners slows down velocity.

Zelsis evaluates repository ASTs in-memory in under 3.5 seconds.

### What it checks
1. Next.js 15 & React: Unauthenticated Server Actions, raw <img> tags causing layout shift, client-side secret leakage, and hydration mismatches.
2. Cloud & Database: Supabase tables with Row Level Security (RLS) disabled, open CORS origins, and Docker containers running as root.
3. Supply Chain (SCA): Unlicensed or strict copyleft licenses (AGPL/GPL) that create intellectual property hazards.
4. WCAG 2.2 AA Accessibility: Naked `outline-none` stripping focus indicators, unlabelled interactive inputs, and touch targets below 44x44px.

### Architecture & Privacy
- Zero code persistence: Repositories fetched via GitHub API are analyzed strictly in volatile memory. No ASTs or source files are stored on disk or used for training.
- 1-Click CI/CD: Includes a pre-configured GitHub Actions workflow (`.github/workflows/zelsis-gate.yml`) that runs via curl and posts PR status comments.
- Executive PDF Export: Generates standalone, print-optimized certified audit reports for audit compliance.

You can test any public GitHub repo directly without an account.

I would appreciate any feedback on false positives, rule calibration, or edge cases.

URL: https://zelsis.com
```

---

## 3. Launch Day Checklist & Hour-by-Hour Playbook

| Time (PST) | Stage | Action Item |
|---|---|---|
| **12:01 AM** | **Go Live** | Schedule Product Hunt post to unlock at midnight PST. Verify links, demo data, and thumbnail GIF. |
| **05:00 AM** | **X / Twitter Drop** | Publish the Launch Thread on X using the assets from `docs/X_TWITTER_LAUNCH_KIT.md`. Tag relevant creators in tech. |
| **07:30 AM** | **Reddit Release** | Post the technical breakdown to `r/webdev` and `r/SideProject` using `docs/REDDIT_LAUNCH_KIT.md`. |
| **08:30 AM** | **Hacker News "Show HN"** | Submit the Show HN post. Monitor new submissions tab (`/newest`) and respond to every comment within 5 minutes. |
| **12:00 PM** | **Midday Momentum** | Share progress update on LinkedIn and Twitter. Check Stripe / Polar dashboard for early Pro conversions. |
| **06:00 PM** | **Evening Push** | Post a technical recap on `r/nextjs` discussing specific Next.js Server Action security rules discovered during scans. |
| **11:59 PM** | **Wrap & Retrospective** | Thank the Product Hunt and Reddit communities in pinned comments. Record user feedback into GitHub issues. |
