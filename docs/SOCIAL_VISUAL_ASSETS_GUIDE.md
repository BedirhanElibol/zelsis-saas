# Zelsis Visual Identity & Social Media Assets Production Guide
## Master Specification for X (Twitter), Reddit, and Open Graph Assets (v25.0.0)

This guide provides the complete, production-grade visual design specifications, responsive safe zones, typographic scales, design tokens, complete standalone SVG code mockups, and screenshot capture checklists for **Zelsis** across X (Twitter), Reddit, and web preview channels.

---

## 1. Executive Visual Brand Foundations & Design Tokens

### 1.1 Brand Philosophy: Utilitarian, Developer-First, High Trust
Zelsis is an automated pre-deployment release gate for modern web applications (Next.js, React, Node.js, Python, full-stack web). Its visual language conveys **rigor, precision, zero hype, and absolute transparency**.

Developers reject marketing noise, gimmicky gradients, and artificial hype. The Zelsis aesthetic is rooted in:
- **Obsidian Monochromatic Surfaces:** Deep charcoal and black foundation that minimizes optical fatigue and reflects modern developer interfaces (terminals, IDEs, code diffs).
- **Surgical Emerald Accents:** A single vibrant accent color (`#10B981`) denoting passing release gates, security clearance, and verified code health.
- **High-Contrast Typographic Hierarchy:** Uncompromising legibility with distinct pairings between system sans-serif headers and crisp monospace data readouts.
- **Architectural Clarity:** Strict 4px/8px grid discipline, 1px hairline borders (`rgba(255, 255, 255, 0.1)`), and purposeful whitespace.

---

### 1.2 Color Token Architecture

The color system is strictly defined across functional categories. No off-palette shades may be introduced.

| Token Name | Hex Code / Value | CSS Variable | Semantic Usage |
| :--- | :--- | :--- | :--- |
| **Obsidian Dark** | `#0A0A0A` | `--color-bg-base` | Primary canvas, social banner background, outer container |
| **Card Surface** | `#141414` | `--color-surface-card` | Scorecard surfaces, terminal windows, elevated containers |
| **Surface Hover / Sub** | `#1C1C1E` | `--color-surface-elevated` | Interactive elements, table headers, pill backgrounds |
| **Subtle Border** | `rgba(255, 255, 255, 0.1)` | `--color-border-subtle` | 1px hairline card borders, dividers, bounding boxes |
| **Active Border** | `rgba(16, 185, 129, 0.3)` | `--color-border-active` | Selected scorecard state, passing release gate outline |
| **Emerald Primary** | `#10B981` | `--color-accent-emerald` | Passing status, primary score (100/100), success badges |
| **Emerald Glow / Tint** | `rgba(16, 185, 129, 0.12)` | `--color-accent-tint` | Badge fills, active pill backgrounds, subtle glows |
| **Text Foreground** | `#EDEDED` | `--color-text-primary` | Main titles, scorecard numbers, high-priority labels |
| **Text Muted** | `#A1A1AA` | `--color-text-secondary` | Body explanations, technical specs, secondary metadata |
| **Text Dim** | `#71717A` | `--color-text-tertiary` | Timestamp, inactive flags, terminal timestamps |
| **Status Fail** | `#EF4444` | `--color-status-fail` | Critical vulnerability flags, failing checks (reference only) |
| **Status Warning** | `#F59E0B` | `--color-status-warning` | Advisories, optimization recommendations |
| **Status Info** | `#3B82F6` | `--color-status-info` | Metadata tags, framework badges |

---

### 1.3 Strict Anti-Cliche Rules & Prohibitions

To preserve elite developer credibility and comply with the zero-slop brand guidelines, all creatives must enforce these prohibitions:

1. **Strict Purple & Violet Ban:** Under no circumstances should violet, indigo, purple neon, or magenta gradients (`#8B5CF6`, `#6366F1`, `#A855F7`) be used. These have become associated with low-utility wrapper tools.
2. **Zero Floating 3D Orbs / Glass Icons:** Do not use glossy 3D spheres, floating plastic cubes, or fake metallic shields. All iconography must be flat, geometric, and vector-clean.
3. **Zero Sparkle & Magic Icons:** No four-point glitter stars, magic wands, or faux-galaxy backgrounds.
4. **No Exaggerated Pulsing Animations:** Dynamic banners and cards must remain steady, legible, and crisp without vibrating halos or distracting pulse loops.
5. **No Stock Imagery:** No generic corporate handshakes, server racks with blue laser beams, or staged developer photos.
6. **No Vague Sensationalism:** Every graphic must feature concrete technical data: genuine file names, real framework names (Next.js, FastAPI, Node.js), exact score breakdowns (100/100), and specific rule counts (7,850 rules).

---

### 1.4 Typography Hierarchy & Font Pairings

All social assets use a clean pairing of an enterprise geometric sans-serif for headlines and a high-readability monospace font for technical metrics.

- **Primary Sans:** `Inter`, `Geist`, or system fallback (`-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`).
- **Technical Monospace:** `JetBrains Mono`, `Geist Mono`, or system fallback (`ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace`).

#### Typographic Scale Matrix
| Role | Font Family | Size | Weight | Tracking (Letter Spacing) | Line Height |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Banner Hero Title** | Sans-Serif | 42px - 48px | 700 (Bold) | -0.03em (-1.2px) | 1.15 |
| **Card Header / H1** | Sans-Serif | 28px - 32px | 600 (SemiBold) | -0.02em (-0.6px) | 1.25 |
| **Score Numerical Hero** | Monospace | 72px - 84px | 800 (ExtraBold) | -0.04em (-3px) | 1.0 |
| **Subhead / Tagline** | Sans-Serif | 18px - 20px | 400 (Regular) | -0.01em (-0.2px) | 1.4 |
| **Pillar Category Label** | Sans-Serif | 14px - 16px | 600 (SemiBold) | 0.0em (0px) | 1.3 |
| **Terminal Code / Path** | Monospace | 13px - 14px | 500 (Medium) | 0.02em (+0.3px) | 1.5 |
| **Micro Badge / Meta** | Monospace | 11px - 12px | 600 (SemiBold) | 0.05em (+0.6px) | 1.2 |

---

## 2. Channel 1: X (Twitter) Header Banner (1500 x 500 px)

### 2.1 Technical Specifications & Responsive Safe Zones

The X header banner requires precise engineering due to responsive viewport scaling and mobile client avatar overlays.

- **Canvas Dimensions:** 1500px width by 500px height (3:1 aspect ratio).
- **Export Resolution:** 1500 x 500 px @ 1x (or 3000 x 1000 px @ 2x for Retina).
- **Maximum File Size:** Under 3.0 MB (PNG or lossless optimized WebP).
- **Desktop Avatar Cutout Safe Zone:**
  - On desktop, the profile avatar is a circle (400px diameter on profile page) that overlays the banner starting at `X: 40px`, `Y: 330px`, extending down into the profile details section.
  - **Rule:** Keep `X: 0px` to `X: 380px` and `Y: 300px` to `Y: 500px` free of essential text or primary logos.
- **Mobile Viewport Cropping:**
  - On mobile devices, up to 45px can be trimmed from the top and bottom edges.
  - Profile avatar is centered or left-aligned with a smaller diameter, cutting into the lower third.
  - **Rule:** Keep all critical text and graphics within the vertical safe area between `Y: 60px` and `Y: 440px`, and horizontal safe area between `X: 380px` and `X: 1440px`.
- **Primary Content Focal Zone:**
  - `X: 400px` to `X: 840px`: Tagline, brand title, value proposition, and trust signals.
  - `X: 860px` to `X: 1450px`: Visual scorecard card showing the passing release gate and 5 pillars.

---

### 2.2 Header Banner Layout Architecture

```text
+---------------------------------------------------------------------------------------------------+
|  X: 0, Y: 0                                                                           X: 1500, Y: 0|
|   [TOP MARGIN SAFE ZONE - 40px]                                                                   |
|                                                                                                   |
|                                   +-------------------------------------------------------------+ |
|   BRAND HEADLINE & POSITIONING    | THE ZELSIS RELEASE GATE CARD                             | |
|   Zelsis                       | +---------------------------------------------------------+ | |
|   Universal Pre-Deployment Gate   | | REPO: acme/web-app        STATUS: 100/100 PASSED            | | |
|                                   | | [v] Security Check: OWASP & Secrets Cleared             | | |
|   Deterministic AST code hygiene, | | [v] Dependencies: 0 Critical Vulnerabilities            | | |
|   vulnerability scanning &        | | [v] Infrastructure: Connection Pooling & SSL Enforced   | | |
|   cloud configuration checks.     | | [v] Code Hygiene: Unhandled Promises Clean              | | |
|                                   | | [v] Privacy: Zero Code Retention Guarantee              | | |
|   [7,850 Rules] [3.2s In-Memory]  | +---------------------------------------------------------+ | |
|                                   +-------------------------------------------------------------+ |
|   [AVATAR SAFE ZONE]                                                                              |
|   (Desktop avatar sits here)       [BOTTOM MARGIN SAFE ZONE - 40px]                               |
+---------------------------------------------------------------------------------------------------+
```

---

### 2.3 Standalone Clean SVG Code: X (Twitter) Header Banner (1500 x 500 px)

Save or render this SVG code directly to generate the exact, production-ready 1500x500 banner:

```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1500 500" width="1500" height="500">
  <defs>
    <!-- Background Gradient: Subtle Dark Obsidian -->
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0A0A0A" />
      <stop offset="60%" stop-color="#111111" />
      <stop offset="100%" stop-color="#0E1411" />
    </linearGradient>

    <!-- Card Fill Gradient -->
    <linearGradient id="cardGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#161616" />
      <stop offset="100%" stop-color="#121212" />
    </linearGradient>

    <!-- Subtle Emerald Glow for the Score Badge -->
    <radialGradient id="emeraldRadial" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#10B981" stop-opacity="0.18" />
      <stop offset="100%" stop-color="#10B981" stop-opacity="0.0" />
    </radialGradient>

    <!-- Hairline Grid Pattern -->
    <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
      <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#FFFFFF" stroke-opacity="0.02" stroke-width="1" />
    </pattern>
  </defs>

  <style>
    .font-sans { font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif; }
    .font-mono { font-family: "JetBrains Mono", "Geist Mono", ui-monospace, monospace; }
  </style>

  <!-- 1. Background Foundation -->
  <rect width="1500" height="500" fill="url(#bgGrad)" />
  <rect width="1500" height="500" fill="url(#grid)" />

  <!-- Subtle Emerald Ambient Accent in Upper Right -->
  <circle cx="1250" cy="120" r="300" fill="url(#emeraldRadial)" />

  <!-- 2. Left Column: Brand & Value Proposition (Positioned safely above/beside avatar) -->
  <g transform="translate(420, 95)">
    <!-- Brand Name + Category Badge -->
    <g>
      <rect x="0" y="0" width="104" height="24" rx="4" fill="#18231E" stroke="#10B981" stroke-width="1" stroke-opacity="0.4" />
      <text x="52" y="16" class="font-mono" font-size="11" font-weight="600" fill="#10B981" text-anchor="middle" letter-spacing="0.05em">RELEASE GATE</text>
    </g>

    <!-- Main Headline -->
    <text x="0" y="70" class="font-sans" font-size="44" font-weight="700" fill="#EDEDED" letter-spacing="-0.03em">
      Zelsis
    </text>
    <text x="0" y="105" class="font-sans" font-size="20" font-weight="500" fill="#10B981" letter-spacing="-0.01em">
      Universal Pre-Deployment Code &amp; Security Gate
    </text>

    <!-- Descriptive Copy (Concise, technical, zero-slop) -->
    <text x="0" y="145" class="font-sans" font-size="14" font-weight="400" fill="#A1A1AA">
      Deterministic AST audits for Next.js, Node.js, Python &amp; Full-Stack repositories.
    </text>
    <text x="0" y="168" class="font-sans" font-size="14" font-weight="400" fill="#A1A1AA">
      Catches security leaks, configuration flaws, and package vulnerabilities before you merge.
    </text>

    <!-- Technical Badges -->
    <g transform="translate(0, 210)">
      <!-- Badge 1: 7,850 Rules -->
      <g>
        <rect x="0" y="0" width="112" height="28" rx="6" fill="#141414" stroke="rgba(255,255,255,0.1)" stroke-width="1" />
        <circle cx="14" cy="14" r="3" fill="#10B981" />
        <text x="24" y="18" class="font-mono" font-size="11" font-weight="500" fill="#EDEDED">7,850 Rules</text>
      </g>

      <!-- Badge 2: In-Memory -->
      <g transform="translate(122, 0)">
        <rect x="0" y="0" width="138" height="28" rx="6" fill="#141414" stroke="rgba(255,255,255,0.1)" stroke-width="1" />
        <circle cx="14" cy="14" r="3" fill="#10B981" />
        <text x="24" y="18" class="font-mono" font-size="11" font-weight="500" fill="#EDEDED">Zero Retention</text>
      </g>

      <!-- Badge 3: 3.2s Audit -->
      <g transform="translate(270, 0)">
        <rect x="0" y="0" width="102" height="28" rx="6" fill="#141414" stroke="rgba(255,255,255,0.1)" stroke-width="1" />
        <circle cx="14" cy="14" r="3" fill="#10B981" />
        <text x="24" y="18" class="font-mono" font-size="11" font-weight="500" fill="#EDEDED">3.2s Run</text>
      </g>
    </g>
  </g>

  <!-- 3. Right Column: The Release Gate Scorecard Terminal Card -->
  <g transform="translate(860, 50)">
    <!-- Card Frame -->
    <rect width="590" height="400" rx="12" fill="url(#cardGrad)" stroke="rgba(255,255,255,0.12)" stroke-width="1" />

    <!-- Terminal Title Bar -->
    <path d="M 0 12 C 0 5.37 5.37 0 12 0 L 578 0 C 584.63 0 590 5.37 590 12 L 590 38 L 0 38 Z" fill="#18181A" />
    <circle cx="20" cy="19" r="4.5" fill="#EF4444" opacity="0.8" />
    <circle cx="36" cy="19" r="4.5" fill="#F59E0B" opacity="0.8" />
    <circle cx="52" cy="19" r="4.5" fill="#10B981" opacity="0.8" />
    <text x="76" y="23" class="font-mono" font-size="11" font-weight="500" fill="#71717A">zelsis audit --target https://github.com/acme/web-app</text>

    <!-- Top Card Stats Header -->
    <g transform="translate(24, 60)">
      <!-- Left side: Repo and Branch -->
      <text x="0" y="16" class="font-sans" font-size="15" font-weight="600" fill="#EDEDED">acme-corp/web-production</text>
      <text x="0" y="34" class="font-mono" font-size="11" font-weight="400" fill="#71717A">branch: main · commit: 7f208a9 · nextjs 15</text>

      <!-- Right side: Score Status Badge -->
      <g transform="translate(410, 0)">
        <rect x="0" y="0" width="130" height="38" rx="6" fill="#10B981" fill-opacity="0.12" stroke="#10B981" stroke-width="1" />
        <text x="65" y="18" class="font-mono" font-size="12" font-weight="700" fill="#10B981" text-anchor="middle">100 / 100</text>
        <text x="65" y="31" class="font-sans" font-size="9" font-weight="600" fill="#10B981" text-anchor="middle" letter-spacing="0.05em">GATE PASSED</text>
      </g>
    </g>

    <!-- Divider Line -->
    <line x1="24" y1="114" x2="566" y2="114" stroke="rgba(255,255,255,0.06)" stroke-width="1" />

    <!-- 5 Pillar Release Breakdown List -->
    <g transform="translate(24, 134)">
      <!-- Pillar 1: Security -->
      <g transform="translate(0, 0)">
        <circle cx="8" cy="8" r="7" fill="#10B981" fill-opacity="0.15" />
        <path d="M 5 8 L 7.5 10.5 L 11.5 5.5" stroke="#10B981" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none" />
        <text x="26" y="12" class="font-sans" font-size="13" font-weight="600" fill="#EDEDED">Security (OWASP Top 10, Secrets &amp; RLS)</text>
        <text x="540" y="12" class="font-mono" font-size="11" font-weight="600" fill="#10B981" text-anchor="end">0 FAILED</text>
      </g>

      <!-- Pillar 2: Dependencies -->
      <g transform="translate(0, 36)">
        <circle cx="8" cy="8" r="7" fill="#10B981" fill-opacity="0.15" />
        <path d="M 5 8 L 7.5 10.5 L 11.5 5.5" stroke="#10B981" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none" />
        <text x="26" y="12" class="font-sans" font-size="13" font-weight="600" fill="#EDEDED">Dependencies &amp; Supply Chain (SCA)</text>
        <text x="540" y="12" class="font-mono" font-size="11" font-weight="600" fill="#10B981" text-anchor="end">0 CVE</text>
      </g>

      <!-- Pillar 3: Infrastructure & Config -->
      <g transform="translate(0, 72)">
        <circle cx="8" cy="8" r="7" fill="#10B981" fill-opacity="0.15" />
        <path d="M 5 8 L 7.5 10.5 L 11.5 5.5" stroke="#10B981" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none" />
        <text x="26" y="12" class="font-sans" font-size="13" font-weight="600" fill="#EDEDED">Infrastructure &amp; Serverless Pooling</text>
        <text x="540" y="12" class="font-mono" font-size="11" font-weight="600" fill="#10B981" text-anchor="end">PASSED</text>
      </g>

      <!-- Pillar 4: Code Hygiene -->
      <g transform="translate(0, 108)">
        <circle cx="8" cy="8" r="7" fill="#10B981" fill-opacity="0.15" />
        <path d="M 5 8 L 7.5 10.5 L 11.5 5.5" stroke="#10B981" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none" />
        <text x="26" y="12" class="font-sans" font-size="13" font-weight="600" fill="#EDEDED">Code Quality &amp; Error Boundaries</text>
        <text x="540" y="12" class="font-mono" font-size="11" font-weight="600" fill="#10B981" text-anchor="end">PASSED</text>
      </g>

      <!-- Pillar 5: Compliance & Privacy -->
      <g transform="translate(0, 144)">
        <circle cx="8" cy="8" r="7" fill="#10B981" fill-opacity="0.15" />
        <path d="M 5 8 L 7.5 10.5 L 11.5 5.5" stroke="#10B981" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none" />
        <text x="26" y="12" class="font-sans" font-size="13" font-weight="600" fill="#EDEDED">Privacy &amp; Data Leakage Prevention</text>
        <text x="540" y="12" class="font-mono" font-size="11" font-weight="600" fill="#10B981" text-anchor="end">VERIFIED</text>
      </g>
    </g>

    <!-- Bottom Status Log Footer -->
    <g transform="translate(24, 344)">
      <rect x="0" y="0" width="542" height="34" rx="6" fill="#18181A" stroke="rgba(255,255,255,0.06)" stroke-width="1" />
      <circle cx="16" cy="17" r="3.5" fill="#10B981" />
      <text x="30" y="21" class="font-mono" font-size="11" font-weight="500" fill="#EDEDED">Release Gate Cleared: Ready for mainnet deployment</text>
      <text x="526" y="21" class="font-mono" font-size="11" font-weight="400" fill="#71717A" text-anchor="end">3.2s</text>
    </g>
  </g>
</svg>
```

---

## 3. Channel 2: Reddit Visual Asset System

Reddit developer communities (r/webdev, r/SideProject, r/nextjs, r/SaaS, r/reactjs) are strictly anti-corporate. Visual assets on Reddit must look like **an open-source developer tool**, not a commercial sales pitch.

### 3.1 Reddit Profile & Community Banner Specification (1920 x 384 px)

- **Canvas Dimensions:** 1920px width by 384px height (5:1 aspect ratio).
- **Format & Export:** PNG or high-quality WebP, sRGB color profile, under 5.0 MB.
- **Responsive Layout Safe Zones:**
  - **Left Offset Safe Zone:** On Reddit user profiles, the avatar overlaps the bottom-left corner (`X: 40px` to `X: 220px`).
  - **Mobile Horizontal Crop:** On mobile screens and narrow viewports, the outer 360px on both sides are clipped.
  - **Central Focal Canvas:** Place all critical content between `X: 380px` and `X: 1540px` (centered 1160px container).
- **Banner Layout Blueprint:**
  - Left Zone (`X: 380px` to `X: 950px`): Minimalist wordmark `Zelsis`, tag `PRE-DEPLOYMENT RELEASE GATE`, and a clean single-line description: *"Audit security, configurations, and dependencies before production."*
  - Right Zone (`X: 980px` to `X: 1540px`): A sleek horizontal scorecard showing the 5 verified pillars and the `100/100 PASSED` clearance stamp.

#### Standalone Clean SVG Code: Reddit Banner (1920 x 384 px)

```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 384" width="1920" height="384">
  <defs>
    <linearGradient id="redditBgGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#0A0A0A" />
      <stop offset="50%" stop-color="#121212" />
      <stop offset="100%" stop-color="#0D1411" />
    </linearGradient>
    <linearGradient id="redditCardGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#171717" />
      <stop offset="100%" stop-color="#111111" />
    </linearGradient>
  </defs>

  <style>
    .font-sans { font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif; }
    .font-mono { font-family: "JetBrains Mono", "Geist Mono", ui-monospace, monospace; }
  </style>

  <!-- Background Base -->
  <rect width="1920" height="384" fill="url(#redditBgGrad)" />

  <!-- Subtle Horizontal Grid Lines -->
  <line x1="0" y1="96" x2="1920" y2="96" stroke="rgba(255,255,255,0.02)" stroke-width="1" />
  <line x1="0" y1="192" x2="1920" y2="192" stroke="rgba(255,255,255,0.02)" stroke-width="1" />
  <line x1="0" y1="288" x2="1920" y2="288" stroke="rgba(255,255,255,0.02)" stroke-width="1" />

  <!-- Left Content Zone (X: 380) -->
  <g transform="translate(380, 80)">
    <!-- Pill Category -->
    <rect x="0" y="0" width="140" height="24" rx="4" fill="#18231E" stroke="#10B981" stroke-width="1" stroke-opacity="0.3" />
    <text x="70" y="16" class="font-mono" font-size="10" font-weight="600" fill="#10B981" text-anchor="middle" letter-spacing="0.08em">WEB RELEASE GATE</text>

    <!-- Main Title -->
    <text x="0" y="70" class="font-sans" font-size="40" font-weight="700" fill="#EDEDED" letter-spacing="-0.03em">
      Zelsis
    </text>
    <text x="0" y="105" class="font-sans" font-size="18" font-weight="500" fill="#10B981">
      Automated Pre-Deployment Verification for Web Apps
    </text>

    <!-- Subtitle -->
    <text x="0" y="140" class="font-sans" font-size="14" font-weight="400" fill="#A1A1AA">
      Instant AST security scans, misconfiguration detection &amp; dependency audits.
    </text>
    <text x="0" y="164" class="font-mono" font-size="12" font-weight="500" fill="#71717A">
      Next.js · React · Node.js · Python · In-Memory · 7,850 Rules
    </text>
  </g>

  <!-- Right Content Zone: Scorecard Preview (X: 1040) -->
  <g transform="translate(1040, 56)">
    <rect width="520" height="272" rx="10" fill="url(#redditCardGrad)" stroke="rgba(255,255,255,0.1)" stroke-width="1" />

    <!-- Terminal Header Bar -->
    <rect width="520" height="34" rx="10" fill="#1C1C1E" />
    <rect y="24" width="520" height="10" fill="#1C1C1E" />
    <circle cx="18" cy="17" r="4" fill="#EF4444" opacity="0.7" />
    <circle cx="32" cy="17" r="4" fill="#F59E0B" opacity="0.7" />
    <circle cx="46" cy="17" r="4" fill="#10B981" opacity="0.7" />
    <text x="64" y="21" class="font-mono" font-size="10" font-weight="500" fill="#71717A">zelsis release-gate --check-all</text>

    <!-- Card Body -->
    <g transform="translate(20, 50)">
      <!-- Score Hero -->
      <g>
        <text x="0" y="34" class="font-mono" font-size="38" font-weight="800" fill="#10B981">100/100</text>
        <text x="0" y="52" class="font-sans" font-size="12" font-weight="600" fill="#EDEDED">ALL GATES PASSED</text>
        <text x="0" y="68" class="font-mono" font-size="10" font-weight="400" fill="#71717A">Latency: 3.2s · 0 CVEs</text>
      </g>

      <!-- Pillar Badges Column -->
      <g transform="translate(180, 8)">
        <g transform="translate(0, 0)">
          <path d="M 0 5 L 4 9 L 10 2" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none" />
          <text x="18" y="8" class="font-sans" font-size="12" font-weight="500" fill="#EDEDED">Security (OWASP &amp; Secrets)</text>
        </g>
        <g transform="translate(0, 24)">
          <path d="M 0 5 L 4 9 L 10 2" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none" />
          <text x="18" y="8" class="font-sans" font-size="12" font-weight="500" fill="#EDEDED">Dependencies (SCA)</text>
        </g>
        <g transform="translate(0, 48)">
          <path d="M 0 5 L 4 9 L 10 2" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none" />
          <text x="18" y="8" class="font-sans" font-size="12" font-weight="500" fill="#EDEDED">Infrastructure &amp; Pooling</text>
        </g>
        <g transform="translate(0, 72)">
          <path d="M 0 5 L 4 9 L 10 2" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none" />
          <text x="18" y="8" class="font-sans" font-size="12" font-weight="500" fill="#EDEDED">Code Hygiene &amp; Async Safety</text>
        </g>
        <g transform="translate(0, 96)">
          <path d="M 0 5 L 4 9 L 10 2" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none" />
          <text x="18" y="8" class="font-sans" font-size="12" font-weight="500" fill="#EDEDED">Zero Code Storage Guaranteed</text>
        </g>
      </g>
    </g>

    <!-- Bottom Clearance Bar -->
    <g transform="translate(20, 224)">
      <rect width="480" height="30" rx="4" fill="#18231E" stroke="#10B981" stroke-width="1" stroke-opacity="0.3" />
      <text x="240" y="20" class="font-mono" font-size="11" font-weight="600" fill="#10B981" text-anchor="middle">
        CLEAR TO DEPLOY · NO BLOCKERS
      </text>
    </g>
  </g>
</svg>
```

---

### 3.2 Profile Avatar & Community Icon Specification (256 x 256 px)

The avatar icon is rendered across circular masks (Reddit, X, GitHub) and square/squircle masks (browser tabs, Slack, Discord). It must maintain razor-sharp legibility at micro-resolutions (32x32px and 16x16px favicon scale).

- **Canvas Size:** 256 x 256 px (1:1 aspect ratio).
- **Core Motif:** A geometric, architectural release gate / shield emblem. The outer perimeter is an angled hexagonal shield in Obsidian Dark (`#141414`) with an Emerald hairline border (`#10B981`). The center features code terminal brackets `{ }` enclosing an emerald verification checkmark.
- **Margin / Padding:** 24px internal padding so the circular mask never cuts off the emblem corners.

#### Standalone Clean SVG Code: Profile Avatar Icon (256 x 256 px)

```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
  <defs>
    <!-- Background Circle Fill -->
    <linearGradient id="avatarBgGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#141414" />
      <stop offset="100%" stop-color="#0A0A0A" />
    </linearGradient>

    <!-- Shield Face Gradient -->
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#1A1A1C" />
      <stop offset="100%" stop-color="#121614" />
    </linearGradient>

    <!-- Subtle Emerald Accent Radial -->
    <radialGradient id="emeraldAvatarGlow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#10B981" stop-opacity="0.25" />
      <stop offset="100%" stop-color="#10B981" stop-opacity="0.0" />
    </radialGradient>
  </defs>

  <!-- 1. Background Canvas -->
  <rect width="256" height="256" fill="#0A0A0A" />
  <circle cx="128" cy="128" r="118" fill="url(#avatarBgGrad)" stroke="rgba(255,255,255,0.08)" stroke-width="1.5" />
  <circle cx="128" cy="128" r="80" fill="url(#emeraldAvatarGlow)" />

  <!-- 2. Geometric Shield Gate (Vector Emblem) -->
  <g transform="translate(128, 128)">
    <!-- Outer Shield Hairline -->
    <path d="M 0 -72 
             L 54 -46 
             L 54 18 
             L 0 68 
             L -54 18 
             L -54 -46 Z" 
          fill="url(#shieldGrad)" 
          stroke="#10B981" 
          stroke-width="3.5" 
          stroke-linejoin="round" />

    <!-- Inner Code Gate Brackets: Left Bracket -->
    <path d="M -22 -24 
             L -34 -12 
             L -34 12 
             L -22 24" 
          stroke="#EDEDED" 
          stroke-width="3" 
          stroke-linecap="round" 
          stroke-linejoin="round" 
          fill="none" />

    <!-- Inner Code Gate Brackets: Right Bracket -->
    <path d="M 22 -24 
             L 34 -12 
             L 34 12 
             L 22 24" 
          stroke="#EDEDED" 
          stroke-width="3" 
          stroke-linecap="round" 
          stroke-linejoin="round" 
          fill="none" />

    <!-- Central Verified Gate Checkmark -->
    <path d="M -12 2 
             L -3 11 
             L 14 -7" 
          stroke="#10B981" 
          stroke-width="4.5" 
          stroke-linecap="round" 
          stroke-linejoin="round" 
          fill="none" />
  </g>
</svg>
```

---

## 4. Channel 3: Social Share Card (Open Graph / Twitter Card - 1200 x 630 px)

The Open Graph image is displayed automatically when links are shared on X, Reddit, LinkedIn, Discord, Telegram, and Slack. It must immediately communicate **objective code clearance and professional authority**.

### 4.1 Card Anatomy & Information Architecture

- **Canvas Dimensions:** 1200px width by 630px height (1.91:1 standard OG ratio).
- **Format:** High-fidelity PNG or WebP, sRGB.
- **Card Anatomy:**
  1. **Top Navigation & Identity Bar:**
     - Left: Zelsis Wordmark + Shield Icon + Tag `PRE-DEPLOYMENT AUDIT REPORT`.
     - Right: Verification Stamp `AUDIT STATUS: COMPLETE (3.2s)`.
  2. **Repository Target Bar:**
     - Container displaying analyzed target metadata: `repo: vercel/commerce` · `commit: e3f09a1` · `stack: Next.js 15, TypeScript, Tailwind`.
  3. **Dual-Column Body:**
     - **Left Column (The Clearance Score):**
       - Massive `100/100` numeric indicator in Emerald `#10B981`.
       - Status badge: `RELEASE GATE PASSED`.
       - Metrics list: `7,850 Checks Run` · `0 Blockers` · `0 Warnings` · `In-Memory Audit`.
     - **Right Column (5-Pillar Scorecard Grid):**
       - Pillar 1: **Security (OWASP Top 10, Secrets & RLS)** -> `PASSED (0 leaks)`
       - Pillar 2: **Dependencies & Supply Chain (SCA)** -> `PASSED (0 CVEs)`
       - Pillar 3: **Infrastructure & Serverless Pooling** -> `PASSED (Verified)`
       - Pillar 4: **Code Hygiene & Error Boundaries** -> `PASSED (0 leaks)`
       - Pillar 5: **Privacy & Zero Data Retention** -> `100% IN-MEMORY`
  4. **Bottom Verification Footer:**
     - Live application URL: `https://zelsis.com`
     - Trust pledge: *"No source code is ever stored on disk or used for model training."*

---

### 4.2 Standalone Clean SVG Code: Social Share Card (1200 x 630 px)

```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 630" width="1200" height="630">
  <defs>
    <!-- Background Foundation Gradient -->
    <linearGradient id="ogBg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0A0A0A" />
      <stop offset="60%" stop-color="#111111" />
      <stop offset="100%" stop-color="#0E1713" />
    </linearGradient>

    <!-- Card Background -->
    <linearGradient id="ogCardBg" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#161616" />
      <stop offset="100%" stop-color="#121212" />
    </linearGradient>

    <!-- Emerald Ambient Radial Glow -->
    <radialGradient id="ogEmeraldGlow" cx="20%" cy="40%" r="60%">
      <stop offset="0%" stop-color="#10B981" stop-opacity="0.14" />
      <stop offset="100%" stop-color="#10B981" stop-opacity="0.0" />
    </radialGradient>
  </defs>

  <style>
    .font-sans { font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif; }
    .font-mono { font-family: "JetBrains Mono", "Geist Mono", ui-monospace, monospace; }
  </style>

  <!-- 1. Background Foundation -->
  <rect width="1200" height="630" fill="url(#ogBg)" />
  <circle cx="280" cy="280" r="340" fill="url(#ogEmeraldGlow)" />

  <!-- Outer Card Boundary with 1px hairline border -->
  <rect x="40" y="40" width="1120" height="550" rx="16" fill="url(#ogCardBg)" stroke="rgba(255,255,255,0.12)" stroke-width="1.5" />

  <!-- 2. Top Header Row -->
  <g transform="translate(80, 80)">
    <!-- Logo Shield Motif -->
    <g transform="translate(0, 0)">
      <path d="M 12 0 L 24 6 L 24 18 L 12 26 L 0 18 L 0 6 Z" fill="#18231E" stroke="#10B981" stroke-width="1.8" />
      <path d="M 8 13 L 11 16 L 16 10" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none" />
    </g>

    <!-- Brand Name -->
    <text x="36" y="20" class="font-sans" font-size="22" font-weight="700" fill="#EDEDED" letter-spacing="-0.02em">Zelsis</text>
    <text x="160" y="19" class="font-mono" font-size="12" font-weight="500" fill="#71717A">/ PRE-DEPLOYMENT RELEASE GATE</text>

    <!-- Status Badge (Right aligned) -->
    <g transform="translate(840, -4)">
      <rect x="0" y="0" width="200" height="32" rx="6" fill="#10B981" fill-opacity="0.12" stroke="#10B981" stroke-width="1" />
      <circle cx="16" cy="16" r="3.5" fill="#10B981" />
      <text x="28" y="20" class="font-mono" font-size="11" font-weight="700" fill="#10B981" letter-spacing="0.04em">PRODUCTION CLEARED</text>
    </g>
  </g>

  <!-- Divider Line -->
  <line x1="80" y1="130" x2="1120" y2="130" stroke="rgba(255,255,255,0.08)" stroke-width="1" />

  <!-- 3. Target Repository Metadata Bar -->
  <g transform="translate(80, 154)">
    <rect width="1040" height="42" rx="8" fill="#18181A" stroke="rgba(255,255,255,0.06)" stroke-width="1" />
    
    <text x="20" y="26" class="font-mono" font-size="12" font-weight="500" fill="#71717A">TARGET:</text>
    <text x="80" y="26" class="font-mono" font-size="12" font-weight="600" fill="#EDEDED">github.com/acme-corp/web-production</text>

    <text x="440" y="26" class="font-mono" font-size="12" font-weight="500" fill="#71717A">BRANCH:</text>
    <text x="506" y="26" class="font-mono" font-size="12" font-weight="600" fill="#10B981">main</text>

    <text x="570" y="26" class="font-mono" font-size="12" font-weight="500" fill="#71717A">STACK:</text>
    <text x="626" y="26" class="font-mono" font-size="12" font-weight="500" fill="#EDEDED">Next.js 15 · TypeScript · Node.js</text>

    <text x="940" y="26" class="font-mono" font-size="12" font-weight="500" fill="#71717A">TIME: 3.2s</text>
  </g>

  <!-- 4. Main Body: Dual-Column Layout -->
  
  <!-- Left Column: Big Scorecard Hero -->
  <g transform="translate(80, 226)">
    <!-- Container Box -->
    <rect width="360" height="270" rx="10" fill="#161616" stroke="rgba(255,255,255,0.08)" stroke-width="1" />

    <!-- Numerical Score -->
    <text x="40" y="104" class="font-mono" font-size="82" font-weight="800" fill="#10B981" letter-spacing="-0.04em">100</text>
    <text x="195" y="104" class="font-mono" font-size="34" font-weight="600" fill="#71717A">/ 100</text>

    <!-- Score Status -->
    <text x="40" y="142" class="font-sans" font-size="16" font-weight="700" fill="#EDEDED" letter-spacing="-0.01em">
      PASSED ALL RELEASE GATES
    </text>
    <text x="40" y="166" class="font-sans" font-size="13" font-weight="400" fill="#A1A1AA">
      Zero critical production blockers found.
    </text>

    <!-- Metrics Mini List -->
    <g transform="translate(40, 196)">
      <text x="0" y="14" class="font-mono" font-size="11" font-weight="500" fill="#71717A">Rules Evaluated:</text>
      <text x="140" y="14" class="font-mono" font-size="11" font-weight="600" fill="#EDEDED">7,850</text>

      <text x="0" y="36" class="font-mono" font-size="11" font-weight="500" fill="#71717A">Execution Model:</text>
      <text x="140" y="36" class="font-mono" font-size="11" font-weight="600" fill="#10B981">In-Memory AST</text>

      <text x="0" y="58" class="font-mono" font-size="11" font-weight="500" fill="#71717A">Code Retention:</text>
      <text x="140" y="58" class="font-mono" font-size="11" font-weight="600" fill="#EDEDED">Zero (Ephemeral)</text>
    </g>
  </g>

  <!-- Right Column: The 5 Pillars Breakdown -->
  <g transform="translate(465, 226)">
    <!-- Container Box -->
    <rect width="655" height="270" rx="10" fill="#161616" stroke="rgba(255,255,255,0.08)" stroke-width="1" />

    <g transform="translate(30, 26)">
      <!-- Row 1: Security -->
      <g transform="translate(0, 0)">
        <circle cx="8" cy="8" r="8" fill="#10B981" fill-opacity="0.15" />
        <path d="M 5 8 L 7.5 10.5 L 11.5 5.5" stroke="#10B981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none" />
        <text x="30" y="13" class="font-sans" font-size="14" font-weight="600" fill="#EDEDED">Security (OWASP Top 10, Secrets &amp; RLS)</text>
        <rect x="495" y="0" width="100" height="22" rx="4" fill="#10B981" fill-opacity="0.12" />
        <text x="545" y="15" class="font-mono" font-size="11" font-weight="600" fill="#10B981" text-anchor="middle">0 DEFECTS</text>
      </g>

      <!-- Row 2: Dependencies -->
      <g transform="translate(0, 44)">
        <circle cx="8" cy="8" r="8" fill="#10B981" fill-opacity="0.15" />
        <path d="M 5 8 L 7.5 10.5 L 11.5 5.5" stroke="#10B981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none" />
        <text x="30" y="13" class="font-sans" font-size="14" font-weight="600" fill="#EDEDED">Dependencies &amp; Supply Chain (SCA)</text>
        <rect x="495" y="0" width="100" height="22" rx="4" fill="#10B981" fill-opacity="0.12" />
        <text x="545" y="15" class="font-mono" font-size="11" font-weight="600" fill="#10B981" text-anchor="middle">0 CVES</text>
      </g>

      <!-- Row 3: Infrastructure -->
      <g transform="translate(0, 88)">
        <circle cx="8" cy="8" r="8" fill="#10B981" fill-opacity="0.15" />
        <path d="M 5 8 L 7.5 10.5 L 11.5 5.5" stroke="#10B981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none" />
        <text x="30" y="13" class="font-sans" font-size="14" font-weight="600" fill="#EDEDED">Infrastructure &amp; Serverless Connection Pooling</text>
        <rect x="495" y="0" width="100" height="22" rx="4" fill="#10B981" fill-opacity="0.12" />
        <text x="545" y="15" class="font-mono" font-size="11" font-weight="600" fill="#10B981" text-anchor="middle">VERIFIED</text>
      </g>

      <!-- Row 4: Code Hygiene -->
      <g transform="translate(0, 132)">
        <circle cx="8" cy="8" r="8" fill="#10B981" fill-opacity="0.15" />
        <path d="M 5 8 L 7.5 10.5 L 11.5 5.5" stroke="#10B981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none" />
        <text x="30" y="13" class="font-sans" font-size="14" font-weight="600" fill="#EDEDED">Code Hygiene &amp; Error Boundary Completeness</text>
        <rect x="495" y="0" width="100" height="22" rx="4" fill="#10B981" fill-opacity="0.12" />
        <text x="545" y="15" class="font-mono" font-size="11" font-weight="600" fill="#10B981" text-anchor="middle">CLEARED</text>
      </g>

      <!-- Row 5: Privacy -->
      <g transform="translate(0, 176)">
        <circle cx="8" cy="8" r="8" fill="#10B981" fill-opacity="0.15" />
        <path d="M 5 8 L 7.5 10.5 L 11.5 5.5" stroke="#10B981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none" />
        <text x="30" y="13" class="font-sans" font-size="14" font-weight="600" fill="#EDEDED">Privacy Compliance &amp; Zero Code Storage</text>
        <rect x="495" y="0" width="100" height="22" rx="4" fill="#10B981" fill-opacity="0.12" />
        <text x="545" y="15" class="font-mono" font-size="11" font-weight="600" fill="#10B981" text-anchor="middle">IN-MEMORY</text>
      </g>
    </g>
  </g>

  <!-- 5. Bottom Verification Footer -->
  <g transform="translate(80, 526)">
    <text x="0" y="20" class="font-mono" font-size="12" font-weight="500" fill="#71717A">
      VERIFY ANY PUBLIC REPOSITORY:
    </text>
    <text x="210" y="20" class="font-mono" font-size="12" font-weight="600" fill="#10B981">
      https://zelsis.com
    </text>
    <text x="1040" y="20" class="font-mono" font-size="11" font-weight="400" fill="#52525B" text-anchor="end">
      Deterministic Pre-Flight Gate · Zero Third-Party Telemetry
    </text>
  </g>
</svg>
```

---

## 5. Product Screenshot Capture Checklist & Operating Procedures

To maintain high technical trust on X threads and Reddit posts, screenshots must never look like unformatted browser windows. Follow this strict capture checklist.

### 5.1 Environment Configuration & Display Calibration

| Configuration Parameter | Required Setting | Rationale |
| :--- | :--- | :--- |
| **Display Resolution** | 2560 x 1440 px or 3840 x 2160 px (4K) | Eliminates pixelation on high-DPI smartphone screens |
| **Display Pixel Ratio (DPR)** | 2.0x (Retina scale) | Renders sub-pixel fonts and hairline borders with razor clarity |
| **Theme Calibration** | Forced Dark Mode (`#0A0A0A` background) | Matches obsidian developer tool aesthetic |
| **Browser Chrome Frame** | Clean macOS Dark Window Frame (Red, Amber, Green dots) | Communicates desktop-class precision |
| **Browser Window Padding** | 32px to 48px drop shadow around window | Creates visual elevation against social feeds |
| **Browser Viewport** | 1280 x 800 px (scaled 2x to 2560 x 1600 px) | Perfect proportions without tiny unreadable UI text |
| **Browser Zoom Level** | 100% (No artificial browser zoom) | Retains authentic design token proportions |
| **Clean Data Standard** | Use realistic repo targets (e.g. `acme-corp/web-app`) | Avoid test1, asdf, or developer placeholder strings |
| **Privacy Safeguards** | Zero real personal tokens, API keys, or private org names | Preserves security credibility |

---

### 5.2 Key View 1: Clean Dashboard Overview & Scorecard

- **Target URL:** `https://zelsis.com`
- **Component Hierarchy to Capture:**
  1. Top navigation: Logo, "Docs", "GitHub", "Status: Operational".
  2. Main Hero Input: Clean input field containing `https://github.com/acme-corp/nextjs-saas-template` with an emerald `"Run Release Audit"` button.
  3. The Gate Scorecard: Massive `100/100 PASSED` indicator.
  4. 5-Pillar Cards: Five clean cards side-by-side or in a 3+2 grid showing zero blockers.
- **Visual State:** Completed scan state with subtle emerald borders (`#10B981` at 30% opacity).
- **Intended Use Case:** Opening image for Tweet #3 ("What Zelsis does") and Reddit Post Template A (`r/webdev`).

---

### 5.3 Key View 2: Live Terminal Scanner / Execution Stream

- **Capture Mode:** High-resolution screenshot or clean 4-second MP4/GIF loop.
- **Component Hierarchy to Capture:**
  1. Dark Terminal Window (`#141414`) with hairline border and title `zelsis-cli v25.0.0`.
  2. Step-by-step audit logs:
     ```text
     [0.12s] Fetching repository tree (acme-corp/web-app) ... DONE
     [0.45s] Building AST for 184 JavaScript/TypeScript files ... DONE
     [1.10s] Evaluating Security Pillar (OWASP, Secrets, RLS) ... 0 findings
     [1.85s] Auditing Dependencies (pnpm-lock.yaml) ... 0 vulnerabilities
     [2.40s] Validating Serverless Infrastructure & Pooling ... PASS
     [2.95s] Checking Error Boundaries & Unhandled Promises ... PASS
     [3.20s] Clearance Granted: 100/100 PASSED GATE in 3.20s
     ```
- **Visual Accent:** Pulsing green terminal cursor and emerald checkmarks beside each passed step.
- **Intended Use Case:** Tweet #2 ("How fast it runs") and Reddit Post Template B (`r/SideProject`).

---

### 5.4 Key View 3: Git Diff Remediation Drawer

- **Component Hierarchy to Capture:**
  1. Side-by-side or unified Git diff drawer sliding in from the right edge.
  2. Vulnerability context: *"Permissive CORS Origin with Credentials Detected"*.
  3. The Diff Preview:
     ```diff
     - cors: { origin: "*", credentials: true }
     + cors: { 
     +   origin: process.env.NODE_ENV === "production" 
     +     ? "https://acme.com" 
     +     : "http://localhost:3000", 
     +   credentials: true 
     + }
     ```
  4. Action button: Crisp emerald button labeled `[Copy Git Patch]`.
- **Visual State:** Surgical red line highlight (`#EF4444` background at 15%) and emerald green fix highlight (`#10B981` background at 15%).
- **Intended Use Case:** Tweet #5 ("Actionable remediations, not just alarms") and technical discussion comments on Reddit.

---

### 5.5 Production Export Specifications

| Asset Type | Target Resolution | Aspect Ratio | Export Format | Target File Size |
| :--- | :--- | :--- | :--- | :--- |
| **X Header Banner** | 1500 x 500 px (3000x1000 @ 2x) | 3:1 | PNG-24 (Lossless) | < 1.8 MB |
| **Reddit Profile Banner** | 1920 x 384 px | 5:1 | PNG-24 (Lossless) | < 2.0 MB |
| **Avatar / Profile Icon** | 256 x 256 px (512x512 @ 2x) | 1:1 | PNG-24 (Transparent) | < 150 KB |
| **Open Graph / Twitter Card** | 1200 x 630 px | 1.91:1 | PNG-24 / WebP (90%) | < 600 KB |
| **Product UI Screenshots** | 2560 x 1440 px | 16:9 | PNG-24 (Lossless) | < 2.5 MB |
| **Terminal Animation (Loop)** | 1280 x 720 px | 16:9 | MP4 (H.264, 60fps) | < 4.0 MB |

---

## 6. Pre-Flight Asset Quality Verification Checklist

Before publishing any visual asset to X, Reddit, or CDN storage, confirm all 7 verification gates:

- [ ] **1. Zero Purple/Violet:** Inspect color histogram. Verify 0 occurrences of violet/magenta tones.
- [ ] **2. 100% Native English:** Verify zero foreign or placeholder text in headers, badges, code comments, or metadata.
- [ ] **3. Safe Zone Compliance:** Preview the X header with the desktop circular avatar cutout mask applied. Ensure brand name and badges remain fully visible.
- [ ] **4. High-DPI Font Crispness:** Inspect typography at 200% zoom. Monospace numbers and text must remain vector-sharp with no blur.
- [ ] **5. Contrast Ratio Verification:** Test text against background using WCAG AAA standards (minimum 7:1 for body copy `#A1A1AA` on `#0A0A0A`, 14:1 for `#EDEDED` on `#0A0A0A`).
- [ ] **6. SVG Code Validity:** Validate all embedded SVG code blocks with standard XML parsers. Verify explicit `xmlns`, `viewBox`, and self-closing tags.
- [ ] **7. Privacy & Data Hygiene:** Ensure all repository URLs in graphics reference standard mock paths (`acme-corp/web-production`) with no real secrets or internal URLs.
