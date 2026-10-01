import type { Finding, Project } from './schema';

/**
 * Demo project and findings shown before a first scan. Kept apart from the rule catalogs
 * (data/mockData.ts) so importing the demo does not ship ~3 MB of catalog data to the client.
 */
export const SHOWCASE_DEMO_FINDINGS: Finding[] = [
  {
    id: 'showcase-infra-01',
    ruleId: 3001,
    type: 'INFRA_DATABASE',
    title: 'PostgreSQL/Supabase Table "organizations" Missing Row Level Security (RLS)',
    severity: 'HIGH',
    category: 'Database Security',
    filePath: 'supabase/migrations/20250101_init.sql',
    lineRange: 'Lines 12-16',
    snippet: 'CREATE TABLE public.organizations (\n  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\n  name TEXT NOT NULL,\n  billing_email TEXT\n);',
    reproductionSteps: [
      'Reviewed database migration file "supabase/migrations/20250101_init.sql".',
      'Table "organizations" defined without "ALTER TABLE ... ENABLE ROW LEVEL SECURITY;".',
      'Anonymous PostgREST client can query sensitive tenant records if default grant permissions are left unrestricted.'
    ],
    remediationPrompt: 'Enable RLS immediately on "organizations":\nALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "Tenants can only read own organization" ON public.organizations FOR SELECT TO authenticated USING (auth.uid() = owner_id);',
    diffPatch: '--- a/supabase/migrations/20250101_init.sql\n+++ b/supabase/migrations/20250101_init.sql\n@@ -12,4 +12,7 @@\n CREATE TABLE public.organizations (\n   id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\n   name TEXT NOT NULL,\n   billing_email TEXT\n );\n+\n+-- Enforce Row Level Security (RLS)\n+ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;\n+CREATE POLICY "Tenant isolation" ON public.organizations FOR ALL TO authenticated USING (auth.uid() = owner_id);',
    status: 'OPEN',
    owner: 'Database Lead',
    falsePositive: false
  },
  {
    id: 'showcase-sec-08',
    ruleId: 8,
    type: 'SECURITY',
    title: 'CORS Policy Wildcard Domain in API routes',
    severity: 'HIGH',
    category: 'Network & CORS',
    filePath: 'app/api/v1/auth/route.ts',
    lineRange: 'Lines 14-18',
    snippet: 'response.headers.set("Access-Control-Allow-Origin", "*");\nresponse.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");',
    reproductionSteps: [
      'Dispatched preflight OPTIONS request from external origin (https://attacker-domain.com).',
      'Server returned "Access-Control-Allow-Origin: *" permitting unauthenticated cross-origin requests to API endpoints.',
      'Violates OWASP A05:2025 Security Misconfiguration standards.'
    ],
    remediationPrompt: 'Replace wildcard CORS header with explicit origin allowlist in middleware.ts or next.config.ts. Allow only approved production domains (process.env.NEXT_PUBLIC_APP_URL) and reject untrusted cross-origin requests.',
    diffPatch: '--- a/app/api/v1/auth/route.ts\n+++ b/app/api/v1/auth/route.ts\n@@ -14,2 +14,3 @@\n- response.headers.set("Access-Control-Allow-Origin", "*");\n+ const allowedOrigin = process.env.NEXT_PUBLIC_APP_URL || "https://app.zelsis.com";\n+ response.headers.set("Access-Control-Allow-Origin", allowedOrigin);',
    status: 'OPEN',
    owner: 'Security Architect',
    falsePositive: false
  },
  {
    id: 'showcase-ui-a11y-01',
    ruleId: 1026,
    type: 'VIBEPOLISH',
    title: 'Form Input Missing Accessible Label / Focus Ring',
    severity: 'HIGH',
    category: 'Accessibility (WCAG)',
    filePath: 'components/auth/LoginForm.tsx',
    lineRange: 'Lines 42-46',
    snippet: '<input\n  type="email"\n  className="w-full bg-zinc-900 border border-zinc-800 rounded-md py-2 px-3 outline-none"\n  placeholder="name@work.com"\n/>',
    reproductionSteps: [
      'Executed keyboard navigation through form inputs using Tab key.',
      'Focus state is invisible due to "outline-none" without replacement focus-visible ring styles.',
      'Screen reader accessibility tree inspection revealed missing <label> or aria-label attribute.'
    ],
    remediationPrompt: 'Add an accessible <label htmlFor="email"> or aria-label="Work Email Address" attribute. Replace "outline-none" with "focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none" to meet WCAG 2.2 AA keyboard focus criteria.',
    diffPatch: '--- a/components/auth/LoginForm.tsx\n+++ b/components/auth/LoginForm.tsx\n@@ -42,3 +42,4 @@\n+ <label htmlFor="email" className="block text-xs font-mono text-zinc-400 mb-1">Work Email</label>\n  <input\n+   id="email"\n    type="email"\n-   className="w-full bg-zinc-900 border border-zinc-800 rounded-md py-2 px-3 outline-none"\n+   className="w-full bg-zinc-900 border border-zinc-800 rounded-md py-2 px-3 focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none"',
    status: 'OPEN',
    owner: 'Frontend Specialist',
    falsePositive: false
  },
  {
    id: 'showcase-compl-03',
    ruleId: 2003,
    type: 'LEGAL_COMPLIANCE',
    title: 'Cookie Consent Banner Equal Decline Choice',
    severity: 'MEDIUM',
    category: 'Consent & Tracking',
    filePath: 'components/compliance/CookieConsentBanner.tsx',
    lineRange: 'Lines 28-34',
    snippet: '<div className="flex gap-3 items-center">\n  <button className="bg-emerald-600 text-white px-4 py-2 rounded-lg font-bold">Accept All</button>\n  <button className="text-zinc-400 text-xs hover:underline">Customize in Settings</button>\n</div>',
    reproductionSteps: [
      'Navigated to site in incognito session to inspect first-party cookie banner.',
      'Detected dark pattern: prominent "Accept All" CTA but decline option buried under multi-click customization links.',
      'Violates EDPB & CNIL equal choice guidelines requiring 1-click decline parity.'
    ],
    remediationPrompt: 'Provide dual, symmetrical action buttons with equal visual contrast: "Accept All" and "Reject Non-Essential". Ensure users can decline tracking with a single click without opening nested configuration panels.',
    diffPatch: '--- a/components/compliance/CookieConsentBanner.tsx\n+++ b/components/compliance/CookieConsentBanner.tsx\n@@ -28,3 +28,4 @@\n  <div className="flex gap-3 items-center">\n    <button className="bg-emerald-600 text-white px-4 py-2 rounded-lg font-bold">Accept All</button>\n-   <button className="text-zinc-400 text-xs hover:underline">Customize in Settings</button>\n+   <button className="bg-zinc-800 hover:bg-zinc-700 text-white px-4 py-2 rounded-lg font-bold">Reject Non-Essential</button>\n  </div>',
    status: 'OPEN',
    owner: 'Compliance Officer',
    falsePositive: false
  },
  {
    id: 'showcase-ui-perf-01',
    ruleId: 1027,
    type: 'VIBEPOLISH',
    title: 'Unoptimized Raw <img> Tag (Next.js Image recommendation)',
    severity: 'MEDIUM',
    category: 'Performance & CWV',
    filePath: 'components/marketing/HeroSection.tsx',
    lineRange: 'Lines 58-62',
    snippet: '<img\n  src="/assets/dashboard-mockup.png"\n  alt="SaaS Platform Interface"\n  className="w-full h-auto rounded-xl shadow-2xl"\n/>',
    reproductionSteps: [
      'Audited Core Web Vitals (CWV) on hero section.',
      'Identified raw HTML <img> element loading a 2.4MB uncompressed PNG without Next.js automatic WebP/AVIF format conversion, responsive srcSet, or layout shift dimensions.'
    ],
    remediationPrompt: 'Replace raw <img> with Next.js <Image src="/assets/dashboard-mockup.png" alt="SaaS Platform Interface" width={1200} height={675} priority placeholder="blur" /> to eliminate layout shifts (CLS) and enable automated modern format compression.',
    diffPatch: '--- a/components/marketing/HeroSection.tsx\n+++ b/components/marketing/HeroSection.tsx\n@@ -58,3 +58,3 @@\n- <img src="/assets/dashboard-mockup.png" alt="SaaS Platform Interface" className="w-full h-auto rounded-xl shadow-2xl" />\n+ <Image src="/assets/dashboard-mockup.png" alt="SaaS Platform Interface" width={1200} height={675} priority className="w-full h-auto rounded-xl shadow-2xl" />',
    status: 'OPEN',
    owner: 'Frontend Specialist',
    falsePositive: false
  },
  {
    id: 'showcase-cliche-01',
    ruleId: 201,
    type: 'VIBEPOLISH',
    title: 'Monochromatic Dark Token Palette Harmony',
    severity: 'LOW',
    category: 'AI Cliché & Layout',
    filePath: 'tailwind.config.ts',
    lineRange: 'Lines 18-24',
    snippet: 'colors: {\n  background: "#000000",\n  card: "#18181b",\n  border: "rgba(255, 255, 255, 0.15)"\n}',
    reproductionSteps: [
      'Inspected dark token definitions across component surfaces.',
      'Detected pure black #000000 backdrop causing stark contrast vibration against pure white text without mid-tone elevation layers.',
      'Violates visual hierarchy guidelines for enterprise SaaS dashboards.'
    ],
    remediationPrompt: 'Adopt layered neutral tokens: bg-canvas (#09090B), bg-surface (#121215), and bg-card (#18181B) with muted border-white/10 to create harmonious depth and eliminate high-contrast eye fatigue.',
    diffPatch: '--- a/tailwind.config.ts\n+++ b/tailwind.config.ts\n@@ -18,3 +18,3 @@\n  colors: {\n-   background: "#000000",\n+   background: "#09090B",\n    card: "#18181b",',
    status: 'OPEN',
    owner: 'UI/UX Designer',
    falsePositive: false
  },
  {
    id: 'showcase-cliche-22',
    ruleId: 222,
    type: 'VIBEPOLISH',
    title: 'Pastel Square Icon Container Replacement',
    severity: 'LOW',
    category: 'AI Cliché & Visual',
    filePath: 'components/features/FeatureCard.tsx',
    lineRange: 'Lines 12-16',
    snippet: '<div className="w-12 h-12 rounded-xl bg-purple-100 text-purple-600 flex items-center justify-center">\n  <Sparkles className="w-6 h-6" />\n</div>',
    reproductionSteps: [
      'Inspected marketing feature cards.',
      'Detected repetitive formulaic pastel rounded square icon containers wrapping generic Lucide icons.',
      'Triggers CLICHE-22 anti-pattern for AI-generated template styling.'
    ],
    remediationPrompt: 'Replace pastel icon boxes with authentic micro-UI snippets, interactive metric indicators, or subtle border-embedded monochrome icons (e.g. bg-white/5 border border-white/10 text-white) to elevate enterprise credibility.',
    diffPatch: '--- a/components/features/FeatureCard.tsx\n+++ b/components/features/FeatureCard.tsx\n@@ -12,3 +12,3 @@\n- <div className="w-12 h-12 rounded-xl bg-purple-100 text-purple-600 flex items-center justify-center">\n+ <div className="w-10 h-10 rounded-lg bg-white/5 border border-white/10 text-emerald-400 flex items-center justify-center">',
    status: 'OPEN',
    owner: 'UI/UX Designer',
    falsePositive: false
  }
];

export const MOCK_PROJECTS: Project[] = [
  {
    id: 'proj-saas-starter',
    name: 'Next.js 15 SaaS Starter (Demo Showcase)',
    repoUrl: 'https://github.com/vercel/next.js',
    previewUrl: 'https://demo.zelsis.com',
    framework: 'Next.js 15 + Tailwind',
    providers: ['PostgreSQL', 'Stripe', 'Vercel', 'Tailwind v4'],
    lastScanAt: 'Just now',
    readinessScore: 88,
    gateStatus: 'PASSED',
    criticalCount: 0,
    highCount: 2,
    mediumCount: 2,
    lowCount: 2,
    uiClicheCount: 2,
    findings: SHOWCASE_DEMO_FINDINGS
  }
];

export const MOCK_SCAN_LOGS = [
  '[00:01] 🚀 Initializing Zelsis AI Release Gate Engine v1.4...',
  '[00:02] 📦 Fetching repository tree from target preview deployment (http://localhost:3009)...',
  '[00:03] 🔍 [Phase 1/3] Running Pre-flight Security & Secrets Audit...',
  '[00:04] ✅ SEC-01 Secret Isolation: Zero hardcoded secrets in client bundles.',
  '[00:05] ✅ SEC-03 Supabase Row Level Security (RLS): All policies enforced.',
  '[00:06] ✅ SEC-08 CORS Security: Wildcard origins disabled.',
  '[00:07] 🔑 SEC-11 Password Hashing & Auth Cookies: HttpOnly & Secure flags verified.',
  '[00:08] ⚡ SEC-05 Rate Limiting: Endpoint throttling active.',
  '[00:09] 🎨 [Phase 2/3] Executing VibePolish UI Anti-Pattern Matrix Audit...',
  '[00:10] 💅 UI-01: Monochromatic dark tokens verified.',
  '[00:11] 💅 UI-02: Zero Lucide icon flooding.',
  '[00:12] 🌿 [Phase 3/3] Running VibeCare Sustainability & Budget Drift Check...',
  '[00:13] 📊 Calculating overall health score and evaluating Release Gate Status...',
  '[00:14] 🎉 GATE EVALUATION COMPLETE: RELEASE GATE STATUS = PASSED (100/100 Readiness Score).'
];

export const DEMO_AUDIT_FINDINGS: Finding[] = SHOWCASE_DEMO_FINDINGS;
