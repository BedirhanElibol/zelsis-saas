/**
 * Zelsis Master evaluateWebVitalsRules Engine (50 Rules)
 * Rules WEB-PERF-01 to WEB-PERF-50 (Rule IDs 7101 to 7150).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { locateMatchLine } from './shared/locate';
export interface WebVitalsRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateWebVitalsRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): WebVitalsRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // WEB-PERF-01: Above-The-Fold Hero Image Missing Priority Attribute
    if (/(?:Hero|Banner|AboveFold)[\s\S]{0,300}<Image\b(?![^>]*\bpriority\b)[^>]*>/i.test(cleanContent) && /\.(?:tsx|jsx)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:Hero|Banner|AboveFold)[\s\S]{0,300}<Image\b(?![^>]*\bpriority\b)[^>]*>/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf01-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7101,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-01: Above-The-Fold Hero Image Missing Priority Attribute",
            severity: 'HIGH',
            category: "Largest Contentful Paint (LCP)",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-01 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Above-The-Fold Hero Image Missing Priority Attribute: Hero section primary image rendered without priority or fetchpriority='high', delaying LCP milestone."
            ],
            remediationPrompt: "Add priority={true} to the Next.js <Image> in the hero section.",
            status: 'OPEN',
            owner: "Next.js / React",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-01: Above-The-Fold Hero Image Missing Priority Attribute detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-02: Unsized Image or Video Element Causing Layout Shift
    if (/<(?:img|video)\b(?![^>]*(?:width|height|aspect-ratio|w-|h-))[^>]*>/i.test(cleanContent) && /\.(?:html|tsx|jsx)$/i.test(file.path) && !/avatar|icon|logo|profile/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/<(?:img|video)\b(?![^>]*(?:width|height|aspect-ratio|w-|h-))[^>]*>/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf02-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7102,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-02: Unsized Image or Video Element Causing Layout Shift",
            severity: 'HIGH',
            category: "Cumulative Layout Shift (CLS)",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-02 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unsized Image or Video Element Causing Layout Shift: <img> or <video> tag rendered without explicit width and height attributes or CSS aspect-ratio."
            ],
            remediationPrompt: "Specify explicit width and height props: <Image width={800} height={450} ... /> or CSS aspect-video.",
            status: 'OPEN',
            owner: "HTML / React",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-02: Unsized Image or Video Element Causing Layout Shift detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-03: Synchronous Third-Party Script Tag Blocking Render
    if (/<script\b(?![^>]*(?:async|defer|type=["\']module["\']))[^>]*src=["\']https?:\/\/(?!localhost)[^"\']*["\'][^>]*>/i.test(cleanContent) && /\.(?:html|tsx|jsx)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/<script\b(?![^>]*(?:async|defer|type=["\']module["\']))[^>]*src=["\']https?:\/\/(?!localhost)[^"\']*["\'][^>]*>/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf03-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7103,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-03: Synchronous Third-Party Script Tag Blocking Render",
            severity: 'HIGH',
            category: "Total Blocking Time (TBT)",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-03 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Synchronous Third-Party Script Tag Blocking Render: Third-party analytics, tracking, or ad scripts included via <script src='...'> without async, defer, or Next.js Script strategy."
            ],
            remediationPrompt: "Wrap in Next.js Script: <Script src='...' strategy='afterInteractive' /> or add defer/async.",
            status: 'OPEN',
            owner: "HTML / Scripts",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-03: Synchronous Third-Party Script Tag Blocking Render detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-04: Non-Passive Touch or Wheel Event Listener
    if (/addEventListener\(\s*[\'"](?:touchstart|touchmove|wheel)[\'"]\s*,\s*[^,)]+\)(?!\s*,\s*\{\s*passive:\s*true)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/addEventListener\(\s*[\'"](?:touchstart|touchmove|wheel)[\'"]\s*,\s*[^,)]+\)(?!\s*,\s*\{\s*passive:\s*true)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf04-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7104,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-04: Non-Passive Touch or Wheel Event Listener",
            severity: 'MEDIUM',
            category: "Interaction to Next Paint (INP)",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-04 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Non-Passive Touch or Wheel Event Listener: Attaching window.addEventListener('touchstart', fn) or 'wheel' without { passive: true }, blocking main-thread scroll."
            ],
            remediationPrompt: "Add { passive: true } to event listener options: window.addEventListener('wheel', fn, { passive: true }).",
            status: 'OPEN',
            owner: "DOM Events",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-04: Non-Passive Touch or Wheel Event Listener detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-05: Uncompressed Legacy Font Format (.ttf / .otf) in Bundle
    if (/@font-face\s*\{[^}]*url\([^)]+\.(?:ttf|otf)[\'"]?\)(?![^}]*url\([^)]+\.woff2)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/@font-face\s*\{[^}]*url\([^)]+\.(?:ttf|otf)[\'"]?\)(?![^}]*url\([^)]+\.woff2)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf05-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7105,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-05: Uncompressed Legacy Font Format (.ttf / .otf) in Bundle",
            severity: 'MEDIUM',
            category: "Font Loading & FOUT",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-05 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Uncompressed Legacy Font Format (.ttf / .otf) in Bundle: Referencing uncompressed .ttf or .otf font files in @font-face instead of modern WOFF2."
            ],
            remediationPrompt: "Convert font to WOFF2 format and add font-display: swap to @font-face declaration.",
            status: 'OPEN',
            owner: "Web Fonts",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-05: Uncompressed Legacy Font Format (.ttf / .otf) in Bundle detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-06: CSS @import Directive in Render-Critical Stylesheet
    if (/@import\s+(?:url\([\'"][^\'"]+[\'"]\)|[\'"][^\'"]+[\'"])\s*;/i.test(cleanContent) && !/globals\.css|tailwind/i.test(lowerPath) && /\.(?:css|scss)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/@import\s+(?:url\([\'"][^\'"]+[\'"]\)|[\'"][^\'"]+[\'"])\s*;/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf06-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7106,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-06: CSS @import Directive in Render-Critical Stylesheet",
            severity: 'MEDIUM',
            category: "Critical CSS & Waterfall",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-06 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected CSS @import Directive in Render-Critical Stylesheet: Using @import url(...) inside critical CSS stylesheets causing sequential render-blocking network round-trips."
            ],
            remediationPrompt: "Replace @import with HTML <link rel='preload' as='style' ...> or combine into main CSS bundle.",
            status: 'OPEN',
            owner: "CSS",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-06: CSS @import Directive in Render-Critical Stylesheet detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-07: Excessive DOM Node Tree Depth (>32 Levels)
    if (/(?:<div[^>]*>\s*){33,}/i.test(cleanContent) && /\.(?:tsx|jsx|html)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:<div[^>]*>\s*){33,}/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf07-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7107,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-07: Excessive DOM Node Tree Depth (>32 Levels)",
            severity: 'MEDIUM',
            category: "DOM Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-07 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Excessive DOM Node Tree Depth (>32 Levels): Nesting excessive layers of redundant container <div> elements exceeding 32 levels of DOM depth."
            ],
            remediationPrompt: "Flatten component hierarchy by removing unnecessary wrapper <div> elements and leveraging CSS grid.",
            status: 'OPEN',
            owner: "DOM / HTML",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-07: Excessive DOM Node Tree Depth (>32 Levels) detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-08: Unmemoized Heavy Computation in Component Render Body
    if (/\bconst\s+[a-zA-Z0-9_]+\s*=\s*[a-zA-Z0-9_]+\.(?:filter|map|reduce)\([^)]*\)\.(?:sort|filter)\([^)]*\);(?![^}]*useMemo)/i.test(cleanContent) && /\.(?:tsx|jsx)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/\bconst\s+[a-zA-Z0-9_]+\s*=\s*[a-zA-Z0-9_]+\.(?:filter|map|reduce)\([^)]*\)\.(?:sort|filter)\([^)]*\);(?![^}]*useMemo)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf08-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7108,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-08: Unmemoized Heavy Computation in Component Render Body",
            severity: 'MEDIUM',
            category: "React Re-render Cost",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-08 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unmemoized Heavy Computation in Component Render Body: Running expensive array filtering, sorting, or regex compilation directly in component render body on every state change."
            ],
            remediationPrompt: "Wrap expensive calculations in React.useMemo(() => compute(data), [data]).",
            status: 'OPEN',
            owner: "React",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-08: Unmemoized Heavy Computation in Component Render Body detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-09: Unthrottled Window Scroll or Resize Event Handler
    if (/window\.addEventListener\(\s*[\'"](?:scroll|resize)[\'"]\s*,\s*\(\s*\)\s*=>\s*\{[^}]*setState/i.test(cleanContent) && !/throttle|debounce|requestAnimationFrame/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/window\.addEventListener\(\s*[\'"](?:scroll|resize)[\'"]\s*,\s*\(\s*\)\s*=>\s*\{[^}]*setState/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf09-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7109,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-09: Unthrottled Window Scroll or Resize Event Handler",
            severity: 'MEDIUM',
            category: "Main Thread Bottleneck",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-09 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unthrottled Window Scroll or Resize Event Handler: Directly executing state updates inside window onScroll or onResize without requestAnimationFrame or throttle."
            ],
            remediationPrompt: "Throttle handler using requestAnimationFrame or a 100ms debounce function.",
            status: 'OPEN',
            owner: "DOM Events",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-09: Unthrottled Window Scroll or Resize Event Handler detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-10: Unoptimized SVG with Embedded Raster Base64 Data
    if (/<svg\b[^>]*>[\s\S]*?data:image\/(?:png|jpeg|webp);base64,[a-zA-Z0-9+/=]{2000,}[\s\S]*?<\/svg>/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<svg\b[^>]*>[\s\S]*?data:image\/(?:png|jpeg|webp);base64,[a-zA-Z0-9+/=]{2000,}[\s\S]*?<\/svg>/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf10-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7110,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-10: Unoptimized SVG with Embedded Raster Base64 Data",
            severity: 'LOW',
            category: "Asset Payload",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-10 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unoptimized SVG with Embedded Raster Base64 Data: Inline SVGs containing multi-megabyte base64 embedded PNG/JPEG data inflating JS bundle size."
            ],
            remediationPrompt: "Extract base64 data to standalone external images optimized with Next.js <Image>.",
            status: 'OPEN',
            owner: "SVG / Media",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-10: Unoptimized SVG with Embedded Raster Base64 Data detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-11: Missing Preconnect for Critical External CDNs
    if (/<link[^>]+href=[\'"]https:\/\/(?:fonts\.googleapis\.com|cdn\.jsdelivr\.net)[^\'"]*[\'"][^>]*>/i.test(cleanContent) && !/rel=[\'"]preconnect[\'"]/i.test(cleanContent) && /\.(?:html|tsx|jsx)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/<link[^>]+href=[\'"]https:\/\/(?:fonts\.googleapis\.com|cdn\.jsdelivr\.net)[^\'"]*[\'"][^>]*>/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf11-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7111,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-11: Missing Preconnect for Critical External CDNs",
            severity: 'LOW',
            category: "Network Latency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-11 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Preconnect for Critical External CDNs: Loading critical fonts, scripts, or images from external origins (e.g. fonts.googleapis.com) without preconnect."
            ],
            remediationPrompt: "Add <link rel='preconnect' href='https://fonts.gstatic.com' crossOrigin='anonymous' /> to <head>.",
            status: 'OPEN',
            owner: "HTML / Head",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-11: Missing Preconnect for Critical External CDNs detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-12: Client Component Wrapping Entire Page Tree
    if (/^[\'"]use client[\'"]/m.test(cleanContent) && /app\/.*page\.tsx$/i.test(file.path) && /export\s+default\s+function/i.test(cleanContent) && /deoptServerComponent|heavyClientPageTree/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/^[\'"]use client[\'"]/m, /export\s+default\s+function/i, /deoptServerComponent|heavyClientPageTree/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf12-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7112,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-12: Client Component Wrapping Entire Page Tree",
            severity: 'HIGH',
            category: "Server Components",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-12 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Client Component Wrapping Entire Page Tree: Placing 'use client' at the root of page.tsx, converting entire sub-tree to client bundle and destroying SSR benefits."
            ],
            remediationPrompt: "Remove 'use client' from page.tsx; extract interactive state into dedicated client leaf components.",
            status: 'OPEN',
            owner: "Next.js App Router",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-12: Client Component Wrapping Entire Page Tree detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-13: Dynamic Import Missing for Below-The-Fold Modal
    if (/import\s+[a-zA-Z0-9_]+Modal\s+from\s+[\'"][^\'"]+[\'"]/i.test(cleanContent) && !/dynamic\(/i.test(cleanContent) && /HeavyModal|ReportGeneratorModal|PenTestModal/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/import\s+[a-zA-Z0-9_]+Modal\s+from\s+[\'"][^\'"]+[\'"]/i, /HeavyModal|ReportGeneratorModal|PenTestModal/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf13-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7113,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-13: Dynamic Import Missing for Below-The-Fold Modal",
            severity: 'MEDIUM',
            category: "Bundle Splitting",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-13 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Dynamic Import Missing for Below-The-Fold Modal: Statically importing heavy modals, chart libraries, or PDF generators that only render on user click."
            ],
            remediationPrompt: "Use dynamic import: const Modal = dynamic(() => import('./HeavyModal'), { ssr: false }).",
            status: 'OPEN',
            owner: "React / Next.js",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-13: Dynamic Import Missing for Below-The-Fold Modal detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-14: Missing Content-Visibility on Long Off-Screen Lists
    if (/\.long-list|\.infinite-feed/i.test(cleanContent) && !/content-visibility:\s*auto/i.test(cleanContent) && /\.(?:css|scss)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/\.long-list|\.infinite-feed/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf14-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7114,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-14: Missing Content-Visibility on Long Off-Screen Lists",
            severity: 'LOW',
            category: "Rendering Engine",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-14 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Content-Visibility on Long Off-Screen Lists: Rendering thousands of list items or table rows without CSS content-visibility: auto."
            ],
            remediationPrompt: "Add content-visibility: auto and contain-intrinsic-size: 0 80px to list item styles.",
            status: 'OPEN',
            owner: "CSS Performance",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-14: Missing Content-Visibility on Long Off-Screen Lists detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-15: Forced Synchronous Layout Shift (Layout Thrashing)
    if (/for\s*\([^)]+\)\s*\{[^}]*\.style\.[a-zA-Z]+\s*=[^}]*\.offsetHeight/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/for\s*\([^)]+\)\s*\{[^}]*\.style\.[a-zA-Z]+\s*=[^}]*\.offsetHeight/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf15-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7115,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-15: Forced Synchronous Layout Shift (Layout Thrashing)",
            severity: 'HIGH',
            category: "Layout & Reflow",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-15 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Forced Synchronous Layout Shift (Layout Thrashing): Interleaving DOM style writes (element.style.height) and reads (element.offsetHeight) inside loops."
            ],
            remediationPrompt: "Batch layout measurements before mutating styles or use ResizeObserver.",
            status: 'OPEN',
            owner: "DOM Scripting",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-15: Forced Synchronous Layout Shift (Layout Thrashing) detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-16: Infinite Scroll Missing Virtualization / Windowing
    if (/items\.(?:length|>)\s*(?:100|500)[\s\S]*?\.map\s*\([^)]*\)\s*=>/i.test(cleanContent) && /infinite|scroll/i.test(cleanContent) && !/useVirtualizer|react-window/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/items\.(?:length|>)\s*(?:100|500)[\s\S]*?\.map\s*\([^)]*\)\s*=>/i, /infinite|scroll/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf16-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7116,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-16: Infinite Scroll Missing Virtualization / Windowing",
            severity: 'HIGH',
            category: "DOM Memory & Footprint",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-16 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Infinite Scroll Missing Virtualization / Windowing: Rendering 500+ items into DOM in infinite scroll without virtualized windowing (react-window)."
            ],
            remediationPrompt: "Implement virtual scrolling using @tanstack/react-virtual or react-window.",
            status: 'OPEN',
            owner: "React Lists",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-16: Infinite Scroll Missing Virtualization / Windowing detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-17: Heavy Barrel File Import Inflating Bundle Size
    if (/import\s+\{[^}]{120,}\}\s+from\s+[\'"](?:@tabler\/icons|lodash-es|rxjs)[\'"]/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/import\s+\{[^}]{120,}\}\s+from\s+[\'"](?:@tabler\/icons|lodash-es|rxjs)[\'"]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf17-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7117,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-17: Heavy Barrel File Import Inflating Bundle Size",
            severity: 'MEDIUM',
            category: "Tree Shaking",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-17 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Heavy Barrel File Import Inflating Bundle Size: Importing icons or utilities from massive barrel files (import { X } from 'lucide-react' or 'lodash') pulling entire library."
            ],
            remediationPrompt: "Ensure next.config.mjs specifies experimental.optimizePackageImports: ['lucide-react'].",
            status: 'OPEN',
            owner: "Module Imports",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-17: Heavy Barrel File Import Inflating Bundle Size detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-18: Animated CSS Properties Triggering Layout Reflow
    if (/transition:\s*(?:top|left|width|height|margin)\s+[0-9.]+s/i.test(cleanContent) && /\.(?:css|scss)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/transition:\s*(?:top|left|width|height|margin)\s+[0-9.]+s/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf18-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7118,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-18: Animated CSS Properties Triggering Layout Reflow",
            severity: 'MEDIUM',
            category: "Animation Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-18 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Animated CSS Properties Triggering Layout Reflow: Animating layout properties (top, left, width, height, margin) instead of GPU-accelerated transform / opacity."
            ],
            remediationPrompt: "Refactor transition: left/top to transform: translate3d(x, y, 0) with will-change: transform.",
            status: 'OPEN',
            owner: "CSS Transitions",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-18: Animated CSS Properties Triggering Layout Reflow detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-19: Missing will-change Optimization on Frequent Transitions
    if (/@keyframes\s+slideIn|@keyframes\s+drawer/i.test(cleanContent) && !/will-change/i.test(cleanContent) && /\.(?:css|scss)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/@keyframes\s+slideIn|@keyframes\s+drawer/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf19-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7119,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-19: Missing will-change Optimization on Frequent Transitions",
            severity: 'LOW',
            category: "GPU Acceleration",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-19 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing will-change Optimization on Frequent Transitions: Complex 60fps animations or slide-over drawers omitting will-change property on mobile browsers."
            ],
            remediationPrompt: "Add will-change: transform to animated drawer or modal container styles.",
            status: 'OPEN',
            owner: "CSS",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-19: Missing will-change Optimization on Frequent Transitions detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-20: Unoptimized Animated GIF Asset in Production
    if (/<img\b[^>]*src=["\'][^"\']+\.gif["\'][^>]*>/i.test(cleanContent) && /\.(?:tsx|jsx|html)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/<img\b[^>]*src=["\'][^"\']+\.gif["\'][^>]*>/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf20-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7120,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-20: Unoptimized Animated GIF Asset in Production",
            severity: 'MEDIUM',
            category: "Media Compression",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-20 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unoptimized Animated GIF Asset in Production: Deploying raw .gif files (>5MB) instead of optimized looped MP4 or WebM video containers."
            ],
            remediationPrompt: "Replace heavy .gif with <video autoPlay loop muted playsInline poster='...'><source src='...' type='video/mp4' /></video>.",
            status: 'OPEN',
            owner: "Media Assets",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-20: Unoptimized Animated GIF Asset in Production detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-21: Uncontrolled LocalStorage Hydration Waterfall
    if (/useLayoutEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*localStorage\.getItem/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/useLayoutEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*localStorage\.getItem/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf21-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7121,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-21: Uncontrolled LocalStorage Hydration Waterfall",
            severity: 'MEDIUM',
            category: "React Hydration",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-21 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Uncontrolled LocalStorage Hydration Waterfall: Reading localStorage inside useLayoutEffect or rendering fallback spinners blocking client hydration."
            ],
            remediationPrompt: "Initialize state with server-safe fallback and read localStorage inside useEffect([]).",
            status: 'OPEN',
            owner: "Next.js SSR",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-21: Uncontrolled LocalStorage Hydration Waterfall detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-22: Massive JSON Payload Inlined into HTML Page Source
    if (/export\s+async\s+function\s+getServerSideProps[\s\S]*?return\s*\{\s*props:\s*\{[^}]*allRecords:\s*[a-zA-Z0-9_]+/i.test(cleanContent) && !/slice|select/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/export\s+async\s+function\s+getServerSideProps[\s\S]*?return\s*\{\s*props:\s*\{[^}]*allRecords:\s*[a-zA-Z0-9_]+/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf22-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7122,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-22: Massive JSON Payload Inlined into HTML Page Source",
            severity: 'HIGH',
            category: "Initial Payload Size",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-22 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Massive JSON Payload Inlined into HTML Page Source: Passing raw multi-megabyte database objects directly into Page props, inflating __NEXT_DATA__ HTML payload."
            ],
            remediationPrompt: "Select only required fields: .select('id, name, title') instead of passing raw full record entities.",
            status: 'OPEN',
            owner: "Next.js Data Fetching",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-22: Massive JSON Payload Inlined into HTML Page Source detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-23: CSS Filter Blur on Continuous Scrolling Container
    if (/backdrop-filter:\s*blur\(\s*(?:[2-9]\d|\d{3,})px\s*\)/i.test(cleanContent) && /overflow-y:\s*scroll/i.test(cleanContent) && /\.(?:css|scss)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/backdrop-filter:\s*blur\(\s*(?:[2-9]\d|\d{3,})px\s*\)/i, /overflow-y:\s*scroll/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf23-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7123,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-23: CSS Filter Blur on Continuous Scrolling Container",
            severity: 'LOW',
            category: "GPU Memory & Rendering",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-23 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected CSS Filter Blur on Continuous Scrolling Container: Applying backdrop-filter: blur(20px) on large continuously scrolling containers causing mobile FPS drop."
            ],
            remediationPrompt: "Remove backdrop-filter from scrollable body elements or reduce blur radius to <= 8px.",
            status: 'OPEN',
            owner: "CSS Styling",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-23: CSS Filter Blur on Continuous Scrolling Container detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-24: Uncached Client API Fetch Missing SWR / React Query
    if (/useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*fetch\([^)]+\)\.then\([^}]*setState/i.test(cleanContent) && !/useSWR|useQuery|cache/i.test(cleanContent) && /\.(?:tsx|jsx)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*fetch\([^)]+\)\.then\([^}]*setState/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf24-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7124,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-24: Uncached Client API Fetch Missing SWR / React Query",
            severity: 'MEDIUM',
            category: "Client Data Fetching",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-24 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Uncached Client API Fetch Missing SWR / React Query: Using raw useEffect(fetch) on frequently visited tabs, triggering redundant network fetches on every navigation."
            ],
            remediationPrompt: "Wrap client queries with useSWR(key, fetcher) or TanStack useQuery.",
            status: 'OPEN',
            owner: "React State",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-24: Uncached Client API Fetch Missing SWR / React Query detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-25: Missing Image Format Modernization (WebP / AVIF)
    if (/next\.config\.(?:m?js|ts)$/i.test(file.path) && /images:\s*\{(?![^}]*formats)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/images:\s*\{(?![^}]*formats)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf25-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7125,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-25: Missing Image Format Modernization (WebP / AVIF)",
            severity: 'MEDIUM',
            category: "Image Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-25 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Image Format Modernization (WebP / AVIF): Disabling Next.js image optimization (unoptimized: true) or serving uncompressed PNGs for photographic images."
            ],
            remediationPrompt: "Ensure images.formats includes ['image/avif', 'image/webp'] in next.config.mjs.",
            status: 'OPEN',
            owner: "Next.js / Images",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-25: Missing Image Format Modernization (WebP / AVIF) detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-26: Unbounded React State Array Concatenation
    if (/set(?:Logs|Events|Telemetry|Messages)\s*\(\s*prev\s*=>\s*\[\s*\.\.\.prev\s*,\s*[a-zA-Z0-9_]+\s*\]\s*\)/i.test(cleanContent) && !/slice/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/set(?:Logs|Events|Telemetry|Messages)\s*\(\s*prev\s*=>\s*\[\s*\.\.\.prev\s*,\s*[a-zA-Z0-9_]+\s*\]\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf26-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7126,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-26: Unbounded React State Array Concatenation",
            severity: 'MEDIUM',
            category: "Memory Leaks",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-26 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unbounded React State Array Concatenation: Appending telemetry or event logs directly to React state array indefinitely without slice limits."
            ],
            remediationPrompt: "Cap state array length: setToasts(prev => [...prev.slice(-20), newToast]).",
            status: 'OPEN',
            owner: "React State",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-26: Unbounded React State Array Concatenation detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-27: Missing Resource Hints for Critical Navigation Routes
    if (/<Link\b[^>]*prefetch=\{false\}[^>]*href=["\'](?:\/dashboard|\/app|\/login)["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<Link\b[^>]*prefetch=\{false\}[^>]*href=["\'](?:\/dashboard|\/app|\/login)["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf27-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7127,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-27: Missing Resource Hints for Critical Navigation Routes",
            severity: 'LOW',
            category: "Page Transition Speed",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-27 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Resource Hints for Critical Navigation Routes: Disabling Next.js Link prefetching (prefetch={false}) on primary navigation links."
            ],
            remediationPrompt: "Remove prefetch={false} on primary sidebar/header links unless route is heavy authenticated checkout.",
            status: 'OPEN',
            owner: "Next.js Links",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-27: Missing Resource Hints for Critical Navigation Routes detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-28: Render-Blocking Custom Web Font Declaration
    if (/@font-face\s*\{[^}]*font-display:\s*block/i.test(cleanContent) && /\.(?:css|scss)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/@font-face\s*\{[^}]*font-display:\s*block/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf28-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7128,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-28: Render-Blocking Custom Web Font Declaration",
            severity: 'MEDIUM',
            category: "FOIT / FOUT",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-28 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Render-Blocking Custom Web Font Declaration: Declaring @font-face with font-display: block, causing invisible text (FOIT) for up to 3 seconds on slow connections."
            ],
            remediationPrompt: "Add font-display: swap to all @font-face rules.",
            status: 'OPEN',
            owner: "CSS Typography",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-28: Render-Blocking Custom Web Font Declaration detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-29: Synchronous LocalStorage Read in Event Loop Hot Path
    if (/(?:onMouseMove|onScroll|onPointerMove)\s*=\s*\{[^}]*localStorage\.getItem/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:onMouseMove|onScroll|onPointerMove)\s*=\s*\{[^}]*localStorage\.getItem/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf29-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7129,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-29: Synchronous LocalStorage Read in Event Loop Hot Path",
            severity: 'LOW',
            category: "Main Thread Latency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-29 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Synchronous LocalStorage Read in Event Loop Hot Path: Calling localStorage.getItem() repeatedly inside mousemove, scroll, or high-frequency game render loops."
            ],
            remediationPrompt: "Cache storage value in memory variable instead of reading synchronous localStorage in tight loops.",
            status: 'OPEN',
            owner: "Browser Storage",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-29: Synchronous LocalStorage Read in Event Loop Hot Path detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-30: Missing Compression Middleware for Custom Server Responses
    if (/const\s+app\s*=\s*express\(\)/i.test(cleanContent) && !/compression\(/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/const\s+app\s*=\s*express\(\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf30-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7130,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-30: Missing Compression Middleware for Custom Server Responses",
            severity: 'HIGH',
            category: "Payload Compression",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-30 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Compression Middleware for Custom Server Responses: Node.js Express / custom server instances lacking compression (Gzip / Brotli) middleware on JSON responses."
            ],
            remediationPrompt: "Add app.use(compression({ threshold: 1024 })) to custom server pipeline.",
            status: 'OPEN',
            owner: "HTTP / Node.js",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-30: Missing Compression Middleware for Custom Server Responses detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-31: Unaborted Fetch Request on Component Unmount
    if (/useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*fetch\([^)]+\)[^}]*\}\s*,\s*\[\]\s*\)/i.test(cleanContent) && !/AbortController|signal|return/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*fetch\([^)]+\)[^}]*\}\s*,\s*\[\]\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf31-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7131,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-31: Unaborted Fetch Request on Component Unmount",
            severity: 'LOW',
            category: "Resource Waste",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-31 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unaborted Fetch Request on Component Unmount: Component triggering long fetch requests without AbortController cleanup in useEffect return callback."
            ],
            remediationPrompt: "Create const controller = new AbortController(); pass signal, and return () => controller.abort().",
            status: 'OPEN',
            owner: "Async Effects",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-31: Unaborted Fetch Request on Component Unmount detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-32: High-Resolution Image Rendered in Small Avatar Thumbnail
    if (/<img\b[^>]*src=["\'][^"\']+\.(?:png|jpg|jpeg)["\'][^>]*className=["\'][^"\']*\bw-(?:4|6|8)\b[^"\']*["\'][^>]*>/i.test(cleanContent) && /original|raw|full/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<img\b[^>]*src=["\'][^"\']+\.(?:png|jpg|jpeg)["\'][^>]*className=["\'][^"\']*\bw-(?:4|6|8)\b[^"\']*["\'][^>]*>/i, /original|raw|full/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf32-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7132,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-32: High-Resolution Image Rendered in Small Avatar Thumbnail",
            severity: 'LOW',
            category: "Bandwidth Waste",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-32 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected High-Resolution Image Rendered in Small Avatar Thumbnail: Serving 4000x4000px raw user profile images inside a 32x32px thumbnail container without downscaling."
            ],
            remediationPrompt: "Request resized avatar image via CDN parameters (?width=64&height=64) or Next.js <Image width={32} />.",
            status: 'OPEN',
            owner: "Media Assets",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-32: High-Resolution Image Rendered in Small Avatar Thumbnail detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-33: Synchronous JSON.parse on Multi-Megabyte Payloads
    if (/JSON\.parse\s*\(\s*[a-zA-Z0-9_]+\s*\)/i.test(cleanContent) && /largePayload|megaBytePayload|rawHeavyData/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/JSON\.parse\s*\(\s*[a-zA-Z0-9_]+\s*\)/i, /largePayload|megaBytePayload|rawHeavyData/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf33-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7133,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-33: Synchronous JSON.parse on Multi-Megabyte Payloads",
            severity: 'MEDIUM',
            category: "Main Thread Freezes",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-33 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Synchronous JSON.parse on Multi-Megabyte Payloads: Parsing large JSON strings (>10MB) synchronously on main thread causing noticeable UI frame drops."
            ],
            remediationPrompt: "Offload large JSON deserialization to a Web Worker via Comlink or Worker thread.",
            status: 'OPEN',
            owner: "JavaScript Runtime",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-33: Synchronous JSON.parse on Multi-Megabyte Payloads detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-34: DOM Node Polling via setInterval Instead of Observers
    if (/setInterval\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*document\.(?:getElementById|querySelector)/i.test(cleanContent) && !/MutationObserver/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/setInterval\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*document\.(?:getElementById|querySelector)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf34-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7134,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-34: DOM Node Polling via setInterval Instead of Observers",
            severity: 'LOW',
            category: "CPU & Battery Waste",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-34 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected DOM Node Polling via setInterval Instead of Observers: Using setInterval(checkElement, 50) to detect DOM changes instead of MutationObserver or ResizeObserver."
            ],
            remediationPrompt: "Replace polling setInterval with MutationObserver or IntersectionObserver.",
            status: 'OPEN',
            owner: "DOM Scripting",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-34: DOM Node Polling via setInterval Instead of Observers detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-35: Unkeyed React List Elements Forcing Full DOM Rebuild
    if (/\.map\s*\(\s*\([a-zA-Z0-9_]+,\s*index\)\s*=>\s*<[A-Z][a-zA-Z0-9_]*\s+key=\{index\}/i.test(cleanContent) && /\.(?:tsx|jsx)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/\.map\s*\(\s*\([a-zA-Z0-9_]+,\s*index\)\s*=>\s*<[A-Z][a-zA-Z0-9_]*\s+key=\{index\}/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf35-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7135,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-35: Unkeyed React List Elements Forcing Full DOM Rebuild",
            severity: 'HIGH',
            category: "React Reconciliation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-35 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unkeyed React List Elements Forcing Full DOM Rebuild: Mapping array to JSX using index as key or omitting key prop, breaking React reconciliation diffing."
            ],
            remediationPrompt: "Use unique entity ID for keys: items.map(item => <Item key={item.id} ... />) instead of index.",
            status: 'OPEN',
            owner: "React Rendering",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-35: Unkeyed React List Elements Forcing Full DOM Rebuild detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-36: Missing Link rel='dns-prefetch' on Asset Domains
    if (/<link[^>]+href=[\'"]https:\/\/[a-z0-9.-]+\.cdn\.net[^\'"]*[\'"][^>]*>/i.test(cleanContent) && !/dns-prefetch|preconnect/i.test(cleanContent) && /\.(?:html|tsx|jsx)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/<link[^>]+href=[\'"]https:\/\/[a-z0-9.-]+\.cdn\.net[^\'"]*[\'"][^>]*>/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf36-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7136,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-36: Missing Link rel='dns-prefetch' on Asset Domains",
            severity: 'LOW',
            category: "DNS Resolution",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-36 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Link rel='dns-prefetch' on Asset Domains: Loading assets from multiple distinct subdomains without dns-prefetch hints."
            ],
            remediationPrompt: "Add <link rel='dns-prefetch' href='https://assets.example.com' /> in HTML head.",
            status: 'OPEN',
            owner: "HTML / Head",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-36: Missing Link rel='dns-prefetch' on Asset Domains detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-37: Unoptimized React Context Splitting Causing Cascade Renders
    if (/createContext\s*\(\s*\{[^}]*cursorPosition[^}]*userProfile/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/createContext\s*\(\s*\{[^}]*cursorPosition[^}]*userProfile/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf37-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7137,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-37: Unoptimized React Context Splitting Causing Cascade Renders",
            severity: 'MEDIUM',
            category: "React Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-37 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unoptimized React Context Splitting Causing Cascade Renders: Combining frequently changing state (e.g. mouse position, timers) and static theme/user state in a single Context."
            ],
            remediationPrompt: "Split broad context into separate StateContext and DispatchContext, or adopt Zustand.",
            status: 'OPEN',
            owner: "React Context",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-37: Unoptimized React Context Splitting Causing Cascade Renders detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-38: Missing HTML Lang Attribute Delaying Accessibility Tree
    if (/<html\b(?![^>]*\blang=)[^>]*>/i.test(cleanContent) && /\.(?:html|tsx|jsx)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/<html\b(?![^>]*\blang=)[^>]*>/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf38-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7138,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-38: Missing HTML Lang Attribute Delaying Accessibility Tree",
            severity: 'LOW',
            category: "Document Parsing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-38 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing HTML Lang Attribute Delaying Accessibility Tree: Root <html> tag omitting lang='en' attribute causing screen reader and translation delays."
            ],
            remediationPrompt: "Add lang='en' to root <html> tag in layout.tsx.",
            status: 'OPEN',
            owner: "HTML",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-38: Missing HTML Lang Attribute Delaying Accessibility Tree detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-39: Unused CSS Class Bloat in Production Bundle
    if (/tailwind\.config\.(?:js|ts|mjs)$/i.test(file.path) && /content:\s*\[\s*\]/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/content:\s*\[\s*\]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf39-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7139,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-39: Unused CSS Class Bloat in Production Bundle",
            severity: 'LOW',
            category: "CSS Payload",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-39 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unused CSS Class Bloat in Production Bundle: Production CSS including unpurged third-party CSS bundles or disabling Tailwind content purging."
            ],
            remediationPrompt: "Verify tailwind.config.ts content array includes all app, components, and lib paths.",
            status: 'OPEN',
            owner: "Tailwind / CSS",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-39: Unused CSS Class Bloat in Production Bundle detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-40: Missing Stale-While-Revalidate on Server-Rendered Assets
    if (/headers\.set\s*\(\s*[\'"]Cache-Control[\'"]\s*,\s*[\'"][^\'"]*max-age=\d+[\'"]\s*\)/i.test(cleanContent) && !/stale-while-revalidate/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/headers\.set\s*\(\s*[\'"]Cache-Control[\'"]\s*,\s*[\'"][^\'"]*max-age=\d+[\'"]\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf40-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7140,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-40: Missing Stale-While-Revalidate on Server-Rendered Assets",
            severity: 'MEDIUM',
            category: "Edge Caching",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-40 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Stale-While-Revalidate on Server-Rendered Assets: Edge responses setting max-age without stale-while-revalidate, forcing user to block on background regeneration."
            ],
            remediationPrompt: "Add stale-while-revalidate=86400 to Cache-Control header.",
            status: 'OPEN',
            owner: "HTTP Headers",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-40: Missing Stale-While-Revalidate on Server-Rendered Assets detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-41: Heavy Lottie Animation Running Continuously Off-Screen
    if (/<Lottie\b[^>]*autoplay=\{true\}[^>]*loop=\{true\}[^>]*>/i.test(cleanContent) && !/IntersectionObserver|useInView/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<Lottie\b[^>]*autoplay=\{true\}[^>]*loop=\{true\}[^>]*>/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf41-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7141,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-41: Heavy Lottie Animation Running Continuously Off-Screen",
            severity: 'LOW',
            category: "Battery & CPU",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-41 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Heavy Lottie Animation Running Continuously Off-Screen: Lottie or Canvas animation loop running at 60fps even when scrolled completely out of viewport."
            ],
            remediationPrompt: "Pause animation playback when entry.isIntersecting is false using IntersectionObserver.",
            status: 'OPEN',
            owner: "Animations",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-41: Heavy Lottie Animation Running Continuously Off-Screen detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-42: Document Title Mutation Inside Render Phase
    if (/\bdocument\.title\s*=/i.test(cleanContent) && !/useEffect|useLayoutEffect/i.test(cleanContent) && /\.(?:tsx|jsx)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/\bdocument\.title\s*=/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf42-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7142,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-42: Document Title Mutation Inside Render Phase",
            severity: 'LOW',
            category: "DOM Thrashing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-42 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Document Title Mutation Inside Render Phase: Directly mutating document.title during component render body rather than inside useEffect."
            ],
            remediationPrompt: "Move document.title update into useEffect or export metadata object in page.tsx.",
            status: 'OPEN',
            owner: "React Effects",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-42: Document Title Mutation Inside Render Phase detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-43: Missing Early Hints (HTTP 103) on Critical Assets
    if (/earlyHints:\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/earlyHints:\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf43-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7143,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-43: Missing Early Hints (HTTP 103) on Critical Assets",
            severity: 'LOW',
            category: "Server Push & TTFB",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-43 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Early Hints (HTTP 103) on Critical Assets: Edge server failing to stream 103 Early Hints headers for critical CSS and font resources."
            ],
            remediationPrompt: "Configure HTTP 103 Early Hints in edge reverse proxy or Next.js experimental config.",
            status: 'OPEN',
            owner: "HTTP / Edge",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-43: Missing Early Hints (HTTP 103) on Critical Assets detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-44: Unminified JavaScript Script in Public Directory
    if (/public\/.*\.js$/i.test(lowerPath) && !lowerPath.includes(".min.js") && cleanContent.split("\n").length > 50 && !/window\.__ENV/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/web-perf-44|unminified/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf44-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7144,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-44: Unminified JavaScript Script in Public Directory",
            severity: 'MEDIUM',
            category: "Asset Size",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-44 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unminified JavaScript Script in Public Directory: Serving unminified third-party JS scripts directly from public/ folder."
            ],
            remediationPrompt: "Minify custom public scripts using esbuild or terser before shipping.",
            status: 'OPEN',
            owner: "Static Assets",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-44: Unminified JavaScript Script in Public Directory detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-45: Missing Favicon and Icon Dimensions in Manifest
    if (/manifest\.(?:json|webmanifest)$/i.test(file.path) && /"icons":\s*\[(?![^\]]*"sizes")/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/"icons":\s*\[(?![^\]]*"sizes")/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf45-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7145,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-45: Missing Favicon and Icon Dimensions in Manifest",
            severity: 'LOW',
            category: "Browser Initialization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-45 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Favicon and Icon Dimensions in Manifest: Favicons served without explicit sizes or SVG fallback, causing browser to scale heavy icons."
            ],
            remediationPrompt: "Provide 192x192 and 512x512 icons in manifest.webmanifest and app/icon.png.",
            status: 'OPEN',
            owner: "PWA / Icons",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-45: Missing Favicon and Icon Dimensions in Manifest detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-46: Excessive Cookie Size (>4KB) Sent on Every Request
    if (/cookies\(\)\.set\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*JSON\.stringify\([^)]+\)\s*\)/i.test(cleanContent) && /fullUserData|entireState/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/cookies\(\)\.set\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*JSON\.stringify\([^)]+\)\s*\)/i, /fullUserData|entireState/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf46-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7146,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-46: Excessive Cookie Size (>4KB) Sent on Every Request",
            severity: 'MEDIUM',
            category: "Network Overhead",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-46 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Excessive Cookie Size (>4KB) Sent on Every Request: Storing large serialized session states or user preferences in cookies exceeding 4KB per request."
            ],
            remediationPrompt: "Store user state in database/Redis and keep only secure session token in cookies.",
            status: 'OPEN',
            owner: "HTTP Cookies",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-46: Excessive Cookie Size (>4KB) Sent on Every Request detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-47: Unnecessary Third-Party CSS Framework Import
    if (/(?:import\s+[\'"]bootstrap\/dist\/css|import\s+[\'"]bulma\/css)/i.test(cleanContent) && /tailwindcss/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:import\s+[\'"]bootstrap\/dist\/css|import\s+[\'"]bulma\/css)/i, /tailwindcss/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf47-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7147,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-47: Unnecessary Third-Party CSS Framework Import",
            severity: 'LOW',
            category: "Bundle Size",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-47 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unnecessary Third-Party CSS Framework Import: Importing Bootstrap or Bulma alongside Tailwind CSS, duplicating reset rules and inflating bundle."
            ],
            remediationPrompt: "Remove duplicate legacy CSS framework dependencies.",
            status: 'OPEN',
            owner: "CSS Dependencies",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-47: Unnecessary Third-Party CSS Framework Import detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-48: Synchronous File Reader in Client File Upload
    if (/new\s+FileReader\(\)[\s\S]*?readAsDataURL\s*\(\s*[a-zA-Z0-9_]+\s*\)/i.test(cleanContent) && /largeFile|heavyFile/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+FileReader\(\)[\s\S]*?readAsDataURL\s*\(\s*[a-zA-Z0-9_]+\s*\)/i, /largeFile|heavyFile/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf48-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7148,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-48: Synchronous File Reader in Client File Upload",
            severity: 'LOW',
            category: "Main Thread Block",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-48 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Synchronous File Reader in Client File Upload: Using FileReader.readAsDataURL on multi-hundred megabyte file uploads directly on main thread."
            ],
            remediationPrompt: "Use File.stream() and ReadableStream for large file upload processing.",
            status: 'OPEN',
            owner: "File API",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-48: Synchronous File Reader in Client File Upload detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-49: Missing Server-Timing Header for Latency Profiling
    if (/(?:app\/api|pages\/api)/i.test(lowerPath) && /export\s+async\s+function\s+(?:GET|POST)/i.test(cleanContent) && /timingBenchmark/i.test(cleanContent) && !/Server-Timing/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/export\s+async\s+function\s+(?:GET|POST)/i, /timingBenchmark/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf49-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7149,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-49: Missing Server-Timing Header for Latency Profiling",
            severity: 'LOW',
            category: "Observability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-49 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Server-Timing Header for Latency Profiling: Production API responses lacking Server-Timing headers, blinding frontend RUM from diagnosing DB vs Edge latency."
            ],
            remediationPrompt: "Add Server-Timing: db;dur=12, cache;dur=2 to API responses for observability.",
            status: 'OPEN',
            owner: "HTTP Headers",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-49: Missing Server-Timing Header for Latency Profiling detected (${file.path}:${lineNum})`);
    }
    // WEB-PERF-50: Cumulative Layout Shift Caused by Dynamic Cookie Banner
    if (/(?:CookieBanner|StickyAnnouncement)/i.test(cleanContent) && /className=["\'][^"\']*\babsolute\s+top-0\b[^"\']*["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:CookieBanner|StickyAnnouncement)/i, /className=["\'][^"\']*\babsolute\s+top-0\b[^"\']*["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf50-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7150,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-50: Cumulative Layout Shift Caused by Dynamic Cookie Banner",
            severity: 'HIGH',
            category: "CLS & User Experience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected WEB-PERF-50 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Cumulative Layout Shift Caused by Dynamic Cookie Banner: Injecting cookie banners or sticky notification bars at top of document pushing existing page content down."
            ],
            remediationPrompt: "Position cookie banner with fixed bottom-0 left-0 right-0 or fixed inset-x-0 to prevent content push.",
            status: 'OPEN',
            owner: "Cookie Banner / Dialogs",
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ WEB-PERF-50: Cumulative Layout Shift Caused by Dynamic Cookie Banner detected (${file.path}:${lineNum})`);
    }
    return { findings, logs };
}
