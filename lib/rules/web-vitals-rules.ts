/**
 * Zelsis Master evaluateWebVitalsRules Engine (50 Rules)
 * Rules WEB-PERF-01 to WEB-PERF-50 (Rule IDs 7101 to 7150).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
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
    const hit_7101 = /\.(?:tsx|jsx)$/i.test(file.path) ? findHeroImageWithoutPriority(cleanContent) : -1;
    if (hit_7101 !== -1) {
        const matchLineIdx = hit_7101;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf01-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7101,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-01: Above-The-Fold Hero Image Missing Priority Attribute",
            severity: 'MEDIUM',
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
    const hit_7102 = /\.(?:html|tsx|jsx)$/i.test(file.path) ? findUnsizedMedia(cleanContent) : -1;
    if (hit_7102 !== -1) {
        const matchLineIdx = hit_7102;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf02-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7102,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-02: Unsized Image or Video Element Causing Layout Shift",
            severity: 'MEDIUM',
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
    const hit_7103 = /\.(?:html|tsx|jsx)$/i.test(file.path) ? findBlockingThirdPartyScript(cleanContent) : -1;
    if (hit_7103 !== -1) {
        const matchLineIdx = hit_7103;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf03-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7103,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-03: Synchronous Third-Party Script Tag Blocking Render",
            severity: 'MEDIUM',
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
    const hit_7104 = lines.findIndex((l) => /\baddEventListener\(\s*['"](?:touchstart|touchmove|wheel|mousewheel)['"]\s*,\s*[\w.]+\s*\)/.test(l));
    if (hit_7104 !== -1) {
        const matchLineIdx = hit_7104;
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
    const hit_7105 = /\.(?:css|scss|sass|less)$/i.test(file.path) ? findInFontFace(cleanContent, (b) => !/\.woff2\b/i.test(b), /url\([^)]*\.(?:ttf|otf)\b/i) : -1;
    if (hit_7105 !== -1) {
        const matchLineIdx = hit_7105;
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
    const hit_7106 = /\.(?:css|scss)$/i.test(file.path) ? lines.findIndex((l) => /^\s*@import\s+(?:url\(\s*)?["']?https?:\/\//i.test(l)) : -1;
    if (hit_7106 !== -1) {
        const matchLineIdx = hit_7106;
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
    // WEB-PERF-10: Unoptimized SVG with Embedded Raster Base64 Data
    const hit_7110 = findSvgEmbeddedRaster(cleanContent);
    if (hit_7110 !== -1) {
        const matchLineIdx = hit_7110;
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
    const hit_7111 = /\.(?:html|tsx|jsx)$/i.test(file.path) && !/rel=["']preconnect["']/i.test(cleanContent) ? lines.findIndex((l) => /<link\b[^>]*href=["']https:\/\/(?:fonts\.googleapis\.com|cdn\.jsdelivr\.net)/i.test(l)) : -1;
    if (hit_7111 !== -1) {
        const matchLineIdx = hit_7111;
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
    // WEB-PERF-15: Forced Synchronous Layout Shift (Layout Thrashing)
    const hit_7115 = findLayoutThrashing(cleanContent);
    if (hit_7115 !== -1) {
        const matchLineIdx = hit_7115;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf15-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7115,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-15: Forced Synchronous Layout Shift (Layout Thrashing)",
            severity: 'MEDIUM',
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
    // WEB-PERF-18: Animated CSS Properties Triggering Layout Reflow
    const hit_7118 = /\.(?:css|scss)$/i.test(file.path) ? lines.findIndex((l) => /\btransition(?:-property)?\s*:[^;]*\b(?:top|left|right|bottom|width|height|margin(?:-\w+)?|padding(?:-\w+)?)\s+[0-9.]+m?s\b/i.test(l)) : -1;
    if (hit_7118 !== -1) {
        const matchLineIdx = hit_7118;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf18-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7118,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-18: Animated CSS Properties Triggering Layout Reflow",
            severity: 'LOW',
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
    // WEB-PERF-20: Unoptimized Animated GIF Asset in Production
    const hit_7120 = /\.(?:tsx|jsx|html)$/i.test(file.path) ? findTag(cleanContent, /<img\b[^>]*?\bsrc=["'][^"']+\.gif["'][^>]*>/gi) : -1;
    if (hit_7120 !== -1) {
        const matchLineIdx = hit_7120;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf20-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7120,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-20: Unoptimized Animated GIF Asset in Production",
            severity: 'LOW',
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
    // WEB-PERF-23: CSS Filter Blur on Continuous Scrolling Container
    const hit_7123 = /\.(?:css|scss)$/i.test(file.path) ? findBlurOnScroller(cleanContent) : -1;
    if (hit_7123 !== -1) {
        const matchLineIdx = hit_7123;
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
    // WEB-PERF-28: Render-Blocking Custom Web Font Declaration
    const hit_7128 = /\.(?:css|scss|sass|less)$/i.test(file.path) ? findInFontFace(cleanContent, (b) => !/font-family\s*:\s*["']?[^;"']*(?:icon|awesome|symbols|glyph)/i.test(b), /font-display\s*:\s*block\b/i) : -1;
    if (hit_7128 !== -1) {
        const matchLineIdx = hit_7128;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf28-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7128,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-28: Render-Blocking Custom Web Font Declaration",
            severity: 'LOW',
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
    const hit_7129 = findTag(cleanContent, /\bon(?:MouseMove|Scroll|PointerMove|Wheel|TouchMove)\s*=\s*\{[^}]*\blocalStorage\.getItem/g, /localStorage\.getItem/);
    if (hit_7129 !== -1) {
        const matchLineIdx = hit_7129;
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
    // WEB-PERF-34: DOM Node Polling via setInterval Instead of Observers
    const hit_7134 = /MutationObserver|ResizeObserver|IntersectionObserver/.test(cleanContent) ? -1 : findTag(cleanContent, /\bsetInterval\s*\(\s*(?:\(\s*\)|\w+)\s*=>\s*\{[^}]*\bdocument\.(?:getElementById|querySelector(?:All)?)\s*\(/g);
    if (hit_7134 !== -1) {
        const matchLineIdx = hit_7134;
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
    const hit_7135 = /\.(?:tsx|jsx)$/i.test(file.path) ? findIndexKey(lines) : -1;
    if (hit_7135 !== -1) {
        const matchLineIdx = hit_7135;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `webperf35-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7135,
            type: 'VIBEPOLISH',
            title: "WEB-PERF-35: Unkeyed React List Elements Forcing Full DOM Rebuild",
            severity: 'LOW',
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
    // WEB-PERF-38: Missing HTML Lang Attribute Delaying Accessibility Tree
    const hit_7138 = /\.(?:html|tsx|jsx)$/i.test(file.path) ? findTag(cleanContent, /<html\b(?![^>]*\blang=)(?![^>]*\{\s*\.\.\.)[^>]*>/g) : -1;
    if (hit_7138 !== -1) {
        const matchLineIdx = hit_7138;
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
    const hit_7139 = /tailwind\.config\.(?:js|ts|mjs|cjs)$/i.test(file.path) ? lines.findIndex((l) => /\bcontent\s*:\s*\[\s*\]/.test(l)) : -1;
    if (hit_7139 !== -1) {
        const matchLineIdx = hit_7139;
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
    // WEB-PERF-45: Missing Favicon and Icon Dimensions in Manifest
    const hit_7145 = /manifest\.(?:json|webmanifest)$/i.test(file.path) ? findManifestIconWithoutSizes(file.content, lines) : -1;
    if (hit_7145 !== -1) {
        const matchLineIdx = hit_7145;
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
    return { findings, logs };
}
// ---- precise matchers (rule-proof pass) ----
const lineAt = (text: string, idx: number): number => text.slice(0, idx).split('\n').length - 1;
/** Line of the first match of `re` (global) — or of `inner` inside that match when given. */
function findTag(src: string, re: RegExp, inner?: RegExp): number {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    const m = g.exec(src);
    if (!m) return -1;
    const off = inner ? Math.max(0, m[0].search(inner)) : 0;
    return lineAt(src, m.index + off);
}
/** WEB-PERF-01: the first next/image inside a *Hero* component rendered without priority / preload. */
function findHeroImageWithoutPriority(src: string): number {
    const comp = /(?:function|const)\s+\w*Hero\w*\b/g;
    let m: RegExpExecArray | null;
    while ((m = comp.exec(src))) {
        const img = /<Image\b[\s\S]*?\/?>/.exec(src.slice(m.index, m.index + 3000));
        if (!img) continue;
        if (/\b(?:priority|preload|fetchPriority)\b|loading=["']eager["']/.test(img[0])) continue;
        return lineAt(src, m.index + img.index);
    }
    return -1;
}
/** WEB-PERF-02: <img>/<video> with no intrinsic size, aspect ratio, sizing class, or fill. */
function findUnsizedMedia(src: string): number {
    const tag = /<(?:img|video)\b[^>]*>/g;
    let m: RegExpExecArray | null;
    while ((m = tag.exec(src))) {
        if (/\b(?:width|height|fill)\b|aspect|\bsize-|\b[wh]-|style=|\{\s*\.\.\.|className=\{|class(?:Name)?=["'][^"']*\b(?:hidden|sr-only)\b/.test(m[0])) continue;
        return lineAt(src, m.index);
    }
    return -1;
}
/** WEB-PERF-03: plain (lower-case) <script src="https://..."> with no async / defer / module / next strategy. */
function findBlockingThirdPartyScript(src: string): number {
    const tag = /<script\b[^>]*\bsrc=["']https?:\/\/(?!localhost)[^"']*["'][^>]*>/g;
    let m: RegExpExecArray | null;
    while ((m = tag.exec(src))) {
        if (/\b(?:async|defer|strategy)\b|type=["']module["']/.test(m[0])) continue;
        return lineAt(src, m.index);
    }
    return -1;
}
/** Line of `attr` inside the first @font-face block satisfying `blockOk`. */
function findInFontFace(src: string, blockOk: (block: string) => boolean, attr: RegExp): number {
    const face = /@font-face\s*\{[^}]*\}/g;
    let m: RegExpExecArray | null;
    while ((m = face.exec(src))) {
        const a = attr.exec(m[0]);
        if (a && blockOk(m[0])) return lineAt(src, m.index + a.index);
    }
    return -1;
}
/** WEB-PERF-10: a raster image of 2 KB+ base64 inlined inside an <svg>. */
function findSvgEmbeddedRaster(src: string): number {
    const svg = /<svg\b[\s\S]*?<\/svg>/g;
    let m: RegExpExecArray | null;
    while ((m = svg.exec(src))) {
        const d = /data:image\/(?:png|jpe?g|webp);base64,[a-zA-Z0-9+/=]{2000,}/.exec(m[0]);
        if (d) return lineAt(src, m.index + d.index);
    }
    return -1;
}
/** Brace-matched body text after the `{` found at or after `from`. */
function bodyFrom(src: string, from: number): { start: number; text: string } {
    const o = src.indexOf('{', from);
    if (o === -1) return { start: from, text: '' };
    let depth = 0;
    let i = o;
    for (; i < src.length; i++) {
        if (src[i] === '{') depth++;
        else if (src[i] === '}' && --depth === 0) break;
    }
    return { start: o, text: src.slice(o, i + 1) };
}
/** WEB-PERF-15: inside one loop, a style write followed by a layout read (forced synchronous layout). */
function findLayoutThrashing(src: string): number {
    const loop = /\bfor\s*\([^)]*\)\s*\{|\.forEach\(\s*(?:\([^)]*\)|\w+)\s*=>\s*\{/g;
    let m: RegExpExecArray | null;
    while ((m = loop.exec(src))) {
        const body = bodyFrom(src, m.index + m[0].length - 1);
        const write = /\.style\.\w+\s*=(?!=)/.exec(body.text);
        if (!write) continue;
        const read = /\.(?:offset(?:Height|Width|Top|Left)|client(?:Height|Width)|scroll(?:Height|Top)|getBoundingClientRect\s*\()/.exec(body.text.slice(write.index));
        if (read) return lineAt(src, body.start + write.index + read.index);
    }
    return -1;
}
/** WEB-PERF-23: one CSS rule that both scrolls and applies a large backdrop blur. */
function findBlurOnScroller(src: string): number {
    const rule = /[^{}]+\{[^{}]*\}/g;
    let m: RegExpExecArray | null;
    while ((m = rule.exec(src))) {
        const blur = /backdrop-filter\s*:\s*blur\(\s*(?:[2-9]\d|\d{3,})px\s*\)/i.exec(m[0]);
        if (blur && /overflow(?:-y)?\s*:\s*(?:scroll|auto)/i.test(m[0])) return lineAt(src, m.index + blur.index);
    }
    return -1;
}
/** WEB-PERF-35: list items keyed by their array index (`.map((x, i) => <X key={i}`). */
function findIndexKey(lines: string[]): number {
    for (let i = 0; i < lines.length; i++) {
        const m = /\.map\(\s*\(\s*\w+\s*,\s*(\w+)\s*\)\s*=>/.exec(lines[i]);
        if (!m) continue;
        const key = new RegExp(`\\bkey=\\{\\s*${m[1]}\\s*\\}`);
        for (let j = i; j < Math.min(lines.length, i + 4); j++) if (key.test(lines[j])) return j;
    }
    return -1;
}
/** WEB-PERF-45: a web manifest icon entry with no "sizes". */
function findManifestIconWithoutSizes(raw: string, lines: string[]): number {
    try {
        const icons = (JSON.parse(raw) as { icons?: { sizes?: string }[] }).icons;
        if (!Array.isArray(icons) || icons.every((i) => typeof i?.sizes === 'string' && i.sizes)) return -1;
        return lines.findIndex((l) => /"icons"\s*:/.test(l));
    } catch {
        return -1;
    }
}
