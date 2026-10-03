/**
 * Frontend Performance, WCAG 2.2 AA & SEO Quality Rules (Option B)
 *
 * Rules:
 * 1. UI-A11Y-01 (Rule ID 1026): WCAG 2.2 AA Focus & Label Validation
 * 2. UI-PERF-01 (Rule ID 1027): Core Web Vitals & Next.js Image Optimization
 *
 * Removed as unsound (ids never reused): 1028 (multiple <h1> / missing page title: conditional branches and
 * inherited layout metadata are normal), 1127 (Next.js already optimizes lucide-react / date-fns / lodash imports),
 * 1129 (disabled:pointer-events-none is the shadcn default, not a defect), 27231 (target=_blank without rel: browsers
 * imply noopener; the remaining case is covered by rule 274).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
export interface FrontendRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateFrontendRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): FrontendRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    // Only evaluate frontend files (.tsx, .jsx, .html, .css)
    const isFrontend = file.path.endsWith('.tsx') ||
        file.path.endsWith('.jsx') ||
        file.path.endsWith('.html') ||
        file.path.endsWith('.css');
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    if (!isFrontend)
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    // =========================================================================
    // a) UI-A11Y-01 (Rule ID 1026: WCAG 2.2 AA Focus & Label Validation)
    // =========================================================================
    // Checked per element, never file-wide:
    // - outline-none on a native focusable element (input, textarea, select, button, a) whose own class list adds no
    //   replacement focus style (focus/focus-visible ring, border, shadow, outline, bg or underline);
    // - a native <input>/<textarea>/<select> with no aria-label, aria-labelledby, title or id (id implies a
    //   <label htmlFor>) that is not nested inside a <label>. {...props} spreads may carry either, so they are skipped.
    // Tags end at /> or a > that is not part of => (JSX arrow handlers).
    const offsetLine = (offset: number) => cleanContent.slice(0, offset).split('\n').length - 1;
    const focusableTags = Array.from(cleanContent.matchAll(/<(input|textarea|select|button|a)\b[\s\S]*?(?:\/>|(?<!=)>)/g))
        .filter((m) => !/\{\s*\.\.\./.test(m[0]));
    const outlineTag = focusableTags.find((m) => /(?:^|[\s"'`])(?:focus:|focus-visible:)?outline-none\b/.test(m[0]) &&
        !/\b(?:focus|focus-visible|focus-within):(?:ring|border|shadow|outline-(?!none)|bg-|underline)|(?:^|[\s"'`])ring-\d/.test(m[0]));
    const outlineNoneViolation = !!outlineTag;
    const labelRanges = Array.from(cleanContent.matchAll(/<label\b[^>]*>[\s\S]*?<\/label>/g)).map((m) => [m.index ?? 0, (m.index ?? 0) + m[0].length]);
    const unlabelledTag = focusableTags.find((m) => /^<(?:input|textarea|select)\b/.test(m[0]) &&
        !/type\s*=\s*["'](?:hidden|submit|button|reset|image)["']/i.test(m[0]) &&
        !/\b(?:aria-label|aria-labelledby|title|id)\s*=/.test(m[0]) &&
        !labelRanges.some(([s, e]) => (m.index ?? 0) > s && (m.index ?? 0) < e));
    const unlabelledInputFound = !!unlabelledTag;
    const unlabelledInputSnippet = unlabelledTag ? unlabelledTag[0].slice(0, 100) : '';
    if (outlineNoneViolation || unlabelledInputFound) {
        const matchLineIdx = offsetLine((outlineTag ?? unlabelledTag)!.index ?? 0);
        const lineNum = matchLineIdx + 1;
        const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
        findings.push({
            id: `frontend-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1026,
            type: 'VIBEPOLISH',
            title: 'WCAG 2.2 AA: Interactive Input Missing Accessible Label or Keyboard Focus Ring',
            severity: 'MEDIUM',
            category: 'Accessibility (WCAG)',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: snippet || unlabelledInputSnippet || lines[matchLineIdx] || '<input className="outline-none" />',
            reproductionSteps: [
                `Scanned frontend component markup at ${file.path}:${lineNum}.`,
                unlabelledInputFound && outlineNoneViolation
                    ? 'Detected interactive form input lacking accessible label (aria-label/id) and outline-none stripping focus ring without focus-visible:ring replacement.'
                    : unlabelledInputFound
                        ? 'Detected interactive form input (<input>, <textarea>, or <select>) missing aria-label, aria-labelledby, or id for screen reader label binding.'
                        : 'Detected outline-none / outline: none stripping default keyboard focus indicators without focus-visible:ring replacement.'
            ],
            remediationPrompt: `Add missing aria-label or associated <label htmlFor="..."> to interactive form elements in ${file.path}. Replace outline-none with focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none to preserve WCAG 2.2 AA keyboard focus indicators.`,
            status: 'OPEN',
            owner: 'Frontend Team',
            falsePositive: false
        });
        logs.push(`[${ts}] ♿ MEDIUM: UI-A11Y-01 WCAG 2.2 AA Focus / Label issue detected in ${file.path}:${lineNum}`);
    }
    // =========================================================================
    // b) UI-PERF-01 (Rule ID 1027: Core Web Vitals & Next.js Image Optimization)
    // =========================================================================
    const isJsxTsx = file.path.endsWith('.tsx') || file.path.endsWith('.jsx');
    const isHtml = file.path.endsWith('.html');
    const rawImgMatches = cleanContent.match(/<\s*img\b[^>]*>/gi) || [];
    // Exclude SVG vector icons/logos since Next.js Image optimization is for raster formats (F-38)
    const nonSvgImgMatches = rawImgMatches.filter(tag => !/\.svg|\/svg|svg\+/i.test(tag));
    const hasUnsizedHtmlImg = isHtml && /<\s*img\b(?![^>]*\b(?:width|height|loading)\b)[^>]*>/i.test(cleanContent);
    const hasRawRasterImg = isJsxTsx ? nonSvgImgMatches.length > 0 : hasUnsizedHtmlImg;
    const hasHeavyBase64 = (isJsxTsx || isHtml) && (/data:image\/[a-zA-Z0-9+.-]+;base64,[a-zA-Z0-9+/=]{1000,}/i.test(cleanContent) || /data:image\/[^"'\s`]{1000,}/i.test(cleanContent));
    if (!lowerPath.endsWith('.css') && (hasRawRasterImg || hasHeavyBase64)) {
        let matchLineIdx = -1;
        if (hasHeavyBase64) {
            matchLineIdx = lines.findIndex(l => l.includes('data:image/') && l.length > 500);
        }
        if (matchLineIdx === -1 && hasRawRasterImg) {
            matchLineIdx = lines.findIndex(l => /<\s*img\b/i.test(l) && !/\.svg|\/svg|svg\+/i.test(l));
        }
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
        // UI and styling suggestions are LOW / MEDIUM severity, never HIGH release gate blockers (F-38)
        const severity = hasHeavyBase64 ? 'MEDIUM' : 'LOW';
        const title = isJsxTsx
            ? 'Unoptimized Raster <img> Tag or Heavy Inline Data URI (Performance Optimization)'
            : hasHeavyBase64
                ? 'Heavy Inline Base64 Image Data URI in HTML Template'
                : 'HTML <img> Tag Missing Explicit Dimensions or Lazy Loading (Layout Shift Risk)';
        const reproductionSteps = isJsxTsx
            ? [
                `Scanned frontend JSX rendering at ${file.path}:${lineNum}.`,
                hasHeavyBase64 && hasRawRasterImg
                    ? 'Detected both unoptimized raw raster <img> tag and massive inline Base64 data URI (>1000 chars) degrading page load performance.'
                    : hasHeavyBase64
                        ? 'Detected massive inline Base64 image data URI (>1000 characters) embedded in JSX, causing severe bundle bloat and blocking DOM parsing.'
                        : 'Detected unoptimized raw HTML raster <img> tag in Next.js component instead of next/image <Image> for WebP/AVIF compression.'
            ]
            : [
                `Scanned HTML template at ${file.path}:${lineNum}.`,
                hasHeavyBase64
                    ? 'Detected massive inline Base64 image data URI (>1000 characters) embedded in HTML, increasing payload size.'
                    : 'Detected <img> tag without explicit width, height, or loading="lazy" attributes, risking Cumulative Layout Shift (CLS).'
            ];
        const remediationPrompt = isJsxTsx
            ? `Consider replacing raster <img> tags in ${file.path} with Next.js 'next/image' <Image> component with explicit width, height, and priority attributes where appropriate.`
            : `Add explicit 'width', 'height', and 'loading="lazy"' attributes to <img> tags in ${file.path} to optimize page load speed.`;
        findings.push({
            id: `frontend-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1027,
            type: 'VIBEPOLISH',
            title,
            severity,
            category: 'Performance & CWV',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: snippet || lines[matchLineIdx] || '<img src="..." alt="..." />',
            reproductionSteps,
            remediationPrompt,
            status: 'OPEN',
            owner: 'Frontend Team',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ ${severity}: UI-PERF-01 ${title} detected in ${file.path}:${lineNum}`);
    }
    // =========================================================================
    // d) UI-A11Y-02 (Rule ID 1029: Inaccessible Non-Semantic Clickable Element)
    // =========================================================================
    if (isJsxTsx) {
        // Per element (multi-line tags included): a static element with onClick and no role, tabIndex or key handler.
        // aria-hidden elements, {...spread} props and handlers that only stop event propagation are skipped.
        const clickableTag = Array.from(cleanContent.matchAll(/<(?:div|span|section|article|li|p|img)\b[\s\S]*?(?:\/>|(?<!=)>)/g)).find((m) =>
            /\sonClick\s*=/.test(m[0]) &&
            !/\s(?:role|tabIndex|onKeyDown|onKeyUp|onKeyPress|aria-hidden)\s*=|\{\s*\.\.\./.test(m[0]) &&
            !/onClick\s*=\s*\{\s*\(?\s*(\w+)\s*\)?\s*=>\s*\{?\s*\1\.stopPropagation\(\)\s*;?\s*\}?\s*\}/.test(m[0]));
        if (clickableTag) {
            const matchLineIdx = offsetLine(clickableTag.index ?? 0);
            {
                const lineNum = matchLineIdx + 1;
                const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
                findings.push({
                    id: `frontend-${Date.now()}-${findingCounter.count++}`,
                    ruleId: 1029,
                    type: 'VIBEPOLISH',
                    title: 'WCAG 2.2 AA: Non-Semantic Clickable Container Missing Keyboard Accessibility',
                    severity: 'MEDIUM',
                    category: 'Accessibility (WCAG)',
                    filePath: file.path,
                    lineRange: `L${lineNum}`,
                    snippet: snippet || lines[matchLineIdx] || '<div onClick={handleClick}>Click me</div>',
                    reproductionSteps: [
                        `Scanned JSX component markup at ${file.path}:${lineNum}.`,
                        'Detected non-semantic container (<div> or <span>) with an onClick handler but lacking role="button", tabIndex={0}, and onKeyDown keyboard listener. Keyboard and screen reader users cannot activate this element.'
                    ],
                    remediationPrompt: `Replace non-semantic <div onClick=...> in ${file.path}:${lineNum} with a semantic <button onClick=...> element, or add role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') handleClick(); }} to comply with WCAG 2.2 AA accessibility guidelines.`,
                    status: 'OPEN',
                    owner: 'Frontend Team',
                    falsePositive: false
                });
                logs.push(`[${ts}] ♿ MEDIUM: UI-A11Y-02 Non-semantic clickable element missing keyboard accessibility in ${file.path}:${lineNum}`);
            }
        }
    }
    // =========================================================================
    // e) UI-PERF-02 (Rule ID 1030: Unkeyed React Array Mapping Reconciliation Hazard)
    // =========================================================================
    if (isJsxTsx) {
        // Matched on the whole source so a key on a later line of a multi-line tag counts; reported at the .map( line.
        // A {...spread} on the element may carry the key and is skipped.
        const unkeyedMapRegex = /\.map\s*\(\s*(?:\([^)]*\)|[a-zA-Z0-9_]+)\s*=>\s*\(?\s*<[a-zA-Z][\w.]*(?![^>]*\bkey\s*=)(?![^>]*\{\s*\.\.\.)/;
        const unkeyedMap = unkeyedMapRegex.exec(cleanContent);
        if (unkeyedMap) {
            const matchLineIdx = offsetLine(unkeyedMap.index);
            {
                const lineNum = matchLineIdx + 1;
                const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
                findings.push({
                    id: `frontend-${Date.now()}-${findingCounter.count++}`,
                    ruleId: 1030,
                    type: 'VIBEPOLISH',
                    title: 'Unkeyed React Array Mapping Reconciliation Hazard',
                    severity: 'MEDIUM',
                    category: 'Performance & CWV',
                    filePath: file.path,
                    lineRange: `L${lineNum}`,
                    snippet: snippet || lines[matchLineIdx] || 'items.map((item) => <div>{item.name}</div>)',
                    reproductionSteps: [
                        `Scanned React JSX render tree in ${file.path}:${lineNum}.`,
                        'Detected dynamic array mapping returning JSX elements without an explicit unique key prop, risking UI state de-synchronization and excessive DOM reconciliations.'
                    ],
                    remediationPrompt: `Add unique stable key prop (e.g. key={item.id}) to outermost mapped JSX elements in ${file.path}:${lineNum}. Avoid using raw array indices as keys if items can be re-ordered, filtered, or mutated.`,
                    status: 'OPEN',
                    owner: 'Frontend Team',
                    falsePositive: false
                });
                logs.push(`[${ts}] ⚡ MEDIUM: UI-PERF-02 Unkeyed array map in ${file.path}:${lineNum}`);
            }
        }
    }
    // =========================================================================
    // j) UI-PERF-06 (Rule ID 1033: Custom Web Fonts Missing font-display: swap)
    // =========================================================================
    // Per @font-face block with no font-display at all (the browser default "auto" blocks text for up to 3s);
    // any explicit value (swap, optional, fallback) is a deliberate choice.
    const fontFaceNoDisplay = Array.from(cleanContent.matchAll(/@font-face\s*\{[^}]*\}/g)).find((m) => !/font-display\s*:/.test(m[0]));
    if (fontFaceNoDisplay) {
        const matchLineIdx = offsetLine(fontFaceNoDisplay.index ?? 0);
        const lineNum = matchLineIdx + 1;
        const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
        findings.push({
            id: `frontend-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1033,
            type: 'VIBEPOLISH',
            title: 'Custom Web Font Missing font-display: swap (FOIT / LCP Penalty)',
            severity: 'LOW',
            category: 'Performance & CWV',
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: snippet || lines[matchLineIdx] || '@font-face { font-family: "Custom"; }',
            reproductionSteps: [
                `Scanned font stylesheet declarations at ${file.path}:${lineNum}.`,
                'Detected @font-face rule without font-display: swap, causing Flash of Invisible Text (FOIT) while external fonts are downloading.'
            ],
            remediationPrompt: `Add font-display: swap to @font-face rules in ${file.path}:${lineNum} to ensure instant fallback text rendering.`,
            status: 'OPEN',
            owner: 'Frontend Team',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ LOW: UI-PERF-06 Font missing font-display: swap in ${file.path}:${lineNum}`);
    }
    // =========================================================================
    // k) UI-PERF-07 (Rule ID 1034: Synchronous Render-Blocking Script Tags)
    // =========================================================================
    if (file.path.endsWith('.html') || lowerPath.includes('layout.') || lowerPath.includes('document.')) {
        // Lowercase <script> only: next/script's <Script> defaults to afterInteractive and never blocks parsing.
        const scriptTags = Array.from(cleanContent.matchAll(/<script\b([^>]*)>/g));
        const blockingTag = scriptTags.find(m => {
            const attrs = m[1];
            const hasSrc = /\bsrc\s*=/i.test(attrs);
            if (!hasSrc) return false;
            const isNonBlocking = /\b(async|defer|nomodule)\b/i.test(attrs) || /type\s*=\s*['"]module['"]/i.test(attrs);
            return !isNonBlocking;
        });
        if (blockingTag) {
            const matchLineIdx = offsetLine(blockingTag.index ?? 0);
            const lineNum = matchLineIdx + 1;
            const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
            findings.push({
                id: `frontend-${Date.now()}-${findingCounter.count++}`,
                ruleId: 1034,
                type: 'VIBEPOLISH',
                title: 'Synchronous Render-Blocking Script Tag Detected in Document Head',
                severity: 'LOW',
                category: 'Performance & CWV',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: snippet || lines[matchLineIdx] || '<script src="analytics.js"></script>',
                reproductionSteps: [
                    `Scanned script tags at ${file.path}:${lineNum}.`,
                    'Detected synchronous <script src="..."> tag without async, defer, or Next.js next/script strategy, blocking HTML parser and delaying First Contentful Paint (FCP).'
                ],
                remediationPrompt: `Add defer or async attribute, or migrate to Next.js <Script strategy="afterInteractive" /> in ${file.path}:${lineNum}.`,
                status: 'OPEN',
                owner: 'Performance Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] ⚡ LOW: UI-PERF-07 Render-blocking script tag in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // n) UI-A11Y-05 (Rule ID 1044: Touch Target Below WCAG 2.2 AA Minimum (<24x24px, SC 2.5.8))
    // =========================================================================
    if (isJsxTsx) {
        const tinyTargetRegex = /<(?:button|a)\b[^>]*className=['"][^'"]*\b(?:w-[2345]\s+h-[2345]|h-[2345]\s+w-[2345])\b(?![^'"]*\b(?:p-|py-|px-|min-h-|min-w-|h-1[0-9]|w-1[0-9]))[^'"]*['"][^>]*>/i;
        if (tinyTargetRegex.test(cleanContent)) {
            const matchLineIdx = lines.findIndex(l => tinyTargetRegex.test(l));
            if (matchLineIdx !== -1) {
                const lineNum = matchLineIdx + 1;
                const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');
                findings.push({
                    id: `frontend-${Date.now()}-${findingCounter.count++}`,
                    ruleId: 1044,
                    type: 'VIBEPOLISH',
                    title: 'Interactive Element Touch Target Below WCAG 2.2 AA Minimum (<24x24px)',
                    severity: 'LOW',
                    category: 'Accessibility (WCAG)',
                    filePath: file.path,
                    lineRange: `L${lineNum}`,
                    snippet: snippet || lines[matchLineIdx] || '<button className="w-4 h-4">',
                    reproductionSteps: [
                        `Scanned interactive tap target dimensions at ${file.path}:${lineNum}.`,
                        'Detected a clickable button/link sized w-2..w-5 / h-2..h-5 (8-20px) with no padding or min size, below the 24x24 CSS pixel WCAG 2.2 AA Target Size (Minimum) criterion (2.5.8).'
                    ],
                    remediationPrompt: `Increase the interactive hit area to at least 24x24px (44x44px recommended) using padding (p-1 or more) or min-w-6 min-h-6 in ${file.path}:${lineNum}.`,
                    status: 'OPEN',
                    owner: 'Accessibility Lead',
                    falsePositive: false
                });
                logs.push(`[${ts}] ♿ LOW: UI-A11Y-05 Touch target below 24x24px in ${file.path}:${lineNum}`);
            }
        }
    }
    return { findings, logs };
}
export const evaluateFrontendQualityRules = evaluateFrontendRules;
