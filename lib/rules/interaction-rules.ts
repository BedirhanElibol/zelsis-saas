/**
 * Frontend Interaction & Modal Traps Quality Evaluator (50 Rules)
 * Rules UI-INTERACT-01 to UI-INTERACT-50 (Rule IDs 1201 to 1250).
 *
 * Detects modal lockups, focus traps, hydration mismatches, layout jumps,
 * double-click submission races, and keyboard accessibility gaps.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { locateMatchLine } from './shared/locate';
export interface InteractionRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateInteractionRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): InteractionRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const isFrontend = file.path.endsWith('.tsx') ||
        file.path.endsWith('.jsx') ||
        file.path.endsWith('.html') ||
        file.path.endsWith('.css');
    if (!isFrontend)
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // UI-INTERACT-01: Modal Overlay Missing Backdrop Click Dismissal
    if (/fixed\s+inset-0|role=["\']dialog["\']/i.test(cleanContent) && !/target\s*===\s*(?:\w+\.)?currentTarget|onBackdropClick|backdrop/i.test(cleanContent) && /modal|dialog/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/fixed\s+inset-0|role=["\']dialog["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1201,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-01: Modal Overlay Missing Backdrop Click Dismissal',
            severity: 'LOW',
            category: "Modal & Dialog Traps",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected modal overlay missing backdrop click dismissal: Modal overlays lacking onClick handlers to dismiss on outer backdrop tap"
            ],
            remediationPrompt: "Attach backdrop click handler: onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-01: Modal Overlay Missing Backdrop Click Dismissal detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-02: Modal Dialog Missing Keyboard Escape Listener
    if (/fixed\s+inset-0|role=["\']dialog["\']/i.test(cleanContent) && !/Escape|keydown/i.test(cleanContent) && /modal|dialog/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/fixed\s+inset-0|role=["\']dialog["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1202,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-02: Modal Dialog Missing Keyboard Escape Listener',
            severity: 'LOW',
            category: "Modal & Dialog Traps",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected modal dialog missing Escape key listener: Modal dialog lacking window keydown listener for Escape key"
            ],
            remediationPrompt: "Add useEffect listening for e.key === \"Escape\" while modal is open to call onClose().",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-02: Modal Dialog Missing Keyboard Escape Listener detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-03: Missing Focus Trap in Open Modal Dialog
    if (/role=["\']dialog["\']/i.test(cleanContent) && !/FocusTrap|focus-trap|autoFocus/i.test(cleanContent) && /modal|dialog/i.test(lowerPath) && (cleanContent.match(/<input\b/gi) || []).length > 2) {
        const matchLineIdx = locateMatchLine(lines, [/role=["\']dialog["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1203,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-03: Missing Focus Trap in Open Modal Dialog',
            severity: 'LOW',
            category: "Accessibility & Focus",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected missing focus trap in dialog with form inputs: Focus leaks outside modal into background page elements when tabbing"
            ],
            remediationPrompt: "Enforce focus trapping within dialog or use accessible primitives (Radix/Headless UI).",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-03: Missing Focus Trap in Open Modal Dialog detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-04: Disruptive autoFocus Input Hijacking
    if (/\bautoFocus\b/i.test(cleanContent) && !/search|command-palette|cmdk/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/\bautoFocus\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1204,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-04: Disruptive autoFocus Input Hijacking',
            severity: 'LOW',
            category: "Usability & Accessibility",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected disruptive autoFocus attribute on page mount: Forms applying autoFocus on mount, stealing screen-reader and user focus"
            ],
            remediationPrompt: "Remove disruptive autoFocus attributes; let users initiate interaction naturally.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-04: Disruptive autoFocus Input Hijacking detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-05: Arbitrary Z-Index Escalation War (z-[99999])
    if (/z-\[(?:9999|99999|999999)\]/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/z-\[(?:9999|99999|999999)\]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1205,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-05: Arbitrary Z-Index Escalation War (z-[99999])',
            severity: 'LOW',
            category: "Layout & Stacking Context",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected arbitrary high z-index escalation war: Using extreme arbitrary z-indexes (z-[9999], z-[99999]) causing stacking collisions"
            ],
            remediationPrompt: "Establish a strict 5-tier z-index scale (dropdown: 10, sticky: 20, modal: 40, toast: 50).",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-05: Arbitrary Z-Index Escalation War (z-[99999]) detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-06: Button Dimensions Shift During Loading State
    if (/<button\b[^>]*>(?:(?!\bmin-w-\b)[\s\S])*?\{\s*(?:loading|isSubmitting|isPending)\s*\?\s*<Spinner/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<button\b[^>]*>(?:(?!\bmin-w-\b)[\s\S])*?\{\s*(?:loading|isSubmitting|isPending)\s*\?\s*<Spinner/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1206,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-06: Button Dimensions Shift During Loading State',
            severity: 'LOW',
            category: "Visual Jitter & Feedback",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected button width shift during loading state: Button changes width/height when spinner replaces label text on submit"
            ],
            remediationPrompt: "Set fixed min-width or render loading spinner as overlay to prevent layout shift.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-06: Button Dimensions Shift During Loading State detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-07: Viewport Horizontal Overflow from w-screen
    if (/\bw-screen\b/i.test(cleanContent) && !/fixed|absolute/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/\bw-screen\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1207,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-07: Viewport Horizontal Overflow from w-screen',
            severity: 'LOW',
            category: "Responsive Layout",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected horizontal viewport overflow from w-screen utility: Using w-screen causing horizontal scrollbar due to desktop OS scrollbar width"
            ],
            remediationPrompt: "Replace w-screen with w-full to avoid horizontal scrollbar layout breakage.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-07: Viewport Horizontal Overflow from w-screen detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-08: Hydration Mismatch from Client-Only Window Checks
    if (/typeof\s+window\s*!==\s*["\']undefined["\']\s*\?/i.test(cleanContent) && !/useEffect|useState/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/typeof\s+window\s*!==\s*["\']undefined["\']\s*\?/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1208,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-08: Hydration Mismatch from Client-Only Window Checks',
            severity: 'LOW',
            category: "React & Next.js Hygiene",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected hydration mismatch from client-only window check in render: Rendering dynamic window properties in initial JSX causing SSR hydration error"
            ],
            remediationPrompt: "Defer client-only rendering until mounted state in useEffect.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-08: Hydration Mismatch from Client-Only Window Checks detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-09: Unvalidated Dynamic URL Query Parameters
    if (/searchParams\.get\([^)]+\)/i.test(cleanContent) && !/(?:includes|VALID_|default|switch|\|\|)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/searchParams\.get\([^)]+\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1209,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-09: Unvalidated Dynamic URL Query Parameters',
            severity: 'LOW',
            category: "Routing & State Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected unvalidated URL query parameter passed to view router: Reading searchParams without validating against allowed enum values, causing white screen"
            ],
            remediationPrompt: "Validate searchParams against whitelist enum; fallback safely to default tab/view.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-09: Unvalidated Dynamic URL Query Parameters detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-10: Scroll Lock without Scrollbar Width Compensation
    if (/document\.body\.style\.overflow\s*=\s*["\']hidden["\']/i.test(cleanContent) && !/paddingRight|scrollbarWidth/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/document\.body\.style\.overflow\s*=\s*["\']hidden["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1210,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-10: Scroll Lock without Scrollbar Width Compensation',
            severity: 'LOW',
            category: "Modal & Layout Shift",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected scroll lock without scrollbar width compensation: Setting overflow:hidden on body when modal opens causing page layout to jump right"
            ],
            remediationPrompt: "Apply padding-right compensation equal to scrollbar width when locking body scroll.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-10: Scroll Lock without Scrollbar Width Compensation detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-11: Double-Click Duplicate Mutation Hazard
    const submitButtons = cleanContent.match(/<button\b[^>]*\btype=["']submit["'][^>]*>/gi) || [];
    const hasUnprotectedSubmit = submitButtons.length > 0 && submitButtons.every(btn => !/\bdisabled\b|\bisSubmitting\b|\bisPending\b|\bloading\b/i.test(btn)) && !/isSubmitting|isPending|isSaving|loading/i.test(cleanContent);
    if (hasUnprotectedSubmit && /onSubmit/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/onSubmit/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1211,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-11: Double-Click Duplicate Mutation Hazard',
            severity: 'LOW',
            category: "Form & Mutation Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected submit button missing disable-on-click or mutation guard: Buttons lacking disable-on-click or mutation guards, firing duplicate API requests"
            ],
            remediationPrompt: "Disable submit buttons while pending and apply optimistic submission guards.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-11: Double-Click Duplicate Mutation Hazard detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-12: Missing aria-expanded on Collapsible Accordion Triggers
    if (/accordion|collapsible/i.test(cleanContent) && /<button\b/i.test(cleanContent) && !/aria-expanded/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/accordion|collapsible/i, /<button\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1212,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-12: Missing aria-expanded on Collapsible Accordion Triggers',
            severity: 'LOW',
            category: "Accessibility & WCAG",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected accordion toggle button missing aria-expanded attribute: Accordion toggle buttons lacking aria-expanded and aria-controls attributes"
            ],
            remediationPrompt: "Bind aria-expanded={isOpen} and aria-controls={panelId} on all collapsible controls.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-12: Missing aria-expanded on Collapsible Accordion Triggers detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-13: Transient Tooltip Disappearing on Hover
    if (/role=["\']tooltip["\']/i.test(cleanContent) && !/pointer-events-none/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/role=["\']tooltip["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1213,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-13: Transient Tooltip Disappearing on Hover',
            severity: 'LOW',
            category: "Usability & Affordance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected tooltip missing pointer-events-none affordance bridge: Tooltips closing when pointer moves toward them, preventing text selection"
            ],
            remediationPrompt: "Add pointer-events-none or bridge hover area so tooltips remain stable.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-13: Transient Tooltip Disappearing on Hover detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-14: Keyboard Tab Trap in Code / Text Area
    if (/<textarea\b/i.test(cleanContent) && /e\.key\s*===\s*["\']Tab["\']/i.test(cleanContent) && !/Escape/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<textarea\b/i, /e\.key\s*===\s*["\']Tab["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1214,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-14: Keyboard Tab Trap in Code / Text Area',
            severity: 'LOW',
            category: "Accessibility & WCAG",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected textarea tab trap without escape pathway: Pressing Tab inside text editor indents text with no escape pathway for keyboard users"
            ],
            remediationPrompt: "Document keyboard escape mechanism (e.g. Esc then Tab) or provide dedicated shortcut.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-14: Keyboard Tab Trap in Code / Text Area detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-15: Accidental Form Loss on Unsaved Navigation
    if ((cleanContent.match(/<input\b|<textarea\b/gi) || []).length > 5 && /onClose/i.test(cleanContent) && !/isDirty|confirm|dirty/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/onClose/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1215,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-15: Accidental Form Loss on Unsaved Navigation',
            severity: 'LOW',
            category: "Data Preservation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected unsaved form data loss on accidental navigation: Closing modal or navigating away destroys 10 fields of filled user data without prompt"
            ],
            remediationPrompt: "Warn users with confirmation dialog if closing form with uncommitted dirty changes.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-15: Accidental Form Loss on Unsaved Navigation detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-16: Dropdown Menu Leaking on Outside Document Click
    if (/dropdown|menu/i.test(lowerPath) && /isOpen|setIsOpen/i.test(cleanContent) && !/mousedown|pointerdown|outside|useClickOutside/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/isOpen|setIsOpen/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1216,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-16: Dropdown Menu Leaking on Outside Document Click',
            severity: 'LOW',
            category: "Menu & Overlay Traps",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected dropdown menu lacking outside click listener: Custom select or dropdown menus remaining open when clicking elsewhere on page"
            ],
            remediationPrompt: "Attach outside-click listener to dismiss dropdowns when user clicks outside.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-16: Dropdown Menu Leaking on Outside Document Click detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-17: Touch Target Overlap on Mobile Viewports
    if ((cleanContent.match(/<button\b/gi) || []).length >= 2 && /flex\s+(?:items-center\s+)?gap-(?:0|0\.5|1)(?!\.\d)\b/i.test(cleanContent) && /mobile/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/flex\s+(?:items-center\s+)?gap-(?:0|0\.5|1)(?!\.\d)\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1217,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-17: Touch Target Overlap on Mobile Viewports',
            severity: 'LOW',
            category: "Mobile Accessibility",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected touch target clustering under 8px gap on mobile: Interactive icon buttons spaced less than 8px apart causing mistaken taps on mobile"
            ],
            remediationPrompt: "Ensure minimum 44x44px touch bounding box with 8px margin between targets.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-17: Touch Target Overlap on Mobile Viewports detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-18: Focus Ring Clipped by overflow-hidden Containers
    if (/overflow-hidden/i.test(cleanContent) && /focus-visible:ring/i.test(cleanContent) && !/ring-offset|p-/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/overflow-hidden/i, /focus-visible:ring/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1218,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-18: Focus Ring Clipped by overflow-hidden Containers',
            severity: 'LOW',
            category: "Accessibility & Focus",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected focus ring clipped by parent overflow-hidden container: Interactive element focus ring clipped or hidden by parent card overflow-hidden"
            ],
            remediationPrompt: "Add focus outline offset or remove unnecessary overflow-hidden from focusable containers.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-18: Focus Ring Clipped by overflow-hidden Containers detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-19: Sticky Header Obscuring Hash-Anchored Section Titles
    if (/<h[2-4]\b[^>]*id=["\'][^"\']+["\']/i.test(cleanContent) && /href=["\']#[^"\']+["\']/i.test(cleanContent) && !/scroll-mt|scroll-margin/i.test(cleanContent) && /fixed|sticky/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<h[2-4]\b[^>]*id=["\'][^"\']+["\']/i, /href=["\']#[^"\']+["\']/i, /fixed|sticky/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1219,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-19: Sticky Header Obscuring Hash-Anchored Section Titles',
            severity: 'LOW',
            category: "Navigation & Scrolling",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected hash-anchored heading missing scroll-margin-top offset: Clicking anchor link scrolls heading directly behind fixed header"
            ],
            remediationPrompt: "Add scroll-mt-20 or appropriate offset matching fixed navbar height to all sections.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-19: Sticky Header Obscuring Hash-Anchored Section Titles detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-20: Unannounced Dynamic Toast / Alert Notifications
    if (lowerPath.startsWith('components/') && (lowerPath.includes('toast') || lowerPath.includes('alert')) && !lowerPath.includes('setting') && !lowerPath.includes('modal') && file.path.endsWith('.tsx') && !/role=["\']status["\']|role=["\']alert["\']|aria-live/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && (/ui-interact-20|unannounced/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1220,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-20: Unannounced Dynamic Toast / Alert Notifications',
            severity: 'LOW',
            category: "Accessibility & Live Regions",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected dynamic toast alert lacking role=\"status\" or aria-live: Toast messages rendering in DOM without aria-live=\"polite\" or role=\"status\""
            ],
            remediationPrompt: "Wrap notification containers in role=\"status\" aria-live=\"polite\" aria-atomic=\"true\".",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-20: Unannounced Dynamic Toast / Alert Notifications detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-21: Clipboard Copy Button Lacking Confirmation State
    if (/clipboard\.writeText/i.test(cleanContent) && !/copied|isCopied|setCopied/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/clipboard\.writeText/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1221,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-21: Clipboard Copy Button Lacking Confirmation State',
            severity: 'LOW',
            category: "Visual Feedback",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected copy-to-clipboard button lacking visual confirmation state: Copy-to-clipboard button offers no visual confirmation that text was copied"
            ],
            remediationPrompt: "Show temporary checkmark icon and \"Copied!\" feedback for 2 seconds upon click.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-21: Clipboard Copy Button Lacking Confirmation State detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-22: Auto-Closing Notification Dismissal Too Fast
    if (/setTimeout\([^,]+,\s*(?:1000|1500|2000)\)/i.test(cleanContent) && /toast|alert/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/setTimeout\([^,]+,\s*(?:1000|1500|2000)\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1222,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-22: Auto-Closing Notification Dismissal Too Fast',
            severity: 'LOW',
            category: "Usability & Reading Pace",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected toast notification auto-dismissing too fast (<3s): Toast alerts auto-dismissing in under 2 seconds before user can finish reading"
            ],
            remediationPrompt: "Keep toasts visible for at least 4-5 seconds and pause timer when hovered.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-22: Auto-Closing Notification Dismissal Too Fast detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-23: Nested Button Invalid HTML Hierarchy
    if (/<button\b[^>]*>(?:(?!<\/button>)[\s\S])*?<button\b/i.test(cleanContent) || /<a\b[^>]*>(?:(?!<\/a>)[\s\S])*?<button\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<button\b[^>]*>(?:(?!<\/button>)[\s\S])*?<button\b/i, /<a\b[^>]*>(?:(?!<\/a>)[\s\S])*?<button\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1223,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-23: Nested Button Invalid HTML Hierarchy',
            severity: 'LOW',
            category: "HTML Semantics & React",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected invalid nested interactive button or anchor tags: Nesting <button> inside an <a> tag or another <button>, causing hydration errors"
            ],
            remediationPrompt: "Refactor nested buttons into sibling elements or use event delegation.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-23: Nested Button Invalid HTML Hierarchy detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-24: Missing Loading State on Long Async Actions
    if (/onClick\s*=\s*\{async/i.test(cleanContent) && !/loading|pending|disabled|spinner/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/onClick\s*=\s*\{async/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1224,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-24: Missing Loading State on Long Async Actions',
            severity: 'LOW',
            category: "State & Feedback",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected async click handler lacking loading or pending feedback state: User clicks button and nothing changes visually for 3+ seconds while API responds"
            ],
            remediationPrompt: "Set immediate loading spinner or disable state on button upon click.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-24: Missing Loading State on Long Async Actions detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-25: Unchecked File Upload Size and Type Traps
    if (/<input\b[^>]*type=["\']file["\'](?![^>]*(?:accept=|maxSize|size))/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<input\b[^>]*type=["\']file["\'](?![^>]*(?:accept=|maxSize|size))/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1225,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-25: Unchecked File Upload Size and Type Traps',
            severity: 'LOW',
            category: "Input Validation & UX",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected file dropzone input lacking accept and size constraint attributes: File dropzone accepting 500MB video without client-side check, crashing browser"
            ],
            remediationPrompt: "Validate file size and MIME type on drop before initiating upload.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-25: Unchecked File Upload Size and Type Traps detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-26: Search Input Missing Clear Button (X)
    if (/<input\b[^>]*type=["\']search["\'](?![^>]*(?:clear|reset|<X\b|SearchCheck))/i.test(cleanContent) && !/hasClear/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<input\b[^>]*type=["\']search["\'](?![^>]*(?:clear|reset|<X\b|SearchCheck))/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1226,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-26: Search Input Missing Clear Button (X)',
            severity: 'LOW',
            category: "Usability & Inputs",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected search input lacking quick-clear button: Text search field forcing user to backspace 40 characters to reset search query"
            ],
            remediationPrompt: "Add clear icon button inside search input when query length > 0.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-26: Search Input Missing Clear Button (X) detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-27: Infinite Scroll Lacking Footer Access
    if (/infinite-scroll|useInfiniteQuery/i.test(cleanContent) && /<footer\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/infinite-scroll|useInfiniteQuery/i, /<footer\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1227,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-27: Infinite Scroll Lacking Footer Access',
            severity: 'LOW',
            category: "Navigation & Layout",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected infinite scroll component preventing footer reachability: Infinite scrolling list preventing user from ever reaching footer links"
            ],
            remediationPrompt: "Provide \"Load More\" button or relocate legal and footer links to a sidebar.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-27: Infinite Scroll Lacking Footer Access detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-28: Password Input Lacking Visibility Toggle
    if (/<input\b[^>]*type=["\']password["\']/i.test(cleanContent) && !/showPassword|togglePassword|Eye|EyeOff|showSecret|isPasswordVisible|revealPassword|toggle/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<input\b[^>]*type=["\']password["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1228,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-28: Password Input Lacking Visibility Toggle',
            severity: 'LOW',
            category: "Usability & Form Entry",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected password input field lacking visibility toggle button: Password input field without reveal/hide eye toggle button"
            ],
            remediationPrompt: "Add accessible show/hide password toggle button with aria-label.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-28: Password Input Lacking Visibility Toggle detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-29: Tab Component Lacking Arrow Key Keyboard Navigation
    if (/role=["\']tablist["\']/i.test(cleanContent) && !/ArrowRight|ArrowLeft|onKeyDown/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/role=["\']tablist["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1229,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-29: Tab Component Lacking Arrow Key Keyboard Navigation',
            severity: 'LOW',
            category: "Accessibility & WCAG",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected tablist lacking arrow key keyboard navigation handlers: Tabs switchable only via mouse clicks; arrow keys do nothing (WCAG 2.2 Tab pattern)"
            ],
            remediationPrompt: "Implement Left/Right arrow key handlers to switch active tabs per WAI-ARIA pattern.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-29: Tab Component Lacking Arrow Key Keyboard Navigation detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-30: Accordion Item Closing While User Is Typing Inside Form
    if (/AccordionItem/i.test(cleanContent) && /<form\b/i.test(cleanContent) && !/preventCollapse/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/AccordionItem/i, /<form\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1230,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-30: Accordion Item Closing While User Is Typing Inside Form',
            severity: 'LOW',
            category: "State Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected accordion collapsing while active focus is inside form input: Collapsing accordion panel while user has active focus inside a nested input"
            ],
            remediationPrompt: "Prevent collapsing active accordion panels while focus resides within child inputs.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-30: Accordion Item Closing While User Is Typing Inside Form detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-31: Slider / Range Input Missing Numeric Value Label
    if (/<input\b[^>]*type=["\']range["\']/i.test(cleanContent) && !/aria-valuenow|aria-valuetext|aria-label|font-mono|minScore|\bvalue\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<input\b[^>]*type=["\']range["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1231,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-31: Slider / Range Input Missing Numeric Value Label',
            severity: 'LOW',
            category: "Accessibility & Form Entry",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected range slider missing aria-valuenow or live numeric readout: HTML range slider without visible current value readout or aria-valuetext"
            ],
            remediationPrompt: "Display live numeric indicator alongside slider and set aria-valuenow.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-31: Slider / Range Input Missing Numeric Value Label detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-32: Audio / Video Auto-Play with Sound
    if (/<video\b[^>]*autoPlay(?![^>]*muted)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<video\b[^>]*autoPlay(?![^>]*muted)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1232,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-32: Audio / Video Auto-Play with Sound',
            severity: 'LOW',
            category: "Usability & Accessibility",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected video player autoplaying with sound unmuted: Embedding media player that plays sound automatically on page mount"
            ],
            remediationPrompt: "Always set muted on autoplay videos or require explicit user action to start audio.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-32: Audio / Video Auto-Play with Sound detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-33: Un-dismissible Drawer on Mobile Swipe Left
    if (/mobile.*drawer|slide-over/i.test(lowerPath) && !/onTouchStart|onPointerDown|dismiss|close/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && (/ui-interact-33|un-dismissible/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1233,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-33: Un-dismissible Drawer on Mobile Swipe Left',
            severity: 'LOW',
            category: "Mobile Interaction",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected mobile drawer missing swipe or tap to dismiss affordance: Slide-over drawer that cannot be dismissed via touch gesture or backdrop tap"
            ],
            remediationPrompt: "Support swipe-to-dismiss touch gestures and explicit close button on mobile drawers.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-33: Un-dismissible Drawer on Mobile Swipe Left detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-34: Radio Button Group Missing Default Selection
    if (/<input\b[^>]*type=["\']radio["\'](?![^>]*(?:checked|defaultChecked))/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<input\b[^>]*type=["\']radio["\'](?![^>]*(?:checked|defaultChecked))/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1234,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-34: Radio Button Group Missing Default Selection',
            severity: 'LOW',
            category: "Form Usability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected radio button group missing default checked selection: Radio button group rendered with none of the options selected by default"
            ],
            remediationPrompt: "Always initialize radio button groups with a sensible default selection.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-34: Radio Button Group Missing Default Selection detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-35: Checkbox Label Click Area Disconnected
    if (/<label\b(?![^>]*htmlFor)[^>]*>[\s\S]*?<\/label>\s*<input\b[^>]*type=["\']checkbox["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<label\b(?![^>]*htmlFor)[^>]*>[\s\S]*?<\/label>\s*<input\b[^>]*type=["\']checkbox["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1235,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-35: Checkbox Label Click Area Disconnected',
            severity: 'LOW',
            category: "Accessibility & Usability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected checkbox label disconnected from input id: Clicking checkbox label text does not toggle the checkbox"
            ],
            remediationPrompt: "Wrap input inside <label> or bind htmlFor explicitly to input id.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-35: Checkbox Label Click Area Disconnected detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-36: Auto-Complete Dropdown Obscuring Submit Button
    if (/autocomplete-dropdown|suggestions-menu/i.test(cleanContent) && !/max-h-|maxHeight/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/autocomplete-dropdown|suggestions-menu/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1236,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-36: Auto-Complete Dropdown Obscuring Submit Button',
            severity: 'LOW',
            category: "Mobile Form Usability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected autocomplete menu missing maxHeight constraint obscuring submit button: Browser autocomplete or custom suggestions menu covering the submit button"
            ],
            remediationPrompt: "Limit autocomplete dropdown max-height to 200px and ensure submit button remains visible.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-36: Auto-Complete Dropdown Obscuring Submit Button detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-37: Date Picker Missing Manual Text Input Fallback
    if (/datepicker|calendar-picker/i.test(lowerPath) && !/manualInput|allowTextInput/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && (/ui-interact-37|date/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1237,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-37: Date Picker Missing Manual Text Input Fallback',
            severity: 'LOW',
            category: "Accessibility & Usability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected date picker lacking manual keyboard text input mode: Calendar datepicker widget forcing user to click back 360 months to select birth year"
            ],
            remediationPrompt: "Provide direct text input masking or quick year/month dropdown jump selectors.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-37: Date Picker Missing Manual Text Input Fallback detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-38: Context Menu Trigger Colliding with Mobile Long-Press
    if (/onContextMenu/i.test(cleanContent) && !/onTouchHold|longPress|contextMenuButton/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/onContextMenu/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1238,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-38: Context Menu Trigger Colliding with Mobile Long-Press',
            severity: 'LOW',
            category: "Mobile Interaction",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected context menu relying strictly on right click without mobile long press: Custom right-click context menu failing to open or breaking on mobile devices"
            ],
            remediationPrompt: "Provide alternate action menu trigger button for mobile viewports.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-38: Context Menu Trigger Colliding with Mobile Long-Press detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-39: Missing Confirmation on Destructive Delete Actions
    if (/handleDelete|deleteProject|onDelete/i.test(cleanContent) && !/confirm|modal|isDeleteModalOpen|Prompt/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/handleDelete|deleteProject|onDelete/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1239,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-39: Missing Confirmation on Destructive Delete Actions',
            severity: 'LOW',
            category: "Data Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected destructive delete action executing without confirmation prompt: Clicking \"Delete Project\" executes immediate irreversible API deletion without confirmation"
            ],
            remediationPrompt: "Require explicit two-step confirmation or modal prompt for destructive deletions.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-39: Missing Confirmation on Destructive Delete Actions detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-40: Interactive Chart Missing Keyboard Accessible Data Table
    if (/<(?:ResponsiveContainer|BarChart|LineChart|PieChart)\b/i.test(cleanContent) && !/aria-label|role=["\']img["\']|summary|table/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<(?:ResponsiveContainer|BarChart|LineChart|PieChart)\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1240,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-40: Interactive Chart Missing Keyboard Accessible Data Table',
            severity: 'LOW',
            category: "Accessibility & WCAG",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected interactive data chart lacking accessible text or table alternative: Canvas / SVG data chart completely inaccessible to screen reader users"
            ],
            remediationPrompt: "Provide hidden or togglable tabular data alternative (role=\"table\") for all charts.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-40: Interactive Chart Missing Keyboard Accessible Data Table detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-41: Draggable Kanban / List Lacking Keyboard Reordering
    if (/Draggable|droppable/i.test(cleanContent) && !/dragHandleProps|keyboardEvents/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/Draggable|droppable/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1241,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-41: Draggable Kanban / List Lacking Keyboard Reordering',
            severity: 'LOW',
            category: "Accessibility & WCAG",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected draggable list items missing keyboard reorder affordance: Drag-and-drop items movable only with mouse; impossible with keyboard"
            ],
            remediationPrompt: "Support keyboard reordering via Space (grab) and Arrow keys (move).",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-41: Draggable Kanban / List Lacking Keyboard Reordering detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-42: Sticky Elements Overlapping Floating Action Buttons
    if (/fixed\s+bottom-(?:4|6|8)/i.test(cleanContent) && /sticky\s+bottom-0/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/fixed\s+bottom-(?:4|6|8)/i, /sticky\s+bottom-0/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1242,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-42: Sticky Elements Overlapping Floating Action Buttons',
            severity: 'LOW',
            category: "Layout & Stacking",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected fixed floating button colliding with sticky bottom bar: Sticky bottom bar and floating WhatsApp/help button colliding into a messy blob"
            ],
            remediationPrompt: "Coordinate positioning of sticky elements with CSS variables or shared layout state.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-42: Sticky Elements Overlapping Floating Action Buttons detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-43: Form Submission Resetting Cursor Position in Controlled Input
    if (/onChange\s*=\s*\{\s*\(e\)\s*=>\s*setValue\(e\.target\.value\.replace/i.test(cleanContent) && !/selectionStart/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/onChange\s*=\s*\{\s*\(e\)\s*=>\s*setValue\(e\.target\.value\.replace/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1243,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-43: Form Submission Resetting Cursor Position in Controlled Input',
            severity: 'LOW',
            category: "React State Hygiene",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected controlled input regex format jumping cursor to end on keystroke: Typing in controlled input jumps cursor to end of field on every keystroke"
            ],
            remediationPrompt: "Maintain cursor selection start/end indices during custom input formatters.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-43: Form Submission Resetting Cursor Position in Controlled Input detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-44: Broken Zoom Affordance on Pinch Gestures
    if (/user-scalable\s*=\s*no|maximum-scale\s*=\s*1(?:\.0)?\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/user-scalable\s*=\s*no|maximum-scale\s*=\s*1(?:\.0)?\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1244,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-44: Broken Zoom Affordance on Pinch Gestures',
            severity: 'LOW',
            category: "Mobile Usability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected meta viewport disabling accessibility pinch-to-zoom: Meta viewport tag containing user-scalable=no, disabling accessibility zoom"
            ],
            remediationPrompt: "Remove maximum-scale=1.0 and user-scalable=no from viewport metadata.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-44: Broken Zoom Affordance on Pinch Gestures detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-45: Unresponsive Action Sheet Close Gesture
    if (/bottom-sheet|actionsheet/i.test(lowerPath) && !/dragHandle|onDragEnd/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && (/ui-interact-45|unresponsive/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1245,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-45: Unresponsive Action Sheet Close Gesture',
            severity: 'LOW',
            category: "Mobile UX",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected bottom sheet lacking drag-down dismiss gesture: Bottom sheet dialog closing only on tiny X button, ignoring down-drag gesture"
            ],
            remediationPrompt: "Implement drag-down gesture listener to dismiss bottom sheets naturally.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-45: Unresponsive Action Sheet Close Gesture detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-46: Missing Empty State Action Button
    if (/No\s*(?:items|results|data)\s*found/i.test(cleanContent) && !/<button\b|<Link\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/No\s*(?:items|results|data)\s*found/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1246,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-46: Missing Empty State Action Button',
            severity: 'LOW',
            category: "Empty State UX",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected empty state missing primary call-to-action button: Empty state displays \"No items found\" with zero call-to-action button"
            ],
            remediationPrompt: "Provide primary action button (\"Create New Item\") inside all empty states.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-46: Missing Empty State Action Button detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-47: Animated Counter Freezing on Rapid Page Scroll
    if (/useCountUp|requestAnimationFrame/i.test(cleanContent) && !/cancelAnimationFrame|clean/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/useCountUp|requestAnimationFrame/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1247,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-47: Animated Counter Freezing on Rapid Page Scroll',
            severity: 'LOW',
            category: "Animation Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected animation counter missing cancelAnimationFrame on unmount: Count-up animation script crashing or locking up if user scrolls past rapidly"
            ],
            remediationPrompt: "Clean up animation frame timers on component unmount and handle fast scrolling.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-47: Animated Counter Freezing on Rapid Page Scroll detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-48: Multi-Step Wizard Lacking Step History Navigation
    if (/step|wizard/i.test(lowerPath) && /currentStep/i.test(cleanContent) && !/history|hash|pushState|replaceState/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/currentStep/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1248,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-48: Multi-Step Wizard Lacking Step History Navigation',
            severity: 'LOW',
            category: "Wizard UX",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected multi-step wizard lacking browser history synchronization: Browser back button leaves entire multi-step wizard rather than going to previous step"
            ],
            remediationPrompt: "Sync wizard step changes with shallow URL query or history state.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-48: Multi-Step Wizard Lacking Step History Navigation detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-49: Unescaped Error Message Rendering in UI Alert
    if (/<(?:Alert|Badge|p)\b[^>]*>\{error\.message\}<\//i.test(cleanContent) && !/sanitize|userMessage/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<(?:Alert|Badge|p)\b[^>]*>\{error\.message\}<\//i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1249,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-49: Unescaped Error Message Rendering in UI Alert',
            severity: 'LOW',
            category: "Security & UX",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected raw backend error.message rendered directly in user-facing UI: Displaying raw backend stack traces or database errors directly in user alert banners"
            ],
            remediationPrompt: "Map internal errors to user-friendly messages and log raw errors privately.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-49: Unescaped Error Message Rendering in UI Alert detected (${file.path}:${lineNum})`);
    }
    // UI-INTERACT-50: Scanner Countdown Missing Zero-Second Transition
    if (/countdownSeconds\s*===?\s*0\b/i.test(cleanContent) && !/onComplete|completeScan|router\.push/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/countdownSeconds\s*===?\s*0\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1250,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-50: Scanner Countdown Missing Zero-Second Transition',
            severity: 'LOW',
            category: "Workflow Automation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || '<detected interaction flaw>',
            reproductionSteps: [
                `Scanned component interaction handlers in ${file.path}:${lineNum}.`,
                "Detected scanner countdown timer reaching zero without auto-transition: Countdown reaches 0s and hangs indefinitely without triggering auto-completion"
            ],
            remediationPrompt: "Invoke completion callback immediately when countdown hits zero.",
            status: 'OPEN',
            owner: 'UI Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🖱️ UI-INTERACT-50: Scanner Countdown Missing Zero-Second Transition detected (${file.path}:${lineNum})`);
    }
    return { findings, logs };
}
