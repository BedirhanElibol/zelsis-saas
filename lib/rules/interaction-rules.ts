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
    /** 0-based line of the first match of a (possibly multi-line) pattern in cleanContent; -1 when absent. */
    const lineOfMatch = (re: RegExp): number => {
        const m = new RegExp(re.source, re.flags.replace(/[gy]/g, '')).exec(cleanContent);
        return m ? cleanContent.slice(0, m.index).split('\n').length - 1 : -1;
    };
    /** 0-based line of the first <name ...> tag satisfying `pred` (`=>` in JSX attributes does not end the tag). */
    const findTagLine = (name: string, pred: (tag: string) => boolean): number => {
        const re = new RegExp(`<${name}\\b(?:=>|[^>=]|=(?!>))*>`, 'gi');
        for (let m = re.exec(cleanContent); m; m = re.exec(cleanContent)) {
            if (pred(m[0])) return cleanContent.slice(0, m.index).split('\n').length - 1;
        }
        return -1;
    };
    // Headless / component libraries (Radix, shadcn ui, Headless UI, vaul, react-aria...) ship dismissal,
    // focus trapping, Escape handling and aria-expanded themselves: their wrappers are not custom widgets.
    const usesHeadlessUi = /from\s+['"](?:@radix-ui\/|@headlessui\/|vaul['"]|react-aria|@ark-ui\/|@reach\/|@mui\/|@chakra-ui\/|@mantine\/|antd['"]|@\/components\/ui\/)/.test(cleanContent);
    // UI-INTERACT-01: Modal Overlay Missing Backdrop Click Dismissal
    if (!usesHeadlessUi && /fixed\s+inset-0|role=["\']dialog["\']/i.test(cleanContent) && !/target\s*===\s*(?:\w+\.)?currentTarget|onBackdropClick|backdrop/i.test(cleanContent) && /modal|dialog/i.test(lowerPath)) {
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
    if (!usesHeadlessUi && /fixed\s+inset-0|role=["\']dialog["\']/i.test(cleanContent) && !/Escape|keydown/i.test(cleanContent) && /modal|dialog/i.test(lowerPath)) {
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
    if (!usesHeadlessUi && /role=["\']dialog["\']/i.test(cleanContent) && !/FocusTrap|focus-trap|autoFocus/i.test(cleanContent) && /modal|dialog/i.test(lowerPath) && (cleanContent.match(/<input\b/gi) || []).length > 2) {
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
    // A button whose label is swapped for a spinner while its opening tag sets no fixed / minimum width.
    let shiftingButtonIdx = -1;
    const spinnerSwap = /<button\b((?:=>|[^>=]|=(?!>))*)>(?:(?!<\/button>)[\s\S])*?\{\s*(?:loading|isSubmitting|isPending)\s*\?\s*<Spinner/gi;
    for (let m = spinnerSwap.exec(cleanContent); m; m = spinnerSwap.exec(cleanContent)) {
        if (!/\bmin-w-|\bw-(?:\d|\[)/.test(m[1])) { shiftingButtonIdx = cleanContent.slice(0, m.index).split('\n').length - 1; break; }
    }
    if (shiftingButtonIdx !== -1) {
        const matchLineIdx = shiftingButtonIdx;
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
        const matchLineIdx = lineOfMatch(/<button\b[^>]*\btype=["']submit["']/i);
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
    if (!usesHeadlessUi && /accordion|collapsible/i.test(cleanContent) && /<button\b/i.test(cleanContent) && !/aria-expanded/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<button\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
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
    // UI-INTERACT-16: Dropdown Menu Leaking on Outside Document Click
    if (!usesHeadlessUi && /dropdown|menu/i.test(lowerPath) && /isOpen|setIsOpen/i.test(cleanContent) && !/mousedown|pointerdown|outside|useClickOutside/i.test(cleanContent)) {
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
    // UI-INTERACT-20: Unannounced Dynamic Toast / Alert Notifications
    if (lowerPath.startsWith('components/') && (lowerPath.includes('toast') || lowerPath.includes('alert')) && !lowerPath.includes('setting') && !lowerPath.includes('modal') && file.path.endsWith('.tsx') && !/role=["\']status["\']|role=["\']alert["\']|aria-live/i.test(cleanContent) &&
        !/from\s+['"](?:sonner|react-hot-toast|react-toastify|@radix-ui\/react-toast|notistack)['"]/.test(cleanContent) && !usesHeadlessUi) {
        const matchLineIdx = locateMatchLine(lines, [/(?:function|const)\s+\w*(?:Toast|Alert)\w*/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
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
        const nestedIdx = [lineOfMatch(/<button\b[^>]*>(?:(?!<\/button>)[\s\S])*?<button\b/i), lineOfMatch(/<a\b[^>]*>(?:(?!<\/a>)[\s\S])*?<button\b/i)].filter(i => i !== -1);
        const matchLineIdx = nestedIdx.length ? Math.min(...nestedIdx) : -1;
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
    // UI-INTERACT-25: Unchecked File Upload Size and Type Traps
    const fileInputIdx = findTagLine('input', tag => /\btype=["\']file["\']/i.test(tag) && !/\baccept=|maxSize/i.test(tag));
    if (fileInputIdx !== -1) {
        const matchLineIdx = fileInputIdx;
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
    // UI-INTERACT-31: Slider / Range Input Missing Numeric Value Label
    // A range input whose own tag carries no accessible name (aria-label / aria-labelledby / id for <label htmlFor>)
    // and no aria-valuetext: screen readers announce a bare number with no meaning.
    // Tag scan treats `=>` inside JSX attribute arrows as part of the tag, not its end.
    const unlabeledRangeTag = (cleanContent.match(/<input\b(?:=>|[^>=]|=(?!>))*>/gi) || []).find(tag => /\btype=["\']range["\']/i.test(tag) && !/\baria-(?:label|labelledby|valuetext)\b|\bid=/i.test(tag));
    if (unlabeledRangeTag) {
        const matchLineIdx = cleanContent.slice(0, cleanContent.indexOf(unlabeledRangeTag)).split('\n').length - 1;
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
    const autoPlayIdx = findTagLine('video', tag => /\bautoPlay\b/i.test(tag) && !/\bmuted\b/i.test(tag));
    if (autoPlayIdx !== -1) {
        const matchLineIdx = autoPlayIdx;
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
    // UI-INTERACT-35: Checkbox Label Click Area Disconnected
    if (/<label\b(?![^>]*htmlFor)[^>]*>[\s\S]*?<\/label>\s*<input\b[^>]*type=["\']checkbox["\']/i.test(cleanContent)) {
        const matchLineIdx = lineOfMatch(/<label\b(?![^>]*htmlFor)[^>]*>[\s\S]*?<\/label>\s*<input\b[^>]*type=["\']checkbox["\']/i);
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
    // UI-INTERACT-40: Interactive Chart Missing Keyboard Accessible Data Table
    if (/<(?:ResponsiveContainer|BarChart|LineChart|PieChart)\b/i.test(cleanContent) && !/aria-label|role=["\']img["\']|summary|table|accessibilityLayer/i.test(cleanContent)) {
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
    // dnd-kit: sensors registered for pointer / mouse / touch only, no KeyboardSensor -> mouse-only reordering.
    // react-beautiful-dnd / hello-pangea: <Draggable> whose handle props are never spread (no keyboard lift).
    const pointerOnlyDndKit = /useSensors?\s*\(/.test(cleanContent) && /\b(?:Pointer|Mouse|Touch)Sensor\b/.test(cleanContent) && !/\bKeyboardSensor\b/.test(cleanContent);
    const rbdWithoutHandle = /<Draggable\b/.test(cleanContent) && /from\s+['"](?:react-beautiful-dnd|@hello-pangea\/dnd)['"]/.test(cleanContent) && !/dragHandleProps/.test(cleanContent);
    if (pointerOnlyDndKit || rbdWithoutHandle) {
        const matchLineIdx = locateMatchLine(lines, [pointerOnlyDndKit ? /useSensors?\s*\(/ : /<Draggable\b/], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
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
    // Meta viewport string, or the Next.js `export const viewport` object form.
    const zoomLock = /user-scalable\s*=\s*(?:no|0)\b|maximum-scale\s*=\s*1(?:\.0)?\b|\buserScalable\s*:\s*false\b|\bmaximumScale\s*:\s*1(?:\.0)?\b/i;
    if (zoomLock.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [zoomLock], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `interact-${Date.now()}-${findingCounter.count++}`,
            ruleId: 1244,
            type: 'VIBEPOLISH',
            title: 'UI-INTERACT-44: Viewport Blocks Zoom (WCAG 1.4.4 Resize Text)',
            severity: 'HIGH',
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
    // UI-INTERACT-47: Animated Counter Freezing on Rapid Page Scroll
    // An animation-frame loop started from an effect that never cancels it keeps running after unmount.
    if (/\brequestAnimationFrame\s*\(/.test(cleanContent) && /\buseEffect\s*\(/.test(cleanContent) && !/\bcancelAnimationFrame\b/.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/\brequestAnimationFrame\s*\(/], l => !l.trim().startsWith('//') && !l.trim().startsWith('*'));
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
    return { findings, logs };
}
