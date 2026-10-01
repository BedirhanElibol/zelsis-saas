/**
* Zelsis No-AI-Slop & Human Voice Rules Engine (20+ Patterns)
* Source Inspiration: https://github.com/petergyang/no-ai-slop
*
* Rules:
* 1. COPY-SLOP-01 (Rule ID 25011 - LOW): Banned AI Fluff & Buzzword Lexicon in User-Facing UI Copy
* 2. COPY-SLOP-02 (Rule ID 25012 - LOW): AI Binary Contrast & Faux-Insight Headline Patterns
* 3. UI-CLICHE-04 (Rule ID 25013 - LOW): Misplaced Sparkles/Wand Icon on Non-Generative Actions
*/
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
export interface NoAiSlopRuleResult {
    findings: Finding[];
    logs: string[];
}
// Exact banned lexicon per no-ai-slop specification
const BANNED_AI_WORDS = [
    'delve',
    'foster',
    'leverage',
    'utilize',
    'streamline',
    'cutting-edge',
    'paradigm shift',
    'game changer',
    'tapestry',
    'realm',
    'beacon',
    'supercharge',
    'harness',
    'ever-evolving',
    'empower',
    'transformative'
];
export function evaluateNoAiSlopRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): NoAiSlopRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip pure backend code, schemas, catalogs, mocks, and agents
    // Edge Case: Only evaluate frontend components (.tsx, .jsx, .html) and documentation (.md)
    const isEligibleFile = lowerPath.endsWith('.tsx') ||
        lowerPath.endsWith('.jsx') ||
        lowerPath.endsWith('.html') ||
        (lowerPath.endsWith('.md') && !lowerPath.includes('plan.md') && !lowerPath.includes('architecture.md'));
    if (!isEligibleFile)
        return { findings, logs };
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts') || lowerPath.includes('rules/')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // =========================================================================
    // 1. COPY-SLOP-01: Banned AI Fluff & Buzzword Lexicon in UI Copy
    // =========================================================================
    for (const word of BANNED_AI_WORDS) {
        // Regex matching the word as a discrete token inside JSX text or quotes
        const wordRegex = new RegExp(`(?:>|["'\`])\\s*[^<"'\`]*\\b${word}\\b`, 'i');
        if (wordRegex.test(cleanContent)) {
            const lineIdx = lines.findIndex(l => !l.trim().startsWith('//') &&
                !l.trim().startsWith('*') &&
                new RegExp(`\\b${word}\\b`, 'i').test(l) &&
                !/import\s+|from\s+["']/.test(l));
            if (lineIdx !== -1) {
                const lineNum = lineIdx + 1;
                const matchedLine = lines[lineIdx];
                findings.push({
                    id: `slop-lexicon-${word}-${Date.now()}-${findingCounter.count++}`,
                    ruleId: 25011,
                    type: 'VIBEPOLISH',
                    title: `COPY-SLOP-01: Banned AI Buzzword "${word}" Detected in UI Copy`,
                    severity: 'LOW',
                    category: 'Text & Copywriting',
                    filePath: file.path,
                    lineRange: `L${lineNum}`,
                    snippet: matchedLine.trim(),
                    reproductionSteps: [
                        `Audited user-facing copy in ${file.path}:${lineNum}.`,
                        `Detected banned AI-slop filler word: "${word}".`,
                        'Generic buzzwords flatten authentic product tone and read as low-effort AI generation (per Peter Yang No-AI-Slop guide).'
                    ],
                    remediationPrompt: `Replace buzzword "${word}" in ${file.path}:${lineNum} with concrete, direct verbs and metrics (e.g. use "builds", "runs in 4s", "connects", "automates").`,
                    status: 'OPEN',
                    owner: 'Content & UI Lead',
                    falsePositive: false
                });
                logs.push(`[${ts}] [NO-AI-SLOP] Banned AI buzzword "${word}" found in ${file.path}:${lineNum}`);
                break; // Max 1 finding per file to avoid flooding
            }
        }
    }
    // =========================================================================
    // 2. COPY-SLOP-02: Binary Contrast & Faux-Insight Headline Patterns
    // =========================================================================
    const binaryContrastPattern = /(?:it'?s\s+not\s+[^.!?]+[.]\s*it'?s\s+|the\s+question\s+isn'?t\s+[^.!?]+,\s*it'?s\s+|what\s+nobody\s+tells\s+you\s+is|the\s+part\s+everyone\s+misses)/i;
    if (binaryContrastPattern.test(cleanContent)) {
        const lineIdx = lines.findIndex(l => !l.trim().startsWith('//') &&
            !l.trim().startsWith('*') &&
            binaryContrastPattern.test(l));
        if (lineIdx !== -1) {
            const lineNum = lineIdx + 1;
            const matchedLine = lines[lineIdx];
            findings.push({
                id: `slop-contrast-${Date.now()}-${findingCounter.count++}`,
                ruleId: 25012,
                type: 'VIBEPOLISH',
                title: 'COPY-SLOP-02: AI Binary Contrast / Faux-Insight Headline Pattern',
                severity: 'LOW',
                category: 'Text & Copywriting',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: matchedLine.trim(),
                reproductionSteps: [
                    `Scanned headline / paragraph copy in ${file.path}:${lineNum}.`,
                    'Detected formulaic AI binary contrast ("It\'s not X. It\'s Y.") or faux-insight opener ("What nobody tells you is...").',
                    'These patterns produce synthetic drama instead of direct, authoritative engineering communication.'
                ],
                remediationPrompt: `Eliminate artificial binary contrast in ${file.path}:${lineNum}. State the actual value proposition directly in a single declarative sentence.`,
                status: 'OPEN',
                owner: 'Content & UI Lead',
                falsePositive: false
            });
            logs.push(`[${ts}] [NO-AI-SLOP] Formulaic AI contrast pattern found in ${file.path}:${lineNum}`);
        }
    }
    // =========================================================================
    // 3. UI-CLICHE-04: Misplaced Sparkles/Wand Icon on Non-Generative Actions
    // =========================================================================
    const hasSparklesImport = /import\s*\{[^}]*(?:Sparkles|Wand2)[^}]*\}\s*from\s*['"]lucide-react['"]/i.test(cleanContent);
    if (hasSparklesImport) {
        // Check if Sparkles or Wand2 is paired with non-AI buttons
        const nonAiButtonWithSparkles = /<button[^>]*>[\s\S]*?<(?:Sparkles|Wand2)\b[\s\S]*?(?:Save|Submit|Export|Download|Delete|Filter|Search|Sign\s*in|Log\s*in)[\s\S]*?<\/button>/i;
        if (nonAiButtonWithSparkles.test(cleanContent)) {
            const lineIdx = lines.findIndex(l => /<(?:Sparkles|Wand2)\b/i.test(l) ||
                (/<button/i.test(l) && /(?:Save|Submit|Export|Download|Filter)/i.test(l)));
            const lineNum = lineIdx !== -1 ? lineIdx + 1 : 1;
            findings.push({
                id: `slop-sparkles-${Date.now()}-${findingCounter.count++}`,
                ruleId: 25013,
                type: 'VIBEPOLISH',
                title: 'UI-CLICHE-04: Misplaced Sparkles Icon on Non-Generative Action Trigger',
                severity: 'LOW',
                category: 'UI Engineering Standards',
                filePath: file.path,
                lineRange: `L${lineNum}`,
                snippet: lines[lineIdx]?.trim() || '<button><Sparkles /> Save</button>',
                reproductionSteps: [
                    `Audited interactive button triggers in ${file.path}:${lineNum}.`,
                    'Detected Lucide Sparkles/Wand2 icon placed on a standard deterministic action (Save, Export, Filter, Submit).',
                    'Violates UI Engineering Standard Rule 10: "Do not place 4-pointed Lucide Sparkles icons on non-generative-AI buttons."'
                ],
                remediationPrompt: `Replace Sparkles icon in ${file.path}:${lineNum} with a semantic functional icon (e.g. Save, Download, Filter) or remove the decorative icon.`,
                status: 'OPEN',
                owner: 'UI Architect',
                falsePositive: false
            });
            logs.push(`[${ts}] [NO-AI-SLOP] Misplaced Sparkles icon detected in ${file.path}:${lineNum}`);
        }
    }
    return { findings, logs };
}
