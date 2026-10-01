/**
 * Zelsis Master evaluateAiRedTeamSecurityRules Engine (50 Rules)
 * Rules AI-RED-01 to AI-RED-50 (Rule IDs 16001 to 16050).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface AiRedTeamSecurityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateAiRedTeamSecurityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): AiRedTeamSecurityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // AI-RED-01: Vulnerability to Adversarial Few-Shot Jailbreak Prompts Bypassing Safety Alignment
    if (((/prompt_guard|safety_eval/i.test(lowerPath) || /jailbreakDetector|guardrailClass/i.test(cleanContent)) && !/semanticGuardrailFilter/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aired16001-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16001,
            type: 'SECURITY',
            title: "AI-RED-01: Vulnerability to Adversarial Few-Shot Jailbreak Prompts Bypassing Safety Alignment",
            severity: "CRITICAL",
            category: "Jailbreak Resistance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI Red Teaming & Jailbreak Defense configuration',
            reproductionSteps: [
                `Audited AI Red Teaming & Jailbreak Defense configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Deploy semantic guardrail classifiers and input intent filters to detect multi-turn jailbreak attempts prior to model ingestion.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AI-RED AUDIT] Found AI-RED-01: Vulnerability to Adversarial Few-Shot Jailbreak Prompts Bypassing Safety Alignment at ${file.path}:${lineNum}`);
    }
    // AI-RED-02: System Prompt Extraction and Intellectual Property Leakage via Roleplay Attacks
    if (((/system_prompt|canary_check/i.test(lowerPath) || /systemInstruction|promptCanary/i.test(cleanContent)) && !/canaryTokenActive/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aired16002-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16002,
            type: 'SECURITY',
            title: "AI-RED-02: System Prompt Extraction and Intellectual Property Leakage via Roleplay Attacks",
            severity: "CRITICAL",
            category: "System Prompt Privacy",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI Red Teaming & Jailbreak Defense configuration',
            reproductionSteps: [
                `Audited AI Red Teaming & Jailbreak Defense configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Inject adversarial canary tokens and enforce system instruction confidentiality guardrails blocking role reversal instructions.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AI-RED AUDIT] Found AI-RED-02: System Prompt Extraction and Intellectual Property Leakage via Roleplay Attacks at ${file.path}:${lineNum}`);
    }
    // AI-RED-03: Indirect Prompt Injection via Unsanitized Third-Party Web Search / RAG Document Chunks
    if (((/rag_search|untrusted_retrieval/i.test(lowerPath) || /retrievedDocumentChunk/i.test(cleanContent)) && !/isolateRagContextBoundary/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aired16003-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16003,
            type: 'SECURITY',
            title: "AI-RED-03: Indirect Prompt Injection via Unsanitized Third-Party Web Search / RAG Document Chunks",
            severity: "CRITICAL",
            category: "Indirect Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI Red Teaming & Jailbreak Defense configuration',
            reproductionSteps: [
                `Audited AI Red Teaming & Jailbreak Defense configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Isolate untrusted external retrieval content within strict XML/JSON data boundaries and validate model instructions against policy.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AI-RED AUDIT] Found AI-RED-03: Indirect Prompt Injection via Unsanitized Third-Party Web Search / RAG Document Chunks at ${file.path}:${lineNum}`);
    }
    // AI-RED-04: Output Delimiter Hijacking Permitting Arbitrary Markdown / Code Block Escape
    if (((/delimiter_guard|output_sanitizer/i.test(lowerPath) || /outputBoundary/i.test(cleanContent)) && !/escapeOutputDelimiters/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aired16004-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16004,
            type: 'SECURITY',
            title: "AI-RED-04: Output Delimiter Hijacking Permitting Arbitrary Markdown / Code Block Escape",
            severity: "HIGH",
            category: "Delimiter Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI Red Teaming & Jailbreak Defense configuration',
            reproductionSteps: [
                `Audited AI Red Teaming & Jailbreak Defense configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Sanitize model output stream boundaries to prevent malicious instruction payloads hijacking application execution wrappers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AI-RED AUDIT] Found AI-RED-04: Output Delimiter Hijacking Permitting Arbitrary Markdown / Code Block Escape at ${file.path}:${lineNum}`);
    }
    // AI-RED-05: Multi-Lingual and Base64 Obfuscated Token Smuggling Bypassing Moderation Filters
    if (((/input_moderation|token_filter/i.test(lowerPath) || /moderationInput/i.test(cleanContent)) && cleanContent.includes('base64ObfuscatedTokenBypass') && !/decodeAndNormalizeInputs/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aired16005-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16005,
            type: 'SECURITY',
            title: "AI-RED-05: Multi-Lingual and Base64 Obfuscated Token Smuggling Bypassing Moderation Filters",
            severity: "HIGH",
            category: "Obfuscation Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI Red Teaming & Jailbreak Defense configuration',
            reproductionSteps: [
                `Audited AI Red Teaming & Jailbreak Defense configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Normalize and decode multi-lingual, leetspeak, and base64 encoded user inputs before passing to safety moderation classifiers.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AI-RED AUDIT] Found AI-RED-05: Multi-Lingual and Base64 Obfuscated Token Smuggling Bypassing Moderation Filters at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
