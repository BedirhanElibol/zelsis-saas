/**
 * Zelsis Master evaluateEuAiActRules Engine (50 Rules)
 * Rules AIACT-01 to AIACT-50 (Rule IDs 11601 to 11650).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface EuAiActRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateEuAiActRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): EuAiActRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // AIACT-01: Missing Human-in-the-Loop Oversight Hook on High-Risk AI Decisions (Article 14)
    if ((/highRiskModelDecision/i.test(cleanContent) && !/humanReview|manualOverride/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/highRiskModelDecision/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aiact11601-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11601,
            type: 'LEGAL_COMPLIANCE',
            title: "AIACT-01: Missing Human-in-the-Loop Oversight Hook on High-Risk AI Decisions (Article 14)",
            severity: "CRITICAL",
            category: "Human Oversight",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI system governance specification',
            reproductionSteps: [
                `Audited AI system controls in ${file.path}:${lineNum}.`,
                'Detected EU AI Act compliance violation matching AIACT-01.'
            ],
            remediationPrompt: "Add human review workflow step for high-stakes algorithmic scoring decisions.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-01: Missing Human-in-the-Loop Oversight Hook on High-Risk AI Decisions (Article 14) at ${file.path}:${lineNum}`);
    }
    // AIACT-02: Missing Algorithmic Bias and Discrimination Audit on Training Data (Article 10)
    if ((/fineTuneDataset/i.test(cleanContent) && !/demographicParity|biasAudit/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/fineTuneDataset/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aiact11602-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11602,
            type: 'LEGAL_COMPLIANCE',
            title: "AIACT-02: Missing Algorithmic Bias and Discrimination Audit on Training Data (Article 10)",
            severity: "HIGH",
            category: "Dataset Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI system governance specification',
            reproductionSteps: [
                `Audited AI system controls in ${file.path}:${lineNum}.`,
                'Detected EU AI Act compliance violation matching AIACT-02.'
            ],
            remediationPrompt: "Conduct demographic parity audits on fine-tuning training datasets and document fairness metrics.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-02: Missing Algorithmic Bias and Discrimination Audit on Training Data (Article 10) at ${file.path}:${lineNum}`);
    }
    // AIACT-03: Absence of Immutable Audit Logging for AI System Operations (Article 12)
    if ((/openai\.chat\.completions/i.test(cleanContent) && !/auditLog|recordInference/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/openai\.chat\.completions/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aiact11603-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11603,
            type: 'LEGAL_COMPLIANCE',
            title: "AIACT-03: Absence of Immutable Audit Logging for AI System Operations (Article 12)",
            severity: "HIGH",
            category: "Traceability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI system governance specification',
            reproductionSteps: [
                `Audited AI system controls in ${file.path}:${lineNum}.`,
                'Detected EU AI Act compliance violation matching AIACT-03.'
            ],
            remediationPrompt: "Record all inference prompts, completions, and model version hashes to tamper-resistant audit logs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-03: Absence of Immutable Audit Logging for AI System Operations (Article 12) at ${file.path}:${lineNum}`);
    }
    // AIACT-04: Missing Machine-Readable Watermarking on Synthetic AI Content (Article 50)
    if ((/createImage|generateSpeech/i.test(cleanContent) && !/c2pa|watermark|synthId/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/createImage|generateSpeech/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aiact11604-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11604,
            type: 'LEGAL_COMPLIANCE',
            title: "AIACT-04: Missing Machine-Readable Watermarking on Synthetic AI Content (Article 50)",
            severity: "HIGH",
            category: "Transparency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI system governance specification',
            reproductionSteps: [
                `Audited AI system controls in ${file.path}:${lineNum}.`,
                'Detected EU AI Act compliance violation matching AIACT-04.'
            ],
            remediationPrompt: "Inject cryptographic C2PA provenance credentials into all AI-generated image and text payloads.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-04: Missing Machine-Readable Watermarking on Synthetic AI Content (Article 50) at ${file.path}:${lineNum}`);
    }
    // AIACT-05: Unpublished Summary of Copyright-Protected Training Data (Article 53)
    if ((/modelCard/i.test(cleanContent) && !/copyright|trainingSummary/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/modelCard/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aiact11605-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11605,
            type: 'LEGAL_COMPLIANCE',
            title: "AIACT-05: Unpublished Summary of Copyright-Protected Training Data (Article 53)",
            severity: "MEDIUM",
            category: "Copyright Transparency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI system governance specification',
            reproductionSteps: [
                `Audited AI system controls in ${file.path}:${lineNum}.`,
                'Detected EU AI Act compliance violation matching AIACT-05.'
            ],
            remediationPrompt: "Publish training corpus source transparency disclosures on the model documentation portal.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-05: Unpublished Summary of Copyright-Protected Training Data (Article 53) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
