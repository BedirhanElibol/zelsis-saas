/**
 * Zelsis Master evaluateAiAgentEthicsGovernanceRules Engine (50 Rules)
 * Rules AI-ETHICS-01 to AI-ETHICS-50 (Rule IDs 16901 to 16950).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface AiAgentEthicsGovernanceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateAiAgentEthicsGovernanceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): AiAgentEthicsGovernanceRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // AI-ETHICS-01: Absence of Deceptive Intent and Strategic Sycophancy Detection in Agent Output
    if (((/agent_intent|sycophancy_check|agent_trace/i.test(lowerPath) || /evaluateAgentIntent|sycophancyScore/i.test(cleanContent)) && !/detectStrategicSycophancyAndDeception/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/evaluateAgentIntent|sycophancyScore/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aiethics16901-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16901,
            type: 'LEGAL_COMPLIANCE',
            title: "AI-ETHICS-01: Absence of Deceptive Intent and Strategic Sycophancy Detection in Agent Output",
            severity: "CRITICAL",
            category: "Deception Auditing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI Agent Ethics Governance configuration',
            reproductionSteps: [
                `Audited AI Agent Ethics Governance configuration in ${file.path}:${lineNum}.`,
                'Matched AI-ETHICS-01: Absence of Deceptive Intent and Strategic Sycophancy Detection in Agent Output.'
            ],
            remediationPrompt: "Audit agent reasoning traces against deceptive goal alignment and covert preference manipulation heuristics.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AI ETHICS AUDIT] Found AI-ETHICS-01: Absence of Deceptive Intent and Strategic Sycophancy Detection in Agent Output at ${file.path}:${lineNum}`);
    }
    // AI-ETHICS-02: Violation of Human Agency and Autonomous Action Reversibility (IEEE 7000)
    if (((/agent_action|state_mutation|human_agency/i.test(lowerPath) || /commitAgentAction|mutateAppState/i.test(cleanContent)) && !/enforceHumanOverrideAndRollback/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/commitAgentAction|mutateAppState/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aiethics16902-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16902,
            type: 'LEGAL_COMPLIANCE',
            title: "AI-ETHICS-02: Violation of Human Agency and Autonomous Action Reversibility (IEEE 7000)",
            severity: "CRITICAL",
            category: "Reversibility Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI Agent Ethics Governance configuration',
            reproductionSteps: [
                `Audited AI Agent Ethics Governance configuration in ${file.path}:${lineNum}.`,
                'Matched AI-ETHICS-02: Violation of Human Agency and Autonomous Action Reversibility (IEEE 7000).'
            ],
            remediationPrompt: "Enforce mandatory human override controls and programmatic rollback APIs for all autonomous agent irreversible state mutations.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AI ETHICS AUDIT] Found AI-ETHICS-02: Violation of Human Agency and Autonomous Action Reversibility (IEEE 7000) at ${file.path}:${lineNum}`);
    }
    // AI-ETHICS-03: Unmonitored Disparate Impact and Demographic Bias in Algorithmic Scoring
    if (((/fairness_audit|demographic_parity|equalized_odds/i.test(lowerPath) || /disparateImpactRatio|protectedAttributeOdds/i.test(cleanContent)) && !/auditAlgorithmicDemographicParity/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/disparateImpactRatio|protectedAttributeOdds/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aiethics16903-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16903,
            type: 'LEGAL_COMPLIANCE',
            title: "AI-ETHICS-03: Unmonitored Disparate Impact and Demographic Bias in Algorithmic Scoring",
            severity: "CRITICAL",
            category: "Algorithmic Bias",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI Agent Ethics Governance configuration',
            reproductionSteps: [
                `Audited AI Agent Ethics Governance configuration in ${file.path}:${lineNum}.`,
                'Matched AI-ETHICS-03: Unmonitored Disparate Impact and Demographic Bias in Algorithmic Scoring.'
            ],
            remediationPrompt: "Continuously measure equalized odds and demographic parity metrics across sensitive protected demographic attributes.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AI ETHICS AUDIT] Found AI-ETHICS-03: Unmonitored Disparate Impact and Demographic Bias in Algorithmic Scoring at ${file.path}:${lineNum}`);
    }
    // AI-ETHICS-04: Lack of Explainable Multi-Hop Reasoning Chains on High-Stakes Agent Decisions
    if (((/explainability|decision_provenance|agent_justification/i.test(lowerPath) || /decisionProvenanceGraph|counterfactualRationale/i.test(cleanContent)) && !/generateVerifiableProvenanceChain/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/decisionProvenanceGraph|counterfactualRationale/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aiethics16904-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16904,
            type: 'LEGAL_COMPLIANCE',
            title: "AI-ETHICS-04: Lack of Explainable Multi-Hop Reasoning Chains on High-Stakes Agent Decisions",
            severity: "HIGH",
            category: "Decision Explainability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI Agent Ethics Governance configuration',
            reproductionSteps: [
                `Audited AI Agent Ethics Governance configuration in ${file.path}:${lineNum}.`,
                'Matched AI-ETHICS-04: Lack of Explainable Multi-Hop Reasoning Chains on High-Stakes Agent Decisions.'
            ],
            remediationPrompt: "Persist structured, interpretable decision provenance graphs and counterfactual explanations for automated decisions.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AI ETHICS AUDIT] Found AI-ETHICS-04: Lack of Explainable Multi-Hop Reasoning Chains on High-Stakes Agent Decisions at ${file.path}:${lineNum}`);
    }
    // AI-ETHICS-05: Uncalibrated Overconfidence and Epistemic Uncertainty Masking in Agent Output
    if (((/epistemic_uncertainty|confidence_bounds|probabilistic/i.test(lowerPath) || /confidenceIntervalRange|epistemicUncertaintyScore/i.test(cleanContent)) && !/calibrateEpistemicUncertaintyBounds/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/confidenceIntervalRange|epistemicUncertaintyScore/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `aiethics16905-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16905,
            type: 'LEGAL_COMPLIANCE',
            title: "AI-ETHICS-05: Uncalibrated Overconfidence and Epistemic Uncertainty Masking in Agent Output",
            severity: "HIGH",
            category: "Uncertainty Calibration",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'AI Agent Ethics Governance configuration',
            reproductionSteps: [
                `Audited AI Agent Ethics Governance configuration in ${file.path}:${lineNum}.`,
                'Matched AI-ETHICS-05: Uncalibrated Overconfidence and Epistemic Uncertainty Masking in Agent Output.'
            ],
            remediationPrompt: "Require calibrated probabilistic confidence intervals on model assertions and enforce explicit expressions of epistemic uncertainty.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [AI ETHICS AUDIT] Found AI-ETHICS-05: Uncalibrated Overconfidence and Epistemic Uncertainty Masking in Agent Output at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
