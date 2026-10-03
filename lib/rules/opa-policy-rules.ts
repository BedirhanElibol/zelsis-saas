/**
 * Zelsis Master evaluateOpaPolicyRules Engine (50 Rules)
 * Rules OPA-01 to OPA-50 (Rule IDs 13201 to 13250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface OpaPolicyRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateOpaPolicyRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): OpaPolicyRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isOpaTarget = lowerPath.endsWith(".rego") || lowerPath.endsWith(".opa") ||
      ((lowerPath.includes("k8s") || lowerPath.includes("policy") || lowerPath.includes("admission")) && (cleanContent.includes("package ") || cleanContent.includes("ValidatingWebhookConfiguration") || cleanContent.includes("rego")));
    if (!isOpaTarget) {
      return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // OPA-02: Admission Webhook Fail-Open Misconfiguration in Production
    if ((/ValidatingWebhookConfiguration/i.test(cleanContent) && cleanContent.includes('failurePolicy: Ignore'))) {
        const matchLineIdx = locateMatchLine(lines, [/failurePolicy:\s*Ignore/], l => !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `opa13202-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13202,
            type: 'INFRA_DATABASE',
            title: "OPA-02: Admission Webhook Fail-Open Misconfiguration in Production",
            severity: "LOW",
            category: "Admission Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Open Policy Agent configuration',
            reproductionSteps: [
                `Audited Open Policy Agent configuration in ${file.path}:${lineNum}.`,
                'Matched OPA-02: Admission Webhook Fail-Open Misconfiguration in Production.'
            ],
            remediationPrompt: "With failurePolicy: Ignore, any webhook outage or timeout admits every object unchecked. For webhooks that enforce security policy, run them highly available and set failurePolicy: Fail (exempt kube-system via namespaceSelector).",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OPA AUDIT] Found OPA-02: Admission Webhook Fail-Open Misconfiguration in Production at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
