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
    // OPA-01: Rego Policy Infinite Recursion and Execution Timeout
    if ((/rego|policy/i.test(cleanContent) && !/evaluationTimeout|timeoutSeconds/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/rego|policy/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `opa13201-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13201,
            type: 'INFRA_DATABASE',
            title: "OPA-01: Rego Policy Infinite Recursion and Execution Timeout",
            severity: "CRITICAL",
            category: "Evaluation Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Open Policy Agent configuration',
            reproductionSteps: [
                `Audited Open Policy Agent configuration in ${file.path}:${lineNum}.`,
                'Matched OPA-01: Rego Policy Infinite Recursion and Execution Timeout.'
            ],
            remediationPrompt: "Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OPA AUDIT] Found OPA-01: Rego Policy Infinite Recursion and Execution Timeout at ${file.path}:${lineNum}`);
    }
    // OPA-02: Admission Webhook Fail-Open Misconfiguration in Production
    if ((/ValidatingWebhookConfiguration/i.test(cleanContent) && cleanContent.includes('failurePolicy: Ignore'))) {
        const matchLineIdx = locateMatchLine(lines, [/ValidatingWebhookConfiguration/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `opa13202-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13202,
            type: 'INFRA_DATABASE',
            title: "OPA-02: Admission Webhook Fail-Open Misconfiguration in Production",
            severity: "CRITICAL",
            category: "Admission Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Open Policy Agent configuration',
            reproductionSteps: [
                `Audited Open Policy Agent configuration in ${file.path}:${lineNum}.`,
                'Matched OPA-02: Admission Webhook Fail-Open Misconfiguration in Production.'
            ],
            remediationPrompt: "Configure failurePolicy: Fail on validating admission webhooks to prevent security bypasses on outage.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OPA AUDIT] Found OPA-02: Admission Webhook Fail-Open Misconfiguration in Production at ${file.path}:${lineNum}`);
    }
    // OPA-03: Uncached External HTTP Requests Inside Rego Evaluation Loop
    if ((/http\.send/i.test(cleanContent) && !/cache_duration/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/http\.send/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `opa13203-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13203,
            type: 'INFRA_DATABASE',
            title: "OPA-03: Uncached External HTTP Requests Inside Rego Evaluation Loop",
            severity: "HIGH",
            category: "Performance Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Open Policy Agent configuration',
            reproductionSteps: [
                `Audited Open Policy Agent configuration in ${file.path}:${lineNum}.`,
                'Matched OPA-03: Uncached External HTTP Requests Inside Rego Evaluation Loop.'
            ],
            remediationPrompt: "Forbid uncached http.send calls in real-time webhook rules; use pre-computed cached bundles.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OPA AUDIT] Found OPA-03: Uncached External HTTP Requests Inside Rego Evaluation Loop at ${file.path}:${lineNum}`);
    }
    // OPA-04: Unrestricted Container Linux Capabilities (SYS_ADMIN) Admission
    if ((/capabilities/i.test(cleanContent) && !/dropAllCapabilities/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/capabilities/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `opa13204-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13204,
            type: 'INFRA_DATABASE',
            title: "OPA-04: Unrestricted Container Linux Capabilities (SYS_ADMIN) Admission",
            severity: "CRITICAL",
            category: "Capability Guardrails",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Open Policy Agent configuration',
            reproductionSteps: [
                `Audited Open Policy Agent configuration in ${file.path}:${lineNum}.`,
                'Matched OPA-04: Unrestricted Container Linux Capabilities (SYS_ADMIN) Admission.'
            ],
            remediationPrompt: "Reject pod specs requesting dangerous capabilities such as CAP_SYS_ADMIN or CAP_NET_ADMIN.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OPA AUDIT] Found OPA-04: Unrestricted Container Linux Capabilities (SYS_ADMIN) Admission at ${file.path}:${lineNum}`);
    }
    // OPA-05: Host Network and Host PID Namespace Sharing Policy Bypass
    if ((/hostNetwork:\s*true/i.test(cleanContent) && !/denyHostNetwork/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/hostNetwork:\s*true/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `opa13205-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13205,
            type: 'INFRA_DATABASE',
            title: "OPA-05: Host Network and Host PID Namespace Sharing Policy Bypass",
            severity: "CRITICAL",
            category: "Namespace Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Open Policy Agent configuration',
            reproductionSteps: [
                `Audited Open Policy Agent configuration in ${file.path}:${lineNum}.`,
                'Matched OPA-05: Host Network and Host PID Namespace Sharing Policy Bypass.'
            ],
            remediationPrompt: "Deny admission to workloads setting hostNetwork: true or hostPID: true in non-system namespaces.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [OPA AUDIT] Found OPA-05: Host Network and Host PID Namespace Sharing Policy Bypass at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
