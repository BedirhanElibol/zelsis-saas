/**
 * Zelsis Master evaluateCicdSupplyChainRules Engine (50 Rules)
 * Rules CICD-SEC-01 to CICD-SEC-50 (Rule IDs 9501 to 9550).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface CicdSupplyChainRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateCicdSupplyChainRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): CicdSupplyChainRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and non-cicd paths
    if (lowerPath.includes("data/catalogs/") || lowerPath.includes("data/mockdata") || lowerPath.includes("data/workspacefiles") || lowerPath.includes("data/schema") || lowerPath.includes("scratch/") || lowerPath.includes(".agent/") || lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isCicd = lowerPath.includes(".github/workflows/") || lowerPath.endsWith(".gitlab-ci.yml") || lowerPath.includes("jenkinsfile") || cleanContent.includes("pull_request_target");
    if (!isCicd)
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    // CICD-SEC-01: Dangerous pull_request_target Workflow with Untrusted Checkout
    if (cleanContent.includes('pull_request_target') && cleanContent.includes('ref: ${{ github.event.pull_request.head.sha }}')) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cicdsec9501-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9501,
            type: 'SECURITY',
            title: "CICD-SEC-01: Dangerous pull_request_target Workflow with Untrusted Checkout",
            severity: "CRITICAL",
            category: "CI/CD Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'CI/CD workflow YAML instruction',
            reproductionSteps: [
                `Audited CI/CD workflow in ${file.path}:${lineNum}.`,
                'Detected pipeline security violation matching CICD-SEC-01.'
            ],
            remediationPrompt: "Use pull_request trigger instead of pull_request_target when checking out PR code.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CICD SEC] Found CICD-SEC-01: Dangerous pull_request_target Workflow with Untrusted Checkout at ${file.path}:${lineNum}`);
    }
    // CICD-SEC-02: Unpinned Third-Party Action Mutable Reference (@v1)
    if ((/uses\s*:\s*[a-zA-Z0-9-_]+\/[a-zA-Z0-9-_]+@v[0-9]+/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cicdsec9502-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9502,
            type: 'SECURITY',
            title: "CICD-SEC-02: Unpinned Third-Party Action Mutable Reference (@v1)",
            severity: "HIGH",
            category: "Supply Chain Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'CI/CD workflow YAML instruction',
            reproductionSteps: [
                `Audited CI/CD workflow in ${file.path}:${lineNum}.`,
                'Detected pipeline security violation matching CICD-SEC-02.'
            ],
            remediationPrompt: "Replace action@v3 with action@commit_sha to prevent supply chain action hijacking.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CICD SEC] Found CICD-SEC-02: Unpinned Third-Party Action Mutable Reference (@v1) at ${file.path}:${lineNum}`);
    }
    // CICD-SEC-03: Script Injection via Unescaped GitHub Context Expression
    const untrustedContextRegex = /\$\{\{\s*github\.(?:head_ref|event\.(?:issue|pull_request|comment|review|review_comment|discussion|discussion_comment|head_commit|commits|pages)\b[\w.\[\]*]*\.(?:title|body|message|ref|label|name|email|page_name))/i;
    const indentOf = (l: string) => l.length - l.trimStart().length;
    const isInsideRunScript = (idx: number) => {
        if (/^\s*-?\s*(?:run|script)\s*:/.test(lines[idx])) return true;
        for (let i = idx - 1, indent = indentOf(lines[idx]); i >= 0; i--) {
            if (!lines[i].trim() || lines[i].trim().startsWith('#') || indentOf(lines[i]) >= indent) continue;
            return /^\s*-?\s*(?:run|script)\s*:/.test(lines[i]);
        }
        return false;
    };
    const injectionLineIdx = lines.findIndex((l, i) => untrustedContextRegex.test(l) && isInsideRunScript(i));
    if (injectionLineIdx !== -1) {
        const matchLineIdx = injectionLineIdx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cicdsec9503-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9503,
            type: 'SECURITY',
            title: "CICD-SEC-03: Script Injection via Unescaped GitHub Context Expression",
            severity: "CRITICAL",
            category: "Command Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'CI/CD workflow YAML instruction',
            reproductionSteps: [
                `Audited CI/CD workflow in ${file.path}:${lineNum}.`,
                'Detected pipeline security violation matching CICD-SEC-03.'
            ],
            remediationPrompt: "Pass context expressions via env: block instead of inlining ${{ ... }} in shell scripts.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CICD SEC] Found CICD-SEC-03: Script Injection via Unescaped GitHub Context Expression at ${file.path}:${lineNum}`);
    }
    // CICD-SEC-04: Overprivileged GITHUB_TOKEN Permissions (permissions: write-all)
    if (/permissions\s*:\s*write-all/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cicdsec9504-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9504,
            type: 'SECURITY',
            title: "CICD-SEC-04: Overprivileged GITHUB_TOKEN Permissions (permissions: write-all)",
            severity: "HIGH",
            category: "CI/CD Privilege",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'CI/CD workflow YAML instruction',
            reproductionSteps: [
                `Audited CI/CD workflow in ${file.path}:${lineNum}.`,
                'Detected pipeline security violation matching CICD-SEC-04.'
            ],
            remediationPrompt: "Set top-level permissions: contents: read and grant write permissions only to specific jobs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CICD SEC] Found CICD-SEC-04: Overprivileged GITHUB_TOKEN Permissions (permissions: write-all) at ${file.path}:${lineNum}`);
    }
    // CICD-SEC-05: Exposed Secret Tokens in Build Log Outputs
    if ((/run\s*:[\s\S]*?echo\s+["']?\$\{\{\s*secrets\./i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cicdsec9505-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9505,
            type: 'SECURITY',
            title: "CICD-SEC-05: Exposed Secret Tokens in Build Log Outputs",
            severity: "CRITICAL",
            category: "Credential Exposure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'CI/CD workflow YAML instruction',
            reproductionSteps: [
                `Audited CI/CD workflow in ${file.path}:${lineNum}.`,
                'Detected pipeline security violation matching CICD-SEC-05.'
            ],
            remediationPrompt: "Remove printenv and debug echo statements that expose secret tokens in workflow logs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CICD SEC] Found CICD-SEC-05: Exposed Secret Tokens in Build Log Outputs at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
