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
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isCicd = lowerPath.includes(".github/workflows/") || lowerPath.endsWith(".gitlab-ci.yml") || lowerPath.includes("jenkinsfile") || cleanContent.includes("pull_request_target");
    if (!isCicd)
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    // CICD-SEC-01: Dangerous pull_request_target Workflow with Untrusted Checkout
    // A pull_request_target workflow (runs with secrets and a write token) that checks out the PR's own code
    // (head sha/ref, github.head_ref or refs/pull/N/merge) and later runs a step, which executes that code
    const prHeadRef = /^\s*ref\s*:\s*['"]?(?:\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref)\s*\}\}|refs\/pull\/\$\{\{[^}]*\}\}\/(?:merge|head))/;
    const cicd01Line = (() => {
        if (!lines.some((l) => !l.trim().startsWith('#') && /\bpull_request_target\b/.test(l))) return -1;
        const refIdx = lines.findIndex((l) => prHeadRef.test(l));
        return refIdx !== -1 && lines.slice(refIdx + 1).some((l) => /^\s*-?\s*run\s*:/.test(l)) ? refIdx : -1;
    })();
    if (cicd01Line !== -1) {
        const matchLineIdx = cicd01Line;
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
    const unpinnedActionRegex = /^\s*-?\s*uses\s*:\s*['\"]?[\w.-]+\/[\w./-]+@(?![0-9a-f]{40}\b)[\w.-]+/i;
    if (/\.github\/workflows\/[^/]+\.ya?ml$/i.test(file.path) && lines.some(l => unpinnedActionRegex.test(l))) {
        const matchLineIdx = lines.findIndex(l => unpinnedActionRegex.test(l));
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
    const cicd04Line = lines.findIndex((l) => /^\s*permissions\s*:\s*write-all\b/.test(l));
    if (cicd04Line !== -1) {
        const matchLineIdx = cicd04Line;
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
    // `echo ${{ secrets.X }}` printed to the log; piping (`| docker login --password-stdin`) or
    // redirecting (`> .env`, `>> $GITHUB_ENV`) the value is the normal way to hand it to a tool
    const cicd05Line = lines.findIndex((l) => !l.trim().startsWith('#') && /\becho\s+(?:-[a-z]+\s+)?["']?[^|>]*\$\{\{\s*secrets\.[\w-]+\s*\}\}[^|>]*$/.test(l));
    if (cicd05Line !== -1) {
        const matchLineIdx = cicd05Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cicdsec9505-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9505,
            type: 'SECURITY',
            title: "CICD-SEC-05: Exposed Secret Tokens in Build Log Outputs",
            severity: 'LOW',
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
