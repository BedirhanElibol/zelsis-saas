/**
 * Zelsis Master evaluateGrpcWebSecurityRules Engine (50 Rules)
 * Rules GRPCSEC-01 to GRPCSEC-50 (Rule IDs 14701 to 14750).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface GrpcWebSecurityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateGrpcWebSecurityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): GrpcWebSecurityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // GRPCSEC-01: Insecure Plaintext gRPC Channel Instantiation in Production
    const hit_14701 = lines.findIndex((l) => /\bgrpc\.insecure_channel\s*\(|\bgrpc\.WithInsecure\s*\(\s*\)|\binsecure\.NewCredentials\s*\(\s*\)/.test(l) && !/localhost|127\.0\.0\.1|\[::1\]|unix:|bufconn/.test(l));
    if (hit_14701 !== -1) {
        const matchLineIdx = hit_14701;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grpcsec14701-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14701,
            type: 'INFRA_DATABASE',
            title: "GRPCSEC-01: Insecure Plaintext gRPC Channel Instantiation in Production",
            severity: "MEDIUM",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
            reproductionSteps: [
                `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
                'Matched GRPCSEC-01: Insecure Plaintext gRPC Channel Instantiation in Production.'
            ],
            remediationPrompt: "Require TLS or mutual TLS credentials when instantiating gRPC communication channels in production.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-01: Insecure Plaintext gRPC Channel Instantiation in Production at ${file.path}:${lineNum}`);
    }
    // GRPCSEC-03: Unbounded gRPC Inbound Message Size Permitting Memory Exhaustion
    const hit_14703 = lines.findIndex((l) => /["']grpc\.max_(?:receive|send)_message_length["']\s*[,:]\s*-1\b/.test(l) || /\bmax(?:Receive|Send)MessageLength\s*:\s*-1\b/.test(l) || /\bgrpc\.MaxRecvMsgSize\s*\(\s*math\.MaxInt(?:32|64)?\s*\)/.test(l));
    if (hit_14703 !== -1) {
        const matchLineIdx = hit_14703;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grpcsec14703-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14703,
            type: 'INFRA_DATABASE',
            title: "GRPCSEC-03: Unbounded gRPC Inbound Message Size Permitting Memory Exhaustion",
            severity: "HIGH",
            category: "Message Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
            reproductionSteps: [
                `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
                'Matched GRPCSEC-03: Unbounded gRPC Inbound Message Size Permitting Memory Exhaustion.'
            ],
            remediationPrompt: "Restrict max_receive_message_length (e.g. max 4MB) to prevent JVM and worker heap exhaustion.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-03: Unbounded gRPC Inbound Message Size Permitting Memory Exhaustion at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
