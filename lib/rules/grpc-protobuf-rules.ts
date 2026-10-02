/**
 * Zelsis Master evaluateGrpcProtobufRules Engine (50 Rules)
 * Rules GRPC-01 to GRPC-50 (Rule IDs 10201 to 10250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface GrpcProtobufRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateGrpcProtobufRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): GrpcProtobufRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // GRPC-03: Plaintext Insecure Channel Credentials in Production
    const hit_10203 = lines.findIndex((l) => /\b(?:grpc\.)?credentials\.createInsecure\s*\(\s*\)/.test(l) && !/localhost|127\.0\.0\.1|\[::1\]|unix:/.test(l));
    if (hit_10203 !== -1) {
        const matchLineIdx = hit_10203;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grpc10203-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10203,
            type: 'INFRA_DATABASE',
            title: "GRPC-03: Plaintext Insecure Channel Credentials in Production",
            severity: "MEDIUM",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'gRPC service definition',
            reproductionSteps: [
                `Audited RPC handler in ${file.path}:${lineNum}.`,
                'Detected gRPC architecture violation matching GRPC-03.'
            ],
            remediationPrompt: "Replace createInsecure() with createSsl() for remote cluster communication.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [gRPC AUDIT] Found GRPC-03: Plaintext Insecure Channel Credentials in Production at ${file.path}:${lineNum}`);
    }
    // GRPC-05: Unprotected gRPC Server Reflection in Public Production
    const hit_10205 = findUngatedReflection(lines);
    if (hit_10205 !== -1) {
        const matchLineIdx = hit_10205;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grpc10205-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10205,
            type: 'INFRA_DATABASE',
            title: "GRPC-05: Unprotected gRPC Server Reflection in Public Production",
            severity: "MEDIUM",
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'gRPC service definition',
            reproductionSteps: [
                `Audited RPC handler in ${file.path}:${lineNum}.`,
                'Detected gRPC architecture violation matching GRPC-05.'
            ],
            remediationPrompt: "Conditionally enable gRPC reflection only when process.env.NODE_ENV !== 'production'.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [gRPC AUDIT] Found GRPC-05: Unprotected gRPC Server Reflection in Public Production at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
// ---- precise matchers (rule-proof pass) ----
/** gRPC server reflection registered unconditionally (not behind a dev / env check in the lines just above). */
function findUngatedReflection(lines: string[]): number {
    const call = /\breflection\.Register\s*\(|\breflection\.enable_server_reflection\s*\(|\bnew\s+ReflectionService\s*\(/;
    const gate = /\bif\b[^\n]*(?:env|ENV|Getenv|environ|debug|DEBUG|dev|Dev|DEV|production|PRODUCTION)/;
    return lines.findIndex((l, i) => call.test(l) && !lines.slice(Math.max(0, i - 3), i + 1).some((p) => gate.test(p)));
}
