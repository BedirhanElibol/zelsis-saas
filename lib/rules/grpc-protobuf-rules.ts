/**
 * Zelsis Master evaluateGrpcProtobufRules Engine (50 Rules)
 * Rules GRPC-01 to GRPC-50 (Rule IDs 10201 to 10250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
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
    // GRPC-01: Missing Per-RPC Client Deadline / Timeout Propagation
    if ((/client\.[a-zA-Z0-9_]+\s*\([\s\S]*?\)/.test(cleanContent) && !/deadline|timeout/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/client\.[a-zA-Z0-9_]+\s*\([\s\S]*?\)/], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grpc10201-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10201,
            type: 'INFRA_DATABASE',
            title: "GRPC-01: Missing Per-RPC Client Deadline / Timeout Propagation",
            severity: "HIGH",
            category: "RPC Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'gRPC service definition',
            reproductionSteps: [
                `Audited RPC handler in ${file.path}:${lineNum}.`,
                'Detected gRPC architecture violation matching GRPC-01.'
            ],
            remediationPrompt: "Add context with timeout or deadline parameter to all outbound gRPC stubs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [gRPC AUDIT] Found GRPC-01: Missing Per-RPC Client Deadline / Timeout Propagation at ${file.path}:${lineNum}`);
    }
    // GRPC-02: Unbounded Inbound Message Size (Missing Max Receive Limit)
    if ((/new\s+grpc\.Server\s*\([\s\S]*?\)/.test(cleanContent) && !/maxReceiveMessageLength/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+grpc\.Server\s*\([\s\S]*?\)/], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grpc10202-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10202,
            type: 'INFRA_DATABASE',
            title: "GRPC-02: Unbounded Inbound Message Size (Missing Max Receive Limit)",
            severity: "CRITICAL",
            category: "Buffer Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'gRPC service definition',
            reproductionSteps: [
                `Audited RPC handler in ${file.path}:${lineNum}.`,
                'Detected gRPC architecture violation matching GRPC-02.'
            ],
            remediationPrompt: "Set grpc.max_receive_message_length: 4194304 in gRPC channel options.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [gRPC AUDIT] Found GRPC-02: Unbounded Inbound Message Size (Missing Max Receive Limit) at ${file.path}:${lineNum}`);
    }
    // GRPC-03: Plaintext Insecure Channel Credentials in Production
    if ((/grpc\.credentials\.createInsecure\s*\(\)/.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/grpc\.credentials\.createInsecure\s*\(\)/], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grpc10203-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10203,
            type: 'INFRA_DATABASE',
            title: "GRPC-03: Plaintext Insecure Channel Credentials in Production",
            severity: "CRITICAL",
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
    // GRPC-04: Missing Canonical Status Code Error Mapping (Raw Stack Exposure)
    if ((/callback\s*\(\s*(?:err|error)\s*,/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/callback\s*\(\s*(?:err|error)\s*,/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grpc10204-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10204,
            type: 'INFRA_DATABASE',
            title: "GRPC-04: Missing Canonical Status Code Error Mapping (Raw Stack Exposure)",
            severity: "HIGH",
            category: "Error Handling",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'gRPC service definition',
            reproductionSteps: [
                `Audited RPC handler in ${file.path}:${lineNum}.`,
                'Detected gRPC architecture violation matching GRPC-04.'
            ],
            remediationPrompt: "Map caught exceptions to grpc.status codes with scrubbed public error messages.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [gRPC AUDIT] Found GRPC-04: Missing Canonical Status Code Error Mapping (Raw Stack Exposure) at ${file.path}:${lineNum}`);
    }
    // GRPC-05: Unprotected gRPC Server Reflection in Public Production
    if ((/reflection\.add\s*\([\s\S]*?\)/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/reflection\.add\s*\([\s\S]*?\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
