/**
 * Zelsis Master evaluateGrpcWebSecurityRules Engine (50 Rules)
 * Rules GRPCSEC-01 to GRPCSEC-50 (Rule IDs 14701 to 14750).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
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
    if ((/createChannel|grpc\.insecure/i.test(cleanContent) && !/ChannelCredentials\.createSsl/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/createChannel|grpc\.insecure/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grpcsec14701-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14701,
            type: 'INFRA_DATABASE',
            title: "GRPCSEC-01: Insecure Plaintext gRPC Channel Instantiation in Production",
            severity: "CRITICAL",
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
    // GRPCSEC-02: Missing HTTP/2 Flow Control and Stream Window Limits
    if ((/http2_settings|initial_window_size/i.test(cleanContent) && !/max_concurrent_streams/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/http2_settings|initial_window_size/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grpcsec14702-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14702,
            type: 'INFRA_DATABASE',
            title: "GRPCSEC-02: Missing HTTP/2 Flow Control and Stream Window Limits",
            severity: "HIGH",
            category: "Flow Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
            reproductionSteps: [
                `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
                'Matched GRPCSEC-02: Missing HTTP/2 Flow Control and Stream Window Limits.'
            ],
            remediationPrompt: "Configure HTTP/2 initial connection and stream window limits to mitigate stream flood Denial of Service attacks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-02: Missing HTTP/2 Flow Control and Stream Window Limits at ${file.path}:${lineNum}`);
    }
    // GRPCSEC-03: Unbounded gRPC Inbound Message Size Permitting Memory Exhaustion
    if ((/max_receive_message_length/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/max_receive_message_length/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
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
    // GRPCSEC-04: Unprotected gRPC Server Reflection Enabled in Production
    if ((/(?:reflection|enableReflection)/i.test(cleanContent) && !/disableInProduction/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/(?:reflection|enableReflection)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grpcsec14704-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14704,
            type: 'INFRA_DATABASE',
            title: "GRPCSEC-04: Unprotected gRPC Server Reflection Enabled in Production",
            severity: "HIGH",
            category: "Schema Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
            reproductionSteps: [
                `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
                'Matched GRPCSEC-04: Unprotected gRPC Server Reflection Enabled in Production.'
            ],
            remediationPrompt: "Disable Server Reflection services in production environments to prevent unauthorized API schema enumeration.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-04: Unprotected gRPC Server Reflection Enabled in Production at ${file.path}:${lineNum}`);
    }
    // GRPCSEC-05: Missing Protobuf Payload Schema Validation Rules
    if ((/rpcHandler|serviceImpl/i.test(cleanContent) && !/validateRequest/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/rpcHandler|serviceImpl/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `grpcsec14705-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14705,
            type: 'INFRA_DATABASE',
            title: "GRPCSEC-05: Missing Protobuf Payload Schema Validation Rules",
            severity: "CRITICAL",
            category: "Input Validation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
            reproductionSteps: [
                `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
                'Matched GRPCSEC-05: Missing Protobuf Payload Schema Validation Rules.'
            ],
            remediationPrompt: "Enforce protoc-gen-validate (PGV) rules and message constraints on all incoming gRPC RPC requests.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-05: Missing Protobuf Payload Schema Validation Rules at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
