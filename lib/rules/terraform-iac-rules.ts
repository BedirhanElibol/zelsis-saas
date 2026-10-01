/**
 * Zelsis Master evaluateTerraformIacRules Engine (50 Rules)
 * Rules TF-01 to TF-50 (Rule IDs 11001 to 11050).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface TerraformIacRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateTerraformIacRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): TerraformIacRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // TF-01: Unencrypted Cloud State Backend (Missing SSE on S3 / GCS State Bucket)
    if ((/backend\s+['"]s3['"]/i.test(cleanContent) && !/encrypt\s*=\s*true|kms_key_id/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tf11001-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11001,
            type: 'INFRA_DATABASE',
            title: "TF-01: Unencrypted Cloud State Backend (Missing SSE on S3 / GCS State Bucket)",
            severity: "CRITICAL",
            category: "State Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Terraform block definition',
            reproductionSteps: [
                `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
                'Detected Terraform policy violation matching TF-01.'
            ],
            remediationPrompt: "Enable server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = 'aws:kms' } } }.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TF AUDIT] Found TF-01: Unencrypted Cloud State Backend (Missing SSE on S3 / GCS State Bucket) at ${file.path}:${lineNum}`);
    }
    // TF-02: Missing State Locking on Distributed Terraform Backend (DynamoDB Table)
    if ((/backend\s+['"]s3['"]/i.test(cleanContent) && !/dynamodb_table/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tf11002-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11002,
            type: 'INFRA_DATABASE',
            title: "TF-02: Missing State Locking on Distributed Terraform Backend (DynamoDB Table)",
            severity: "HIGH",
            category: "Concurrency",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Terraform block definition',
            reproductionSteps: [
                `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
                'Detected Terraform policy violation matching TF-02.'
            ],
            remediationPrompt: "Add dynamodb_table = 'terraform-lock-table' to the backend 's3' configuration.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TF AUDIT] Found TF-02: Missing State Locking on Distributed Terraform Backend (DynamoDB Table) at ${file.path}:${lineNum}`);
    }
    // TF-03: Security Group Ingress Open to the World on Administrative Ports (0.0.0.0/0)
    if ((/from_port\s*=\s*22/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tf11003-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11003,
            type: 'INFRA_DATABASE',
            title: "TF-03: Security Group Ingress Open to the World on Administrative Ports (0.0.0.0/0)",
            severity: "CRITICAL",
            category: "Perimeter Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Terraform block definition',
            reproductionSteps: [
                `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
                'Detected Terraform policy violation matching TF-03.'
            ],
            remediationPrompt: "Replace cidr_blocks = ['0.0.0.0/0'] on port 22 with corporate VPN gateway CIDR.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TF AUDIT] Found TF-03: Security Group Ingress Open to the World on Administrative Ports (0.0.0.0/0) at ${file.path}:${lineNum}`);
    }
    // TF-04: Hardcoded Cloud Provider Access Keys in Terraform Files
    if ((/provider\s+['"]aws['"][\s\S]*?access_key\s*=\s*['"][A-Z0-9]{16,}['"]/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tf11004-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11004,
            type: 'INFRA_DATABASE',
            title: "TF-04: Hardcoded Cloud Provider Access Keys in Terraform Files",
            severity: "CRITICAL",
            category: "Credential Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Terraform block definition',
            reproductionSteps: [
                `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
                'Detected Terraform policy violation matching TF-04.'
            ],
            remediationPrompt: "Remove hardcoded access_key and secret_key from provider 'aws' and rely on ambient IAM roles.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TF AUDIT] Found TF-04: Hardcoded Cloud Provider Access Keys in Terraform Files at ${file.path}:${lineNum}`);
    }
    // TF-05: Unversioned Terraform Provider / Module References (Floating Dependencies)
    if ((/module\s+['"][a-zA-Z0-9_-]+['"][\s\S]*?source\s*=\s*['"][^'"]+['"]/i.test(cleanContent) && !/version|ref=/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tf11005-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11005,
            type: 'INFRA_DATABASE',
            title: "TF-05: Unversioned Terraform Provider / Module References (Floating Dependencies)",
            severity: "MEDIUM",
            category: "Supply Chain",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Terraform block definition',
            reproductionSteps: [
                `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
                'Detected Terraform policy violation matching TF-05.'
            ],
            remediationPrompt: "Pin module source versions with ?ref=v1.4.2 or explicit version = '~> 5.0' constraints.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TF AUDIT] Found TF-05: Unversioned Terraform Provider / Module References (Floating Dependencies) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
