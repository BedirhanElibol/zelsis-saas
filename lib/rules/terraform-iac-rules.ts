/**
 * Zelsis Master evaluateTerraformIacRules Engine (50 Rules)
 * Rules TF-01 to TF-50 (Rule IDs 11001 to 11050).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { hclBlocks, hclLine, openIngressLine, stripHashComments } from './iac-rules';
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
    const isTf = /\.tf$/i.test(lowerPath);
    const tf = isTf ? stripHashComments(cleanContent) : '';
    // Inline S3 backend blocks; an empty block means partial config (-backend-config), which we cannot see
    const s3Backends = isTf ? hclBlocks(tf, /backend\s+"s3"/).filter((b) => b.body.trim() !== '') : [];
    // TF-01: Unencrypted Cloud State Backend (Missing SSE on S3 / GCS State Bucket)
    const tf01 = s3Backends.find((b) => !/\bencrypt\s*=\s*true|\bkms_key_id\s*=/.test(b.body));
    if (tf01) {
        const matchLineIdx = hclLine(tf, tf01);
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tf11001-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11001,
            type: 'INFRA_DATABASE',
            title: "TF-01: Unencrypted Cloud State Backend (Missing SSE on S3 / GCS State Bucket)",
            severity: 'MEDIUM',
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
    // Terraform >= 1.10 locks natively with use_lockfile = true
    const tf02 = s3Backends.find((b) => !/\bdynamodb_table\s*=|\buse_lockfile\s*=\s*true/.test(b.body));
    if (tf02) {
        const matchLineIdx = hclLine(tf, tf02);
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tf11002-${Date.now()}-${findingCounter.count++}`,
            ruleId: 11002,
            type: 'INFRA_DATABASE',
            title: "TF-02: Missing State Locking on Distributed Terraform Backend (DynamoDB Table)",
            severity: 'MEDIUM',
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
    // Ingress open to 0.0.0.0/0 or ::/0 whose port range covers SSH or RDP
    const tf03Line = isTf ? openIngressLine(tf, [22, 3389]) : -1;
    if (tf03Line !== -1) {
        const matchLineIdx = tf03Line;
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
    // A literal access key ID inside a provider "aws" block (AWS documentation sample keys excluded)
    const accessKeyAttr = /\baccess_key\s*=\s*"(?:AKIA|ASIA)[A-Z0-9]{12,}"/;
    const tf04 = isTf ? hclBlocks(tf, /provider\s+"aws"/).find((b) => accessKeyAttr.test(b.body) && !/EXAMPLE"/.test(b.body)) : undefined;
    if (tf04) {
        const matchLineIdx = hclLine(tf, tf04, accessKeyAttr);
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
    // Per module block: a registry source (ns/name/provider) with no `version`, or a git source with no ?ref=; local ./ sources need no pin
    const tf05Line = (() => {
        if (!isTf) return -1;
        for (const b of hclBlocks(tf, /module\s+"[\w-]+"/)) {
            const src = /^\s*source\s*=\s*"([^"]+)"/m.exec(b.body);
            if (!src) continue;
            const s = src[1];
            const registry = /^(?:[\w.-]+\/)?[\w-]+\/[\w-]+\/[\w-]+$/.test(s) && !/^\.{1,2}\//.test(s);
            const git = /^(?:git::|git@|github\.com\/|bitbucket\.org\/)/.test(s);
            if ((registry && !/^\s*version\s*=/m.test(b.body)) || (git && !/[?&]ref=/.test(s))) return hclLine(tf, b, /^\s*source\s*=/m);
        }
        return -1;
    })();
    if (tf05Line !== -1) {
        const matchLineIdx = tf05Line;
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
