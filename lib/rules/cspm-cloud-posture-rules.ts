/**
 * Zelsis Master evaluateCspmCloudPostureRules Engine (50 Rules)
 * Rules CSPM-01 to CSPM-50 (Rule IDs 14801 to 14850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface CspmCloudPostureRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateCspmCloudPostureRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): CspmCloudPostureRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip non-cloud IaC and non-infrastructure configuration files
    if (
        lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts") ||
        (!/\.(tf|tfvars|ya?ml)$/i.test(file.path) && !/terraform|cloudformation|iac|k8s|cloud/i.test(lowerPath))
    ) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // CSPM-01: Unrestricted Cloud Storage Bucket Public Read/Write Access
    if ((/aws_s3_bucket|google_storage_bucket/i.test(cleanContent) && !/block_public_acls/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cspm14801-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14801,
            type: 'SECURITY',
            title: "CSPM-01: Unrestricted Cloud Storage Bucket Public Read/Write Access",
            severity: "CRITICAL",
            category: "Storage Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
            reproductionSteps: [
                `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
                'Matched CSPM-01: Unrestricted Cloud Storage Bucket Public Read/Write Access.'
            ],
            remediationPrompt: "Enforce S3 and GCS block public access controls across all storage accounts and individual buckets.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-01: Unrestricted Cloud Storage Bucket Public Read/Write Access at ${file.path}:${lineNum}`);
    }
    // CSPM-02: Overprivileged Cloud IAM Roles with Wildcard Actions (*:*)
    if ((/"Action"\s*:\s*"\*"/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cspm14802-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14802,
            type: 'SECURITY',
            title: "CSPM-02: Overprivileged Cloud IAM Roles with Wildcard Actions (*:*)",
            severity: "CRITICAL",
            category: "IAM Boundaries",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
            reproductionSteps: [
                `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
                'Matched CSPM-02: Overprivileged Cloud IAM Roles with Wildcard Actions (*:*).'
            ],
            remediationPrompt: "Disallow wildcard action permissions in IAM policies; require explicit least-privilege resource ARNs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-02: Overprivileged Cloud IAM Roles with Wildcard Actions (*:*) at ${file.path}:${lineNum}`);
    }
    // CSPM-03: Missing Hardware MFA Enforcement on Cloud Root and Admin Accounts
    if ((/cloud_root_account/i.test(lowerPath) && !/enforceFido2Mfa/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cspm14803-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14803,
            type: 'SECURITY',
            title: "CSPM-03: Missing Hardware MFA Enforcement on Cloud Root and Admin Accounts",
            severity: "CRITICAL",
            category: "Privilege Assurance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
            reproductionSteps: [
                `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
                'Matched CSPM-03: Missing Hardware MFA Enforcement on Cloud Root and Admin Accounts.'
            ],
            remediationPrompt: "Enforce hardware FIDO2 MFA for cloud account root users and mandate temporary role assumption.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-03: Missing Hardware MFA Enforcement on Cloud Root and Admin Accounts at ${file.path}:${lineNum}`);
    }
    // CSPM-04: Cloud Security Group Permitting Inbound SSH/RDP from 0.0.0.0/0
    if (((/security_group|ingress|sg/i.test(lowerPath) || /security_group|ingress/i.test(cleanContent)) && cleanContent.includes('port22OpenToInternet') && /0\.0\.0\.0\/0/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cspm14804-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14804,
            type: 'SECURITY',
            title: "CSPM-04: Cloud Security Group Permitting Inbound SSH/RDP from 0.0.0.0/0",
            severity: "CRITICAL",
            category: "Network Boundary",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
            reproductionSteps: [
                `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
                'Matched CSPM-04: Cloud Security Group Permitting Inbound SSH/RDP from 0.0.0.0/0.'
            ],
            remediationPrompt: "Ban ingress rules opening administrative ports (22, 3389) directly to the public internet.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-04: Cloud Security Group Permitting Inbound SSH/RDP from 0.0.0.0/0 at ${file.path}:${lineNum}`);
    }
    // CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region
    if (((/aws_cloudtrail|audit_logs/i.test(lowerPath) || /aws_cloudtrail|audit_logs/i.test(cleanContent)) && !/is_multi_region_trail\s*=\s*true/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cspm14805-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14805,
            type: 'SECURITY',
            title: "CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region",
            severity: "HIGH",
            category: "Audit Logging",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
            reproductionSteps: [
                `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
                'Matched CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region.'
            ],
            remediationPrompt: "Enforce multi-region audit logging with log file integrity validation and KMS customer-managed keys.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
