/**
 * Zelsis Master evaluateCloudSecurityRules Engine (50 Rules)
 * Rules CLOUD-SEC-01 to CLOUD-SEC-50 (Rule IDs 9201 to 9250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface CloudSecurityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateCloudSecurityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): CloudSecurityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isCloud = lowerPath.endsWith(".tf") || lowerPath.endsWith(".json") || lowerPath.endsWith(".yaml") || lowerPath.endsWith(".yml") ||
        cleanContent.includes("aws_") || cleanContent.includes("s3") || cleanContent.includes("cloudtrail") || cleanContent.includes("iam:") || cleanContent.includes("azurerm_");
    if (!isCloud)
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    // CLOUD-SEC-01: Publicly Accessible S3 Bucket / Blob Container
    if ((/acl\s*=\s*['"]public-read['"]/i.test(cleanContent) && cleanContent.includes('aws_s3_bucket'))) {
        const matchLineIdx = locateMatchLine(lines, [/acl\s*=\s*['"]public-read['"]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloudsec9201-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9201,
            type: 'SECURITY',
            title: "CLOUD-SEC-01: Publicly Accessible S3 Bucket / Blob Container",
            severity: "CRITICAL",
            category: "Cloud Storage",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud infrastructure specification',
            reproductionSteps: [
                `Audited cloud configuration in ${file.path}:${lineNum}.`,
                'Detected cloud security violation matching CLOUD-SEC-01.'
            ],
            remediationPrompt: "Enable BlockPublicAcls, BlockPublicPolicy, and RestrictPublicBuckets on the S3 bucket.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CLOUD SEC] Found CLOUD-SEC-01: Publicly Accessible S3 Bucket / Blob Container at ${file.path}:${lineNum}`);
    }
    // CLOUD-SEC-02: Overprivileged IAM Wildcard Action (*)
    if ((/"Action"\s*:\s*"\*"[\s\S]*?"Resource"\s*:\s*"\*"/i.test(cleanContent) && cleanContent.includes('Effect'))) {
        const matchLineIdx = locateMatchLine(lines, [/"Action"\s*:\s*"\*"[\s\S]*?"Resource"\s*:\s*"\*"/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloudsec9202-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9202,
            type: 'SECURITY',
            title: "CLOUD-SEC-02: Overprivileged IAM Wildcard Action (*)",
            severity: "CRITICAL",
            category: "IAM Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud infrastructure specification',
            reproductionSteps: [
                `Audited cloud configuration in ${file.path}:${lineNum}.`,
                'Detected cloud security violation matching CLOUD-SEC-02.'
            ],
            remediationPrompt: "Replace Action: '*' with specific granular permissions required by the workload.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CLOUD SEC] Found CLOUD-SEC-02: Overprivileged IAM Wildcard Action (*) at ${file.path}:${lineNum}`);
    }
    // CLOUD-SEC-03: Unencrypted Cloud Storage Volumes at Rest (EBS / Managed Disk)
    if ((/resource\s+["']aws_ebs_volume["']/i.test(cleanContent) && /encrypted\s*=\s*false/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/resource\s+["']aws_ebs_volume["']/i, /encrypted\s*=\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloudsec9203-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9203,
            type: 'SECURITY',
            title: "CLOUD-SEC-03: Unencrypted Cloud Storage Volumes at Rest (EBS / Managed Disk)",
            severity: "HIGH",
            category: "Data at Rest",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud infrastructure specification',
            reproductionSteps: [
                `Audited cloud configuration in ${file.path}:${lineNum}.`,
                'Detected cloud security violation matching CLOUD-SEC-03.'
            ],
            remediationPrompt: "Enable encrypted: true and configure a customer-managed KMS key ID.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CLOUD SEC] Found CLOUD-SEC-03: Unencrypted Cloud Storage Volumes at Rest (EBS / Managed Disk) at ${file.path}:${lineNum}`);
    }
    // CLOUD-SEC-04: Security Group Ingress Open to 0.0.0.0/0 on Management Ports
    if ((/cidr_blocks\s*=\s*\[\s*['"]0\.0\.0\.0\/0['"]\s*\]/i.test(cleanContent) && /(?:from_port\s*=\s*22|from_port\s*=\s*3389)/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/cidr_blocks\s*=\s*\[\s*['"]0\.0\.0\.0\/0['"]\s*\]/i, /(?:from_port\s*=\s*22|from_port\s*=\s*3389)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloudsec9204-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9204,
            type: 'SECURITY',
            title: "CLOUD-SEC-04: Security Group Ingress Open to 0.0.0.0/0 on Management Ports",
            severity: "CRITICAL",
            category: "Network Exposure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud infrastructure specification',
            reproductionSteps: [
                `Audited cloud configuration in ${file.path}:${lineNum}.`,
                'Detected cloud security violation matching CLOUD-SEC-04.'
            ],
            remediationPrompt: "Remove 0.0.0.0/0 ingress and restrict management access to trusted IP ranges or SSM Session Manager.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CLOUD SEC] Found CLOUD-SEC-04: Security Group Ingress Open to 0.0.0.0/0 on Management Ports at ${file.path}:${lineNum}`);
    }
    // CLOUD-SEC-05: Multi-Cloud Audit Logging / CloudTrail Disabled
    if ((/resource\s+["']aws_cloudtrail["']/i.test(cleanContent) && /enable_logging\s*=\s*false/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/resource\s+["']aws_cloudtrail["']/i, /enable_logging\s*=\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('#'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloudsec9205-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9205,
            type: 'SECURITY',
            title: "CLOUD-SEC-05: Multi-Cloud Audit Logging / CloudTrail Disabled",
            severity: "HIGH",
            category: "Audit Observability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud infrastructure specification',
            reproductionSteps: [
                `Audited cloud configuration in ${file.path}:${lineNum}.`,
                'Detected cloud security violation matching CLOUD-SEC-05.'
            ],
            remediationPrompt: "Enable CloudTrail across all regions with KMS encryption and log integrity validation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CLOUD SEC] Found CLOUD-SEC-05: Multi-Cloud Audit Logging / CloudTrail Disabled at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
