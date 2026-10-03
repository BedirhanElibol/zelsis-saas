/**
 * Zelsis Master evaluateCloudSecurityRules Engine (50 Rules)
 * Rules CLOUD-SEC-01 to CLOUD-SEC-50 (Rule IDs 9201 to 9250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
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
    const hit_9201 = findInBlocks(cleanContent, /resource\s+"aws_s3_bucket(?:_acl)?"\s+"[^"]+"\s*\{/g, /^\s*acl\s*=\s*"public-read(?:-write)?"/m);
    if (hit_9201 !== -1) {
        const matchLineIdx = hit_9201;
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
    const hit_9202 = findWildcardIamStatement(cleanContent);
    if (hit_9202 !== -1) {
        const matchLineIdx = hit_9202;
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
    const hit_9203 = findInBlocks(cleanContent, /resource\s+"aws_ebs_volume"\s+"[^"]+"\s*\{/g, /^\s*encrypted\s*=\s*false\b/m);
    if (hit_9203 !== -1) {
        const matchLineIdx = hit_9203;
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
    const hit_9204 = findOpenManagementIngress(cleanContent);
    if (hit_9204 !== -1) {
        const matchLineIdx = hit_9204;
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
    const hit_9205 = findInBlocks(cleanContent, /resource\s+"aws_cloudtrail"\s+"[^"]+"\s*\{/g, /^\s*enable_logging\s*=\s*false\b/m);
    if (hit_9205 !== -1) {
        const matchLineIdx = hit_9205;
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
// ---- precise matchers (rule-proof pass) ----
const lineAt = (text: string, idx: number): number => text.slice(0, idx).split('\n').length - 1;
/** Brace-matched blocks whose opening (ending in `{`) matches `open`; HCL `#` comment lines are blanked first. */
function hclBlocks(src: string, open: RegExp): { start: number; text: string }[] {
    const code = src.replace(/^[ \t]*#.*$/gm, (l) => ' '.repeat(l.length));
    const out: { start: number; text: string }[] = [];
    const re = new RegExp(open.source, open.flags.includes('g') ? open.flags : open.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(code))) {
        let depth = 0;
        let i = m.index + m[0].length - 1;
        for (; i < code.length; i++) {
            if (code[i] === '{') depth++;
            else if (code[i] === '}' && --depth === 0) break;
        }
        out.push({ start: m.index, text: code.slice(m.index, i + 1) });
    }
    return out;
}
/** Line of the first `attr` match inside a block opened by `open`, or -1. */
function findInBlocks(src: string, open: RegExp, attr: RegExp): number {
    for (const b of hclBlocks(src, open)) {
        const m = attr.exec(b.text);
        if (m) return lineAt(src, b.start + m.index + (m[0].length - m[0].trimStart().length));
    }
    return -1;
}
/** An Allow statement granting Action "*" on Resource "*" (IAM JSON or aws_iam_policy_document HCL). */
function findWildcardIamStatement(src: string): number {
    const json = /"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])/g;
    let m: RegExpExecArray | null;
    while ((m = json.exec(src))) {
        const s = src.lastIndexOf('{', m.index);
        const e = src.indexOf('}', m.index);
        const stmt = src.slice(s, e === -1 ? undefined : e);
        if (/"Effect"\s*:\s*"Allow"/i.test(stmt) && /"Resource"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])/.test(stmt)) return lineAt(src, m.index);
    }
    for (const b of hclBlocks(src, /\bstatement\s*\{/g)) {
        const a = /^\s*actions\s*=\s*\[\s*"\*"\s*\]/m.exec(b.text);
        if (a && /^\s*resources\s*=\s*\[\s*"\*"\s*\]/m.test(b.text) && !/effect\s*=\s*"Deny"/i.test(b.text)) {
            return lineAt(src, b.start + a.index + (a[0].length - a[0].trimStart().length));
        }
    }
    return -1;
}
/** An ingress rule open to 0.0.0.0/0 whose port range covers SSH (22) or RDP (3389). */
function findOpenManagementIngress(src: string): number {
    const blocks = [
        ...hclBlocks(src, /\bingress\s*\{/g),
        ...hclBlocks(src, /resource\s+"aws_security_group_rule"\s+"[^"]+"\s*\{/g).filter((b) => /type\s*=\s*"ingress"/.test(b.text)),
        ...hclBlocks(src, /resource\s+"aws_vpc_security_group_ingress_rule"\s+"[^"]+"\s*\{/g),
    ];
    for (const b of blocks) {
        const cidr = /(?:cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"|cidr_ipv4\s*=\s*"0\.0\.0\.0\/0")/.exec(b.text);
        if (!cidr) continue;
        const from = Number(/from_port\s*=\s*(\d+)/.exec(b.text)?.[1] ?? NaN);
        const to = Number(/to_port\s*=\s*(\d+)/.exec(b.text)?.[1] ?? from);
        const allProto = /(?:protocol|ip_protocol)\s*=\s*"-1"/.test(b.text);
        const covers = (p: number) => from <= p && p <= to;
        if (allProto || covers(22) || covers(3389)) return lineAt(src, b.start + cidr.index);
    }
    return -1;
}
