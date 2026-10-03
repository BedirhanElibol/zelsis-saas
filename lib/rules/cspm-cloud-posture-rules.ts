/**
 * Zelsis Master evaluateCspmCloudPostureRules Engine
 * CSPM-01 (14801), CSPM-02 (14802), CSPM-04 (14804), CSPM-05 (14805), all scoped to the offending block.
 * Removed as unsound (id never reused): 14803 hardware MFA on root accounts (keyed on a sentinel path and
 * name; root MFA is account configuration, not visible in IaC).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface CspmCloudPostureRuleResult {
    findings: Finding[];
    logs: string[];
}
const lineAt = (src: string, index: number): number => src.slice(0, index).split('\n').length - 1;
/** Brace-matched `{ ... }` starting at the first `{` at or after `from`. */
function blockFrom(src: string, from: number): { start: number; text: string } | null {
    const open = src.indexOf('{', from);
    if (open === -1) return null;
    let depth = 0;
    for (let i = open; i < src.length; i++) {
        if (src[i] === '{') depth++;
        else if (src[i] === '}' && --depth === 0) return { start: open, text: src.slice(open, i + 1) };
    }
    return null;
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
        (!/\.(tf|tfvars|ya?ml|json)$/i.test(file.path) && !/terraform|cloudformation|iac|k8s|cloud/i.test(lowerPath))
    ) {
        return { findings, logs };
    }
    // HCL / YAML `#` comment lines are not stripped upstream: blank them (line count preserved).
    const code = cleanContent.split('\n').map(l => (/^\s*#/.test(l) ? '' : l)).join('\n');
    const ts = new Date().toLocaleTimeString();
    // CSPM-01: storage bucket writable by anyone (S3 canned ACL public-read-write, GCS allUsers writer roles).
    const publicWrite = /\bacl\s*=\s*"public-read-write"|\bAccessControl\s*:\s*PublicReadWrite\b|\brole\s*=\s*"roles\/storage\.(?:objectAdmin|objectCreator|legacyBucketWriter|admin)"[^}]*\bmembers?\s*=\s*\[?\s*"all(?:Authenticated)?Users"|\bmembers?\s*=\s*\[?\s*"all(?:Authenticated)?Users"[^}]*\brole\s*=\s*"roles\/storage\.(?:objectAdmin|objectCreator|legacyBucketWriter|admin)"/.exec(code);
    if (publicWrite) {
        const matchLineIdx = lineAt(code, publicWrite.index);
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `cspm14801-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14801,
            type: 'INFRA_DATABASE',
            title: "CSPM-01: Unrestricted Cloud Storage Bucket Public Read/Write Access",
            severity: "CRITICAL",
            category: "Storage Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
            reproductionSteps: [
                `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
                'The bucket grants write access to anonymous / all-authenticated principals: anyone can upload, overwrite or plant content.'
            ],
            remediationPrompt: "Remove public write grants; keep the bucket private behind block public access and hand out pre-signed upload URLs instead.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-01: Unrestricted Cloud Storage Bucket Public Read/Write Access at ${file.path}:${lineNum}`);
    }
    // CSPM-02: an Allow statement granting every action (`"Action": "*"`, `Action = "*"`, `actions = ["*"]`).
    let wildcardIdx = -1;
    const stmt = /\{[^{}]*\}/g;
    for (let m = stmt.exec(code); m && wildcardIdx === -1; m = stmt.exec(code)) {
        const a = /["']?\b(?:Action|actions)["']?\s*[:=]\s*\[?\s*["']\*(?::\*)?["']\s*\]?/.exec(m[0]);
        if (a && !/["']?\b(?:Effect|effect)["']?\s*[:=]\s*["']Deny["']/.test(m[0]) && !/\bNotAction\b/.test(m[0])) {
            wildcardIdx = lineAt(code, m.index + a.index);
        }
    }
    if (wildcardIdx !== -1) {
        const matchLineIdx = wildcardIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `cspm14802-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14802,
            type: 'INFRA_DATABASE',
            title: "CSPM-02: Overprivileged Cloud IAM Roles with Wildcard Actions (*:*)",
            severity: "CRITICAL",
            category: "IAM Boundaries",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
            reproductionSteps: [
                `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
                'An Allow statement grants every action ("*"): the principal is effectively an administrator.'
            ],
            remediationPrompt: "Disallow wildcard action permissions in IAM policies; require explicit least-privilege resource ARNs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-02: Overprivileged Cloud IAM Roles with Wildcard Actions (*:*) at ${file.path}:${lineNum}`);
    }
    // CSPM-04: one ingress rule opening SSH (22) or RDP (3389) to 0.0.0.0/0 or ::/0.
    let openAdminIdx = -1;
    const ingressHeads = /\bingress\s*\{|resource\s+"aws_(?:security_group_rule|vpc_security_group_ingress_rule)"\s+"[^"]+"\s*\{/g;
    for (let m = ingressHeads.exec(code); m && openAdminIdx === -1; m = ingressHeads.exec(code)) {
        const block = blockFrom(code, m.index);
        if (!block) continue;
        const b = block.text;
        if (/\btype\s*=\s*"egress"/.test(b)) continue;
        const world = /(?:cidr_blocks|ipv6_cidr_blocks|cidr_ipv4|cidr_ipv6)\s*=\s*\[?[^\]\n]*"(?:0\.0\.0\.0\/0|::\/0)"/.exec(b);
        if (!world) continue;
        const from = /\bfrom_port\s*=\s*(\d+)/.exec(b);
        const to = /\bto_port\s*=\s*(\d+)/.exec(b);
        const allTraffic = /\b(?:protocol|ip_protocol)\s*=\s*"(?:-1|all)"/.test(b);
        const lo = from ? Number(from[1]) : NaN;
        const hi = to ? Number(to[1]) : lo;
        const coversAdmin = allTraffic || [22, 3389].some(p => p >= lo && p <= hi);
        if (coversAdmin) openAdminIdx = lineAt(code, block.start + world.index);
    }
    if (openAdminIdx !== -1) {
        const matchLineIdx = openAdminIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `cspm14804-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14804,
            type: 'INFRA_DATABASE',
            title: "CSPM-04: Cloud Security Group Permitting Inbound SSH/RDP from 0.0.0.0/0",
            severity: "CRITICAL",
            category: "Network Boundary",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
            reproductionSteps: [
                `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
                'An ingress rule exposes SSH / RDP to the whole internet, inviting credential stuffing and exploit scanning.'
            ],
            remediationPrompt: "Ban ingress rules opening administrative ports (22, 3389) directly to the public internet.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-04: Cloud Security Group Permitting Inbound SSH/RDP from 0.0.0.0/0 at ${file.path}:${lineNum}`);
    }
    // CSPM-05: an aws_cloudtrail resource that is single-region or has logging switched off.
    let trailIdx = -1;
    const trailHead = /resource\s+"aws_cloudtrail"\s+"[^"]+"\s*/g;
    for (let m = trailHead.exec(code); m && trailIdx === -1; m = trailHead.exec(code)) {
        const block = blockFrom(code, m.index);
        if (!block) continue;
        const disabled = /\benable_logging\s*=\s*false\b/.exec(block.text);
        if (disabled) trailIdx = lineAt(code, block.start + disabled.index);
        else if (!/\bis_multi_region_trail\s*=\s*true\b/.test(block.text)) trailIdx = lineAt(code, m.index);
    }
    if (trailIdx !== -1) {
        const matchLineIdx = trailIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `cspm14805-${Date.now()}-${findingCounter.count++}`,
            ruleId: 14805,
            type: 'INFRA_DATABASE',
            title: "CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region",
            severity: "MEDIUM",
            category: "Audit Logging",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
            reproductionSteps: [
                `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
                'The CloudTrail trail is single-region or has logging disabled, so API activity in other regions goes unrecorded (CIS AWS 3.1).'
            ],
            remediationPrompt: "Enforce multi-region audit logging with log file integrity validation and KMS customer-managed keys.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
