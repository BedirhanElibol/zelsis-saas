/**
 * Zelsis Master evaluateIacRules Engine (50 Rules)
 * Rules IAC-01 to IAC-50 (Rule IDs 8301 to 8350).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { locateMatchLine } from './shared/locate';
export interface IacRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateIacRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): IacRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // Terraform source with `#` comments blanked; rules below evaluate one resource block at a time
    const isTf = /\.tf$/i.test(lowerPath);
    const tf = isTf ? stripHashComments(cleanContent) : '';
    const isYaml = isYamlPath(lowerPath);
    // IAC-01: Security Group Ingress Open to World on SSH Port 22
    const iac01Line = isTf ? openIngressLine(tf, [22]) : -1;
    if (iac01Line !== -1) {
        const matchLineIdx = iac01Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac01-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8301,
            type: 'INFRA_DATABASE',
            title: "IAC-01: Security Group Ingress Open to World on SSH Port 22",
            severity: 'CRITICAL',
            category: "Network Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-01 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Security Group Ingress Open to World on SSH Port 22: Terraform aws_security_group declaring cidr_blocks = ['0.0.0.0/0'] on ingress port 22, exposing instances to brute-force attacks."
            ],
            remediationPrompt: "Restrict SSH ingress to corporate VPN IP blocks or use AWS SSM Session Manager instead of public SSH.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-01 finding in ${file.path}:${lineNum}`);
    }
    // IAC-02: Security Group Ingress Open to World on RDP Port 3389
    const iac02Line = isTf ? openIngressLine(tf, [3389]) : -1;
    if (iac02Line !== -1) {
        const matchLineIdx = iac02Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac02-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8302,
            type: 'INFRA_DATABASE',
            title: "IAC-02: Security Group Ingress Open to World on RDP Port 3389",
            severity: 'CRITICAL',
            category: "Network Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-02 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Security Group Ingress Open to World on RDP Port 3389: Opening Remote Desktop Protocol port 3389 to 0.0.0.0/0 in Terraform or CloudFormation templates."
            ],
            remediationPrompt: "Restrict RDP port 3389 ingress to internal subnets or private bastion hosts.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-02 finding in ${file.path}:${lineNum}`);
    }
    // IAC-03: Security Group Ingress Open to World on Database Ports (5432 / 3306)
    const iac03Line = isTf ? openIngressLine(tf, [5432, 3306]) : -1;
    if (iac03Line !== -1) {
        const matchLineIdx = iac03Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac03-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8303,
            type: 'INFRA_DATABASE',
            title: "IAC-03: Security Group Ingress Open to World on Database Ports (5432 / 3306)",
            severity: 'CRITICAL',
            category: "Database Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-03 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Security Group Ingress Open to World on Database Ports (5432 / 3306): Database security groups accepting public ingress (0.0.0.0/0) on PostgreSQL (5432) or MySQL (3306) ports."
            ],
            remediationPrompt: "Restrict database port ingress strictly to application security group IDs rather than CIDR blocks.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-03 finding in ${file.path}:${lineNum}`);
    }
    // IAC-04: AWS EBS Storage Volume Missing Default Encryption
    if (/(?:aws_ebs_volume|root_block_device)\b/i.test(cleanContent) && !/encrypted\s*=\s*true/i.test(cleanContent) && /\.(?:tf|hcl)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:aws_ebs_volume|root_block_device)\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac04-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8304,
            type: 'INFRA_DATABASE',
            title: "IAC-04: AWS EBS Storage Volume Missing Default Encryption",
            severity: 'HIGH',
            category: "Storage Encryption",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-04 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS EBS Storage Volume Missing Default Encryption: aws_ebs_volume or root_block_device definitions omitting encrypted = true."
            ],
            remediationPrompt: "Set encrypted = true on all aws_ebs_volume and launch template block device mappings.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-04 finding in ${file.path}:${lineNum}`);
    }
    // IAC-05: IAM Policy with Wildcard Administrative Actions (Action: *)
    // Allow statements granting Action "*" on Resource "*": inline JSON / jsonencode policies and
    // aws_iam_policy_document statements (both keys within a few lines, no Deny in the block)
    const iac05Line = (() => {
        if (!isTf) return -1;
        const starAction = /\bactions?"?\s*[:=]\s*\[?\s*"\*"/i;
        const starResource = /\bresources?"?\s*[:=]\s*\[?\s*"\*"/i;
        const blocks = [
            ...hclBlocks(tf, tfResource('aws_iam_policy|aws_iam_role_policy|aws_iam_user_policy|aws_iam_group_policy')),
            ...hclBlocks(tf, /data\s+"aws_iam_policy_document"\s+"([\w-]+)"/).flatMap((d) => hclBlocks(tf, /\bstatement/, d))
        ];
        for (const b of blocks) {
            if (!starAction.test(b.body) || !starResource.test(b.body) || /"?effect"?\s*[:=]\s*"Deny"/i.test(b.body)) continue;
            const a = hclLine(tf, b, starAction);
            if (Math.abs(a - hclLine(tf, b, starResource)) <= 6) return a;
        }
        return -1;
    })();
    if (iac05Line !== -1) {
        const matchLineIdx = iac05Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac05-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8305,
            type: 'INFRA_DATABASE',
            title: "IAC-05: IAM Policy with Wildcard Administrative Actions (Action: *)",
            severity: 'CRITICAL',
            category: "IAM Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-05 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected IAM Policy with Wildcard Administrative Actions (Action: *): Declaring Action: '*' on Resource: '*' in aws_iam_policy documents, granting full AWS account takeover."
            ],
            remediationPrompt: "Replace wildcard Action: '*' with specific, least-privilege API actions required by the workload.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-05 finding in ${file.path}:${lineNum}`);
    }
    // IAC-06: S3 Bucket Versioning Disabled on Critical Storage
    if (/aws_s3_bucket_versioning\b/i.test(cleanContent) && /status\s*=\s*["\']Disabled["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/status\s*=\s*["\']Disabled["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac06-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8306,
            type: 'INFRA_DATABASE',
            title: "IAC-06: S3 Bucket Versioning Disabled on Critical Storage",
            severity: 'HIGH',
            category: "Data Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-06 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected S3 Bucket Versioning Disabled on Critical Storage: aws_s3_bucket_versioning setting status = 'Disabled' or omitting versioning configuration."
            ],
            remediationPrompt: "Configure aws_s3_bucket_versioning with status = 'Enabled' on production buckets.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-06 finding in ${file.path}:${lineNum}`);
    }
    // IAC-07: AWS CloudTrail Multi-Region Audit Logging Disabled
    if (/aws_cloudtrail\b/i.test(cleanContent) && /is_multi_region_trail\s*=\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/is_multi_region_trail\s*=\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac07-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8307,
            type: 'INFRA_DATABASE',
            title: "IAC-07: AWS CloudTrail Multi-Region Audit Logging Disabled",
            severity: 'HIGH',
            category: "Audit & Compliance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-07 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS CloudTrail Multi-Region Audit Logging Disabled: aws_cloudtrail setting is_multi_region_trail = false, failing to capture activity in secondary AWS regions."
            ],
            remediationPrompt: "Set is_multi_region_trail = true on production AWS CloudTrail configurations.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-07 finding in ${file.path}:${lineNum}`);
    }
    // IAC-08: VPC Flow Logs Disabled on Production Network Subnets
    if (/aws_vpc\b/i.test(cleanContent) && !/aws_flow_log/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_vpc\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac08-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8308,
            type: 'INFRA_DATABASE',
            title: "IAC-08: VPC Flow Logs Disabled on Production Network Subnets",
            severity: 'MEDIUM',
            category: "Network Observability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-08 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected VPC Flow Logs Disabled on Production Network Subnets: aws_vpc definitions lacking associated aws_flow_log resources to monitor network traffic."
            ],
            remediationPrompt: "Create an aws_flow_log resource attached to the production VPC.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ MEDIUM: IAC-08 finding in ${file.path}:${lineNum}`);
    }
    // IAC-09: RDS Database Instance Missing Automated Backup Retention
    if (/aws_db_instance\b/i.test(cleanContent) && /backup_retention_period\s*=\s*0\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/backup_retention_period\s*=\s*0\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac09-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8309,
            type: 'INFRA_DATABASE',
            title: "IAC-09: RDS Database Instance Missing Automated Backup Retention",
            severity: 'HIGH',
            category: "Disaster Recovery",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-09 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected RDS Database Instance Missing Automated Backup Retention: aws_db_instance setting backup_retention_period = 0, disabling automated database snapshot backups."
            ],
            remediationPrompt: "Set backup_retention_period = 14 on all production aws_db_instance resources.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-09 finding in ${file.path}:${lineNum}`);
    }
    // IAC-10: RDS Database Instance Publicly Accessible (publicly_accessible = true)
    const iac10Line = isTf ? attrLineIn(tf, hclBlocks(tf, tfResource('aws_db_instance|aws_rds_cluster_instance')), /\bpublicly_accessible\s*=\s*true\b/) : -1;
    if (iac10Line !== -1) {
        const matchLineIdx = iac10Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac10-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8310,
            type: 'INFRA_DATABASE',
            title: "IAC-10: RDS Database Instance Publicly Accessible (publicly_accessible = true)",
            severity: 'CRITICAL',
            category: "Database Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-10 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected RDS Database Instance Publicly Accessible (publicly_accessible = true): Configuring publicly_accessible = true on database instances, assigning public IP addresses to database nodes."
            ],
            remediationPrompt: "Set publicly_accessible = false and deploy database instances into private VPC subnets.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-10 finding in ${file.path}:${lineNum}`);
    }
    // IAC-11: Kubernetes Namespace Missing NetworkPolicy Isolation
    if (/kind:\s*Namespace\b/i.test(cleanContent) && !/kind:\s*NetworkPolicy/i.test(cleanContent) && /\.(?:ya?ml)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/kind:\s*Namespace\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac11-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8311,
            type: 'INFRA_DATABASE',
            title: "IAC-11: Kubernetes Namespace Missing NetworkPolicy Isolation",
            severity: 'HIGH',
            category: "Kubernetes Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-11 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Namespace Missing NetworkPolicy Isolation: Kubernetes namespaces lacking default-deny NetworkPolicy resources, allowing unrestricted east-west traffic."
            ],
            remediationPrompt: "Deploy a default-deny NetworkPolicy in all production Kubernetes namespaces.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-11 finding in ${file.path}:${lineNum}`);
    }
    // IAC-12: Kubernetes Container Running with Host PID or IPC Namespace
    const iac12Line = isYaml ? yamlLine(lines, /^\s*host(?:PID|IPC)\s*:\s*true\b/) : -1;
    if (iac12Line !== -1) {
        const matchLineIdx = iac12Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac12-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8312,
            type: 'INFRA_DATABASE',
            title: "IAC-12: Kubernetes Container Running with Host PID or IPC Namespace",
            severity: 'CRITICAL',
            category: "Container Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-12 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Container Running with Host PID or IPC Namespace: Pod manifests setting hostPID: true or hostIPC: true, exposing host process table and IPC memory."
            ],
            remediationPrompt: "Remove hostPID: true and hostIPC: true directives from pod specifications.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-12 finding in ${file.path}:${lineNum}`);
    }
    // IAC-13: Kubernetes Secret Injected as Plaintext Environment Variable
    if (/valueFrom:\s*\{\s*secretKeyRef:/i.test(cleanContent) && /\.(?:ya?ml)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/valueFrom:\s*\{\s*secretKeyRef:/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac13-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8313,
            type: 'INFRA_DATABASE',
            title: "IAC-13: Kubernetes Secret Injected as Plaintext Environment Variable",
            severity: 'HIGH',
            category: "Secret Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-13 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Secret Injected as Plaintext Environment Variable: Injecting sensitive secrets via env.valueFrom.secretKeyRef without envelope encryption or external secret stores."
            ],
            remediationPrompt: "Migrate sensitive credentials from raw K8s secretKeyRef to External Secrets Operator or Vault.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-13 finding in ${file.path}:${lineNum}`);
    }
    // IAC-14: Dockerfile Missing HEALTHCHECK Instruction
    if (file.path.toLowerCase().endsWith("dockerfile") && !/HEALTHCHECK/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/iac-14|dockerfile/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac14-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8314,
            type: 'INFRA_DATABASE',
            title: "IAC-14: Dockerfile Missing HEALTHCHECK Instruction",
            severity: 'MEDIUM',
            category: "Container Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-14 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Dockerfile Missing HEALTHCHECK Instruction: Production Dockerfiles omitting HEALTHCHECK instruction, preventing orchestrators from detecting hung containers."
            ],
            remediationPrompt: "Add a HEALTHCHECK instruction (e.g. HEALTHCHECK CMD curl -f http://localhost:3000/api/health || exit 1) to Dockerfile.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ MEDIUM: IAC-14 finding in ${file.path}:${lineNum}`);
    }
    // IAC-15: Kubernetes Pod Missing ReadOnlyRootFilesystem Enforcement
    if (/securityContext:\s*\{(?![^}]*readOnlyRootFilesystem:\s*true)/i.test(cleanContent) && /\.(?:ya?ml)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/securityContext:\s*\{(?![^}]*readOnlyRootFilesystem:\s*true)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac15-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8315,
            type: 'INFRA_DATABASE',
            title: "IAC-15: Kubernetes Pod Missing ReadOnlyRootFilesystem Enforcement",
            severity: 'HIGH',
            category: "Container Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-15 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Pod Missing ReadOnlyRootFilesystem Enforcement: Pod securityContext omitting readOnlyRootFilesystem: true, allowing attackers to modify container binaries."
            ],
            remediationPrompt: "Add readOnlyRootFilesystem: true to container securityContext in pod manifests.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-15 finding in ${file.path}:${lineNum}`);
    }
    // IAC-16: AWS S3 Bucket Missing Default Server-Side Encryption Rule
    if (/aws_s3_bucket\b/i.test(cleanContent) && cleanContent.includes("s3BucketLacksEncryptionResource") && !/aws_s3_bucket_server_side_encryption_configuration/i.test(cleanContent) && /\.(?:tf|hcl)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_s3_bucket\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac16-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8316,
            type: 'INFRA_DATABASE',
            title: "IAC-16: AWS S3 Bucket Missing Default Server-Side Encryption Rule",
            severity: 'HIGH',
            category: "Storage Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-16 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS S3 Bucket Missing Default Server-Side Encryption Rule: aws_s3_bucket lacking an aws_s3_bucket_server_side_encryption_configuration resource."
            ],
            remediationPrompt: "Add aws_s3_bucket_server_side_encryption_configuration with AES256 or KMS rules.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-16 finding in ${file.path}:${lineNum}`);
    }
    // IAC-17: Kubernetes Ingress Missing TLS Termination Certificate
    if (/kind:\s*Ingress\b/i.test(cleanContent) && !/tls:\s*\[/i.test(cleanContent) && /\.(?:ya?ml)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/kind:\s*Ingress\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac17-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8317,
            type: 'INFRA_DATABASE',
            title: "IAC-17: Kubernetes Ingress Missing TLS Termination Certificate",
            severity: 'HIGH',
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-17 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Ingress Missing TLS Termination Certificate: Kubernetes Ingress manifests omitting tls.secretName configurations, serving traffic over plaintext HTTP."
            ],
            remediationPrompt: "Add a tls block with secretName and hosts in Kubernetes Ingress definitions.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-17 finding in ${file.path}:${lineNum}`);
    }
    // IAC-18: AWS CloudFront Distribution Missing WAF WebACL Association
    if (/aws_cloudfront_distribution\b/i.test(cleanContent) && !/web_acl_id\s*=/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_cloudfront_distribution\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac18-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8318,
            type: 'INFRA_DATABASE',
            title: "IAC-18: AWS CloudFront Distribution Missing WAF WebACL Association",
            severity: 'HIGH',
            category: "Edge Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-18 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS CloudFront Distribution Missing WAF WebACL Association: aws_cloudfront_distribution omitting web_acl_id, exposing origin servers to layer 7 DDoS and bot attacks."
            ],
            remediationPrompt: "Associate an aws_wafv2_web_acl ARN with the CloudFront distribution web_acl_id parameter.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-18 finding in ${file.path}:${lineNum}`);
    }
    // IAC-19: Terraform State Backend Missing State Locking (DynamoDB)
    if (/backend\s+["\']s3["\']\s*\{(?![^}]*dynamodb_table)/i.test(cleanContent) && /\.(?:tf|hcl)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/backend\s+["\']s3["\']\s*\{(?![^}]*dynamodb_table)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac19-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8319,
            type: 'INFRA_DATABASE',
            title: "IAC-19: Terraform State Backend Missing State Locking (DynamoDB)",
            severity: 'MEDIUM',
            category: "IaC Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-19 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Terraform State Backend Missing State Locking (DynamoDB): Terraform S3 backend configuration omitting dynamodb_table for state locking, risking concurrent corruption."
            ],
            remediationPrompt: "Add dynamodb_table = 'terraform-locks' to the Terraform backend S3 configuration.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ MEDIUM: IAC-19 finding in ${file.path}:${lineNum}`);
    }
    // IAC-20: AWS KMS Key Policy Permitting Wildcard Principal (*)
    // Key policy granting everyone with no Condition (e.g. kms:CallerAccount) and no Deny statement
    const iac20Line = isTf ? attrLineIn(tf, hclBlocks(tf, tfResource('aws_kms_key')), PRINCIPAL_STAR, (b) => UNSCOPED_GRANT_EXEMPT.test(b.body)) : -1;
    if (iac20Line !== -1) {
        const matchLineIdx = iac20Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac20-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8320,
            type: 'INFRA_DATABASE',
            title: "IAC-20: AWS KMS Key Policy Permitting Wildcard Principal (*)",
            severity: 'CRITICAL',
            category: "Cryptographic Access",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-20 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS KMS Key Policy Permitting Wildcard Principal (*): aws_kms_key policy declaring Principal = {'AWS': '*'} without restrictive Condition blocks."
            ],
            remediationPrompt: "Restrict KMS key policy Principals to authorized IAM role ARNs; eliminate wildcard Principal access.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-20 finding in ${file.path}:${lineNum}`);
    }
    // IAC-21: Container Running with hostNetwork Enabled
    const iac21Line = isYaml ? yamlLine(lines, /^\s*hostNetwork\s*:\s*true\b/) : -1;
    if (iac21Line !== -1) {
        const matchLineIdx = iac21Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac21-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8321,
            type: 'INFRA_DATABASE',
            title: "IAC-21: Container Running with hostNetwork Enabled",
            severity: 'CRITICAL',
            category: "Container Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-21 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Container Running with hostNetwork Enabled: Pod or compose definition setting hostNetwork: true, bypassing network namespaces and exposing host ports."
            ],
            remediationPrompt: "Disable hostNetwork: true in container definitions and use container networking instead.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-21 finding in ${file.path}:${lineNum}`);
    }
    // IAC-22: Terraform Resource Using Hardcoded Plaintext Passwords
    const iac22Line = /\.(?:tf|hcl)$/i.test(file.path) && !/data\.aws_secretsmanager/i.test(cleanContent) && !/test|spec|mock/i.test(lowerPath)
        ? yamlLine(lines, /^\s*\w*password\s*=\s*["\'][^"\'$]{6,}["\']/i) : -1;
    if (iac22Line !== -1) {
        const matchLineIdx = iac22Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac22-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8322,
            type: 'INFRA_DATABASE',
            title: "IAC-22: Terraform Resource Using Hardcoded Plaintext Passwords",
            severity: 'CRITICAL',
            category: "Secret Exposure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-22 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Terraform Resource Using Hardcoded Plaintext Passwords: Declaring password = 'my-secret-password' directly in Terraform resource definitions."
            ],
            remediationPrompt: "Replace hardcoded passwords with data source lookups from AWS Secrets Manager or Vault.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-22 finding in ${file.path}:${lineNum}`);
    }
    // IAC-23: AWS Elasticache Redis Cluster Missing In-Transit Encryption
    if (/aws_elasticache_replication_group\b/i.test(cleanContent) && /transit_encryption_enabled\s*=\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/transit_encryption_enabled\s*=\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac23-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8323,
            type: 'INFRA_DATABASE',
            title: "IAC-23: AWS Elasticache Redis Cluster Missing In-Transit Encryption",
            severity: 'HIGH',
            category: "Data Transmission",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-23 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS Elasticache Redis Cluster Missing In-Transit Encryption: aws_elasticache_replication_group setting transit_encryption_enabled = false."
            ],
            remediationPrompt: "Set transit_encryption_enabled = true on aws_elasticache_replication_group resources.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-23 finding in ${file.path}:${lineNum}`);
    }
    // IAC-24: AWS S3 Bucket Policy Permitting Wildcard Principal (*)
    // Bucket policy granting everyone with no Condition and no Deny (e.g. the common deny-insecure-transport policy)
    const iac24Line = isTf ? attrLineIn(tf, hclBlocks(tf, tfResource('aws_s3_bucket_policy')), PRINCIPAL_STAR, (b) => UNSCOPED_GRANT_EXEMPT.test(b.body)) : -1;
    if (iac24Line !== -1) {
        const matchLineIdx = iac24Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac24-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8324,
            type: 'INFRA_DATABASE',
            title: "IAC-24: AWS S3 Bucket Policy Permitting Wildcard Principal (*)",
            severity: 'CRITICAL',
            category: "Storage Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-24 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS S3 Bucket Policy Permitting Wildcard Principal (*): aws_s3_bucket_policy granting s3:GetObject or s3:* to Principal: '*'."
            ],
            remediationPrompt: "Remove wildcard Principal: '*' from S3 bucket policies; use CloudFront Origin Access Control.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-24 finding in ${file.path}:${lineNum}`);
    }
    // IAC-25: Kubernetes Pod Missing Non-Root User (runAsNonRoot: true)
    if (/securityContext:\s*\{(?![^}]*runAsNonRoot:\s*true)/i.test(cleanContent) && /\.(?:ya?ml)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/securityContext:\s*\{(?![^}]*runAsNonRoot:\s*true)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac25-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8325,
            type: 'INFRA_DATABASE',
            title: "IAC-25: Kubernetes Pod Missing Non-Root User (runAsNonRoot: true)",
            severity: 'HIGH',
            category: "Container Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-25 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Pod Missing Non-Root User (runAsNonRoot: true): Pod securityContext omitting runAsNonRoot: true, allowing containers to run as UID 0."
            ],
            remediationPrompt: "Add runAsNonRoot: true and runAsUser: 10001 to the pod securityContext.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-25 finding in ${file.path}:${lineNum}`);
    }
    // IAC-26: AWS Lambda Function Missing VPC Configuration for DB Access
    if (/aws_lambda_function\b/i.test(cleanContent) && !/vpc_config/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_lambda_function\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac26-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8326,
            type: 'INFRA_DATABASE',
            title: "IAC-26: AWS Lambda Function Missing VPC Configuration for DB Access",
            severity: 'MEDIUM',
            category: "Network Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-26 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS Lambda Function Missing VPC Configuration for DB Access: aws_lambda_function accessing internal RDS databases without configuring vpc_config."
            ],
            remediationPrompt: "Configure vpc_config with private subnet_ids and security_group_ids on the Lambda resource.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ MEDIUM: IAC-26 finding in ${file.path}:${lineNum}`);
    }
    // IAC-27: Terraform AWS Provider Missing Default Resource Tags
    if (/provider\s+["\']aws["\']\s*\{(?![^}]*default_tags)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/provider\s+["\']aws["\']\s*\{(?![^}]*default_tags)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac27-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8327,
            type: 'INFRA_DATABASE',
            title: "IAC-27: Terraform AWS Provider Missing Default Resource Tags",
            severity: 'LOW',
            category: "IaC Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-27 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Terraform AWS Provider Missing Default Resource Tags: aws provider configuration omitting default_tags, resulting in untagged resources and cost tracking gaps."
            ],
            remediationPrompt: "Add default_tags block to the AWS provider configuration in Terraform.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ LOW: IAC-27 finding in ${file.path}:${lineNum}`);
    }
    // IAC-28: AWS Elastic Load Balancer (ALB) Dropping HTTP to HTTPS Redirection
    // A plain-HTTP listener (port 80 / protocol HTTP) that forwards to the app instead of redirecting,
    // unless it belongs to an internal load balancer declared in the same file
    const iac28Line = (() => {
        if (!isTf) return -1;
        const internalLbs = new Set(hclBlocks(tf, tfResource('aws_lb|aws_alb')).filter((b) => /\binternal\s*=\s*true\b/.test(b.body)).map((b) => b.label));
        return attrLineIn(tf, hclBlocks(tf, tfResource('aws_lb_listener|aws_alb_listener')), /\btype\s*=\s*"forward"/, (b) => {
            const plainHttp = (/\bport\s*=\s*"?80"?\s*$/m.test(b.body) || /\bprotocol\s*=\s*"HTTP"/.test(b.body)) && !/\bprotocol\s*=\s*"HTTPS"/.test(b.body);
            const lb = /load_balancer_arn\s*=\s*aws_a?lb\.([\w-]+)\.arn/.exec(b.body);
            return !plainHttp || (!!lb && internalLbs.has(lb[1]));
        });
    })();
    if (iac28Line !== -1) {
        const matchLineIdx = iac28Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac28-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8328,
            type: 'INFRA_DATABASE',
            title: "IAC-28: AWS Elastic Load Balancer (ALB) Dropping HTTP to HTTPS Redirection",
            severity: 'HIGH',
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-28 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS Elastic Load Balancer (ALB) Dropping HTTP to HTTPS Redirection: aws_lb_listener on port 80 forwarding traffic directly instead of redirecting to port 443 with HTTPS."
            ],
            remediationPrompt: "Configure HTTP port 80 listener default action to redirect to HTTPS port 443.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-28 finding in ${file.path}:${lineNum}`);
    }
    // IAC-29: Kubernetes Pod Permitting Linux Capabilities (ALL)
    const iac29Line = isYaml ? (capabilityAdds(lines).find((a) => a.caps.includes('ALL'))?.line ?? -1) : -1;
    if (iac29Line !== -1) {
        const matchLineIdx = iac29Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac29-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8329,
            type: 'INFRA_DATABASE',
            title: "IAC-29: Kubernetes Pod Permitting Linux Capabilities (ALL)",
            severity: 'CRITICAL',
            category: "Container Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-29 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Pod Permitting Linux Capabilities (ALL): Container securityContext setting capabilities.add: ['ALL'] or adding dangerous capabilities like SYS_ADMIN."
            ],
            remediationPrompt: "Add capabilities.drop: ['ALL'] to container securityContext in pod specs.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-29 finding in ${file.path}:${lineNum}`);
    }
    // IAC-30: AWS Secrets Manager Secret Missing KMS Customer-Managed Key
    if (/aws_secretsmanager_secret\b/i.test(cleanContent) && !/kms_key_id\s*=/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_secretsmanager_secret\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac30-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8330,
            type: 'INFRA_DATABASE',
            title: "IAC-30: AWS Secrets Manager Secret Missing KMS Customer-Managed Key",
            severity: 'MEDIUM',
            category: "Secret Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-30 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS Secrets Manager Secret Missing KMS Customer-Managed Key: aws_secretsmanager_secret omitting kms_key_id, defaulting to generic AWS-managed keys."
            ],
            remediationPrompt: "Configure kms_key_id with a customer-managed KMS key ARN on aws_secretsmanager_secret.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ MEDIUM: IAC-30 finding in ${file.path}:${lineNum}`);
    }
    // IAC-31: Docker Compose Version 2/3 File Declaring Privileged Flag
    const iac31Line = /(?:^|\/)(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$/i.test(lowerPath) ? yamlLine(lines, /^\s*privileged\s*:\s*true\b/) : -1;
    if (iac31Line !== -1) {
        const matchLineIdx = iac31Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac31-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8331,
            type: 'INFRA_DATABASE',
            title: "IAC-31: Docker Compose Version 2/3 File Declaring Privileged Flag",
            severity: 'CRITICAL',
            category: "Container Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-31 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Docker Compose Version 2/3 File Declaring Privileged Flag: docker-compose.yml setting privileged: true on application containers."
            ],
            remediationPrompt: "Remove privileged: true from docker-compose service specifications.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-31 finding in ${file.path}:${lineNum}`);
    }
    // IAC-32: AWS RDS Instance Missing Deletion Protection
    if (/aws_db_instance\b/i.test(cleanContent) && !/deletion_protection\s*=\s*true/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_db_instance\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac32-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8332,
            type: 'INFRA_DATABASE',
            title: "IAC-32: AWS RDS Instance Missing Deletion Protection",
            severity: 'HIGH',
            category: "Data Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-32 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS RDS Instance Missing Deletion Protection: aws_db_instance omitting deletion_protection = true on production database instances."
            ],
            remediationPrompt: "Set deletion_protection = true on all production aws_db_instance resources.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-32 finding in ${file.path}:${lineNum}`);
    }
    // IAC-33: AWS OpenSearch / Elasticsearch Cluster Missing Node-to-Node Encryption
    if (/aws_opensearch_domain\b/i.test(cleanContent) && /node_to_node_encryption\s*\{[^}]*enabled\s*=\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/node_to_node_encryption\s*\{/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac33-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8333,
            type: 'INFRA_DATABASE',
            title: "IAC-33: AWS OpenSearch / Elasticsearch Cluster Missing Node-to-Node Encryption",
            severity: 'HIGH',
            category: "Data Transmission",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-33 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS OpenSearch / Elasticsearch Cluster Missing Node-to-Node Encryption: aws_opensearch_domain setting node_to_node_encryption.enabled = false."
            ],
            remediationPrompt: "Set node_to_node_encryption { enabled = true } on OpenSearch domain resources.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-33 finding in ${file.path}:${lineNum}`);
    }
    // IAC-34: Kubernetes Service Account Automatically Mounting API Tokens
    if (/kind:\s*ServiceAccount\b/i.test(cleanContent) && !/automountServiceAccountToken:\s*false/i.test(cleanContent) && /\.(?:ya?ml)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/kind:\s*ServiceAccount\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac34-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8334,
            type: 'INFRA_DATABASE',
            title: "IAC-34: Kubernetes Service Account Automatically Mounting API Tokens",
            severity: 'HIGH',
            category: "Least Privilege",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-34 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Service Account Automatically Mounting API Tokens: ServiceAccount manifests omitting automountServiceAccountToken: false on pods that do not require K8s API access."
            ],
            remediationPrompt: "Set automountServiceAccountToken: false on ServiceAccounts and Pod specifications.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-34 finding in ${file.path}:${lineNum}`);
    }
    // IAC-35: AWS CloudFront Distribution Using Insecure SSL/TLS Protocols (TLSv1)
    const iac35Line = isTf ? attrLineIn(tf, hclBlocks(tf, tfResource('aws_cloudfront_distribution')), /\bminimum_protocol_version\s*=\s*"(?:SSLv3|TLSv1|TLSv1_2016|TLSv1\.1_2016)"/) : -1;
    if (iac35Line !== -1) {
        const matchLineIdx = iac35Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac35-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8335,
            type: 'INFRA_DATABASE',
            title: "IAC-35: AWS CloudFront Distribution Using Insecure SSL/TLS Protocols (TLSv1)",
            severity: 'HIGH',
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-35 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS CloudFront Distribution Using Insecure SSL/TLS Protocols (TLSv1): viewer_certificate setting minimum_protocol_version = 'TLSv1' or 'TLSv1_2016'."
            ],
            remediationPrompt: "Set minimum_protocol_version = 'TLSv1.2_2021' in viewer_certificate configuration.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-35 finding in ${file.path}:${lineNum}`);
    }
    // IAC-36: Terraform AWS Security Group Egress Open to All Protocols and Ports
    if (/aws_security_group\b/i.test(cleanContent) && /protocol\s*=\s*["\']-1["\']/i.test(cleanContent) && /0\.0\.0\.0\/0/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_security_group\b/i, /protocol\s*=\s*["\']-1["\']/i, /0\.0\.0\.0\/0/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac36-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8336,
            type: 'INFRA_DATABASE',
            title: "IAC-36: Terraform AWS Security Group Egress Open to All Protocols and Ports",
            severity: 'MEDIUM',
            category: "Network Egress",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-36 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Terraform AWS Security Group Egress Open to All Protocols and Ports: aws_security_group declaring egress with protocol = '-1' and cidr_blocks = ['0.0.0.0/0']."
            ],
            remediationPrompt: "Restrict egress rules to ports 443 (HTTPS) and 53 (DNS) rather than allowing all protocols (-1).",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ MEDIUM: IAC-36 finding in ${file.path}:${lineNum}`);
    }
    // IAC-37: Kubernetes StatefulSet Missing VolumeClaimTemplate Storage Limits
    if (/kind:\s*StatefulSet\b/i.test(cleanContent) && !/requests:\s*\{[^}]*storage:/i.test(cleanContent) && /\.(?:ya?ml)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/kind:\s*StatefulSet\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac37-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8337,
            type: 'INFRA_DATABASE',
            title: "IAC-37: Kubernetes StatefulSet Missing VolumeClaimTemplate Storage Limits",
            severity: 'MEDIUM',
            category: "Resource Allocation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-37 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes StatefulSet Missing VolumeClaimTemplate Storage Limits: StatefulSet volumeClaimTemplates omitting resources.requests.storage bounds."
            ],
            remediationPrompt: "Define explicit storage requests in volumeClaimTemplates.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ MEDIUM: IAC-37 finding in ${file.path}:${lineNum}`);
    }
    // IAC-38: AWS EKS Cluster Endpoint Publicly Accessible Without CIDR Whitelist
    if (/aws_eks_cluster\b/i.test(cleanContent) && /endpoint_public_access\s*=\s*true/i.test(cleanContent) && !/public_access_cidrs/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/endpoint_public_access\s*=\s*true/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac38-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8338,
            type: 'INFRA_DATABASE',
            title: "IAC-38: AWS EKS Cluster Endpoint Publicly Accessible Without CIDR Whitelist",
            severity: 'HIGH',
            category: "Kubernetes Control Plane",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-38 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS EKS Cluster Endpoint Publicly Accessible Without CIDR Whitelist: aws_eks_cluster setting endpoint_public_access = true without declaring public_access_cidrs."
            ],
            remediationPrompt: "Set endpoint_public_access = false or restrict public_access_cidrs to corporate IP addresses.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-38 finding in ${file.path}:${lineNum}`);
    }
    // IAC-39: AWS SQS Queue Missing Dead Letter Queue (RedrivePolicy)
    if (/aws_sqs_queue\b/i.test(cleanContent) && !/redrive_policy/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_sqs_queue\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac39-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8339,
            type: 'INFRA_DATABASE',
            title: "IAC-39: AWS SQS Queue Missing Dead Letter Queue (RedrivePolicy)",
            severity: 'HIGH',
            category: "Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-39 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS SQS Queue Missing Dead Letter Queue (RedrivePolicy): aws_sqs_queue omitting redrive_policy, allowing poisoned messages to loop endlessly."
            ],
            remediationPrompt: "Add redrive_policy with a dead letter queue target ARN to the SQS queue definition.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-39 finding in ${file.path}:${lineNum}`);
    }
    // IAC-40: AWS SNS Topic Missing KMS Customer-Managed Key Encryption
    if (/aws_sns_topic\b/i.test(cleanContent) && !/kms_master_key_id/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_sns_topic\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac40-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8340,
            type: 'INFRA_DATABASE',
            title: "IAC-40: AWS SNS Topic Missing KMS Customer-Managed Key Encryption",
            severity: 'MEDIUM',
            category: "Messaging Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-40 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS SNS Topic Missing KMS Customer-Managed Key Encryption: aws_sns_topic omitting kms_master_key_id."
            ],
            remediationPrompt: "Set kms_master_key_id = 'alias/aws/sns' or specify a customer-managed KMS key ARN.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ MEDIUM: IAC-40 finding in ${file.path}:${lineNum}`);
    }
    // IAC-41: Kubernetes Pod Missing Seccomp Profile Configuration
    if (/kind:\s*Pod\b/i.test(cleanContent) && !/seccompProfile/i.test(cleanContent) && /\.(?:ya?ml)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/kind:\s*Pod\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac41-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8341,
            type: 'INFRA_DATABASE',
            title: "IAC-41: Kubernetes Pod Missing Seccomp Profile Configuration",
            severity: 'MEDIUM',
            category: "Container Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-41 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Pod Missing Seccomp Profile Configuration: Pod securityContext omitting seccompProfile: { type: 'RuntimeDefault' }."
            ],
            remediationPrompt: "Add seccompProfile: { type: 'RuntimeDefault' } to pod securityContext.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ MEDIUM: IAC-41 finding in ${file.path}:${lineNum}`);
    }
    // IAC-42: AWS Lambda Function Runtime Using Deprecated Node.js or Python
    if (/aws_lambda_function\b/i.test(cleanContent) && /runtime\s*=\s*["\'](?:nodejs1[0-6]\.x|python3\.[6-8])["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/runtime\s*=\s*["\'](?:nodejs1[0-6]\.x|python3\.[6-8])["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac42-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8342,
            type: 'INFRA_DATABASE',
            title: "IAC-42: AWS Lambda Function Runtime Using Deprecated Node.js or Python",
            severity: 'HIGH',
            category: "Runtime Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-42 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS Lambda Function Runtime Using Deprecated Node.js or Python: aws_lambda_function using deprecated runtimes like nodejs14.x, nodejs16.x, or python3.8."
            ],
            remediationPrompt: "Upgrade Lambda runtime to an active LTS version (e.g. nodejs20.x or nodejs22.x).",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-42 finding in ${file.path}:${lineNum}`);
    }
    // IAC-43: Terraform AWS API Gateway Missing Access Logging
    if (/aws_apigatewayv2_stage\b/i.test(cleanContent) && !/access_log_settings/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_apigatewayv2_stage\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac43-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8343,
            type: 'INFRA_DATABASE',
            title: "IAC-43: Terraform AWS API Gateway Missing Access Logging",
            severity: 'MEDIUM',
            category: "API Observability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-43 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Terraform AWS API Gateway Missing Access Logging: aws_api_gateway_stage or aws_apigatewayv2_stage omitting access_log_settings."
            ],
            remediationPrompt: "Add access_log_settings block with destination_arn to API Gateway stages.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ MEDIUM: IAC-43 finding in ${file.path}:${lineNum}`);
    }
    // IAC-44: AWS RDS Parameter Group Enforcing SSL/TLS Disabled
    if (/aws_db_parameter_group\b/i.test(cleanContent) && /name\s*=\s*["\']rds\.force_ssl["\'][\s\S]*?value\s*=\s*["\']0["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/rds\.force_ssl/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac44-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8344,
            type: 'INFRA_DATABASE',
            title: "IAC-44: AWS RDS Parameter Group Enforcing SSL/TLS Disabled",
            severity: 'HIGH',
            category: "Database Transport",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-44 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS RDS Parameter Group Enforcing SSL/TLS Disabled: RDS parameter group setting rds.force_ssl = 0, allowing unencrypted database connections."
            ],
            remediationPrompt: "Set rds.force_ssl = 1 in the aws_db_parameter_group resource.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-44 finding in ${file.path}:${lineNum}`);
    }
    // IAC-45: Kubernetes Ingress Allowing Insecure Snippet Annotations
    if (/nginx\.ingress\.kubernetes\.io\/configuration-snippet/i.test(cleanContent) && /\.(?:ya?ml)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/nginx\.ingress\.kubernetes\.io\/configuration-snippet/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac45-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8345,
            type: 'INFRA_DATABASE',
            title: "IAC-45: Kubernetes Ingress Allowing Insecure Snippet Annotations",
            severity: 'CRITICAL',
            category: "Ingress Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-45 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Ingress Allowing Insecure Snippet Annotations: Ingress annotations using nginx.ingress.kubernetes.io/configuration-snippet allowing arbitrary Nginx directives."
            ],
            remediationPrompt: "Remove nginx configuration-snippet annotations from Ingress resources.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ CRITICAL: IAC-45 finding in ${file.path}:${lineNum}`);
    }
    // IAC-46: AWS Backup Plan Missing Production Vault Association
    if (/aws_backup_plan\b/i.test(cleanContent) && !/aws_backup_selection/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_backup_plan\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac46-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8346,
            type: 'INFRA_DATABASE',
            title: "IAC-46: AWS Backup Plan Missing Production Vault Association",
            severity: 'MEDIUM',
            category: "Disaster Recovery",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-46 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS Backup Plan Missing Production Vault Association: Production databases or EBS volumes not included in any automated aws_backup_selection rules."
            ],
            remediationPrompt: "Attach production storage resources to an automated AWS Backup selection plan.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ MEDIUM: IAC-46 finding in ${file.path}:${lineNum}`);
    }
    // IAC-47: AWS WAF WebACL Missing Common Rule Set (AWSManagedRulesCommonRuleSet)
    if (/aws_wafv2_web_acl\b/i.test(cleanContent) && !/AWSManagedRulesCommonRuleSet/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_wafv2_web_acl\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac47-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8347,
            type: 'INFRA_DATABASE',
            title: "IAC-47: AWS WAF WebACL Missing Common Rule Set (AWSManagedRulesCommonRuleSet)",
            severity: 'HIGH',
            category: "Application Firewall",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-47 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS WAF WebACL Missing Common Rule Set (AWSManagedRulesCommonRuleSet): aws_wafv2_web_acl omitting the standard AWSManagedRulesCommonRuleSet rule group."
            ],
            remediationPrompt: "Add AWSManagedRulesCommonRuleSet to the WAF WebACL rule declarations.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-47 finding in ${file.path}:${lineNum}`);
    }
    // IAC-48: Terraform AWS EC2 Instance Missing IMDSv2 Enforcement
    // IMDSv1 explicitly left on (http_tokens = "optional"): SSRF can read instance role credentials
    const iac48Line = isTf
        ? attrLineIn(tf, hclBlocks(tf, tfResource('aws_instance|aws_launch_template')).flatMap((b) => hclBlocks(tf, /\bmetadata_options/, b)), /\bhttp_tokens\s*=\s*"optional"/)
        : -1;
    if (iac48Line !== -1) {
        const matchLineIdx = iac48Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac48-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8348,
            type: 'INFRA_DATABASE',
            title: "IAC-48: Terraform AWS EC2 Instance Missing IMDSv2 Enforcement",
            severity: 'HIGH',
            category: "Instance Metadata",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-48 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Terraform AWS EC2 Instance Missing IMDSv2 Enforcement: aws_instance metadata_options setting http_tokens = 'optional', allowing legacy IMDSv1 SSRF credential theft."
            ],
            remediationPrompt: "Set metadata_options { http_tokens = 'required' } on all EC2 instances and launch templates.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ HIGH: IAC-48 finding in ${file.path}:${lineNum}`);
    }
    // IAC-49: Kubernetes Pod Tolerating All Taints (*)
    if (/tolerations:\s*\[[\s\S]*?operator:\s*["\']Exists["\'](?![^}]*key:)/i.test(cleanContent) && /\.(?:ya?ml)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/tolerations:\s*\[[\s\S]*?operator:\s*["\']Exists["\'](?![^}]*key:)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac49-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8349,
            type: 'INFRA_DATABASE',
            title: "IAC-49: Kubernetes Pod Tolerating All Taints (*)",
            severity: 'MEDIUM',
            category: "Workload Scheduling",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-49 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Pod Tolerating All Taints (*): Pod tolerations setting operator: 'Exists' without key, allowing pods to schedule on control plane master nodes."
            ],
            remediationPrompt: "Replace wildcard tolerations with specific node taint keys.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ MEDIUM: IAC-49 finding in ${file.path}:${lineNum}`);
    }
    // IAC-50: AWS Route 53 Hosted Zone Missing DNSSEC Verification
    if (/aws_route53_zone\b/i.test(cleanContent) && !/aws_route53_key_signing_key/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_route53_zone\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `iac50-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8350,
            type: 'INFRA_DATABASE',
            title: "IAC-50: AWS Route 53 Hosted Zone Missing DNSSEC Verification",
            severity: 'LOW',
            category: "DNS Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected IAC-50 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected AWS Route 53 Hosted Zone Missing DNSSEC Verification: aws_route53_hosted_zone lacking an aws_route53_key_signing_key resource for DNSSEC validation."
            ],
            remediationPrompt: "Configure aws_route53_key_signing_key and enable DNSSEC on the hosted zone.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 🏗️ LOW: IAC-50 finding in ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}

// ---------------------------------------------------------------------------------------------
// Shared Terraform / YAML / Dockerfile helpers (also used by the cloud-native, terraform-iac,
// k8s-hardening and container-security packs). Rules evaluate one resource block at a time so a
// setting in one resource is never paired with an unrelated resource elsewhere in the file.
// ---------------------------------------------------------------------------------------------

/** Blanks `#` comment lines (HCL, YAML, Dockerfile) while keeping line numbers stable. */
export const stripHashComments = (content: string): string => content.replace(/^[ \t]*#.*$/gm, '');

const lineAt = (content: string, index: number): number => content.slice(0, index).split('\n').length - 1;

export const isYamlPath = (path: string): boolean => /\.ya?ml$/i.test(path);

/** A brace-matched HCL block: `start` is the header offset, `offset`/`body` the text between the braces. */
export interface HclBlock { start: number; offset: number; body: string; label: string }

/** Header regex for `resource "<type>" "<name>"`; `type` may be an alternation. Captures the name. */
export const tfResource = (type: string): RegExp => new RegExp(`resource\\s+"(?:${type})"\\s+"([\\w-]+)"`);

/** Blocks whose header matches `header` (the `{` is appended), searched in `src` or inside `within`. */
export function hclBlocks(src: string, header: RegExp, within?: HclBlock): HclBlock[] {
    const text = within ? within.body : src;
    const base = within ? within.offset : 0;
    const re = new RegExp(`${header.source}\\s*\\{`, 'g');
    const blocks: HclBlock[] = [];
    for (const m of text.matchAll(re)) {
        const open = (m.index ?? 0) + m[0].length - 1;
        let depth = 0;
        let end = open;
        for (; end < text.length; end++) {
            if (text[end] === '{') depth++;
            else if (text[end] === '}' && --depth === 0) break;
        }
        blocks.push({ start: base + (m.index ?? 0), offset: base + open + 1, body: text.slice(open + 1, end), label: m[1] ?? '' });
    }
    return blocks;
}

/** 0-based line of the first `attr` match inside the block (the header line when absent). */
export function hclLine(src: string, block: HclBlock, attr?: RegExp): number {
    const m = attr ? new RegExp(attr.source, attr.flags.replace('g', '')).exec(block.body) : null;
    return lineAt(src, m ? block.offset + m.index : block.start);
}

/** First block (of `blocks`) whose body matches `attr`, as a 0-based line of that attribute; -1 when none. */
export function attrLineIn(src: string, blocks: HclBlock[], attr: RegExp, skip?: (b: HclBlock) => boolean): number {
    const hit = blocks.find((b) => attr.test(b.body) && !(skip && skip(b)));
    return hit ? hclLine(src, hit, attr) : -1;
}

/** A policy principal of everyone: "Principal": "*" or {"AWS": "*"} (heredoc JSON or jsonencode). */
export const PRINCIPAL_STAR = /"?\bPrincipal"?\s*[:=]\s*(?:"\*"|\{[^}]*"?\bAWS"?\s*[:=]\s*\[?\s*"\*")/;
/** Grants to everyone are scoped by a Condition, or the statement is a Deny guard. */
export const UNSCOPED_GRANT_EXEMPT = /"?\bCondition"?\s*[:=]|"?\bEffect"?\s*[:=]\s*"Deny"/;

const WORLD_CIDR =/(?:\bcidr_blocks|\bipv6_cidr_blocks)\s*=\s*\[[^\]]*"(?:0\.0\.0\.0\/0|::\/0)"|\bcidr_ipv[46]\s*=\s*"(?:0\.0\.0\.0\/0|::\/0)"/;

function ingressPorts(body: string): [number, number] | null {
    if (/\b(?:ip_)?protocol\s*=\s*"(?:-1|all)"/.test(body)) return [0, 65535];
    const from = /\bfrom_port\s*=\s*(\d+)/.exec(body);
    if (!from) return null;
    const to = /\bto_port\s*=\s*(\d+)/.exec(body);
    return [Number(from[1]), to ? Number(to[1]) : Number(from[1])];
}

/**
 * Terraform ingress rules open to the internet (0.0.0.0/0 or ::/0) whose port range covers one of
 * `ports`: inline `ingress {}` blocks of aws_security_group, aws_security_group_rule (type = "ingress")
 * and aws_vpc_security_group_ingress_rule. Returns the 0-based line of the CIDR, or -1.
 */
export function openIngressLine(src: string, ports: number[]): number {
    const candidates: HclBlock[] = [];
    for (const sg of hclBlocks(src, tfResource('aws_security_group'))) candidates.push(...hclBlocks(src, /\bingress/, sg));
    candidates.push(...hclBlocks(src, tfResource('aws_security_group_rule')).filter((b) => /\btype\s*=\s*"ingress"/.test(b.body)));
    candidates.push(...hclBlocks(src, tfResource('aws_vpc_security_group_ingress_rule')));
    for (const b of candidates) {
        const range = ingressPorts(b.body);
        if (range && WORLD_CIDR.test(b.body) && ports.some((p) => range[0] <= p && p <= range[1])) return hclLine(src, b, WORLD_CIDR);
    }
    return -1;
}

/** 0-based index of the first non-comment YAML line matching `re`; -1 when none. */
export const yamlLine = (lines: string[], re: RegExp): number => lines.findIndex((l) => !l.trim().startsWith('#') && re.test(l));

/** Kubernetes `capabilities.add` lists (flow `[A, B]` or block `- A` style), upper-cased, with their 0-based line. */
export function capabilityAdds(lines: string[]): { line: number; caps: string[] }[] {
    const out: { line: number; caps: string[] }[] = [];
    const parseFlow = (list: string) => list.replace(/[\[\]"']/g, '').split(',').map((c) => c.trim().toUpperCase()).filter(Boolean);
    lines.forEach((l, i) => {
        if (l.trim().startsWith('#')) return;
        const inline = /capabilities\s*:\s*\{[^}]*\badd\s*:\s*(\[[^\]]*\])/.exec(l);
        if (inline) {
            out.push({ line: i, caps: parseFlow(inline[1]) });
            return;
        }
        const m = /^\s*add\s*:\s*([^#]*)/.exec(l);
        if (!m || !lines.slice(Math.max(0, i - 4), i).some((p) => /^\s*capabilities\s*:\s*$/.test(p))) return;
        const rest = m[1].trim();
        if (rest.startsWith('[')) {
            out.push({ line: i, caps: parseFlow(rest) });
            return;
        }
        const caps: string[] = [];
        for (let j = i + 1; j < lines.length; j++) {
            const item = /^\s*-\s*["']?([\w]+)["']?\s*(?:#.*)?$/.exec(lines[j]);
            if (!item) break;
            caps.push(item[1].toUpperCase());
        }
        out.push({ line: i, caps });
    });
    return out;
}
