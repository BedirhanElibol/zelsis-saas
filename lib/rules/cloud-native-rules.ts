/**
 * Zelsis Master evaluateCloudNativeRules Engine (50 Rules)
 * Rules CLOUD-01 to CLOUD-50 (Rule IDs 7001 to 7050).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { locateMatchLine } from './shared/locate';
import { hclBlocks, hclLine, isYamlPath, openIngressLine, stripHashComments, tfResource, yamlLine } from './iac-rules';
export interface CloudNativeRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateCloudNativeRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): CloudNativeRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // Comment-stripped lines (same numbering as `lines`) for line-level rules
    const cleanLines = cleanContent.split('\n');
    // CLOUD-04: Docker Container Running as Default Root User
    if (file.path.toLowerCase().endsWith("dockerfile") && !/USER\s+[a-zA-Z0-9_-]+/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/cloud-04|docker/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud04-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7004,
            type: 'INFRA_DATABASE',
            title: "CLOUD-04: Docker Container Running as Default Root User",
            severity: 'HIGH',
            category: "Container Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-04 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Docker Container Running as Default Root User: Dockerfiles omitting USER instruction, running application processes with container root privileges."
            ],
            remediationPrompt: "Add RUN adduser -D appuser && USER appuser before CMD/ENTRYPOINT.",
            status: 'OPEN',
            owner: "Docker / OCI",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-04: Docker Container Running as Default Root User detected (${file.path}:${lineNum})`);
    }
    // CLOUD-05: Docker Base Image Using Mutable 'latest' Tag
    if (file.path.toLowerCase().endsWith("dockerfile") && /FROM\s+[a-zA-Z0-9_./-]+:latest\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/FROM\s+[a-zA-Z0-9_./-]+:latest\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud05-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7005,
            type: 'INFRA_DATABASE',
            title: "CLOUD-05: Docker Base Image Using Mutable 'latest' Tag",
            severity: 'MEDIUM',
            category: "Container Immutability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-05 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Docker Base Image Using Mutable 'latest' Tag: FROM node:latest or FROM alpine:latest causing non-deterministic builds and breaking upstream changes."
            ],
            remediationPrompt: "Pin base image: FROM node:22.14.0-alpine3.21 instead of node:latest.",
            status: 'OPEN',
            owner: "Docker",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-05: Docker Base Image Using Mutable 'latest' Tag detected (${file.path}:${lineNum})`);
    }
    // CLOUD-06: Docker Secret Leak via Build ARG or ENV
    // A literal secret value baked into an ARG default or ENV (kept in image history). Public client keys
    // (NEXT_PUBLIC_/VITE_/PUBLIC_), empty values, ${...} references and build placeholders are skipped.
    const dockerSecretRe = /^\s*(?:ARG|ENV)\s+(?!(?:NEXT_PUBLIC|VITE|PUBLIC|EXPO_PUBLIC|REACT_APP)_)[A-Za-z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Za-z0-9_]*\s*=\s*["']?(?![$"'\s]|(?:dummy|placeholder|changeme|example|build|ci|test|x+|none)\b)[^\s"']{6,}/i;
    const docker06Idx = file.path.toLowerCase().endsWith("dockerfile") ? lines.findIndex(l => dockerSecretRe.test(l)) : -1;
    if (docker06Idx !== -1) {
        const matchLineIdx = docker06Idx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `cloud06-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7006,
            type: 'INFRA_DATABASE',
            title: "CLOUD-06: Docker Secret Leak via Build ARG or ENV",
            severity: 'HIGH',
            category: "Container Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-06 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Docker Secret Leak via Build ARG or ENV: Passing sensitive API keys, DB passwords, or tokens via ARG or ENV directives preserved in image layers."
            ],
            remediationPrompt: "Use Docker BuildKit secret mounts: RUN --mount=type=secret,id=npmrc npm install.",
            status: 'OPEN',
            owner: "Docker",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-06: Docker Secret Leak via Build ARG or ENV detected (${file.path}:${lineNum})`);
    }
    // CLOUD-07: Missing Multi-Stage Build in Production Dockerfile
    // A single-stage image (one FROM) that runs the JS build: the toolchain and devDependencies ship to production.
    const docker07Idx = file.path.toLowerCase().endsWith("dockerfile") && (cleanContent.match(/^\s*FROM\s+/gim) || []).length === 1
        ? lines.findIndex(l => /^\s*RUN\s+.*\b(?:npm\s+run\s+build|yarn\s+(?:run\s+)?build|pnpm\s+(?:run\s+)?build|bun\s+run\s+build)\b/i.test(l))
        : -1;
    if (docker07Idx !== -1) {
        const matchLineIdx = docker07Idx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `cloud07-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7007,
            type: 'INFRA_DATABASE',
            title: "CLOUD-07: Missing Multi-Stage Build in Production Dockerfile",
            severity: 'LOW',
            category: "Image Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-07 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Multi-Stage Build in Production Dockerfile: Shipping build toolchains (compilers, npm devDependencies) inside the final runtime container image."
            ],
            remediationPrompt: "Adopt multi-stage build: copy only compiled dist/ artifacts and production dependencies to runtime stage.",
            status: 'OPEN',
            owner: "Docker",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-07: Missing Multi-Stage Build in Production Dockerfile detected (${file.path}:${lineNum})`);
    }
    // CLOUD-13: Kubernetes Pod Running with Privileged SecurityContext
    // Only `privileged: true` (allowPrivilegeEscalation: true is the Kubernetes default, a hardening gap rather than a privileged pod)
    const cloud13Line = isYamlPath(lowerPath) && /^\s*apiVersion\s*:/m.test(cleanContent) ? yamlLine(lines, /^\s*privileged\s*:\s*true\b/) : -1;
    if (cloud13Line !== -1) {
        const matchLineIdx = cloud13Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud13-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7013,
            type: 'INFRA_DATABASE',
            title: "CLOUD-13: Kubernetes Pod Running with Privileged SecurityContext",
            severity: 'CRITICAL',
            category: "Container Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-13 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Pod Running with Privileged SecurityContext: Pod securityContext setting privileged: true or allowPrivilegeEscalation: true."
            ],
            remediationPrompt: "Set securityContext: privileged: false, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true.",
            status: 'OPEN',
            owner: "K8s",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-13: Kubernetes Pod Running with Privileged SecurityContext detected (${file.path}:${lineNum})`);
    }
    // CLOUD-15: Lambda Cold Start Heavy Module Initialization
    // An AWS SDK v3 client constructed inside the exported Lambda handler body (rebuilt on every invocation instead of
    // reused across warm starts). PrismaClient per request is INFRA-09 (3009).
    const cloud15Idx = (() => {
        const head = /export\s+(?:async\s+function\s+handler\s*\([^)]*\)[^{]*\{|function\s+handler\s*\([^)]*\)[^{]*\{|const\s+handler\b[^=]*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*(?::[^=]*)?=>\s*\{)/.exec(cleanContent);
        if (!head) return -1;
        const open = head.index + head[0].length - 1;
        let depth = 0;
        let end = open;
        for (; end < cleanContent.length; end++) {
            if (cleanContent[end] === '{') depth++;
            else if (cleanContent[end] === '}' && --depth === 0) break;
        }
        const client = /\bnew\s+(?:S3Client|DynamoDBClient|SQSClient|SNSClient|SESClient|SESv2Client|SecretsManagerClient|SSMClient|LambdaClient|KinesisClient|EventBridgeClient)\s*\(/.exec(cleanContent.slice(open, end));
        return client ? cleanContent.slice(0, open + client.index).split('\n').length - 1 : -1;
    })();
    if (cloud15Idx !== -1) {
        const matchLineIdx = cloud15Idx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `cloud15-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7015,
            type: 'INFRA_DATABASE',
            title: "CLOUD-15: Lambda Cold Start Heavy Module Initialization",
            severity: 'LOW',
            category: "Serverless Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-15 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lambda Cold Start Heavy Module Initialization: Instantiating heavy clients, loading entire SDKs, or reading files inside the invocation handler rather than global scope."
            ],
            remediationPrompt: "Move SDK instantiation (new S3Client(), new PrismaClient()) outside the handler function.",
            status: 'OPEN',
            owner: "Node.js / AWS Lambda",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-15: Lambda Cold Start Heavy Module Initialization detected (${file.path}:${lineNum})`);
    }
    // CLOUD-20: CloudFormation / CDK Wildcard IAM Action (Action: '*')
    // Action '*' in an Allow statement: CloudFormation YAML/JSON, CDK PolicyStatement (`actions: ['*']`) or HCL.
    // The statement context (Effect / PolicyStatement) must sit within a few lines, so app-level RBAC
    // config such as `{ role: 'admin', actions: ['*'] }` is not mistaken for an IAM policy.
    const cloud20Line = (() => {
        if (lowerPath.includes('test')) return -1;
        const starAction = /(?:\bAction"?\s*[:=]\s*\[?\s*['"]\*['"]|\bactions\s*[:=]\s*\[\s*['"]\*['"]\s*\])/;
        for (let i = 0; i < lines.length; i++) {
            const l = cleanLines[i];
            if (/^\s*(?:\/\/|#|\*)/.test(l) || !starAction.test(l)) continue;
            const statement = cleanLines.slice(Math.max(0, i - 6), i + 7).join('\n');
            if (/PolicyStatement|\bEffect"?\s*[:=]|\beffect\s*=/.test(statement) && !/\bDeny\b|Effect\.DENY/.test(statement)) return i;
        }
        return -1;
    })();
    if (cloud20Line !== -1) {
        const matchLineIdx = cloud20Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud20-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7020,
            type: 'INFRA_DATABASE',
            title: "CLOUD-20: CloudFormation / CDK Wildcard IAM Action (Action: '*')",
            severity: 'CRITICAL',
            category: "Cloud IAM Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-20 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected CloudFormation / CDK Wildcard IAM Action (Action: '*'): IAM role policies granting Action: '*' or Action: 's3:*' violating principle of least privilege."
            ],
            remediationPrompt: "Replace wildcard actions with explicit least-privilege action permissions.",
            status: 'OPEN',
            owner: "IAM / CDK",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-20: CloudFormation / CDK Wildcard IAM Action (Action: '*') detected (${file.path}:${lineNum})`);
    }
    // CLOUD-26: CloudFront Missing Enforced HTTPS Redirection
    // CloudFront-only setting: Terraform, CloudFormation (quoted or bare) and CDK (ViewerProtocolPolicy.ALLOW_ALL)
    const cloud26Line = yamlLine(cleanLines, /\bviewer_?protocol_?policy"?\s*[:=]\s*(?:['"]?allow-all\b|(?:\w+\.)?ViewerProtocolPolicy\.ALLOW_ALL\b)/i);
    if (cloud26Line !== -1) {
        const matchLineIdx = cloud26Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud26-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7026,
            type: 'INFRA_DATABASE',
            title: "CLOUD-26: CloudFront Missing Enforced HTTPS Redirection",
            severity: 'HIGH',
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-26 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected CloudFront Missing Enforced HTTPS Redirection: CloudFront distribution viewer protocol policy set to 'allow-all' instead of 'redirect-to-https'."
            ],
            remediationPrompt: "Set ViewerProtocolPolicy: redirect-to-https in CloudFront cache behaviors.",
            status: 'OPEN',
            owner: "CloudFront",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-26: CloudFront Missing Enforced HTTPS Redirection detected (${file.path}:${lineNum})`);
    }
    // CLOUD-27: CloudFront Insecure Legacy TLS Protocol Version (<TLSv1.2)
    // CloudFormation (MinimumProtocolVersion: TLSv1, quoted or bare) and CDK (SecurityPolicyProtocol.TLS_V1_2016 etc.);
    // Terraform minimum_protocol_version is covered by IAC-35
    const cloud27Line = yamlLine(cleanLines, /\bminimumProtocolVersion"?\s*:\s*(?:['"]?(?:SSLv3|TLSv1|TLSv1_2016|TLSv1\.1_2016)['"]?\s*,?\s*$|(?:\w+\.)?SecurityPolicyProtocol\.(?:SSL_V3|TLS_V1(?:_2016|_1_2016)?)\b)/i);
    if (cloud27Line !== -1) {
        const matchLineIdx = cloud27Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud27-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7027,
            type: 'INFRA_DATABASE',
            title: "CLOUD-27: CloudFront Insecure Legacy TLS Protocol Version (<TLSv1.2)",
            severity: 'HIGH',
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-27 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected CloudFront Insecure Legacy TLS Protocol Version (<TLSv1.2): CloudFront minimum protocol version set to TLSv1 or TLSv1_2016."
            ],
            remediationPrompt: "Update CloudFront ViewerCertificate to use MinimumProtocolVersion: TLSv1.2_2021.",
            status: 'OPEN',
            owner: "CloudFront",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-27: CloudFront Insecure Legacy TLS Protocol Version (<TLSv1.2) detected (${file.path}:${lineNum})`);
    }
    // CLOUD-29: Indefinite CloudWatch Log Retention Period
    // Terraform: per aws_cloudwatch_log_group block without retention_in_days (0 / unset = never expire);
    // CloudFormation: a LogGroup in a template with no RetentionInDays. CDK defaults to two years and is not checked.
    const tf29 = /\.tf$/i.test(lowerPath) ? stripHashComments(cleanContent) : '';
    const cloud29Line = tf29
        ? (() => { const b = hclBlocks(tf29, tfResource('aws_cloudwatch_log_group')).find((r) => !/\bretention_in_days\s*=\s*[1-9]/.test(r.body)); return b ? hclLine(tf29, b) : -1; })()
        : /^\s*Type\s*:\s*['"]?AWS::Logs::LogGroup\b/m.test(cleanContent) && !/\bRetentionInDays\s*:/.test(cleanContent)
            ? yamlLine(cleanLines, /^\s*Type\s*:\s*['"]?AWS::Logs::LogGroup\b/) : -1;
    if (cloud29Line !== -1) {
        const matchLineIdx = cloud29Line;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `cloud29-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7029,
            type: 'INFRA_DATABASE',
            title: "CLOUD-29: Indefinite CloudWatch Log Retention Period",
            severity: 'LOW',
            category: "Cloud Cost Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-29 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Indefinite CloudWatch Log Retention Period: CloudWatch log groups retaining logs indefinitely with RetentionInDays omitted, accumulating storage charges."
            ],
            remediationPrompt: "Set RetentionInDays: 90 on all CloudWatch log groups.",
            status: 'OPEN',
            owner: "CloudWatch",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-29: Indefinite CloudWatch Log Retention Period detected (${file.path}:${lineNum})`);
    }
    // CLOUD-30: Terraform / OpenTofu Plaintext Secret in Output
    // Output names ending in a secret noun (not kms_key_arn / key_pair_name / ssh_key_id identifiers)
    const tfSrc = /\.tf$/i.test(lowerPath) ? stripHashComments(cleanContent) : '';
    const cloud30 = tfSrc ? hclBlocks(tfSrc, /output\s+"([\w-]*(?:password|secret|api_key|private_key|access_key|token))"/i).find((b) => !/\bsensitive\s*=\s*true\b/.test(b.body)) : undefined;
    if (cloud30) {
        const matchLineIdx = hclLine(tfSrc, cloud30);
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud30-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7030,
            type: 'INFRA_DATABASE',
            title: "CLOUD-30: Terraform / OpenTofu Plaintext Secret in Output",
            severity: 'MEDIUM',
            category: "IaC Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-30 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Terraform / OpenTofu Plaintext Secret in Output: Terraform output blocks exposing database passwords or tokens without sensitive = true attribute."
            ],
            remediationPrompt: "Add sensitive = true to the output definition in Terraform.",
            status: 'OPEN',
            owner: "Terraform",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-30: Terraform / OpenTofu Plaintext Secret in Output detected (${file.path}:${lineNum})`);
    }
    // CLOUD-31: Terraform State Backend Missing Encryption at Rest
    // An empty block is partial configuration (-backend-config), which the scanner cannot see
    if (/\.tf$/i.test(file.path) && /backend\s+["\']s3["\']\s*\{(?!\s*\})(?![^}]*encrypt\s*=\s*true)/i.test(stripHashComments(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/backend\s+["\']s3["\']\s*\{(?![^}]*encrypt\s*=\s*true)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud31-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7031,
            type: 'INFRA_DATABASE',
            title: "CLOUD-31: Terraform State Backend Missing Encryption at Rest",
            severity: 'MEDIUM',
            category: "IaC Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-31 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Terraform State Backend Missing Encryption at Rest: S3 or remote backend for terraform.tfstate lacking server-side encryption or DynamoDB state locking."
            ],
            remediationPrompt: "Add encrypt = true and dynamodb_table = 'terraform-locks' to the backend S3 config.",
            status: 'OPEN',
            owner: "Terraform Backend",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-31: Terraform State Backend Missing Encryption at Rest detected (${file.path}:${lineNum})`);
    }
    // CLOUD-36: Missing CloudTrail Multi-Region Audit Logging
    if (/(?:AWS::CloudTrail::Trail|aws_cloudtrail)\b/i.test(cleanContent) && /isMultiRegionTrail\s*:\s*false|is_multi_region_trail\s*=\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/isMultiRegionTrail\s*:\s*false|is_multi_region_trail\s*=\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud36-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7036,
            type: 'INFRA_DATABASE',
            title: "CLOUD-36: Missing CloudTrail Multi-Region Audit Logging",
            severity: 'MEDIUM',
            category: "Cloud Compliance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-36 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing CloudTrail Multi-Region Audit Logging: AWS account CloudTrail configuration set to single region or omitting global service events."
            ],
            remediationPrompt: "Enable IsMultiRegionTrail: true on AWS CloudTrail audit configuration.",
            status: 'OPEN',
            owner: "AWS CloudTrail",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-36: Missing CloudTrail Multi-Region Audit Logging detected (${file.path}:${lineNum})`);
    }
    // CLOUD-37: ECR Container Image Repository Vulnerability Scan Disabled
    // Terraform: per aws_ecr_repository block; CloudFormation: the template declaring the repository
    const cloud37Line = tfSrc
        ? (() => { const b = hclBlocks(tfSrc, tfResource('aws_ecr_repository')).find((r) => !/\bscan_on_push\s*=\s*true\b/.test(r.body)); return b ? hclLine(tfSrc, b) : -1; })()
        : /^\s*Type\s*:\s*['"]?AWS::ECR::Repository\b/m.test(cleanContent) && !/\bScanOnPush\s*:\s*['"]?true\b/i.test(cleanContent)
            ? yamlLine(cleanLines, /^\s*Type\s*:\s*['"]?AWS::ECR::Repository\b/) : -1;
    if (cloud37Line !== -1) {
        const matchLineIdx = cloud37Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud37-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7037,
            type: 'INFRA_DATABASE',
            title: "CLOUD-37: ECR Container Image Repository Vulnerability Scan Disabled",
            severity: 'MEDIUM',
            category: "Container Registry",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-37 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected ECR Container Image Repository Vulnerability Scan Disabled: Container image registries created without scanOnPush or continuous vulnerability scanning enabled."
            ],
            remediationPrompt: "Configure imageScanningConfiguration: { scanOnPush: true } on ECR repositories.",
            status: 'OPEN',
            owner: "AWS ECR / GCR",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-37: ECR Container Image Repository Vulnerability Scan Disabled detected (${file.path}:${lineNum})`);
    }
    // CLOUD-38: ECR Container Repository Tag Mutability Enabled
    if (/(?:AWS::ECR::Repository|aws_ecr_repository)\b/i.test(cleanContent) && /imageTagMutability\s*:\s*[\'"]MUTABLE[\'"]|image_tag_mutability\s*=\s*[\'"]MUTABLE[\'"]/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/imageTagMutability\s*:\s*[\'"]MUTABLE[\'"]|image_tag_mutability\s*=\s*[\'"]MUTABLE[\'"]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud38-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7038,
            type: 'INFRA_DATABASE',
            title: "CLOUD-38: ECR Container Repository Tag Mutability Enabled",
            severity: 'LOW',
            category: "Supply Chain Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-38 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected ECR Container Repository Tag Mutability Enabled: ECR repositories configured with MUTABLE image tags allowing tags like v1.0.0 to be overwritten maliciously."
            ],
            remediationPrompt: "Set imageTagMutability: IMMUTABLE on all production ECR repositories.",
            status: 'OPEN',
            owner: "AWS ECR",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-38: ECR Container Repository Tag Mutability Enabled detected (${file.path}:${lineNum})`);
    }
    // CLOUD-40: Security Group Permissive Inbound Ingress (0.0.0.0/0)
    // Admin / database ports open to the internet: Terraform ingress rules (per rule block) and CDK
    // `addIngressRule(Peer.anyIpv4(), Port.tcp(22))`
    const exposedPorts = [22, 3389, 5432, 3306, 27017, 6379];
    const cloud40Line = /\.tf$/i.test(lowerPath)
        ? openIngressLine(stripHashComments(cleanContent), exposedPorts)
        : yamlLine(cleanLines, /addIngressRule\(\s*(?:\w+\.)?Peer\.any(?:Ipv4|Ipv6)\(\)\s*,\s*(?:\w+\.)?Port\.tcp\(\s*(?:22|3389|5432|3306|27017|6379)\s*\)/);
    if (cloud40Line !== -1) {
        const matchLineIdx = cloud40Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud40-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7040,
            type: 'INFRA_DATABASE',
            title: "CLOUD-40: Security Group Permissive Inbound Ingress (0.0.0.0/0)",
            severity: 'CRITICAL',
            category: "Network Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-40 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Security Group Permissive Inbound Ingress (0.0.0.0/0): Security groups allowing unrestricted inbound traffic (0.0.0.0/0) on non-HTTP ports (SSH 22, RDP 3389, DB 5432)."
            ],
            remediationPrompt: "Restrict security group ingress to specific bastion CIDRs or internal VPC security groups.",
            status: 'OPEN',
            owner: "AWS Security Groups",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-40: Security Group Permissive Inbound Ingress (0.0.0.0/0) detected (${file.path}:${lineNum})`);
    }
    // CLOUD-41: Missing AWS KMS Key Automatic Rotation
    if (/(?:AWS::KMS::Key|aws_kms_key)\b/i.test(cleanContent) && /enableKeyRotation\s*:\s*false|enable_key_rotation\s*=\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/enableKeyRotation\s*:\s*false|enable_key_rotation\s*=\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud41-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7041,
            type: 'INFRA_DATABASE',
            title: "CLOUD-41: Missing AWS KMS Key Automatic Rotation",
            severity: 'MEDIUM',
            category: "Key Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-41 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing AWS KMS Key Automatic Rotation: Customer managed KMS keys configured with EnableKeyRotation: false."
            ],
            remediationPrompt: "Set EnableKeyRotation: true on all AWS KMS Customer Master Keys.",
            status: 'OPEN',
            owner: "AWS KMS",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-41: Missing AWS KMS Key Automatic Rotation detected (${file.path}:${lineNum})`);
    }
    // CLOUD-42: Lambda Function Invocation URL Missing AuthType
    if (/(?:AWS::Lambda::Url|aws_lambda_function_url)\b/i.test(cleanContent) && /authType\s*:\s*[\'"]NONE[\'"]|authorization_type\s*=\s*[\'"]NONE[\'"]/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/authType\s*:\s*[\'"]NONE[\'"]|authorization_type\s*=\s*[\'"]NONE[\'"]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud42-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7042,
            type: 'INFRA_DATABASE',
            title: "CLOUD-42: Lambda Function Invocation URL Missing AuthType",
            severity: 'MEDIUM',
            category: "Serverless Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-42 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lambda Function Invocation URL Missing AuthType: Lambda Function URLs created with AuthType: 'NONE' exposing internal serverless logic to the open internet."
            ],
            remediationPrompt: "Set AuthType: AWS_IAM or front Lambda URL with an API Gateway Authorizer.",
            status: 'OPEN',
            owner: "AWS Lambda",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-42: Lambda Function Invocation URL Missing AuthType detected (${file.path}:${lineNum})`);
    }
    // CLOUD-43: Redis / ElastiCache Cluster Missing In-Transit Encryption
    if (/(?:AWS::ElastiCache::ReplicationGroup|aws_elasticache_replication_group)\b/i.test(cleanContent) && /transitEncryptionEnabled\s*:\s*false|transit_encryption_enabled\s*=\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/transitEncryptionEnabled\s*:\s*false|transit_encryption_enabled\s*=\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud43-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7043,
            type: 'INFRA_DATABASE',
            title: "CLOUD-43: Redis / ElastiCache Cluster Missing In-Transit Encryption",
            severity: 'MEDIUM',
            category: "Data In Transit",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-43 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Redis / ElastiCache Cluster Missing In-Transit Encryption: ElastiCache or Redis clusters deployed with TransitEncryptionEnabled: false transmitting data in plaintext."
            ],
            remediationPrompt: "Enable TransitEncryptionEnabled: true and AtRestEncryptionEnabled: true on ElastiCache clusters.",
            status: 'OPEN',
            owner: "Redis / ElastiCache",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-43: Redis / ElastiCache Cluster Missing In-Transit Encryption detected (${file.path}:${lineNum})`);
    }
    // CLOUD-44: Redis / ElastiCache Missing Auth Token Requirement
    // Terraform: per replication group block (auth_token or RBAC user_group_ids); CloudFormation: per template
    const cloud44Line = tfSrc
        ? (() => { const b = hclBlocks(tfSrc, tfResource('aws_elasticache_replication_group')).find((r) => !/\b(?:auth_token|user_group_ids)\s*=/.test(r.body)); return b ? hclLine(tfSrc, b) : -1; })()
        : /^\s*Type\s*:\s*['"]?AWS::ElastiCache::ReplicationGroup\b/m.test(cleanContent) && !/\bAuthToken\s*:|\bUserGroupIds\s*:/.test(cleanContent)
            ? yamlLine(cleanLines, /^\s*Type\s*:\s*['"]?AWS::ElastiCache::ReplicationGroup\b/) : -1;
    if (cloud44Line !== -1) {
        const matchLineIdx = cloud44Line;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud44-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7044,
            type: 'INFRA_DATABASE',
            title: "CLOUD-44: Redis / ElastiCache Missing Auth Token Requirement",
            severity: 'MEDIUM',
            category: "Cache Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-44 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Redis / ElastiCache Missing Auth Token Requirement: Redis cluster accessible without AUTH token password protection on internal VPC subnet."
            ],
            remediationPrompt: "Set AuthToken parameter on Redis replication group resource.",
            status: 'OPEN',
            owner: "Redis / ElastiCache",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-44: Redis / ElastiCache Missing Auth Token Requirement detected (${file.path}:${lineNum})`);
    }
    // CLOUD-49: Kubernetes Service Account Automatic Token Mounting
    if (/(?:kind:\s*Pod|kind:\s*ServiceAccount)/i.test(cleanContent) && /automountServiceAccountToken\s*:\s*true/i.test(cleanContent) && /\.(?:ya?ml)$/i.test(file.path)) {
        const matchLineIdx = locateMatchLine(lines, [/automountServiceAccountToken\s*:\s*true/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cloud49-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7049,
            type: 'INFRA_DATABASE',
            title: "CLOUD-49: Kubernetes Service Account Automatic Token Mounting",
            severity: 'LOW',
            category: "Kubernetes Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CLOUD-49 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Kubernetes Service Account Automatic Token Mounting: Pods automatically mounting default service account tokens into /var/run/secrets/kubernetes.io/serviceaccount."
            ],
            remediationPrompt: "Set automountServiceAccountToken: false in Pod or ServiceAccount spec.",
            status: 'OPEN',
            owner: "K8s",
            falsePositive: false
        });
        logs.push(`[${ts}] ☁️ CLOUD-49: Kubernetes Service Account Automatic Token Mounting detected (${file.path}:${lineNum})`);
    }
    return { findings, logs };
}
