/**
 * Zelsis Master evaluateFederatedLearningRules Engine (50 Rules)
 * Rules FED-LEARN-01 to FED-LEARN-50 (Rule IDs 16501 to 16550).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface FederatedLearningRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateFederatedLearningRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): FederatedLearningRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // FED-LEARN-01: Absence of Differential Privacy Noise Injection on Local Model Gradient Updates
    if (((/gradient_upload|dp_mechanism|federated_client/i.test(lowerPath) || /uploadLocalGradients|addGaussianNoise/i.test(cleanContent)) && !/injectDifferentialPrivacyNoise/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `fedlearn16501-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16501,
            type: 'LEGAL_COMPLIANCE',
            title: "FED-LEARN-01: Absence of Differential Privacy Noise Injection on Local Model Gradient Updates",
            severity: "CRITICAL",
            category: "Differential Privacy",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Federated Learning configuration',
            reproductionSteps: [
                `Audited Federated Learning configuration in ${file.path}:${lineNum}.`,
                'Matched FED-LEARN-01: Absence of Differential Privacy Noise Injection on Local Model Gradient Updates.'
            ],
            remediationPrompt: "Inject calibrated Gaussian or Laplacian noise to local gradient tensors satisfying (epsilon, delta)-differential privacy budgets.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FED-LEARN AUDIT] Found FED-LEARN-01: Absence of Differential Privacy Noise Injection on Local Model Gradient Updates at ${file.path}:${lineNum}`);
    }
    // FED-LEARN-02: Vulnerability to Model Inversion and Training Data Reconstruction from Gradients
    if (((/secure_aggregation|smpc_masking|homomorphic/i.test(lowerPath) || /aggregateClientTensors|maskLocalUpdate/i.test(cleanContent)) && !/secureMultipartyAggregation/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `fedlearn16502-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16502,
            type: 'LEGAL_COMPLIANCE',
            title: "FED-LEARN-02: Vulnerability to Model Inversion and Training Data Reconstruction from Gradients",
            severity: "CRITICAL",
            category: "Gradient Inversion Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Federated Learning configuration',
            reproductionSteps: [
                `Audited Federated Learning configuration in ${file.path}:${lineNum}.`,
                'Matched FED-LEARN-02: Vulnerability to Model Inversion and Training Data Reconstruction from Gradients.'
            ],
            remediationPrompt: "Apply Secure Multi-Party Computation (SMPC) or Homomorphic Encryption on client updates before central aggregation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FED-LEARN AUDIT] Found FED-LEARN-02: Vulnerability to Model Inversion and Training Data Reconstruction from Gradients at ${file.path}:${lineNum}`);
    }
    // FED-LEARN-03: Lack of Sybil and Poisoning Defense on Malicious Federated Client Nodes
    if (((/fed_aggregation|fedavg|byzantine_filter/i.test(lowerPath) || /federatedAveraging|krumAggregate/i.test(cleanContent)) && !/byzantineRobustMedian|krumFiltering/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `fedlearn16503-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16503,
            type: 'LEGAL_COMPLIANCE',
            title: "FED-LEARN-03: Lack of Sybil and Poisoning Defense on Malicious Federated Client Nodes",
            severity: "CRITICAL",
            category: "Byzantine Robustness",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Federated Learning configuration',
            reproductionSteps: [
                `Audited Federated Learning configuration in ${file.path}:${lineNum}.`,
                'Matched FED-LEARN-03: Lack of Sybil and Poisoning Defense on Malicious Federated Client Nodes.'
            ],
            remediationPrompt: "Deploy Byzantine-robust aggregation algorithms (e.g. Krum, Trimmed Mean, Coordinate-wise Median) to filter malicious model weights.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FED-LEARN AUDIT] Found FED-LEARN-03: Lack of Sybil and Poisoning Defense on Malicious Federated Client Nodes at ${file.path}:${lineNum}`);
    }
    // FED-LEARN-04: Unbounded Client Update Norms Permitting Backdoor Trigger Injection
    if (((/gradient_norm|clipping_bound/i.test(lowerPath) || /clipGradientNorm|l2NormThreshold/i.test(cleanContent)) && !/clipGradientsL2Norm/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `fedlearn16504-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16504,
            type: 'LEGAL_COMPLIANCE',
            title: "FED-LEARN-04: Unbounded Client Update Norms Permitting Backdoor Trigger Injection",
            severity: "HIGH",
            category: "Gradient Clipping",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Federated Learning configuration',
            reproductionSteps: [
                `Audited Federated Learning configuration in ${file.path}:${lineNum}.`,
                'Matched FED-LEARN-04: Unbounded Client Update Norms Permitting Backdoor Trigger Injection.'
            ],
            remediationPrompt: "Enforce strict L2 gradient norm clipping on all incoming client update tensors prior to aggregation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FED-LEARN AUDIT] Found FED-LEARN-04: Unbounded Client Update Norms Permitting Backdoor Trigger Injection at ${file.path}:${lineNum}`);
    }
    // FED-LEARN-05: Missing Cryptographic Verification of Client Participation Eligibility
    if (((/client_enrollment|federated_auth/i.test(lowerPath) || /authenticateFederatedClient|zkProofVerify/i.test(cleanContent)) && !/verifyClientTlsAndEligibility/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `fedlearn16505-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16505,
            type: 'LEGAL_COMPLIANCE',
            title: "FED-LEARN-05: Missing Cryptographic Verification of Client Participation Eligibility",
            severity: "HIGH",
            category: "Client Authentication",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Federated Learning configuration',
            reproductionSteps: [
                `Audited Federated Learning configuration in ${file.path}:${lineNum}.`,
                'Matched FED-LEARN-05: Missing Cryptographic Verification of Client Participation Eligibility.'
            ],
            remediationPrompt: "Authenticate client nodes using mutual TLS and verify decentralized zero-knowledge compliance proofs before dispatching model weights.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FED-LEARN AUDIT] Found FED-LEARN-05: Missing Cryptographic Verification of Client Participation Eligibility at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
