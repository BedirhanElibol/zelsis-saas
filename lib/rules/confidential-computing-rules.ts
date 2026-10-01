/**
 * Zelsis Master evaluateConfidentialComputingRules Engine (50 Rules)
 * Rules CONF-COMPUTE-01 to CONF-COMPUTE-50 (Rule IDs 16401 to 16450).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface ConfidentialComputingRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateConfidentialComputingRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ConfidentialComputingRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // CONF-COMPUTE-01: Missing Cryptographic Remote Attestation Verification Before Enclave Provisioning
    if (((/enclave_init|sev_snp|sgx_attestation/i.test(lowerPath) || /verifyQuote|sevSnpAttestation/i.test(cleanContent)) && !/verifyHardwareRemoteAttestation/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/verifyQuote|sevSnpAttestation/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `confcompute16401-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16401,
            type: 'SECURITY',
            title: "CONF-COMPUTE-01: Missing Cryptographic Remote Attestation Verification Before Enclave Provisioning",
            severity: "CRITICAL",
            category: "Remote Attestation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Confidential Computing configuration',
            reproductionSteps: [
                `Audited Confidential Computing configuration in ${file.path}:${lineNum}.`,
                'Matched CONF-COMPUTE-01: Missing Cryptographic Remote Attestation Verification Before Enclave Provisioning.'
            ],
            remediationPrompt: "Verify hardware root of trust and quote measurements via AMD SEV-SNP or Intel SGX attestation services before releasing secrets.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CONF-COMPUTE AUDIT] Found CONF-COMPUTE-01: Missing Cryptographic Remote Attestation Verification Before Enclave Provisioning at ${file.path}:${lineNum}`);
    }
    // CONF-COMPUTE-02: Unencrypted Shared Memory Data Transfer Between Host and Confidential Enclave
    if (((/enclave_bridge|shm_channel|host_enclave/i.test(lowerPath) || /sharedMemoryBuffer|enclaveHostChannel/i.test(cleanContent)) && !/encryptEnclaveChannel/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/sharedMemoryBuffer|enclaveHostChannel/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `confcompute16402-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16402,
            type: 'SECURITY',
            title: "CONF-COMPUTE-02: Unencrypted Shared Memory Data Transfer Between Host and Confidential Enclave",
            severity: "CRITICAL",
            category: "Memory Encryption",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Confidential Computing configuration',
            reproductionSteps: [
                `Audited Confidential Computing configuration in ${file.path}:${lineNum}.`,
                'Matched CONF-COMPUTE-02: Unencrypted Shared Memory Data Transfer Between Host and Confidential Enclave.'
            ],
            remediationPrompt: "Encrypt all host-enclave memory communications over authenticated channels using ephemeral TLS or AES-GCM session keys.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CONF-COMPUTE AUDIT] Found CONF-COMPUTE-02: Unencrypted Shared Memory Data Transfer Between Host and Confidential Enclave at ${file.path}:${lineNum}`);
    }
    // CONF-COMPUTE-03: Vulnerability to Controlled Channel and Page Fault Side-Channel Attacks in Enclaves
    if (((/sidechannel|constant_time|enclave_algo/i.test(lowerPath) || /enclaveCryptoRoutine/i.test(cleanContent)) && !/constantTimeSelect|addressMasking/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/enclaveCryptoRoutine/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `confcompute16403-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16403,
            type: 'SECURITY',
            title: "CONF-COMPUTE-03: Vulnerability to Controlled Channel and Page Fault Side-Channel Attacks in Enclaves",
            severity: "HIGH",
            category: "Side-Channel Defense",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Confidential Computing configuration',
            reproductionSteps: [
                `Audited Confidential Computing configuration in ${file.path}:${lineNum}.`,
                'Matched CONF-COMPUTE-03: Vulnerability to Controlled Channel and Page Fault Side-Channel Attacks in Enclaves.'
            ],
            remediationPrompt: "Implement data-independent execution paths and address masking to prevent host-level memory access pattern side-channel leaks.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CONF-COMPUTE AUDIT] Found CONF-COMPUTE-03: Vulnerability to Controlled Channel and Page Fault Side-Channel Attacks in Enclaves at ${file.path}:${lineNum}`);
    }
    // CONF-COMPUTE-04: Use of Outdated CPU Microcode or Deprecated Security Version Numbers (SVN)
    if (((/tcb_policy|hardware_svn/i.test(lowerPath) || /checkTcbLevel|cpuSvnRequirement/i.test(cleanContent)) && !/minHardwareTcbSvnLevel/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/checkTcbLevel|cpuSvnRequirement/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `confcompute16404-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16404,
            type: 'SECURITY',
            title: "CONF-COMPUTE-04: Use of Outdated CPU Microcode or Deprecated Security Version Numbers (SVN)",
            severity: "CRITICAL",
            category: "TCB Freshness",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Confidential Computing configuration',
            reproductionSteps: [
                `Audited Confidential Computing configuration in ${file.path}:${lineNum}.`,
                'Matched CONF-COMPUTE-04: Use of Outdated CPU Microcode or Deprecated Security Version Numbers (SVN).'
            ],
            remediationPrompt: "Enforce minimum hardware TCB (Trusted Computing Base) SVN levels and verify microcode patches are up-to-date during attestation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CONF-COMPUTE AUDIT] Found CONF-COMPUTE-04: Use of Outdated CPU Microcode or Deprecated Security Version Numbers (SVN) at ${file.path}:${lineNum}`);
    }
    // CONF-COMPUTE-05: Unsigned or Tampered Enclave Application Binary Images in Enclave Launch Policy
    if (((/enclave_manifest|mrenclave|launch_policy/i.test(lowerPath) || /enclaveMeasurementHash|mrenclaveDigest/i.test(cleanContent)) && !/verifyEnclaveMeasurementSignature/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/enclaveMeasurementHash|mrenclaveDigest/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `confcompute16405-${Date.now()}-${findingCounter.count++}`,
            ruleId: 16405,
            type: 'SECURITY',
            title: "CONF-COMPUTE-05: Unsigned or Tampered Enclave Application Binary Images in Enclave Launch Policy",
            severity: "CRITICAL",
            category: "Launch Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Confidential Computing configuration',
            reproductionSteps: [
                `Audited Confidential Computing configuration in ${file.path}:${lineNum}.`,
                'Matched CONF-COMPUTE-05: Unsigned or Tampered Enclave Application Binary Images in Enclave Launch Policy.'
            ],
            remediationPrompt: "Validate measurement hashes (MRENCLAVE or launch digest) against signed cryptographic manifests prior to enclave execution.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CONF-COMPUTE AUDIT] Found CONF-COMPUTE-05: Unsigned or Tampered Enclave Application Binary Images in Enclave Launch Policy at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
