/**
 * Zelsis Master evaluateSbomAttestationRules Engine (50 Rules)
 * Rules SBOM-01 to SBOM-50 (Rule IDs 12601 to 12650).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface SbomAttestationRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateSbomAttestationRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): SbomAttestationRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts") || lowerPath.endsWith(".tsx") || lowerPath.endsWith(".jsx")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // SBOM-03: SLSA Level 3 Provenance Attestation Missing in CI/CD Build Pipeline
    // Advisory: a workflow step that actually publishes an artifact (a tag trigger alone is not a release) with no
    // provenance attestation anywhere in the workflow. Points at the publish step.
    const publishStepRe = /npm\s+publish|docker\s+push|docker\/build-push-action|goreleaser|gh\s+release\s+(?:create|upload)|action-gh-release|twine\s+upload|cargo\s+publish/i;
    const publishStepIdx = /\.github\/workflows\/[^/]+\.ya?ml$/i.test(file.path) && !/slsa-framework|attest-build-provenance|provenance\s*:\s*true|--provenance/i.test(cleanContent)
        ? lines.findIndex(l => !l.trim().startsWith('#') && publishStepRe.test(l))
        : -1;
    if (publishStepIdx !== -1) {
        const matchLineIdx = publishStepIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `sbom12603-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12603,
            type: 'SECURITY',
            title: "SBOM-03: SLSA Level 3 Provenance Attestation Missing in CI/CD Build Pipeline",
            severity: "LOW",
            category: "Build Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'SBOM Attestation configuration',
            reproductionSteps: [
                `Audited SBOM Attestation configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SBOM-03.'
            ],
            remediationPrompt: "Generate immutable SLSA Level 3 build provenance attestations in release workflows.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SBOM AUDIT] Found SBOM-03: SLSA Level 3 Provenance Attestation Missing in CI/CD Build Pipeline at ${file.path}:${lineNum}`);
    }
    // SBOM-05: Unvetted Third-Party GitHub Actions in Production CI/CD Workflows
    const thirdPartyActionRegex = /^\s*-?\s*uses\s*:\s*['\"]?(?!(?:actions|github)\/)[\w.-]+\/[\w./-]+@(?![0-9a-f]{40}\b)[\w.-]+/i;
    if (/\.github\/workflows\/[^/]+\.ya?ml$/i.test(file.path) && lines.some(l => thirdPartyActionRegex.test(l))) {
        const matchLineIdx = lines.findIndex(l => thirdPartyActionRegex.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `sbom12605-${Date.now()}-${findingCounter.count++}`,
            ruleId: 12605,
            type: 'SECURITY',
            title: "SBOM-05: Unvetted Third-Party GitHub Actions in Production CI/CD Workflows",
            severity: "HIGH",
            category: "Pipeline Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'SBOM Attestation configuration',
            reproductionSteps: [
                `Audited SBOM Attestation configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching SBOM-05.'
            ],
            remediationPrompt: "Pin third-party GitHub Actions to immutable 40-character commit SHAs instead of mutable tags.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [SBOM AUDIT] Found SBOM-05: Unvetted Third-Party GitHub Actions in Production CI/CD Workflows at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
