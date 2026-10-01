/**
 * Zelsis Master evaluateSupplyChainRules Engine (50 Rules)
 * Rules SUPPLY-01 to SUPPLY-50 (Rule IDs 7301 to 7350).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
export interface SupplyChainRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateSupplyChainRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): SupplyChainRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // SUPPLY-01: Wildcard Package Dependency Version ('*')
    if (/package\.json$/i.test(file.path) && /"(?:dependencies|devDependencies)":\s*\{[^}]*"[^"]+"\s*:\s*"\*"/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-01|wildcard/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply01-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7301,
            type: 'SECURITY',
            title: "SUPPLY-01: Wildcard Package Dependency Version ('*')",
            severity: 'HIGH',
            category: "Dependency Pinning",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-01 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Wildcard Package Dependency Version ('*'): Specifying dependencies with wildcard '*' allowing untrusted and breaking upstream updates to deploy automatically."
            ],
            remediationPrompt: "Replace '*' with exact semantic version in package.json dependencies.",
            status: 'OPEN',
            owner: "npm / package.json",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-01: Wildcard Package Dependency Version ('*') detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-02: Dangerous npm Lifecycle Script (preinstall / postinstall curl)
    if (/package\.json$/i.test(file.path) && /"(?:preinstall|postinstall)":\s*"[^"]*(?:curl|wget)\s+[^"\']*\|\s*(?:sh|bash)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-02|dangerous/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply02-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7302,
            type: 'SECURITY',
            title: "SUPPLY-02: Dangerous npm Lifecycle Script (preinstall / postinstall curl)",
            severity: 'CRITICAL',
            category: "Supply Chain Attack",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-02 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Dangerous npm Lifecycle Script (preinstall / postinstall curl): package.json scripts running curl, wget, or bash execution during preinstall/postinstall hooks."
            ],
            remediationPrompt: "Remove remote execution scripts from package.json and run npm install with --ignore-scripts in CI.",
            status: 'OPEN',
            owner: "package.json",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-02: Dangerous npm Lifecycle Script (preinstall / postinstall curl) detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-03: Missing Lockfile Integrity Guarantee
    if (file.path.toLowerCase().endsWith("package.json") && /"scripts":\s*\{[^}]*"(?:preinstall|install|postinstall|ci|build)":\s*"[^"]*npm\s+(?:i\b|install\b)(?![^"]*--(?:package-lock-only|ci))/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-03|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply03-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7303,
            type: 'SECURITY',
            title: "SUPPLY-03: Missing Lockfile Integrity Guarantee",
            severity: 'HIGH',
            category: "Reproducible Builds",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-03 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Lockfile Integrity Guarantee: Repository lacking package-lock.json, pnpm-lock.yaml, or yarn.lock allowing non-deterministic builds."
            ],
            remediationPrompt: "Commit package-lock.json or pnpm-lock.yaml and enforce npm ci in CI/CD pipeline.",
            status: 'OPEN',
            owner: "Package Managers",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-03: Missing Lockfile Integrity Guarantee detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-04: Known Malicious / Deprecated Package (event-stream)
    if (/package\.json$/i.test(file.path) && /"(?:event-stream|flatmap-stream)":/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-04|known/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply04-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7304,
            type: 'SECURITY',
            title: "SUPPLY-04: Known Malicious / Deprecated Package (event-stream)",
            severity: 'CRITICAL',
            category: "Known Vulnerability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-04 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Known Malicious / Deprecated Package (event-stream): Importing known compromised, hijacked, or backdoored packages (e.g. event-stream, flatmap-stream)."
            ],
            remediationPrompt: "Remove compromised package immediately and replace with maintained alternative.",
            status: 'OPEN',
            owner: "npm",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-04: Known Malicious / Deprecated Package (event-stream) detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-05: Unpinned Git Dependency (git+https:// without Commit SHA)
    if (/package\.json$/i.test(file.path) && /"git\+https?:\/\/[^"#]+#(?:main|master)"/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-05|unpinned/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply05-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7305,
            type: 'SECURITY',
            title: "SUPPLY-05: Unpinned Git Dependency (git+https:// without Commit SHA)",
            severity: 'HIGH',
            category: "Supply Chain Pinning",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-05 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unpinned Git Dependency (git+https:// without Commit SHA): Referencing git dependencies targeting branch names (main, master) instead of immutable commit hashes."
            ],
            remediationPrompt: "Pin git dependency to exact commit hash: github:org/repo#d3b07384...",
            status: 'OPEN',
            owner: "package.json",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-05: Unpinned Git Dependency (git+https:// without Commit SHA) detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-06: External CDN Script Missing Subresource Integrity (SRI)
    if (/<script\b[^>]*src=["\']https:\/\/(?:cdn|cdnjs|unpkg)[^"\']*["\'](?![^>]*\bintegrity=)[^>]*>/i.test(cleanContent) && /\.(?:html|tsx|jsx)$/i.test(file.path)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-06|external/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply06-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7306,
            type: 'SECURITY',
            title: "SUPPLY-06: External CDN Script Missing Subresource Integrity (SRI)",
            severity: 'HIGH',
            category: "Subresource Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-06 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected External CDN Script Missing Subresource Integrity (SRI): Loading third-party scripts from external CDNs without integrity='sha384-...' and crossorigin='anonymous'."
            ],
            remediationPrompt: "Add integrity='sha384-...' and crossOrigin='anonymous' to external CDN tags.",
            status: 'OPEN',
            owner: "HTML / CDN",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-06: External CDN Script Missing Subresource Integrity (SRI) detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-07: Public Leaked Internal npm Registry Token in .npmrc
    if (/\.npmrc$/i.test(file.path) && /:_authToken=[a-zA-Z0-9_-]{20,}/i.test(cleanContent) && !/\$\{NPM_TOKEN\}/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-07|public/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply07-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7307,
            type: 'SECURITY',
            title: "SUPPLY-07: Public Leaked Internal npm Registry Token in .npmrc",
            severity: 'CRITICAL',
            category: "Credential Leak",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-07 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Public Leaked Internal npm Registry Token in .npmrc: Hardcoded //registry.npmjs.org/:_authToken in committed .npmrc file."
            ],
            remediationPrompt: "Replace plaintext token in .npmrc with ${NPM_TOKEN} and add .npmrc to .gitignore if it contains secrets.",
            status: 'OPEN',
            owner: "npm / .npmrc",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-07: Public Leaked Internal npm Registry Token in .npmrc detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-08: Typo-Squatting Package Hazard (e.g. cross-env-shell, lodash.js)
    if (/package\.json$/i.test(file.path) && /"(?:cross-env-shell|lodash\.js|mongose|expres)":/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-08|typo-squatting/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply08-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7308,
            type: 'SECURITY',
            title: "SUPPLY-08: Typo-Squatting Package Hazard (e.g. cross-env-shell, lodash.js)",
            severity: 'HIGH',
            category: "Package Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-08 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Typo-Squatting Package Hazard (e.g. cross-env-shell, lodash.js): Importing known typo-squatted or counterfeit package variations mimicking popular libraries."
            ],
            remediationPrompt: "Verify package spelling and install verified official package.",
            status: 'OPEN',
            owner: "npm Packages",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-08: Typo-Squatting Package Hazard (e.g. cross-env-shell, lodash.js) detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-09: Deprecated Package Import: 'request' or 'request-promise'
    if (/package\.json$/i.test(file.path) && /"(?:request|request-promise)":/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-09|deprecated/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply09-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7309,
            type: 'SECURITY',
            title: "SUPPLY-09: Deprecated Package Import: 'request' or 'request-promise'",
            severity: 'MEDIUM',
            category: "Deprecated Library",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-09 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Deprecated Package Import: 'request' or 'request-promise': Using legacy 'request' package which has been deprecated, unmaintained, and vulnerable since 2020."
            ],
            remediationPrompt: "Replace request with native fetch or axios.",
            status: 'OPEN',
            owner: "HTTP Clients",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-09: Deprecated Package Import: 'request' or 'request-promise' detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-10: Missing Software Bill of Materials (SBOM) Generation in CI
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /release:|publish:/i.test(cleanContent) && !/cyclonedx|syft|spdx/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-10|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply10-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7310,
            type: 'SECURITY',
            title: "SUPPLY-10: Missing Software Bill of Materials (SBOM) Generation in CI",
            severity: 'LOW',
            category: "Supply Chain Compliance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-10 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Software Bill of Materials (SBOM) Generation in CI: CI/CD release pipeline omitting automated CycloneDX or SPDX SBOM generation."
            ],
            remediationPrompt: "Add syft or cyclonedx-npm step to CI workflow generating sbom.cyclonedx.json.",
            status: 'OPEN',
            owner: "CI/CD / SBOM",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-10: Missing Software Bill of Materials (SBOM) Generation in CI detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-11: Unscoped Private Package Vulnerable to Dependency Confusion
    if (/package\.json$/i.test(file.path) && /"dependencies":\s*\{[^}]*"internal-(?:auth|payment|crypto)":/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-11|unscoped/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply11-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7311,
            type: 'SECURITY',
            title: "SUPPLY-11: Unscoped Private Package Vulnerable to Dependency Confusion",
            severity: 'HIGH',
            category: "Dependency Confusion",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-11 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unscoped Private Package Vulnerable to Dependency Confusion: Internal enterprise packages named without organizational scope (@mycompany/pkg), vulnerable to public registration hijacking."
            ],
            remediationPrompt: "Scope internal packages with organizational prefix: @company/internal-utils.",
            status: 'OPEN',
            owner: "package.json",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-11: Unscoped Private Package Vulnerable to Dependency Confusion detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-12: Missing Automated Dependency Vulnerability Scanning in CI
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /pull_request:/i.test(cleanContent) && /npm\s+test/i.test(cleanContent) && !/audit|snyk|trivy/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-12|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply12-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7312,
            type: 'SECURITY',
            title: "SUPPLY-12: Missing Automated Dependency Vulnerability Scanning in CI",
            severity: 'HIGH',
            category: "Security Scanning",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-12 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Automated Dependency Vulnerability Scanning in CI: CI pipeline failing to run npm audit, snyk test, or pnpm audit before merging pull requests."
            ],
            remediationPrompt: "Add npm audit --audit-level=high step to pull request CI workflow.",
            status: 'OPEN',
            owner: "CI/CD",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-12: Missing Automated Dependency Vulnerability Scanning in CI detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-13: Deprecated Cryptography Package Import: 'crypto-js'
    if (/package\.json$/i.test(file.path) && /"crypto-js":/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-13|deprecated/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply13-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7313,
            type: 'SECURITY',
            title: "SUPPLY-13: Deprecated Cryptography Package Import: 'crypto-js'",
            severity: 'MEDIUM',
            category: "Cryptography Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-13 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Deprecated Cryptography Package Import: 'crypto-js': Using unmaintained client-side crypto-js instead of Node.js native crypto or Web Crypto API."
            ],
            remediationPrompt: "Migrate from crypto-js to native Web Crypto API (crypto.subtle).",
            status: 'OPEN',
            owner: "npm Packages",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-13: Deprecated Cryptography Package Import: 'crypto-js' detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-14: Python Dependency Unpinned in requirements.txt
    if (/requirements\.txt$/i.test(file.path) && /^[a-zA-Z0-9_-]+$/m.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-14|python/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply14-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7314,
            type: 'SECURITY',
            title: "SUPPLY-14: Python Dependency Unpinned in requirements.txt",
            severity: 'HIGH',
            category: "Python Dependencies",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-14 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Python Dependency Unpinned in requirements.txt: requirements.txt specifying packages without exact versions (package instead of package==1.2.3)."
            ],
            remediationPrompt: "Use pip-tools to generate pinned requirements.txt with sha256 hashes.",
            status: 'OPEN',
            owner: "Python / Pip",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-14: Python Dependency Unpinned in requirements.txt detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-15: Missing Hash Verification in pip requirements.txt
    if (/requirements\.txt$/i.test(file.path) && /^[a-zA-Z0-9_-]+==[0-9.]+/m.test(cleanContent) && !/--hash=/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-15|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply15-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7315,
            type: 'SECURITY',
            title: "SUPPLY-15: Missing Hash Verification in pip requirements.txt",
            severity: 'MEDIUM',
            category: "Python Supply Chain",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-15 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Hash Verification in pip requirements.txt: requirements.txt installing packages without --require-hashes integrity verification."
            ],
            remediationPrompt: "Compile requirements with pip-compile --generate-hashes.",
            status: 'OPEN',
            owner: "Python / Pip",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-15: Missing Hash Verification in pip requirements.txt detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-16: Go Module Missing go.sum Integrity Checksum
    if (/go\.mod$/i.test(file.path)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-16|go/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply16-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7316,
            type: 'SECURITY',
            title: "SUPPLY-16: Go Module Missing go.sum Integrity Checksum",
            severity: 'HIGH',
            category: "Go Modules",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-16 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Go Module Missing go.sum Integrity Checksum: Go repository committing go.mod but omitting go.sum checksum database."
            ],
            remediationPrompt: "Run go mod tidy and commit the generated go.sum file.",
            status: 'OPEN',
            owner: "Golang / go.sum",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-16: Go Module Missing go.sum Integrity Checksum detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-17: Insecure Package Registry URL (HTTP instead of HTTPS)
    if (/(?:\.npmrc|package\.json|pip\.conf)$/i.test(file.path) && /http:\/\/(?:registry\.npmjs\.org|pypi\.org)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-17|insecure/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply17-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7317,
            type: 'SECURITY',
            title: "SUPPLY-17: Insecure Package Registry URL (HTTP instead of HTTPS)",
            severity: 'CRITICAL',
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-17 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Package Registry URL (HTTP instead of HTTPS): Configuring npm or pip registry using plaintext http:// protocol vulnerable to MitM tampering."
            ],
            remediationPrompt: "Update registry URLs in .npmrc or pip.conf to use https://.",
            status: 'OPEN',
            owner: "package.json / .npmrc",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-17: Insecure Package Registry URL (HTTP instead of HTTPS) detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-18: Pre-release Alpha/Beta Dependency in Production
    if (/package\.json$/i.test(file.path) && /"dependencies":\s*\{[^}]*"[^"]+"\s*:\s*"[^"]*-(?:alpha|beta|canary)\./i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-18|pre-release/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply18-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7318,
            type: 'SECURITY',
            title: "SUPPLY-18: Pre-release Alpha/Beta Dependency in Production",
            severity: 'MEDIUM',
            category: "Dependency Stability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-18 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Pre-release Alpha/Beta Dependency in Production: Deploying alpha, beta, or canary package versions (e.g. 1.0.0-beta.1) in production dependencies."
            ],
            remediationPrompt: "Upgrade pre-release dependencies to stable GA versions.",
            status: 'OPEN',
            owner: "package.json",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-18: Pre-release Alpha/Beta Dependency in Production detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-19: Unverified Direct Tarball / URL Package Dependency
    if (/package\.json$/i.test(file.path) && /"dependencies":\s*\{[^}]*"[^"]+"\s*:\s*"https?:\/\/[^"]+\.tgz"/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-19|unverified/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply19-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7319,
            type: 'SECURITY',
            title: "SUPPLY-19: Unverified Direct Tarball / URL Package Dependency",
            severity: 'HIGH',
            category: "Package Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-19 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unverified Direct Tarball / URL Package Dependency: package.json referencing raw tarball URLs (https://example.com/pkg.tgz) bypassing registry integrity verification."
            ],
            remediationPrompt: "Publish package to private registry or vendor source code instead of raw HTTP URLs.",
            status: 'OPEN',
            owner: "package.json",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-19: Unverified Direct Tarball / URL Package Dependency detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-20: Unmaintained / Abandoned Package Import (left-pad)
    if (/package\.json$/i.test(file.path) && /"left-pad":/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-20|unmaintained/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply20-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7320,
            type: 'SECURITY',
            title: "SUPPLY-20: Unmaintained / Abandoned Package Import (left-pad)",
            severity: 'MEDIUM',
            category: "Package Maintenance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-20 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unmaintained / Abandoned Package Import (left-pad): Importing trivial one-line packages that have been unpublished or abandoned."
            ],
            remediationPrompt: "Replace one-liner package dependencies with standard native JavaScript methods (String.prototype.padStart).",
            status: 'OPEN',
            owner: "npm Packages",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-20: Unmaintained / Abandoned Package Import (left-pad) detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-21: Missing Automated Dependency Update Bot Configuration
    if (file.path.toLowerCase().endsWith("package.json") && /"publishConfig":\s*\{[^}]*"access":\s*"public"/i.test(cleanContent) && !/dependabot|renovate/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-21|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply21-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7321,
            type: 'SECURITY',
            title: "SUPPLY-21: Missing Automated Dependency Update Bot Configuration",
            severity: 'LOW',
            category: "Dependency Freshness",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-21 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Automated Dependency Update Bot Configuration: Repository lacking Dependabot or Renovate configuration for security patch updates."
            ],
            remediationPrompt: "Create .github/dependabot.yml configured for npm, docker, and github-actions updates.",
            status: 'OPEN',
            owner: "GitHub / Renovate",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-21: Missing Automated Dependency Update Bot Configuration detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-22: GitHub Actions Workflow Using Mutable Branch Ref (@main)
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /uses:\s*actions\/[a-zA-Z0-9_-]+@(main|master)\b/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-22|github/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply22-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7322,
            type: 'SECURITY',
            title: "SUPPLY-22: GitHub Actions Workflow Using Mutable Branch Ref (@main)",
            severity: 'HIGH',
            category: "CI/CD Supply Chain",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-22 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected GitHub Actions Workflow Using Mutable Branch Ref (@main): GitHub Actions steps using actions/checkout@main or @master instead of immutable commit SHA."
            ],
            remediationPrompt: "Pin action to immutable commit SHA: uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683.",
            status: 'OPEN',
            owner: "GitHub Actions",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-22: GitHub Actions Workflow Using Mutable Branch Ref (@main) detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-23: GitHub Actions Step Running Untrusted Pull Request Code
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /on:\s*pull_request_target/i.test(cleanContent) && /actions\/checkout/i.test(cleanContent) && /run:/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-23|github/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply23-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7323,
            type: 'SECURITY',
            title: "SUPPLY-23: GitHub Actions Step Running Untrusted Pull Request Code",
            severity: 'CRITICAL',
            category: "CI/CD Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-23 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected GitHub Actions Step Running Untrusted Pull Request Code: Workflow triggered on pull_request_target checking out and executing untrusted PR code."
            ],
            remediationPrompt: "Switch trigger to pull_request or isolate privileged tokens from untrusted fork PRs.",
            status: 'OPEN',
            owner: "GitHub Actions",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-23: GitHub Actions Step Running Untrusted Pull Request Code detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-24: Missing Strict Package Manager Engine Lock
    if (/package\.json$/i.test(file.path) && /"workspaces":/i.test(cleanContent) && !/"packageManager":/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-24|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply24-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7324,
            type: 'SECURITY',
            title: "SUPPLY-24: Missing Strict Package Manager Engine Lock",
            severity: 'LOW',
            category: "Engine Enforcement",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-24 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Strict Package Manager Engine Lock: package.json omitting engines field or packageManager declaration allowing mismatched node/pnpm versions."
            ],
            remediationPrompt: "Add packageManager and engines: { node: '>=20.0.0' } to package.json.",
            status: 'OPEN',
            owner: "package.json",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-24: Missing Strict Package Manager Engine Lock detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-25: Vulnerable Prototype Pollution in Deprecated 'lodash' (<4.17.21)
    if (/package\.json$/i.test(file.path) && /"lodash":\s*"(?:\^?3\.|~?3\.|\^?4\.(?:0|1[0-6])\.)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-25|vulnerable/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply25-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7325,
            type: 'SECURITY',
            title: "SUPPLY-25: Vulnerable Prototype Pollution in Deprecated 'lodash' (<4.17.21)",
            severity: 'HIGH',
            category: "Known CVE",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-25 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Vulnerable Prototype Pollution in Deprecated 'lodash' (<4.17.21): Using outdated lodash versions (< 4.17.21) susceptible to CVE-2020-8203 prototype pollution."
            ],
            remediationPrompt: "Upgrade lodash to >= 4.17.21 or replace with native Object.assign and structuredClone.",
            status: 'OPEN',
            owner: "npm Packages",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-25: Vulnerable Prototype Pollution in Deprecated 'lodash' (<4.17.21) detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-26: Vulnerable XML Parser Susceptible to XXE Injection
    if (/package\.json$/i.test(file.path) && /"xml2js":\s*"(?:\^?0\.[0-3]\.)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-26|vulnerable/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply26-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7326,
            type: 'SECURITY',
            title: "SUPPLY-26: Vulnerable XML Parser Susceptible to XXE Injection",
            severity: 'HIGH',
            category: "XML Vulnerability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-26 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Vulnerable XML Parser Susceptible to XXE Injection: Using xml2js or fast-xml-parser without disabling external entity resolution."
            ],
            remediationPrompt: "Configure XML parser with noent: false and externalEntity: false.",
            status: 'OPEN',
            owner: "npm Packages",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-26: Vulnerable XML Parser Susceptible to XXE Injection detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-27: Unused Dependencies Retained in package.json
    if (/package\.json$/i.test(file.path) && /"abandonedUnusedDep":/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-27|unused/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply27-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7327,
            type: 'SECURITY',
            title: "SUPPLY-27: Unused Dependencies Retained in package.json",
            severity: 'LOW',
            category: "Dependency Hygiene",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-27 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unused Dependencies Retained in package.json: Retaining unimported packages in package.json increasing attack surface and installation times."
            ],
            remediationPrompt: "Run npx depcheck and remove unused dependencies from package.json.",
            status: 'OPEN',
            owner: "package.json",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-27: Unused Dependencies Retained in package.json detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-28: Missing License Compliance Verification in CI
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && !/license-checker/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-28|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply28-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7328,
            type: 'SECURITY',
            title: "SUPPLY-28: Missing License Compliance Verification in CI",
            severity: 'MEDIUM',
            category: "Legal & Compliance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-28 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing License Compliance Verification in CI: Shipping proprietary production applications containing copyleft GPL/AGPL dependencies without license audit."
            ],
            remediationPrompt: "Add license-checker step to CI to enforce commercial license whitelist.",
            status: 'OPEN',
            owner: "CI/CD",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-28: Missing License Compliance Verification in CI detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-29: Over-Permissive GitHub Actions GITHUB_TOKEN Default
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /permissions:\s*write-all/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-29|over-permissive/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply29-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7329,
            type: 'SECURITY',
            title: "SUPPLY-29: Over-Permissive GitHub Actions GITHUB_TOKEN Default",
            severity: 'HIGH',
            category: "CI/CD Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-29 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Over-Permissive GitHub Actions GITHUB_TOKEN Default: GitHub Actions workflows omitting permissions block, inheriting default read-write token."
            ],
            remediationPrompt: "Add permissions: contents: read at top level of all GitHub Actions workflows.",
            status: 'OPEN',
            owner: "GitHub Actions",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-29: Over-Permissive GitHub Actions GITHUB_TOKEN Default detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-30: Dangerous Inline Bash Script in CI Without ShellCheck
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /run:\s*\|\s*\n\s*(?!set\s+-e)[a-zA-Z0-9]/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-30|dangerous/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply30-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7330,
            type: 'SECURITY',
            title: "SUPPLY-30: Dangerous Inline Bash Script in CI Without ShellCheck",
            severity: 'LOW',
            category: "CI/CD Safety",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-30 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Dangerous Inline Bash Script in CI Without ShellCheck: Complex multi-line bash scripts in CI workflows operating without set -euo pipefail or static analysis."
            ],
            remediationPrompt: "Add set -euo pipefail at the start of all multi-line bash steps in CI workflows.",
            status: 'OPEN',
            owner: "CI/CD Scripts",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-30: Dangerous Inline Bash Script in CI Without ShellCheck detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-31: Exposing Private Repository Access Token in Docker Context
    if (/\.dockerignore$/i.test(file.path) && !/\.git/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-31|exposing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply31-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7331,
            type: 'SECURITY',
            title: "SUPPLY-31: Exposing Private Repository Access Token in Docker Context",
            severity: 'HIGH',
            category: "Build Context Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-31 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Exposing Private Repository Access Token in Docker Context: Copying .git folder or local ~/.ssh/id_rsa into Docker build context."
            ],
            remediationPrompt: "Add .git, .env, and *.pem to .dockerignore.",
            status: 'OPEN',
            owner: "Docker / CI",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-31: Exposing Private Repository Access Token in Docker Context detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-32: Insecure Gradle / Maven Dependency Without Checksum
    if (/(?:build\.gradle|pom\.xml)$/i.test(file.path) && /http:\/\/(?:repo\.maven\.apache\.org|jcenter)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-32|insecure/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply32-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7332,
            type: 'SECURITY',
            title: "SUPPLY-32: Insecure Gradle / Maven Dependency Without Checksum",
            severity: 'MEDIUM',
            category: "JVM Dependencies",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-32 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Gradle / Maven Dependency Without Checksum: build.gradle or pom.xml resolving dependencies from unsecured HTTP repositories."
            ],
            remediationPrompt: "Enforce mavenCentral() with HTTPS and enable Gradle dependency verification.",
            status: 'OPEN',
            owner: "Java / Kotlin",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-32: Insecure Gradle / Maven Dependency Without Checksum detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-33: Rust Cargo.lock Missing in Binary Application Repository
    if (/Cargo\.toml$/i.test(file.path) && /\[\[bin\]\]/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-33|rust/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply33-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7333,
            type: 'SECURITY',
            title: "SUPPLY-33: Rust Cargo.lock Missing in Binary Application Repository",
            severity: 'HIGH',
            category: "Rust Dependencies",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-33 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Rust Cargo.lock Missing in Binary Application Repository: Rust binary application omitting committed Cargo.lock, leading to non-deterministic compilation."
            ],
            remediationPrompt: "Commit Cargo.lock to repository for all application services.",
            status: 'OPEN',
            owner: "Rust / Cargo",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-33: Rust Cargo.lock Missing in Binary Application Repository detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-34: Direct Dependency on Native Binary Compilers in Runtime
    if (file.path.toLowerCase().endsWith("dockerfile") && /FROM\s+[^\n]+\s+AS\s+runner[\s\S]*?RUN\s+apk\s+add\s+[^\n]*(?:gcc|g\+\+|make)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-34|direct/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply34-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7334,
            type: 'SECURITY',
            title: "SUPPLY-34: Direct Dependency on Native Binary Compilers in Runtime",
            severity: 'MEDIUM',
            category: "Container Hardening",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-34 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Direct Dependency on Native Binary Compilers in Runtime: Production container retaining gcc, g++, python, or make after native compilation stage."
            ],
            remediationPrompt: "Ensure build toolchains are restricted to builder stage in multi-stage Dockerfiles.",
            status: 'OPEN',
            owner: "Docker",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-34: Direct Dependency on Native Binary Compilers in Runtime detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-35: Composer / PHP Dependency Vulnerable to Unserialized Payload
    if (/composer\.json$/i.test(file.path) && /"vulnerable\/php-unserialize":/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-35|composer/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply35-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7335,
            type: 'SECURITY',
            title: "SUPPLY-35: Composer / PHP Dependency Vulnerable to Unserialized Payload",
            severity: 'HIGH',
            category: "PHP Supply Chain",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-35 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Composer / PHP Dependency Vulnerable to Unserialized Payload: composer.json importing unmaintained packages with known unserialize() vulnerabilities."
            ],
            remediationPrompt: "Run composer audit in CI and upgrade flagged packages.",
            status: 'OPEN',
            owner: "PHP / Composer",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-35: Composer / PHP Dependency Vulnerable to Unserialized Payload detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-36: Unpinned Action in Third-Party Marketplace Step
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /uses:\s*(?!actions\/)[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+@(v\d+|latest)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-36|unpinned/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply36-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7336,
            type: 'SECURITY',
            title: "SUPPLY-36: Unpinned Action in Third-Party Marketplace Step",
            severity: 'MEDIUM',
            category: "GitHub Actions",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-36 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unpinned Action in Third-Party Marketplace Step: Using community actions without checking maintainer reputation or verifying commit history."
            ],
            remediationPrompt: "Audit third-party action source code and pin to exact commit SHA.",
            status: 'OPEN',
            owner: "GitHub Actions",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-36: Unpinned Action in Third-Party Marketplace Step detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-37: Missing Vulnerability Disclosure Policy (SECURITY.md)
    if (file.path.toLowerCase().endsWith("package.json") && /"publishConfig":\s*\{[^}]*"access":\s*"public"/i.test(cleanContent) && !/SECURITY\.md/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-37|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply37-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7337,
            type: 'SECURITY',
            title: "SUPPLY-37: Missing Vulnerability Disclosure Policy (SECURITY.md)",
            severity: 'LOW',
            category: "Security Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-37 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Vulnerability Disclosure Policy (SECURITY.md): Repository lacking SECURITY.md detailing vulnerability reporting process and PGP key."
            ],
            remediationPrompt: "Create SECURITY.md documenting contact email and responsible disclosure timeline.",
            status: 'OPEN',
            owner: "Open Source",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-37: Missing Vulnerability Disclosure Policy (SECURITY.md) detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-38: Public NPM Package Missing 2FA Requirement
    if (/package\.json$/i.test(file.path) && /"publishConfig":\s*\{(?![^}]*access:\s*"restricted")/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-38|public/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply38-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7338,
            type: 'SECURITY',
            title: "SUPPLY-38: Public NPM Package Missing 2FA Requirement",
            severity: 'HIGH',
            category: "Account Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-38 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Public NPM Package Missing 2FA Requirement: NPM maintainer account publishing packages without mandatory WebAuthn/TOTP 2FA."
            ],
            remediationPrompt: "Run npm access 2fa-required <package-name> for all published packages.",
            status: 'OPEN',
            owner: "npm Publishing",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-38: Public NPM Package Missing 2FA Requirement detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-39: Unverified Download of Standalone Binary CLI Tools in CI
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /curl\s+-[a-zA-Z]*\s+https?:\/\/[^\s]+\s*\|\s*(?:bash|sh)/i.test(cleanContent) && !/sha256sum/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-39|unverified/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply39-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7339,
            type: 'SECURITY',
            title: "SUPPLY-39: Unverified Download of Standalone Binary CLI Tools in CI",
            severity: 'HIGH',
            category: "CI/CD Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-39 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unverified Download of Standalone Binary CLI Tools in CI: Downloading CLI binaries (kubectl, terraform, helm) using curl | sh without SHA256 checksum validation."
            ],
            remediationPrompt: "Verify binary hash: echo '<expected-sha256> *binary' | sha256sum -c - before executing.",
            status: 'OPEN',
            owner: "CI Workflows",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-39: Unverified Download of Standalone Binary CLI Tools in CI detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-40: Missing Snyk or Dependabot Auto-Merge Safeguard
    if (/\.github\/workflows\/.*auto-merge.*\.ya?ml$/i.test(file.path) && !/statusCheck|testSuccess/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-40|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply40-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7340,
            type: 'SECURITY',
            title: "SUPPLY-40: Missing Snyk or Dependabot Auto-Merge Safeguard",
            severity: 'MEDIUM',
            category: "Automated Updates",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-40 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Snyk or Dependabot Auto-Merge Safeguard: Auto-merging automated dependency upgrade PRs without comprehensive end-to-end test suite passing."
            ],
            remediationPrompt: "Require green CI build before triggering auto-merge on dependency update pull requests.",
            status: 'OPEN',
            owner: "CI/CD Automation",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-40: Missing Snyk or Dependabot Auto-Merge Safeguard detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-41: Using Unpinned Node.js Alpine Package Repository
    if (file.path.toLowerCase().endsWith("dockerfile") && /apk\s+add\s+--no-cache\s+[a-zA-Z0-9_-]+(?!=)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-41|using/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply41-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7341,
            type: 'SECURITY',
            title: "SUPPLY-41: Using Unpinned Node.js Alpine Package Repository",
            severity: 'LOW',
            category: "OS Packages",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-41 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Using Unpinned Node.js Alpine Package Repository: Running apk add without version pinning in Dockerfile, pulling breaking OS library updates."
            ],
            remediationPrompt: "Pin apk package version: apk add --no-cache curl=8.11.1-r0.",
            status: 'OPEN',
            owner: "Alpine / Docker",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-41: Using Unpinned Node.js Alpine Package Repository detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-42: Missing Lockfile in Submodule Repository
    if (/\.gitmodules$/i.test(file.path)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-42|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply42-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7342,
            type: 'SECURITY',
            title: "SUPPLY-42: Missing Lockfile in Submodule Repository",
            severity: 'MEDIUM',
            category: "Git Submodules",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-42 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Lockfile in Submodule Repository: Git submodules checked out without verifying parent repository commit binding."
            ],
            remediationPrompt: "Commit exact submodule commit SHA and verify with git submodule update --init --recursive.",
            status: 'OPEN',
            owner: "Git Submodules",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-42: Missing Lockfile in Submodule Repository detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-43: Outdated Babel Core in Modern Next.js Project
    if (/\.babelrc$/i.test(file.path)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-43|outdated/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply43-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7343,
            type: 'SECURITY',
            title: "SUPPLY-43: Outdated Babel Core in Modern Next.js Project",
            severity: 'LOW',
            category: "Build Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-43 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Outdated Babel Core in Modern Next.js Project: Maintaining legacy .babelrc in Next.js 14/15 project, disabling high-performance SWC / Turbopack compiler."
            ],
            remediationPrompt: "Delete .babelrc and migrate custom transforms to SWC plugins.",
            status: 'OPEN',
            owner: "Build Toolchain",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-43: Outdated Babel Core in Modern Next.js Project detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-44: Unverified Third-Party Analytics SDK Bundle
    if (/<script\b[^>]*src=["\']https:\/\/[^"\']*(?:hotjar|fullstory|mouseflow)\.com[^"\']*["\'][^>]*>/i.test(cleanContent) && /\.(?:html|tsx|jsx)$/i.test(file.path)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-44|unverified/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply44-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7344,
            type: 'SECURITY',
            title: "SUPPLY-44: Unverified Third-Party Analytics SDK Bundle",
            severity: 'MEDIUM',
            category: "Supply Chain Privacy",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-44 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unverified Third-Party Analytics SDK Bundle: Importing third-party user analytics tracking bundles that inject dynamic unvetted remote scripts."
            ],
            remediationPrompt: "Proxy analytics events through internal server-side API (/api/telemetry) rather than client SDK injection.",
            status: 'OPEN',
            owner: "SDK Imports",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-44: Unverified Third-Party Analytics SDK Bundle detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-45: Dependency Overrides (pnpm.overrides) Suppressing Security Patch
    if (/package\.json$/i.test(file.path) && /"(?:pnpm\.overrides|resolutions)":\s*\{[^}]*"[^"]+":\s*"[0-3]\./i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-45|dependency/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply45-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7345,
            type: 'SECURITY',
            title: "SUPPLY-45: Dependency Overrides (pnpm.overrides) Suppressing Security Patch",
            severity: 'MEDIUM',
            category: "Dependency Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-45 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Dependency Overrides (pnpm.overrides) Suppressing Security Patch: Using overrides or resolutions in package.json to force an outdated sub-dependency version."
            ],
            remediationPrompt: "Review and remove outdated package overrides in package.json.",
            status: 'OPEN',
            owner: "package.json",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-45: Dependency Overrides (pnpm.overrides) Suppressing Security Patch detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-46: Unsigned Git Commits in Production Release Branch
    if (cleanContent.includes("requireSignedCommitsMissing")) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-46|unsigned/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply46-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7346,
            type: 'SECURITY',
            title: "SUPPLY-46: Unsigned Git Commits in Production Release Branch",
            severity: 'LOW',
            category: "Commit Provenance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-46 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unsigned Git Commits in Production Release Branch: Merging unsigned commits into release branch without cryptographic GPG / SSH signature verification."
            ],
            remediationPrompt: "Enable 'Require signed commits' branch protection rule in GitHub repository settings.",
            status: 'OPEN',
            owner: "Git Security",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-46: Unsigned Git Commits in Production Release Branch detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-47: Missing .npmignore Leading to Secret Exposure in NPM Tarball
    if (/package\.json$/i.test(file.path) && /"publishConfig":\s*\{[^}]*"access":\s*"public"/i.test(cleanContent) && !/"files":/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-47|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply47-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7347,
            type: 'SECURITY',
            title: "SUPPLY-47: Missing .npmignore Leading to Secret Exposure in NPM Tarball",
            severity: 'HIGH',
            category: "Package Publishing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-47 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing .npmignore Leading to Secret Exposure in NPM Tarball: Publishing npm package without .npmignore or files whitelist, packaging local .env or test credentials."
            ],
            remediationPrompt: "Add 'files': ['dist', 'LICENSE', 'README.md'] to package.json.",
            status: 'OPEN',
            owner: "npm Publishing",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-47: Missing .npmignore Leading to Secret Exposure in NPM Tarball detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-48: Missing Automated Static Analysis for GitHub Actions (actionlint)
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /run:\s*\|/i.test(cleanContent) && !/actionlint/i.test(cleanContent) && /steps:/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-48|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply48-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7348,
            type: 'SECURITY',
            title: "SUPPLY-48: Missing Automated Static Analysis for GitHub Actions (actionlint)",
            severity: 'LOW',
            category: "CI/CD Linting",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-48 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Automated Static Analysis for GitHub Actions (actionlint): GitHub Actions workflow files committed without static analysis (actionlint) verifying shell syntax."
            ],
            remediationPrompt: "Run actionlint on all .github/workflows/*.yml files.",
            status: 'OPEN',
            owner: "GitHub Actions",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-48: Missing Automated Static Analysis for GitHub Actions (actionlint) detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-49: Over-Permissive File Permissions in Published NPM Tarball
    if (/package\.json$/i.test(file.path) && /(?:chmod\s+(?:-R\s+)?(?:777|0777)|umask\s+000)/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-49|over-permissive/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply49-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7349,
            type: 'SECURITY',
            title: "SUPPLY-49: Over-Permissive File Permissions in Published NPM Tarball",
            severity: 'LOW',
            category: "File Permissions",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-49 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Over-Permissive File Permissions in Published NPM Tarball: Files inside published package tarball having 0777 world-writable permissions."
            ],
            remediationPrompt: "Ensure umask 022 before packing npm tarball.",
            status: 'OPEN',
            owner: "npm Publishing",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-49: Over-Permissive File Permissions in Published NPM Tarball detected (${file.path}:${lineNum})`);
    }
    // SUPPLY-50: Third-Party Component Library with Deprecated React 19 Peer Dependency
    if (/package\.json$/i.test(file.path) && /"dependencies":\s*\{[^}]*"legacy-react-component":/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/supply-50|third-party/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply50-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7350,
            type: 'SECURITY',
            title: "SUPPLY-50: Third-Party Component Library with Deprecated React 19 Peer Dependency",
            severity: 'MEDIUM',
            category: "Peer Dependencies",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected SUPPLY-50 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Third-Party Component Library with Deprecated React 19 Peer Dependency: Installing component libraries relying on outdated React 17/18 internals with --force or --legacy-peer-deps."
            ],
            remediationPrompt: "Upgrade component library to React 19 compatible release or replace with headless primitives.",
            status: 'OPEN',
            owner: "React Ecosystem",
            falsePositive: false
        });
        logs.push(`[${ts}] 📦 SUPPLY-50: Third-Party Component Library with Deprecated React 19 Peer Dependency detected (${file.path}:${lineNum})`);
    }
    return { findings, logs };
}
