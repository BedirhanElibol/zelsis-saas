/**
 * Zelsis Master evaluateSupplyChainRules Engine (50 Rules)
 * Rules SUPPLY-01 to SUPPLY-50 (Rule IDs 7301 to 7350).
 * Removed as unsound (ids never reused): 7309 and 7336 (duplicates of SCA 27212 / CICD-SEC-02), 7310, 7315, 7321,
 * 7324, 7328, 7337, 7340, 7347 (absence-of-X in a file), 7327, 7346, 7350 (sentinel names), 7342, 7343 (line-1
 * file-level), 7318, 7330, 7338, 7341, 7344, 7345 (wrong premise: pre-release deps, GHA bash already runs -e,
 * 2FA not visible in package.json, apk pinning breaks builds, analytics is a product choice, overrides usually
 * force security patches).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { locateMatchLine } from './shared/locate';
export interface SupplyChainRuleResult {
    findings: Finding[];
    logs: string[];
}
/** `ref:` line of a pull_request_target workflow that checks out the PR head and runs a step after it, or -1. */
function prTargetHeadCheckoutLine(lines: string[]): number {
    if (!lines.some((l) => !l.trim().startsWith('#') && /\bpull_request_target\b/.test(l))) return -1;
    const prHeadRef = /^\s*ref\s*:\s*['"]?(?:\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref)\s*\}\}|refs\/pull\/\$\{\{[^}]*\}\}\/(?:merge|head))/;
    const refIdx = lines.findIndex((l) => prHeadRef.test(l));
    return refIdx !== -1 && lines.slice(refIdx + 1).some((l) => /^\s*-?\s*run\s*:/.test(l)) ? refIdx : -1;
}
/**
 * Line of a `"pkg": "*"` entry in dependencies / devDependencies / optionalDependencies of a non-monorepo
 * package.json, or -1. Monorepos (workspaces, packages/ or apps/ members) use "*" to link sibling workspace
 * packages, and peerDependencies "*" is the normal way to accept any host version, so both are skipped.
 */
function wildcardDependencyLine(lowerPath: string, lines: string[], cleanContent: string): number {
    if (!/(?:^|\/)package\.json$/.test(lowerPath)) return -1;
    if (/(?:^|\/)(?:packages|apps|libs|examples|templates)\//.test(lowerPath) || /"workspaces"\s*:/.test(cleanContent)) return -1;
    let inDeps = false;
    for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        if (/^\s*"(?:dependencies|devDependencies|optionalDependencies)"\s*:\s*\{\s*$/.test(l)) { inDeps = true; continue; }
        if (inDeps && /^\s*\}/.test(l)) { inDeps = false; continue; }
        if (inDeps && /^\s*"[^"]+"\s*:\s*"\*"\s*,?\s*$/.test(l)) return i;
    }
    return -1;
}
/**
 * Line installing a C/C++ toolchain in the final stage of a multi-stage Dockerfile, or -1. Single-stage images
 * and install lines that remove the toolchain again (apk --virtual ... && apk del) are skipped.
 */
function finalStageCompilerLine(lines: string[]): number {
    const froms = lines.map((l, i) => (/^\s*FROM\s+/i.test(l) ? i : -1)).filter(i => i !== -1);
    if (froms.length < 2) return -1;
    const install = /\b(?:apk\s+add|apt-get\s+install|apt\s+install|yum\s+install|dnf\s+install)\b.*\b(?:gcc|g\+\+|build-base|build-essential)(?![\w-])/i;
    for (let i = froms[froms.length - 1] + 1; i < lines.length; i++) {
        if (install.test(lines[i]) && !/--virtual|apk\s+del\b|apt-get\s+(?:purge|remove)\b/i.test(lines[i])) return i;
    }
    return -1;
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
    const wildcardIdx = wildcardDependencyLine(lowerPath, lines, cleanContent);
    if (wildcardIdx !== -1) {
        const matchLineIdx = wildcardIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `supply01-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7301,
            type: 'SECURITY',
            title: "SUPPLY-01: Wildcard Package Dependency Version ('*')",
            severity: 'MEDIUM',
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
        const matchLineIdx = locateMatchLine(lines, [/"(?:preinstall|postinstall)":\s*"[^"]*(?:curl|wget)\s+[^"\']*\|\s*(?:sh|bash)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // SUPPLY-04: Known Malicious / Deprecated Package (event-stream)
    if (/package\.json$/i.test(file.path) && /"flatmap-stream":|"event-stream":\s*"[~^=]?3\.3\.6"/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/"flatmap-stream":|"event-stream":\s*"[~^=]?3\.3\.6"/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
        const matchLineIdx = locateMatchLine(lines, [/"git\+https?:\/\/[^"#]+#(?:main|master)"/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
        const matchLineIdx = locateMatchLine(lines, [/<script\b[^>]*src=["\']https:\/\/(?:cdn|cdnjs|unpkg)[^"\']*["\'](?![^>]*\bintegrity=)[^>]*>/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply06-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7306,
            type: 'SECURITY',
            title: "SUPPLY-06: External CDN Script Missing Subresource Integrity (SRI)",
            severity: 'MEDIUM',
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
    // .npmrc registry lines start with "//", which comment stripping removes: read the raw file
    if (/\.npmrc$/i.test(file.path) && /:_authToken=[a-zA-Z0-9_-]{20,}/i.test(file.content)) {
        const matchLineIdx = lines.findIndex(l => /:_authToken=[a-zA-Z0-9_-]{20,}/i.test(l));
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
        const matchLineIdx = locateMatchLine(lines, [/"(?:cross-env-shell|lodash\.js|mongose|expres)":/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // SUPPLY-13: Deprecated Cryptography Package Import: 'crypto-js'
    if (/package\.json$/i.test(file.path) && lines.some(l => /^\s*"crypto-js"\s*:\s*"/.test(l))) {
        const matchLineIdx = lines.findIndex(l => /^\s*"crypto-js"\s*:\s*"/.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply13-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7313,
            type: 'SECURITY',
            title: "SUPPLY-13: Deprecated Cryptography Package Import: 'crypto-js'",
            severity: 'LOW',
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
        const matchLineIdx = locateMatchLine(lines, [/^[a-zA-Z0-9_-]+$/m], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply14-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7314,
            type: 'SECURITY',
            title: "SUPPLY-14: Python Dependency Unpinned in requirements.txt",
            severity: 'MEDIUM',
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
    // SUPPLY-17: Insecure Package Registry URL (HTTP instead of HTTPS)
    if (/(?:\.npmrc|package\.json|pip\.conf)$/i.test(file.path) && /http:\/\/(?:registry\.npmjs\.org|pypi\.org)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/http:\/\/(?:registry\.npmjs\.org|pypi\.org)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply17-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7317,
            type: 'SECURITY',
            title: "SUPPLY-17: Insecure Package Registry URL (HTTP instead of HTTPS)",
            severity: 'HIGH',
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
    // SUPPLY-19: Unverified Direct Tarball / URL Package Dependency
    if (/package\.json$/i.test(file.path) && /"dependencies":\s*\{[^}]*"[^"]+"\s*:\s*"http:\/\/[^"]+\.tgz"/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/"[^"]+"\s*:\s*"http:\/\/[^"]+\.tgz"/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    if (/package\.json$/i.test(file.path) && lines.some(l => /^\s*"left-pad"\s*:\s*"/.test(l))) {
        const matchLineIdx = lines.findIndex(l => /^\s*"left-pad"\s*:\s*"/.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply20-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7320,
            type: 'SECURITY',
            title: "SUPPLY-20: Unmaintained / Abandoned Package Import (left-pad)",
            severity: 'LOW',
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
    // SUPPLY-22: GitHub Actions Workflow Using Mutable Branch Ref (@main)
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /uses:\s*actions\/[a-zA-Z0-9_-]+@(main|master)\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/uses:\s*actions\/[a-zA-Z0-9_-]+@(main|master)\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply22-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7322,
            type: 'SECURITY',
            title: "SUPPLY-22: GitHub Actions Workflow Using Mutable Branch Ref (@main)",
            severity: 'MEDIUM',
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
    // Only when the PR's own code is checked out (head sha/ref, head_ref, refs/pull/N) and a later step runs it.
    const supply23Line = /\.github\/workflows\/.*\.ya?ml$/i.test(file.path) ? prTargetHeadCheckoutLine(lines) : -1;
    if (supply23Line !== -1) {
        const matchLineIdx = supply23Line;
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
    // SUPPLY-25: Vulnerable Prototype Pollution in Deprecated 'lodash' (<4.17.21)
    if (/package\.json$/i.test(file.path) && /"lodash":\s*"[\^~]?(?:[0-3]\.|4\.(?:\d|1[0-6])\.|4\.17\.(?:\d|1\d|20)")/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/"lodash":\s*"[\^~]?(?:[0-3]\.|4\.(?:\d|1[0-6])\.|4\.17\.(?:\d|1\d|20)")/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    if (/package\.json$/i.test(file.path) && /"xml2js":\s*"(?:[\^~]?0\.[0-4]\.)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/"xml2js":\s*"(?:[\^~]?0\.[0-4]\.)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // SUPPLY-29: Over-Permissive GitHub Actions GITHUB_TOKEN Default
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /permissions:\s*write-all/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/permissions:\s*write-all/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // SUPPLY-32: Insecure Gradle / Maven Dependency Without Checksum
    if (/(?:build\.gradle(?:\.kts)?|pom\.xml)$/i.test(file.path) && /http:\/\/(?:repo1?\.maven\.(?:apache\.)?org|jcenter)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/http:\/\/(?:repo1?\.maven\.(?:apache\.)?org|jcenter)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // SUPPLY-34: Direct Dependency on Native Binary Compilers in Runtime
    const runtimeCompilerIdx = lowerPath.endsWith('dockerfile') ? finalStageCompilerLine(lines) : -1;
    if (runtimeCompilerIdx !== -1) {
        const matchLineIdx = runtimeCompilerIdx;
        const lineNum = matchLineIdx + 1;
        findings.push({
            id: `supply34-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7334,
            type: 'SECURITY',
            title: "SUPPLY-34: Direct Dependency on Native Binary Compilers in Runtime",
            severity: 'LOW',
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
    // SUPPLY-39: Unverified Download of Standalone Binary CLI Tools in CI
    if (/\.github\/workflows\/.*\.ya?ml$/i.test(file.path) && /curl\s+-[a-zA-Z]*\s+https?:\/\/[^\s]+\s*\|\s*(?:bash|sh)/i.test(cleanContent) && !/sha256sum/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/curl\s+-[a-zA-Z]*\s+https?:\/\/[^\s]+\s*\|\s*(?:bash|sh)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `supply39-${Date.now()}-${findingCounter.count++}`,
            ruleId: 7339,
            type: 'SECURITY',
            title: "SUPPLY-39: Unverified Download of Standalone Binary CLI Tools in CI",
            severity: 'MEDIUM',
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
    // SUPPLY-49: Over-Permissive File Permissions in Published NPM Tarball
    if (/package\.json$/i.test(file.path) && /(?:chmod\s+(?:-R\s+)?0?777\b|umask\s+0?000\b)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:chmod\s+(?:-R\s+)?0?777\b|umask\s+0?000\b)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    return { findings, logs };
}
