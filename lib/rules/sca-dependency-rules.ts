/**
 * Zelsis Master evaluateScaDependencyRules Engine
 * Software Composition Analysis (SCA), Known CVE Detection, License Compliance & Supply Chain Hygiene.
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface ScaDependencyRuleResult {
    findings: Finding[];
    logs: string[];
}
interface CveDefinition {
    cveId: string;
    cvss: number;
    severity: "CRITICAL" | "HIGH" | "MEDIUM";
    title: string;
    description: string;
    safeVersion: string;
    isVulnerable: (verStr: string) => boolean;
}
// Helper to parse clean semver numbers (major, minor, patch)
function parseSemVer(verStr: string): {
    major: number;
    minor: number;
    patch: number;
} | null {
    const clean = verStr.replace(/^[\^~>=<v\s]+/, '').trim();
    const parts = clean.split('.').map(p => parseInt(p, 10));
    if (parts.length >= 2 && !isNaN(parts[0]) && !isNaN(parts[1])) {
        return {
            major: parts[0],
            minor: parts[1],
            patch: isNaN(parts[2]) ? 0 : parts[2]
        };
    }
    return null;
}
function isLessThan(ver: {
    major: number;
    minor: number;
    patch: number;
}, target: [
    number,
    number,
    number
]): boolean {
    if (ver.major !== target[0])
        return ver.major < target[0];
    if (ver.minor !== target[1])
        return ver.minor < target[1];
    return ver.patch < target[2];
}
// Curated high-impact real-world CVEs
const NPM_CVE_REGISTRY: Record<string, CveDefinition> = {
    axios: {
        cveId: "CVE-2023-45857",
        cvss: 9.1,
        severity: "CRITICAL",
        title: "Axios Server-Side Request Forgery (SSRF) & Credential Leakage",
        description: "Axios versions prior to 1.7.4 are vulnerable to SSRF and sensitive header leakage across cross-origin redirects.",
        safeVersion: "^1.7.4",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [1, 7, 4]);
        }
    },
    lodash: {
        cveId: "CVE-2019-10744",
        cvss: 8.8,
        severity: "HIGH",
        title: "Lodash Prototype Pollution via merge, defaultsDeep, and template",
        description: "Lodash prior to 4.17.21 allows attackers to modify Object.prototype, leading to Denial of Service or Remote Code Execution.",
        safeVersion: "^4.17.21",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [4, 17, 21]);
        }
    },
    jsonwebtoken: {
        cveId: "CVE-2022-23529",
        cvss: 9.8,
        severity: "CRITICAL",
        title: "JsonWebToken Insecure Key Retrieval & Remote Code Execution",
        description: "Versions of jsonwebtoken prior to 9.0.0 allow arbitrary file retrieval and prototype manipulation via crafted payload options.",
        safeVersion: "^9.0.0",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [9, 0, 0]);
        }
    },
    minimist: {
        cveId: "CVE-2021-44906",
        cvss: 7.5,
        severity: "HIGH",
        title: "Minimist Prototype Pollution via Constructor Manipulation",
        description: "Minimist prior to 1.2.6 does not properly sanitize __proto__ and constructor keys when parsing CLI arguments.",
        safeVersion: "^1.2.8",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [1, 2, 6]);
        }
    },
    express: {
        cveId: "CVE-2024-29041",
        cvss: 7.5,
        severity: "HIGH",
        title: "Express Open Redirect & Malformed Route Path Bypass",
        description: "Express versions before 4.19.2 mishandle encoded redirect URLs, enabling external phishing and bypass of routing boundaries.",
        safeVersion: "^4.19.2",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [4, 19, 2]);
        }
    },
    semver: {
        cveId: "CVE-2022-25883",
        cvss: 7.5,
        severity: "HIGH",
        title: "Semver Regular Expression Denial of Service (ReDoS)",
        description: "Semver before 7.5.2 is vulnerable to ReDoS when parsing complex version expressions or range sets.",
        safeVersion: "^7.5.4",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [7, 5, 2]);
        }
    },
    tar: {
        cveId: "CVE-2024-28863",
        cvss: 8.1,
        severity: "HIGH",
        title: "Node-Tar Arbitrary File Overwrite & Path Traversal",
        description: "Node-tar before 6.2.1 allows attackers to write outside the extraction directory through crafted archive entries.",
        safeVersion: "^6.2.1",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [6, 2, 1]);
        }
    },
    next: {
        cveId: "CVE-2024-34351",
        cvss: 7.5,
        severity: "HIGH",
        title: "Next.js Server Actions Server-Side Request Forgery (SSRF)",
        description: "Next.js versions prior to 14.1.1 mishandle Host headers during Server Action redirects, leading to SSRF.",
        safeVersion: "^14.2.0",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [14, 1, 1]);
        }
    },
    cookie: {
        cveId: "CVE-2024-47764",
        cvss: 5.3,
        severity: "MEDIUM",
        title: "Cookie Out-of-Bounds Control Character Parsing Flaw",
        description: "Cookie library prior to 0.7.0 mishandles invalid character sequences during cookie name and value serialization.",
        safeVersion: "^0.7.1",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [0, 7, 0]);
        }
    },
    ws: {
        cveId: "CVE-2024-37890",
        cvss: 7.5,
        severity: "HIGH",
        title: "WS WebSocket Frame Extension ReDoS & Memory Exhaustion",
        description: "WS before 8.17.1 permits unbounded Sec-WebSocket-Extensions header parsing causing Denial of Service.",
        safeVersion: "^8.17.1",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [8, 17, 1]);
        }
    },
    "follow-redirects": {
        cveId: "CVE-2024-28849",
        cvss: 7.4,
        severity: "HIGH",
        title: "Follow-Redirects Authorization Leakage in Cross-Origin Redirects",
        description: "Versions prior to 1.15.6 forward sensitive Authorization headers to untrusted third-party hosts during HTTP redirects.",
        safeVersion: "^1.15.6",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [1, 15, 6]);
        }
    },
    braces: {
        cveId: "CVE-2024-4068",
        cvss: 7.5,
        severity: "HIGH",
        title: "Braces Exponential Pattern Expansion Denial of Service",
        description: "Braces prior to 3.0.3 allows attackers to exhaust CPU resources using nested curly brace permutations.",
        safeVersion: "^3.0.3",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [3, 0, 3]);
        }
    },
    micromatch: {
        cveId: "CVE-2024-4067",
        cvss: 7.5,
        severity: "HIGH",
        title: "Micromatch ReDoS on Untrusted Glob Patterns",
        description: "Micromatch before 4.0.8 is vulnerable to Regular Expression Denial of Service when matching deep wildcard glob expressions.",
        safeVersion: "^4.0.8",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [4, 0, 8]);
        }
    },
    ejs: {
        cveId: "CVE-2024-33883",
        cvss: 9.8,
        severity: "CRITICAL",
        title: "EJS Server-Side Template Injection (SSTI) & Remote Code Execution",
        description: "EJS prior to 3.1.10 does not sanitize settings parameter in render functions, leading to arbitrary code execution.",
        safeVersion: "^3.1.10",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [3, 1, 10]);
        }
    },
    nodemailer: {
        cveId: "CVE-2024-0007",
        cvss: 7.5,
        severity: "HIGH",
        title: "Nodemailer SMTP Header Injection & Address Spoofing",
        description: "Nodemailer versions before 6.9.9 allow attackers to inject CRLF headers via unsanitized envelope recipients.",
        safeVersion: "^6.9.9",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [6, 9, 9]);
        }
    },
    "fast-xml-parser": {
        cveId: "CVE-2024-41818",
        cvss: 7.5,
        severity: "HIGH",
        title: "Fast-XML-Parser ReDoS & Unbounded Entity Memory Allocation",
        description: "Versions before 4.4.1 are susceptible to denial of service via circular entity expansion or deeply nested tags.",
        safeVersion: "^4.4.1",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [4, 4, 1]);
        }
    },
    validator: {
        cveId: "CVE-2021-3765",
        cvss: 5.3,
        severity: "MEDIUM",
        title: "Validator.js Regular Expression Denial of Service in URL Validation",
        description: "Validator before 13.7.0 is susceptible to ReDoS when validating untrusted URL inputs with specific repeating prefixes.",
        safeVersion: "^13.7.0",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [13, 7, 0]);
        }
    },
    "tough-cookie": {
        cveId: "CVE-2023-26136",
        cvss: 7.5,
        severity: "HIGH",
        title: "Tough-Cookie Prototype Pollution in Memory Cookie Store",
        description: "Tough-cookie before 4.1.3 allows prototype pollution via setCookie parameter manipulation.",
        safeVersion: "^4.1.3",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [4, 1, 3]);
        }
    },
    "path-to-regexp": {
        cveId: "CVE-2024-45296",
        cvss: 7.5,
        severity: "HIGH",
        title: "Path-To-Regexp ReDoS on Complex Parameterized Routes",
        description: "Versions prior to 6.3.0 are vulnerable to catastrophic backtracking when matching URL paths against long patterns.",
        safeVersion: "^6.3.0",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [6, 3, 0]);
        }
    },
    "express-fileupload": {
        cveId: "CVE-2020-7699",
        cvss: 9.8,
        severity: "CRITICAL",
        title: "Express-Fileupload Prototype Pollution to Remote Code Execution",
        description: "express-fileupload prior to 1.4.0 allows remote code execution via prototype pollution in parseNested parameter parsing.",
        safeVersion: "^1.4.0",
        isVulnerable: (ver) => {
            const v = parseSemVer(ver);
            return v !== null && isLessThan(v, [1, 4, 0]);
        }
    }
};
// Deprecated or abandoned packages in the JavaScript ecosystem
const DEPRECATED_PACKAGES: Record<string, {
    replacement: string;
    reason: string;
}> = {
    request: {
        replacement: "native fetch, axios, or undici",
        reason: "Package was officially deprecated in February 2020 and contains unpatched security and TLS issues."
    },
    querystring: {
        replacement: "native URLSearchParams",
        reason: "Node.js core legacy module deprecated in favor of WHATWG URLSearchParams."
    },
    "node-uuid": {
        replacement: "uuid (v9+)",
        reason: "Original package abandoned and superseded by the official 'uuid' repository."
    },
    nomnom: {
        replacement: "commander or cac",
        reason: "Deprecated CLI argument parser without maintenance for over 8 years."
    }
};
export function evaluateScaDependencyRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ScaDependencyRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, scratch, and .agent
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isPackageJson = lowerPath.endsWith("package.json");
    const isPackageLock = lowerPath.endsWith("package-lock.json");
    const isRequirementsTxt = lowerPath.endsWith("requirements.txt");
    const isPyprojectToml = lowerPath.endsWith("pyproject.toml");
    if (!isPackageJson && !isPackageLock && !isRequirementsTxt && !isPyprojectToml) {
        return { findings, logs };
    }
    // ==========================================
    // 1. Audit package.json Manifest
    // ==========================================
    if (isPackageJson) {
        try {
            const pkgJson = JSON.parse(cleanContent);
            const allDeps: Record<string, string> = {
                ...(pkgJson.dependencies || {}),
                ...(pkgJson.devDependencies || {})
            };
            // Check 1.1: Known CVEs in Dependencies
            for (const [pkgName, versionSpec] of Object.entries(allDeps)) {
                const cveDef = NPM_CVE_REGISTRY[pkgName];
                if (cveDef && cveDef.isVulnerable(versionSpec)) {
                    // Find exact line in package.json
                    const lineIdx = lines.findIndex(l => {
                        const trimmed = l.trim();
                        return ((trimmed.includes(`"${pkgName}"`) || trimmed.includes(`'${pkgName}'`)) &&
                            (trimmed.includes(`"${versionSpec}"`) || trimmed.includes(`'${versionSpec}'`)));
                    });
                    const lineNum = lineIdx !== -1 ? lineIdx + 1 : 1;
                    const originalLine = lineIdx !== -1 ? lines[lineIdx] : `    "${pkgName}": "${versionSpec}"`;
                    const patchedLine = originalLine.replace(versionSpec, cveDef.safeVersion);
                    const diffPatch = [
                        `--- a/${file.path}`,
                        `+++ b/${file.path}`,
                        `@@ -${lineNum},1 +${lineNum},1 @@`,
                        `-${originalLine}`,
                        `+${patchedLine}`
                    ].join("\n");
                    findings.push({
                        id: `sca-cve-${Date.now()}-${findingCounter.count++}`,
                        ruleId: 27211,
                        type: "SECURITY",
                        title: `SCA: ${cveDef.cveId} - ${cveDef.title} (${pkgName}@${versionSpec})`,
                        severity: cveDef.severity,
                        category: "Software Composition Analysis (SCA)",
                        filePath: file.path,
                        lineRange: `L${lineNum}`,
                        snippet: originalLine.trim(),
                        reproductionSteps: [
                            `Audited project manifest at ${file.path}:${lineNum}.`,
                            `Detected vulnerable dependency '${pkgName}' declared with version specifier '${versionSpec}'.`,
                            `Matched against National Vulnerability Database record ${cveDef.cveId} (CVSS: ${cveDef.cvss}).`,
                            cveDef.description
                        ],
                        remediationPrompt: `Upgrade '${pkgName}' from '${versionSpec}' to safe release '${cveDef.safeVersion}' or higher using: npm install ${pkgName}@${cveDef.safeVersion.replace('^', '')}`,
                        diffPatch,
                        status: "OPEN",
                        owner: "Dependency Security Lead",
                        falsePositive: false
                    });
                    logs.push(`[${new Date().toLocaleTimeString()}] [SCA] ${cveDef.cveId} detected in ${file.path} (${pkgName}@${versionSpec})`);
                }
                // Check 1.2: Deprecated / Abandoned Packages
                const deprecatedDef = DEPRECATED_PACKAGES[pkgName];
                if (deprecatedDef) {
                    const lineIdx = lines.findIndex(l => l.includes(`"${pkgName}"`) || l.includes(`'${pkgName}'`));
                    const lineNum = lineIdx !== -1 ? lineIdx + 1 : 1;
                    findings.push({
                        id: `sca-dep-${Date.now()}-${findingCounter.count++}`,
                        ruleId: 27212,
                        type: "SECURITY",
                        title: `SCA: Deprecated Supply Chain Dependency '${pkgName}'`,
                        severity: "MEDIUM",
                        category: "Software Composition Analysis (SCA)",
                        filePath: file.path,
                        lineRange: `L${lineNum}`,
                        snippet: lines[lineIdx]?.trim() || `"${pkgName}": "${versionSpec}"`,
                        reproductionSteps: [
                            `Audited project manifest at ${file.path}:${lineNum}.`,
                            `Identified abandoned package '${pkgName}'.`,
                            deprecatedDef.reason
                        ],
                        remediationPrompt: `Replace deprecated package '${pkgName}' with modern maintained alternative: ${deprecatedDef.replacement}.`,
                        status: "OPEN",
                        owner: "Dependency Security Lead",
                        falsePositive: false
                    });
                }
            }
            // Check 1.3: Open Source License Compliance (GPL/AGPL Viral Copyleft)
            const declaredLicense = pkgJson.license || pkgJson.licenses;
            if (declaredLicense && typeof declaredLicense === "string") {
                const isStrongCopyleft = /GPL-?([23])(\.0)?|AGPL-?([23])(\.0)?|SSPL|EUPL/i.test(declaredLicense);
                if (isStrongCopyleft) {
                    const lineIdx = lines.findIndex(l => l.includes('"license"') || l.includes("'license'"));
                    const lineNum = lineIdx !== -1 ? lineIdx + 1 : 1;
                    findings.push({
                        id: `sca-lic-${Date.now()}-${findingCounter.count++}`,
                        ruleId: 27213,
                        type: "LEGAL_COMPLIANCE",
                        title: `LICENSE-01: Restrictive Strong Copyleft License Detected (${declaredLicense})`,
                        severity: "MEDIUM",
                        category: "Open Source License Compliance",
                        filePath: file.path,
                        lineRange: `L${lineNum}`,
                        snippet: lines[lineIdx]?.trim() || `"license": "${declaredLicense}"`,
                        reproductionSteps: [
                            `Audited license declaration in ${file.path}:${lineNum}.`,
                            `Detected Strong Copyleft license '${declaredLicense}'.`,
                            "Strong Copyleft licenses can legally require proprietary commercial software that links with them to disclose and open-source all internal source code."
                        ],
                        remediationPrompt: "For proprietary commercial SaaS products, utilize permissive open-source licenses such as MIT, Apache-2.0, BSD-3-Clause, or ISC.",
                        status: "OPEN",
                        owner: "Compliance Officer",
                        falsePositive: false
                    });
                    logs.push(`[${new Date().toLocaleTimeString()}] [LICENSE] Strong copyleft license '${declaredLicense}' detected in ${file.path}`);
                }
            }
        }
        catch {
            // Invalid JSON handled gracefully
        }
    }
    // ==========================================
    // 2. Audit Python Manifests (requirements.txt & pyproject.toml)
    // ==========================================
    if (isRequirementsTxt || isPyprojectToml) {
        const pythonCves: Record<string, {
            cve: string;
            safe: string;
            title: string;
            isVulnerable: (maj: number, min: number, patch: number) => boolean;
        }> = {
            urllib3: {
                cve: "CVE-2023-45803",
                safe: ">=2.0.7",
                title: "Urllib3 Request Body Leak on Cross-Origin Redirect",
                isVulnerable: (maj, min, patch) => maj < 2 || (maj === 2 && min === 0 && patch < 7)
            },
            flask: {
                cve: "CVE-2023-30861",
                safe: ">=2.2.5",
                title: "Flask Cookie Session Context Leakage",
                isVulnerable: (maj, min, patch) => maj < 2 || (maj === 2 && min < 2) || (maj === 2 && min === 2 && patch < 5)
            },
            django: {
                cve: "CVE-2024-27351",
                safe: ">=4.2.11",
                title: "Django ReDoS in RegularExpressionValidator",
                isVulnerable: (maj, min, patch) => maj < 4 || (maj === 4 && min < 2) || (maj === 4 && min === 2 && patch < 11)
            },
            requests: {
                cve: "CVE-2023-32681",
                safe: ">=2.31.0",
                title: "Requests Proxy-Authorization Header Leak",
                isVulnerable: (maj, min) => maj < 2 || (maj === 2 && min < 31)
            },
            jinja2: {
                cve: "CVE-2024-34064",
                safe: ">=3.1.4",
                title: "Jinja2 HTML Attribute Injection & Sandbox Bypass",
                isVulnerable: (maj, min, patch) => maj < 3 || (maj === 3 && min < 1) || (maj === 3 && min === 1 && patch < 4)
            },
            pyyaml: {
                cve: "CVE-2020-14343",
                safe: ">=5.4",
                title: "PyYAML Arbitrary Code Execution in FullLoader",
                isVulnerable: (maj, min) => maj < 5 || (maj === 5 && min < 4)
            },
            cryptography: {
                cve: "CVE-2023-49083",
                safe: ">=41.0.6",
                title: "Cryptography NULL Pointer Dereference in PKCS7 Parsing",
                isVulnerable: (maj, min, patch) => maj < 41 || (maj === 41 && min === 0 && patch < 6)
            },
            werkzeug: {
                cve: "CVE-2024-34069",
                safe: ">=3.0.3",
                title: "Werkzeug Infinite Loop / DoS in Multipart Parsing",
                isVulnerable: (maj, min, patch) => maj < 3 || (maj === 3 && min === 0 && patch < 3)
            },
            certifi: {
                cve: "CVE-2023-37920",
                safe: ">=2023.7.22",
                title: "Certifi Untrusted E-Tugra Root CA Certificates",
                isVulnerable: (maj, min, patch) => maj < 2023 || (maj === 2023 && min < 7) || (maj === 2023 && min === 7 && patch < 22)
            }
        };
        lines.forEach((line, idx) => {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith("#"))
                return;
            for (const [pkg, info] of Object.entries(pythonCves)) {
                const pkgRegex = new RegExp(`(?:^|["'\\s])${pkg}(?:$|["'\\s=<>~^])`, "i");
                if (pkgRegex.test(trimmed) || trimmed.toLowerCase().startsWith(pkg)) {
                    const match = trimmed.match(/(?:==|<=|~=|=|\^|>=|["'])\s*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?/);
                    if (match) {
                        const major = parseInt(match[1], 10);
                        const minor = parseInt(match[2], 10);
                        const patch = match[3] ? parseInt(match[3], 10) : 0;
                        if (info.isVulnerable(major, minor, patch)) {
                            findings.push({
                                id: `sca-py-${Date.now()}-${findingCounter.count++}`,
                                ruleId: 27214,
                                type: "SECURITY",
                                title: `SCA: ${info.cve} - ${info.title} (${pkg})`,
                                severity: "HIGH",
                                category: "Software Composition Analysis (SCA)",
                                filePath: file.path,
                                lineRange: `L${idx + 1}`,
                                snippet: trimmed,
                                reproductionSteps: [
                                    `Audited Python dependency manifest at ${file.path}:${idx + 1}.`,
                                    `Detected vulnerable package '${pkg}' with version specifier '${trimmed}'.`
                                ],
                                remediationPrompt: `Pin ${pkg} to safe version '${pkg}${info.safe}' in ${isRequirementsTxt ? "requirements.txt" : "pyproject.toml"}.`,
                                status: "OPEN",
                                owner: "Backend Security Lead",
                                falsePositive: false
                            });
                            logs.push(`[${new Date().toLocaleTimeString()}] [SCA PYTHON] Flagged ${info.cve} (${pkg}) in ${file.path}:${idx + 1}`);
                        }
                    }
                }
            }
        });
    }
    return { findings, logs };
}
