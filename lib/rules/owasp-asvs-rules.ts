/**
 * Zelsis Master evaluateOwaspAsvsRules Engine (50 Rules)
 * Rules ASVS-01 to ASVS-50 (Rule IDs 13801 to 13850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface OwaspAsvsRuleResult {
    findings: Finding[];
    logs: string[];
}
/** bcrypt cost below 10, e.g. bcrypt.hash(pw, 8), genSaltSync(6), gensalt(rounds=4). */
const WEAK_BCRYPT_COST = /bcrypt\w*\.(?:hash(?:Sync)?\s*\(\s*[^,()]+,\s*|genSalt(?:Sync)?\s*\(\s*|gensalt\s*\(\s*(?:rounds\s*=\s*)?)[1-9]\s*[,)]/i;
/** PBKDF2 iteration count literal, Node (pbkdf2/pbkdf2Sync) and Python (hashlib.pbkdf2_hmac). */
const PBKDF2_ITERATIONS = /pbkdf2(?:Sync)?\s*\(\s*[^,()]+,\s*[^,()]+,\s*(\d[\d_]*)\s*,|pbkdf2_hmac\s*\(\s*[^,()]+,\s*[^,()]+,\s*[^,()]+,\s*(\d[\d_]*)\s*[,)]/gi;
/** Index of the first line hashing passwords with a weak work factor (bcrypt cost < 10, PBKDF2 < 100k), or -1. */
function weakKdfLine(lines: string[]): number {
    return lines.findIndex((l) => {
        if (WEAK_BCRYPT_COST.test(l)) return true;
        for (const m of l.matchAll(PBKDF2_ITERATIONS)) {
            if (Number((m[1] ?? m[2]).replace(/_/g, '')) < 100000) return true;
        }
        return false;
    });
}
export function evaluateOwaspAsvsRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): OwaspAsvsRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // ASVS-02: ASVS V3.2 Session Management: Permitting Session Fixation or Insecure Cookie Flags
    if ((/(?:setHeader\(\s*["']set-cookie["']|cookies\(\)\.set|response\.cookies\.set)\s*\(/i.test(cleanContent) && !/HttpOnly/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/(?:setHeader\(\s*["']set-cookie["']|cookies\(\)\.set|response\.cookies\.set)\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `asvs13802-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13802,
            type: 'SECURITY',
            title: "ASVS-02: ASVS V3.2 Session Management: Permitting Session Fixation or Insecure Cookie Flags",
            severity: "CRITICAL",
            category: "Session Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OWASP ASVS L3 configuration',
            reproductionSteps: [
                `Audited OWASP ASVS L3 configuration in ${file.path}:${lineNum}.`,
                'Matched ASVS-02: ASVS V3.2 Session Management: Permitting Session Fixation or Insecure Cookie Flags.'
            ],
            remediationPrompt: "Enforce HttpOnly, Secure, SameSite=Strict cookies with session regeneration upon login.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [ASVS AUDIT] Found ASVS-02: ASVS V3.2 Session Management: Permitting Session Fixation or Insecure Cookie Flags at ${file.path}:${lineNum}`);
    }
    // ASVS-03: ASVS V4.1 Access Control: Insecure Direct Object References (IDOR) on Tenant APIs
    if ((/lookupRecord|findById/i.test(cleanContent) && !/where.*tenant_id/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/lookupRecord|findById/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `asvs13803-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13803,
            type: 'SECURITY',
            title: "ASVS-03: ASVS V4.1 Access Control: Insecure Direct Object References (IDOR) on Tenant APIs",
            severity: "CRITICAL",
            category: "Access Boundaries",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OWASP ASVS L3 configuration',
            reproductionSteps: [
                `Audited OWASP ASVS L3 configuration in ${file.path}:${lineNum}.`,
                'Matched ASVS-03: ASVS V4.1 Access Control: Insecure Direct Object References (IDOR) on Tenant APIs.'
            ],
            remediationPrompt: "Enforce object-level authorization checking tenant ownership on every record lookup.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [ASVS AUDIT] Found ASVS-03: ASVS V4.1 Access Control: Insecure Direct Object References (IDOR) on Tenant APIs at ${file.path}:${lineNum}`);
    }
    // ASVS-05: ASVS V6.2 Cryptographic Storage: Using Insecure Random Salt or Low Iteration Counts
    if (/pbkdf2|bcrypt/i.test(cleanContent) && weakKdfLine(lines) !== -1) {
        const matchLineIdx = weakKdfLine(lines);
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `asvs13805-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13805,
            type: 'SECURITY',
            title: "ASVS-05: ASVS V6.2 Cryptographic Storage: Using Insecure Random Salt or Low Iteration Counts",
            severity: 'HIGH',
            category: "Data at Rest",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'OWASP ASVS L3 configuration',
            reproductionSteps: [
                `Audited OWASP ASVS L3 configuration in ${file.path}:${lineNum}.`,
                'Matched ASVS-05: ASVS V6.2 Cryptographic Storage: Using Insecure Random Salt or Low Iteration Counts.'
            ],
            remediationPrompt: "Use Argon2id or PBKDF2 with at least 600,000 iterations and unique 16-byte cryptographic salts.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [ASVS AUDIT] Found ASVS-05: ASVS V6.2 Cryptographic Storage: Using Insecure Random Salt or Low Iteration Counts at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
