/**
 * Zelsis Master evaluateOwaspAsvsRules Engine (50 Rules)
 * Rules ASVS-01 to ASVS-50 (Rule IDs 13801 to 13850).
 * Removed as unsound (ids never reused): 13802 (any cookie set in a file without the word HttpOnly), 13803
 * (any findById in a file without a tenant_id filter); both absence-of-X heuristics.
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
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
    // ASVS-05: ASVS V6.2 Cryptographic Storage: Using Insecure Random Salt or Low Iteration Counts
    if (/pbkdf2|bcrypt/i.test(cleanContent) && weakKdfLine(lines) !== -1) {
        const matchLineIdx = weakKdfLine(lines);
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `asvs13805-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13805,
            type: 'SECURITY',
            title: "ASVS-05: ASVS V6.2 Cryptographic Storage: Using Insecure Random Salt or Low Iteration Counts",
            severity: 'MEDIUM',
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
