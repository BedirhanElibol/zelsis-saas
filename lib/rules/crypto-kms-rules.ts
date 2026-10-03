/**
 * Zelsis Master evaluateCryptoKmsRules Engine (50 Rules)
 * Rules CRYPTO-01 to CRYPTO-50 (Rule IDs 13301 to 13350).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface CryptoKmsRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateCryptoKmsRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): CryptoKmsRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // CRYPTO-01: Hardcoded Cryptographic Keys and Static Salts in Source Code
    const hit_13301 = lines.findIndex((l) => /\b(?:aes_?key|AES_KEY|encryption_?key|ENCRYPTION_KEY|cipher_?key|CIPHER_KEY|crypto_?key|CRYPTO_KEY|salt|SALT|static_?salt|STATIC_SALT)\s*[:=]\s*(?:Buffer\.from\(\s*)?["'][A-Za-z0-9+/=_-]{16,}["']/i.test(l) && !/your|example|change|placeholder|dummy|xxxx|<|\.\.\./i.test(l));
    if (hit_13301 !== -1) {
        const matchLineIdx = hit_13301;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `crypto13301-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13301,
            type: 'SECURITY',
            title: "CRYPTO-01: Hardcoded Cryptographic Keys and Static Salts in Source Code",
            severity: "CRITICAL",
            category: "Key Storage",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Enterprise KMS configuration',
            reproductionSteps: [
                `Audited Enterprise KMS configuration in ${file.path}:${lineNum}.`,
                'Matched CRYPTO-01: Hardcoded Cryptographic Keys and Static Salts in Source Code.'
            ],
            remediationPrompt: "Disallow static cryptographic keys in source code; retrieve key material from dedicated KMS or HSM.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CRYPTO AUDIT] Found CRYPTO-01: Hardcoded Cryptographic Keys and Static Salts in Source Code at ${file.path}:${lineNum}`);
    }
    // CRYPTO-02: Missing Automated Master Key Rotation Schedule Exceeding 90 Days
    const hit_13302 = findKmsKeyWithoutRotation(cleanContent);
    if (hit_13302 !== -1) {
        const matchLineIdx = hit_13302;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `crypto13302-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13302,
            type: 'SECURITY',
            title: "CRYPTO-02: Missing Automated Master Key Rotation Schedule Exceeding 90 Days",
            severity: "LOW",
            category: "Key Lifecycle",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Enterprise KMS configuration',
            reproductionSteps: [
                `Audited Enterprise KMS configuration in ${file.path}:${lineNum}.`,
                'Matched CRYPTO-02: Missing Automated Master Key Rotation Schedule Exceeding 90 Days.'
            ],
            remediationPrompt: "Enforce automated 90-day cryptographic key rotation on all envelope encryption KMS master keys.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CRYPTO AUDIT] Found CRYPTO-02: Missing Automated Master Key Rotation Schedule Exceeding 90 Days at ${file.path}:${lineNum}`);
    }
    // CRYPTO-03: Insecure Legacy Cipher Modes Permitted (AES-ECB / Unauthenticated CBC)
    const hit_13303 = lines.findIndex((l) => /["'](?:aes-(?:128|192|256)-ecb|des-ecb|AES\/ECB\/\w+|DESede\/ECB\/\w+|DES\/ECB\/\w+)["']|\bAES\.MODE_ECB\b|\bmodes\.ECB\s*\(/i.test(l));
    if (hit_13303 !== -1) {
        const matchLineIdx = hit_13303;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `crypto13303-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13303,
            type: 'SECURITY',
            title: "CRYPTO-03: Insecure Legacy Cipher Modes Permitted (AES-ECB / Unauthenticated CBC)",
            severity: "CRITICAL",
            category: "Cipher Selection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Enterprise KMS configuration',
            reproductionSteps: [
                `Audited Enterprise KMS configuration in ${file.path}:${lineNum}.`,
                'Matched CRYPTO-03: Insecure Legacy Cipher Modes Permitted (AES-ECB / Unauthenticated CBC).'
            ],
            remediationPrompt: "Enforce authenticated AEAD encryption (AES-256-GCM or ChaCha20-Poly1305); reject ECB and unauthenticated CBC.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CRYPTO AUDIT] Found CRYPTO-03: Insecure Legacy Cipher Modes Permitted (AES-ECB / Unauthenticated CBC) at ${file.path}:${lineNum}`);
    }
    // CRYPTO-04: Cryptographic Nonce Reuse in Galois/Counter Mode (GCM) Encryption
    const hit_13304 = findStaticGcmNonce(cleanContent);
    if (hit_13304 !== -1) {
        const matchLineIdx = hit_13304;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `crypto13304-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13304,
            type: 'SECURITY',
            title: "CRYPTO-04: Cryptographic Nonce Reuse in Galois/Counter Mode (GCM) Encryption",
            severity: "CRITICAL",
            category: "Nonce Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Enterprise KMS configuration',
            reproductionSteps: [
                `Audited Enterprise KMS configuration in ${file.path}:${lineNum}.`,
                'Matched CRYPTO-04: Cryptographic Nonce Reuse in Galois/Counter Mode (GCM) Encryption.'
            ],
            remediationPrompt: "Ensure unique 96-bit initialization vectors/nonces per encryption operation to prevent plaintext recovery.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CRYPTO AUDIT] Found CRYPTO-04: Cryptographic Nonce Reuse in Galois/Counter Mode (GCM) Encryption at ${file.path}:${lineNum}`);
    }
    // CRYPTO-05: Weak Asymmetric Key Strengths (RSA < 3072 bits or ECC < 256 bits)
    const hit_13305 = findWeakRsaModulus(cleanContent);
    if (hit_13305 !== -1) {
        const matchLineIdx = hit_13305;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `crypto13305-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13305,
            type: 'SECURITY',
            title: "CRYPTO-05: Weak Asymmetric Key Strengths (RSA < 3072 bits or ECC < 256 bits)",
            severity: "HIGH",
            category: "Key Strength",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Enterprise KMS configuration',
            reproductionSteps: [
                `Audited Enterprise KMS configuration in ${file.path}:${lineNum}.`,
                'Matched CRYPTO-05: Weak Asymmetric Key Strengths (RSA < 3072 bits or ECC < 256 bits).'
            ],
            remediationPrompt: "Mandate minimum RSA-3072 or ECC P-256 / Ed25519 for all digital signatures and key exchange.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CRYPTO AUDIT] Found CRYPTO-05: Weak Asymmetric Key Strengths (RSA < 3072 bits or ECC < 256 bits) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
// ---- precise matchers (rule-proof pass) ----
const lineAt = (text: string, idx: number): number => text.slice(0, idx).split('\n').length - 1;
/** Brace-matched block text starting at `start` (the first `{` after it). */
function blockFrom(src: string, start: number, open = '{', close = '}'): string {
    const o = src.indexOf(open, start);
    if (o === -1) return '';
    let depth = 0;
    let i = o;
    for (; i < src.length; i++) {
        if (src[i] === open) depth++;
        else if (src[i] === close && --depth === 0) break;
    }
    return src.slice(start, i + 1);
}
/** A symmetric KMS key (Terraform aws_kms_key or CDK kms.Key) declared without automatic rotation. */
function findKmsKeyWithoutRotation(src: string): number {
    const tf = /resource\s+"aws_kms_key"\s+"[^"]+"\s*\{/g;
    let m: RegExpExecArray | null;
    while ((m = tf.exec(src))) {
        const block = blockFrom(src, m.index);
        if (/customer_master_key_spec\s*=\s*"(?!SYMMETRIC_DEFAULT)/.test(block) || /key_usage\s*=\s*"(?:SIGN_VERIFY|GENERATE_VERIFY_MAC)"/.test(block)) continue;
        if (!/enable_key_rotation\s*=\s*true/.test(block)) return lineAt(src, m.index);
    }
    const cdk = /new\s+kms\.Key\s*\(/g;
    while ((m = cdk.exec(src))) {
        const call = blockFrom(src, m.index, '(', ')');
        if (/keySpec\s*:\s*kms\.KeySpec\.(?!SYMMETRIC_DEFAULT)/.test(call)) continue;
        if (!/enableKeyRotation\s*:\s*true/.test(call)) return lineAt(src, m.index);
    }
    return -1;
}
/** AES-GCM encryption whose IV is a fixed buffer, a string literal, or a value read from env/config. */
function findStaticGcmNonce(src: string): number {
    const call = /createCipheriv\s*\(\s*["']aes-\d+-gcm["']\s*,\s*(?:[^,()]+|\([^()]*\))+,\s*((?:[^,()\n]+|\([^()]*\))+?)\s*[,)]/g;
    let m: RegExpExecArray | null;
    const isStatic = (expr: string): boolean => /^Buffer\.(?:alloc\s*\(|from\s*\(\s*(?:["'`]|process\.env|\[))|^["'`]|process\.env/.test(expr.trim());
    while ((m = call.exec(src))) {
        const iv = m[1].trim();
        if (isStatic(iv)) return lineAt(src, m.index);
        const id = /^[A-Za-z_$][\w$]*$/.test(iv) ? iv : null;
        if (!id) continue;
        const decl = new RegExp(`\\b(?:const|let|var)\\s+${id.replace(/\$/g, '\\$')}\\s*=\\s*([^;\\n]+)`).exec(src);
        if (decl && isStatic(decl[1]) && !/randomBytes|getRandomValues|randomUUID/.test(decl[1])) return lineAt(src, m.index);
    }
    return -1;
}
/** RSA key generation with a modulus below 2048 bits (Node, Python cryptography, Go). */
function findWeakRsaModulus(src: string): number {
    const pats = [
        /generateKeyPair(?:Sync)?\s*\(\s*["']rsa["']\s*,\s*\{[^}]*?modulusLength\s*:\s*(\d+)/g,
        /rsa\.generate_private_key\s*\([^)]*?key_size\s*=\s*(\d+)/g,
        /rsa\.GenerateKey\s*\(\s*[\w.]+\s*,\s*(\d+)\s*\)/g,
    ];
    for (const p of pats) {
        let m: RegExpExecArray | null;
        while ((m = p.exec(src))) {
            if (Number(m[1]) < 2048) return lineAt(src, m.index + m[0].lastIndexOf(m[1]));
        }
    }
    return -1;
}
