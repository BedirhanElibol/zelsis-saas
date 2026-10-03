/**
 * Zelsis Master evaluateWeb3SecurityRules Engine (50 Rules)
 * Rules WEB3-01 to WEB3-50 (Rule IDs 8701 to 8750).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface Web3SecurityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateWeb3SecurityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): Web3SecurityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and non-web3 paths
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    // Contract sources only: the word "contract " appears in pricing copy, and ethers/web3 client code is not a contract
    const isWeb3 = lowerPath.endsWith(".sol") || lowerPath.endsWith(".vy") || lowerPath.endsWith(".cairo") ||
        cleanContent.includes("pragma solidity");
    if (!isWeb3)
        return { findings, logs };
    const ts = new Date().toLocaleTimeString();
    // WEB3-01: Reentrancy Vulnerability (Checks-Effects-Interactions Violation)
    // An external call before the balance update, in a contract without a reentrancy guard
    const hit_8701 = findReentrancy(cleanContent);
    if (hit_8701 !== -1) {
        const matchLineIdx = hit_8701;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `web38701-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8701,
            type: 'SECURITY',
            title: "WEB3-01: Reentrancy Vulnerability (Checks-Effects-Interactions Violation)",
            severity: "CRITICAL",
            category: "Smart Contract Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Smart contract instruction',
            reproductionSteps: [
                `Audited smart contract in ${file.path}:${lineNum}.`,
                'Detected security violation matching WEB3-01.'
            ],
            remediationPrompt: "Apply OpenZeppelin ReentrancyGuard nonReentrant modifier and strictly follow Checks-Effects-Interactions.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WEB3 AUDIT] Found WEB3-01: Reentrancy Vulnerability (Checks-Effects-Interactions Violation) at ${file.path}:${lineNum}`);
    }
    // WEB3-02: Integer Overflow / Underflow in Unchecked Math Block
    const hit_8702 = findUncheckedUnderflow(cleanContent);
    if (hit_8702 !== -1) {
        const matchLineIdx = hit_8702;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `web38702-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8702,
            type: 'SECURITY',
            title: "WEB3-02: Integer Overflow / Underflow in Unchecked Math Block",
            severity: "HIGH",
            category: "Arithmetic Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Smart contract instruction',
            reproductionSteps: [
                `Audited smart contract in ${file.path}:${lineNum}.`,
                'Detected security violation matching WEB3-02.'
            ],
            remediationPrompt: "Avoid unchecked blocks around balance deductions; rely on Solidity 0.8+ overflow reverts.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WEB3 AUDIT] Found WEB3-02: Integer Overflow / Underflow in Unchecked Math Block at ${file.path}:${lineNum}`);
    }
    // WEB3-03: Frontrunning / MEV Sandwich Vulnerability (Zero Slippage Tolerance)
    const hit_8703 = lines.findIndex((l) => /\bswapExact(?:Tokens|ETH)For(?:Tokens|ETH)(?:SupportingFeeOnTransferTokens)?\s*\(\s*[^,()]+,\s*0\s*,/.test(l) || /\bswapExactETHForTokens(?:SupportingFeeOnTransferTokens)?\s*(?:\{[^}]*\})?\s*\(\s*0\s*,/.test(l));
    if (hit_8703 !== -1) {
        const matchLineIdx = hit_8703;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `web38703-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8703,
            type: 'SECURITY',
            title: "WEB3-03: Frontrunning / MEV Sandwich Vulnerability (Zero Slippage Tolerance)",
            severity: "CRITICAL",
            category: "DeFi Market Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Smart contract instruction',
            reproductionSteps: [
                `Audited smart contract in ${file.path}:${lineNum}.`,
                'Detected security violation matching WEB3-03.'
            ],
            remediationPrompt: "Enforce explicit slippage tolerance (e.g. minAmountOut >= expected * 0.99) and dynamic deadline timestamps.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WEB3 AUDIT] Found WEB3-03: Frontrunning / MEV Sandwich Vulnerability (Zero Slippage Tolerance) at ${file.path}:${lineNum}`);
    }
    // WEB3-05: Missing Access Control on Critical Admin Functions
    const hit_8705 = findUnguardedAdminFn(cleanContent);
    if (hit_8705 !== -1) {
        const matchLineIdx = hit_8705;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `web38705-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8705,
            type: 'SECURITY',
            title: "WEB3-05: Missing Access Control on Critical Admin Functions",
            severity: "CRITICAL",
            category: "Access Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Smart contract instruction',
            reproductionSteps: [
                `Audited smart contract in ${file.path}:${lineNum}.`,
                'Detected security violation matching WEB3-05.'
            ],
            remediationPrompt: "Enforce onlyOwner or AccessControl DEFAULT_ADMIN_ROLE on all state-altering administrative functions.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WEB3 AUDIT] Found WEB3-05: Missing Access Control on Critical Admin Functions at ${file.path}:${lineNum}`);
    }
    // WEB3-06: Signature Replay Attack (Missing EIP-712 Nonce & ChainID)
    const hit_8706 = findReplayableEcrecover(cleanContent);
    if (hit_8706 !== -1) {
        const matchLineIdx = hit_8706;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `web38706-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8706,
            type: 'SECURITY',
            title: "WEB3-06: Signature Replay Attack (Missing EIP-712 Nonce & ChainID)",
            severity: "HIGH",
            category: "Cryptographic Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Smart contract instruction',
            reproductionSteps: [
                `Audited smart contract in ${file.path}:${lineNum}.`,
                'Detected security violation matching WEB3-06.'
            ],
            remediationPrompt: "Implement EIP-712 typed structured data hashing with incremental user nonces and chainid validation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WEB3 AUDIT] Found WEB3-06: Signature Replay Attack (Missing EIP-712 Nonce & ChainID) at ${file.path}:${lineNum}`);
    }
    // WEB3-07: Dangerous Delegatecall to Untrusted Target Address
    const hit_8707 = findUserDelegatecall(cleanContent);
    if (hit_8707 !== -1) {
        const matchLineIdx = hit_8707;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `web38707-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8707,
            type: 'SECURITY',
            title: "WEB3-07: Dangerous Delegatecall to Untrusted Target Address",
            severity: "CRITICAL",
            category: "Contract Execution",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Smart contract instruction',
            reproductionSteps: [
                `Audited smart contract in ${file.path}:${lineNum}.`,
                'Detected security violation matching WEB3-07.'
            ],
            remediationPrompt: "Never delegatecall to user-controlled addresses; whitelist trusted implementation contract addresses.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WEB3 AUDIT] Found WEB3-07: Dangerous Delegatecall to Untrusted Target Address at ${file.path}:${lineNum}`);
    }
    // WEB3-08: Unprotected Selfdestruct / Suicide Call
    const hit_8708 = findUnguardedSelfdestruct(cleanContent);
    if (hit_8708 !== -1) {
        const matchLineIdx = hit_8708;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `web38708-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8708,
            type: 'SECURITY',
            title: "WEB3-08: Unprotected Selfdestruct / Suicide Call",
            severity: "CRITICAL",
            category: "Contract Destruction",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Smart contract instruction',
            reproductionSteps: [
                `Audited smart contract in ${file.path}:${lineNum}.`,
                'Detected security violation matching WEB3-08.'
            ],
            remediationPrompt: "Remove selfdestruct or restrict behind multi-signature timelock governance authorization.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WEB3 AUDIT] Found WEB3-08: Unprotected Selfdestruct / Suicide Call at ${file.path}:${lineNum}`);
    }
    // WEB3-09: Block Timestamp as Randomness Source
    const hit_8709 = findTimestampRandomness(cleanContent);
    if (hit_8709 !== -1) {
        const matchLineIdx = hit_8709;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `web38709-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8709,
            type: 'SECURITY',
            title: "WEB3-09: Block Timestamp as Randomness Source",
            severity: "MEDIUM",
            category: "Weak Randomness",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Smart contract instruction',
            reproductionSteps: [
                `Audited smart contract in ${file.path}:${lineNum}.`,
                'Detected security violation matching WEB3-09.'
            ],
            remediationPrompt: "Use Chainlink VRF (Verifiable Random Function) for tamper-proof on-chain randomness.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WEB3 AUDIT] Found WEB3-09: Block Timestamp as Randomness Source at ${file.path}:${lineNum}`);
    }
    // WEB3-10: Unchecked ERC-20 Transfer Return Value
    const hit_8710 = findUncheckedErc20Transfer(cleanContent, lines);
    if (hit_8710 !== -1) {
        const matchLineIdx = hit_8710;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `web38710-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8710,
            type: 'SECURITY',
            title: "WEB3-10: Unchecked ERC-20 Transfer Return Value",
            severity: "HIGH",
            category: "Token Handling",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Smart contract instruction',
            reproductionSteps: [
                `Audited smart contract in ${file.path}:${lineNum}.`,
                'Detected security violation matching WEB3-10.'
            ],
            remediationPrompt: "Use OpenZeppelin SafeERC20 safeTransfer and safeTransferFrom wrappers for non-standard tokens.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [WEB3 AUDIT] Found WEB3-10: Unchecked ERC-20 Transfer Return Value at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
// ---- precise matchers (rule-proof pass) ----
const lineAt = (text: string, idx: number): number => text.slice(0, idx).split('\n').length - 1;
interface SolFn { name: string; params: string; header: string; body: string; bodyStart: number; headerStart: number }
/** Every `function name(params) modifiers { body }` in a Solidity source, with brace-matched bodies. */
function solFunctions(src: string): SolFn[] {
    const out: SolFn[] = [];
    const re = /\bfunction\s+(\w+)\s*\(([^)]*)\)([^{;]*)\{/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) {
        const open = m.index + m[0].length - 1;
        let depth = 0;
        let i = open;
        for (; i < src.length; i++) {
            if (src[i] === '{') depth++;
            else if (src[i] === '}' && --depth === 0) break;
        }
        out.push({ name: m[1], params: m[2], header: m[3], body: src.slice(open + 1, i), bodyStart: open + 1, headerStart: m.index });
    }
    return out;
}
const ACCESS_MODIFIER = /\bonly[A-Z]\w*|\bonly\b|\brequiresAuth\b|\bauth\b|\binitializer\b/;
const INLINE_ACCESS_CHECK = /msg\.sender\s*==|==\s*msg\.sender|msg\.sender\s*!=|!=\s*msg\.sender|_checkOwner\s*\(|_checkRole\s*\(|hasRole\s*\(|_onlyOwner\s*\(|isAdmin\s*\[|admins?\s*\[\s*msg\.sender/;
const isExposed = (fn: SolFn): boolean => /\b(?:public|external)\b/.test(fn.header);
const isGuarded = (fn: SolFn): boolean => ACCESS_MODIFIER.test(fn.header) || INLINE_ACCESS_CHECK.test(fn.body);
/** WEB3-01: an ETH-sending low-level call followed by a balance write in the same unguarded function. */
function findReentrancy(src: string): number {
    for (const fn of solFunctions(src)) {
        if (/\bnonReentrant\b/.test(fn.header)) continue;
        const call = /\.call(?:\{\s*value\s*:|\.value\s*\()/.exec(fn.body);
        if (!call) continue;
        if (/\b\w*balances?\s*\[[^\]]+\]\s*(?:-?=|\+=)/i.test(fn.body.slice(call.index))) return lineAt(src, fn.bodyStart + call.index);
    }
    return -1;
}
/** WEB3-02: `balances[x] -= y` inside `unchecked {}` with no preceding bound check in the function. */
function findUncheckedUnderflow(src: string): number {
    for (const fn of solFunctions(src)) {
        const block = /unchecked\s*\{[^}]*?\b\w*balances?\s*\[[^\]]+\]\s*-=/i.exec(fn.body);
        if (!block) continue;
        if (/\brequire\s*\(|\brevert\b|\bif\s*\(/.test(fn.body.slice(0, block.index))) continue;
        const sub = fn.body.indexOf('-=', block.index);
        return lineAt(src, fn.bodyStart + sub);
    }
    return -1;
}
/** WEB3-05: a public mint/pause/treasury-withdraw/ownership function with no access modifier or sender check. */
function findUnguardedAdminFn(src: string): number {
    const ADMIN = /^(?:mint|safeMint|mintTo|pause|unpause|withdrawTreasury|withdrawAll|emergencyWithdraw|setOwner|setAdmin|transferOwnership|upgradeTo|upgradeToAndCall|setFeeRecipient|setOracle)$/;
    for (const fn of solFunctions(src)) {
        if (!ADMIN.test(fn.name) || !isExposed(fn) || isGuarded(fn)) continue;
        return lineAt(src, fn.headerStart);
    }
    return -1;
}
/** WEB3-06: raw ecrecover in a contract that has no nonce / chainId / EIP-712 domain / used-signature tracking. */
function findReplayableEcrecover(src: string): number {
    if (!/\bcontract\s+\w+/.test(src)) return -1; // signature libraries (ECDSA.sol) are not where replay protection lives
    if (/nonce|chainid|block\.chainid|EIP712|_hashTypedData|usedSignatures|\bused\w*\s*\[|claimed\s*\[|deadline|expir/i.test(src)) return -1;
    const m = /\becrecover\s*\(/.exec(src);
    return m ? lineAt(src, m.index) : -1;
}
/** WEB3-07: delegatecall to an address that the (unguarded, external) caller passes in. */
function findUserDelegatecall(src: string): number {
    for (const fn of solFunctions(src)) {
        if (!isExposed(fn) || isGuarded(fn)) continue;
        const params = [...fn.params.matchAll(/\baddress(?:\s+payable)?\s+(\w+)/g)].map((p) => p[1]);
        for (const p of params) {
            const m = new RegExp(`\\b${p}\\.delegatecall\\s*\\(`).exec(fn.body);
            if (m) return lineAt(src, fn.bodyStart + m.index);
        }
    }
    return -1;
}
/** WEB3-08: selfdestruct inside a function with no owner modifier or sender check. */
function findUnguardedSelfdestruct(src: string): number {
    for (const fn of solFunctions(src)) {
        const m = /\b(?:selfdestruct|suicide)\s*\(/.exec(fn.body);
        if (!m || isGuarded(fn)) continue;
        return lineAt(src, fn.bodyStart + m.index);
    }
    return -1;
}
/** WEB3-09: a hash of block.timestamp / difficulty / prevrandao reduced modulo N, i.e. used as a random number. */
function findTimestampRandomness(src: string): number {
    const re = /[^;{}]*\bkeccak256\s*\([^;]*\bblock\.(?:timestamp|difficulty|prevrandao)\b[^;]*%[^;]*;/g;
    const m = re.exec(src);
    if (!m) return -1;
    return lineAt(src, m.index + m[0].search(/keccak256/));
}
/** WEB3-10: an ERC-20 transfer/transferFrom used as a bare statement, its bool return value dropped. */
function findUncheckedErc20Transfer(src: string, lines: string[]): number {
    const typed = [...src.matchAll(/\bIERC20\w*\s+(?:(?:public|private|internal|immutable|constant)\s+)*(\w+)\s*[;=)]/g)].map((m) => m[1]);
    const receivers = ['IERC20\\w*\\s*\\([^)]*\\)', ...typed].join('|');
    const stmt = new RegExp(`^\\s*(?:${receivers})\\.transfer(?:From)?\\s*\\(`);
    return lines.findIndex((l) => stmt.test(l));
}
