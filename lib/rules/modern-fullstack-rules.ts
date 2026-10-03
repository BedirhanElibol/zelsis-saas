/**
 * Zelsis Master evaluateModernFullstackRules Engine (50 Rules)
 * Rules NEXT15-01 to NEXT15-50 (Rule IDs 8601 to 8650).
 * Removed as unsound (ids never reused): 8604 8608 8609 8610 (config choice, path-only, absence, version-dependent).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface ModernFullstackRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateModernFullstackRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ModernFullstackRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // NEXT15-02: Client Component Props Exposing Server Secrets
    if (cleanContent.includes('use client') && /(?:rawDbUser|dbCredentials|serviceRoleKey|adminSecret)/i.test(cleanContent) && !lowerPath.includes('test') && !lowerPath.includes('mock')) {
        const matchLineIdx = locateMatchLine(lines, [/(?:rawDbUser|dbCredentials|serviceRoleKey|adminSecret)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `next15_8602-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8602,
            type: 'INFRA_DATABASE',
            title: "NEXT15-02: Client Component Props Exposing Server Secrets",
            severity: 'CRITICAL',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Next.js 15 component declaration',
            reproductionSteps: [
                `Scanned Next.js App Router code in ${file.path}:${lineNum}.`,
                'Detected fullstack architecture defect matching NEXT15-02.'
            ],
            remediationPrompt: "Do not pass private server models or keys into 'use client' component props.",
            status: 'OPEN',
            owner: 'Fullstack Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ FULLSTACK NEXT15-02: Client Component Props Exposing Server Secrets in ${file.path}:${lineNum}`);
    }
    // NEXT15-05: Edge Middleware Header Injection via URL Parameters
    if (lowerPath.includes('middleware') && /headers\.set\s*\(\s*["']x-[\w-]*(?:user|tenant|org|role|admin|auth|account)[\w-]*["']\s*,\s*(?:req|request)\.nextUrl\.searchParams\.get/i.test(cleanContent) && !/sanitize/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/headers\.set\s*\(\s*["']x-[\w-]*(?:user|tenant|org|role|admin|auth|account)[\w-]*["']\s*,\s*(?:req|request)\.nextUrl\.searchParams\.get/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `next15_8605-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8605,
            type: 'INFRA_DATABASE',
            title: "NEXT15-05: Edge Middleware Header Injection via URL Parameters",
            severity: 'HIGH',
            category: "Header Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Next.js 15 component declaration',
            reproductionSteps: [
                `Scanned Next.js App Router code in ${file.path}:${lineNum}.`,
                'Detected fullstack architecture defect matching NEXT15-05.'
            ],
            remediationPrompt: "Sanitize URL search parameters before reflecting them into HTTP response headers.",
            status: 'OPEN',
            owner: 'Fullstack Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ FULLSTACK NEXT15-05: Edge Middleware Header Injection via URL Parameters in ${file.path}:${lineNum}`);
    }
    // NEXT15-06: Unbounded revalidateTag Invocations Allowing Cache Flush DoS
    if (/(?:^|\/)app\/(?:.*\/)?route\.[jt]sx?$|(?:^|\/)pages\/api\//.test(lowerPath) && /revalidateTag\s*\(/i.test(cleanContent) && !/verifyToken|secret|auth|session|isAdmin|hasRole/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/revalidateTag\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `next15_8606-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8606,
            type: 'INFRA_DATABASE',
            title: "NEXT15-06: Unbounded revalidateTag Invocations Allowing Cache Flush DoS",
            severity: 'MEDIUM',
            category: "Cache Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Next.js 15 component declaration',
            reproductionSteps: [
                `Scanned Next.js App Router code in ${file.path}:${lineNum}.`,
                'Detected fullstack architecture defect matching NEXT15-06.'
            ],
            remediationPrompt: "Protect cache revalidation handlers behind secret bearer tokens.",
            status: 'OPEN',
            owner: 'Fullstack Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ FULLSTACK NEXT15-06: Unbounded revalidateTag Invocations Allowing Cache Flush DoS in ${file.path}:${lineNum}`);
    }
    // NEXT15-07: Mutating Server Action Triggered via Link Navigation (GET)
    if (/<Link\b[^>]*href=(?:\{\s*`|['"])\/api\/[^'"`]*(?:delete|cancel|purge|remove)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/<Link\b[^>]*href=(?:\{\s*`|['"])\/api\/[^'"`]*(?:delete|cancel|purge|remove)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `next15_8607-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8607,
            type: 'INFRA_DATABASE',
            title: "NEXT15-07: Mutating Server Action Triggered via Link Navigation (GET)",
            severity: 'HIGH',
            category: "CSRF / Replay",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Next.js 15 component declaration',
            reproductionSteps: [
                `Scanned Next.js App Router code in ${file.path}:${lineNum}.`,
                'Detected fullstack architecture defect matching NEXT15-07.'
            ],
            remediationPrompt: "Trigger mutating operations via form actions or POST buttons, never via GET links.",
            status: 'OPEN',
            owner: 'Fullstack Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ FULLSTACK NEXT15-07: Mutating Server Action Triggered via Link Navigation (GET) in ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}

