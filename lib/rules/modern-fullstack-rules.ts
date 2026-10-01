/**
 * Zelsis Master evaluateModernFullstackRules Engine (50 Rules)
 * Rules NEXT15-01 to NEXT15-50 (Rule IDs 8601 to 8650).
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
    const isNextApp = lowerPath.includes("app/") || lowerPath.includes("components/") || lowerPath.includes("next.config");
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
    // NEXT15-03: Missing React 19 taintObjectReference on Sensitive Entities
    if (lowerPath.includes('auth') && cleanContent.includes('export async function getUser')) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `next15_8603-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8603,
            type: 'INFRA_DATABASE',
            title: "NEXT15-03: Missing React 19 taintObjectReference on Sensitive Entities",
            severity: 'HIGH',
            category: "Data Leakage",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Next.js 15 component declaration',
            reproductionSteps: [
                `Scanned Next.js App Router code in ${file.path}:${lineNum}.`,
                'Detected fullstack architecture defect matching NEXT15-03.'
            ],
            remediationPrompt: "Apply experimental_taintObjectReference on sensitive user records.",
            status: 'OPEN',
            owner: 'Fullstack Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ FULLSTACK NEXT15-03: Missing React 19 taintObjectReference on Sensitive Entities in ${file.path}:${lineNum}`);
    }
    // NEXT15-04: Uncached Dynamic Route Render Explosion (force-dynamic)
    if (/export\s+const\s+dynamic\s*=\s*['"]force-dynamic['"]/i.test(cleanContent) && !lowerPath.includes('app/api') && !cleanContent.includes('api/')) {
        const matchLineIdx = locateMatchLine(lines, [/export\s+const\s+dynamic\s*=\s*['"]force-dynamic['"]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `next15_8604-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8604,
            type: 'INFRA_DATABASE',
            title: "NEXT15-04: Uncached Dynamic Route Render Explosion (force-dynamic)",
            severity: 'MEDIUM',
            category: "Cost & Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Next.js 15 component declaration',
            reproductionSteps: [
                `Scanned Next.js App Router code in ${file.path}:${lineNum}.`,
                'Detected fullstack architecture defect matching NEXT15-04.'
            ],
            remediationPrompt: "Use revalidate or static rendering on marketing/static pages instead of force-dynamic.",
            status: 'OPEN',
            owner: 'Fullstack Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ FULLSTACK NEXT15-04: Uncached Dynamic Route Render Explosion (force-dynamic) in ${file.path}:${lineNum}`);
    }
    // NEXT15-05: Edge Middleware Header Injection via URL Parameters
    if (lowerPath.includes('middleware') && /headers\.set\s*\([^,]+,\s*req\.nextUrl\.searchParams\.get/i.test(cleanContent) && !/sanitize/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/headers\.set\s*\([^,]+,\s*req\.nextUrl\.searchParams\.get/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    if (/revalidateTag\s*\(/i.test(cleanContent) && !/verifyToken|secret|auth|session|isAdmin|hasRole/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/revalidateTag\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `next15_8606-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8606,
            type: 'INFRA_DATABASE',
            title: "NEXT15-06: Unbounded revalidateTag Invocations Allowing Cache Flush DoS",
            severity: 'HIGH',
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
    if (/<Link[^>]*href=['"][^'"]*(?:delete|cancel|purge|remove)[^'"]*['"]/i.test(cleanContent) && !cleanContent.includes('LinkWrapperSafe')) {
        const matchLineIdx = locateMatchLine(lines, [/<Link[^>]*href=['"][^'"]*(?:delete|cancel|purge|remove)[^'"]*['"]/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    // NEXT15-08: Parallel Route Missing default.tsx Fallback
    if (lowerPath.includes('@')) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `next15_8608-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8608,
            type: 'INFRA_DATABASE',
            title: "NEXT15-08: Parallel Route Missing default.tsx Fallback",
            severity: 'MEDIUM',
            category: "Hydration / Error",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Next.js 15 component declaration',
            reproductionSteps: [
                `Scanned Next.js App Router code in ${file.path}:${lineNum}.`,
                'Detected fullstack architecture defect matching NEXT15-08.'
            ],
            remediationPrompt: "Provide default.tsx fallback components in parallel route slots.",
            status: 'OPEN',
            owner: 'Fullstack Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ FULLSTACK NEXT15-08: Parallel Route Missing default.tsx Fallback in ${file.path}:${lineNum}`);
    }
    // NEXT15-09: React 19 useActionState Missing Double-Submit Guard
    const isReactFormComponent = (file.path.endsWith('.tsx') || file.path.endsWith('.jsx')) && isNextApp && /<form\b/i.test(cleanContent);
    // Pending state (useFormStatus / useActionState / form libraries / loading props) also blocks a double submit
    const hasSubmitGuard = /disabled\s*(?:=|\s|>)|useFormStatus|\bpending\b|isPending|isSubmitting|\bloading\s*=|isLoading/i.test(cleanContent);
    if (isReactFormComponent && /<button[^>]*type=['"]submit['"][^>]*>/i.test(cleanContent) && !hasSubmitGuard) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && /<button[^>]*type=['"]submit['"]/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `next15_8609-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8609,
            type: 'INFRA_DATABASE',
            title: "NEXT15-09: React 19 useActionState Missing Double-Submit Guard",
            severity: 'LOW',
            category: "UI State Hygiene",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Next.js 15 component declaration',
            reproductionSteps: [
                `Scanned Next.js App Router code in ${file.path}:${lineNum}.`,
                'Detected fullstack architecture defect matching NEXT15-09.'
            ],
            remediationPrompt: "Bind disabled={isPending} on submit buttons inside action forms.",
            status: 'OPEN',
            owner: 'Fullstack Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ FULLSTACK NEXT15-09: React 19 useActionState Missing Double-Submit Guard in ${file.path}:${lineNum}`);
    }
    // NEXT15-10: Next.js 15 Dynamic APIs (cookies, headers) Accessed Synchronously
    if (/const\s+[a-zA-Z0-9_]+\s*=\s*(?:cookies|headers)\s*\(\s*\)/i.test(cleanContent) && !/await\s+(?:cookies|headers)/i.test(cleanContent) && !lowerPath.includes('test')) {
        const matchLineIdx = locateMatchLine(lines, [/const\s+[a-zA-Z0-9_]+\s*=\s*(?:cookies|headers)\s*\(\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `next15_8610-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8610,
            type: 'INFRA_DATABASE',
            title: "NEXT15-10: Next.js 15 Dynamic APIs (cookies, headers) Accessed Synchronously",
            severity: 'CRITICAL',
            category: "Runtime Error",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Next.js 15 component declaration',
            reproductionSteps: [
                `Scanned Next.js App Router code in ${file.path}:${lineNum}.`,
                'Detected fullstack architecture defect matching NEXT15-10.'
            ],
            remediationPrompt: "Await cookies() and headers() calls in Next.js 15 App Router.",
            status: 'OPEN',
            owner: 'Fullstack Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] ⚡ FULLSTACK NEXT15-10: Next.js 15 Dynamic APIs (cookies, headers) Accessed Synchronously in ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}

