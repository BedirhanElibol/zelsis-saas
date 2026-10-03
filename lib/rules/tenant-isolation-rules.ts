/**
 * Zelsis Master evaluateTenantIsolationRules Engine (50 Rules)
 * Rules TENANT-01 to TENANT-50 (Rule IDs 9101 to 9150).
 * Removed as unsound (ids never reused): 9101 (whole-file absence of a tenant column), 9103 (wrong premise).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { AUTH_GUARD } from "./shared/stack-signals";
import { locateMatchLine } from './shared/locate';
export interface TenantIsolationRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateTenantIsolationRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): TenantIsolationRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // TENANT-02: Tenant Context Leaked Across Async Execution Store
    if (/^(?:export\s+)?let\s+(?:current(?:Tenant|TenantId|Org|OrgId|User|UserId)|tenantId|orgId)\b/m.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/^(?:export\s+)?let\s+(?:current(?:Tenant|TenantId|Org|OrgId|User|UserId)|tenantId|orgId)\b/], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tenant9102-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9102,
            type: 'SECURITY',
            title: "TENANT-02: Tenant Context Leaked Across Async Execution Store",
            severity: "HIGH",
            category: "Context Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Multi-tenant operation',
            reproductionSteps: [
                `Audited multi-tenant logic in ${file.path}:${lineNum}.`,
                'Detected tenant isolation violation matching TENANT-02.'
            ],
            remediationPrompt: "Use AsyncLocalStorage to scope tenant session data per async request execution chain.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TENANT AUDIT] Found TENANT-02: Tenant Context Leaked Across Async Execution Store at ${file.path}:${lineNum}`);
    }
    // TENANT-04: Tenant S3 Storage Prefix Path Traversal Leakage
    if (/(?:\.upload|PutObjectCommand|GetObjectCommand|DeleteObjectCommand)\s*\(\s*\{[^}]{0,400}?\bKey\s*:\s*(?:req\.(?:body|query|params)\.\w+|(?:body|params|query)\.(?:filename|key|path|name)\b|formData\.get\()/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/\bKey\s*:\s*(?:req\.(?:body|query|params)\.\w+|(?:body|params|query)\.(?:filename|key|path|name)\b|formData\.get\()/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tenant9104-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9104,
            type: 'SECURITY',
            title: "TENANT-04: Tenant S3 Storage Prefix Path Traversal Leakage",
            severity: "HIGH",
            category: "Storage Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Multi-tenant operation',
            reproductionSteps: [
                `Audited multi-tenant logic in ${file.path}:${lineNum}.`,
                'Detected tenant isolation violation matching TENANT-04.'
            ],
            remediationPrompt: "Prefix all S3 object keys with validated tenant UUID to enforce logical storage boundaries.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TENANT AUDIT] Found TENANT-04: Tenant S3 Storage Prefix Path Traversal Leakage at ${file.path}:${lineNum}`);
    }
    // TENANT-06: IDOR - a record loaded by a request-supplied id without scoping it to the caller.
    // Supabase service-role clients bypass RLS; ORMs (Prisma, Drizzle, Mongoose, Sequelize, TypeORM) never had it.
    const reqIdNames = new Set<string>();
    for (const m of cleanContent.matchAll(/(?:const|let)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:params|(?:req|request|ctx)\.(?:params|query))\b/g)) {
        m[1].split(',').map((x) => x.split(':').pop()!.split('=')[0].trim()).filter((x) => /^\w*id$/i.test(x)).forEach((x) => reqIdNames.add(x));
    }
    for (const m of cleanContent.matchAll(/(?:const|let)\s+(\w*id)\s*=\s*(?:(?:await\s+)?params\.\w+|searchParams\.get\([^)]*\)|(?:req|request|ctx)\.(?:params|query)\.\w+)/gi)) reqIdNames.add(m[1]);
    const boundIdNames = [...reqIdNames].filter((n) => /^\w+$/.test(n));
    const reqId = String.raw`(?:(?:\(await\s+params\)|params|(?:req|request|ctx)\.(?:params|query))\.\w*id\b|searchParams\.get\(\s*['"]\w*id['"]\s*\)` + (boundIdNames.length ? String.raw`|\b(?:` + boundIdNames.join('|') + String.raw`)\b` : '') + ')';
    const supabaseLookup = new RegExp(String.raw`\.eq\(\s*['"]id['"]\s*,\s*` + reqId, 'i');
    const ormLookup = new RegExp([
        String.raw`\.(?:findUnique|findUniqueOrThrow|findFirst|update|delete)\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*:\s*` + reqId,
        String.raw`\beq\(\s*\w+\.id\s*,\s*` + reqId,
        String.raw`\.(?:findById|findByIdAndUpdate|findByIdAndDelete|findByPk)\s*\(\s*` + reqId,
        String.raw`\.(?:findOne|findOneBy|findOneAndUpdate|findOneAndDelete)\s*\(\s*\{\s*(?:_id|id)\s*:\s*` + reqId
    ].join('|'), 'i');
    const usesServiceRole = /SUPABASE_SERVICE_ROLE_KEY|service_role|supabaseAdmin|adminClient/i.test(cleanContent);
    const scopesToOwner = /\b(?:user_?id|owner_?id|org(?:anization)?_?id|tenant_?id|team_?id|workspace_?id|account_?id|created_?by|author_?id)\b/i.test(cleanContent);
    const idLookupRegex = usesServiceRole && supabaseLookup.test(cleanContent) ? supabaseLookup : ormLookup;
    const isIdor = !scopesToOwner && (
        (usesServiceRole && supabaseLookup.test(cleanContent)) ||
        (ormLookup.test(cleanContent) && AUTH_GUARD.test(cleanContent))
    );
    if (isIdor) {
        const matchLineIdx = lines.findIndex(l => idLookupRegex.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `tenant9106-${Date.now()}-${findingCounter.count++}`,
            ruleId: 9106,
            type: 'SECURITY',
            title: "TENANT-06: IDOR - Record Loaded by Request ID Without Owner Scoping",
            severity: "CRITICAL",
            category: "Multi-Tenant Isolation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Lookup by request id',
            reproductionSteps: [
                `Audited data access in ${file.path}:${lineNum}.`,
                usesServiceRole ? 'A service-role client (bypasses row level security) loads a row by an id taken from the request without filtering by the caller, so anyone can read other users\' records by changing the id.' : 'The handler authenticates the caller but loads the record by a request-supplied id without filtering by owner/tenant, so any signed-in user can access other accounts\' records by changing the id.'
            ],
            remediationPrompt: `In ${file.path}, scope the lookup to the caller: add the owner/tenant to the filter (e.g. where: { id, userId: session.user.id }, .eq('user_id', user.id), { _id: id, owner: req.user.id }) or verify record.ownerId === caller before returning it. With Supabase, prefer the user-scoped client so RLS applies.`,
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [TENANT AUDIT] Found TENANT-06: IDOR lookup by request id at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
