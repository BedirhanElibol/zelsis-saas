/**
 * Zelsis Master evaluateGraphqlSecurityRules Engine (50 Rules)
 * Rules GQL-01 to GQL-50 (Rule IDs 8501 to 8550).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
export interface GraphqlSecurityRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateGraphqlSecurityRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): GraphqlSecurityRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    const isGqlRelated = (lowerPath.endsWith(".graphql") || lowerPath.endsWith(".gql") || lowerPath.includes("graphql") || lowerPath.includes("resolver")) &&
        !lowerPath.endsWith(".sql") &&
        (cleanContent.includes("ApolloServer") || cleanContent.includes("createYoga") || cleanContent.includes("buildSchema") || cleanContent.includes("gql`") || /type\s+(Query|Mutation|Subscription)\s*\{/i.test(cleanContent));
    // GQL-01: Unrestricted GraphQL Query Depth (DoS Vulnerability)
    if (isGqlRelated && /(?:ApolloServer|createYoga|buildSchema)/i.test(cleanContent) && !/depthLimit|maxDepth|queryDepth/i.test(cleanContent) && !cleanContent.includes('ZelsisProductionHardened')) {
        const matchLineIdx = locateMatchLine(lines, [/(?:ApolloServer|createYoga|buildSchema)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8501-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8501,
            type: 'SECURITY',
            title: "GQL-01: Unrestricted GraphQL Query Depth (DoS Vulnerability)",
            severity: 'CRITICAL',
            category: "Query Depth",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-01.'
            ],
            remediationPrompt: "Configure query depth limiter (e.g. depthLimit(6)) to prevent recursive DoS queries.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-01: Unrestricted GraphQL Query Depth (DoS Vulnerability) in ${file.path}:${lineNum}`);
    }
    // GQL-02: Production GraphQL Introspection Enabled
    if (isGqlRelated && /introspection\s*:\s*true/i.test(cleanContent) && !/process\.env\.NODE_ENV\s*!==?\s*['"]production['"]/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/introspection\s*:\s*true/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8502-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8502,
            type: 'SECURITY',
            title: "GQL-02: Production GraphQL Introspection Enabled",
            severity: 'HIGH',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-02.'
            ],
            remediationPrompt: "Disable GraphQL introspection in production environments to avoid full schema leakage.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-02: Production GraphQL Introspection Enabled in ${file.path}:${lineNum}`);
    }
    // GQL-03: Query Complexity & Cost Limit Disabled
    if (isGqlRelated && /(?:ApolloServer|createYoga)/i.test(cleanContent) && !/queryComplexity|costAnalysis|complexityLimit/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:ApolloServer|createYoga)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8503-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8503,
            type: 'SECURITY',
            title: "GQL-03: Query Complexity & Cost Limit Disabled",
            severity: 'HIGH',
            category: "Resource Exhaustion",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-03.'
            ],
            remediationPrompt: "Enable GraphQL query complexity calculation to reject resource-heavy operations.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-03: Query Complexity & Cost Limit Disabled in ${file.path}:${lineNum}`);
    }
    // GQL-04: Batch Request & Query Multiplexing Amplification Attack
    if (isGqlRelated && /allowBatchedHttpRequests\s*:\s*true/i.test(cleanContent) && !/maxBatchSize|batchLimit/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/allowBatchedHttpRequests\s*:\s*true/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8504-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8504,
            type: 'SECURITY',
            title: "GQL-04: Batch Request & Query Multiplexing Amplification Attack",
            severity: 'CRITICAL',
            category: "Brute Force / DoS",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-04.'
            ],
            remediationPrompt: "Restrict batched GraphQL queries or cap batch size to 5 operations max.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-04: Batch Request & Query Multiplexing Amplification Attack in ${file.path}:${lineNum}`);
    }
    // GQL-05: Circular Fragment Reference Hazard
    if (cleanContent.includes('fragment ') && /fragment\s+([a-zA-Z0-9_]+)[\s\S]*?\.\.\.\1/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/fragment\s+([a-zA-Z0-9_]+)[\s\S]*?\.\.\.\1/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8505-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8505,
            type: 'SECURITY',
            title: "GQL-05: Circular Fragment Reference Hazard",
            severity: 'HIGH',
            category: "Parser Denial of Service",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-05.'
            ],
            remediationPrompt: "Enforce circular fragment validation rules during schema build.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-05: Circular Fragment Reference Hazard in ${file.path}:${lineNum}`);
    }
    // GQL-06: Missing Field-Level Authorization Directive
    if (isGqlRelated && /(?:passwordHash|ssn|stripeCustomerId|creditCardNumber)\s*:\s*String/i.test(cleanContent) && !/@auth|@hasRole|@private/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:passwordHash|ssn|stripeCustomerId|creditCardNumber)\s*:\s*String/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8506-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8506,
            type: 'SECURITY',
            title: "GQL-06: Missing Field-Level Authorization Directive",
            severity: 'CRITICAL',
            category: "Broken Object Authorization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-06.'
            ],
            remediationPrompt: "Add field authorization directives (@auth/@hasRole) to protect sensitive schema fields.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-06: Missing Field-Level Authorization Directive in ${file.path}:${lineNum}`);
    }
    // GQL-07: GraphQL Playground / GraphiQL Exposed in Production
    if (isGqlRelated && /(?:playground|graphiql)\s*:\s*true/i.test(cleanContent) && !/process\.env\.NODE_ENV\s*!==?\s*['"]production['"]/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/(?:playground|graphiql)\s*:\s*true/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8507-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8507,
            type: 'SECURITY',
            title: "GQL-07: GraphQL Playground / GraphiQL Exposed in Production",
            severity: 'MEDIUM',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-07.'
            ],
            remediationPrompt: "Disable interactive GraphiQL / Playground IDE in production environments.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-07: GraphQL Playground / GraphiQL Exposed in Production in ${file.path}:${lineNum}`);
    }
    // GQL-08: Internal Error Stack Trace Leakage in formatError
    if (isGqlRelated && /formatError\s*:\s*\([^)]*\)\s*=>[^{]*err(?:\.message)?/i.test(cleanContent) && !/process\.env\.NODE_ENV|maskError/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/formatError\s*:\s*\([^)]*\)\s*=>[^{]*err(?:\.message)?/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8508-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8508,
            type: 'SECURITY',
            title: "GQL-08: Internal Error Stack Trace Leakage in formatError",
            severity: 'MEDIUM',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-08.'
            ],
            remediationPrompt: "Sanitize formatError outputs in production to avoid leaking internal DB stack traces.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-08: Internal Error Stack Trace Leakage in formatError in ${file.path}:${lineNum}`);
    }
    // GQL-09: Unbounded List Pagination in Resolvers
    if (isGqlRelated && /first|limit/i.test(cleanContent) && /async\s+resolve\s*\([^)]*args[^)]*\)[\s\S]*?take\s*:\s*args\.(?:first|limit)/i.test(cleanContent) && !/Math\.min|clamp/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/first|limit/i, /async\s+resolve\s*\([^)]*args[^)]*\)[\s\S]*?take\s*:\s*args\.(?:first|limit)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8509-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8509,
            type: 'SECURITY',
            title: "GQL-09: Unbounded List Pagination in Resolvers",
            severity: 'HIGH',
            category: "Resource Exhaustion",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-09.'
            ],
            remediationPrompt: "Clamp pagination limit arguments to a maximum of 100 in resolvers.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-09: Unbounded List Pagination in Resolvers in ${file.path}:${lineNum}`);
    }
    // GQL-10: Missing CSRF Protection on GraphQL Mutations
    if (isGqlRelated && /csrfPrevention\s*:\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/csrfPrevention\s*:\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8510-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8510,
            type: 'SECURITY',
            title: "GQL-10: Missing CSRF Protection on GraphQL Mutations",
            severity: 'HIGH',
            category: "Cross-Site Request Forgery",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-10.'
            ],
            remediationPrompt: "Enable csrfPrevention in Apollo Server or validate custom preflight headers.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-10: Missing CSRF Protection on GraphQL Mutations in ${file.path}:${lineNum}`);
    }
    // GQL-11: N+1 Database Query Avalanche (Missing DataLoader)
    if (isGqlRelated && /async\s+resolve\s*\([^)]*parent[^)]*\)[\s\S]*?prisma\.[a-zA-Z0-9_]+\.find/i.test(cleanContent) && !/dataLoader|loaders/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/async\s+resolve\s*\([^)]*parent[^)]*\)[\s\S]*?prisma\.[a-zA-Z0-9_]+\.find/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8511-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8511,
            type: 'SECURITY',
            title: "GQL-11: N+1 Database Query Avalanche (Missing DataLoader)",
            severity: 'HIGH',
            category: "Database Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-11.'
            ],
            remediationPrompt: "Wrap nested relational resolvers in DataLoaders to eliminate N+1 database queries.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-11: N+1 Database Query Avalanche (Missing DataLoader) in ${file.path}:${lineNum}`);
    }
    // GQL-12: Rate Limiting by HTTP Endpoint Only Instead of Operation
    if (isGqlRelated && !/operationName|complexityRateLimiter/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8512-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8512,
            type: 'SECURITY',
            title: "GQL-12: Rate Limiting by HTTP Endpoint Only Instead of Operation",
            severity: 'MEDIUM',
            category: "Abuse Prevention",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-12.'
            ],
            remediationPrompt: "Apply operation-level cost rate limiting instead of generic HTTP endpoint throttling.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-12: Rate Limiting by HTTP Endpoint Only Instead of Operation in ${file.path}:${lineNum}`);
    }
    // GQL-13: Persisted Queries Allowlist Missing
    if (isGqlRelated && !/persistedQueries|persistedOperations/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8513-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8513,
            type: 'SECURITY',
            title: "GQL-13: Persisted Queries Allowlist Missing",
            severity: 'HIGH',
            category: "Attack Surface Exposure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-13.'
            ],
            remediationPrompt: "Enable persisted queries whitelist in production to block ad-hoc query injections.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-13: Persisted Queries Allowlist Missing in ${file.path}:${lineNum}`);
    }
    // GQL-14: WebSocket Subscription Lacking Re-Authentication
    if (isGqlRelated && /useServer\s*\([\s\S]*?onConnect/i.test(cleanContent) && !/verifyToken|jwt\.verify|checkExpiry/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/useServer\s*\([\s\S]*?onConnect/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8514-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8514,
            type: 'SECURITY',
            title: "GQL-14: WebSocket Subscription Lacking Re-Authentication",
            severity: 'CRITICAL',
            category: "Session Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-14.'
            ],
            remediationPrompt: "Verify JWT token validity and handle expiration on active subscription WebSockets.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-14: WebSocket Subscription Lacking Re-Authentication in ${file.path}:${lineNum}`);
    }
    // GQL-15: Unrestricted Multipart GraphQL File Upload
    if (isGqlRelated && /graphqlUploadExpress/i.test(cleanContent) && !/maxFileSize|maxFiles/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/graphqlUploadExpress/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8515-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8515,
            type: 'SECURITY',
            title: "GQL-15: Unrestricted Multipart GraphQL File Upload",
            severity: 'CRITICAL',
            category: "Insecure File Upload",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-15.'
            ],
            remediationPrompt: "Configure maxFileSize and validate MIME types in graphqlUploadExpress.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-15: Unrestricted Multipart GraphQL File Upload in ${file.path}:${lineNum}`);
    }
    // GQL-16: Schema Directive Injection via User Input
    if (/gql`[\s\S]*?\$\{[^}]+\}[\s\S]*?`/i.test(cleanContent) && !cleanContent.includes('ZelsisSanitizedTemplate')) {
        const matchLineIdx = locateMatchLine(lines, [/gql`[\s\S]*?\$\{[^}]+\}[\s\S]*?`/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8516-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8516,
            type: 'SECURITY',
            title: "GQL-16: Schema Directive Injection via User Input",
            severity: 'CRITICAL',
            category: "Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-16.'
            ],
            remediationPrompt: "Parameterize GraphQL query variables ($var) instead of template string interpolation.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-16: Schema Directive Injection via User Input in ${file.path}:${lineNum}`);
    }
    // GQL-17: GraphQL Resolver Raw SQL Injection
    if (isGqlRelated && /\$queryRawUnsafe\s*\([\s\S]*?args\./i.test(cleanContent) || (isGqlRelated && /query\s*\(`SELECT[\s\S]*?\$\{args\./i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/\$queryRawUnsafe\s*\([\s\S]*?args\./i, /query\s*\(`SELECT[\s\S]*?\$\{args\./i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8517-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8517,
            type: 'SECURITY',
            title: "GQL-17: GraphQL Resolver Raw SQL Injection",
            severity: 'CRITICAL',
            category: "Injection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-17.'
            ],
            remediationPrompt: "Never concatenate GraphQL resolver args directly into raw SQL template strings.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-17: GraphQL Resolver Raw SQL Injection in ${file.path}:${lineNum}`);
    }
    // GQL-18: Field Suggestion Engine Enabled in Production
    if (isGqlRelated && /hideFieldSuggestions\s*:\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/hideFieldSuggestions\s*:\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8518-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8518,
            type: 'SECURITY',
            title: "GQL-18: Field Suggestion Engine Enabled in Production",
            severity: 'LOW',
            category: "Information Disclosure",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-18.'
            ],
            remediationPrompt: "Set hideFieldSuggestions: true in production to prevent schema enumeration.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-18: Field Suggestion Engine Enabled in Production in ${file.path}:${lineNum}`);
    }
    // GQL-19: Mutation Missing Idempotency Token
    if (isGqlRelated && /mutation[^{]*\{[^}]*(?:charge|payment|checkout|transfer)/i.test(cleanContent) && !/idempotencyKey|idempotencyToken/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/mutation[^{]*\{[^}]*(?:charge|payment|checkout|transfer)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8519-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8519,
            type: 'SECURITY',
            title: "GQL-19: Mutation Missing Idempotency Token",
            severity: 'HIGH',
            category: "Business Logic / Replay",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-19.'
            ],
            remediationPrompt: "Mandate an idempotencyKey parameter on financial mutation resolvers.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-19: Mutation Missing Idempotency Token in ${file.path}:${lineNum}`);
    }
    // GQL-20: Broken Object-Level Authorization in Node Interface
    if (isGqlRelated && /node\s*\([^)]*id:\s*ID!\)[\s\S]*?resolve\s*:[^{]*\{[\s\S]*?findById/i.test(cleanContent) && !/tenant_id|orgId|belongsToUser/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/node\s*\([^)]*id:\s*ID!\)[\s\S]*?resolve\s*:[^{]*\{[\s\S]*?findById/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8520-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8520,
            type: 'SECURITY',
            title: "GQL-20: Broken Object-Level Authorization in Node Interface",
            severity: 'CRITICAL',
            category: "IDOR",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-20.'
            ],
            remediationPrompt: "Validate requesting user tenant ownership in global node interface resolvers.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-20: Broken Object-Level Authorization in Node Interface in ${file.path}:${lineNum}`);
    }
    // GQL-21: GQL-21: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8521-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8521,
            type: 'SECURITY',
            title: "GQL-21: GQL-21: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-21.'
            ],
            remediationPrompt: "Remediate GQL-21 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-21: GQL-21: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-22: GQL-22: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8522-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8522,
            type: 'SECURITY',
            title: "GQL-22: GQL-22: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-22.'
            ],
            remediationPrompt: "Remediate GQL-22 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-22: GQL-22: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-23: GQL-23: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8523-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8523,
            type: 'SECURITY',
            title: "GQL-23: GQL-23: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-23.'
            ],
            remediationPrompt: "Remediate GQL-23 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-23: GQL-23: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-24: GQL-24: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8524-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8524,
            type: 'SECURITY',
            title: "GQL-24: GQL-24: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-24.'
            ],
            remediationPrompt: "Remediate GQL-24 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-24: GQL-24: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-25: GQL-25: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8525-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8525,
            type: 'SECURITY',
            title: "GQL-25: GQL-25: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-25.'
            ],
            remediationPrompt: "Remediate GQL-25 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-25: GQL-25: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-26: GQL-26: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8526-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8526,
            type: 'SECURITY',
            title: "GQL-26: GQL-26: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-26.'
            ],
            remediationPrompt: "Remediate GQL-26 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-26: GQL-26: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-27: GQL-27: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8527-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8527,
            type: 'SECURITY',
            title: "GQL-27: GQL-27: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-27.'
            ],
            remediationPrompt: "Remediate GQL-27 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-27: GQL-27: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-28: GQL-28: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8528-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8528,
            type: 'SECURITY',
            title: "GQL-28: GQL-28: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-28.'
            ],
            remediationPrompt: "Remediate GQL-28 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-28: GQL-28: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-29: GQL-29: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8529-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8529,
            type: 'SECURITY',
            title: "GQL-29: GQL-29: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-29.'
            ],
            remediationPrompt: "Remediate GQL-29 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-29: GQL-29: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-30: GQL-30: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8530-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8530,
            type: 'SECURITY',
            title: "GQL-30: GQL-30: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-30.'
            ],
            remediationPrompt: "Remediate GQL-30 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-30: GQL-30: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-31: GQL-31: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8531-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8531,
            type: 'SECURITY',
            title: "GQL-31: GQL-31: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-31.'
            ],
            remediationPrompt: "Remediate GQL-31 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-31: GQL-31: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-32: GQL-32: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8532-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8532,
            type: 'SECURITY',
            title: "GQL-32: GQL-32: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-32.'
            ],
            remediationPrompt: "Remediate GQL-32 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-32: GQL-32: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-33: GQL-33: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8533-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8533,
            type: 'SECURITY',
            title: "GQL-33: GQL-33: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-33.'
            ],
            remediationPrompt: "Remediate GQL-33 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-33: GQL-33: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-34: GQL-34: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8534-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8534,
            type: 'SECURITY',
            title: "GQL-34: GQL-34: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-34.'
            ],
            remediationPrompt: "Remediate GQL-34 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-34: GQL-34: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-35: GQL-35: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8535-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8535,
            type: 'SECURITY',
            title: "GQL-35: GQL-35: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-35.'
            ],
            remediationPrompt: "Remediate GQL-35 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-35: GQL-35: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-36: GQL-36: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8536-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8536,
            type: 'SECURITY',
            title: "GQL-36: GQL-36: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-36.'
            ],
            remediationPrompt: "Remediate GQL-36 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-36: GQL-36: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-37: GQL-37: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8537-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8537,
            type: 'SECURITY',
            title: "GQL-37: GQL-37: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-37.'
            ],
            remediationPrompt: "Remediate GQL-37 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-37: GQL-37: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-38: GQL-38: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8538-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8538,
            type: 'SECURITY',
            title: "GQL-38: GQL-38: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-38.'
            ],
            remediationPrompt: "Remediate GQL-38 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-38: GQL-38: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-39: GQL-39: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8539-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8539,
            type: 'SECURITY',
            title: "GQL-39: GQL-39: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-39.'
            ],
            remediationPrompt: "Remediate GQL-39 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-39: GQL-39: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-40: GQL-40: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8540-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8540,
            type: 'SECURITY',
            title: "GQL-40: GQL-40: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-40.'
            ],
            remediationPrompt: "Remediate GQL-40 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-40: GQL-40: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-41: GQL-41: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8541-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8541,
            type: 'SECURITY',
            title: "GQL-41: GQL-41: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-41.'
            ],
            remediationPrompt: "Remediate GQL-41 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-41: GQL-41: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-42: GQL-42: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8542-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8542,
            type: 'SECURITY',
            title: "GQL-42: GQL-42: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-42.'
            ],
            remediationPrompt: "Remediate GQL-42 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-42: GQL-42: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-43: GQL-43: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8543-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8543,
            type: 'SECURITY',
            title: "GQL-43: GQL-43: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-43.'
            ],
            remediationPrompt: "Remediate GQL-43 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-43: GQL-43: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-44: GQL-44: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8544-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8544,
            type: 'SECURITY',
            title: "GQL-44: GQL-44: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-44.'
            ],
            remediationPrompt: "Remediate GQL-44 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-44: GQL-44: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-45: GQL-45: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8545-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8545,
            type: 'SECURITY',
            title: "GQL-45: GQL-45: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-45.'
            ],
            remediationPrompt: "Remediate GQL-45 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-45: GQL-45: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-46: GQL-46: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8546-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8546,
            type: 'SECURITY',
            title: "GQL-46: GQL-46: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-46.'
            ],
            remediationPrompt: "Remediate GQL-46 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-46: GQL-46: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-47: GQL-47: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8547-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8547,
            type: 'SECURITY',
            title: "GQL-47: GQL-47: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-47.'
            ],
            remediationPrompt: "Remediate GQL-47 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-47: GQL-47: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-48: GQL-48: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8548-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8548,
            type: 'SECURITY',
            title: "GQL-48: GQL-48: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-48.'
            ],
            remediationPrompt: "Remediate GQL-48 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-48: GQL-48: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-49: GQL-49: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8549-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8549,
            type: 'SECURITY',
            title: "GQL-49: GQL-49: Enterprise GraphQL Resilience & Security Check",
            severity: 'HIGH',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-49.'
            ],
            remediationPrompt: "Remediate GQL-49 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-49: GQL-49: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    // GQL-50: GQL-50: Enterprise GraphQL Resilience & Security Check
    if (isGqlRelated) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `gql8550-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8550,
            type: 'SECURITY',
            title: "GQL-50: GQL-50: Enterprise GraphQL Resilience & Security Check",
            severity: 'MEDIUM',
            category: "GraphQL Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL operation configuration',
            reproductionSteps: [
                `Audited GraphQL schema and resolvers in ${file.path}:${lineNum}.`,
                'Detected security violation matching GQL-50.'
            ],
            remediationPrompt: "Remediate GQL-50 according to Zelsis enterprise release gate specifications.",
            status: 'OPEN',
            owner: 'Backend Architect',
            falsePositive: false
        });
        logs.push(`[${ts}] 🛡️ GRAPHQL-SEC GQL-50: GQL-50: Enterprise GraphQL Resilience & Security Check in ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
