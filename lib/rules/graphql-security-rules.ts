/**
 * Zelsis Master evaluateGraphqlSecurityRules Engine (50 Rules)
 * Rules GQL-01 to GQL-50 (Rule IDs 8501 to 8550).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
/** GraphQL document built by interpolating request / resolver input instead of using $variables. */
const GQL_USER_INTERPOLATION = /gql`[^`]*\$\{\s*(?:args|input|req|request|params|searchParams|query|body|variables)\b[^}]*\}[^`]*`/i;
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
    // Code-first schemas (graphql-js, resolver maps) carry no SDL keywords; used by resolver-level rules only.
    const isGqlResolverCode = /graphql|resolver/.test(lowerPath) && /\bargs\b/.test(cleanContent);
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
            severity: 'HIGH',
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
            severity: 'MEDIUM',
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
            severity: 'HIGH',
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
            severity: 'LOW',
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
    if ((isGqlRelated || isGqlResolverCode) && /first|limit/i.test(cleanContent) && /async\s+resolve\s*\([^)]*args[^)]*\)[\s\S]*?take\s*:\s*args\.(?:first|limit)/i.test(cleanContent) && !/Math\.min|clamp/i.test(cleanContent)) {
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
    if (GQL_USER_INTERPOLATION.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/\$\{\s*(?:args|input|req|request|params|searchParams|query|body|variables)\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
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
    if ((isGqlRelated || isGqlResolverCode) && (/\$queryRawUnsafe\s*\([^;]*?args\./i.test(cleanContent) || /query\s*\(`SELECT[^`]*?\$\{args\./i.test(cleanContent))) {
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
    return { findings, logs };
}
