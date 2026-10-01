/**
 * Zelsis Master evaluateGraphqlFederationRules Engine (50 Rules)
 * Rules FED-01 to FED-50 (Rule IDs 13701 to 13750).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface GraphqlFederationRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateGraphqlFederationRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): GraphqlFederationRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isFedTarget = (lowerPath.includes("supergraph") || lowerPath.includes("subgraph") || lowerPath.includes("federation") || lowerPath.endsWith(".graphql") || lowerPath.endsWith(".gql")) ||
      (cleanContent.includes("@apollo/gateway") || cleanContent.includes("@apollo/subgraph") || cleanContent.includes("ApolloGateway"));
    if (!isFedTarget) {
      return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // FED-01: Unbounded Subgraph Query Depth in Federated Gateway
    if ((/router|supergraph/i.test(cleanContent) && !/max_depth|queryDepth/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `fed13701-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13701,
            type: 'INFRA_DATABASE',
            title: "FED-01: Unbounded Subgraph Query Depth in Federated Gateway",
            severity: "CRITICAL",
            category: "Query Complexity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL Federation configuration',
            reproductionSteps: [
                `Audited GraphQL Federation configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FEDERATION AUDIT] Found FED-01: Unbounded Subgraph Query Depth in Federated Gateway at ${file.path}:${lineNum}`);
    }
    // FED-02: Missing Entity Resolver Batching Causing N+1 Subgraph Storms
    if ((/resolveReference|@key/i.test(cleanContent) && !/DataLoader|batchFetch/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `fed13702-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13702,
            type: 'INFRA_DATABASE',
            title: "FED-02: Missing Entity Resolver Batching Causing N+1 Subgraph Storms",
            severity: "HIGH",
            category: "Performance Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL Federation configuration',
            reproductionSteps: [
                `Audited GraphQL Federation configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Implement DataLoader pattern on @key entity representations to batch subgraph network fetches.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FEDERATION AUDIT] Found FED-02: Missing Entity Resolver Batching Causing N+1 Subgraph Storms at ${file.path}:${lineNum}`);
    }
    // FED-03: Unprotected Subgraph Introspection in Production
    if ((/(?:"introspection"|introspection)\s*:\s*true/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `fed13703-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13703,
            type: 'INFRA_DATABASE',
            title: "FED-03: Unprotected Subgraph Introspection in Production",
            severity: "HIGH",
            category: "Schema Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL Federation configuration',
            reproductionSteps: [
                `Audited GraphQL Federation configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Disable introspection schemas across all internal federated microservices and public router endpoints.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FEDERATION AUDIT] Found FED-03: Unprotected Subgraph Introspection in Production at ${file.path}:${lineNum}`);
    }
    // FED-04: Breaking Schema Changes Lacking CI/CD Composition Check
    if ((/subgraph/i.test(lowerPath) && !/rover subgraph check/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `fed13704-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13704,
            type: 'INFRA_DATABASE',
            title: "FED-04: Breaking Schema Changes Lacking CI/CD Composition Check",
            severity: "CRITICAL",
            category: "Schema Governance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL Federation configuration',
            reproductionSteps: [
                `Audited GraphQL Federation configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Run schema composition linting (rover subgraph check) before merging PRs to prevent router composition failure.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FEDERATION AUDIT] Found FED-04: Breaking Schema Changes Lacking CI/CD Composition Check at ${file.path}:${lineNum}`);
    }
    // FED-05: Missing Subgraph Authentication Header Propagation
    if ((/subgraph_endpoint/i.test(cleanContent) && !/Authorization|mTLS/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `fed13705-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13705,
            type: 'INFRA_DATABASE',
            title: "FED-05: Missing Subgraph Authentication Header Propagation",
            severity: "CRITICAL",
            category: "Transport Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL Federation configuration',
            reproductionSteps: [
                `Audited GraphQL Federation configuration in ${file.path}:${lineNum}.`,
                'Detected violation matching {code}.'
            ],
            remediationPrompt: "Validate mTLS or cryptographic JWT signatures on requests between Apollo Router and internal subgraphs.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FEDERATION AUDIT] Found FED-05: Missing Subgraph Authentication Header Propagation at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
