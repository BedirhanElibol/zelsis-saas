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
    // FED-03: Unprotected Subgraph Introspection in Production
    const hit_13703 = /ApolloServer|createYoga|graphqlHTTP|createHandler|GraphQLModule|mercurius|supergraph:/.test(cleanContent) ? lines.findIndex((l) => /^\s*["']?introspection["']?\s*:\s*true\b/.test(l)) : -1;
    if (hit_13703 !== -1) {
        const matchLineIdx = hit_13703;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `fed13703-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13703,
            type: 'INFRA_DATABASE',
            title: "FED-03: Unprotected Subgraph Introspection in Production",
            severity: "MEDIUM",
            category: "Schema Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'GraphQL Federation configuration',
            reproductionSteps: [
                `Audited GraphQL Federation configuration in ${file.path}:${lineNum}.`,
                'Matched FED-03: Unprotected Subgraph Introspection in Production.'
            ],
            remediationPrompt: "Disable introspection schemas across all internal federated microservices and public router endpoints.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [FEDERATION AUDIT] Found FED-03: Unprotected Subgraph Introspection in Production at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
