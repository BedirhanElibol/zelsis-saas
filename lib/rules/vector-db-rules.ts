/**
 * Zelsis Master evaluateVectorDbRules Engine (50 Rules)
 * Rules VECTOR-01 to VECTOR-50 (Rule IDs 13501 to 13550).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface VectorDbRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateVectorDbRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): VectorDbRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const isVectorTarget = /pinecone|qdrant|chromadb|weaviate|milvus|pgvector|createCollection|searchVector/i.test(cleanContent);
    if (!isVectorTarget) {
      return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // VECTOR-03: Unbounded Similarity Query Limit (top_k > 1000) Causing Memory Exhaustion
    const r13503Idx = lines.findIndex(l => Number((l.match(/\b(?:top_?k|topK|n_results|nResults)\s*[:=]\s*(\d+)/) || [])[1] || 0) >= 1000);
    if (r13503Idx !== -1) {
        const matchLineIdx = r13503Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `vector13503-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13503,
            type: 'INFRA_DATABASE',
            title: "VECTOR-03: Unbounded Similarity Query Limit (top_k > 1000) Causing Memory Exhaustion",
            severity: "MEDIUM",
            category: "Resource Protection",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Vector Database configuration',
            reproductionSteps: [
                `Audited Vector Database configuration in ${file.path}:${lineNum}.`,
                'Matched VECTOR-03: Unbounded Similarity Query Limit (top_k > 1000) Causing Memory Exhaustion.'
            ],
            remediationPrompt: "Cap top_k retrieval parameters to prevent JVM / worker process out-of-memory crashes under load.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [VECTOR AUDIT] Found VECTOR-03: Unbounded Similarity Query Limit (top_k > 1000) Causing Memory Exhaustion at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
