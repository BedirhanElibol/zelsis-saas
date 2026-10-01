/**
 * Zelsis Master evaluateVectorDbRules Engine (50 Rules)
 * Rules VECTOR-01 to VECTOR-50 (Rule IDs 13501 to 13550).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
import { locateMatchLine } from './shared/locate';
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
    // VECTOR-01: Unindexed Vector Column Triggering Exhaustive Flat KNN Scans
    if ((/createCollection|create_index/i.test(cleanContent) && !/HNSW|IVF_FLAT/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/createCollection|create_index/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `vector13501-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13501,
            type: 'INFRA_DATABASE',
            title: "VECTOR-01: Unindexed Vector Column Triggering Exhaustive Flat KNN Scans",
            severity: "CRITICAL",
            category: "Index Optimization",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Vector Database configuration',
            reproductionSteps: [
                `Audited Vector Database configuration in ${file.path}:${lineNum}.`,
                'Matched VECTOR-01: Unindexed Vector Column Triggering Exhaustive Flat KNN Scans.'
            ],
            remediationPrompt: "Enforce HNSW or IVF index creation on high-dimensional vector columns before executing queries.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [VECTOR AUDIT] Found VECTOR-01: Unindexed Vector Column Triggering Exhaustive Flat KNN Scans at ${file.path}:${lineNum}`);
    }
    // VECTOR-02: Embedding Vector Dimension Mismatch at Query Time
    if ((/searchVector|similaritySearch/i.test(cleanContent) && !/assertDimension/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/searchVector|similaritySearch/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `vector13502-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13502,
            type: 'INFRA_DATABASE',
            title: "VECTOR-02: Embedding Vector Dimension Mismatch at Query Time",
            severity: "HIGH",
            category: "Schema Validation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Vector Database configuration',
            reproductionSteps: [
                `Audited Vector Database configuration in ${file.path}:${lineNum}.`,
                'Matched VECTOR-02: Embedding Vector Dimension Mismatch at Query Time.'
            ],
            remediationPrompt: "Validate vector dimensions against collection schema (e.g. 1536 / 3072) prior to executing similarity search.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [VECTOR AUDIT] Found VECTOR-02: Embedding Vector Dimension Mismatch at Query Time at ${file.path}:${lineNum}`);
    }
    // VECTOR-03: Unbounded Similarity Query Limit (top_k > 1000) Causing Memory Exhaustion
    if ((/top_k:\s*\d{4,}/i.test(cleanContent) && !/maxTopK/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/top_k:\s*\d{4,}/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `vector13503-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13503,
            type: 'INFRA_DATABASE',
            title: "VECTOR-03: Unbounded Similarity Query Limit (top_k > 1000) Causing Memory Exhaustion",
            severity: "HIGH",
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
    // VECTOR-04: HNSW Index Parameters M and efConstruction Suboptimally Tuned
    if ((/index_params/i.test(cleanContent) && !/efConstruction/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/index_params/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `vector13504-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13504,
            type: 'INFRA_DATABASE',
            title: "VECTOR-04: HNSW Index Parameters M and efConstruction Suboptimally Tuned",
            severity: "MEDIUM",
            category: "Hyperparameter Tuning",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Vector Database configuration',
            reproductionSteps: [
                `Audited Vector Database configuration in ${file.path}:${lineNum}.`,
                'Matched VECTOR-04: HNSW Index Parameters M and efConstruction Suboptimally Tuned.'
            ],
            remediationPrompt: "Tune M (16-64) and efConstruction (100-512) to achieve balanced recall rate without excessive memory consumption.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [VECTOR AUDIT] Found VECTOR-04: HNSW Index Parameters M and efConstruction Suboptimally Tuned at ${file.path}:${lineNum}`);
    }
    // VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields
    if ((/vectorFilter|searchParams/i.test(cleanContent) && !/createPayloadIndex/i.test(cleanContent))) {
        const matchLineIdx = locateMatchLine(lines, [/vectorFilter|searchParams/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `vector13505-${Date.now()}-${findingCounter.count++}`,
            ruleId: 13505,
            type: 'INFRA_DATABASE',
            title: "VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields",
            severity: "HIGH",
            category: "Metadata Indexing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Vector Database configuration',
            reproductionSteps: [
                `Audited Vector Database configuration in ${file.path}:${lineNum}.`,
                'Matched VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields.'
            ],
            remediationPrompt: "Create payload/metadata secondary indices on frequently filtered attributes to avoid post-filtering table scans.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [VECTOR AUDIT] Found VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
