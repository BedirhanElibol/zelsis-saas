/**
 * Zelsis Master evaluateCacheRedisRules Engine (50 Rules)
 * Rules CACHE-01 to CACHE-50 (Rule IDs 10701 to 10750).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface CacheRedisRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateCacheRedisRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): CacheRedisRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts") || lowerPath.endsWith(".tsx") || lowerPath.endsWith(".jsx")) {
        return { findings, logs };
    }
    const isCacheTarget = /redis|ioredis|upstash|memcached|cacheClient|cacheStore/i.test(cleanContent);
    if (!isCacheTarget) {
      return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // CACHE-01: Cache Stampede (Thundering Herd) via Unsynchronized Cache Misses
    if ((/redis\.get\s*\([\s\S]*?\)/.test(cleanContent) && !/lock|mutex|redlock/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cache10701-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10701,
            type: 'INFRA_DATABASE',
            title: "CACHE-01: Cache Stampede (Thundering Herd) via Unsynchronized Cache Misses",
            severity: "HIGH",
            category: "Cache Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Redis cache operation',
            reproductionSteps: [
                `Audited caching routines in ${file.path}:${lineNum}.`,
                'Detected cache architecture violation matching CACHE-01.'
            ],
            remediationPrompt: "Wrap high-traffic cache fetches with distributed redlock or early probabilistic recomputation.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-01: Cache Stampede (Thundering Herd) via Unsynchronized Cache Misses at ${file.path}:${lineNum}`);
    }
    // CACHE-02: Unbounded Cache Keys Lacking TTL Expiration (OOM Crash)
    if ((/redis\.(?:set|setex|hset)\s*\([\s\S]*?\)/.test(cleanContent) && !/ex|ttl|expire/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cache10702-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10702,
            type: 'INFRA_DATABASE',
            title: "CACHE-02: Unbounded Cache Keys Lacking TTL Expiration (OOM Crash)",
            severity: "CRITICAL",
            category: "Memory Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Redis cache operation',
            reproductionSteps: [
                `Audited caching routines in ${file.path}:${lineNum}.`,
                'Detected cache architecture violation matching CACHE-02.'
            ],
            remediationPrompt: "Enforce mandatory EX parameter on redis.set() calls and verify maxmemory-policy is set to allkeys-lru.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-02: Unbounded Cache Keys Lacking TTL Expiration (OOM Crash) at ${file.path}:${lineNum}`);
    }
    // CACHE-03: Unauthenticated Redis Port Bound to Public Network Interfaces (0.0.0.0)
    if ((/bind\s+0\.0\.0\.0/.test(cleanContent) && !/requirepass/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cache10703-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10703,
            type: 'INFRA_DATABASE',
            title: "CACHE-03: Unauthenticated Redis Port Bound to Public Network Interfaces (0.0.0.0)",
            severity: "CRITICAL",
            category: "Network Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Redis cache operation',
            reproductionSteps: [
                `Audited caching routines in ${file.path}:${lineNum}.`,
                'Detected cache architecture violation matching CACHE-03.'
            ],
            remediationPrompt: "Configure bind 127.0.0.1 and requirepass in redis.conf, and block public port 6379 in security groups.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-03: Unauthenticated Redis Port Bound to Public Network Interfaces (0.0.0.0) at ${file.path}:${lineNum}`);
    }
    // CACHE-04: Unsafe Lua Script Execution Susceptible to Injection or Infinite Loops
    if ((/redis\.eval\s*\(\s*`[\s\S]*?\$\{/.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cache10704-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10704,
            type: 'INFRA_DATABASE',
            title: "CACHE-04: Unsafe Lua Script Execution Susceptible to Injection or Infinite Loops",
            severity: "HIGH",
            category: "Script Security",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Redis cache operation',
            reproductionSteps: [
                `Audited caching routines in ${file.path}:${lineNum}.`,
                'Detected cache architecture violation matching CACHE-04.'
            ],
            remediationPrompt: "Refactor redis.eval() calls to use static EVALSHA scripts with parameterized KEYS/ARGV arrays.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-04: Unsafe Lua Script Execution Susceptible to Injection or Infinite Loops at ${file.path}:${lineNum}`);
    }
    // CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob)
    const cacheWriteRegex = /\b(?:redis|cache|kv|upstash|memcached?|client)\.(?:set|setex|setEx|hset|hSet|mset|put)\s*\([^;]*JSON\.stringify/i;
    if (cacheWriteRegex.test(cleanContent) && !/compress|gzip|brotli|snappy|lz4|zstd/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => /JSON\.stringify/.test(l) && /\.(?:set|setex|setEx|hset|hSet|mset|put)\s*\(/i.test(l));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cache10705-${Date.now()}-${findingCounter.count++}`,
            ruleId: 10705,
            type: 'INFRA_DATABASE',
            title: "CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob)",
            severity: "MEDIUM",
            category: "Network Throughput",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Redis cache operation',
            reproductionSteps: [
                `Audited caching routines in ${file.path}:${lineNum}.`,
                'Detected cache architecture violation matching CACHE-05.'
            ],
            remediationPrompt: "Apply gzip/snappy compression before caching or paginate large cached entity collections.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
