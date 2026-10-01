/**
 * Zelsis Master evaluateChaosResilienceRules Engine (48 Rules)
 * Rules CHAOS-01 to CHAOS-48 (Rule IDs 8401 to 8448).
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
import { locateMatchLine } from './shared/locate';
export interface ChaosResilienceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateChaosResilienceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ChaosResilienceRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes('node_modules/') || lowerPath.endsWith('.d.ts')) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // CHAOS-01: Downstream HTTP Fetch Missing Timeout Signal (AbortSignal)
    if (/fetch\s*\(\s*url\s*\)/i.test(cleanContent) && !/AbortSignal\.timeout|signal/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/fetch\s*\(\s*url\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos01-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8401,
            type: 'INFRA_DATABASE',
            title: "CHAOS-01: Downstream HTTP Fetch Missing Timeout Signal (AbortSignal)",
            severity: 'MEDIUM',
            category: "Network Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-01 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Downstream HTTP Fetch Missing Timeout Signal (AbortSignal): Invoking fetch(url) without AbortSignal.timeout() or signal parameter, causing unbounded worker thread hanging when downstream services stall."
            ],
            remediationPrompt: "Add signal: AbortSignal.timeout(8000) to all downstream fetch invocations to prevent hung connections.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-01 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-02: Unbounded Retry Loop Without Exponential Backoff and Jitter
    if (/while\s*\(\s*retries\s*<\s*maxRetries\s*\)[\s\S]*?await\s+sleep\s*\(\s*1000\s*\)/i.test(cleanContent) && !/Math\.random|backoff/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/while\s*\(\s*retries\s*<\s*maxRetries\s*\)[\s\S]*?await\s+sleep\s*\(\s*1000\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos02-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8402,
            type: 'INFRA_DATABASE',
            title: "CHAOS-02: Unbounded Retry Loop Without Exponential Backoff and Jitter",
            severity: 'HIGH',
            category: "Cascading Failures",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-02 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unbounded Retry Loop Without Exponential Backoff and Jitter: Retrying failed network requests in tight while loops or fixed interval sleep without randomized jitter, creating retry storms."
            ],
            remediationPrompt: "Implement exponential backoff with randomized jitter (delay = Math.random() * base * Math.pow(2, attempt)).",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-02 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-03: Missing Circuit Breaker Pattern on External Third-Party APIs
    if (/invokePaymentGatewayDirect/i.test(cleanContent) && !/circuitBreaker|breaker\.fire/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/invokePaymentGatewayDirect/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos03-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8403,
            type: 'INFRA_DATABASE',
            title: "CHAOS-03: Missing Circuit Breaker Pattern on External Third-Party APIs",
            severity: 'HIGH',
            category: "Fault Tolerance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-03 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Circuit Breaker Pattern on External Third-Party APIs: Invoking critical third-party dependencies (Stripe, AI APIs) synchronously on user paths without circuit breaker protections."
            ],
            remediationPrompt: "Wrap external API integrations in a circuit breaker to fail fast and trigger fallbacks during outages.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-03 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-04: Database Connection Pool Starvation (Missing Max Limit / Timeout)
    if (/new\s+Pool\s*\(\s*\{(?![^}]*max\s*:)/i.test(cleanContent) && !/test|mock|spec/i.test(lowerPath)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+Pool\s*\(\s*\{(?![^}]*max\s*:)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos04-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8404,
            type: 'INFRA_DATABASE',
            title: "CHAOS-04: Database Connection Pool Starvation (Missing Max Limit / Timeout)",
            severity: 'MEDIUM',
            category: "Database Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-04 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Database Connection Pool Starvation (Missing Max Limit / Timeout): Database connection pool configured without max connections limit or connection acquisition timeout."
            ],
            remediationPrompt: "Configure max: 20, idleTimeoutMillis: 30000, and connectionTimeoutMillis: 5000 in database pool settings.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-04 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-05: Missing Dead Letter Queue (DLQ) on Async Background Processing
    if (/new\s+Queue\s*\(\s*["\'][^"\']+["\']\s*,\s*\{(?![^}]*defaultJobOptions)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+Queue\s*\(\s*["\'][^"\']+["\']\s*,\s*\{(?![^}]*defaultJobOptions)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos05-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8405,
            type: 'INFRA_DATABASE',
            title: "CHAOS-05: Missing Dead Letter Queue (DLQ) on Async Background Processing",
            severity: 'HIGH',
            category: "Queue Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-05 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Dead Letter Queue (DLQ) on Async Background Processing: Asynchronous background workers processing messages without a Dead Letter Queue or poisoned pill message discard policy."
            ],
            remediationPrompt: "Configure attempts: 3 and backoff: { type: 'exponential' } with dead letter queue routing in queue options.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-05 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-06: Process Missing Graceful Shutdown Handlers (SIGTERM / SIGINT)
    if (/server\.listen\s*\(/i.test(cleanContent) && !/process\.on\s*\(\s*["\']SIGTERM["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/server\.listen\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos06-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8406,
            type: 'INFRA_DATABASE',
            title: "CHAOS-06: Process Missing Graceful Shutdown Handlers (SIGTERM / SIGINT)",
            severity: 'HIGH',
            category: "Lifecycle Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-06 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Process Missing Graceful Shutdown Handlers (SIGTERM / SIGINT): Node.js server omitting process.on('SIGTERM') handlers, terminating active in-flight requests abruptly on deployment."
            ],
            remediationPrompt: "Add process.on('SIGTERM', () => server.close(() => process.exit(0))) graceful shutdown logic.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-06 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-07: Health Check Endpoint Tightly Coupled to Slow Downstream Dependencies
    if (/app\/api\/healthz\/route\.(?:ts|js)$/i.test(file.path) && /await\s+db\.query\s*\(/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/await\s+db\.query\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos07-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8407,
            type: 'INFRA_DATABASE',
            title: "CHAOS-07: Health Check Endpoint Tightly Coupled to Slow Downstream Dependencies",
            severity: 'HIGH',
            category: "Probe Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-07 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Health Check Endpoint Tightly Coupled to Slow Downstream Dependencies: Liveness /healthz probe executing heavy SQL queries or downstream third-party pings, triggering cascaded pod crash loops."
            ],
            remediationPrompt: "Isolate shallow liveness (/healthz) from deep readiness (/readyz) checks to prevent restart cascades.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-07 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-08: Bulkhead Isolation Missing Between Critical and Background Tasks
    if (/generateHeavyPdfReportSync/i.test(cleanContent) && !/worker_threads|queue/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/generateHeavyPdfReportSync/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos08-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8408,
            type: 'INFRA_DATABASE',
            title: "CHAOS-08: Bulkhead Isolation Missing Between Critical and Background Tasks",
            severity: 'HIGH',
            category: "Bulkhead Pattern",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-08 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Bulkhead Isolation Missing Between Critical and Background Tasks: Running CPU-heavy batch report generation inside the primary HTTP request-handling thread pool."
            ],
            remediationPrompt: "Offload CPU-intensive background tasks to worker threads or asynchronous queue workers.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-08 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-09: DNS TTL Caching Misconfiguration Preventing Fast Failover
    if (/aws_route53_record\b/i.test(cleanContent) && /ttl\s*=\s*(?:86400|172800)\b/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_route53_record\b/i, /ttl\s*=\s*(?:86400|172800)\b/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos09-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8409,
            type: 'INFRA_DATABASE',
            title: "CHAOS-09: DNS TTL Caching Misconfiguration Preventing Fast Failover",
            severity: 'MEDIUM',
            category: "DNS Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-09 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected DNS TTL Caching Misconfiguration Preventing Fast Failover: Configuring high DNS TTL (>86400s / 24 hours) on mission-critical service hostnames, delaying failover DNS switching."
            ],
            remediationPrompt: "Lower DNS TTL on critical public endpoints to 300 seconds to facilitate rapid failover.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-09 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-10: Missing Fallback Cache on Transient External Service Failure
    if (/fetchExternalWeatherFeed/i.test(cleanContent) && !/getStaleCache|fallback/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/fetchExternalWeatherFeed/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos10-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8410,
            type: 'INFRA_DATABASE',
            title: "CHAOS-10: Missing Fallback Cache on Transient External Service Failure",
            severity: 'MEDIUM',
            category: "Graceful Degradation",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-10 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Fallback Cache on Transient External Service Failure: Displaying hard 500 error screens to users when non-critical third-party widgets (currency, weather, feeds) fail."
            ],
            remediationPrompt: "Serve stale cached data gracefully when non-critical external data feeds fail or time out.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-10 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-11: Unconstrained Thread Pool / Worker Concurrency in CPU-Bound Work
    if (/items\.map\s*\([\s\S]*?new\s+Worker\s*\(/i.test(cleanContent) && !/p-limit|pLimit|concurrency/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/items\.map\s*\([\s\S]*?new\s+Worker\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos11-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8411,
            type: 'INFRA_DATABASE',
            title: "CHAOS-11: Unconstrained Thread Pool / Worker Concurrency in CPU-Bound Work",
            severity: 'HIGH',
            category: "Concurrency Limits",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-11 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unconstrained Thread Pool / Worker Concurrency in CPU-Bound Work: Spawning unbounded worker threads or child processes per incoming request without concurrency semaphores."
            ],
            remediationPrompt: "Throttle concurrent worker thread execution using p-limit or worker pool managers.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-11 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-12: Missing Chaos Simulation Integration in Staging CI/CD
    if (/\.github\/workflows\/chaos\.ya?ml$/i.test(file.path)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/chaos-12|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos12-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8412,
            type: 'INFRA_DATABASE',
            title: "CHAOS-12: Missing Chaos Simulation Integration in Staging CI/CD",
            severity: 'MEDIUM',
            category: "Chaos Testing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-12 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Chaos Simulation Integration in Staging CI/CD: Shipping microservices without testing response to induced packet loss, latency, or container kills (Chaos Mesh / Gremlin)."
            ],
            remediationPrompt: "Incorporate automated chaos experiments (e.g. latency injection) into staging verification pipelines.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-12 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-13: Lack of Backpressure Handling in Streaming Data Pipelines
    if (/dest\.write\s*\(\s*chunk\s*\)/i.test(cleanContent) && !/pause|drain/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/dest\.write\s*\(\s*chunk\s*\)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos13-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8413,
            type: 'INFRA_DATABASE',
            title: "CHAOS-13: Lack of Backpressure Handling in Streaming Data Pipelines",
            severity: 'HIGH',
            category: "Stream Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-13 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Backpressure Handling in Streaming Data Pipelines: Writing fast upstream chunks to slow downstream network sockets without evaluating return value of stream.write()."
            ],
            remediationPrompt: "Handle backpressure by pausing stream consumption until the destination stream emits 'drain'.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-13 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-14: Missing Idempotency in Payment / Transaction Retries
    if (/app\/api\/checkout\/charge\/route\.(?:ts|js)$/i.test(file.path) && !/idempotency/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/chaos-14|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos14-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8414,
            type: 'INFRA_DATABASE',
            title: "CHAOS-14: Missing Idempotency in Payment / Transaction Retries",
            severity: 'CRITICAL',
            category: "Data Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-14 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Idempotency in Payment / Transaction Retries: Retrying failed payment or order creation requests without supplying unique Idempotency-Key headers."
            ],
            remediationPrompt: "Attach an Idempotency-Key header with a unique request UUID on all payment and order requests.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 CRITICAL: CHAOS-14 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-15: Cascading Failure via Synchronous Cross-Service Dependency Chains
    if (/orderServiceHandler/i.test(cleanContent) && !/queue|messageBus/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/orderServiceHandler/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos15-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8415,
            type: 'INFRA_DATABASE',
            title: "CHAOS-15: Cascading Failure via Synchronous Cross-Service Dependency Chains",
            severity: 'HIGH',
            category: "Distributed Architecture",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-15 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Cascading Failure via Synchronous Cross-Service Dependency Chains: A synchronous call from Service A -> B -> C -> D where a failure in D cascades upwards to collapse Service A."
            ],
            remediationPrompt: "Decouple synchronous inter-service chains using message queues or local read caches.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-15 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-16: Unbounded In-Memory Cache Growth (Missing LRU Eviction)
    if (/const\s+cache\s*:\s*Record<[^>]+>\s*=\s*\{\};/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/const\s+cache\s*:\s*Record<[^>]+>\s*=\s*\{\};/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos16-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8416,
            type: 'INFRA_DATABASE',
            title: "CHAOS-16: Unbounded In-Memory Cache Growth (Missing LRU Eviction)",
            severity: 'HIGH',
            category: "Memory Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-16 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unbounded In-Memory Cache Growth (Missing LRU Eviction): Storing cache entries in plain JavaScript objects (const cache = {}) without max item count or TTL eviction."
            ],
            remediationPrompt: "Replace plain object caches with lru-cache configured with a max items cap and TTL.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-16 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-17: Missing Jitter on Scheduled Cron Job Execution
    if (/cron\.schedule\s*\(\s*["\']0\s+0\s+\*\s+\*\s+\*["\']/i.test(cleanContent) && !/Math\.random/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/cron\.schedule\s*\(\s*["\']0\s+0\s+\*\s+\*\s+\*["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos17-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8417,
            type: 'INFRA_DATABASE',
            title: "CHAOS-17: Missing Jitter on Scheduled Cron Job Execution",
            severity: 'MEDIUM',
            category: "Thundering Herd",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-17 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Jitter on Scheduled Cron Job Execution: Scheduling all cron jobs to fire exactly at 00:00:00 UTC, causing massive database CPU spikes at midnight."
            ],
            remediationPrompt: "Add randomized runtime jitter (sleep 0-60s) before executing heavy scheduled cron jobs.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-17 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-18: Single Point of Failure (SPOF) Without Multi-AZ Redundancy
    if (/aws_db_instance\b/i.test(cleanContent) && /multi_az\s*=\s*false/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/aws_db_instance\b/i, /multi_az\s*=\s*false/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos18-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8418,
            type: 'INFRA_DATABASE',
            title: "CHAOS-18: Single Point of Failure (SPOF) Without Multi-AZ Redundancy",
            severity: 'CRITICAL',
            category: "High Availability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-18 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Single Point of Failure (SPOF) Without Multi-AZ Redundancy: Deploying core production databases or server clusters into a single AWS Availability Zone without read replicas."
            ],
            remediationPrompt: "Deploy databases and compute clusters across multi-AZ configurations with automated failover.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 CRITICAL: CHAOS-18 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-19: Missing Failure Recovery in WebSocket Disconnection Scenarios
    if (/ws\.onclose\s*=\s*\(\s*\)\s*=>\s*\{(?![^}]*setTimeout)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/ws\.onclose\s*=\s*\(\s*\)\s*=>\s*\{(?![^}]*setTimeout)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos19-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8419,
            type: 'INFRA_DATABASE',
            title: "CHAOS-19: Missing Failure Recovery in WebSocket Disconnection Scenarios",
            severity: 'MEDIUM',
            category: "Connection Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-19 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Failure Recovery in WebSocket Disconnection Scenarios: Client WebSocket code lacking automated reconnect logic with exponential backoff on unexpected socket drop."
            ],
            remediationPrompt: "Implement auto-reconnect with exponential backoff in client WebSocket event handlers.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-19 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-20: Uncaught Promise Rejections Terminating Node.js Process
    if (/mainServerEntry/i.test(cleanContent) && !/unhandledRejection/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/mainServerEntry/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos20-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8420,
            type: 'INFRA_DATABASE',
            title: "CHAOS-20: Uncaught Promise Rejections Terminating Node.js Process",
            severity: 'CRITICAL',
            category: "Process Stability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-20 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Uncaught Promise Rejections Terminating Node.js Process: Omission of process.on('unhandledRejection') and process.on('uncaughtException') safety handlers."
            ],
            remediationPrompt: "Register process.on('unhandledRejection') handlers to log errors safely without terminating the process.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 CRITICAL: CHAOS-20 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-21: Missing Fallback for Third-Party Font or Script Outages
    if (/@import\s+url\([^)]*fonts\.googleapis\.com[^)]*\);/i.test(cleanContent) && !/font-display/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/@import\s+url\([^)]*fonts\.googleapis\.com[^)]*\);/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos21-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8421,
            type: 'INFRA_DATABASE',
            title: "CHAOS-21: Missing Fallback for Third-Party Font or Script Outages",
            severity: 'LOW',
            category: "Frontend Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-21 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Fallback for Third-Party Font or Script Outages: Loading third-party fonts or analytics synchronously, blocking page render when the external CDN stalls."
            ],
            remediationPrompt: "Use font-display: swap and load third-party scripts asynchronously with defer.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 LOW: CHAOS-21 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-22: Lack of Database Read/Write Split Under High Load
    if (/new\s+Pool\s*\(\s*\{[\s\S]*?MASTER_DB_URL/i.test(cleanContent) && !/readPool|replica/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+Pool\s*\(\s*\{[\s\S]*?MASTER_DB_URL/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos22-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8422,
            type: 'INFRA_DATABASE',
            title: "CHAOS-22: Lack of Database Read/Write Split Under High Load",
            severity: 'HIGH',
            category: "Database Scalability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-22 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Database Read/Write Split Under High Load: Directing all read queries to primary database master, causing write lockouts during peak read traffic."
            ],
            remediationPrompt: "Direct read queries to dedicated read replicas to preserve primary database capacity for writes.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-22 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-23: Missing Rate Limit Shedding on Backend Worker Queues
    if (/new\s+Worker\s*\(\s*["\']api-tasks["\']\s*,\s*handler\s*,\s*\{(?![^}]*limiter:)/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/new\s+Worker\s*\(\s*["\']api-tasks["\']\s*,\s*handler\s*,\s*\{(?![^}]*limiter:)/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos23-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8423,
            type: 'INFRA_DATABASE',
            title: "CHAOS-23: Missing Rate Limit Shedding on Backend Worker Queues",
            severity: 'HIGH',
            category: "Load Shedding",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-23 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Rate Limit Shedding on Backend Worker Queues: Queue workers consuming jobs faster than downstream APIs allow, resulting in continuous 429 Too Many Requests."
            ],
            remediationPrompt: "Add rate-limiting constraints to queue worker definitions to match downstream rate limits.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-23 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-24: Insecure Memory Leak from Uncleaned Event Emitter Listeners
    if (/req\.on\s*\(\s*["\']data["\']/i.test(cleanContent) && !/removeListener|off/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/req\.on\s*\(\s*["\']data["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos24-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8424,
            type: 'INFRA_DATABASE',
            title: "CHAOS-24: Insecure Memory Leak from Uncleaned Event Emitter Listeners",
            severity: 'HIGH',
            category: "Memory Management",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-24 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Memory Leak from Uncleaned Event Emitter Listeners: Attaching event listeners inside request handlers without removing listeners on request finish or abort."
            ],
            remediationPrompt: "Clean up event listeners on request termination to prevent memory leaks.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-24 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-25: Missing Graceful Degradation on Search Engine Service Outage
    if (/executeProductSearch/i.test(cleanContent) && !/dbFallbackSearch|fallback/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/executeProductSearch/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos25-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8425,
            type: 'INFRA_DATABASE',
            title: "CHAOS-25: Missing Graceful Degradation on Search Engine Service Outage",
            severity: 'MEDIUM',
            category: "Search Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-25 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Graceful Degradation on Search Engine Service Outage: Crashing entire product listings when Algolia or Elasticsearch cluster experiences an outage."
            ],
            remediationPrompt: "Implement database full-text search fallback when external search services fail.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-25 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-26: Unmonitored Event Loop Delay Under CPU Spikes
    if (/telemetrySetup\.ts$/i.test(file.path) && !/monitorEventLoopDelay/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/chaos-26|unmonitored/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos26-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8426,
            type: 'INFRA_DATABASE',
            title: "CHAOS-26: Unmonitored Event Loop Delay Under CPU Spikes",
            severity: 'HIGH',
            category: "Observability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-26 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unmonitored Event Loop Delay Under CPU Spikes: Failing to measure and alert on Node.js event loop lag exceeding 100ms in production telemetry."
            ],
            remediationPrompt: "Monitor event loop latency with perf_hooks.monitorEventLoopDelay and alert on delays > 100ms.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-26 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-27: Missing Automated Canary Analysis in Deployment Rollouts
    if (/deploy\.yaml$/i.test(file.path) && !/canary|setWeight/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/chaos-27|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos27-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8427,
            type: 'INFRA_DATABASE',
            title: "CHAOS-27: Missing Automated Canary Analysis in Deployment Rollouts",
            severity: 'HIGH',
            category: "Release Engineering",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-27 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Automated Canary Analysis in Deployment Rollouts: Routing 100% of production traffic to new software versions immediately without progressive canary phases."
            ],
            remediationPrompt: "Adopt progressive canary deployments with automated rollback on error rate increases.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-27 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-28: Unconstrained Log Ingestion Flooding Disk / Logging Storage
    if (/logger\.ts$/i.test(file.path) && /level:\s*["\']debug["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/level:\s*["\']debug["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos28-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8428,
            type: 'INFRA_DATABASE',
            title: "CHAOS-28: Unconstrained Log Ingestion Flooding Disk / Logging Storage",
            severity: 'MEDIUM',
            category: "Resource Exhaustion",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-28 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unconstrained Log Ingestion Flooding Disk / Logging Storage: Logging verbose debug statements inside hot loop iterations, exhausting local disk storage or logging quotas."
            ],
            remediationPrompt: "Disable verbose debug logging in production and throttle repeated error log messages.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-28 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-29: Missing Health Check Grace Period on Container Startup
    if (/kind:\s*Pod\b/i.test(cleanContent) && /readinessProbe:\s*\{[^}]*initialDelaySeconds:\s*0/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/kind:\s*Pod\b/i, /readinessProbe:\s*\{[^}]*initialDelaySeconds:\s*0/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos29-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8429,
            type: 'INFRA_DATABASE',
            title: "CHAOS-29: Missing Health Check Grace Period on Container Startup",
            severity: 'MEDIUM',
            category: "Kubernetes Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-29 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Health Check Grace Period on Container Startup: Kubernetes readiness probe failing immediately because initialDelaySeconds is too short for app initialization."
            ],
            remediationPrompt: "Add initialDelaySeconds and a startupProbe to allow sufficient container initialization time.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-29 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-30: Lack of Automated Schema Drift Detection in Staging
    if (/\.github\/workflows\/deploy\.ya?ml$/i.test(file.path) && !/prisma migrate/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/chaos-30|lack/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos30-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8430,
            type: 'INFRA_DATABASE',
            title: "CHAOS-30: Lack of Automated Schema Drift Detection in Staging",
            severity: 'MEDIUM',
            category: "Database Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-30 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Automated Schema Drift Detection in Staging: Deploying application updates without asserting that target database schema matches Prisma/TypeORM definitions."
            ],
            remediationPrompt: "Run prisma migrate status or diff checks in deployment verification pipelines to catch schema drift.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-30 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-31: Unbounded Webhook Notification Queue Size
    if (/outboundWebhookQueue/i.test(cleanContent) && !/maxSize|capacity/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/outboundWebhookQueue/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos31-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8431,
            type: 'INFRA_DATABASE',
            title: "CHAOS-31: Unbounded Webhook Notification Queue Size",
            severity: 'HIGH',
            category: "Queue Reliability",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-31 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unbounded Webhook Notification Queue Size: Queueing millions of outbound webhook dispatches in Redis without memory caps or eviction policies."
            ],
            remediationPrompt: "Set maximum queue length limits on webhook dispatch buffers to prevent memory exhaustion.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-31 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-32: Missing Chaos Latency Injection Testing on Microservice Mesh
    if (/virtualservice.*\.ya?ml$/i.test(file.path) && !/fault:\s*\{[^}]*delay/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/chaos-32|missing/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos32-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8432,
            type: 'INFRA_DATABASE',
            title: "CHAOS-32: Missing Chaos Latency Injection Testing on Microservice Mesh",
            severity: 'MEDIUM',
            category: "Chaos Engineering",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-32 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Chaos Latency Injection Testing on Microservice Mesh: Failing to verify that frontend services gracefully handle 2000ms latency spikes from downstream services."
            ],
            remediationPrompt: "Simulate upstream latency in staging using service mesh fault injection to test UI loading states.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-32 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-33: Insecure Fast-Fail Bypass Causing Silent Data Corruption
    if (/catch\s*\(\s*dbWriteError\s*\)\s*\{[\s\S]*?return\s+\{\s*success:\s*true\s*\};/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/catch\s*\(\s*dbWriteError\s*\)\s*\{[\s\S]*?return\s+\{\s*success:\s*true\s*\};/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos33-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8433,
            type: 'INFRA_DATABASE',
            title: "CHAOS-33: Insecure Fast-Fail Bypass Causing Silent Data Corruption",
            severity: 'HIGH',
            category: "Error Handling",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-33 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Insecure Fast-Fail Bypass Causing Silent Data Corruption: Catching fatal database write errors and returning HTTP 200 with empty mock data, masking critical corruption."
            ],
            remediationPrompt: "Do not swallow fatal database write errors with silent fallbacks; propagate errors to trigger rollbacks.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-33 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-34: Missing Cross-Region Database Read Replica Failover
    if (/dbClusterInfrastructure/i.test(cleanContent) && !/replicate_source_db/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/dbClusterInfrastructure/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos34-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8434,
            type: 'INFRA_DATABASE',
            title: "CHAOS-34: Missing Cross-Region Database Read Replica Failover",
            severity: 'HIGH',
            category: "Disaster Recovery",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-34 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Cross-Region Database Read Replica Failover: Operating multi-region compute services relying strictly on a single regional database master without cross-region replica."
            ],
            remediationPrompt: "Configure cross-region database replicas to ensure continuity during major cloud region outages.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-34 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-35: Unbounded Event Listener Growth on Global Window Object
    if (/window\.addEventListener\s*\(\s*["\']resize["\']/i.test(cleanContent) && !/removeEventListener/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/window\.addEventListener\s*\(\s*["\']resize["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos35-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8435,
            type: 'INFRA_DATABASE',
            title: "CHAOS-35: Unbounded Event Listener Growth on Global Window Object",
            severity: 'HIGH',
            category: "Frontend Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-35 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unbounded Event Listener Growth on Global Window Object: Attaching window.addEventListener('resize') inside React components without removing listener in useEffect cleanup."
            ],
            remediationPrompt: "Always return a cleanup function in useEffect to remove window event listeners.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-35 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-36: Missing Heartbeat Mechanism in Distributed Lock Manager
    if (/redlock\.acquire\s*\(/i.test(cleanContent) && !/startAutoRenewal|heartbeat/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/redlock\.acquire\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos36-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8436,
            type: 'INFRA_DATABASE',
            title: "CHAOS-36: Missing Heartbeat Mechanism in Distributed Lock Manager",
            severity: 'HIGH',
            category: "Concurrency Control",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-36 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Heartbeat Mechanism in Distributed Lock Manager: Acquiring distributed locks with static TTLs without automated heartbeat renewal for long-running transactions."
            ],
            remediationPrompt: "Use an automated lock renewal heartbeat to prevent premature lock release during long tasks.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-36 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-37: Unmonitored File Descriptor Exhaustion in High-Volume APIs
    if (/highVolumeSocketServer/i.test(cleanContent) && !/getFdCount|maxFiles/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/highVolumeSocketServer/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos37-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8437,
            type: 'INFRA_DATABASE',
            title: "CHAOS-37: Unmonitored File Descriptor Exhaustion in High-Volume APIs",
            severity: 'HIGH',
            category: "OS Resources",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-37 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unmonitored File Descriptor Exhaustion in High-Volume APIs: Opening network sockets and file handles without checking process file descriptor limits, causing EMFILE errors."
            ],
            remediationPrompt: "Monitor active file descriptors and raise process ulimit to prevent EMFILE crashes.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-37 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-38: Missing Backoff on Database Connection Reconnection
    if (/client\.on\s*\(\s*["\']error["\']\s*,\s*\(\s*\)\s*=>\s*\{[\s\S]*?client\.connect\s*\(\s*\);/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/client\.on\s*\(\s*["\']error["\']\s*,\s*\(\s*\)\s*=>\s*\{[\s\S]*?client\.connect\s*\(\s*\);/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos38-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8438,
            type: 'INFRA_DATABASE',
            title: "CHAOS-38: Missing Backoff on Database Connection Reconnection",
            severity: 'HIGH',
            category: "Database Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-38 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Backoff on Database Connection Reconnection: Reconnecting to database immediately in a tight loop when connection drops, overloading recovering database server."
            ],
            remediationPrompt: "Apply exponential backoff when reconnecting to a dropped database server.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-38 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-39: Lack of Client-Side Cache Busting on Critical Static Assets
    if (/webpackConfig/i.test(cleanContent) && /filename:\s*["\']\[name\]\.js["\']/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/webpackConfig/i, /filename:\s*["\']\[name\]\.js["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos39-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8439,
            type: 'INFRA_DATABASE',
            title: "CHAOS-39: Lack of Client-Side Cache Busting on Critical Static Assets",
            severity: 'LOW',
            category: "Frontend Deployment",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-39 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Client-Side Cache Busting on Critical Static Assets: Serving updated JavaScript bundles with stale Cache-Control headers without content-hash filenames."
            ],
            remediationPrompt: "Use content-hash filenames for all bundled assets to prevent stale script caching after deployments.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 LOW: CHAOS-39 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-40: Missing Downstream HTTP Response Size Limit
    if (/fetchExternalBlob/i.test(cleanContent) && !/content-length|maxSize/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/fetchExternalBlob/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos40-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8440,
            type: 'INFRA_DATABASE',
            title: "CHAOS-40: Missing Downstream HTTP Response Size Limit",
            severity: 'MEDIUM',
            category: "DoS Prevention",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-40 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Downstream HTTP Response Size Limit: Reading entire external HTTP response body into memory without maximum content-length boundaries."
            ],
            remediationPrompt: "Enforce maximum payload size limits when fetching external HTTP resources.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-40 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-41: Lack of Isolated Rollback Test in Pre-Deployment Verifications
    if (/\.github\/workflows\/db-test\.ya?ml$/i.test(file.path) && !/migrate down/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/chaos-41|lack/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos41-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8441,
            type: 'INFRA_DATABASE',
            title: "CHAOS-41: Lack of Isolated Rollback Test in Pre-Deployment Verifications",
            severity: 'HIGH',
            category: "Release Engineering",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-41 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Isolated Rollback Test in Pre-Deployment Verifications: Testing only forward deployment migrations without verifying that down / rollback migrations execute cleanly."
            ],
            remediationPrompt: "Test both up and down database migrations in CI to verify clean rollback capabilities.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-41 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-42: Unchecked Local Storage Exhaustion in Client Applications
    if (/localStorage\.setItem\s*\(\s*["\']big_dataset["\']/i.test(cleanContent) && !/try\s*\{/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/localStorage\.setItem\s*\(\s*["\']big_dataset["\']/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos42-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8442,
            type: 'INFRA_DATABASE',
            title: "CHAOS-42: Unchecked Local Storage Exhaustion in Client Applications",
            severity: 'LOW',
            category: "Storage Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-42 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unchecked Local Storage Exhaustion in Client Applications: Writing large datasets to localStorage without catching QuotaExceededError exceptions."
            ],
            remediationPrompt: "Wrap localStorage writes in try-catch blocks to handle QuotaExceededError gracefully.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 LOW: CHAOS-42 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-43: Missing Automated Database Failover Health Check Drill
    if (/chaosDrills/i.test(cleanContent) && !/rebootDBInstance/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/chaosDrills/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos43-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8443,
            type: 'INFRA_DATABASE',
            title: "CHAOS-43: Missing Automated Database Failover Health Check Drill",
            severity: 'MEDIUM',
            category: "Chaos Testing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-43 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Automated Database Failover Health Check Drill: Operating multi-AZ database configurations without ever executing automated failover simulation drills."
            ],
            remediationPrompt: "Run regular automated database failover drills to ensure client reconnection logic functions seamlessly.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-43 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-44: Unthrottled Recursive DOM Tree Traversal
    if (/function\s+traverseAllDomNodes\s*\(/i.test(cleanContent) && !/requestIdleCallback/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/function\s+traverseAllDomNodes\s*\(/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos44-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8444,
            type: 'INFRA_DATABASE',
            title: "CHAOS-44: Unthrottled Recursive DOM Tree Traversal",
            severity: 'MEDIUM',
            category: "Browser Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-44 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unthrottled Recursive DOM Tree Traversal: Executing unmemoized recursive DOM traversal scripts on dynamic pages with thousands of nodes, freezing browser UI."
            ],
            remediationPrompt: "Wrap heavy DOM traversal operations in requestIdleCallback to avoid blocking the main UI thread.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-44 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-45: Missing Thread-Safe Locking in Concurrent File System Writes
    if (/fs\.promises\.writeFile\s*\(\s*sharedFilePath/i.test(cleanContent) && !/rename/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/fs\.promises\.writeFile\s*\(\s*sharedFilePath/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos45-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8445,
            type: 'INFRA_DATABASE',
            title: "CHAOS-45: Missing Thread-Safe Locking in Concurrent File System Writes",
            severity: 'HIGH',
            category: "Data Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-45 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Thread-Safe Locking in Concurrent File System Writes: Concurrent async operations writing to the same file path using fs.writeFile without mutex locks, causing corrupted writes."
            ],
            remediationPrompt: "Write data to a temporary file first and atomically rename it to prevent file corruption from concurrent writes.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-45 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-46: Lack of Cold Start Latency Mitigation for High-Traffic Serverless Functions
    if (/serverless\.ya?ml$/i.test(file.path) && !/provisionedConcurrency/i.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*') && (/chaos-46|lack/i.test(l) || lines.indexOf(l) === 0));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos46-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8446,
            type: 'INFRA_DATABASE',
            title: "CHAOS-46: Lack of Cold Start Latency Mitigation for High-Traffic Serverless Functions",
            severity: 'MEDIUM',
            category: "Serverless Performance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-46 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Lack of Cold Start Latency Mitigation for High-Traffic Serverless Functions: High-traffic serverless API routes without provisioned concurrency, causing 3000ms latency spikes on traffic surges."
            ],
            remediationPrompt: "Add provisioned concurrency or warm-up cron triggers to serverless functions experiencing traffic spikes.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 MEDIUM: CHAOS-46 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-47: Missing Automatic Memory Dump on Heap Limit Warning
    if (/package\.json$/i.test(file.path) && /--max-old-space-size/i.test(cleanContent) && !/heapsnapshot-near-heap-limit/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/--max-old-space-size/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos47-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8447,
            type: 'INFRA_DATABASE',
            title: "CHAOS-47: Missing Automatic Memory Dump on Heap Limit Warning",
            severity: 'LOW',
            category: "Diagnostics",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-47 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Missing Automatic Memory Dump on Heap Limit Warning: Node.js server crashing with Out Of Memory (OOM) errors without generating heap dumps for postmortem analysis."
            ],
            remediationPrompt: "Add --heapsnapshot-near-heap-limit=3 to Node.js startup flags to capture diagnostic snapshots before OOM crashes.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 LOW: CHAOS-47 finding in ${file.path}:${lineNum}`);
    }
    // CHAOS-48: Unbounded WebSocket Message Buffer Size on Client
    if (/offlineWebSocketQueue\.push/i.test(cleanContent) && !/maxQueueSize|length\s*>=/i.test(cleanContent)) {
        const matchLineIdx = locateMatchLine(lines, [/offlineWebSocketQueue\.push/i], l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos48-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8448,
            type: 'INFRA_DATABASE',
            title: "CHAOS-48: Unbounded WebSocket Message Buffer Size on Client",
            severity: 'HIGH',
            category: "Connection Resilience",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || "<detected CHAOS-48 pattern>",
            reproductionSteps: [
                `Scanned source code in ${file.path}:${lineNum}.`,
                "Detected Unbounded WebSocket Message Buffer Size on Client: Buffering outbound WebSocket messages indefinitely in array when connection is offline, crashing browser tab memory."
            ],
            remediationPrompt: "Set a maximum queue limit on offline WebSocket message buffers to prevent browser memory exhaustion.",
            status: 'OPEN',
            owner: 'Security & Release Engineering',
            falsePositive: false
        });
        logs.push(`[${ts}] 💥 HIGH: CHAOS-48 finding in ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
