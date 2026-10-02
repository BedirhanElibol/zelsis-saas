/**
 * Zelsis evaluateChaosResilienceRules Engine.
 * Rules CHAOS-09/11/13/18/21/28/33/35/38/39 (Rule IDs 84xx). The other CHAOS ids were removed as unsound
 * (sentinel names, file-level absence checks, process advice) and must not be reused.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';
export interface ChaosResilienceRuleResult {
    findings: Finding[];
    logs: string[];
}
/** Lines from `start` through the end of the brace block opened there (capped at `max` lines). */
function blockLines(lines: string[], start: number, max = 40): string[] {
    const out: string[] = [];
    let depth = 0;
    let opened = false;
    for (let i = start; i < lines.length && i < start + max; i++) {
        out.push(lines[i]);
        // `} catch (e) {` closes the previous block before opening this one
        for (const ch of i === start ? lines[i].replace(/^\s*\}/, '') : lines[i]) {
            if (ch === '{') { depth++; opened = true; }
            else if (ch === '}') depth--;
        }
        if (opened && depth <= 0) break;
    }
    return out;
}
/** First line index inside a block opened by a `start` line where `pick(block)` returns an offset. */
function findInBlocks(lines: string[], start: RegExp, pick: (block: string[], i: number) => number, max = 40): number {
    for (let i = 0; i < lines.length; i++) {
        if (!start.test(lines[i])) continue;
        const off = pick(blockLines(lines, i, max), i);
        if (off !== -1) return i + off;
    }
    return -1;
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
    // CHAOS-09: DNS TTL Caching Misconfiguration Preventing Fast Failover
    // Only failover-relevant records (A/AAAA/CNAME) with a TTL of a day or more; MX/TXT/NS records are meant to be long-lived.
    const chaos09Idx = findInBlocks(lines, /resource\s+"aws_route53_record"/, (block) =>
        /\btype\s*=\s*"(?:A|AAAA|CNAME)"/.test(block.join('\n'))
            ? block.findIndex(l => Number((l.match(/^\s*ttl\s*=\s*"?(\d+)/) || [])[1] || 0) >= 86400)
            : -1, 60);
    if (chaos09Idx !== -1) {
        const matchLineIdx = chaos09Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos09-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8409,
            type: 'INFRA_DATABASE',
            title: "CHAOS-09: DNS TTL Caching Misconfiguration Preventing Fast Failover",
            severity: 'LOW',
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
    // CHAOS-11: Unconstrained Thread Pool / Worker Concurrency in CPU-Bound Work
    // One worker thread per collection element: spawning is bounded by input size, not by CPU count.
    const chaos11Idx = /p-limit|pLimit|piscina|workerpool|concurrency|availableParallelism|cpus\(\)/i.test(cleanContent) ? -1
        : findInBlocks(lines, /\.(?:map|forEach)\s*\(/, (block) => block.findIndex(l => /new\s+Worker\s*\(/.test(l)), 15);
    if (chaos11Idx !== -1) {
        const matchLineIdx = chaos11Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos11-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8411,
            type: 'INFRA_DATABASE',
            title: "CHAOS-11: Unconstrained Thread Pool / Worker Concurrency in CPU-Bound Work",
            severity: 'MEDIUM',
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
    // CHAOS-13: Lack of Backpressure Handling in Streaming Data Pipelines
    // A 'data' handler that writes every chunk and ignores write()'s return value never applies backpressure.
    const chaos13Idx = /['"]drain['"]|\.pause\s*\(/.test(cleanContent) ? -1
        : findInBlocks(lines, /\.on\s*\(\s*['"]data['"]/, (block) => block.findIndex(l => /^\s*(?:await\s+)?[\w$.]+\.write\s*\(\s*\w+/.test(l)), 15);
    if (chaos13Idx !== -1) {
        const matchLineIdx = chaos13Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos13-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8413,
            type: 'INFRA_DATABASE',
            title: "CHAOS-13: Lack of Backpressure Handling in Streaming Data Pipelines",
            severity: 'MEDIUM',
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
    // CHAOS-18: Single Point of Failure (SPOF) Without Multi-AZ Redundancy
    // Explicit single-AZ RDS instance; dev / staging / test databases are single-AZ on purpose.
    const chaos18Idx = /(?:^|[/_.-])(?:dev|development|staging|stage|test|sandbox|preview|local)(?:[/_.-]|$)/i.test(lowerPath) ? -1
        : findInBlocks(lines, /resource\s+"aws_db_instance"/, (block) =>
            /(?:dev|staging|stage|test|sandbox|preview|local)/i.test(block.filter(l => /resource\s+"aws_db_instance"|^\s*identifier\s*=/.test(l)).join(' '))
                ? -1
                : block.findIndex(l => /^\s*multi_az\s*=\s*false\b/.test(l)), 80);
    if (chaos18Idx !== -1) {
        const matchLineIdx = chaos18Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos18-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8418,
            type: 'INFRA_DATABASE',
            title: "CHAOS-18: Single Point of Failure (SPOF) Without Multi-AZ Redundancy",
            severity: 'MEDIUM',
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
    // CHAOS-21: Missing Fallback for Third-Party Font or Script Outages
    // Google Fonts stylesheet requested without display=swap: text stays invisible while the font CDN is slow or down.
    const chaos21Idx = lines.findIndex(l => /(?:@import\s+url\(|href\s*=\s*)['"]?https:\/\/fonts\.googleapis\.com\/css2?\?[^'")\s]*/i.test(l) && !/[?&]display=/i.test(l));
    if (chaos21Idx !== -1) {
        const matchLineIdx = chaos21Idx;
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
    // CHAOS-28: Unconstrained Log Ingestion Flooding Disk / Logging Storage
    // Logger constructed with a hardcoded debug/trace level (no environment switch around it).
    const chaos28Idx = !/\b(?:pino|winston|bunyan)\b/.test(cleanContent) || /LOG_LEVEL/.test(cleanContent) ? -1
        : lines.findIndex((l, i) => /\blevel\s*:\s*['"](?:debug|trace|silly)['"]/.test(l) && !/\?/.test(l) &&
            !/NODE_ENV|isDev|development|production/.test(lines.slice(Math.max(0, i - 3), i).join(' ')));
    if (chaos28Idx !== -1) {
        const matchLineIdx = chaos28Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos28-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8428,
            type: 'INFRA_DATABASE',
            title: "CHAOS-28: Unconstrained Log Ingestion Flooding Disk / Logging Storage",
            severity: 'LOW',
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
    // CHAOS-33: Insecure Fast-Fail Bypass Causing Silent Data Corruption
    // A catch block that reports success to the caller: the failed write is silently swallowed.
    const chaos33Idx = findInBlocks(lines, /\bcatch\s*(?:\([^)]*\))?\s*\{/, (block) =>
        block.findIndex(l => /\breturn\s+(?:\{\s*(?:success|ok)\s*:\s*true\b|(?:NextResponse|Response|res(?:\.status\(\s*200\s*\))?)\.json\(\s*\{\s*(?:success|ok)\s*:\s*true\b)/.test(l)), 15);
    if (chaos33Idx !== -1) {
        const matchLineIdx = chaos33Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos33-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8433,
            type: 'INFRA_DATABASE',
            title: "CHAOS-33: Insecure Fast-Fail Bypass Causing Silent Data Corruption",
            severity: 'MEDIUM',
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
    // CHAOS-35: Unbounded Event Listener Growth on Global Window Object
    // A React effect that adds a window listener and never returns a cleanup: every re-mount adds another listener.
    const chaos35Idx = findInBlocks(lines, /\buse(?:Layout)?Effect\s*\(/, (block) => {
        const body = block.join('\n');
        if (/removeEventListener|\bsignal\b|once\s*:\s*true/.test(body)) return -1;
        return block.findIndex(l => /\bwindow\.addEventListener\s*\(/.test(l));
    }, 40);
    if (chaos35Idx !== -1) {
        const matchLineIdx = chaos35Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos35-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8435,
            type: 'INFRA_DATABASE',
            title: "CHAOS-35: Unbounded Event Listener Growth on Global Window Object",
            severity: 'LOW',
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
    // CHAOS-38: Missing Backoff on Database Connection Reconnection
    // Reconnecting straight from an error/close handler with no delay: a DB outage becomes a tight reconnect loop.
    const chaos38Idx = findInBlocks(lines, /\.on\s*\(\s*['"](?:error|end|close)['"]\s*,/, (block) =>
        /setTimeout|backoff|delay|sleep|retry/i.test(block.join('\n')) ? -1 : block.findIndex((l, j) => j > 0 && /\b[\w$.]+\.connect\s*\(\s*\)/.test(l)), 12);
    if (chaos38Idx !== -1) {
        const matchLineIdx = chaos38Idx;
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `chaos38-${Date.now()}-${findingCounter.count++}`,
            ruleId: 8438,
            type: 'INFRA_DATABASE',
            title: "CHAOS-38: Missing Backoff on Database Connection Reconnection",
            severity: 'MEDIUM',
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
    // Production webpack build emitting un-hashed bundle names: browsers keep serving stale cached JS after a deploy.
    const chaos39Idx = /webpack/i.test(lowerPath) && /\bmode\s*:\s*['"]production['"]/.test(cleanContent)
        ? lines.findIndex(l => /\bfilename\s*:\s*['"](?:[\w/-]*\/)?\[name\]\.js['"]/.test(l))
        : -1;
    if (chaos39Idx !== -1) {
        const matchLineIdx = chaos39Idx;
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
    return { findings, logs };
}
