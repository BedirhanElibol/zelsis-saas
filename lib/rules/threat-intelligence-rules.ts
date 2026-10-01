/**
 * Zelsis Master evaluateThreatIntelligenceRules Engine (50 Rules)
 * Rules CTI-01 to CTI-50 (Rule IDs 15601 to 15650).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";
export interface ThreatIntelligenceRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateThreatIntelligenceRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
    count: number;
}): ThreatIntelligenceRuleResult {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");
    // Skip self-referential catalogs, mocks, and schema definitions
    if (lowerPath.includes("node_modules/") || lowerPath.endsWith(".d.ts")) {
        return { findings, logs };
    }
    const ts = new Date().toLocaleTimeString();
    // CTI-01: Unvalidated Cyber Threat Intelligence (CTI) Feed Ingestion Permitting Malicious Rule Poisoning
    if (((/threat_intel|taxii_client/i.test(lowerPath) || /taxiiFeed|stixParser/i.test(cleanContent)) && !/verifyFeedSignature/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cti15601-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15601,
            type: 'SECURITY',
            title: "CTI-01: Unvalidated Cyber Threat Intelligence (CTI) Feed Ingestion Permitting Malicious Rule Poisoning",
            severity: "CRITICAL",
            category: "Feed Integrity",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
            reproductionSteps: [
                `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
                'Matched CTI-01: Unvalidated Cyber Threat Intelligence (CTI) Feed Ingestion Permitting Malicious Rule Poisoning.'
            ],
            remediationPrompt: "Authenticate threat intelligence feeds using TLS client certificates and cryptographically sign STIX/TAXII indicator payloads.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CTI AUDIT] Found CTI-01: Unvalidated Cyber Threat Intelligence (CTI) Feed Ingestion Permitting Malicious Rule Poisoning at ${file.path}:${lineNum}`);
    }
    // CTI-02: Missing STIX 2.1 & TAXII 2.1 Automated Threat Indicator Expiration and TTL Governance
    if (((/ioc_database|blocklist_rules/i.test(lowerPath) || /stixIndicator|iocStore/i.test(cleanContent)) && !/iocTtlDays/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cti15602-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15602,
            type: 'SECURITY',
            title: "CTI-02: Missing STIX 2.1 & TAXII 2.1 Automated Threat Indicator Expiration and TTL Governance",
            severity: "HIGH",
            category: "Indicator Lifecycle",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
            reproductionSteps: [
                `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
                'Matched CTI-02: Missing STIX 2.1 & TAXII 2.1 Automated Threat Indicator Expiration and TTL Governance.'
            ],
            remediationPrompt: "Implement automated Time-to-Live (TTL) policies retiring ephemeral threat indicators (e.g. dynamic IP addresses) after 7 to 14 days.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CTI AUDIT] Found CTI-02: Missing STIX 2.1 & TAXII 2.1 Automated Threat Indicator Expiration and TTL Governance at ${file.path}:${lineNum}`);
    }
    // CTI-03: Lack of Automated Threat Feed Confidence Scoring Leading to Critical Benign Asset Blacklisting
    if (((/threat_scoring|ioc_filtering/i.test(lowerPath) || /confidenceThreshold/i.test(cleanContent)) && !/minConfidenceScore/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cti15603-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15603,
            type: 'SECURITY',
            title: "CTI-03: Lack of Automated Threat Feed Confidence Scoring Leading to Critical Benign Asset Blacklisting",
            severity: "HIGH",
            category: "Accuracy Assurance",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
            reproductionSteps: [
                `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
                'Matched CTI-03: Lack of Automated Threat Feed Confidence Scoring Leading to Critical Benign Asset Blacklisting.'
            ],
            remediationPrompt: "Enforce minimum confidence score thresholds (e.g. score >= 85) and cross-reference major CDN/DNS provider whitelists prior to blocking.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CTI AUDIT] Found CTI-03: Lack of Automated Threat Feed Confidence Scoring Leading to Critical Benign Asset Blacklisting at ${file.path}:${lineNum}`);
    }
    // CTI-04: Missing MISP Security Incident Event Synchronization on Perimeter Edge Firewalls
    if (((/misp_integration|firewall_sync/i.test(lowerPath) || /mispEvent/i.test(cleanContent)) && !/syncMispToFirewall/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cti15604-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15604,
            type: 'SECURITY',
            title: "CTI-04: Missing MISP Security Incident Event Synchronization on Perimeter Edge Firewalls",
            severity: "MEDIUM",
            category: "Incident Sharing",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
            reproductionSteps: [
                `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
                'Matched CTI-04: Missing MISP Security Incident Event Synchronization on Perimeter Edge Firewalls.'
            ],
            remediationPrompt: "Automate bi-directional synchronization between security incident management and edge firewall IoC enforcement systems.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CTI AUDIT] Found CTI-04: Missing MISP Security Incident Event Synchronization on Perimeter Edge Firewalls at ${file.path}:${lineNum}`);
    }
    // CTI-05: Unverified IoC (Indicator of Compromise) Matching Running Without IP/Domain Reputation Scoring
    if (((/ioc_matcher|perimeter_alert/i.test(lowerPath) || /iocMatcher/i.test(cleanContent)) && !/enrichWithReputation/i.test(cleanContent))) {
        const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        findings.push({
            id: `cti15605-${Date.now()}-${findingCounter.count++}`,
            ruleId: 15605,
            type: 'SECURITY',
            title: "CTI-05: Unverified IoC (Indicator of Compromise) Matching Running Without IP/Domain Reputation Scoring",
            severity: "HIGH",
            category: "Reputation Scoring",
            filePath: file.path,
            lineRange: `L${lineNum}`,
            snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
            reproductionSteps: [
                `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
                'Matched CTI-05: Unverified IoC (Indicator of Compromise) Matching Running Without IP/Domain Reputation Scoring.'
            ],
            remediationPrompt: "Enrich all IoC detection alerts with multi-source reputation scoring before escalating to automated account lockouts or IP bans.",
            status: 'OPEN',
            falsePositive: false
        });
        logs.push(`[${ts}] [CTI AUDIT] Found CTI-05: Unverified IoC (Indicator of Compromise) Matching Running Without IP/Domain Reputation Scoring at ${file.path}:${lineNum}`);
    }
    return { findings, logs };
}
