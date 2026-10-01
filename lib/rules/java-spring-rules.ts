import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export function evaluateJavaSpringRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: { count: number }): { findings: Finding[], logs: string[] } {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');

    if (!lowerPath.endsWith('.java')) return { findings, logs };

    // JAVA-SEC-01: Log4j CVE-2021-44228
    const reg_log4j = /import\s+org\.apache\.logging\.log4j/i;
    if (reg_log4j.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => reg_log4j.test(l));
        findings.push({
            id: `java-log4j-${findingCounter.count++}`,
            ruleId: 27203,
            type: 'SECURITY',
            title: 'JAVA-SEC-01: Potential Log4Shell Vulnerability (Log4j)',
            severity: 'CRITICAL',
            category: 'Vulnerable Dependency',
            filePath: file.path,
            lineRange: matchLineIdx !== -1 ? `L${matchLineIdx + 1}` : 'L1',
            snippet: matchLineIdx !== -1 ? lines[matchLineIdx].trim() : 'import org.apache.logging.log4j.Logger;',
            reproductionSteps: ['Send JNDI payload in a logged request header.'],
            remediationPrompt: 'Upgrade log4j-core to 2.17.1 or newer.',
            status: 'OPEN',
            falsePositive: false
        });
    }
    return { findings, logs };
}
