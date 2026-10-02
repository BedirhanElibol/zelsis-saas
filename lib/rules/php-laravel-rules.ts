import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export function evaluatePhpLaravelRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: { count: number }): { findings: Finding[], logs: string[] } {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');

    if (!lowerPath.endsWith('.php')) return { findings, logs };

    // PHP-SEC-01: unserialize() user input
    const reg_unserialize = /unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i;
    const matchLineIdx = lines.findIndex(l => !/^\s*(?:\/\/|#|\*)/.test(l) && reg_unserialize.test(l) && !/allowed_classes['"]\s*=>\s*false/i.test(l));
    if (matchLineIdx !== -1) {
        findings.push({
            id: `php-uns-${findingCounter.count++}`,
            ruleId: 27202,
            type: 'SECURITY',
            title: 'PHP-SEC-01: PHP Object Injection via unserialize()',
            severity: 'CRITICAL',
            category: 'Insecure Deserialization',
            filePath: file.path,
            lineRange: matchLineIdx !== -1 ? `L${matchLineIdx + 1}` : 'L1',
            snippet: matchLineIdx !== -1 ? lines[matchLineIdx].trim() : 'unserialize($_POST["data"])',
            reproductionSteps: ['Send malicious serialized PHP object payload.'],
            remediationPrompt: 'Use json_decode() instead of unserialize().',
            status: 'OPEN',
            falsePositive: false
        });
    }
    return { findings, logs };
}
