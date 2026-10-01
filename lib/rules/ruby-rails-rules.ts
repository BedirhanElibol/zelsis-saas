import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export function evaluateRubyRailsRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: { count: number }): { findings: Finding[], logs: string[] } {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');

    if (!lowerPath.endsWith('.rb') && !lowerPath.endsWith('.erb')) return { findings, logs };

    // RUBY-SEC-01: YAML.load insecure deserialization
    const reg_yaml = /YAML\.load\s*\(/i;
    if (reg_yaml.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => reg_yaml.test(l));
        findings.push({
            id: `ruby-yaml-${findingCounter.count++}`,
            ruleId: 27201,
            type: 'SECURITY',
            title: 'RUBY-SEC-01: Unsafe YAML Deserialization',
            severity: 'CRITICAL',
            category: 'Insecure Deserialization',
            filePath: file.path,
            lineRange: matchLineIdx !== -1 ? `L${matchLineIdx + 1}` : 'L1',
            snippet: matchLineIdx !== -1 ? lines[matchLineIdx].trim() : 'YAML.load(user_input)',
            reproductionSteps: ['Supply payload with ruby/object tags.'],
            remediationPrompt: 'Use YAML.safe_load instead of YAML.load.',
            status: 'OPEN',
            falsePositive: false
        });
    }
    return { findings, logs };
}
