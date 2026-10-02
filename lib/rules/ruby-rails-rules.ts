import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export function evaluateRubyRailsRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: { count: number }): { findings: Finding[], logs: string[] } {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');

    if (!lowerPath.endsWith('.rb') && !lowerPath.endsWith('.erb')) return { findings, logs };

    // RUBY-SEC-01: YAML.load insecure deserialization
    // Psych 4 (Ruby 3.1+) made YAML.load safe by default, so flag YAML.unsafe_load on anything but a
    // local file, and YAML.load only on request input (exploitable on Ruby < 3.1).
    const reg_yaml = /\b(?:YAML|Psych)\.(load|unsafe_load)\s*\(\s*(.*)$/;
    const requestInput = /\bparams\[|\bparams\.(?:require|fetch|dig)\b|request\.(?:body|raw_post|params)\b|\bcookies\[/;
    const requestVars = new Set<string>();
    for (const l of lines) {
        const m = /^\s*(\w+)\s*=\s*(.*)$/.exec(l);
        if (m && requestInput.test(m[2])) requestVars.add(m[1]);
    }
    const matchLineIdx = lines.findIndex(l => {
        if (l.trim().startsWith('#')) return false;
        const m = reg_yaml.exec(l);
        if (!m) return false;
        const arg = m[2];
        const fromRequest = requestInput.test(arg) || [...arg.matchAll(/\b([a-z_]\w*)\b/g)].some((v) => requestVars.has(v[1]));
        return fromRequest || (m[1] === 'unsafe_load' && !/^(?:File|IO|ERB|Rails\.root|Pathname)\b/.test(arg));
    });
    if (matchLineIdx !== -1) {
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
