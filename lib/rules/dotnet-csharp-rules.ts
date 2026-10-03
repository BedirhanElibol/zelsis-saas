import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export function evaluateDotnetCsharpRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: { count: number }): { findings: Finding[], logs: string[] } {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');

    if (!lowerPath.endsWith('.cs')) return { findings, logs };

    // DOTNET-SEC-01: Insecure XML Deserialization
    // XmlSerializer bound to a compile-time type (typeof(T)) is safe; the exploitable case is a type
    // resolved at runtime from input, e.g. new XmlSerializer(Type.GetType(request.TypeName)).
    const runtimeTypeVars = new Set<string>();
    for (const l of lines) {
        const m = /\b(\w+)\s*=\s*Type\.GetType\s*\(\s*(?!"[^"]*"\s*\))/.exec(l);
        if (m) runtimeTypeVars.add(m[1]);
    }
    const reg_xml = /XmlSerializer\s*\(\s*(Type\.GetType\s*\(\s*(?!"[^"]*"\s*\))|\w+\s*[,)])/;
    const matchLineIdx = lines.findIndex(l => {
        if (/^\s*(?:\/\/|\*)/.test(l)) return false;
        const m = reg_xml.exec(l);
        if (!m) return false;
        return m[1].startsWith('Type.GetType') || runtimeTypeVars.has(m[1].replace(/\s*[,)]$/, ''));
    });
    if (matchLineIdx !== -1) {
        findings.push({
            id: `dotnet-xml-${findingCounter.count++}`,
            ruleId: 27204,
            type: 'SECURITY',
            title: 'DOTNET-SEC-01: Insecure XML Deserialization',
            severity: 'CRITICAL',
            category: 'Insecure Deserialization',
            filePath: file.path,
            lineRange: matchLineIdx !== -1 ? `L${matchLineIdx + 1}` : 'L1',
            snippet: matchLineIdx !== -1 ? lines[matchLineIdx].trim() : 'new XmlSerializer(typeof(MyType))',
            reproductionSteps: ['Send malicious XML payload.'],
            remediationPrompt: 'Use DataContractSerializer or secure XmlReader settings.',
            status: 'OPEN',
            falsePositive: false
        });
    }
    return { findings, logs };
}
