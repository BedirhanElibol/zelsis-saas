import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export function evaluateDotnetCsharpRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: { count: number }): { findings: Finding[], logs: string[] } {
    const findings: Finding[] = [];
    const logs: string[] = [];
    const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');

    if (!lowerPath.endsWith('.cs')) return { findings, logs };

    // DOTNET-SEC-01: Insecure XML Deserialization
    const reg_xml = /XmlSerializer\s*\(/i;
    if (reg_xml.test(cleanContent)) {
        const matchLineIdx = lines.findIndex(l => reg_xml.test(l));
        findings.push({
            id: `dotnet-xml-${findingCounter.count++}`,
            ruleId: 9004,
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
