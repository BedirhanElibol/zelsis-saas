import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

/**
 * Java / Spring rule pack. JAVA-SEC-01 (27203, "Potential Log4Shell" on any log4j import) was removed:
 * an import says nothing about the resolved log4j-core version; the dependency audit (OSV) covers it.
 */
export function evaluateJavaSpringRules(_file: CodeFile, _lines: string[], _cleanContent: string, _findingCounter: { count: number }): { findings: Finding[], logs: string[] } {
    return { findings: [], logs: [] };
}
