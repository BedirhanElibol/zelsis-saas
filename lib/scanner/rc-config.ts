import { parseZelsisIgnore } from './ignore-parser';

export interface ZelsisRcConfig {
  projectName?: string;
  minScoreThreshold?: number;
  failStrategy?: 'smart' | 'strict' | 'advisory';
  gates?: {
    security?: boolean;
    legalCompliance?: boolean;
    infraDatabase?: boolean;
    designVibePolish?: boolean;
    vibeCareHealth?: boolean;
  };
  ignoreRules?: string[];
  ignoredPaths?: string[];
}

/**
 * F-43 Remediation: Parses Policy-as-Code .zelsisrc.json or .zelsisrc file
 * Standardizes security governance, failStrategy, and gate thresholds across CI/CD and dashboard.
 */
export function parseZelsisRc(rcContent: string): {
  config: ZelsisRcConfig | null;
  ignoredRuleIds: Set<number>;
  ignoredPaths: string[];
  disabledPillars: Set<string>;
} {
  const ignoredRuleIds = new Set<number>();
  const ignoredPaths: string[] = [];
  const disabledPillars = new Set<string>();

  if (!rcContent || typeof rcContent !== 'string') {
    return { config: null, ignoredRuleIds, ignoredPaths, disabledPillars };
  }

  try {
    const rc: ZelsisRcConfig = JSON.parse(rcContent);
    if (Array.isArray(rc.ignoreRules)) {
      for (const ruleStr of rc.ignoreRules) {
        const parsed = parseZelsisIgnore(String(ruleStr));
        parsed.ignoredRuleIds.forEach((id) => ignoredRuleIds.add(id));
      }
    }
    if (Array.isArray(rc.ignoredPaths)) {
      for (const pathStr of rc.ignoredPaths) {
        ignoredPaths.push(String(pathStr).toLowerCase());
      }
    }
    if (rc.gates) {
      if (rc.gates.security === false) disabledPillars.add('SECURITY');
      if (rc.gates.legalCompliance === false) disabledPillars.add('LEGAL_COMPLIANCE');
      if (rc.gates.infraDatabase === false) disabledPillars.add('INFRA_DATABASE');
      if (rc.gates.designVibePolish === false) disabledPillars.add('VIBEPOLISH');
      if (rc.gates.vibeCareHealth === false) disabledPillars.add('VIBECARE');
    }
    return { config: rc, ignoredRuleIds, ignoredPaths, disabledPillars };
  } catch {
    return { config: null, ignoredRuleIds, ignoredPaths, disabledPillars };
  }
}
