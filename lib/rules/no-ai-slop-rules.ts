/**
 * Zelsis No-AI-Slop & Human Voice Rules Engine (all rules retired)
 *
 * Retired rules: COPY-SLOP-01 (25011), COPY-SLOP-02 (25012), UI-CLICHE-04 (25013). Removed as unsound: they judged
 * copywriting taste (words such as "leverage" / "empower", "it's not X, it's Y" phrasing, a Sparkles icon on a
 * button), which is not a defect and fired on ordinary marketing copy in clean repositories.
 * The ids are retired and must not be reused. The engine stays registered in lib/scanner/rule-engines.ts.
 */
import { Finding } from '@/data/schema';
export interface NoAiSlopRuleResult {
    findings: Finding[];
    logs: string[];
}
export function evaluateNoAiSlopRules(): NoAiSlopRuleResult {
    return { findings: [], logs: [] };
}
