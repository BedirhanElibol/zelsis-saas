import type { Finding } from '@/data/schema';

/**
 * Cost of abuse, computed only from numbers the user enters. Zelsis does not know the app's traffic or prices, so
 * it never shows a dollar figure on its own: the user supplies the unit price and the request rate, and every
 * result is shown next to those assumptions.
 */

/** Rules where each abusive request costs the owner money: SMS sends and paid AI calls (or a stolen key for them). */
export const PAID_CALL_RULES: ReadonlySet<number> = new Set([
  30312, // XL-12: SMS sent without a rate limit
  10402, // AI inference endpoint without an edge rate limit
  4001, // unbounded LLM token consumption
  29933, // LLM called in a loop with no attempt limit
  28310, // client-chosen model passed to the provider
  22, // LLM SDK used directly from the browser
  28206, // LLM SDK in the browser with a bundled key
  5013, // OpenAI secret key exposed
  5014, // Anthropic secret key exposed
  5021, // Twilio SID and auth token exposed
]);

export interface CostInputs {
  /** Cost of one abusive request in USD (one SMS, or one average AI request). */
  pricePerRequest: number;
  /** Requests per minute an attacker can push through (the endpoint's real limit, or the provider's). */
  requestsPerMinute: number;
  /** Users whose records the app stores (for data leak findings). */
  userCount: number;
}

export interface CostEstimate {
  paidCallFindings: Finding[];
  dataLeakFindings: Finding[];
  /** USD for one hour and one day of abuse at the entered rate; null when price or rate is missing. */
  perHour: number | null;
  perDay: number | null;
  /** Records at risk from data leak findings; null when the user count is missing. */
  usersAtRisk: number | null;
}

const isOpenSerious = (f: Finding) => f.status === 'OPEN' && !f.falsePositive && (f.severity === 'CRITICAL' || f.severity === 'HIGH' || f.severity === 'MEDIUM');

export function estimateCost(findings: Finding[], inputs: Partial<CostInputs>): CostEstimate {
  const paidCallFindings = findings.filter((f) => isOpenSerious(f) && PAID_CALL_RULES.has(f.ruleId));
  const dataLeakFindings = findings.filter((f) => isOpenSerious(f) && f.risk === 'DATA_LEAK' && (f.severity === 'CRITICAL' || f.severity === 'HIGH'));
  const price = inputs.pricePerRequest;
  const rate = inputs.requestsPerMinute;
  const ok = (n: number | undefined): n is number => typeof n === 'number' && Number.isFinite(n) && n > 0;
  const perHour = paidCallFindings.length > 0 && ok(price) && ok(rate) ? Math.round(price * rate * 60 * 100) / 100 : null;
  return {
    paidCallFindings,
    dataLeakFindings,
    perHour,
    perDay: perHour === null ? null : Math.round(perHour * 24 * 100) / 100,
    usersAtRisk: dataLeakFindings.length > 0 && ok(inputs.userCount) ? Math.floor(inputs.userCount) : null,
  };
}

export const formatUsd = (n: number) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: n < 100 ? 2 : 0 });
