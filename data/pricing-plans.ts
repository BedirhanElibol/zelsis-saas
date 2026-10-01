import { z } from 'zod';

import { formatCount, RULE_COUNTS } from '@/lib/rule-status';

export const PricingPlanSchema = z.object({
  id: z.enum(['free', 'zelsis-core', 'shipguard-core', 'vibecare', 'zelsis-suite']),
  name: z.string(),
  priceMonthly: z.number(),
  description: z.string(),
  features: z.array(z.string()),
  /** Sold as part of the plan but not shipped yet; rendered with a "Coming soon" label. */
  comingSoon: z.array(z.string()).optional(),
  isPopular: z.boolean().optional(),
  buttonText: z.string(),
  polarCheckoutUrl: z.string().optional(),
});

export type PricingPlanItem = z.infer<typeof PricingPlanSchema>;

/** Monthly USD prices. Must match the Polar products; Polar bills monthly only. */
export const PLAN_PRICES = { Free: 0, Pro: 19, Enterprise: 49 } as const;

/** "$49/mo" style label for copy. */
export const priceLabel = (tier: keyof typeof PLAN_PRICES): string =>
  tier === 'Free' ? '$0' : `$${PLAN_PRICES[tier]}/mo`;

/** Support promises per tier, kept in one place so copy and Terms stay consistent. */
export const SUPPORT_TERMS = {
  Free: 'Email support, best effort',
  Pro: 'Email support, reply within 2 business days',
  Enterprise: 'Priority email support, reply within 1 business day',
} as const;

export const ZELSIS_PRICING_PLANS: PricingPlanItem[] = [
  {
    id: 'free',
    name: 'Free Starter',
    priceMonthly: PLAN_PRICES.Free,
    isPopular: false,
    description: 'Release-gate scans for hobbyists and public open-source repositories.',
    features: [
      '3 scans per month',
      '1 connected public repository',
      `All ${formatCount(RULE_COUNTS.gating)} active rules`,
      '1 AI fix prompt trial',
      SUPPORT_TERMS.Free,
    ],
    buttonText: 'Start Free',
  },
  {
    id: 'zelsis-core',
    name: 'Zelsis Pro',
    priceMonthly: PLAN_PRICES.Pro,
    isPopular: true,
    description: 'Unlimited scans of public and private repos, CI release gate and AI fix prompts.',
    features: [
      'Unlimited scans (fair-use rate limits)',
      'Unlimited public & private repositories',
      `All ${formatCount(RULE_COUNTS.gating)} active rules`,
      'Unlimited AI fix prompts',
      'Printable PDF audit report',
      'GitHub Actions & CI/CD release gate',
      SUPPORT_TERMS.Pro,
    ],
    buttonText: 'Upgrade to Pro',
    polarCheckoutUrl: 'https://buy.polar.sh/polar_cl_rxs3MC7Hq08OwYgoaJQatH93arqZfotoGUS0N15NqbC',
  },
  {
    id: 'vibecare',
    name: 'Zelsis Enterprise',
    priceMonthly: PLAN_PRICES.Enterprise,
    isPopular: false,
    description: 'Everything in Pro with priority support. Team workspace and organization rules are on the way.',
    features: [
      'Everything in Zelsis Pro',
      SUPPORT_TERMS.Enterprise,
    ],
    comingSoon: [
      'Team workspace with roles and invites',
      'Custom organization ruleset',
      'White-label PDF report with SOC 2 control mapping',
    ],
    buttonText: 'Upgrade to Enterprise',
    polarCheckoutUrl: 'https://buy.polar.sh/polar_cl_M0yZJgYVCucd7U5gDz4oFTND6hdqvYPo65HJQ2334od',
  },
];

export const SHIPGUARD_PRICING_PLANS = ZELSIS_PRICING_PLANS;
