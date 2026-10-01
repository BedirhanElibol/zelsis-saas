import { z } from 'zod';

export const PricingPlanSchema = z.object({
  id: z.enum(['free', 'zelsis-core', 'shipguard-core', 'vibecare', 'zelsis-suite']),
  name: z.string(),
  priceMonthly: z.number(),
  priceAnnual: z.number(),
  description: z.string(),
  features: z.array(z.string()),
  isPopular: z.boolean().optional(),
  buttonText: z.string(),
  polarCheckoutUrl: z.string().optional(),
});

export type PricingPlanItem = z.infer<typeof PricingPlanSchema>;

export const ZELSIS_PRICING_PLANS: PricingPlanItem[] = [
  {
    id: 'free',
    name: 'Free Starter',
    priceMonthly: 0,
    priceAnnual: 0,
    isPopular: false,
    description: 'Baseline AST pre-flight checks for hobbyists and public open-source repositories.',
    features: [
      '3 automated scans per month',
      '1 connected public repository',
      '20 core OWASP security rules',
      '1 AI remediation trial prompt',
      'Community forum support',
    ],
    buttonText: 'Start Free',
  },
  {
    id: 'zelsis-core',
    name: 'Zelsis Pro',
    priceMonthly: 19,
    priceAnnual: 15,
    isPopular: true,
    description: 'Comprehensive Security Pre-flight Checks, Secret Isolation, DB RLS rules & AI Remediation Prompts.',
    features: [
      'Unlimited automated scans per month',
      'Unlimited public & private repositories',
      'All 1,450+ production rules',
      'Unlimited AI fix prompts',
      'Signed cryptographic PDF certificates',
      'GitHub Actions & CI/CD release gate',
      'Priority 24/7 SLA Guarantee',
    ],
    buttonText: 'Upgrade to Pro',
    polarCheckoutUrl: 'https://buy.polar.sh/polar_cl_rxs3MC7Hq08OwYgoaJQatH93arqZfotoGUS0N15NqbC',
  },
  {
    id: 'vibecare',
    name: 'Zelsis Enterprise',
    priceMonthly: 99,
    priceAnnual: 79,
    isPopular: false,
    description: 'Long-term lifecycle monitoring, Dependency CVE drifts, Cloud & LLM cost alerts, Multi-Org Security Gates.',
    features: [
      'Everything in Zelsis Pro',
      'Dedicated Parallel AST scan cluster',
      'White-label PDF audit reports & SOC 2 dossiers',
      'Custom organization ruleset catalog',
      'Multi-organization team & role management',
      '1-Hour Priority SLA & Dedicated Solutions Architect',
    ],
    buttonText: 'Upgrade to Enterprise',
    polarCheckoutUrl: 'https://buy.polar.sh/polar_cl_M0yZJgYVCucd7U5gDz4oFTND6hdqvYPo65HJQ2334od',
  },
];

export const SHIPGUARD_PRICING_PLANS = ZELSIS_PRICING_PLANS;
