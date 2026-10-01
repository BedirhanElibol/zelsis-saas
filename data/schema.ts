import { z } from 'zod';

export const SeverityEnum = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'PASSED']);
export const StatusEnum = z.enum(['OPEN', 'ACCEPTED_RISK', 'RESOLVED']);
export const GateStatusEnum = z.enum(['PASSED', 'FAILED', 'WARNING']);
export const PillarTypeEnum = z.enum(['SECURITY', 'VIBEPOLISH', 'VIBECARE', 'LEGAL_COMPLIANCE', 'INFRA_DATABASE']);

export const FindingSchema = z.object({
  id: z.string(),
  ruleId: z.number(),
  type: PillarTypeEnum,
  title: z.string(),
  severity: SeverityEnum,
  category: z.string(),
  filePath: z.string(),
  lineRange: z.string(),
  snippet: z.string(),
  reproductionSteps: z.array(z.string()),
  remediationPrompt: z.string(),
  diffPatch: z.string().optional(),
  status: StatusEnum,
  owner: z.string().optional(),
  falsePositive: z.boolean().default(false),
  /** experimental = rule not yet proven precise on the benchmark corpus: shown, but excluded from gate and score. */
  maturity: z.enum(['verified', 'unproven', 'experimental']).optional(),
  // Set by the server when fix text was withheld (Free tier); fetch it via /api/v1/scans/fix
  lockedFix: z.object({ jobId: z.string(), ref: z.string() }).optional(),
});

export interface ScanHistoryItem {
  id: string;
  date: string;
  target: string;
  score: number;
  gateStatus: 'PASSED' | 'FAILED' | 'WARNING';
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  duration: string;
  triggeredBy: string;
}

export const ProjectSchema = z.object({
  id: z.string(),
  name: z.string(),
  repoUrl: z.string(),
  githubToken: z.string().optional(),
  previewUrl: z.string().optional(),
  framework: z.string(),
  providers: z.array(z.string()),
  lastScanAt: z.string(),
  readinessScore: z.number().min(0).max(100),
  gateStatus: GateStatusEnum,
  criticalCount: z.number(),
  highCount: z.number(),
  mediumCount: z.number(),
  lowCount: z.number(),
  uiClicheCount: z.number(),
  findings: z.array(FindingSchema),
  scanHistory: z.array(z.any()).optional(),
  organizationId: z.string().optional(),
});


export const SourceTypeEnum = z.enum(['official-standard', 'open-source-tool', 'industry-research', 'community-consensus']);
export const DetectionMethodEnum = z.enum(['AST', 'regex', 'dataflow']);
export const FalsePositiveRiskEnum = z.enum(['low', 'medium', 'high']);
export const RuleStatusEnum = z.enum(['draft', 'published']);

export const BaseRuleSchema = z.object({
  id: z.union([z.string(), z.number()]),
  code: z.string(),
  title: z.string(),
  category: z.string(),
  sourceUrl: z.string().optional(),
  sourceType: SourceTypeEnum.optional(),
  positiveExample: z.string().optional(),
  negativeExample: z.string().optional(),
  owasp2025Category: z.string().optional(),
  cweId: z.string().optional(),
  applicableLanguages: z.array(z.string()).optional(),
  applicableFrameworks: z.array(z.string()).optional(),
  detectionMethod: DetectionMethodEnum.optional(),
  falsePositiveRisk: FalsePositiveRiskEnum.optional(),
  status: RuleStatusEnum.optional(),
});

export const SecurityRuleSchema = BaseRuleSchema.extend({
    owaspTag: z.string(),
  riskLevel: SeverityEnum,
  description: z.string(),
  verificationControl: z.string(),
  claudePrompt: z.string(),
});

export const UiRuleSchema = BaseRuleSchema.extend({
    clichePattern: z.string(),
  whyAiDoesIt: z.string(),
  zelsisSolution: z.string().optional(),
  shipguardSolution: z.string().optional(),
});

export const ComplianceRuleSchema = BaseRuleSchema.extend({
    legalFramework: z.string(),
  riskLevel: SeverityEnum,
  penaltyExposure: z.string(),
  description: z.string(),
  verificationControl: z.string(),
  remediationPrompt: z.string(),
});

export const InfraRuleSchema = BaseRuleSchema.extend({
    targetStack: z.string(),
  riskLevel: SeverityEnum,
  description: z.string(),
  verificationControl: z.string(),
  remediationPrompt: z.string(),
  sampleDiff: z.string().optional(),
});

export type SeverityLevel = z.infer<typeof SeverityEnum>;
export type StatusLevel = z.infer<typeof StatusEnum>;
export type GateStatusLevel = z.infer<typeof GateStatusEnum>;
export type PillarType = z.infer<typeof PillarTypeEnum>;
export type Finding = z.infer<typeof FindingSchema>;
export type Project = z.infer<typeof ProjectSchema>;
export type SecurityRule = z.infer<typeof SecurityRuleSchema>;
export type UiRule = z.infer<typeof UiRuleSchema>;
export type ComplianceRule = z.infer<typeof ComplianceRuleSchema>;
export type InfraRule = z.infer<typeof InfraRuleSchema>;

export type UserTier = 'Free' | 'Pro' | 'Enterprise';

export interface PlanUsageQuota {
  scansUsed: number;
  scansLimit: number;
  projectsUsed: number;
  projectsLimit: number;
  aiPromptsUsed: number;
  aiPromptsLimit: number;
  billingCycleReset: string;
}

export const OrganizationSchema = z.object({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  ownerId: z.string(),
  planTier: z.enum(['Free', 'Pro', 'Enterprise']),
  membersCount: z.number().default(1),
  allowedDomains: z.array(z.string()).default([]),
  securityPolicy: z.object({
    enforceOrgPolicy: z.boolean().default(true),
    defaultMinScore: z.number().default(85),
    requireScaPassing: z.boolean().default(true),
    blockOnCritical: z.boolean().default(true),
  }).default({
    enforceOrgPolicy: true,
    defaultMinScore: 85,
    requireScaPassing: true,
    blockOnCritical: true,
  }),
});

export type Organization = z.infer<typeof OrganizationSchema>;

