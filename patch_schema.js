const fs = require('fs');

let schema = fs.readFileSync('data/schema.ts', 'utf8');

const newEnums = `
export const SourceTypeEnum = z.enum(['official-standard', 'open-source-tool', 'industry-research', 'community-consensus']);
export const DetectionMethodEnum = z.enum(['AST', 'regex', 'dataflow']);
export const FalsePositiveRiskEnum = z.enum(['low', 'medium', 'high']);
export const RuleStatusEnum = z.enum(['draft', 'published']);

export const BaseRuleSchema = z.object({
  id: z.number(),
  code: z.string(),
  title: z.string(),
  category: z.string(),
  sourceUrl: z.string().optional(),
  sourceType: SourceTypeEnum.optional(),
  positiveExample: z.string().optional(),
  negativeExample: z.string().optional(),
  owasp2025Category: z.string().optional(),
  cweId: z.string().optional(),
  applicableLanguages: z.array(z.string()).default([]),
  applicableFrameworks: z.array(z.string()).default([]),
  detectionMethod: DetectionMethodEnum.optional(),
  falsePositiveRisk: FalsePositiveRiskEnum.optional(),
  status: RuleStatusEnum.default('draft'),
});
`;

schema = schema.replace("export const SecurityRuleSchema = z.object({", newEnums + "\nexport const SecurityRuleSchema = BaseRuleSchema.extend({");
schema = schema.replace("export const UiRuleSchema = z.object({", "export const UiRuleSchema = BaseRuleSchema.extend({");
schema = schema.replace("export const ComplianceRuleSchema = z.object({", "export const ComplianceRuleSchema = BaseRuleSchema.extend({");
schema = schema.replace("export const InfraRuleSchema = z.object({", "export const InfraRuleSchema = BaseRuleSchema.extend({");

schema = schema.replace(/id: z\.number\(\),\r?\n\s*code: z\.string\(\),\r?\n\s*title: z\.string\(\),\r?\n\s*category: z\.string\(\),\r?\n/g, "");

fs.writeFileSync('data/schema.ts', schema);
