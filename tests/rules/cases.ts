import type { CodeFile } from '../../lib/scanner-engine';

/**
 * Rule fixture table. Every rule gets at least one `detects` case (true positive)
 * and one `ignores` case (known-safe code that must not trigger it).
 * Add a row here when adding or fixing a rule.
 */
export interface RuleCase {
  ruleId: number;
  name: string;
  detects: CodeFile[];
  ignores: CodeFile[];
}

export const RULE_CASES: RuleCase[] = [
  {
    ruleId: 1,
    name: 'Hardcoded API secret',
    detects: [{ path: 'src/lib/openai.ts', content: 'export const key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";\n' }],
    ignores: [{ path: 'src/lib/openai.ts', content: 'export const key = process.env.OPENAI_API_KEY;\n' }]
  },
  {
    ruleId: 3,
    name: 'Permissive Supabase RLS policy',
    detects: [{ path: 'supabase/migrations/001.sql', content: 'CREATE POLICY "all" ON profiles FOR ALL USING (true);\n' }],
    ignores: [{ path: 'supabase/migrations/001.sql', content: 'CREATE POLICY "own" ON profiles FOR SELECT USING (auth.uid() = user_id);\n' }]
  },
  {
    ruleId: 8,
    name: 'Wildcard CORS origin',
    detects: [{ path: 'server/app.ts', content: "app.use(cors({ origin: '*' }));\n" }],
    ignores: [{ path: 'server/app.ts', content: 'app.use(cors({ origin: process.env.PRODUCTION_CLIENT_URL }));\n' }]
  },
  {
    ruleId: 16,
    name: 'Unsanitized innerHTML',
    detects: [{ path: 'components/Post.tsx', content: 'export const Post = ({ html }: { html: string }) => <div dangerouslySetInnerHTML={{ __html: html }} />;\n' }],
    ignores: [{
      path: 'app/layout.tsx',
      content: 'const ld = { "@context": "https://schema.org" };\nexport const Ld = () => <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(ld) }} />;\n'
    }]
  }
];
