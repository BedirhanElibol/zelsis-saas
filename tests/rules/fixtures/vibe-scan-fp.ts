import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

// False positives found by scanning 179 real Lovable / Bolt apps (.cache/vibe-results.jsonl)
const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [16], name: 'innerHTML XSS vs shadcn chart.tsx theme <style> (90 of 179 vibe apps)',
    detects: f('components/comment.tsx', `export function Comment({ body }: { body: string }) {
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}
`),
    ignores: f('components/ui/chart.tsx', `const THEMES = { light: '', dark: '.dark' } as const;
const ChartStyle = ({ id, config }: { id: string; config: Record<string, { color?: string }> }) => {
  return (
    <style
      dangerouslySetInnerHTML={{
        __html: Object.entries(THEMES).map(([theme, prefix]) => \`\${prefix} [data-chart=\${id}] {}\`).join('\\n'),
      }}
    />
  );
};
export { ChartStyle };
`),
  },
  {
    ruleIds: [8811], name: 'Python eval in app code vs a committed .venv site-packages',
    detects: f('backend/app/calc.py', `def calc(expr):
    return eval(expr)
`),
    ignores: f('backend/.venv/lib/python3.11/site-packages/somepkg/calc.py', `def calc(expr):
    return eval(expr)
`),
  },
];
