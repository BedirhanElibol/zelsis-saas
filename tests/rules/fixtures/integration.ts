import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

/** Fixes made while integrating the rule waves (false positives found by scanning Zelsis itself). */
export const CASES: RuleCase[] = [
  {
    ruleIds: [1244],
    name: 'UI-INTERACT-44 meta viewport tag disables zoom; the same text in a docs string does not',
    detects: f('public/index.html', '<!doctype html>\n<html lang="en">\n<head>\n  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">\n</head>\n<body></body>\n</html>\n'),
    ignores: f('components/docs/ZoomRule.tsx', "export const example = {\n  name: 'Viewport blocks zoom (user-scalable=no)',\n  bad: 'maximum-scale=1 stops pinch zoom',\n};\n")
  },
  {
    ruleIds: [1026],
    name: 'outline-none input is fine when its wrapper draws a focus-within ring',
    detects: f('components/SearchBox.tsx', 'export function SearchBox() {\n  return (\n    <div className="flex items-center border rounded">\n      <input id="q" className="w-full bg-transparent outline-none" />\n    </div>\n  );\n}\n'),
    ignores: f('components/SearchBox.tsx', 'export function SearchBox() {\n  return (\n    <div className="flex items-center border rounded focus-within:ring-2 focus-within:ring-emerald-500">\n      <input id="q" className="w-full bg-transparent outline-none" />\n    </div>\n  );\n}\n')
  }
];
