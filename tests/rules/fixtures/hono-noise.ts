import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29701],
    name: 'SHIP-01 a baseURL used for real requests vs a bare localhost base for in-process requests',
    detects: f('src/api/client.ts', "const baseURL = 'http://localhost'\nexport const load = () => fetch(baseURL + '/items')\n"),
    ignores: f('src/helper/ssg.ts', "const baseURL = 'http://localhost'\nexport const render = (app: App, path: string) => app.request(new URL(path, baseURL))\n"),
  },
];
