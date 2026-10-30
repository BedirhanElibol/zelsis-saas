import type { RuleCase } from '../cases';

const PKG = (deps: string) => ({ path: 'package.json', content: `{"name":"x","dependencies":{${deps}}}` });
const VITE_ELECTRON = PKG('"vite":"5.4.10","electron":"33.2.0","react":"18.3.1"');
const VITE_REACT = PKG('"vite":"5.4.10","react":"18.3.1"');
const NEXT = PKG('"next":"15.0.0","react":"18.3.1"');
const PAGE = `import { useEffect } from 'react';
export default function HomePage() {
  useEffect(() => { document.title = 'Home'; }, []);
  return <main>Home</main>;
}
`;
const ENV_READ = 'export const devUrl = process.env.DEV_SERVER_URL;\n';

export const CASES: RuleCase[] = [
  {
    ruleIds: [29646], name: 'BUG-46 hook in an app/ page with Next.js vs a Vite app that has a page.tsx under app/',
    detects: [NEXT, { path: 'app/home/page.tsx', content: PAGE }],
    ignores: [VITE_REACT, { path: 'app/src/features/home/page.tsx', content: PAGE }],
  },
  {
    ruleIds: [29799], name: 'BUG-145 process.env in Vite renderer code vs Electron main and preload code',
    detects: [VITE_ELECTRON, { path: 'src/renderer/config.ts', content: ENV_READ }],
    ignores: [
      VITE_ELECTRON,
      { path: 'app/electron/main.ts', content: ENV_READ },
      { path: 'src/main/index.ts', content: ENV_READ },
      { path: 'src/preload/index.ts', content: ENV_READ },
    ],
  },
];
