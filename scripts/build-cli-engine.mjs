// Bundles the scan engine into packages/cli/engine.mjs so `zelsis check --local` runs on the developer's machine
// with no network. Runs from the CLI's prepack step; the bundle is generated, not committed.
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
// esbuild ships with tsx, which the repo already uses for tests
const { build } = createRequire(join(root, 'package.json'))('esbuild');

await build({
  entryPoints: [join(root, 'lib', 'scan-files.ts')],
  outfile: join(root, 'packages', 'cli', 'engine.mjs'),
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node18',
  logLevel: 'warning',
  legalComments: 'none',
});
console.log('zelsis: wrote packages/cli/engine.mjs');
