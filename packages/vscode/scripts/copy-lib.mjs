// The extension reuses the CLI's scan client. Packaging only includes files under this folder, so copy it in.
import { copyFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

copyFileSync(fileURLToPath(new URL('../../cli/lib.mjs', import.meta.url)), fileURLToPath(new URL('../zelsis-lib.mjs', import.meta.url)));
