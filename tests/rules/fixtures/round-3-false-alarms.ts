import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [32], name: 'SEC-32 Function built from a request value vs fixed literal arguments',
    detects: f('src/run.ts', 'export const run = (req: Req) => new Function(req.body.code)();\n'),
    ignores: f('src/load.ts', 'export const load = new Function(\'specifier\', \'return import(specifier)\');\n'),
  },
  {
    ruleIds: [37], name: 'SEC-37 SHA-1 over a password vs the WebSocket handshake accept key',
    detects: f('src/auth.ts', 'import { createHash } from "node:crypto";\nexport const hashPassword = (password: string) => createHash("sha1").update(password).digest("hex");\n'),
    ignores: f('src/ws.ts', 'import { createHash } from "node:crypto";\nconst key = String(req.headers["sec-websocket-key"] ?? "");\nconst accept = createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");\n'),
  },
  {
    ruleIds: [21], name: 'SEC-21 token written to a log vs a helper named like print that returns a digest',
    detects: f('src/slack.ts', 'export function connect(token: string) {\n  console.log("connecting", token);\n}\n'),
    ignores: f('internal/daemon/slack.go', 'package daemon\n\nfunc tokenPrint(bot, appToken string) string {\n\tsum := sha256.Sum256([]byte(bot + appToken))\n\treturn hex.EncodeToString(sum[:8])\n}\n'),
  },
  {
    ruleIds: [29804], name: 'FAKE-09 demo token in an app route vs in a dev mock server file',
    detects: f('app/api/login/route.ts', 'export async function POST() {\n  return Response.json({ token: "demo-token" });\n}\n'),
    ignores: f('web/fake-api.ts', 'export function login(send: Send) {\n  send(200, { token: "demo-token" });\n}\n'),
  },
  {
    ruleIds: [16], name: 'SEC-16 prop filled from user markup vs from a function that draws the app SVG',
    detects: f('src/Bubble.tsx', 'export const Bubble = ({ html }: { html: string }) => <span dangerouslySetInnerHTML={{ __html: html }} />;\n'),
    ignores: f('src/Face.tsx', 'export const Face = ({ name }: { name: string }) => <span className="face" dangerouslySetInnerHTML={{ __html: faceSvg(name) }} />;\n'),
  },
  {
    ruleIds: [16], name: 'SEC-16 joined strings that end in a value vs strings that start on the first line',
    detects: f('src/banner.js', 'function show(el, user) {\n  el.innerHTML = \'<div>\' +\n    user.bio +\n    \'</div>\';\n}\n'),
    ignores: f('src/banner.js', 'function show(el) {\n  el.innerHTML = \'<div style="padding:2rem">\' +\n    \'<h2>Paused</h2>\' +\n    \'</div>\';\n}\n'),
  },
];
