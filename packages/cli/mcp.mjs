// Minimal MCP server over stdio (JSON-RPC 2.0, one message per line). Exposes one tool: zelsis_check.
import { createInterface } from 'node:readline';
import { VERSION, runCheck, formatReport } from './lib.mjs';

export const TOOLS = [
  {
    name: 'zelsis_check',
    description:
      'Scan the code in the current repository with Zelsis before committing. Returns security and logic findings ' +
      '(file, line, what someone can do with it, how to fix) and the release gate result (PASSED, WARNING, FAILED). ' +
      'By default only files changed in the working tree decide the gate; the rest of the repository is sent as context.',
    inputSchema: {
      type: 'object',
      properties: {
        scope: { type: 'string', enum: ['changed', 'all'], description: 'changed (default): uncommitted changes. all: every file.' },
        base: { type: 'string', description: 'Optional git ref; commits since this ref also count as changed (e.g. origin/main).' },
      },
      additionalProperties: false,
    },
  },
];

/** What the agent should do next, so it fixes blocking issues before handing the change back. */
export function agentNote(result) {
  const blocking = (result.findings ?? []).filter((f) => (f.severity === 'CRITICAL' || f.severity === 'HIGH') && !f.experimental);
  if (blocking.length === 0) return '\n\nNo critical or high findings in the changed files. You can finish.';
  return `\n\nFix the ${blocking.length} critical/high finding(s) above in the code you wrote, then call zelsis_check again. ` +
    'Do not report the task as done while the gate is FAILED. If a finding is wrong, explain why to the user instead of hiding it.';
}

/** Handles one JSON-RPC message. Returns the response object, or null for notifications. */
export async function handleMessage(msg, { cwd, env, check = runCheck }) {
  const reply = (result) => ({ jsonrpc: '2.0', id: msg.id, result });
  const fail = (code, message) => ({ jsonrpc: '2.0', id: msg.id ?? null, error: { code, message } });
  if (msg.id === undefined) return null; // notification (e.g. notifications/initialized)

  switch (msg.method) {
    case 'initialize':
      return reply({
        protocolVersion: msg.params?.protocolVersion ?? '2025-06-18',
        capabilities: { tools: {} },
        serverInfo: { name: 'zelsis', version: VERSION },
      });
    case 'ping':
      return reply({});
    case 'tools/list':
      return reply({ tools: TOOLS });
    case 'tools/call': {
      if (msg.params?.name !== 'zelsis_check') return fail(-32602, `Unknown tool: ${msg.params?.name}`);
      const args = msg.params.arguments ?? {};
      try {
        const result = await check({
          cwd,
          all: args.scope === 'all',
          base: typeof args.base === 'string' && args.base ? args.base : undefined,
          url: env.ZELSIS_URL,
          apiKey: env.ZELSIS_API_KEY,
        });
        return reply({ content: [{ type: 'text', text: formatReport(result, { limit: 30 }) + agentNote(result) }], isError: false });
      } catch (err) {
        return reply({ content: [{ type: 'text', text: `Zelsis check failed: ${err.message}` }], isError: true });
      }
    }
    default:
      return fail(-32601, `Method not found: ${msg.method}`);
  }
}

export function serveMcp({ cwd = process.cwd(), env = process.env } = {}) {
  const rl = createInterface({ input: process.stdin });
  rl.on('line', async (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n');
      return;
    }
    const res = await handleMessage(msg, { cwd, env });
    if (res) process.stdout.write(JSON.stringify(res) + '\n');
  });
}
