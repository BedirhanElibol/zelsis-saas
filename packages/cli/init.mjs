// `zelsis init`: tell the AI coding agents in this repo to run Zelsis before they call a task done.
// Appends one marked block to the agent instruction files that exist (never twice), and prints how to add the
// MCP server. The API key is never written to a file.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export const MARKER = '<!-- zelsis:agent-rule -->';

export const AGENT_RULE = `${MARKER}
## Zelsis check

Before you report a coding task as done, run \`npx zelsis verify\` (or the \`zelsis_check\` MCP tool) and fix every
critical or high finding in the code you changed. Do not finish while the gate is FAILED. If a finding looks wrong,
tell the user why instead of working around it.
`;

/** Agent instruction files, in the order they are reported. */
export const TARGETS = ['CLAUDE.md', 'AGENTS.md', '.cursorrules', '.windsurfrules', '.github/copilot-instructions.md'];

/** Files created when the repo has none of the targets: AGENTS.md (read by most agents) and CLAUDE.md (Claude Code). */
export const DEFAULT_CREATE = ['AGENTS.md', 'CLAUDE.md'];

/**
 * What init would do in `cwd`: append to each existing target that lacks the block, skip those that have it,
 * and create the defaults when no target exists.
 */
export function planInit(cwd, fs = { existsSync, readFileSync }) {
  const existing = TARGETS.filter((t) => fs.existsSync(join(cwd, t)));
  if (existing.length === 0) return DEFAULT_CREATE.map((path) => ({ path, action: 'create' }));
  return existing.map((path) => ({
    path,
    action: fs.readFileSync(join(cwd, path), 'utf8').includes(MARKER) ? 'skip' : 'append',
  }));
}

export function applyInit(cwd, plan, fs = { existsSync, mkdirSync, readFileSync, writeFileSync }) {
  for (const step of plan) {
    const file = join(cwd, step.path);
    if (step.action === 'create') {
      fs.mkdirSync(dirname(file), { recursive: true });
      fs.writeFileSync(file, AGENT_RULE);
    } else if (step.action === 'append') {
      const current = fs.readFileSync(file, 'utf8');
      const sep = current.length === 0 || current.endsWith('\n\n') ? '' : current.endsWith('\n') ? '\n' : '\n\n';
      fs.writeFileSync(file, current + sep + AGENT_RULE);
    }
  }
}

export const MCP_HELP = `Add the MCP server so the agent can call zelsis_check itself:

  Claude Code:  claude mcp add zelsis --env ZELSIS_API_KEY=<your key> -- npx -y zelsis mcp
  Cursor:       add to .cursor/mcp.json
                { "mcpServers": { "zelsis": { "command": "npx", "args": ["-y", "zelsis", "mcp"],
                  "env": { "ZELSIS_API_KEY": "<your key>" } } } }

Create the key in Zelsis: Settings -> API keys. Keep it out of files you commit.`;

/** Human-readable summary of a plan. */
export function describePlan(plan, dryRun) {
  const verb = { create: dryRun ? 'would create' : 'created', append: dryRun ? 'would add the Zelsis rule to' : 'added the Zelsis rule to', skip: 'already has the Zelsis rule:' };
  return plan.map((s) => `  ${verb[s.action]} ${s.path}`).join('\n');
}
