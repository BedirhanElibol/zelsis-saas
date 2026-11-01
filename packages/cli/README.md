# zelsis

Check your code with [Zelsis](https://zelsis.com) from the terminal or from an AI coding agent, before you push.

Create an API key at [zelsis.com/dashboard](https://zelsis.com/dashboard) under Settings & API Keys, then set it and run a check:

```bash
export ZELSIS_API_KEY=your-key
npx zelsis check
```

On Windows PowerShell, set it with `$env:ZELSIS_API_KEY = "your-key"` for the current window, or keep it for every new window with `[Environment]::SetEnvironmentVariable("ZELSIS_API_KEY", "your-key", "User")`.

`zelsis check` sends your uncommitted changes, plus the rest of the repository as context, and prints each finding with its file and line, what someone could do with it, and the fix. Only the files you changed decide the result:

- `FAILED` (exit code 1): a proven critical issue in your changes
- `WARNING` (exit code 0, or 1 with `--strict`): high-severity issues to review
- `PASSED` (exit code 0)

Options:

- `--all` scans and gates on every file
- `--base origin/main` also counts commits since that ref as changed
- `--json` prints the raw result
- `--sarif` prints SARIF 2.1.0, and `--sarif-file-output=<path>` also writes it to a file
- `--severity-threshold=<low|medium|high|critical>` exits 1 when a finding is at or above that severity, in place of the gate result and `--strict`

Exit code 2 means the check could not run (for example a missing API key or an invalid option).

Files are scanned in memory on the Zelsis server and are not stored. Build folders, binaries, lockfiles and files over 512 KB are not sent.

## Make your AI agent check its own work

```bash
npx zelsis init
```

Adds a short rule to the agent instruction files in the repo (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`, `.github/copilot-instructions.md`): run `zelsis verify` before calling a task done and fix critical or high findings first. Files that already have the rule are left alone; if none exist it creates `AGENTS.md` and `CLAUDE.md`. `--dry-run` only prints what it would change. It never writes your API key.

## Use it from an AI coding agent (MCP)

`zelsis mcp` starts an MCP server with one tool, `zelsis_check`. Your agent can call it after editing code and fix what it reports before you review the change.

Claude Code:

```bash
claude mcp add zelsis --env ZELSIS_API_KEY=your-key -- npx -y zelsis mcp
```

Cursor, Windsurf and other clients (`mcp.json`):

```json
{
  "mcpServers": {
    "zelsis": {
      "command": "npx",
      "args": ["-y", "zelsis", "mcp"],
      "env": { "ZELSIS_API_KEY": "your-key" }
    }
  }
}
```

Requires Node 18 or newer and git.
