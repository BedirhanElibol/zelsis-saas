# zelsis

Check your code with [Zelsis](https://zelsis.com) from the terminal or from an AI coding agent, before you push.

```bash
export ZELSIS_API_KEY=...   # Zelsis: Settings -> API keys
npx zelsis check
```

`zelsis check` sends your uncommitted changes, plus the rest of the repository as context, and prints each finding with its file and line, what someone could do with it, and the fix. Only the files you changed decide the result:

- `FAILED` (exit code 1): a proven critical issue in your changes
- `WARNING` (exit code 0, or 1 with `--strict`): high-severity issues to review
- `PASSED` (exit code 0)

Options:

- `--all` scans and gates on every file
- `--base origin/main` also counts commits since that ref as changed
- `--json` prints the raw result

Files are scanned in memory on the Zelsis server and are not stored. Build folders, binaries, lockfiles and files over 512 KB are not sent.

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
