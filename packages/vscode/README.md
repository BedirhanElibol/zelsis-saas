# Zelsis for VS Code

Full guide: [zelsis.com/docs/vscode](https://zelsis.com/docs/vscode)

Runs the Zelsis release check on your changed files and shows the findings as problems in the editor, with the fix text and a CWE link where one applies.

## Use

1. Create an API key at [zelsis.com](https://zelsis.com/dashboard) under Settings & API Keys.
2. Run **Zelsis: Set API Key** from the command palette. The key is kept in the editor's secret storage. `ZELSIS_API_KEY` from the environment also works.
3. Run **Zelsis: Check Changed Files**, or **Zelsis: Check Whole Workspace**.

The workspace must be a git repository. Files are scanned in memory on the Zelsis server and not stored. Build folders, binaries and lockfiles are not sent.

## Commands

- **Zelsis: Check Changed Files**: uncommitted changes decide the gate; the rest of the repository is sent as context.
- **Zelsis: Check Whole Workspace**: every file decides the gate.
- **Zelsis: Clear Findings**
- **Zelsis: Set API Key**

## Settings

- `zelsis.url`: server URL, `https://zelsis.com` by default.
