const vscode = require('vscode');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { toProblems, summary } = require('./findings');

const SECRET_KEY = 'zelsis.apiKey';
const LEVELS = [vscode.DiagnosticSeverity.Error, vscode.DiagnosticSeverity.Warning, vscode.DiagnosticSeverity.Information];

/** @param {vscode.ExtensionContext} context */
function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection('zelsis');
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
  status.command = 'zelsis.checkChanges';
  context.subscriptions.push(diagnostics, status);

  // The scan client is the CLI's ES module, copied in when the extension is packaged.
  const lib = () => import(pathToFileURL(path.join(__dirname, 'zelsis-lib.mjs')).href);

  async function apiKey() {
    const stored = await context.secrets.get(SECRET_KEY);
    if (stored) return stored;
    return process.env.ZELSIS_API_KEY;
  }

  async function check(all) {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return vscode.window.showWarningMessage('Zelsis: open a folder first.');
    const key = await apiKey();
    if (!key) {
      const pick = await vscode.window.showWarningMessage('Zelsis needs an API key. Create one at zelsis.com under Settings & API Keys.', 'Set API Key');
      if (pick) await vscode.commands.executeCommand('zelsis.setApiKey');
      return;
    }
    status.text = '$(sync~spin) Zelsis';
    status.show();
    try {
      const { runCheck } = await lib();
      const url = vscode.workspace.getConfiguration('zelsis').get('url');
      const result = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: all ? 'Zelsis: checking the workspace' : 'Zelsis: checking changed files' },
        () => runCheck({ cwd: folder.uri.fsPath, all, url, apiKey: key }),
      );
      diagnostics.clear();
      for (const [file, problems] of toProblems(result)) {
        diagnostics.set(vscode.Uri.joinPath(folder.uri, file), problems.map((p) => {
          const d = new vscode.Diagnostic(new vscode.Range(p.line, 0, p.line, Number.MAX_SAFE_INTEGER), p.message, LEVELS[p.severity]);
          d.source = 'Zelsis';
          d.code = p.cweId ? { value: `${p.code} ${p.cweId}`, target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${p.cweId.slice(4)}.html`) } : p.code;
          return d;
        }));
      }
      status.text = summary(result);
    } catch (err) {
      status.text = 'Zelsis: check failed';
      vscode.window.showErrorMessage(`Zelsis: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  context.subscriptions.push(
    vscode.commands.registerCommand('zelsis.checkChanges', () => check(false)),
    vscode.commands.registerCommand('zelsis.checkAll', () => check(true)),
    vscode.commands.registerCommand('zelsis.clear', () => { diagnostics.clear(); status.hide(); }),
    vscode.commands.registerCommand('zelsis.setApiKey', async () => {
      const value = await vscode.window.showInputBox({ prompt: 'Zelsis API key', password: true, ignoreFocusOut: true });
      if (value?.trim()) {
        await context.secrets.store(SECRET_KEY, value.trim());
        vscode.window.showInformationMessage('Zelsis: API key saved in the editor secret storage.');
      }
    }),
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
