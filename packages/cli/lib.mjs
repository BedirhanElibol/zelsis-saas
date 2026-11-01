// Shared logic for the zelsis CLI and MCP server. No dependencies: Node 18+ only.
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

export const VERSION = '0.2.0';
export const DEFAULT_URL = 'https://zelsis.com';
const MAX_FILE_BYTES = 512 * 1024;
const MAX_TOTAL_BYTES = 3.5 * 1024 * 1024; // stays under the API's 4 MB limit with JSON overhead
const MAX_FILES = 3000;

const SKIP_DIR = /(?:^|\/)(?:node_modules|\.git|\.next|dist|build|out|coverage|vendor|\.venv|venv|__pycache__|target|\.turbo|\.cache)\//;
const SKIP_EXT = /\.(?:png|jpe?g|gif|webp|avif|ico|bmp|svgz|pdf|zip|gz|tgz|bz2|7z|rar|jar|war|class|exe|dll|so|dylib|bin|wasm|woff2?|ttf|otf|eot|mp[34]|mov|avi|webm|wav|ogg|psd|sketch|fig|sqlite|db|lock)$|\.min\.(?:js|css)$|\.map$/i;

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 });
}

const lines = (s) => s.split('\n').map((l) => l.trim()).filter(Boolean);

/** True when the path is worth sending: not a build folder, binary type or lockfile. */
export function isScannablePath(path) {
  const p = path.replace(/\\/g, '/');
  return !SKIP_DIR.test(p) && !SKIP_EXT.test(p);
}

/** Files changed in the working tree (staged, unstaged, untracked), plus commits since `base` when given. */
export function changedPaths(cwd, base) {
  const out = new Set();
  const add = (s) => lines(s).forEach((p) => out.add(p));
  if (base) add(git(cwd, ['diff', '--name-only', '--diff-filter=d', `${base}...HEAD`]));
  try { add(git(cwd, ['diff', '--name-only', '--diff-filter=d', 'HEAD'])); } catch { /* no commits yet */ }
  add(git(cwd, ['ls-files', '--others', '--exclude-standard']));
  return [...out].filter(isScannablePath);
}

/**
 * Picks the files to send: changed files first, then the rest of the repository as context
 * (rules look across files, for example migrations and middleware), within the size limits.
 * @param {string} cwd
 * @param {{ changed?: string[] }} [opts]
 */
export function collectFiles(cwd, { changed = [] } = {}) {
  const tracked = lines(git(cwd, ['ls-files', '--cached', '--others', '--exclude-standard'])).filter(isScannablePath);
  const order = [...new Set([...changed, ...tracked])];
  const files = [];
  let total = 0;
  let skipped = 0;
  for (const path of order) {
    if (files.length >= MAX_FILES) { skipped++; continue; }
    let content;
    try {
      if (statSync(join(cwd, path)).size > MAX_FILE_BYTES) { skipped++; continue; }
      content = readFileSync(join(cwd, path), 'utf8');
    } catch { continue; }
    if (content.includes('\u0000')) continue;
    // Changed files come first in `order`, so they get the budget before context files
    if (total + content.length > MAX_TOTAL_BYTES) { skipped++; continue; }
    total += content.length;
    files.push({ path, content });
  }
  return { files, skipped };
}

export async function scanFiles({ url = DEFAULT_URL, apiKey, files, changed, projectName }) {
  const res = await fetch(`${url.replace(/\/$/, '')}/api/v1/scan-files`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': apiKey, 'user-agent': `zelsis-cli/${VERSION}` },
    body: JSON.stringify({ files, changed, projectName }),
  });
  const body = await res.json().catch(() => null);
  if (!res.ok || !body) throw new Error(body?.error || `Zelsis returned HTTP ${res.status}`);
  return body;
}

export const MISSING_KEY_HELP = `ZELSIS_API_KEY is not set.

Create a key at https://zelsis.com/dashboard under Settings & API Keys, then set it:
  PowerShell (this window):  $env:ZELSIS_API_KEY = "your-key"
  PowerShell (permanent):    [Environment]::SetEnvironmentVariable("ZELSIS_API_KEY", "your-key", "User")
  bash / zsh:                export ZELSIS_API_KEY=your-key
After the permanent setting, open a new terminal.`;

/** Runs a check in `cwd` and returns the API result. Used by both the CLI and the MCP tool. */
export async function runCheck({ cwd, all = false, base, url, apiKey }) {
  if (!apiKey) throw new Error(MISSING_KEY_HELP);
  const changed = all ? undefined : changedPaths(cwd, base);
  if (changed && changed.length === 0) return { gateStatus: 'PASSED', findings: [], filesScanned: 0, scope: 'changed', nothingChanged: true };
  const { files, skipped } = collectFiles(cwd, { changed: changed ?? [] });
  const projectName = cwd.replace(/\\/g, '/').split('/').filter(Boolean).pop();
  const result = await scanFiles({ url, apiKey, files, changed, projectName });
  return { ...result, skippedFiles: skipped };
}

const color = (on) => (code, s) => (on ? `\u001b[${code}m${s}\u001b[0m` : s);

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/** The threshold in upper case, or undefined when the value is not a severity. */
export const parseSeverity = (value) => {
  const upper = String(value ?? '').toUpperCase();
  return SEVERITIES.includes(upper) ? upper : undefined;
};

/** True when a finding is at or above the threshold. */
export const meetsThreshold = (result, threshold) =>
  result.findings.some((f) => SEVERITIES.indexOf(f.severity) >= SEVERITIES.indexOf(threshold));

const sarifLevel = (severity) => (severity === 'CRITICAL' || severity === 'HIGH' ? 'error' : severity === 'MEDIUM' ? 'warning' : 'note');

/** SARIF 2.1.0 log for the findings in a result. */
export function toSarif(result) {
  const rules = new Map();
  const results = result.findings.map((f) => {
    const ruleId = `ZLS-${f.ruleId}`;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        shortDescription: { text: f.title },
        defaultConfiguration: { level: sarifLevel(f.severity) },
        ...(f.cweId ? { properties: { tags: [`external/cwe/${f.cweId.toLowerCase()}`] } } : {}),
      });
    }
    const line = Number((f.lineRange || '').match(/\d+/)?.[0]) || 1;
    return {
      ruleId,
      level: sarifLevel(f.severity),
      message: { text: f.fix ? `${f.title}\n\n${f.fix}` : f.title },
      locations: [{ physicalLocation: { artifactLocation: { uri: f.filePath, uriBaseId: '%SRCROOT%' }, region: { startLine: line } } }],
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'Zelsis', version: VERSION, informationUri: DEFAULT_URL, rules: [...rules.values()] } }, results }],
  };
}

/** Human-readable report. `limit` caps how many findings are listed. */
export function formatReport(result, { colors = false, limit = 50 } = {}) {
  const c = color(colors);
  if (result.nothingChanged) return 'No changed files. Run `zelsis check --all` to scan the whole repository.';
  const sev = { CRITICAL: (s) => c('1;31', s), HIGH: (s) => c('31', s), MEDIUM: (s) => c('33', s), LOW: (s) => c('2', s) };
  const out = [];
  for (const f of result.findings.slice(0, limit)) {
    const line = (f.lineRange || '').match(/\d+/)?.[0];
    out.push(`${(sev[f.severity] ?? ((s) => s))(f.severity.padEnd(8))} ${f.filePath}${line ? `:${line}` : ''}  ${f.title}${f.cweId ? ` (${f.cweId})` : ''}${f.experimental ? c('2', ' (experimental)') : ''}`);
    if (f.impact) out.push(`         ${f.risk ? `${c('1', f.risk.toUpperCase())}: ` : ''}${f.impact}`);
    if (f.fix) out.push(c('2', `         Fix: ${f.fix}`));
  }
  if (result.findings.length > limit) out.push(`... and ${result.findings.length - limit} more`);
  const gate = { PASSED: c('32', 'PASSED'), WARNING: c('33', 'WARNING'), FAILED: c('1;31', 'FAILED') }[result.gateStatus] ?? result.gateStatus;
  const scope = result.scope === 'changed' ? 'changed files' : 'all files';
  out.push('', `Zelsis gate: ${gate} · ${result.findings.length} finding(s) in ${scope} · ${result.filesScanned} file(s) scanned`);
  for (const v of (result.crossFileVerified ?? []).slice(0, 5)) {
    out.push(c('2', `Checked across files: ${v.filePath} is not flagged because ${v.reason}.`));
  }
  if (result.otherFindings) out.push(c('2', `${result.otherFindings} more finding(s) in files you did not change. Run with --all to see them.`));
  return out.join('\n');
}
