#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { VERSION, runCheck, formatReport, toSarif, parseSeverity, meetsThreshold } from '../lib.mjs';
import { serveMcp } from '../mcp.mjs';
import { planInit, applyInit, describePlan, MCP_HELP } from '../init.mjs';

const HELP = `zelsis ${VERSION}: check your code with Zelsis before you push

Usage:
  zelsis check            Scan uncommitted changes (the rest of the repo is sent as context)
  zelsis verify           Same as check (for agent instructions: "run zelsis verify before finishing")
  zelsis check --all      Scan and gate on every file
  zelsis check --base origin/main   Also count commits since origin/main as changed
  zelsis mcp              Start the MCP server (tool: zelsis_check) for AI coding agents
  zelsis init             Tell the AI agents in this repo (CLAUDE.md, AGENTS.md, .cursorrules...) to run zelsis verify
                          before finishing, and show how to add the MCP server. --dry-run only prints the plan

Options:
  --json      Print the raw result as JSON
  --strict    Exit 1 on WARNING too, not only on FAILED
  --sarif     Print the result as SARIF 2.1.0
  --sarif-file-output=<path>   Also write SARIF to a file
  --severity-threshold=<low|medium|high|critical>
              Exit 1 when a finding is at or above this severity. Replaces the gate result and --strict for the exit code

Exit codes: 0 passed, 1 issues found, 2 the check could not run

Environment:
  ZELSIS_API_KEY   Required. Create one at https://zelsis.com/dashboard under Settings & API Keys
  ZELSIS_URL       Defaults to https://zelsis.com

Files are scanned in memory on the Zelsis server and not stored.`;

const args = process.argv.slice(2);
const has = (flag) => args.includes(flag);
const valueOf = (flag) => {
  const inline = args.find((a) => a.startsWith(`${flag}=`));
  if (inline) return inline.slice(flag.length + 1);
  const i = args.indexOf(flag);
  return i !== -1 ? args[i + 1] : undefined;
};

async function main() {
  const command = args[0];
  if (!command || has('--help') || has('-h')) { console.log(HELP); return 0; }
  if (command === '--version' || command === '-v') { console.log(VERSION); return 0; }
  if (command === 'mcp') { serveMcp(); return null; }
  if (command === 'init') {
    const dryRun = has('--dry-run');
    const plan = planInit(process.cwd());
    if (!dryRun) applyInit(process.cwd(), plan);
    console.log(`${describePlan(plan, dryRun)}\n\n${MCP_HELP}`);
    return 0;
  }
  if (command !== 'check' && command !== 'verify') { console.error(`Unknown command: ${command}\n\n${HELP}`); return 2; }

  const thresholdValue = valueOf('--severity-threshold');
  const threshold = parseSeverity(thresholdValue);
  if (thresholdValue !== undefined && !threshold) { console.error('zelsis: --severity-threshold must be low, medium, high or critical'); return 2; }
  const sarifFile = valueOf('--sarif-file-output');
  if (has('--sarif-file-output') && !sarifFile) { console.error('zelsis: --sarif-file-output needs a file path'); return 2; }

  const result = await runCheck({
    cwd: process.cwd(),
    all: has('--all'),
    base: valueOf('--base'),
    url: process.env.ZELSIS_URL,
    apiKey: process.env.ZELSIS_API_KEY,
  });
  if (sarifFile) writeFileSync(sarifFile, JSON.stringify(toSarif(result), null, 2));
  if (has('--sarif')) console.log(JSON.stringify(toSarif(result), null, 2));
  else console.log(has('--json') ? JSON.stringify(result, null, 2) : formatReport(result, { colors: process.stdout.isTTY && !process.env.NO_COLOR }));
  if (threshold) return meetsThreshold(result, threshold) ? 1 : 0;
  if (result.gateStatus === 'FAILED') return 1;
  if (has('--strict') && result.gateStatus === 'WARNING') return 1;
  return 0;
}

main().then(
  (code) => { if (code !== null) process.exitCode = code; },
  (err) => { console.error(`zelsis: ${err.message}`); process.exitCode = 2; },
);
