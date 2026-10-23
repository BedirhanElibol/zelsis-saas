import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [33],
    name: 'Rule 33 Command Injection vs safe process utilities and git helpers',
    detects: f('src/agent.ts', `import { execSync } from 'child_process';
export function runUserCommand(req: any) {
  const userInput = req.query.cmd;
  execSync(\`echo \${userInput}\`);
}
`),
    ignores: f('src/utils.ts', `import { execSync } from 'child_process';
export function killProcess(pid: number) {
  execSync('taskkill /pid ' + pid + ' /T /F');
  execSync(\`ps -o ppid= -p \${pid}\`);
}
export function getCommitCount(base: string, cwd: string) {
  return execSync(\`git rev-list --count \${base}..HEAD\`, { cwd });
}
`),
  },
  {
    ruleIds: [18003, 24102],
    name: 'Rule 18003 & 24102 PHP command execution vs escaped arguments and internal git commands',
    detects: f('src/shell.php', `<?php
$cmd = $_GET['command'];
exec("sh -c " . $cmd);
`),
    ignores: f('src/helpers.php', `<?php
function installPlugin($record) {
    $php = escapeshellarg('/usr/bin/php');
    $artisan = escapeshellarg('/path/to/artisan');
    $command = "$php $artisan {$record->name}:install";
    exec($command);
}
function getGitVersion() {
    $command = 'git --git-dir "/path/.git" describe --tags';
    $content = exec($command);
    return $content;
}
`),
  },
];
