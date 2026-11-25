import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const root = resolve(__dirname, '..', '..');
const cli = join(root, 'packages', 'cli', 'bin', 'zelsis.mjs');

// Any network call from the CLI process fails loudly, so a passing run proves --local sends nothing
const BLOCK_NETWORK = 'data:text/javascript,globalThis.fetch=()=>{throw new Error("network blocked")}';

function repoWith(file: string, content: string) {
  const dir = mkdtempSync(join(tmpdir(), 'zelsis-local-'));
  spawnSync('git', ['init', '-q'], { cwd: dir });
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'src', file), content);
  spawnSync('git', ['add', '-A'], { cwd: dir });
  return dir;
}

const run = (cwd: string, args: string[]) =>
  spawnSync(process.execPath, ['--import', BLOCK_NETWORK, cli, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, ZELSIS_API_KEY: '', ZELSIS_URL: 'http://127.0.0.1:1' },
  });

test('check --local scans on this machine with no key and no network', () => {
  const build = spawnSync(process.execPath, [join(root, 'scripts', 'build-cli-engine.mjs')], { encoding: 'utf8' });
  assert.equal(build.status, 0, build.stderr);

  const dir = repoWith('a.js', 'const q = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(q);\n');
  try {
    const res = run(dir, ['check', '--local', '--all']);
    assert.equal(res.status, 1, res.stdout + res.stderr);
    assert.match(res.stdout, /Zelsis gate: FAILED/);
    assert.match(res.stdout, /src\/a\.js:\d+/);
    assert.doesNotMatch(res.stderr, /network blocked/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('check --local passes a clean repository', () => {
  const dir = repoWith('b.js', 'export const add = (a, b) => a + b;\n');
  try {
    const res = run(dir, ['check', '--local', '--all']);
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.match(res.stdout, /Zelsis gate: PASSED/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('without --local and without a key the CLI still asks for a key', () => {
  const dir = repoWith('c.js', 'export const x = 1;\n');
  try {
    const res = run(dir, ['check', '--all']);
    assert.notEqual(res.status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
