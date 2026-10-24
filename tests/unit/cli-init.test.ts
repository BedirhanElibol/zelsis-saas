import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { planInit, applyInit, describePlan, MARKER, AGENT_RULE } from '../../packages/cli/init.mjs';

const tempRepo = () => mkdtempSync(join(tmpdir(), 'zelsis-init-'));

test('init creates AGENTS.md and CLAUDE.md when the repo has no agent instructions', () => {
  const dir = tempRepo();
  try {
    const plan = planInit(dir);
    assert.deepEqual(plan, [{ path: 'AGENTS.md', action: 'create' }, { path: 'CLAUDE.md', action: 'create' }]);
    applyInit(dir, plan);
    assert.equal(readFileSync(join(dir, 'AGENTS.md'), 'utf8'), AGENT_RULE);
    assert.ok(existsSync(join(dir, 'CLAUDE.md')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('init appends once to existing files and keeps their content', () => {
  const dir = tempRepo();
  try {
    writeFileSync(join(dir, 'CLAUDE.md'), '# House rules\nUse pnpm.');
    mkdirSync(join(dir, '.github'));
    writeFileSync(join(dir, '.github/copilot-instructions.md'), `Be brief.\n\n${AGENT_RULE}`);
    const plan = planInit(dir);
    assert.deepEqual(plan, [
      { path: 'CLAUDE.md', action: 'append' },
      { path: '.github/copilot-instructions.md', action: 'skip' },
    ]);
    applyInit(dir, plan);
    const claude = readFileSync(join(dir, 'CLAUDE.md'), 'utf8');
    assert.ok(claude.startsWith('# House rules\nUse pnpm.\n\n'));
    assert.equal(claude.split(MARKER).length, 2);
    // Running again changes nothing
    applyInit(dir, planInit(dir));
    assert.equal(readFileSync(join(dir, 'CLAUDE.md'), 'utf8'), claude);
    assert.ok(!existsSync(join(dir, 'AGENTS.md')), 'no new files when the repo already has agent instructions');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('dry-run wording says what would happen without doing it', () => {
  const dir = tempRepo();
  try {
    const plan = planInit(dir);
    assert.match(describePlan(plan, true), /would create AGENTS\.md/);
    assert.ok(!existsSync(join(dir, 'AGENTS.md')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
