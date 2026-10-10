import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dedupeProjects, repoKey } from '../../lib/dashboard/project-state';
import type { Project } from '../../data/schema';

const proj = (id: string, repoUrl: string, extra: Partial<Project> = {}): Project => ({ id, name: id, repoUrl, findings: [], ...extra } as unknown as Project);

test('repoKey treats owner/repo, full GitHub URLs, trailing slashes and .git as one repository', () => {
  const k = repoKey('BedirhanElibol/zelsis-saas');
  assert.equal(repoKey('https://github.com/BedirhanElibol/zelsis-saas'), k);
  assert.equal(repoKey('https://www.github.com/bedirhanelibol/zelsis-saas/'), k);
  assert.equal(repoKey('https://github.com/BedirhanElibol/zelsis-saas.git'), k);
  assert.notEqual(repoKey('https://github.com/expressjs/express'), k);
});

test('duplicates collapse to the copy with findings and the newest scan, keeping list order', () => {
  const empty = proj('a', 'BedirhanElibol/zelsis-saas');
  const scanned = proj('b', 'https://github.com/BedirhanElibol/zelsis-saas', { findings: [{}] as never, lastScanIso: '2026-10-01' } as Partial<Project>);
  const other = proj('c', 'https://github.com/expressjs/express');
  const out = dedupeProjects([empty, other, scanned]);
  assert.deepEqual(out.map((p) => p.id), ['b', 'c']);
});
