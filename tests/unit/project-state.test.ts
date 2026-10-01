import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { Finding, Project } from '../../data/schema';
import {
  findUpdatedProject,
  normalizeProject,
  serializeProjectsForStorage,
  updateMatchingFindings,
  withRecalculatedFindings
} from '../../lib/dashboard/project-state';

const finding = (over: Partial<Finding>): Finding => ({
  id: 'f1', ruleId: 1, type: 'SECURITY', title: 't', severity: 'CRITICAL', category: 'c',
  filePath: 'a.ts', lineRange: 'L1', snippet: 's', reproductionSteps: ['r1', 'r2'],
  remediationPrompt: 'fix', status: 'OPEN', falsePositive: false, ...over
});

const project = (over: Partial<Project>): Project => ({
  id: 'p1', name: 'app', repoUrl: 'https://github.com/a/b', framework: 'Next.js', providers: [],
  lastScanAt: 'now', readinessScore: 0, gateStatus: 'FAILED', criticalCount: 1, highCount: 0,
  mediumCount: 0, lowCount: 0, uiClicheCount: 0, findings: [], ...over
});

describe('withRecalculatedFindings', () => {
  it('counts only OPEN findings and recomputes gate and score', () => {
    const p = withRecalculatedFindings(project({}), [
      finding({ id: 'a', severity: 'CRITICAL', status: 'RESOLVED' }),
      finding({ id: 'b', severity: 'HIGH' }),
      finding({ id: 'c', severity: 'LOW', type: 'VIBEPOLISH' })
    ]);
    assert.equal(p.criticalCount, 0);
    assert.equal(p.highCount, 1);
    assert.equal(p.lowCount, 1);
    assert.equal(p.uiClicheCount, 1);
    assert.equal(p.gateStatus, 'WARNING');
    assert.ok(p.readinessScore > 0 && p.readinessScore < 100);
  });
});

describe('updateMatchingFindings', () => {
  const a = project({ id: 'a', findings: [finding({ id: 'x' })] });
  const b = project({ id: 'b', findings: [finding({ id: 'y' })] });

  it('updates only projects containing a match and keeps others by reference', () => {
    const next = updateMatchingFindings([a, b], (f) => f.id === 'x', (f) => ({ ...f, status: 'RESOLVED' }));
    assert.equal(next[1], b);
    assert.notEqual(next[0], a);
    assert.equal(next[0].findings[0].status, 'RESOLVED');
    assert.equal(next[0].gateStatus, 'PASSED');
  });

  it('reports the changed selected project, or null when untouched', () => {
    const next = updateMatchingFindings([a, b], (f) => f.id === 'x', (f) => ({ ...f, status: 'RESOLVED' }));
    assert.equal(findUpdatedProject([a, b], next, 'a'), next[0]);
    assert.equal(findUpdatedProject([a, b], next, 'b'), null);
  });
});

describe('normalizeProject', () => {
  const fallback = project({ id: 'demo', name: 'Demo', repoUrl: 'https://github.com/demo/repo' });

  it('fills placeholders and derives the name from the repo URL', () => {
    const p = normalizeProject({ id: 'p9', repoUrl: ' https://github.com/acme/shop ', name: 'undefined' } as unknown as Project, fallback);
    assert.equal(p.repoUrl, 'https://github.com/acme/shop');
    assert.equal(p.name, 'shop');
    assert.equal(p.readinessScore, 100);
    assert.equal(p.gateStatus, 'PASSED');
    assert.deepEqual(p.findings, []);
    assert.deepEqual(p.providers, []);
    assert.equal(p.framework, 'Auto-detect');
  });

  it('falls back to the default repo when none is given', () => {
    assert.equal(normalizeProject({ id: 'p9' } as unknown as Project, fallback).repoUrl, fallback.repoUrl);
  });
});

describe('serializeProjectsForStorage', () => {
  const long = 'x'.repeat(200);
  const projects = [
    project({ id: 'p1', githubToken: 'ghs_secret', findings: [finding({ snippet: long })] }),
    project({ id: 'proj-zelsis-self', repoUrl: 'local' })
  ];

  it('never stores GitHub tokens and drops local audit projects when not allowed', () => {
    const stored = JSON.parse(serializeProjectsForStorage(projects, false, false));
    assert.equal(stored.length, 1);
    assert.equal('githubToken' in stored[0], false);
    assert.equal(stored[0].findings[0].snippet.length, 153);
    assert.deepEqual(stored[0].findings[0].reproductionSteps, ['r1']);
  });

  it('keeps only essential finding fields in compact mode', () => {
    const stored = JSON.parse(serializeProjectsForStorage(projects, true, true));
    assert.equal(stored.length, 2);
    assert.deepEqual(Object.keys(stored[0].findings[0]).sort(), ['filePath', 'id', 'ruleId', 'severity', 'status', 'title', 'type']);
  });
});
