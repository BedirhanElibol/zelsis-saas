import { test } from 'node:test';
import assert from 'node:assert/strict';
import { summarizeWeek, summarySubject } from '@/lib/weekly-summary';

const run = (project_id: string, gate_status: string, critical_count = 0, high_count = 0) =>
  ({ user_id: 'u', project_id, gate_status, critical_count, high_count, scanned_at: '2026-10-16T10:00:00Z' });

test('summarizeWeek counts runs, blocks, warnings and the projects with blocked merges', () => {
  const s = summarizeWeek([run('a', 'FAILED', 2, 1), run('a', 'FAILED', 1), run('b', 'WARNING', 0, 3), run('c', 'PASSED')]);
  assert.deepEqual(
    { runs: s.runs, blocked: s.blocked, warned: s.warned, criticalStopped: s.criticalStopped, highFlagged: s.highFlagged },
    { runs: 4, blocked: 2, warned: 1, criticalStopped: 3, highFlagged: 4 },
  );
  assert.deepEqual(s.topProjects, [{ projectId: 'a', blocked: 2 }]);
  assert.equal(summarySubject(s), 'Zelsis stopped 3 critical issues before merge this week');
});

test('a clean week says nothing critical got through', () => {
  const s = summarizeWeek([run('a', 'PASSED')]);
  assert.equal(summarySubject(s), 'Zelsis checked 1 pull request this week: nothing critical got through');
});
